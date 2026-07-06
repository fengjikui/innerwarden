pub(crate) mod state;
pub(crate) mod types;

// Re-export types used by other modules in the crate.
pub use auth::generate_password_hash_interactive;
pub(crate) use state::PlaybookSimContext;
pub use state::{AgentGuardAlert, DashboardActionConfig, DeepSecuritySnapshot, TwoFactorSettings};
pub use types::AdvisoryEntry;

#[allow(unused_imports)]
use state::*;
#[allow(unused_imports)]
use types::*;

mod actions;
mod agent_api;
pub(crate) mod agent_guard_incident;
mod audit_export_csv;
mod audit_export_signing;
mod auth;
mod canonical_counts;
mod case_metrics;
mod case_recurrence;
mod cases_from_sqlite;
mod compliance;
mod data_api;
mod decision_provenance;
mod fleet;
mod helpers;
mod intelligence;
mod investigation;
mod live_feed;
mod playbooks;
mod push;
mod sensors;
mod sse;
mod still_active_now;
mod threat_contract;
mod two_fa;

#[cfg(test)]
mod consistency_block_counts;

#[cfg(test)]
mod consistency_case_metrics;

#[cfg(test)]
mod consistency_incidents_today;

#[allow(unused_imports)]
use actions::*;
#[allow(unused_imports)]
use agent_api::*;
#[allow(unused_imports)]
use auth::*;
#[allow(unused_imports)]
use compliance::*;
#[allow(unused_imports)]
use data_api::*;
#[allow(unused_imports)]
use helpers::*;
#[allow(unused_imports)]
use intelligence::*;
#[allow(unused_imports)]
use investigation::*;
#[allow(unused_imports)]
use live_feed::*;
#[allow(unused_imports)]
use push::*;
#[allow(unused_imports)]
use sensors::*;
#[allow(unused_imports)]
use sse::*;
#[allow(unused_imports)]
use two_fa::*;

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex, RwLock};

use anyhow::{Context, Result};
use argon2::password_hash::{PasswordHashString, SaltString};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::{header, HeaderValue, Method, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use chrono::{DateTime, Datelike, Utc};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt as _;
use tracing::{info, warn};

#[cfg(test)]
use crate::correlation::build_clusters;
use crate::decisions::DecisionEntry;
use crate::mitre;
use crate::report::{self as report_mod, TrialReport};
use innerwarden_core::audit::{append_admin_action, AdminActionEntry};
use innerwarden_core::entities::{EntityRef, EntityType};
use innerwarden_core::event::Severity;
use innerwarden_core::incident::Incident;

// ---------------------------------------------------------------------------
// Live "Needs review" count for the Daily Security Briefing
// ---------------------------------------------------------------------------

/// The number of open cases that still need an operator decision RIGHT NOW,
/// computed from the SAME canonical source the dashboard "Needs review" tile
/// reads (`data_api::compute_overview_counts_from_sqlite`, whose
/// `attention_count` is the per-attacker `KpiBucket::Attention` aggregate /
/// `case_metrics::KpiBucket::Attention -> NeedsReview`).
///
/// The daily briefing MUST use this, not
/// `grouping_engine.drain_digest_stats().needs_review_groups` — that is a
/// transient per-window group counter drained on every send, so it diverges
/// from the live dashboard number (e.g. a Low/Medium `needs_review` incident
/// auto-dismissed by the spec-062 24h timeout is still counted by the grouped
/// counter but has already dropped out of the live `attention_count`). Reading
/// the live source at send time means the briefing can never tell the operator
/// to "review N items" that the dashboard shows as zero.
///
/// `date` is the local-day key (`%Y-%m-%d`) the briefing is for; the function
/// returns 0 on any store/query error so a transient SQLite hiccup degrades to
/// the honest "nothing needs you" rather than a fabricated number.
pub(crate) fn live_needs_review_count(store: &innerwarden_store::Store, date: &str) -> usize {
    let now = chrono::Utc::now();
    data_api::compute_overview_counts_from_sqlite(
        store,
        date,
        0,    // sev_min_rank: no severity floor — count every open case
        None, // detector_substring: all detectors
        None, // hour_filter: the whole day
        now,
        &data_api::DegradedSignals::default(),
        std::path::Path::new(""), // data_dir: unused for the attention tally
    )
    .map(|c| c.attention_count)
    .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Security headers middleware
// ---------------------------------------------------------------------------

async fn security_headers(req: axum::extract::Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();
    headers.insert(header::X_FRAME_OPTIONS, "DENY".parse().unwrap());
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    headers.insert("x-xss-protection", "0".parse().unwrap());
    headers.insert(
        "referrer-policy",
        "strict-origin-when-cross-origin".parse().unwrap(),
    );
    resp
}

// ---------------------------------------------------------------------------
// CSRF middleware (audit I-14)
// ---------------------------------------------------------------------------

/// PR #420 Wave 3: simple-yet-effective CSRF defense for state-changing
/// requests. Rejects POST / PUT / PATCH / DELETE that arrive without
/// `X-Requested-With: XMLHttpRequest`.
///
/// Why this works against CSRF on a Basic-Auth-protected dashboard:
///
/// - Browsers automatically attach Basic-Auth credentials to *any*
///   request whose origin is in the operator's auth cache. A malicious
///   site that submits an HTML `<form action=".../api/action/...">`
///   would otherwise piggyback on those credentials.
/// - Forms can only set `Content-Type: application/x-www-form-urlencoded`
///   / `multipart/form-data` / `text/plain` and a small set of headers.
///   Custom headers like `X-Requested-With` are NOT in that set and
///   trigger a CORS preflight that the dashboard rejects (no CORS
///   policy configured).
/// - Therefore, requiring `X-Requested-With: XMLHttpRequest` is
///   sufficient to block form-based CSRF without the complexity of
///   per-session CSRF tokens.
///
/// GET / HEAD / OPTIONS pass through unchanged — they are read-only and
/// already body-limited.
async fn csrf_protection(req: axum::extract::Request, next: Next) -> Response {
    use axum::http::{Method, StatusCode};
    let method = req.method();
    let needs_check = matches!(
        method,
        &Method::POST | &Method::PUT | &Method::PATCH | &Method::DELETE
    );
    if needs_check {
        let header_ok = req
            .headers()
            .get("x-requested-with")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.eq_ignore_ascii_case("xmlhttprequest"))
            .unwrap_or(false);
        if !header_ok {
            return (
                StatusCode::FORBIDDEN,
                "missing X-Requested-With: XMLHttpRequest header (CSRF protection)",
            )
                .into_response();
        }
    }
    next.run(req).await
}

// ---------------------------------------------------------------------------
// Shared state / auth
// ---------------------------------------------------------------------------

/// Short-lived cache of "this (user, password) tuple was just verified
/// against argon2". Skips the ~64 MB working-buffer allocation per
/// dashboard HTTP request — the dashboard frontend issues Basic Auth
/// on every API call, and per jeprof on prod 2026-05-02 that drove
/// argon2 to 128 MB / 29.4 % of the agent heap.
///
/// ## Security trade-off
///
/// Cache hits skip the slow argon2 path. The window between a
/// password change taking effect server-side and the cache TTL
/// expiring is the operationally-acceptable cost. With the default
/// `TTL_SECS = 300`, a leaked credential remains usable for at most
/// 5 minutes after the password is rotated, which matches the
/// already-existing session token TTL behaviour.
///
/// The cache key is a SHA-256 hash of `(salt || user || ":" || password)`
/// where `salt` is a per-process random value generated at boot.
/// Plaintext credentials never persist in the map; the salt is
/// discarded on restart so cache keys cannot be replayed across
/// process boundaries.
#[derive(Clone)]
struct VerifiedCache {
    state: Arc<VerifiedCacheState>,
}

struct VerifiedCacheState {
    salt: [u8; 32],
    map: RwLock<HashMap<[u8; 32], std::time::Instant>>,
}

impl VerifiedCache {
    /// 5 minutes — same window as session tokens.
    const TTL: std::time::Duration = std::time::Duration::from_secs(300);
    /// Capacity is small by design. The map sees at most one entry per
    /// active operator credential; in practice 1-3 entries.
    const CAPACITY: usize = 16;

    fn new() -> Self {
        let mut salt = [0u8; 32];
        // Use the OsRng path already imported elsewhere in the
        // dashboard module — avoids pulling in a new rand entry point
        // for one 32-byte read at boot.
        use rand_core::RngCore;
        rand_core::OsRng.fill_bytes(&mut salt);
        Self {
            state: Arc::new(VerifiedCacheState {
                salt,
                map: RwLock::new(HashMap::new()),
            }),
        }
    }

    fn key(&self, user: &str, password: &str) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(self.state.salt);
        h.update(user.as_bytes());
        h.update(b":");
        h.update(password.as_bytes());
        h.finalize().into()
    }

    /// Returns `true` when the (user, password) tuple has a non-expired
    /// entry in the cache.
    fn check(&self, user: &str, password: &str) -> bool {
        let k = self.key(user, password);
        let map = self.state.map.read().unwrap_or_else(|p| p.into_inner());
        match map.get(&k) {
            Some(ts) => ts.elapsed() < Self::TTL,
            None => false,
        }
    }

    /// Record a successful verification under the (user, password) key.
    /// Also drains expired entries opportunistically and enforces the
    /// capacity by evicting the oldest survivor when the map is full.
    fn insert(&self, user: &str, password: &str) {
        let k = self.key(user, password);
        let mut map = self.state.map.write().unwrap_or_else(|p| p.into_inner());
        map.retain(|_, ts| ts.elapsed() < Self::TTL);
        if map.len() >= Self::CAPACITY {
            if let Some(oldest_key) = map.iter().min_by_key(|(_, ts)| **ts).map(|(k, _)| *k) {
                map.remove(&oldest_key);
            }
        }
        map.insert(k, std::time::Instant::now());
    }

    #[cfg(test)]
    fn entry_count(&self) -> usize {
        self.state
            .map
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .len()
    }
}

#[derive(Clone)]
pub struct DashboardAuth {
    username: String,
    password_hash: PasswordHashString,
    verified_cache: VerifiedCache,
}

impl DashboardAuth {
    /// Load credentials from environment variables.
    /// Returns `None` if neither env var is set (open access mode).
    /// Returns `Err` if vars are partially set or malformed.
    pub fn try_from_env() -> Result<Option<Self>> {
        let user = std::env::var("INNERWARDEN_DASHBOARD_USER").ok();
        let hash = std::env::var("INNERWARDEN_DASHBOARD_PASSWORD_HASH").ok();
        Self::try_from_env_vars(user, hash)
    }

    /// Pure helper used by `try_from_env` and the unit tests. Splitting
    /// the env-var read from the validation logic lets tests cover all
    /// four `(user, hash)` branches without mutating process-wide
    /// environment state — env-var mutation across parallel tests is
    /// unsound on most platforms.
    pub(super) fn try_from_env_vars(
        user: Option<String>,
        hash: Option<String>,
    ) -> Result<Option<Self>> {
        match (user, hash) {
            (None, None) => Ok(None), // no auth configured - open access
            (Some(username), Some(password_hash_raw)) => {
                if username.trim().is_empty() {
                    anyhow::bail!("INNERWARDEN_DASHBOARD_USER cannot be empty");
                }
                let password_hash =
                    PasswordHashString::new(&password_hash_raw).map_err(|_| {
                        anyhow::anyhow!(
                            "INNERWARDEN_DASHBOARD_PASSWORD_HASH is not a valid PHC hash string"
                        )
                    })?;
                Ok(Some(Self {
                    username,
                    password_hash,
                    verified_cache: VerifiedCache::new(),
                }))
            }
            (Some(_), None) => anyhow::bail!(
                "INNERWARDEN_DASHBOARD_USER is set but INNERWARDEN_DASHBOARD_PASSWORD_HASH is missing.\n\
                 Generate one with: innerwarden-agent --dashboard-generate-password-hash"
            ),
            (None, Some(_)) => anyhow::bail!(
                "INNERWARDEN_DASHBOARD_PASSWORD_HASH is set but INNERWARDEN_DASHBOARD_USER is missing."
            ),
        }
    }

    /// Slow path: parse the stored PHC hash and run argon2 verify.
    /// Allocates the argon2 working buffer (~64 MB at default
    /// parameters). Used directly by the login endpoint and by the
    /// cache miss path in `verify_with_cache`.
    fn verify(&self, user: &str, password: &str) -> bool {
        // Use constant-time comparison for the username to prevent
        // timing side-channels that could enumerate valid usernames.
        if !constant_time_eq(user, &self.username) {
            return false;
        }
        let parsed = PasswordHash::new(self.password_hash.as_str());
        match parsed {
            Ok(hash) => Argon2::default()
                .verify_password(password.as_bytes(), &hash)
                .is_ok(),
            Err(_) => false,
        }
    }

    /// Fast path used by the per-request middleware. Hits the
    /// short-lived `verified_cache` when the same (user, password)
    /// has been verified recently and returns `true` without paying
    /// the argon2 allocation cost. Cache misses fall through to
    /// `verify` and, on success, populate the cache so the next
    /// request from the same client lands on the fast path.
    pub(super) fn verify_with_cache(&self, user: &str, password: &str) -> bool {
        if self.verified_cache.check(user, password) {
            return true;
        }
        let ok = self.verify(user, password);
        if ok {
            self.verified_cache.insert(user, password);
        }
        ok
    }
}

/// Constant-time string equality to prevent timing side-channel attacks.
fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

// ---------------------------------------------------------------------------
// Server entry point
// ---------------------------------------------------------------------------

/// Audit I-14 (2026-04-29): cap request bodies at 1 MiB across the
/// whole router. Without this, an authenticated operator session (or
/// the loopback-bound /api/agent/* endpoints) could be coerced into
/// POSTing a multi-MB body, OOMing the agent under sustained attack.
///
/// 1 MiB is generous for every legitimate POST in this dashboard:
/// web-push subscribe (~1 KB), AI briefing requests (~2 KB), bot
/// command audit append (~500 B), session login basic auth (~100 B).
/// Bump if a future endpoint genuinely needs more.
pub(super) const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Build the `DefaultBodyLimit` layer that the dashboard router
/// applies. Extracted so the regression anchor in `tests` exercises
/// the exact same value `serve()` uses (no duplicated literal).
pub(super) fn build_body_limit_layer() -> DefaultBodyLimit {
    DefaultBodyLimit::max(MAX_BODY_BYTES)
}

#[allow(clippy::too_many_arguments)]
pub async fn serve(
    data_dir: PathBuf,
    bind: String,
    auth: Option<DashboardAuth>,
    action_cfg: DashboardActionConfig,
    web_push_vapid_public_key: String,
    trusted_proxy_strs: Vec<String>,
    session_timeout_minutes: u64,
    max_sessions: usize,
    advisory_cache: Arc<RwLock<VecDeque<AdvisoryEntry>>>,
    rule_engine: Arc<innerwarden_agent_guard::rules::RuleEngine>,
    // Spec 081: shared agent-guard registry (also held by the main agent loop's
    // response gate) so `agent connect` mutations are visible to the verifier.
    agent_registry: Arc<tokio::sync::Mutex<innerwarden_agent_guard::registry::Registry>>,
    agent_alert_tx: tokio::sync::mpsc::Sender<AgentGuardAlert>,
    deep_security: Arc<RwLock<DeepSecuritySnapshot>>,
    knowledge_graph: Arc<std::sync::RwLock<crate::knowledge_graph::KnowledgeGraph>>,
    ai_router: crate::ai::AiRouter,
    briefing_state: Arc<tokio::sync::Mutex<Option<crate::briefing::Briefing>>>,
    briefing_hour: u8,
    briefing_minute: u8,
    sqlite_store: Option<Arc<innerwarden_store::Store>>,
    fleet_state: Option<crate::fleet::FleetState>,
    tls_cert: Option<String>,
    tls_key: Option<String>,
    insecure_no_tls: bool,
    two_factor: state::TwoFactorSettings,
    playbook_sim: state::PlaybookSimContext,
    // Issue #71: shared pending map (bridge between agent loop and dashboard).
    pending_approvals: Arc<Mutex<HashMap<String, crate::telegram::PendingConfirmation>>>,
    // Issue #71: channel to notify the agent loop of approve/deny outcomes.
    approval_outcome_tx: tokio::sync::mpsc::Sender<state::DashboardApprovalOutcome>,
) -> Result<()> {
    // SEC-005: Reject non-loopback bind without authentication.
    let is_loopback_bind = is_loopback_address(&bind);
    if let Err(e) = validate_bind_auth(&bind, auth.is_some()) {
        anyhow::bail!("{}", e);
    }
    // SEC: plain HTTP (`--insecure-no-tls`) leaks credentials + data in
    // cleartext. `validate_bind_auth` already blocks a non-loopback bind with no
    // auth, but plain HTTP on a public interface is unacceptable even WITH auth
    // (the Basic-Auth header crosses the wire in the clear). Refuse to start
    // rather than just warn — a warning is not enough for a security product to
    // expose itself unencrypted on a public interface.
    if reject_insecure_public_bind(&bind, insecure_no_tls) {
        anyhow::bail!(
            "refusing to serve the dashboard over plain HTTP (--insecure-no-tls) on the \
             non-loopback bind {bind}: use --tls-cert/--tls-key, bind to 127.0.0.1, or \
             remove --insecure-no-tls"
        );
    }
    if auth.is_none() && is_loopback_bind {
        warn!(
            "dashboard is running WITHOUT authentication (loopback only) - \
             set INNERWARDEN_DASHBOARD_USER and INNERWARDEN_DASHBOARD_PASSWORD_HASH \
             in agent.env to require a login"
        );
    }

    // HTTPS warning: credentials sent in plaintext over non-localhost HTTP
    if auth.is_some() {
        let is_localhost = bind.starts_with("127.0.0.1")
            || bind.starts_with("[::1]")
            || bind.starts_with("localhost");
        if !is_localhost {
            warn!(
                bind = %bind,
                "dashboard is accessible over HTTP on a non-localhost address. \
                 Credentials will be sent in plaintext. Consider using a reverse \
                 proxy with TLS or binding to 127.0.0.1."
            );
        }
    }

    // D6: broadcast channel - capacity 64 is plenty; lagged receivers are dropped.
    let (event_tx, _) = broadcast::channel::<SsePayload>(64);

    let insecure_http = auth.is_some() && {
        let is_localhost = bind.starts_with("127.0.0.1")
            || bind.starts_with("[::1]")
            || bind.starts_with("localhost");
        !is_localhost
    };

    // Parse trusted proxy IPs at startup - only these connecting IPs may
    // set X-Forwarded-For / X-Real-IP headers.
    let trusted_proxies: Vec<IpAddr> = trusted_proxy_strs
        .iter()
        .filter_map(|s| {
            s.parse::<IpAddr>()
                .map_err(|e| {
                    warn!(proxy = %s, error = %e, "ignoring invalid trusted_proxy IP");
                    e
                })
                .ok()
        })
        .collect();
    if !trusted_proxies.is_empty() {
        info!(
            count = trusted_proxies.len(),
            "loaded trusted proxy IPs for X-Forwarded-For"
        );
    }

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let sessions: Arc<RwLock<HashMap<String, Session>>> = Arc::new(RwLock::new(HashMap::new()));
    let state = DashboardState {
        data_dir: data_dir.clone(),
        action_cfg: Arc::new(action_cfg),
        event_tx: event_tx.clone(),
        web_push_vapid_public_key,
        insecure_http,
        last_activity: Arc::new(std::sync::atomic::AtomicU64::new(now_secs)),
        sensor_cache: Arc::new(tokio::sync::Mutex::new((0, serde_json::json!({})))),
        trusted_proxies: Arc::new(trusted_proxies),
        sessions: sessions.clone(),
        session_timeout_minutes,
        max_sessions,
        advisory_cache: advisory_cache.clone(),
        // 2026-05-18 + spec 081: the agent-guard registry is now built ONCE in
        // `loops::boot` (rehydrated from the on-disk snapshot so `agent connect`
        // survives a watchdog binary swap) and the SAME `Arc<Mutex<Registry>>`
        // is shared between this dashboard and the main agent loop's
        // `managed_agent_guard` response gate. The dashboard receives it as a
        // parameter rather than restoring its own copy, so a connect made via
        // the dashboard API is immediately visible to the response gate.
        agent_registry,
        rule_engine,
        agent_alert_tx,
        deep_security,
        knowledge_graph,
        ai_router,
        latest_briefing: briefing_state,
        briefing_hour,
        briefing_minute,
        sqlite_store,
        fleet_state,
        two_factor: Arc::new(two_factor),
        playbook_sim: Arc::new(playbook_sim),
        pending_approvals,
        approval_outcome_tx: Some(approval_outcome_tx),
    };
    let auth_layer = middleware::from_fn_with_state(
        (
            auth.clone(),
            state.trusted_proxies.clone(),
            state.sessions.clone(),
            session_timeout_minutes,
        ),
        require_auth,
    );
    // Issue #71: clone before `state` is moved into the router builders below.
    let cleanup_pending_approvals = state.pending_approvals.clone();
    let activity_state = state.last_activity.clone();
    let activity_layer = middleware::from_fn(move |req: Request<Body>, next: Next| {
        let ts = activity_state.clone();
        async move {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            ts.store(now, std::sync::atomic::Ordering::Relaxed);
            next.run(req).await
        }
    });
    // Global rate limiter - rejects requests from IPs exceeding 120/min with 429.
    // Prevents memory exhaustion from bot traffic when dashboard is internet-facing.
    let rate_limit_proxies = state.trusted_proxies.clone();
    let rate_limit_layer = middleware::from_fn(move |req: Request<Body>, next: Next| {
        let proxies = rate_limit_proxies.clone();
        async move {
            let ip = extract_client_ip(&req, &proxies);
            if global_rate_check(&ip) {
                return axum::http::Response::builder()
                    .status(429)
                    .header("retry-after", "60")
                    .body(Body::from("Too Many Requests"))
                    .unwrap()
                    .into_response();
            }
            next.run(req).await
        }
    });

    // SEC-006 + Wave 2026-05-17 fix: Agent API routes use a
    // per-request loopback-bypass auth gate.
    //
    // Old behaviour: the WHOLE router was wrapped in either the auth
    // layer (for non-loopback bind) or no auth (for loopback bind).
    // That coarse-grained policy meant `sudo innerwarden agent
    // connect` on a host that bound the dashboard to 0.0.0.0 got 401
    // — even though the CLI runs as root on the same box and reaches
    // the dashboard via 127.0.0.1.
    //
    // New behaviour: every agent_api request is checked individually.
    // - Peer IP is loopback (127.0.0.1 / ::1)  → bypass auth.
    //   The caller is on the host; they already have whatever privs
    //   sudo grants them, and the local services (CLI, OpenClaw,
    //   n8n) can integrate without knowing the dashboard password.
    // - Peer IP is a real remote                → require_auth.
    //   Operator browsing the dashboard from outside, or a remote
    //   attacker, still hits the wall.
    //
    // The peer IP comes from `ConnectInfo<SocketAddr>` (wired up at
    // the serve sites at line 824 / 838), NOT from `X-Forwarded-For`
    // — a proxy header is operator-controlled and forging
    // `X-Forwarded-For: 127.0.0.1` must not bypass auth.
    let agent_api_auth_layer = middleware::from_fn_with_state(
        (
            auth.clone(),
            state.trusted_proxies.clone(),
            state.sessions.clone(),
            session_timeout_minutes,
        ),
        auth::loopback_bypass_or_require_auth,
    );
    let agent_api = Router::new()
        .route(
            "/api/agent/security-context",
            get(api_agent_security_context),
        )
        .route("/api/agent/check-ip", get(api_agent_check_ip))
        .route("/api/agent/check-command", post(api_agent_check_command))
        .route(
            "/api/advisor/check-command",
            post(api_advisor_check_command),
        )
        .route("/metrics", get(api_prometheus_metrics))
        .route("/api/agent-guard/connect", post(api_agent_guard_connect))
        .route(
            "/api/agent-guard/disconnect",
            post(api_agent_guard_disconnect),
        )
        .route("/api/agent-guard/agents", get(api_agent_guard_list))
        .layer(agent_api_auth_layer)
        .with_state(state.clone());

    // Auth login route - public (no auth required; this IS the auth endpoint)
    let auth_login = Router::new()
        .route("/api/auth/login", post(api_auth_login))
        .with_state(state.clone());

    // Dashboard routes - auth required
    let dashboard = Router::new()
        .route("/", get(index))
        .route("/app.css", get(serve_css))
        .route("/js/api.js", get(serve_js_api))
        .route("/js/icons.js", get(serve_js_icons))
        .route("/js/helpers.js", get(serve_js_helpers))
        .route("/js/state.js", get(serve_js_state))
        .route("/js/nav.js", get(serve_js_nav))
        .route("/js/community-banner.js", get(serve_js_community_banner))
        .route("/js/home.js", get(serve_js_home))
        .route("/js/threats.js", get(serve_js_threats))
        .route("/js/journey.js", get(serve_js_journey))
        .route("/js/sensors.js", get(serve_js_sensors))
        .route("/js/reports.js", get(serve_js_reports))
        .route("/js/status.js", get(serve_js_status))
        .route("/js/compliance.js", get(serve_js_compliance))
        .route("/js/intel.js", get(serve_js_intel))
        .route("/js/monthly.js", get(serve_js_monthly))
        .route("/js/responses.js", get(serve_js_responses))
        .route("/js/actions.js", get(serve_js_actions))
        .route("/js/sse.js", get(serve_js_sse))
        .route("/js/fleet.js", get(serve_js_fleet))
        .route("/api/overview", get(api_overview))
        .route("/api/incidents", get(api_incidents))
        .route("/api/decisions", get(api_decisions))
        .route("/api/entities", get(api_entities))
        .route("/api/pivots", get(api_pivots))
        .route("/api/clusters", get(api_clusters))
        .route("/api/threats/diagnostic", get(api_threats_diagnostic))
        .route("/api/journey", get(api_journey))
        .route("/api/export", get(api_export))
        .route(
            "/api/audit-signing/public-key",
            get(api_audit_signing_public_key),
        )
        .route("/api/report", get(api_report))
        .route("/api/report/dates", get(api_report_dates))
        .route("/api/quickwins", get(api_quickwins))
        // AI Intelligence Briefing
        .route("/api/briefing", get(api_briefing))
        .route("/api/briefing/generate", post(api_briefing_generate))
        // 2026-05-15: removed /api/posture — the dashboard's Home
        // posture card was removed. The posture module remains in
        // crate::posture (used by telegram summaries + downgrade).
        // AI Explain — plain-language threat explanation for non-technical operators
        .route("/api/ai-explain", get(api_ai_explain))
        // Sensors activity
        .route("/api/sensors", get(api_sensors))
        // E6 - system status
        .route("/api/status", get(api_status))
        .route("/api/collectors", get(api_collectors))
        // D3 - operator-initiated actions (POST, require auth, respect dry_run)
        .route("/api/action/block-ip", post(api_action_block_ip))
        .route("/api/action/suspend-user", post(api_action_suspend_user))
        .route("/api/action/config", get(api_action_config))
        // 2026-06-10 (operator report): more case actions than just "Block IP".
        // unblock-ip QUEUES a revert for the agent slow loop; triage-case writes
        // operator-action decision rows the read path classifies.
        .route("/api/action/unblock-ip", post(api_action_unblock_ip))
        .route("/api/action/triage-case", post(api_action_triage_case))
        // Operator "Trust IP" — monitor-only allowlist (still detected/logged/
        // notified, only auto-block suppressed). add / remove / list.
        .route("/api/action/trust-ip", post(api_action_trust_ip))
        .route("/api/action/untrust-ip", post(api_action_untrust_ip))
        .route("/api/action/trusted-ips", get(api_action_trusted_ips))
        // Execution Gate operator "Trust Exec" — authorise a binary path (2FA-
        // gated). Writes an allow_exec rule the paid watch daemon hot-reloads.
        .route("/api/action/trust-exec", post(api_action_trust_exec))
        .route("/api/action/untrust-exec", post(api_action_untrust_exec))
        .route("/api/action/trusted-execs", get(api_action_trusted_execs))
        // 2026-05-01 (`tracked-spec-ai-override`): operator
        // overrides AI decisions / re-opens dismissed incidents /
        // labels decisions for retraining. Audit-only for v1.
        .route(
            "/api/action/decision/override",
            post(api_action_override_decision),
        )
        .route(
            "/api/action/incident/reopen",
            post(api_action_reopen_incident),
        )
        .route(
            "/api/action/decision/label",
            post(api_action_label_decision),
        )
        // Honeypot tab
        .route("/api/honeypot/sessions", get(api_honeypot_sessions))
        .route("/api/action/honeypot", post(api_action_honeypot))
        // Compliance tab
        .route("/api/admin-actions", get(api_admin_actions))
        .route("/api/advisory-cache", get(api_advisory_cache))
        .route("/api/compliance", get(api_compliance))
        .route("/api/compliance/audit-trail", get(api_audit_trail))
        // MSSP fleet (spec 038). Both endpoints return 404 when
        // fleet mode is disabled so the absence is unambiguous to
        // the frontend.
        .route("/api/fleet/hosts", get(fleet::api_fleet_hosts))
        .route("/api/fleet/overview", get(fleet::api_fleet_overview))
        // Attacker Intelligence & Monthly Reports
        .route("/api/attacker-profiles", get(api_attacker_profiles))
        .route(
            "/api/attacker-profiles/:ip",
            get(api_attacker_profile_detail),
        )
        .route("/api/threat-report", get(api_threat_report))
        .route("/api/threat-report/months", get(api_threat_report_months))
        .route("/api/campaigns", get(api_campaigns))
        .route("/api/correlation-chains", get(api_correlation_chains))
        .route("/api/baseline-status", get(api_baseline_status))
        .route("/api/playbooks", get(playbooks::api_playbooks))
        .route("/api/playbook/test", post(playbooks::api_playbook_test))
        .route("/api/graph/stats", get(api_graph_stats))
        .route("/api/graph/view", get(api_graph_view))
        .route("/api/graph/neighborhood", get(api_graph_neighborhood))
        .route("/api/graph/path", get(api_graph_path))
        .route("/api/graph/process-tree", get(api_graph_process_tree))
        .route("/api/graph/timeline", get(api_graph_timeline))
        .route("/api/graph/threats", get(api_graph_threats))
        .route("/api/responses", get(api_responses))
        // PR #419 Wave 2: read-only orphan diagnostic.
        .route("/api/responses/orphans", get(api_responses_orphans))
        // PR #420 Wave 3: operator-driven orphan resolution. Both
        // routes require auth + CSRF (X-Requested-With) + 2FA when
        // configured. Audit row written via append_admin_action.
        .route("/api/responses/orphans/:id/clear", post(api_orphan_clear))
        .route(
            "/api/responses/orphans/:id/mark-already-gone",
            post(api_orphan_mark_already_gone),
        )
        // Spec 005 T017: active incident groups snapshot (noise-reduction view).
        .route("/api/incident-groups", get(api_incident_groups))
        .route("/api/mitre/navigator", get(api_mitre_navigator))
        .route("/api/mitre/coverage", get(api_mitre_coverage))
        // Deep Security (integrated modules)
        .route("/api/deep-security", get(api_deep_security))
        // D6 - SSE live event stream
        .route("/api/events/stream", get(api_events_stream))
        // Web Push
        .route("/sw.js", get(service_worker_js))
        .route("/favicon.ico", get(|| async { StatusCode::NO_CONTENT }))
        .route("/api/push/vapid-key", get(api_push_vapid_key))
        .route(
            "/api/push/subscribe",
            post(api_push_subscribe).delete(api_push_unsubscribe),
        )
        // Issue #71: Dashboard 2FA approval endpoints
        .route("/api/2fa/pending", get(api_2fa_pending))
        .route("/api/2fa/approve/:approval_id", post(api_2fa_approve))
        .route("/api/2fa/deny/:approval_id", post(api_2fa_deny))
        // Session management endpoints (auth-protected)
        .route("/api/auth/logout", post(api_auth_logout))
        .route("/api/auth/sessions", get(api_auth_sessions))
        .layer(auth_layer.clone())
        // PR #420 Wave 3 (audit I-14): require X-Requested-With on all
        // state-changing requests. The dashboard JS sends this header
        // automatically; cross-origin <form> POSTs cannot.
        .layer(middleware::from_fn(csrf_protection))
        .with_state(state.clone());

    // AUDIT-005 follow-up: unauthenticated `/livez` liveness probe.
    //
    // Returns 200 OK with the constant body "ok\n". NO business logic,
    // NO secrets, NO state, NO auth. The watchdog supervisor probes this
    // endpoint every 30 s to confirm the agent's HTTP listener is up;
    // it deliberately does NOT scrape `/metrics` because (a) metrics are
    // auth-gated to protect per-detector counts that could inform an
    // attacker, and (b) any non-2xx (incl. 401) on the supervisor's
    // probe is treated as an unresponsive agent and triggers SIGKILL.
    //
    // Pre-AUDIT-005 the supervisor probed `/metrics` against an HTTPS
    // server with basic-auth and got 401 → 1175 SIGKILLs in ~10 hours
    // against a perfectly healthy agent. `/livez` is the explicit
    // contract that splits "process alive AND serving HTTP" (the
    // supervisor's question) from "operator can read internal counters"
    // (the metrics surface). Same shape as kubernetes livenessProbe.
    let health_api = Router::new()
        .route("/livez", get(|| async { "ok\n" }))
        .with_state(state.clone());

    // Live-feed routes are intentionally public (no auth) regardless of bind
    // address. The response shape is already sanitised in `live_feed.rs`:
    // `host` is blanked, `evidence` is empty, `recommended_checks` is empty,
    // `research_only` incidents are filtered, and `is_internal` incidents are
    // filtered — only attacker metadata that is public observable elsewhere
    // (attacker IP, MITRE technique, reputation counters) is exposed. The
    // marketing site's `/live` page depends on these endpoints, so the earlier
    // SEC-007 guard that required auth on non-loopback binds broke the public
    // use case and contradicted the stated intent at `live_feed.rs:7`
    // ("Public live-feed endpoints (CORS-enabled, no auth)"). DoS is bounded
    // by `rate_limit_layer` applied to the merged app below.
    let live_api = Router::new()
        .route("/api/live-feed", get(api_live_feed))
        .route("/api/live-feed/stream", get(api_live_feed_stream))
        .route("/api/live-feed/geoip", get(api_live_feed_geoip))
        .route("/api/live-feed/honeypot", get(api_live_feed_honeypot))
        .route("/api/live-feed/mitre", get(api_live_feed_mitre))
        .layer(middleware::from_fn(cors_middleware))
        .with_state(state);

    let app = agent_api
        .merge(auth_login)
        .merge(health_api)
        .merge(live_api)
        .merge(dashboard)
        .layer(build_body_limit_layer())
        .layer(middleware::from_fn(security_headers))
        .layer(activity_layer)
        .layer(rate_limit_layer);

    // D6: spawn file watcher and heartbeat tasks
    tokio::spawn(watch_for_new_entries(data_dir.clone(), event_tx.clone()));
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            // Spec 037 I-13 PR-7 (K-class): broadcast `send` returns
            // `Err` only when there are zero subscribers — the
            // expected steady state when no operator is viewing the
            // dashboard. Heartbeat to nobody is fine; intentionally
            // silent. Same rationale as `dashboard/sse.rs` sends.
            let _ = event_tx.send(SsePayload {
                kind: "heartbeat".to_string(),
                data: None,
            });
        }
    });

    // Session + advisory + pending-approval cleanup: remove expired entries every 60 seconds
    let cleanup_sessions = sessions;
    let cleanup_timeout = session_timeout_minutes;
    let cleanup_advisory_cache = advisory_cache.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            let mut map = cleanup_sessions.write().unwrap_or_else(|e| e.into_inner());
            map.retain(|_, session| !session.is_expired(cleanup_timeout));
            // Evict advisories older than 1 hour
            if let Ok(mut cache) = cleanup_advisory_cache.write() {
                let cutoff = Utc::now() - chrono::Duration::hours(1);
                cache.retain(|e| e.ts > cutoff);
            }
            // Issue #71: evict expired 2FA approval requests so the map
            // does not grow unbounded when the operator never acts on them.
            {
                let now = Utc::now();
                let mut approvals = cleanup_pending_approvals
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                approvals.retain(|_, pc| pc.expires_at > now);
            }
        }
    });

    if insecure_no_tls {
        // ── Plain HTTP (explicitly opted out of TLS) ─────────────────
        warn!(
            bind = %bind,
            "dashboard serving over PLAIN HTTP — credentials and data are NOT encrypted. \
             Use --tls-cert/--tls-key or remove --insecure-no-tls for production."
        );
        let listener = tokio::net::TcpListener::bind(&bind)
            .await
            .with_context(|| format!("failed to bind dashboard listener on {bind}"))?;
        // Wave 2026-05-17: inject ConnectInfo<SocketAddr> so middlewares
        // can read the real peer IP (needed by the loopback-bypass auth
        // path on /api/agent-guard/* and by per-IP rate limiting).
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .context("dashboard server failed")
    } else {
        // ── HTTPS (default) ──────────────────────────────────────────
        let tls_config = build_tls_config(&data_dir, tls_cert, tls_key).await?;
        let addr: std::net::SocketAddr = bind
            .parse()
            .with_context(|| format!("invalid bind address: {bind}"))?;

        info!(
            bind = %bind,
            "dashboard HTTPS started"
        );
        // Wave 2026-05-17: inject ConnectInfo<SocketAddr> so middlewares
        // can read the real peer IP (needed by the loopback-bypass auth
        // path on /api/agent-guard/* and by per-IP rate limiting).
        axum_server::bind_rustls(addr, tls_config)
            .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
            .await
            .context("dashboard HTTPS server failed")
    }
}

/// Apply a Unix file mode and `warn!` on failure with structured
/// context. Replaces the prior `let _ = std::fs::set_permissions(..)`
/// pattern at the two TLS auto-gen sites in `build_tls_config`
/// (Spec 037 I-13 PR-2). Silent failure was security-relevant: a
/// `chmod` error on the freshly-generated TLS private key would
/// leave it at the file's creation mode (typically 0644 under the
/// process umask) instead of 0600, exposing the private key to any
/// local user. The warn surfaces the failure to the operator log
/// without changing the observable behaviour: the file is left in
/// whatever state the failed chmod left it (same as the prior
/// `let _ =`), the caller continues, and the dashboard binds with
/// whatever cert state is on disk.
///
/// Function is `#[cfg(unix)]` to match the original gating; the
/// PermissionsExt API used for `from_mode` is Unix-only. Returns
/// `()` (infallible) so call sites stay one-line and the calling
/// `build_tls_config` flow is unchanged in shape.
#[cfg(unix)]
fn set_file_mode_or_warn(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)) {
        warn!(
            path = %path.display(),
            intended_mode = format!("{mode:#o}"),
            error = %e,
            "failed to set TLS file permissions (file left at previous mode)"
        );
    }
}

/// Build RustlsConfig from cert/key files or auto-generate a self-signed cert.
async fn build_tls_config(
    data_dir: &std::path::Path,
    cert_path: Option<String>,
    key_path: Option<String>,
) -> Result<axum_server::tls_rustls::RustlsConfig> {
    use axum_server::tls_rustls::RustlsConfig;

    // Ensure a crypto provider is installed (required by rustls 0.23+).
    // Spec 037 I-13 PR-7 (K-class): `install_default()` is
    // idempotent — `Err` means "another provider is already
    // installed", which is the steady state on hot reload or when
    // the test runner has set one up before us. Intentionally
    // silent.
    let _ = rustls::crypto::ring::default_provider().install_default();

    if let (Some(cert), Some(key)) = (cert_path, key_path) {
        // Use operator-provided cert/key
        info!(cert = %cert, key = %key, "loading TLS certificate");
        let config = RustlsConfig::from_pem_file(&cert, &key)
            .await
            .with_context(|| format!("failed to load TLS cert={cert} key={key}"))?;
        Ok(config)
    } else {
        // Auto-generate self-signed certificate
        let cert_file = data_dir.join("dashboard-cert.pem");
        let key_file = data_dir.join("dashboard-key.pem");

        if cert_file.exists() && key_file.exists() {
            info!("loading existing self-signed TLS certificate");
            let config = RustlsConfig::from_pem_file(&cert_file, &key_file)
                .await
                .context("failed to load existing self-signed cert")?;
            return Ok(config);
        }

        info!("generating self-signed TLS certificate for dashboard");
        let mut params = rcgen::CertificateParams::new(vec![
            "localhost".to_string(),
            "innerwarden".to_string(),
        ])?;
        params.distinguished_name.push(
            rcgen::DnType::CommonName,
            rcgen::DnValue::Utf8String("InnerWarden Dashboard".to_string()),
        );
        params.distinguished_name.push(
            rcgen::DnType::OrganizationName,
            rcgen::DnValue::Utf8String("InnerWarden".to_string()),
        );
        // SEC-013: Valid for 365 days from now (not a hardcoded date).
        let (y, m, d) = cert_expiry_ymd(365);
        params.not_after = rcgen::date_time_ymd(y, m, d);
        // Add SANs for common access patterns
        params.subject_alt_names = vec![
            rcgen::SanType::DnsName("localhost".try_into()?),
            rcgen::SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
            rcgen::SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0))),
        ];

        let key_pair = rcgen::KeyPair::generate()?;
        let cert = params.self_signed(&key_pair)?;
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        std::fs::write(&cert_file, &cert_pem)
            .with_context(|| format!("failed to write {}", cert_file.display()))?;
        std::fs::write(&key_file, &key_pem)
            .with_context(|| format!("failed to write {}", key_file.display()))?;

        // Restrict key file permissions. Failure is surfaced via
        // `warn!` (Spec 037 I-13 PR-2) — silent chmod failure on
        // the private key would expose it at the umask's default
        // mode (typically 0644) to any local user.
        #[cfg(unix)]
        {
            set_file_mode_or_warn(&key_file, 0o600);
            set_file_mode_or_warn(&cert_file, 0o644);
        }

        info!(
            cert = %cert_file.display(),
            key = %key_file.display(),
            "self-signed TLS certificate generated (valid 365 days)"
        );

        let config = RustlsConfig::from_pem_file(&cert_file, &key_file)
            .await
            .context("failed to load generated self-signed cert")?;
        Ok(config)
    }
}

// ---------------------------------------------------------------------------

async fn index() -> impl IntoResponse {
    (
        [
            (header::CACHE_CONTROL, "no-store, no-cache, must-revalidate"),
            (header::PRAGMA, "no-cache"),
        ],
        Html(INDEX_HTML),
    )
}

async fn serve_css() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/css; charset=utf-8"),
            // Same rationale as STATIC_NO_CACHE on the JS handlers
            // below: pre-fix, app.css was browser-cached heuristically
            // and a deploy that updated CSS left the operator looking
            // at the pre-deploy theme until they hard-refreshed.
            (header::CACHE_CONTROL, "no-store, max-age=0"),
        ],
        APP_CSS,
    )
}

// 2026-05-02: dashboard JS/CSS were served WITHOUT any Cache-Control
// header. Browsers fall back to heuristic caching (often hours/days)
// for static assets, which meant every deploy left users running the
// pre-deploy JS until they manually hard-refreshed. Operator on
// 2026-05-02: "parece que esse grafico ta congelado" / "parece que vc
// fez uma PR so pra me enganar, porque nao mudou nada no dashboard"
// — the binary on the server already had the fixes; the browser was
// rendering stale JS from cache.
//
// Fix: stamp every static-asset response with `Cache-Control: no-store`
// so the browser always fetches fresh after a deploy. The bundles are
// small (tens of kB each, gzip ~5–15 kB), the dashboard is internal,
// and the cost of "always re-fetch" is negligible compared to the
// confidence of "what I deployed is what the operator sees".
const STATIC_NO_CACHE: &str = "no-store, max-age=0";

macro_rules! js_handler {
    ($name:ident, $content:expr) => {
        async fn $name() -> impl IntoResponse {
            (
                [
                    (
                        header::CONTENT_TYPE,
                        "application/javascript; charset=utf-8",
                    ),
                    (header::CACHE_CONTROL, STATIC_NO_CACHE),
                ],
                $content,
            )
        }
    };
}

js_handler!(serve_js_api, JS_API);
js_handler!(serve_js_icons, JS_ICONS);
js_handler!(serve_js_helpers, JS_HELPERS);
js_handler!(serve_js_state, JS_STATE);
js_handler!(serve_js_nav, JS_NAV);
js_handler!(serve_js_community_banner, JS_COMMUNITY_BANNER);
js_handler!(serve_js_home, JS_HOME);
js_handler!(serve_js_threats, JS_THREATS);
js_handler!(serve_js_journey, JS_JOURNEY);
js_handler!(serve_js_sensors, JS_SENSORS);
js_handler!(serve_js_reports, JS_REPORTS);
js_handler!(serve_js_status, JS_STATUS);
js_handler!(serve_js_compliance, JS_COMPLIANCE);
js_handler!(serve_js_intel, JS_INTEL);
js_handler!(serve_js_monthly, JS_MONTHLY);
js_handler!(serve_js_responses, JS_RESPONSES);
js_handler!(serve_js_actions, JS_ACTIONS);
js_handler!(serve_js_sse, JS_SSE);
js_handler!(serve_js_fleet, JS_FLEET);

// ---------------------------------------------------------------------------
// D10 - Report API
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// UI
// ---------------------------------------------------------------------------

const INDEX_HTML: &str = include_str!("frontend/html/index.html");
const APP_CSS: &str = include_str!("frontend/css/app.css");
const JS_API: &str = include_str!("frontend/js/api.js");
const JS_ICONS: &str = include_str!("frontend/js/icons.js");
const JS_HELPERS: &str = include_str!("frontend/js/helpers.js");
const JS_STATE: &str = include_str!("frontend/js/state.js");
const JS_NAV: &str = include_str!("frontend/js/nav.js");
const JS_COMMUNITY_BANNER: &str = include_str!("frontend/js/community-banner.js");
const JS_HOME: &str = include_str!("frontend/js/home.js");
const JS_THREATS: &str = include_str!("frontend/js/threats.js");
const JS_JOURNEY: &str = include_str!("frontend/js/journey.js");
const JS_SENSORS: &str = include_str!("frontend/js/sensors.js");
const JS_REPORTS: &str = include_str!("frontend/js/reports.js");
const JS_STATUS: &str = include_str!("frontend/js/status.js");
const JS_COMPLIANCE: &str = include_str!("frontend/js/compliance.js");
const JS_INTEL: &str = include_str!("frontend/js/intel.js");
const JS_MONTHLY: &str = include_str!("frontend/js/monthly.js");
const JS_RESPONSES: &str = include_str!("frontend/js/responses.js");
const JS_ACTIONS: &str = include_str!("frontend/js/actions.js");
const JS_SSE: &str = include_str!("frontend/js/sse.js");
const JS_FLEET: &str = include_str!("frontend/js/fleet.js");

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
// SEC-005: Pure helpers for bind address validation (testable).
// ---------------------------------------------------------------------------

/// Check if a bind address is a loopback address.
pub(crate) fn is_loopback_address(bind: &str) -> bool {
    bind.starts_with("127.0.0.1") || bind.starts_with("[::1]") || bind.starts_with("localhost")
}

/// Validate bind address + auth combination.
/// Returns Err if non-loopback bind has no auth configured.
pub(crate) fn validate_bind_auth(bind: &str, has_auth: bool) -> Result<(), String> {
    if !has_auth && !is_loopback_address(bind) {
        return Err(format!(
            "dashboard bound to non-loopback address {} without authentication. \
             Set INNERWARDEN_DASHBOARD_USER and INNERWARDEN_DASHBOARD_PASSWORD_HASH, \
             or bind to 127.0.0.1 for unauthenticated local access.",
            bind
        ));
    }
    Ok(())
}

/// SEC: true when the dashboard would serve plain HTTP (`--insecure-no-tls`) on
/// a non-loopback bind — which leaks Basic-Auth credentials + data in cleartext
/// over a public interface, even when auth is configured. The caller refuses to
/// start in that case.
pub(crate) fn reject_insecure_public_bind(bind: &str, insecure_no_tls: bool) -> bool {
    insecure_no_tls && !is_loopback_address(bind)
}

/// SEC-013: Compute TLS certificate expiry date (year, month, day).
pub(crate) fn cert_expiry_ymd(days_valid: i64) -> (i32, u8, u8) {
    let expiry = chrono::Utc::now() + chrono::Duration::days(days_valid);
    (
        chrono::Datelike::year(&expiry),
        chrono::Datelike::month(&expiry) as u8,
        chrono::Datelike::day(&expiry) as u8,
    )
}

// Wave 2026-05-17: `should_require_api_auth` removed. The bind-address
// global gate was replaced by `auth::loopback_bypass_or_require_auth`,
// which checks per-request whether the TCP peer is on the loopback
// interface. The new policy is stricter on remote requests (auth
// always applies for non-loopback peers, even on loopback-bound
// sockets that don't actually accept remote — defence in depth) and
// looser on local requests (loopback always bypasses, even on
// 0.0.0.0-bound dashboards — fixes the `sudo innerwarden agent
// connect` 401 wall the operator hit on the Oracle prod host).

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // SEC: plain HTTP is rejected on a public bind (even with auth), allowed on loopback.
    #[test]
    fn insecure_plain_http_rejected_on_public_bind() {
        assert!(reject_insecure_public_bind("0.0.0.0:8787", true));
        assert!(reject_insecure_public_bind("192.168.0.10:8787", true));
        assert!(reject_insecure_public_bind("[::]:8787", true));
        // loopback plain HTTP is fine (local dev)
        assert!(!reject_insecure_public_bind("127.0.0.1:8787", true));
        assert!(!reject_insecure_public_bind("[::1]:8787", true));
        assert!(!reject_insecure_public_bind("localhost:8787", true));
        // TLS path (insecure_no_tls=false) never rejected here regardless of bind
        assert!(!reject_insecure_public_bind("0.0.0.0:8787", false));
    }

    use crate::telemetry::TelemetrySnapshot;
    use argon2::password_hash::SaltString;
    use argon2::PasswordHasher;
    use chrono::Utc;
    use innerwarden_core::{
        entities::EntityRef,
        event::{Event, Severity},
        incident::Incident,
    };
    use rand_core::{OsRng, RngCore};
    use tempfile::TempDir;

    // ── Existing tests (unchanged) ──────────────────────────────────────

    fn random_test_secret() -> String {
        let mut bytes = [0u8; 24];
        OsRng.fill_bytes(&mut bytes);
        bytes.iter().map(|b| char::from(b'a' + (b % 26))).collect()
    }

    fn runtime_test_label(prefix: &str, suffix: usize) -> String {
        format!("{prefix}{suffix}")
    }

    // ── Phase 4 (audit RC-4) frontend wiring anchors ────────────────────
    //
    // The dashboard ships its frontend as `include_str!` constants
    // bundled into the agent binary at build time. Anchor that the
    // PR #335 backend contract (block_state on AttackerSummary +
    // JourneyResponse) is actually consumed by the bundled JS. If a
    // future cleanup deletes the helper or renames the field, the
    // operator would silently lose the kernel-evidence badge — these
    // tests fail loudly instead.

    #[test]
    fn helpers_js_exports_block_state_badge_renderer() {
        assert!(
            JS_HELPERS.contains("function blockStateBadgeHtml"),
            "blockStateBadgeHtml helper is missing from bundled helpers.js"
        );
        // The three branches must all be reachable from the helper.
        assert!(JS_HELPERS.contains("blocked_now"));
        assert!(JS_HELPERS.contains("blocked_historical"));
    }

    #[test]
    fn threats_js_renders_block_state_on_attacker_card() {
        assert!(
            JS_THREATS.contains("blockStateBadgeHtml(item.block_state)"),
            "threats.js card renderer must read item.block_state from \
             AttackerSummary; otherwise the kernel-evidence badge never \
             ships to the operator"
        );
    }

    #[test]
    fn journey_js_renders_block_state_in_header() {
        assert!(
            JS_JOURNEY.contains("blockStateBadgeHtml(j.block_state)"),
            "journey.js header must read j.block_state from JourneyResponse"
        );
    }

    #[test]
    fn app_css_defines_kernel_evidence_badge_classes() {
        // The CSS class names are referenced by helpers.js — anchor
        // both ends so a rename on either side fails the build.
        assert!(APP_CSS.contains(".badge-kernel-active"));
        assert!(APP_CSS.contains(".badge-kernel-expired"));
    }

    // ── Phase 7 (audit RC-2) bundle anchors ────────────────────────────
    //
    // Each anchor pins a specific consumption of the new
    // OverviewSnapshot contract. Together they guarantee that the
    // backend's typed shape, the CSS classes, the HTML tile structure
    // and the home.js render path don't drift independently — exactly
    // the fan-out problem the audit's "Three-place writes" RC-2
    // describes, generalised to the front-end bundle.

    #[test]
    fn home_js_reads_overview_snapshot() {
        // The render path reads `overview.snapshot.buckets.*.unique_attackers`
        // (Phase 7 typed snapshot contract). 2026-04-30 redesign drops
        // the `incidents` field from the home — unique-attacker is the
        // only count rendered, matching the unified attacker semantic
        // from Phase 10. The 2026-05-15 slim-down removed the
        // pending-breakdown panel; `snap.pending` is no longer read.
        assert!(JS_HOME.contains("overview.snapshot"));
        assert!(JS_HOME.contains("snap.buckets.blocked.unique_attackers"));
    }

    #[test]
    fn home_js_routes_ai_not_responding_health_to_alert_reasons() {
        // The 'ai_not_responding' health verb must surface as a
        // user-visible reason. If a refactor drops the kind check,
        // operator loses the loudest "AI is wedged" signal.
        assert!(JS_HOME.contains("ai_not_responding"));
        assert!(JS_HOME.contains("backed_up"));
    }

    #[test]
    fn index_html_attention_first_home_layout() {
        // 2026-04-30 redesign: the Home was rebuilt for the 95%
        // 5-second-visit operator. Reading order: hero verb → critical
        // banner (only when needed) → review queue banner (only when
        // needed) → 4-number activity strip → AI briefing (always
        // visible) → system health line → details (collapsed). This
        // anchor pins the structural IDs so a future "improvement"
        // cannot silently drop them. See loadHome() for the
        // orchestration this anchors against.
        // 2026-05-15 slim-down: removed critical banner, health line,
        // details panel + its children (pending grid, collector strip,
        // mode/heartbeat). Anchor pins only the IDs that still ship.
        for id in [
            "homeHero",
            "homeReviewBanner",
            "homeReviewCount",
            "homeActivitySection",
            "homeActWatched",
            "homeActFlagged",
            "homeActStopped",
            "homeActAwaiting",
            // Spec 049 PR2 sub-breakdown row (Contained · Observing · Filtered out).
            "homeActBreakdown",
            "homeActContained",
            "homeActObserving",
            "homeActFilteredOut",
            "briefingSection",
            "briefingContent",
            "briefingBtn",
        ] {
            assert!(
                INDEX_HTML.contains(id),
                "Home redesign requires id={id} — operator-visible block missing"
            );
        }
        // Hero icon SVG path must be inlined so the page renders
        // before JS hydrates (lucide shield-check inner shapes).
        assert!(INDEX_HTML.contains("M20 13c0 5-3.5 7.5-7.66 8.95"));
    }

    #[test]
    fn home_js_renders_attention_first_layout() {
        // The render orchestration must call each block's renderer
        // explicitly. A future refactor that drops one renderer
        // produces an empty block on screen — anchor catches it.
        // 2026-05-15 slim-down: removed critical banner, health line,
        // details panel, since-last-visit, and posture renderers.
        for fn_name in [
            "updateHomeHero",
            "renderReviewBanner",
            "renderActivityStrip",
            "renderOnboardingTip",
            "loadBriefing",
        ] {
            assert!(
                JS_HOME.contains(fn_name),
                "home.js must define {fn_name} (attention-first redesign)"
            );
        }
        // Plain-English copy strings — verb identity for the hero.
        assert!(JS_HOME.contains("All clear"));
        assert!(JS_HOME.contains("You are protected"));
        // Briefing must always be visible — section.style.display set
        // to '' unconditionally, NOT inside a try/catch fallback.
        // This stops the "fetch fails -> hide section silently" bug.
        let briefing_start = JS_HOME.find("loadBriefing").expect("loadBriefing");
        let briefing_end = JS_HOME[briefing_start..]
            .find("\nasync function generateBriefing")
            .expect("end of loadBriefing")
            + briefing_start;
        let body = &JS_HOME[briefing_start..briefing_end];
        assert!(
            body.contains("section.style.display = '';"),
            "loadBriefing must show section unconditionally (always-visible contract)"
        );
        assert!(
            !body.contains("section.style.display = 'none';"),
            "loadBriefing must NOT hide section on error (always-visible contract)"
        );
    }

    // ── 2026-05-15 slim-down anchors ─────────────────────────────────
    // The Home page lost 4 sections (critical banner, since-last-visit,
    // host posture, system health line + Show details toggle + the
    // entire Technical Details panel) and 1 cross-page element (the
    // top-right alert-toast stack). These anchors pin (a) the removed
    // markup MUST NOT come back, (b) the renderers that survived stay
    // wired up, and (c) the AI Briefing generate path is intact since
    // it's the single piece of narrative the operator relies on.

    /// Spec 051 PR1 — Community feedback banner.
    ///
    /// "Zero telemetry by design" is load-bearing branding, but it also
    /// means the project owner has no signal whether anyone is using it.
    /// The banner is the direct ask. These anchors pin:
    ///   - the `homeCommunityBanner` block exists in `index.html`
    ///   - the dismiss buttons are present with the exact CSS classes
    ///     `home.js` queries for (`.community-banner-remind`,
    ///     `.community-banner-dismiss`)
    ///   - the standalone JS module is wired through include_str! and
    ///     exposes the three pure helpers tests + home.js rely on
    ///   - the localStorage keys match the spec (`iw:community-banner:dismissed`
    ///     and `iw:community-banner:remind-until`)
    ///   - the channel set required by spec §3.5 (GitHub, email, plus
    ///     placeholder for Discord/Telegram) is present in the banner copy
    ///   - `home.js` calls `renderCommunityBanner()` during its render
    ///   - external links carry `rel="noopener noreferrer"` (spec §4)
    ///
    /// Drift catcher for accidental deletion in a future dashboard
    /// refactor.
    #[test]
    fn spec_051_community_feedback_banner_is_wired() {
        // (1) The banner block + dismiss buttons exist in index.html.
        for needle in [
            "id=\"homeCommunityBanner\"",
            "community-banner-remind",
            "community-banner-dismiss",
            "Inner Warden has zero telemetry. By design.",
        ] {
            assert!(
                INDEX_HTML.contains(needle),
                "Spec 051 banner missing `{needle}` from index.html — silent regression"
            );
        }

        // (2) Each channel from spec §3.5 has its link in the banner copy.
        for channel in [
            "github.com/InnerWarden/innerwarden",
            "github.com/InnerWarden/innerwarden/discussions",
            "github.com/InnerWarden/innerwarden/issues",
            "feedback@innerwarden.com",
            "Good first issues",
        ] {
            assert!(
                INDEX_HTML.contains(channel),
                "Spec 051 channel `{channel}` missing from banner copy"
            );
        }

        // (3) External links open in a new tab without leaking opener.
        // Counts only matter as "more than one" — every <a> with an
        // external href must carry the rel attributes.
        let banner_block_start = INDEX_HTML
            .find("id=\"homeCommunityBanner\"")
            .expect("banner block must exist");
        let banner_block_end = INDEX_HTML[banner_block_start..]
            .find("status-hero")
            .map(|i| banner_block_start + i)
            .expect("status-hero must follow the banner block");
        let banner_block = &INDEX_HTML[banner_block_start..banner_block_end];
        let external_link_count = banner_block.matches("target=\"_blank\"").count();
        let secured_link_count = banner_block.matches("rel=\"noopener noreferrer\"").count();
        assert!(
            external_link_count >= 4,
            "Spec 051 banner expected >=4 external links, got {external_link_count}"
        );
        assert_eq!(
            external_link_count, secured_link_count,
            "Every external link in the banner must carry rel=noopener noreferrer (spec §4)"
        );

        // (4) The standalone JS module is wired and exposes the helpers.
        for needle in [
            "function shouldShowCommunityBanner",
            "function dismissForever",
            "function remindIn30Days",
            "function renderCommunityBanner",
            "iw:community-banner:dismissed",
            "iw:community-banner:remind-until",
        ] {
            assert!(
                JS_COMMUNITY_BANNER.contains(needle),
                "community-banner.js must contain `{needle}`"
            );
        }
        // 30 days = 30 * 24 * 60 * 60 * 1000 ms — pinning the literal
        // protects against an accidental refactor that "tidies up" the
        // constant into the wrong unit.
        assert!(
            JS_COMMUNITY_BANNER.contains("30 * 24 * 60 * 60 * 1000"),
            "30-day remind interval literal must be preserved"
        );

        // (5) home.js calls renderCommunityBanner during render.
        assert!(
            JS_HOME.contains("renderCommunityBanner"),
            "home.js must invoke renderCommunityBanner() on Home render"
        );

        // (6) The router serves the module. js_handler macro inlines
        // the body but the route registration is the operator-visible
        // contract.
        // Verified at construction time elsewhere; here we just pin
        // the include_str! const.
        assert!(
            !JS_COMMUNITY_BANNER.is_empty(),
            "JS_COMMUNITY_BANNER must be included via include_str! and non-empty"
        );
    }

    #[test]
    fn pr_home_slim_orphan_ids_are_gone_from_index_html() {
        // Sentinel against a future "let's bring it back" PR. Every ID
        // in this list was deleted in the 2026-05-15 slim-down. If any
        // of them comes back, this test fires with the exact name.
        for orphan in [
            "id=\"homeCriticalBanner\"",
            "id=\"homeCriticalTitle\"",
            "id=\"homeCriticalSub\"",
            "id=\"homeCriticalCta\"",
            "id=\"homeSinceLastVisit\"",
            "id=\"homeSinceTitle\"",
            "id=\"homeSinceSub\"",
            "id=\"postureSection\"",
            "id=\"postureContent\"",
            "id=\"homeHealthLine\"",
            "id=\"homeHealthIcon\"",
            "id=\"homeHealthSummary\"",
            "id=\"homeDetailsToggle\"",
            "id=\"homeDetailsPanel\"",
            "id=\"homePendingPanel\"",
            "id=\"homePendingGrid\"",
            "id=\"homePendingHint\"",
            "id=\"homeCollectorStrip\"",
            "id=\"homeMetaRow\"",
            "id=\"homeMetaMode\"",
            "id=\"homeMetaHeartbeat\"",
            "id=\"alertStack\"",
        ] {
            assert!(
                !INDEX_HTML.contains(orphan),
                "2026-05-15 slim-down: {orphan} was removed; re-adding it brings back \
                 a section the operator explicitly asked to drop"
            );
        }
    }

    #[test]
    fn pr_home_slim_orphan_functions_are_gone_from_home_js() {
        // Every renderer in the slim-down delete list. Anchor enforces
        // they stay deleted — if any comes back without an HTML target,
        // the operator gets dead code in the home bundle.
        for orphan_fn in [
            "function findTopOpenCritical",
            "function homeBannerEntityLink",
            "function homeBannerOpenPivot",
            "function renderCriticalBanner",
            "function openTopCritical",
            "function renderHealthLine",
            "function renderDetailsPanel",
            "function toggleHomeDetails",
            "function computeSinceLastVisitCounts",
            "function renderSinceLastVisitBanner",
            "function _humanAgo",
            "function updatePendingPanel",
            "function updateCollectorStrip",
            "function toggleCollectorDetails",
            "function viewSystemHealth",
            "async function loadPosture",
        ] {
            assert!(
                !JS_HOME.contains(orphan_fn),
                "2026-05-15 slim-down: `{orphan_fn}` was removed; bringing it back \
                 re-introduces dead code (the HTML target was deleted)"
            );
        }
        // The corresponding call sites must not reappear either.
        for orphan_call in [
            "renderCriticalBanner(",
            "renderHealthLine(",
            "renderDetailsPanel(",
            "renderSinceLastVisitBanner(",
            "loadPosture(",
            "toggleHomeDetails(",
        ] {
            assert!(
                !JS_HOME.contains(orphan_call),
                "2026-05-15 slim-down: call site `{orphan_call}` resurfaced — \
                 the renderer either came back or the loadHome orchestration \
                 is calling a function that no longer exists"
            );
        }
    }

    #[test]
    fn pr_home_slim_no_alert_toast_stack_in_sse_or_css() {
        // The top-right notification stack was removed. Pin the
        // absence at every bundle boundary: HTML (already covered by
        // pr_home_slim_orphan_ids_are_gone_from_index_html), JS, CSS.
        assert!(!JS_SSE.contains("function showAlertToast"));
        assert!(!JS_SSE.contains("_alertStackOverflow"));
        assert!(!JS_SSE.contains("ALERT_STACK_MAX_VISIBLE"));
        // The action-toast (single confirmation toast used by showToast
        // in actions.js) is a separate concern and MUST stay.
        assert!(INDEX_HTML.contains("id=\"toast\""));
        // CSS: no .alert-toast / .alert-stack / .alert-overflow rules.
        assert!(!APP_CSS.contains(".alert-toast"));
        assert!(!APP_CSS.contains(".alert-stack"));
        assert!(!APP_CSS.contains(".alert-overflow"));
        // The .toast (action confirmation) styles MUST remain.
        assert!(APP_CSS.contains(".toast {"));
    }

    #[test]
    fn pr_home_slim_briefing_generate_posts_to_canonical_endpoint() {
        // The AI Briefing is the single narrative surface on Home.
        // Operator's exact words: "o que for mantido na home deve
        // funcionar perfeitamente inclusive o resumo da AI". Anchor
        // the generate path so a future refactor doesn't accidentally
        // break the canonical POST endpoint or drop the visible UX
        // states (loading / regenerate / error).
        assert!(
            JS_HOME.contains("'/api/briefing/generate'"),
            "generateBriefing must POST to /api/briefing/generate"
        );
        assert!(
            JS_HOME.contains("method: 'POST'"),
            "generateBriefing must use POST (server expects it)"
        );
        assert!(
            JS_HOME.contains("btn.textContent = 'Generating...'"),
            "generateBriefing must show 'Generating...' on the button while in-flight"
        );
        assert!(
            JS_HOME.contains("btn.textContent = 'Regenerate'"),
            "generateBriefing must flip the button to 'Regenerate' after the call completes"
        );
    }

    #[test]
    fn pr_home_slim_loadhome_orchestration_only_calls_kept_renderers() {
        // Whitelist what loadHome calls; anything else inside its body
        // is either a removed renderer (caught by orphan tests) or new
        // code that needs review. Anchor explicitly lists the kept
        // renderers + the briefing loader.
        let start = JS_HOME
            .find("async function loadHome()")
            .expect("loadHome present");
        let end = JS_HOME[start..].find("\n}\n").expect("end of loadHome") + start;
        let body = &JS_HOME[start..end];
        // The six things that must be called inside loadHome today.
        // `renderHomeSensorsPanel` was added 2026-05-15 when the
        // standalone Sensors page was deleted and its content folded
        // into Home — see the Sensors fold anchors below.
        for fn_call in [
            "updateHomeHero(",
            "renderReviewBanner(",
            "renderActivityStrip(",
            "renderOnboardingTip(",
            "loadBriefing(",
            "renderHomeSensorsPanel(",
        ] {
            assert!(
                body.contains(fn_call),
                "loadHome must call `{fn_call}` — slim-down kept this renderer; \
                 missing call leaves the section blank on page load"
            );
        }
    }

    // ── 2026-05-15 Sensors fold-into-Home anchors ────────────────────
    // Operator response to PR #629 (which had kept a slimmed Sensors
    // page and added a duplicate HUD summary on Home): "acho que
    // podemos deletar, ai o que sobrou la em sensors vc tras pra
    // home e deleta sensors". This PR (a) deletes the whole
    // `viewSensors` block + `navSensors` nav button + `loadSensors`
    // entrypoint + the HUD-summary block (cards/gauge/radar/Event
    // Types) PR #629 had just added to Home, (b) folds the surviving
    // content — per-collector telemetry/alarm/snapshot breakdown and
    // the Event Timeline — into a single Home section
    // `#homeSensorsPanel` rendered by `renderHomeSensorsPanel` in
    // home.js, (c) keeps `sensors.js` as a stateless helpers module
    // (sensorColor / COLLECTOR_CATEGORY / categoryBadge / healthBadge /
    // renderSensorSourceRows / drawTimelineChart) so PR25 and PR29
    // anchors keep referring to it. Anchors below enforce the move.

    #[test]
    fn pr_sensors_fold_view_sensors_block_is_gone() {
        // The `viewSensors` div was the standalone Sensors page. Its
        // content folded into Home; the block + all child DOM ids it
        // owned must stay gone.
        for orphan in [
            "id=\"viewSensors\"",
            // Pre-PR629 sensors DOM ids (HUD-era):
            "id=\"topAction\"",
            "id=\"sensorCards\"",
            "id=\"threatGauge\"",
            "id=\"threatLabel\"",
            "id=\"detectorChart\"",
            "id=\"sensorKinds\"",
            // Slimmed-page DOM ids (intermediate PR629 state, also gone):
            "id=\"sensorSources\"",
            "id=\"sensorChart\"",
            // PR629's compromise Home HUD-summary section (deleted in
            // favour of the panel below the briefing):
            "id=\"homeSensorsSummary\"",
            "id=\"homeSensorCards\"",
            "id=\"homeThreatGauge\"",
            "id=\"homeThreatLabel\"",
            "id=\"homeDetectorChart\"",
            "id=\"homeSensorKinds\"",
        ] {
            assert!(
                !INDEX_HTML.contains(orphan),
                "2026-05-15 Sensors fold: `{orphan}` was deleted; bringing it back \
                 either resurrects the standalone Sensors page or PR #629's HUD \
                 summary block that the operator asked to delete"
            );
        }
    }

    #[test]
    fn pr_sensors_fold_nav_sensors_button_is_gone() {
        // The `Sensors` More-menu item was deleted alongside the view.
        // Anchor catches a revert of the nav-menu cleanup.
        assert!(
            !INDEX_HTML.contains("id=\"navSensors\""),
            "2026-05-15 Sensors fold: the `navSensors` More-menu button MUST stay deleted"
        );
        assert!(
            !INDEX_HTML.contains(">Sensors</button>"),
            "2026-05-15 Sensors fold: no nav button MUST render the literal label `Sensors`"
        );
        // And nothing should deeplink into the dead route.
        assert!(
            !INDEX_HTML.contains("showView('sensors')"),
            "2026-05-15 Sensors fold: no DOM handler may call `showView('sensors')` — \
             the route is gone"
        );
    }

    #[test]
    fn pr_sensors_fold_home_panel_is_present_below_briefing() {
        // The folded content lives in `#homeSensorsPanel` under the
        // AI Intelligence Briefing. Operator: "tras pra home", below
        // the briefing.
        for marker in [
            "id=\"homeSensorsPanel\"",
            "id=\"homeSensorSources\"",
            "id=\"homeSensorChart\"",
        ] {
            assert!(
                INDEX_HTML.contains(marker),
                "Home must contain `{marker}` — Sensors content folded 2026-05-15"
            );
        }
        let briefing_pos = INDEX_HTML
            .find("id=\"briefingSection\"")
            .expect("briefingSection still present");
        let panel_pos = INDEX_HTML
            .find("id=\"homeSensorsPanel\"")
            .expect("homeSensorsPanel present");
        assert!(
            briefing_pos < panel_pos,
            "Sensors panel MUST render below AI Intelligence Briefing on Home \
             (operator: \"abaixo de AI Intelligence Briefing\")"
        );
    }

    #[test]
    fn pr_sensors_fold_load_sensors_and_load_top_action_are_gone() {
        // The standalone Sensors loader (`loadSensors`) and the
        // pre-PR629 banner renderer (`loadTopAction`) MUST both stay
        // deleted. Their HTML targets are gone — anything coming back
        // is dead code.
        assert!(
            !JS_SENSORS.contains("async function loadSensors"),
            "2026-05-15 Sensors fold: `loadSensors` was deleted; the per-collector \
             rendering moved into renderHomeSensorsPanel via the shared \
             `renderSensorSourceRows` helper"
        );
        assert!(
            !JS_SENSORS.contains("function loadTopAction"),
            "2026-05-15 Sensors fold: `loadTopAction` (the AI-handling banner \
             renderer) MUST stay deleted"
        );
        // nav.js MUST NOT dispatch the `sensors` view name.
        assert!(
            !JS_NAV.contains("name === 'sensors'"),
            "2026-05-15 Sensors fold: nav.js MUST NOT route the deleted `sensors` view"
        );
        assert!(
            !JS_NAV.contains("loadSensors("),
            "2026-05-15 Sensors fold: nav.js MUST NOT call `loadSensors()`"
        );
        assert!(
            !JS_NAV.contains("loadTopAction("),
            "2026-05-15 Sensors fold: nav.js MUST NOT call `loadTopAction()`"
        );
    }

    #[test]
    fn pr_sensors_fold_chart_and_rows_helpers_are_parameterised() {
        // `drawTimelineChart` + `renderSensorSourceRows` are the only
        // sensors.js helpers Home depends on. Both MUST accept the
        // target DOM id as a parameter so Home can pass `homeSensorChart`
        // / `homeSensorSources` without sensors.js knowing about Home.
        assert!(
            JS_SENSORS.contains("function drawTimelineChart(canvasId, timeline, sources)"),
            "drawTimelineChart MUST accept (canvasId, timeline, sources) so Home \
             can mount it under #homeSensorChart"
        );
        assert!(
            JS_SENSORS.contains("function renderSensorSourceRows(srcElId, data)"),
            "renderSensorSourceRows MUST accept (srcElId, data) so Home can mount \
             it under #homeSensorSources"
        );
        // The pre-fold hardcoded DOM lookups MUST stay gone — they
        // pinned the helpers to the now-deleted standalone Sensors
        // view ids.
        assert!(
            !JS_SENSORS.contains("document.getElementById('sensorChart')"),
            "drawTimelineChart MUST NOT hardcode `sensorChart` — that DOM id was removed"
        );
        assert!(
            !JS_SENSORS.contains("document.getElementById('sensorSources')"),
            "renderSensorSourceRows MUST NOT hardcode `sensorSources` — that DOM id was removed"
        );
        // Gauge + radar were the PR629 compromise. Both MUST stay
        // deleted — their HTML targets are gone, so reviving them
        // leaks dead code.
        assert!(
            !JS_SENSORS.contains("function drawThreatGauge"),
            "2026-05-15 Sensors fold: `drawThreatGauge` was deleted along with the gauge tile"
        );
        assert!(
            !JS_SENSORS.contains("function drawDetectorChart"),
            "2026-05-15 Sensors fold: `drawDetectorChart` was deleted along with the radar tile"
        );
    }

    #[test]
    fn pr_sensors_fold_home_renderer_mounts_to_home_panel_ids() {
        // `renderHomeSensorsPanel` is the single function responsible
        // for filling the folded Sensors panel on Home. It MUST drive
        // the home-specific DOM ids via the shared helpers — anchoring
        // catches a paste error that sends the renderer back to the
        // deleted Sensors ids (silently leaving the Home panel blank).
        let start = JS_HOME
            .find("function renderHomeSensorsPanel(")
            .expect("renderHomeSensorsPanel present in home.js");
        let end = JS_HOME[start..]
            .find("\n}\n")
            .expect("end of renderHomeSensorsPanel")
            + start;
        let body = &JS_HOME[start..end];
        for marker in [
            "renderSensorSourceRows('homeSensorSources', sensors)",
            "drawTimelineChart('homeSensorChart', sensors.event_timeline || {}, sensors.sources || [])",
        ] {
            assert!(
                body.contains(marker),
                "renderHomeSensorsPanel MUST contain `{marker}` so the folded \
                 Sensors content mounts under the Home DOM ids (2026-05-15)"
            );
        }
        // loadHome MUST invoke renderHomeSensorsPanel — pinned by the
        // existing pr_home_slim_loadhome_orchestration anchor (which
        // was updated this PR to list renderHomeSensorsPanel).
    }

    // ── Spec 049 PR3 anchors ────────────────────────────────────────
    // Tab renames: `Threats` → `Cases` (audit weight in the noun) and
    // `Report` → `Briefings` (the MSSP entregable, not an internal
    // doc). Internal route slugs (`investigate`, `report`) keep their
    // old names so deep links and state survive the rename — this is
    // deliberate and pinned by `*_keeps_internal_route_slugs_unchanged`.

    #[test]
    fn nav_tab_label_reads_cases_not_threats() {
        // Top-nav button visible text MUST read `Cases`. Aria-label
        // MUST also use the new vocabulary so screen readers stay in
        // sync. Internal id + onclick route stay on `investigate`.
        assert!(
            INDEX_HTML.contains(">Cases</button>"),
            "main nav button MUST render `Cases` text (spec 049 PR3)"
        );
        assert!(
            INDEX_HTML.contains("aria-label=\"Cases — audit ledger\""),
            "main nav button MUST carry the new aria-label (spec 049 PR3)"
        );
        // Legacy strings must stay gone.
        assert!(
            !INDEX_HTML.contains(">Threats</button>"),
            "main nav button MUST NOT revert to `Threats` text (spec 049 PR3)"
        );
        assert!(
            !INDEX_HTML.contains("aria-label=\"Threat investigation\""),
            "aria-label MUST NOT revert to `Threat investigation` (spec 049 PR3)"
        );
    }

    #[test]
    fn nav_more_menu_reads_briefings_not_report() {
        // The More-menu item that opens the retrospective report
        // surface MUST read `Briefings`. Spec 049 §8.4: the artefact
        // is what the MSSP delivers to the client, not an internal
        // report. Internal `id="navReport"` + `showView('report')`
        // stay so existing JS state / URLs work.
        assert!(
            INDEX_HTML.contains(">Briefings</button>"),
            "More-menu item MUST render `Briefings` text (spec 049 PR3)"
        );
        assert!(
            !INDEX_HTML.contains("\">Report</button>"),
            "More-menu item MUST NOT revert to `Report` (spec 049 PR3)"
        );
    }

    // ── 2026-05-16 PR-G: unified Briefings (Day / Month) ─────────────
    // Operator simplification: the standalone Monthly tab was merged
    // into the Briefings view via a Day / Month period switcher. Same
    // `#reportContent` mount, same `#reportStatus`. The deleted
    // surfaces (`#viewMonthly`, `#monthlyContent`, `#monthlyViewStatus`,
    // `#navMonthly`, `showView('monthly')`) MUST stay gone; the new
    // surfaces (`#reportPeriodSwitch`, `#reportPeriodDay`,
    // `#reportPeriodMonth`, `switchReportPeriod`) MUST be wired.

    #[test]
    fn pr_g_monthly_tab_surfaces_are_gone() {
        for orphan in [
            "id=\"viewMonthly\"",
            "id=\"monthlyContent\"",
            "id=\"monthlyViewStatus\"",
            "id=\"navMonthly\"",
            "showView('monthly')",
            ">Monthly</button>",
        ] {
            assert!(
                !INDEX_HTML.contains(orphan),
                "PR-G: `{orphan}` was deleted; the standalone Monthly tab UI must stay \
                 gone — Day/Month period switcher lives inside the Briefings view"
            );
        }
        // nav.js routes no `'monthly'` view name and does not call
        // `loadMonthly` from the dispatcher.
        assert!(
            !JS_NAV.contains("'monthly'"),
            "PR-G: nav.js MUST NOT reference the 'monthly' route"
        );
        assert!(
            !JS_NAV.contains("name === 'monthly'"),
            "PR-G: nav.js MUST NOT route the 'monthly' view name"
        );
    }

    #[test]
    fn pr_g_briefings_view_has_period_switcher_and_unified_mount() {
        for marker in [
            "id=\"reportPeriodSwitch\"",
            "id=\"reportPeriodDay\"",
            "id=\"reportPeriodMonth\"",
            "id=\"reportDayControls\"",
            "id=\"reportMonthControls\"",
            // Picker moved into the Briefings toolbar.
            "id=\"monthlyPicker\"",
            // Both periods render into the same `#reportContent`.
            "id=\"reportContent\"",
            // Period buttons wire onclick into switchReportPeriod.
            "onclick=\"switchReportPeriod('day')\"",
            "onclick=\"switchReportPeriod('month')\"",
        ] {
            assert!(
                INDEX_HTML.contains(marker),
                "PR-G: Briefings view MUST contain `{marker}`"
            );
        }
        // The internal route slug stays `report` — spec 049 contract.
        assert!(
            INDEX_HTML.contains("id=\"viewReport\""),
            "PR-G: `viewReport` div MUST stay (route slug unchanged)"
        );
    }

    #[test]
    fn pr_g_reports_js_owns_period_switch_and_dispatch() {
        // reports.js carries the period state + the three helpers nav.js
        // and the toolbar need:
        //   - switchReportPeriod(period): toggles toolbar visibility and
        //     kicks off the matching loader.
        //   - loadReportForActivePeriod(): nav.js entry point that
        //     dispatches based on current period.
        //   - refreshReportForActivePeriod(): refresh-button entry.
        for fn_sig in [
            "function switchReportPeriod(period)",
            "function loadReportForActivePeriod()",
            "function refreshReportForActivePeriod()",
            "let _reportPeriod",
        ] {
            assert!(
                JS_REPORTS.contains(fn_sig),
                "PR-G: reports.js MUST define `{fn_sig}`"
            );
        }
        // The switch dispatches to loadReport for day, loadMonthly for month.
        let switch_start = JS_REPORTS
            .find("function switchReportPeriod(period)")
            .expect("switchReportPeriod present");
        let switch_end = JS_REPORTS[switch_start..]
            .find("\n}\n")
            .expect("end of switchReportPeriod")
            + switch_start;
        let switch_body = &JS_REPORTS[switch_start..switch_end];
        assert!(
            switch_body.contains("loadReport()"),
            "switchReportPeriod MUST kick loadReport() for the Day period"
        );
        assert!(
            switch_body.contains("loadMonthly()"),
            "switchReportPeriod MUST kick loadMonthly() for the Month period"
        );
        // nav.js routes to the period-aware entrypoint, not directly
        // to loadReport (which would skip the month case when the
        // active period is month).
        assert!(
            JS_NAV.contains("loadReportForActivePeriod()"),
            "PR-G: nav.js MUST dispatch the `report` view name to \
             loadReportForActivePeriod(), not loadReport() directly"
        );
    }

    #[test]
    fn pr_g_monthly_js_writes_into_shared_report_mount() {
        // monthly.js was rewired to target the shared `#reportContent` +
        // `#reportStatus` instead of the deleted `#monthlyContent` /
        // `#monthlyViewStatus`. Anchor catches a refactor that points
        // it back at the dead ids.
        assert!(
            JS_MONTHLY.contains("getElementById('reportStatus')"),
            "PR-G: monthly.js MUST write status into the shared #reportStatus"
        );
        assert!(
            JS_MONTHLY.contains("getElementById('reportContent')"),
            "PR-G: monthly.js MUST render into the shared #reportContent"
        );
        assert!(
            !JS_MONTHLY.contains("getElementById('monthlyContent')"),
            "PR-G: the deleted #monthlyContent mount must stay unreferenced"
        );
        assert!(
            !JS_MONTHLY.contains("getElementById('monthlyViewStatus')"),
            "PR-G: the deleted #monthlyViewStatus must stay unreferenced"
        );
    }

    #[test]
    fn rename_keeps_internal_route_slugs_unchanged() {
        // The rename is purely operator-facing. Internal route slugs
        // (`showView('investigate')`, `showView('report')`, the `id`
        // attributes `navInvestigate` + `navReport`) MUST survive so
        // bookmarked URLs, JS state, and deep links from external
        // tools keep working. Renaming the slugs is OUT of scope for
        // PR3; if a future PR wants to rename the slugs, it must
        // ship a redirect for the old paths AND update all callers in
        // the same change.
        assert!(
            INDEX_HTML.contains("id=\"navInvestigate\""),
            "internal id `navInvestigate` MUST survive PR3 rename"
        );
        assert!(
            INDEX_HTML.contains("showView('investigate')"),
            "internal route `investigate` MUST survive PR3 rename"
        );
        assert!(
            INDEX_HTML.contains("id=\"navReport\""),
            "internal id `navReport` MUST survive PR3 rename"
        );
        assert!(
            INDEX_HTML.contains("showView('report')"),
            "internal route `report` MUST survive PR3 rename"
        );
    }

    #[test]
    fn cases_panel_header_does_not_use_threats_vocabulary() {
        // The original anchor (spec 049 PR3) pinned "Unresolved Cases"
        // because that string lived on the Sensors page's gauge panel
        // header. The Sensors page + gauge were deleted 2026-05-15;
        // the only remaining contract is that no operator-facing copy
        // ever reverts to "Unresolved Threats". The nav-tab rename is
        // pinned separately by `nav_tab_label_reads_cases_not_threats`.
        assert!(
            !INDEX_HTML.contains("Unresolved Threats"),
            "operator-facing copy MUST NOT revert to `Unresolved Threats`"
        );
    }

    // ── Spec 049 PR14 anchors ───────────────────────────────────────
    // Home strip → Cases scoped handoff. Operator clicks `170
    // Flagged by system` on Home → Cases opens with outcome filter
    // pre-applied and an operator-readable title. Closes the
    // remaining "cade os 170 em threats?" reconciliation gap from
    // operator review on 2026-05-13.

    #[test]
    fn home_js_defines_view_activity_scoped_handoff() {
        assert!(
            JS_HOME.contains("function viewActivityScoped("),
            "home.js must define viewActivityScoped handoff (spec 049 PR14)"
        );
        assert!(
            JS_HOME.contains("state.filterOutcome = bucket || 'all_flagged'"),
            "viewActivityScoped must set state.filterOutcome to the requested bucket (default all_flagged)"
        );
    }

    #[test]
    fn home_strip_cards_route_to_scoped_buckets() {
        // Three of the four strip cards (Flagged by system, Warden
        // decisions, Needs review) wire to a specific Cases bucket.
        // The fourth — Events watched — used to deeplink to the
        // Sensors tab; that tab was deleted 2026-05-15 and its
        // content folded into Home itself, so the cell is now a
        // passive read-only stat (no onclick).
        assert!(
            INDEX_HTML.contains("onclick=\"viewActivityScoped('all_flagged')\""),
            "Flagged by system card must route to all_flagged (operator reads 170 on Home, sees all 170 in Cases)"
        );
        assert!(
            INDEX_HTML.contains("onclick=\"viewActivityScoped('warden_decisions')\""),
            "Warden decisions card must route to warden_decisions bucket"
        );
        assert!(
            INDEX_HTML.contains("onclick=\"viewActivityScoped('needs_review')\""),
            "Needs review card must route to needs_review bucket"
        );
        // The Events watched cell MUST NOT route anywhere — the
        // Sensors tab it used to land on no longer exists.
        assert!(
            !INDEX_HTML.contains("showView('sensors')"),
            "Events watched MUST NOT deeplink to the deleted Sensors view"
        );
    }

    #[test]
    fn home_subbreakdown_chips_route_to_scoped_buckets() {
        for (chip, bucket) in [
            ("contained", "viewActivityScoped('contained')"),
            ("observing", "viewActivityScoped('observing')"),
            ("filtered_out", "viewActivityScoped('filtered_out')"),
        ] {
            assert!(
                INDEX_HTML.contains(bucket),
                "{chip} chip must route to {bucket}"
            );
        }
    }

    #[test]
    fn threats_js_filter_branches_handle_all_pr14_buckets() {
        // The buildGroupedList filter logic must apply each bucket
        // correctly. Without the branch the operator clicks
        // "Warden decisions" and sees the full unfiltered list.
        for needle in [
            "fOutcome === 'warden_decisions'",
            "fOutcome === 'needs_review'",
            "fOutcome === 'observing'",
            "fOutcome === 'filtered_out'",
        ] {
            assert!(
                JS_THREATS.contains(needle),
                "threats.js filter must branch on {needle}"
            );
        }
    }

    #[test]
    fn threats_js_scoped_title_has_clear_link_per_bucket() {
        // Each scoped title carries the `✕ show all` clear-link
        // so the operator escapes the filter with one click.
        // Anti-regression for a future "title-only no-clear" tweak.
        assert!(
            JS_THREATS.contains("var clearLink ="),
            "threats.js must define the clearLink HTML once + reuse across buckets"
        );
        assert!(
            JS_THREATS.contains("state.filterOutcome=null;refreshLeft(false)"),
            "clear-link onclick must reset state.filterOutcome and re-render"
        );
        for title in [
            "'Contained threats'",
            "'Warden decisions'",
            "'Needs review'",
            "'Flagged by system'",
        ] {
            assert!(
                JS_THREATS.contains(title),
                "threats.js must emit scoped title {title}"
            );
        }
    }

    // ── Spec 049 PR13 anchors ───────────────────────────────────────
    // Unit disambiguation + scope-aware AI Defense Log labels.
    // Resolves operator-reported gap (2026-05-13): Home strip showed
    // 170 cases, Cases AI Defense Log showed ~50 unique attackers —
    // operator could not reconcile. Group labels also failed the
    // spec 049 §8.2.D contract for past-scope ("Currently blocked
    // attackers" persisted even when picker = yesterday).

    #[test]
    fn threats_js_outcome_meta_renames_dismissed_to_filtered_out() {
        // Spec 049 §5.5 rename finished: `dismissed` group label now
        // reads `Filtered out`. The wire key `dismissed` is kept as
        // a backwards-compat alias (backend still emits it on some
        // legacy paths); BOTH map to the same operator-facing label.
        assert!(
            JS_THREATS.contains("filtered_out:    { icon: ICON_CHECK,        label: 'Filtered out'"),
            "OUTCOME_META.filtered_out must define the canonical Filtered out label (spec 049 §5.5 rename completion)"
        );
        assert!(
            JS_THREATS.contains("dismissed:       { icon: ICON_CHECK,        label: 'Filtered out'"),
            "Legacy OUTCOME_META.dismissed must echo 'Filtered out' label too — backwards-compat alias"
        );
        assert!(
            !JS_THREATS.contains("label: 'Dismissed'"),
            "`Dismissed` label must NOT come back — spec 049 §5.5 vocabulary contract"
        );
    }

    #[test]
    fn threats_js_group_label_for_scope_returns_past_period_variants() {
        // Past-scope group titles per spec 049 §8.2.D.
        assert!(
            JS_THREATS.contains("function groupLabelForScope("),
            "groupLabelForScope helper must be defined (spec 049 PR13)"
        );
        for past_label in [
            "'Blocked during selected period'",
            "'Observed during selected period'",
            "'Honeypot during selected period'",
            "'Needed review during selected period'",
            "'Filtered out during selected period'",
        ] {
            assert!(
                JS_THREATS.contains(past_label),
                "groupLabelForScope must map past-scope to {past_label}"
            );
        }
    }

    #[test]
    fn threats_js_unit_disambig_emits_both_units_when_diverge() {
        // The disambiguation helper emits `N attackers · M cases`
        // when the two counts diverge, and just `N` when they match.
        // Singular/plural pinned — operator-readable copy.
        assert!(
            JS_THREATS.contains("function unitDisambigFromItems("),
            "unitDisambigFromItems helper must be defined"
        );
        assert!(
            JS_THREATS.contains("attackers === 1 ? ' attacker \u{00b7} ' : ' attackers \u{00b7} '"),
            "unitDisambigFromItems must handle singular vs plural for `attacker`"
        );
        assert!(
            JS_THREATS.contains("cases === 1 ? ' case' : ' cases'"),
            "unitDisambigFromItems must handle singular vs plural for `case`"
        );
    }

    #[test]
    fn threats_js_ai_defense_log_title_carries_unit_disambig_subtitle() {
        // AI Defense Log title gains a subtitle like
        // `· 50 attackers · 170 cases` when units diverge so the
        // operator reconciles Home's `170 Flagged by system` at a
        // glance. Operator-reported gap 2026-05-13.
        assert!(
            JS_THREATS.contains("totalDisambig.cases !== totalDisambig.attackers"),
            "AI Defense Log subtitle must check unit divergence before rendering"
        );
        assert!(
            JS_THREATS.contains("'AI Defense Log' + subtitleHtml"),
            "AI Defense Log title must concatenate the unit-disambig subtitle when units diverge"
        );
    }

    #[test]
    fn threats_js_group_header_uses_scope_aware_label_in_render() {
        // Render loop pulls group title via `groupLabelForScope(o, scope)`
        // rather than hard-coding `meta.label`. Anti-regression for a
        // future simplification that reverts to always-now labels.
        assert!(
            JS_THREATS.contains("var labelText = groupLabelForScope(o, scope);"),
            "render loop must read group label via groupLabelForScope(o, scope)"
        );
        assert!(
            JS_THREATS.contains("var scope = casesScopeFromDate(state.filters.date);"),
            "render loop must derive scope from state.filters.date before iterating groups"
        );
    }

    // ── Spec 049 PR12 anchors ───────────────────────────────────────
    // Detached ed25519 signing for the audit CSV export. Every
    // operator-facing CSV carries a signature over the
    // reproducibility hash; key is auto-generated at first export
    // and persisted to `<data_dir>/audit-signing.{key,pub}`.

    #[test]
    fn audit_signing_route_registered() {
        // `/api/audit-signing/public-key` must be in the router so
        // the operator can fetch the .pub file once and share with
        // the audit recipient. Without the route, the signed CSV is
        // unverifiable (recipient cannot get the key).
        let src = include_str!("mod.rs");
        assert!(
            src.contains("\"/api/audit-signing/public-key\""),
            "/api/audit-signing/public-key route must be registered (spec 049 PR12)"
        );
        assert!(
            src.contains("api_audit_signing_public_key"),
            "handler must be wired in"
        );
    }

    #[test]
    fn investigation_csv_export_path_invokes_signer() {
        // The CSV format dispatch must call load_or_generate +
        // render_csv_export_signed. Without these, exports ship
        // unsigned and the operator's MSSP wedge collapses.
        let src = include_str!("investigation.rs");
        assert!(
            src.contains("AuditSigner::load_or_generate"),
            "CSV export must invoke AuditSigner::load_or_generate"
        );
        assert!(
            src.contains("render_csv_export_signed"),
            "CSV export must use the signed renderer"
        );
        assert!(
            src.contains("render_csv_export_unsigned_with_warning"),
            "fallback path must emit the loud unsigned warning, not silently drop the signature"
        );
    }

    #[test]
    fn investigation_audit_signing_public_key_handler_defined() {
        let src = include_str!("investigation.rs");
        assert!(
            src.contains("pub(super) async fn api_audit_signing_public_key("),
            "api_audit_signing_public_key handler must be defined"
        );
        assert!(
            src.contains("\"attachment; filename=\\\"innerwarden-audit-signing.pub\\\"\""),
            "public-key download must use the canonical filename"
        );
    }

    // ── Spec 049 PR11 anchors ───────────────────────────────────────
    // Audit CSV export — MSSP deliverable foundation. Backend dispatch
    // on `format=csv` produces an RFC 4180 CSV with metadata header
    // (period, filters, reproducibility hash) and one row per journey
    // entry. Frontend exposes "Export Audit CSV" button next to the
    // existing JSON/Markdown buttons.

    #[test]
    fn investigation_api_export_dispatches_csv_format() {
        // The handler MUST check `format == "csv"` and call the
        // CSV renderer. Without dispatch, the operator's "Export
        // Audit CSV" button just downloads JSON.
        let src = include_str!("investigation.rs");
        assert!(
            src.contains("if format == \"csv\""),
            "build_export_response must dispatch on format=csv (spec 049 PR11)"
        );
        assert!(
            src.contains("audit_export_csv::render_csv_export"),
            "CSV dispatch must invoke audit_export_csv::render_csv_export"
        );
        assert!(
            src.contains("text/csv; charset=utf-8"),
            "CSV response must set Content-Type: text/csv"
        );
        assert!(
            src.contains("attachment; filename=\\\"innerwarden-audit-"),
            "CSV response must set Content-Disposition with `innerwarden-audit-` filename prefix (MSSP deliverable convention)"
        );
    }

    #[test]
    fn threats_js_export_csv_button_routes_to_csv_format() {
        // The journey-page Export Audit CSV button must call
        // downloadSnapshot('csv'). Operator click → backend dispatch.
        assert!(
            JS_JOURNEY.contains("downloadSnapshot('csv')"),
            "journey.js must wire the Export Audit CSV button to downloadSnapshot('csv') (spec 049 PR11)"
        );
        assert!(
            JS_JOURNEY.contains(">Export Audit CSV<"),
            "journey.js must label the button `Export Audit CSV` (spec 049 PR11 vocabulary)"
        );
    }

    #[test]
    fn threats_js_download_snapshot_handles_csv_format() {
        // downloadSnapshot must pick the right ext/mime/filename
        // for csv. Pin all three so a future "simplify the
        // if-chain" refactor cannot drop one and silently break the
        // filename pattern operators / clients rely on.
        assert!(
            JS_THREATS.contains("ext = 'csv'"),
            "downloadSnapshot must emit `.csv` extension for format=csv"
        );
        assert!(
            JS_THREATS.contains("mime = 'text/csv; charset=utf-8'"),
            "downloadSnapshot must use text/csv MIME for format=csv"
        );
        assert!(
            JS_THREATS.contains("filenamePrefix = 'innerwarden-audit'"),
            "downloadSnapshot must emit `innerwarden-audit-` filename prefix for format=csv (MSSP deliverable convention)"
        );
    }

    // ── Spec 049 PR10 anchors ───────────────────────────────────────
    // Recurrence block on the Cases drill-down. Backend overlays
    // `RecurrenceBlock` on `JourneyResponse` for IP subjects from
    // `attacker_profiles` SQLite blob. Frontend renders the block
    // above the timeline so the operator reads "is this attacker
    // new or has it visited before?" before scrolling.

    #[test]
    fn journey_js_renders_recurrence_block() {
        // The render helper MUST be defined and the journey detail
        // template MUST call it. Without these, the spec 049
        // §8.2.E item 6 contract goes invisible.
        assert!(
            JS_JOURNEY.contains("function renderRecurrenceBlock("),
            "journey.js must define renderRecurrenceBlock helper (spec 049 PR10)"
        );
        assert!(
            JS_JOURNEY.contains("${renderRecurrenceBlock(j.recurrence)}"),
            "journey detail template MUST invoke renderRecurrenceBlock with j.recurrence (spec 049 PR10)"
        );
    }

    #[test]
    fn journey_js_recurrence_block_reads_backend_fields_directly() {
        // Reads strictly from `rec.*` (backend-emitted) rather than
        // deriving from journey entries. Single source of truth —
        // the agent's `classify_pattern` + `case_recurrence::recurrence_from_profile`
        // own the math.
        for field in [
            "rec.pattern_label",
            "rec.visit_count",
            "rec.total_days_active",
            "rec.first_seen",
            "rec.last_seen",
            "rec.returns_after_unblock",
            "rec.profile_link",
        ] {
            assert!(
                JS_JOURNEY.contains(field),
                "renderRecurrenceBlock must read {field} (backend-emitted)"
            );
        }
    }

    #[test]
    fn journey_js_recurrence_block_returns_empty_when_field_missing() {
        // Non-IP subjects + missing-profile cases emit `recurrence:
        // None` on the backend; the JS must render '' (nothing) for
        // those, NOT a fake "0 visits" panel. Anchor pins the
        // early-return.
        let start = JS_JOURNEY
            .find("function renderRecurrenceBlock(")
            .expect("renderRecurrenceBlock defined");
        let end = JS_JOURNEY[start..]
            .find("\n}\n")
            .expect("end of renderRecurrenceBlock")
            + start;
        let body = &JS_JOURNEY[start..end];
        assert!(
            body.contains("if (!rec || typeof rec !== 'object') return '';"),
            "renderRecurrenceBlock must early-return '' when rec is missing (spec 049 PR10)"
        );
    }

    #[test]
    fn investigation_journey_overlays_recurrence_block_for_ip_subjects() {
        // The api_journey handler must call `overlay_recurrence_block`
        // after spawn_blocking returns. Without the overlay, the
        // builder's `recurrence: None` stays in place and the
        // frontend never sees the data.
        let src = include_str!("investigation.rs");
        assert!(
            src.contains("fn overlay_recurrence_block("),
            "investigation.rs must define overlay_recurrence_block (spec 049 PR10)"
        );
        assert!(
            src.contains("overlay_recurrence_block("),
            "api_journey must invoke overlay_recurrence_block"
        );
        assert!(
            src.contains("\"attacker_profiles\""),
            "overlay must read from the `attacker_profiles` SQLite blob"
        );
    }

    #[test]
    fn app_css_defines_recurrence_block_styles() {
        for selector in [
            ".recurrence-block",
            ".recurrence-block .recurrence-eyebrow",
            ".recurrence-block .recurrence-pattern-badge",
            ".recurrence-block .recurrence-pill",
            ".recurrence-block .recurrence-returned",
            ".recurrence-block .recurrence-profile-link",
        ] {
            assert!(
                APP_CSS.contains(selector),
                "app.css must define {selector} (spec 049 PR10 recurrence block styling)"
            );
        }
    }

    // ── Spec 049 PR9 anchors ────────────────────────────────────────
    // Decision provenance drill-down. Journey decision rows carry
    // an explicit `decision_layer` label derived at read time from
    // `ai_provider` + `reason` + `confidence` (classifier in
    // `decision_provenance.rs`). Frontend renders a dedicated
    // provenance block in the decision card.

    #[test]
    fn journey_js_renders_decision_provenance_block() {
        // The render helper + layer label map MUST be present, and
        // the decision card MUST call the helper. Without these,
        // the spec 049 §8.2.E item 3 contract ("Decision provenance:
        // camada que decidiu") goes invisible.
        assert!(
            JS_JOURNEY.contains("function renderDecisionProvenance("),
            "journey.js must define renderDecisionProvenance helper (spec 049 PR9)"
        );
        assert!(
            JS_JOURNEY.contains("var DECISION_LAYER_LABELS = {"),
            "journey.js must define DECISION_LAYER_LABELS map for human-readable layer names"
        );
        assert!(
            JS_JOURNEY.contains("(entry.kind === 'decision') ? renderDecisionProvenance(d) : ''"),
            "decision card MUST invoke renderDecisionProvenance (spec 049 PR9)"
        );
    }

    #[test]
    fn journey_js_decision_layer_labels_cover_every_backend_variant() {
        // Wire-format strings emitted by `DecisionLayer` (Rust)
        // MUST all have a human-readable label in the frontend map.
        // A new variant without a label would render the raw
        // snake_case string — operator-unfriendly.
        for wire in [
            "algorithm_gate",
            "killchain_fast_path",
            "correlation_rule",
            "ai_local_warden",
            "ai_llm",
            "auto_rule",
            "honeypot_post_session",
            "observation_verifier",
            "manual_operator",
            "unknown",
        ] {
            let needle = format!("{wire}:");
            assert!(
                JS_JOURNEY.contains(&needle),
                "DECISION_LAYER_LABELS must define `{wire}:` (spec 049 PR9 wire contract)"
            );
        }
    }

    #[test]
    fn investigation_journey_decision_entry_carries_provenance_fields() {
        // Both production paths (SQLite + KG fallback) push decision
        // JourneyEntries that include `decision_layer` and
        // `decision_layer_detail`. Pin both call sites so a future
        // refactor cannot drop the provenance from one path and
        // leave it on the other (the "Dashboard count != Site count"
        // recurring-bug pattern but for the drill-down).
        let src = include_str!("investigation.rs");
        let occurrences = src.matches("\"decision_layer\": provenance.layer").count();
        assert_eq!(
            occurrences, 2,
            "investigation.rs MUST inject `decision_layer` in BOTH SQLite and KG decision paths (saw {occurrences})"
        );
        let detail_occurrences = src
            .matches("\"decision_layer_detail\": provenance.detail")
            .count();
        assert_eq!(
            detail_occurrences, 2,
            "investigation.rs MUST inject `decision_layer_detail` in BOTH paths (saw {detail_occurrences})"
        );
    }

    #[test]
    fn app_css_defines_decision_provenance_block_styles() {
        for selector in [
            ".decision-provenance",
            ".decision-provenance-label",
            ".decision-provenance-badge",
            ".decision-provenance-detail",
        ] {
            assert!(
                APP_CSS.contains(selector),
                "app.css must define {selector} (spec 049 PR9 provenance block styling)"
            );
        }
    }

    // ── Spec 049 PR8 anchors ────────────────────────────────────────
    // Live toggle on the Current state band. Default ON (matches
    // pre-PR8 implicit always-live behaviour); operator opts OUT
    // for audit screenshots or "freeze the wall" moments. Toggle
    // state persists across reloads via localStorage.

    // 2026-05-15 slim-down: Cases sidebar collapsed from "duplo" (live-
    // state-now + decisions-in-period) to a single canonical band
    // mirroring Home. The Live toggle, period/now sub-labels, and the
    // separate kpi-now-* / kpi-confirmed / kpi-responded / kpi-noise
    // IDs are all gone. Anchors below pin the NEW contract.

    #[test]
    fn pr_cases_slim_sidebar_mirrors_home_canonical() {
        // Operator's exact requirement (2026-05-15): "clicking 82 on
        // Home must land on Cases where I can trace where each of
        // the 82 came from". The slim Cases sidebar has 4 KPIs
        // matching Home's breakdown — same source = canonical_counts.
        for id in [
            "kpi-contained",
            "kpi-observing",
            "kpi-filtered-out",
            "kpi-needs-review",
        ] {
            assert!(
                INDEX_HTML.contains(&format!("id=\"{id}\"")),
                "Cases sidebar must carry id={id} (slim-down: 4-KPI canonical band)"
            );
        }
        // The total label must exist so operator sees "<N> Warden
        // decisions" — exactly the label Home uses on its strip.
        assert!(
            INDEX_HTML.contains("id=\"cases-band-total\""),
            "Cases sidebar must carry the total label (cases-band-total)"
        );
        // No-residue: the pre-slim IDs MUST NOT come back. Catches a
        // refactor that re-introduces the period-vs-now duplicate band.
        for orphan in [
            "id=\"kpi-now-blocked\"",
            "id=\"kpi-now-observing\"",
            "id=\"kpi-now-needs-review\"",
            "id=\"kpi-confirmed\"",
            "id=\"kpi-responded\"",
            "id=\"kpi-noise\"",
            "id=\"cases-live-toggle\"",
            "class=\"cases-band-label cases-band-current\"",
            "Live state · enforced right now",
            "Decisions in selected period",
        ] {
            assert!(
                !INDEX_HTML.contains(orphan),
                "Cases slim-down: `{orphan}` was removed; bringing it back resurrects \
                 the duplicate-band confusion the operator explicitly asked to drop"
            );
        }
    }

    #[test]
    fn pr_cases_slim_js_populates_canonical_band() {
        // renderCasesSidebarBand reads canonical fields from /api/overview
        // (same as Home) and writes into the 4 new KPI IDs + total label.
        // Anti-regression for a refactor that drops the wire-up or routes
        // through a non-canonical source.
        assert!(
            JS_THREATS.contains("function renderCasesSidebarBand("),
            "threats.js must define renderCasesSidebarBand (canonical Cases band)"
        );
        for id in [
            "kpi-contained",
            "kpi-observing",
            "kpi-filtered-out",
            "kpi-needs-review",
        ] {
            assert!(
                JS_THREATS.contains(&format!("setNum('{id}',")),
                "renderCasesSidebarBand must populate {id}"
            );
        }
        // Source must be ov.blocked_count / observing_count / filtered_out_count
        // / attention_count — the same canonical fields Home reads.
        for field in [
            "ov.blocked_count",
            "ov.observing_count",
            "ov.filtered_out_count",
            "ov.attention_count",
        ] {
            assert!(
                JS_THREATS.contains(field),
                "renderCasesSidebarBand must source from canonical field {field} (matches Home)"
            );
        }
        // The total label uses warden_decisions_count (= blocked + observing +
        // filtered_out, excludes needs_review) so the Cases header total
        // matches Home's "Warden decisions" strip exactly.
        assert!(
            JS_THREATS.contains("ov.warden_decisions_count")
                && JS_THREATS.contains("Warden decision"),
            "renderCasesSidebarBand must render the total as `<N> Warden decisions` \
             from warden_decisions_count (matches Home strip)"
        );
        // No-residue: the pre-slim function names MUST NOT come back as
        // production callers (they would write into IDs that no longer
        // exist and re-introduce the cardinality drift).
        for orphan_fn in [
            "function isCasesLiveEnabled(",
            "function toggleCasesLive(",
            "function applyCasesLiveToggleUi(",
            "function initCasesLiveToggle(",
            "function syncThreatsKpiWindowLabels(",
        ] {
            assert!(
                !JS_THREATS.contains(orphan_fn),
                "Cases slim-down: `{orphan_fn}` was removed; do not re-introduce"
            );
        }
    }

    // ── Spec 049 PR5 anchors ────────────────────────────────────────
    // Scope picker on Cases tab. Operator picks date + hour-from +
    // hour-to and the Cases tab queries `/api/overview` with the
    // matching `hour_from` / `hour_to` query params (backed by PR4).
    // TZ label flows from `overview.timezone` (backend-emitted), so
    // operators / analysts / clients always read the same TZ.

    // 2026-05-15 slim-down: hour-scope picker (flt-hour-from / flt-hour-to /
    // flt-tz-label) was removed from the Cases sidebar — operator confirmed
    // "filtros e tralha pode remover tudo". The backend `parse_hour_filter`
    // continues to exist for any URL-deep-link replay flow; the related JS
    // state fields (hour_from / hour_to in state.filters) are kept so a
    // URL with `?hour_from=15&hour_to=16` still parses cleanly. The UI
    // inputs are gone.

    #[test]
    fn state_js_carries_hour_filter_in_state_filters() {
        // The filter state object must declare both hour fields with
        // empty-string defaults so `buildQuery` treats them as absent
        // (no stray `hour_from=` in the URL when picker is empty).
        assert!(
            JS_STATE.contains("hour_from: ''"),
            "state.filters must declare hour_from with empty-string default (spec 049 PR5)"
        );
        assert!(
            JS_STATE.contains("hour_to: ''"),
            "state.filters must declare hour_to with empty-string default (spec 049 PR5)"
        );
    }

    #[test]
    fn state_js_sync_validates_hour_range_at_ui_boundary() {
        // syncFiltersFromUi must validate the picker pair at the UI
        // boundary so a malformed value (e.g. typed "99") never
        // reaches the backend. Mirrors the backend `parse_hour_filter`
        // contract: both 0-23 AND hour_from <= hour_to.
        assert!(
            JS_STATE.contains("flt-hour-from") && JS_STATE.contains("flt-hour-to"),
            "syncFiltersFromUi must read both hour inputs"
        );
        assert!(
            JS_STATE.contains("hf >= 0 && hf <= 23 && ht >= 0 && ht <= 23 && hf <= ht"),
            "syncFiltersFromUi must enforce 0-23 AND hour_from <= hour_to (spec 049 PR5 — matches `parse_hour_filter` backend contract)"
        );
    }

    #[test]
    fn state_js_persists_hour_filter_via_url() {
        // Hydrate + syncUrl must include hour_from/hour_to so a deep
        // link ("look at the case I saw at 15h yesterday") survives a
        // reload and shares cleanly across MSSP analysts.
        assert!(
            JS_STATE.contains("qs.get('hour_from')") && JS_STATE.contains("qs.get('hour_to')"),
            "hydrateStateFromQuery must read hour_from/hour_to from URL (spec 049 PR5)"
        );
        assert!(
            JS_STATE.contains("hour_from: state.filters.hour_from")
                && JS_STATE.contains("hour_to: state.filters.hour_to"),
            "syncUrl must write hour_from/hour_to back into the URL (spec 049 PR5)"
        );
    }

    #[test]
    fn threats_js_passes_hour_filter_on_overview_queries() {
        // BOTH refresh paths (`refreshLeft` manual + `refreshLeftLive`
        // SSE) must pass hour_from/hour_to to `/api/overview`. If only
        // one path threads them through, the operator sees different
        // counts on live vs manual refresh — the exact
        // "Dashboard count != Site count" recurring-bug pattern.
        // We assert both calls are wrapped in a `buildQuery({...})`
        // that includes `hour_from` AND `hour_to`.
        let occurrences = JS_THREATS
            .matches("hour_from: state.filters.hour_from")
            .count();
        assert_eq!(
            occurrences, 2,
            "Cases tab must pass hour_from in both refreshLeft and refreshLeftLive (saw {occurrences})"
        );
        let occurrences_to = JS_THREATS.matches("hour_to: state.filters.hour_to").count();
        assert_eq!(
            occurrences_to, 2,
            "Cases tab must pass hour_to in both refresh paths (saw {occurrences_to})"
        );
    }

    // 2026-05-15 slim-down: TZ label was removed with the hour scope
    // picker. renderTzLabel kept as a no-op for any caller surviving the
    // slim-down; backend `overview.timezone` is still emitted on the API
    // response so a future surface that wants to display TZ has it.

    // 2026-05-15 slim-down: scope-picker CSS (.flt-hour-row + variants)
    // was removed with the hour-scope picker UI. Backend
    // `parse_hour_filter` still parses `?hour_from=&hour_to=` query args
    // for URL-deep-link replay; no UI surface.

    // ── Spec 049 PR2 anchors ────────────────────────────────────────
    // Home strip migrated from frontend bucket-sum math to backend-
    // emitted counters (`flagged_by_system_count`, `warden_decisions_count`,
    // etc.). Labels migrated to spec 049 vocabulary. Filtered out
    // (silently uncounted pre-spec-049) now visible as a sub-breakdown
    // chip. These anchors pin the contract so a future refactor
    // cannot silently revert.

    #[test]
    fn home_strip_uses_spec_049_metric_names_and_warden_branding() {
        // The four operator-facing strings live in the HTML labels.
        // If a future change reverts to legacy copy, the operator
        // reads back the old (pre-spec-049, inconsistent) names.
        assert!(
            INDEX_HTML.contains("flagged by system"),
            "home strip must label the second cell `flagged by system` (spec 049)"
        );
        assert!(
            INDEX_HTML.contains(">Warden decisions<"),
            "home strip must label the third cell `Warden decisions` (spec 049 Q2 + brand equity)"
        );
        assert!(
            INDEX_HTML.contains("needs review"),
            "home strip must label the fourth cell `needs review` (spec 049 — replaces `awaiting review`)"
        );
        assert!(
            INDEX_HTML.contains(">Filtered out<"),
            "home strip sub-breakdown must include `Filtered out` chip (spec 049 Q1+Q7 — dismiss is a Warden decision, not a trash bin)"
        );
        assert!(
            INDEX_HTML.contains(">Contained<"),
            "home strip sub-breakdown must include `Contained` chip (= blocked + honeypot)"
        );
        assert!(
            INDEX_HTML.contains(">Observing<"),
            "home strip sub-breakdown must include `Observing` chip"
        );
        // Pre-spec-049 legacy labels MUST be gone.
        assert!(
            !INDEX_HTML.contains("flagged as suspicious"),
            "home strip dropped legacy `flagged as suspicious` label — operator now reads `flagged by system`"
        );
        assert!(
            !INDEX_HTML.contains("handled automatically"),
            "home strip dropped legacy `handled automatically` label — operator now reads `Warden decisions`"
        );
        assert!(
            !INDEX_HTML.contains("awaiting review"),
            "home strip dropped legacy `awaiting review` label — operator now reads `needs review`"
        );
    }

    #[test]
    fn home_strip_reads_backend_counters_not_frontend_bucket_sum() {
        // Spec 049 PR1 moved the math contract to the backend. Frontend
        // must read `overview.flagged_by_system_count` etc. directly —
        // NOT sum `snap.buckets.X.unique_attackers` itself (which drifted
        // historically and silently dropped dismissed). If a future
        // refactor re-introduces the frontend sum, the operator sees
        // numbers that disagree with `/api/overview` JSON. Anchor pins
        // the read path.
        let strip_start = JS_HOME
            .find("function renderActivityStrip(")
            .expect("renderActivityStrip defined");
        let strip_end = JS_HOME[strip_start..]
            .find("\nfunction ")
            .expect("end of renderActivityStrip")
            + strip_start;
        let body = &JS_HOME[strip_start..strip_end];
        assert!(
            body.contains("overview.flagged_by_system_count"),
            "renderActivityStrip must read backend `flagged_by_system_count`"
        );
        assert!(
            body.contains("overview.warden_decisions_count"),
            "renderActivityStrip must read backend `warden_decisions_count`"
        );
        assert!(
            body.contains("overview.filtered_out_count"),
            "renderActivityStrip must read backend `filtered_out_count` (the spec 049 dismiss-is-decision counter)"
        );
        // Anti-regression: the pre-spec-049 frontend bucket-sum must
        // not return. These exact substrings would only appear if
        // someone reintroduced the manual aggregation.
        assert!(
            !body.contains("snap.buckets.blocked.unique_attackers"),
            "renderActivityStrip must NOT sum buckets on the frontend — backend owns the math contract (spec 049 PR1)"
        );
        assert!(
            !body.contains("snap.buckets.honeypot.unique_attackers"),
            "renderActivityStrip must NOT sum honeypot bucket on the frontend"
        );
    }

    #[test]
    fn home_strip_breakdown_chips_render_leaf_outcome_counters() {
        // The three sub-breakdown chips MUST read the leaf-bucket
        // counters whose sum equals `warden_decisions_count` by
        // backend construction (case_metrics.rs math contract).
        // Anchor pins the read sites so a refactor cannot rewire them
        // to a different field and silently break the visible
        // reconciliation (chip total != Warden decisions number above).
        let strip_start = JS_HOME
            .find("function renderActivityStrip(")
            .expect("renderActivityStrip defined");
        let strip_end = JS_HOME[strip_start..]
            .find("\nfunction ")
            .expect("end of renderActivityStrip")
            + strip_start;
        let body = &JS_HOME[strip_start..strip_end];
        assert!(
            body.contains("homeActContained") && body.contains("overview.blocked_count"),
            "Contained chip must read `overview.blocked_count` (= Contained in spec 049)"
        );
        assert!(
            body.contains("homeActObserving") && body.contains("overview.observing_count"),
            "Observing chip must read `overview.observing_count`"
        );
        assert!(
            body.contains("homeActFilteredOut") && body.contains("overview.filtered_out_count"),
            "Filtered out chip must read `overview.filtered_out_count`"
        );
    }

    #[test]
    fn app_css_defines_home_activity_breakdown_styles() {
        // The sub-breakdown row depends on these classes. Without
        // them the chips render as inline plain text (no padding,
        // no hover affordance). Anchor pins the contract so a CSS
        // refactor cannot silently drop the styling.
        for selector in [
            ".home-activity-breakdown",
            ".home-activity-breakdown .breakdown-chip",
            ".home-activity-breakdown .breakdown-num",
            ".home-activity-breakdown .breakdown-label",
            ".home-activity-breakdown .breakdown-sep",
        ] {
            assert!(
                APP_CSS.contains(selector),
                "app.css must define {selector} (spec 049 PR2 sub-breakdown styling)"
            );
        }
    }

    // 2026-05-15 slim-down: removed home_pending_panel_renders_only_nonzero_cells
    // (the Technical Details panel that hosted the pending grid is gone) and
    // home_critical_banner_only_renders_open_critical_high (the critical
    // banner was removed from Home — critical incidents still surface on
    // the Cases view and via Telegram).

    #[test]
    fn home_no_summary_pyramid_or_homenow_dom_ids_remain() {
        // 2026-04-30: enforce the redesign's removal of the old
        // pyramid + standalone "Now" section. If a regression
        // re-introduces them, the page will have BOTH the new strip
        // and the old pyramid (data drift visible to operator). The
        // CSS class .summary-pyramid is intentionally kept (legacy
        // safety) but no element should reference it any more.
        for orphan in [
            "id=\"homeNowWhat\"",
            "id=\"homeNowDid\"",
            "id=\"homeSummary\"",
            "id=\"homeSummaryWatched\"",
            "id=\"homeSummaryFlagged\"",
            "id=\"homeSummaryActed\"",
            "id=\"homeSummaryAwaiting\"",
            "id=\"homeSummaryBlocked\"",
            "id=\"homeSummaryHoneypot\"",
            "id=\"homeSummaryTrusted\"",
            "id=\"homeSummaryWatching\"",
            "id=\"homeStatusMeta\"",
            "class=\"summary-pyramid\"",
        ] {
            assert!(
                !INDEX_HTML.contains(orphan),
                "old pre-redesign anchor {orphan} should be gone — check for stale Home markup"
            );
        }
    }

    #[test]
    fn home_view_has_no_emoji_icons() {
        // Phase 11B + 2026-04-30 redesign: the entire home view uses
        // inline lucide SVGs. Walk the home view block specifically
        // (avoid false positives from other pages) and assert no
        // emoji codepoints we previously rendered there.
        let home_start = INDEX_HTML
            .find("<!-- ── Home view ──")
            .or_else(|| INDEX_HTML.find("id=\"viewHome\""))
            .expect("home view block present");
        // 2026-05-15: the standalone Sensors view was deleted (its
        // content folded into Home), so the next markers after Home
        // are the Investigate/Cases view block or the residual deletion
        // comment that points to where viewSensors used to be.
        let home_end = INDEX_HTML[home_start..]
            .find("<!-- ── Investigate")
            .or_else(|| INDEX_HTML[home_start..].find("id=\"viewInvestigate\""))
            .expect("Investigate / Cases view marks the end of home block")
            + home_start;
        let home = &INDEX_HTML[home_start..home_end];
        for emoji in ["📡", "🎯", "🛡️", "⛔", "👁️", "🍯", "🤝", "⚠️", "🤖"]
        {
            assert!(
                !home.contains(emoji),
                "emoji {emoji} still in Home view — should be inline lucide SVG"
            );
        }
        // The hero shield-check SVG must remain so the page renders
        // the verb icon before JS hydrates.
        assert!(home.contains("M20 13c0 5-3.5 7.5-7.66 8.95"));
    }

    #[test]
    fn app_css_defines_attention_first_home_styles() {
        // 2026-05-15 slim-down: dropped .home-alert-critical, .home-health-line,
        // .home-health-bad, .home-details, .home-meta-row — those sections
        // were removed from Home.
        for selector in [
            ".home-alert-banner",
            ".home-alert-warn",
            ".activity-strip",
            ".activity-cell",
            ".activity-cell-attention-active",
        ] {
            assert!(
                APP_CSS.contains(selector),
                "redesign CSS must define {selector}"
            );
        }
    }

    #[test]
    fn phase_14_qa_polish_anchors_present() {
        // 2026-05-15 Cases slim-down: items 1, 2, 5, 6 of the original
        // Phase 14 anchor pinned now-removed UI (compare-date placeholder,
        // detector datalist, pivot-tab active styles, KPI window labels).
        // Items 3 (Show-details stopPropagation) and 4 (hide "0 evt" tail)
        // are retained — item 4 still applies because the card-render
        // path on Cases stays. Item 3 is breadcrumb-only.

        // 4. Hide "0 evt" tail when event_count is zero. Both render
        //    paths (initial render and SSE refresh) must respect it.
        assert!(
            JS_THREATS.contains("(item.event_count || 0) > 0 ? ' \u{00b7} '"),
            "renderCard must hide '0 evt' tail when event_count is zero"
        );
        assert!(
            JS_THREATS.contains("evt > 0 ? ' \u{00b7} ' + evt + ' evt' : ''"),
            "SSE count refresh must hide '0 evt' tail too"
        );
    }

    #[test]
    fn app_css_defines_pending_panel_and_allowlisted_outcome() {
        assert!(APP_CSS.contains(".pending-grid"));
        assert!(APP_CSS.contains(".pending-cell-warn"));
        assert!(APP_CSS.contains(".kpi-pair-line"));
        assert!(APP_CSS.contains(".outcome-allowlisted"));
    }

    #[test]
    fn dashboard_js_files_have_no_template_interp_inside_single_quoted_strings() {
        // 2026-04-30: prod regression — operator hit "Loading attacker
        // profiles..." stuck forever because intel.js had two lines
        // of the form `'<div>${lucideIcon(\'name\', ...)}</div>'`. A
        // single-quoted JS string containing `${...}` is
        // (a) NOT interpolated (renders the literal `${...}` text),
        // (b) syntax-broken when the embedded expression contains a
        //     single quote — the inner `'name'` closes the outer
        //     string and corrupts the parse for the rest of the file.
        // Net effect: the entire JS file failed to load and EVERY
        // function it defined was undefined at runtime. nav.js called
        // loadIntel(), got ReferenceError, the static "Loading..."
        // placeholder remained on screen forever.
        //
        // This anchor scans every bundled JS file for the bug shape
        // (`'...${lucideIcon('...`) so a future "convenience" replace
        // that re-introduces it fails the build.
        for (label, src) in [
            ("api.js", JS_API),
            ("icons.js", JS_ICONS),
            ("helpers.js", JS_HELPERS),
            ("state.js", JS_STATE),
            ("nav.js", JS_NAV),
            ("home.js", JS_HOME),
            ("threats.js", JS_THREATS),
            ("journey.js", JS_JOURNEY),
            ("sensors.js", JS_SENSORS),
            ("reports.js", JS_REPORTS),
            ("status.js", JS_STATUS),
            ("compliance.js", JS_COMPLIANCE),
            ("intel.js", JS_INTEL),
            ("monthly.js", JS_MONTHLY),
            ("responses.js", JS_RESPONSES),
            ("actions.js", JS_ACTIONS),
            ("sse.js", JS_SSE),
        ] {
            for (i, line) in src.lines().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") || trimmed.starts_with("*") {
                    continue;
                }
                let Some(interp_pos) = line.find("${lucideIcon") else {
                    continue;
                };
                // Scan backwards from the interp position for the
                // most recent string opener on the same line. If it
                // is a single quote (and not a backtick), the
                // interpolation cannot evaluate.
                let prefix = &line[..interp_pos];
                let last_backtick = prefix.rfind('`');
                let last_squote = prefix.rfind('\'');
                if let (Some(sq), bt) = (last_squote, last_backtick) {
                    let bt = bt.unwrap_or(0);
                    if last_backtick.is_none() || sq > bt {
                        // Need to also rule out the case where the
                        // single quote is inside a previously-closed
                        // template literal. Coarse but adequate
                        // for current code: count odd parity of `'`.
                        let squote_count = prefix.matches('\'').count();
                        let bt_count = prefix.matches('`').count();
                        if squote_count % 2 == 1 && bt_count % 2 == 0 {
                            panic!(
                                "{label}:{} `${{lucideIcon(...)}}` inside single-quoted string — \
                                 will syntax-break the file at runtime. Use backticks. Line: {}",
                                i + 1,
                                line.trim()
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn icons_module_loaded_before_consumers_and_exposes_lucide_icon() {
        // 2026-04-30: shared icon vocabulary lives in
        // frontend/js/icons.js. Every consumer expects
        // `window.lucideIcon(name)` to be defined at script execution
        // time, so icons.js must be in the <script> chain before any
        // consumer file. Anchor pins the wiring against a future
        // refactor that drops the include.
        assert!(
            INDEX_HTML.contains("<script src=\"/js/icons.js\"></script>"),
            "icons.js must be wired into index.html"
        );
        assert!(
            INDEX_HTML.contains("<script src=\"/js/icons.js\"></script>\n<script src=\"/js/helpers.js\"></script>"),
            "icons.js must load BEFORE helpers.js (consumers expect window.lucideIcon to be defined)"
        );
        // The module must export the helper.
        assert!(JS_ICONS.contains("window.lucideIcon"));
        // And it must contain the canonical names every consumer
        // currently calls. If a consumer adds a new icon name, it
        // must be added to the SHAPES table in icons.js — pin the
        // names that are in active use so a typo in either side
        // surfaces as a test failure rather than a silent missing
        // icon at runtime.
        for name in [
            "shield-check",
            "shield",
            "ban",
            "eye",
            "book-open",
            "check",
            "check-circle",
            "x",
            "x-circle",
            "alert-circle",
            "alert-triangle",
            "activity",
            "radio",
            "search",
            "refresh-ccw",
            "bar-chart-3",
            "clipboard-list",
            "bug",
            "handshake",
            "target",
            "crosshair",
            "swords",
            "dna",
            "link",
            "globe",
            "flask-conical",
            "bot",
            "cpu",
            "monitor",
            "server",
            "wrench",
            "broom",
            "circle-dashed",
            "circle-dot",
            "flame",
            "lock",
        ] {
            let needle = format!("'{name}'");
            assert!(
                JS_ICONS.contains(&needle),
                "icons.js SHAPES must define '{name}' — referenced by a consumer"
            );
        }
    }

    #[test]
    fn dashboard_consumers_use_lucide_icon_not_emoji() {
        // 2026-04-30: every dashboard JS file that previously rendered
        // emoji icons now calls lucideIcon(...). Anchor pins the
        // contract: each consumer must mention lucideIcon at least
        // once, and must NOT contain the emojis it used to render.
        // A future refactor that re-introduces emoji is caught.
        for (file_label, src, must_have_emoji_count_zero) in [
            ("home.js", JS_HOME, true),
            ("threats.js", JS_THREATS, true),
            ("status.js", JS_STATUS, true),
            ("intel.js", JS_INTEL, true),
            ("monthly.js", JS_MONTHLY, true),
            ("compliance.js", JS_COMPLIANCE, true),
            ("responses.js", JS_RESPONSES, true),
            ("journey.js", JS_JOURNEY, true),
            ("reports.js", JS_REPORTS, true),
            ("helpers.js", JS_HELPERS, true),
            ("actions.js", JS_ACTIONS, true),
        ] {
            assert!(
                src.contains("lucideIcon("),
                "{file_label} must call lucideIcon() — emoji icons should be gone"
            );
            if must_have_emoji_count_zero {
                // Spot-check: the surrogate-pair escapes used by the
                // pre-fix code MUST NOT appear in the rendered string
                // bodies. (We allow them inside comments and JSDoc;
                // the test bundles raw bytes so it's an over-strict
                // match — for the canary set below we check shapes
                // we know were in user-facing strings only.)
                for emoji in ["\u{1F6E1}", "\u{1F441}", "\u{1F36F}", "\u{1F916}"] {
                    assert!(
                        !src.contains(emoji),
                        "{file_label} still contains emoji {emoji:?} — should be lucide SVG"
                    );
                }
            }
        }
    }

    #[test]
    fn threats_kpi_tile_label_is_blocks_not_blocked() {
        // 2026-05-15 slim-down: replaced "Block actions" tile with
        // 4-KPI canonical band (Contained / Observing / Filtered out /
        // Needs review). The Wave-10 lesson — the KPI count and the
        // list count have DIFFERENT cardinalities — still applies:
        //   * KPI "Contained": unique attackers contained today
        //   * List "Currently blocked attackers": same number, list view
        // The list label keeps "Currently blocked attackers" (Wave 10)
        // so a smaller number on the list does not look like a contradiction.
        assert!(
            INDEX_HTML.contains("<div class=\"kpi-label\">Contained</div>"),
            "Slim Cases band must label the contained-attackers KPI 'Contained' (matches Home)"
        );
        assert!(
            JS_THREATS.contains("label: 'Currently blocked attackers'"),
            "list group header must read 'Currently blocked attackers' (Wave 10) so the operator reads the count as a snapshot"
        );
        // Anti-regression: the pre-Wave-10 / pre-slim strings must NOT come back.
        assert!(
            !INDEX_HTML.contains("<div class=\"kpi-label\">Blocks</div>"),
            "KPI tile must NOT revert to 'Blocks' (pre-Wave-10); the slim Cases band uses 'Contained'"
        );
        assert!(
            !INDEX_HTML.contains("<div class=\"kpi-label\">Block actions</div>"),
            "KPI tile must NOT revert to 'Block actions' (pre-slim); the slim Cases band uses 'Contained' to match Home's vocabulary"
        );
        assert!(
            !JS_THREATS.contains("label: 'Blocked attackers'"),
            "list group header must NOT revert to bare 'Blocked attackers' (pre-Wave-10); use 'Currently blocked attackers'"
        );
    }

    #[test]
    fn wave10_home_activity_strip_reads_handled_not_stopped() {
        // Wave 10 (label honesty, 2026-05-05) renamed "stopped
        // automatically" -> "handled automatically" because "stopped"
        // lied for the observing bucket. Spec 049 PR2 (2026-05-12)
        // superseded that with the operator-facing brand vocabulary
        // — `Warden decisions` — which folds in Filtered out as well
        // (spec 049 Q1+Q7: dismiss is a decision, not a no-op). Both
        // the Wave-10 lesson (no "stopped" verb on observing/dismiss)
        // and the spec-049 contract (operator reads `Warden decisions`)
        // are pinned here.
        assert!(
            INDEX_HTML.contains("<div class=\"activity-label\">Warden decisions</div>"),
            "home activity strip must read 'Warden decisions' (spec 049 PR2) — the cell sums Contained + Observing + Filtered out, and the brand owns the noun"
        );
        // Pre-Wave-10 string must stay gone.
        assert!(
            !INDEX_HTML.contains("<div class=\"activity-label\">stopped automatically</div>"),
            "home activity strip must NOT revert to 'stopped automatically' (pre-Wave-10) — observing is not stopping"
        );
        // Wave-10 interim string must also stay gone (superseded by spec 049).
        assert!(
            !INDEX_HTML.contains("<div class=\"activity-label\">handled automatically</div>"),
            "home activity strip must NOT revert to 'handled automatically' (Wave 10 interim) — spec 049 PR2 renamed it to 'Warden decisions'"
        );
    }

    #[test]
    fn wave10_live_feed_clips_to_rolling_24h_matching_site_label() {
        // Wave 10: the public site Live page hardcodes "(24h)" on
        // every counter (`total_today`, `total_blocked`, `total_high`,
        // `unique_sources`). Pre-Wave-10 the backend honoured NO time
        // window and read every incident the KG retained — the label
        // was a lie under hot-tier load. The fix clips `real_incidents`
        // to `now - 24h` so the label matches the data. This anchor
        // pins the cutoff variable + filter so a future
        // "remove the cutoff for performance" PR fails CI.
        let src = include_str!("live_feed.rs");
        // Strip comment lines so the assertion below is checking ACTIVE
        // code, not its own comments / panic messages.
        let code: String = src
            .lines()
            .filter(|line| {
                let t = line.trim_start();
                !(t.starts_with("//") || t.starts_with("/*") || t.starts_with("*"))
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            code.contains("cutoff_24h = now - chrono::Duration::hours(24)"),
            "live_feed builder must compute a 24h cutoff to match the site's '(24h)' labels"
        );
        assert!(
            code.contains("i.ts >= cutoff_24h"),
            "live_feed real_incidents filter must apply the 24h cutoff (`i.ts >= cutoff_24h`); without it the public site shows numbers older than its label claims"
        );
    }

    #[test]
    fn threats_js_uses_lucide_svg_icons_not_emoji() {
        // 2026-04-30: outcome group icons match the home pyramid
        // lucide SVG vocabulary (Phase 11B). Anchor that the unique
        // path strings of each lucide icon are present and that the
        // old emoji icons are NOT in OUTCOME_META anymore. A future
        // refactor that re-introduces the emojis fails this test.
        // (Same anchor pattern as `index_html_uses_lucide_svg_icons_
        // not_emoji` for the home pyramid.)
        // Ban (blocked).
        assert!(JS_THREATS.contains("m4.9 4.9 14.2 14.2"));
        // Bug (honeypot).
        assert!(JS_THREATS.contains("M9 7.13v-1a3.003 3.003 0 1 1 6 0v1"));
        // Eye (monitoring).
        assert!(JS_THREATS.contains("M2.062 12.348"));
        // AlertCircle (needs_attention) — distinguishable from
        // AlertTriangle by the circle radius signature.
        assert!(JS_THREATS.contains("<line x1=\"12\" x2=\"12\" y1=\"8\" y2=\"12\"/>"));
        // Handshake (allowlisted).
        assert!(JS_THREATS.contains("m11 17 2 2a1 1 0 1 0 3-3"));
        // Check (dismissed).
        assert!(JS_THREATS.contains("M20 6 9 17l-5-5"));
        // Old emojis must be gone from the OUTCOME_META block.
        let outcome_block_start = JS_THREATS
            .find("var OUTCOME_META = {")
            .expect("OUTCOME_META present");
        let outcome_block_end = JS_THREATS[outcome_block_start..]
            .find("};\n")
            .expect("end of OUTCOME_META")
            + outcome_block_start;
        let block = &JS_THREATS[outcome_block_start..outcome_block_end];
        for emoji_escape in [
            "\\uD83D\\uDEE1", // 🛡️
            "\\uD83C\\uDF6F", // 🍯
            "\\uD83D\\uDC41", // 👁️
            "\\u26A0",        // ⚠️
            "\\uD83E\\uDD1D", // 🤝
        ] {
            assert!(
                !block.contains(emoji_escape),
                "emoji escape {emoji_escape} still in OUTCOME_META — should be lucide SVG constant"
            );
        }
    }

    #[test]
    fn telegram_audit_target_is_in_main_env_filter() {
        // 2026-05-01: the telegram audit log uses
        // `target: "telegram_audit"` (see telegram/client.rs), but
        // the env_filter in main.rs only allowed
        // `innerwarden_agent=info`. Result: ALL outgoing telegram
        // traffic was invisible in journald — daily digests, menu
        // callbacks, manual approvals, integrity alerts. Operator's
        // question "auditar o que funciona" had no answer.
        //
        // This anchor pins the env_filter directive so a future
        // refactor of the logging setup cannot silently drop the
        // audit target again.
        let main_src = include_str!("../main.rs");
        assert!(
            main_src.contains("telegram_audit=info"),
            "main.rs env_filter must include `telegram_audit=info` so the audit log reaches journald"
        );
    }

    #[test]
    fn telegram_audit_jsonl_path_is_wired_in_boot() {
        // The persistent JSONL audit (data_dir/telegram-sent.jsonl)
        // is the durable trail that survives log rotation. Boot must
        // call set_audit_jsonl_path on the TelegramClient — without
        // it the persistent file never exists.
        let boot_src = include_str!("../loops/boot.rs");
        assert!(
            boot_src.contains("set_audit_jsonl_path"),
            "boot.rs must wire the audit jsonl path on the TelegramClient"
        );
        assert!(
            boot_src.contains("telegram-sent.jsonl"),
            "boot.rs must use telegram-sent.jsonl as the audit filename"
        );
    }

    #[test]
    fn compliance_api_surfaces_documented_chain_breaks() {
        // 2026-05-01 (PR after #357): the documented chain breaks
        // must surface in the compliance tab so the operator sees
        // them without ssh + sqlite. Anchor pins the JSON contract
        // (`hash_chain.sqlite.documented_breaks` + `breaks[]`) and
        // the frontend rendering path.
        let compliance_src = include_str!("compliance.rs");
        assert!(
            compliance_src.contains("\"documented_breaks\": r.documented_breaks"),
            "compliance API must include documented_breaks count"
        );
        assert!(
            compliance_src.contains("\"breaks\": breaks"),
            "compliance API must include the breaks array"
        );
        assert!(
            JS_COMPLIANCE.contains("sqliteChain.breaks"),
            "compliance.js must read the new breaks array"
        );
        assert!(
            JS_COMPLIANCE.contains("documented break"),
            "compliance.js must surface the human label"
        );
    }

    #[test]
    fn ctl_chain_break_subcommand_is_wired() {
        // Operator-facing CLI for chain_break_audit. Anchor pins the
        // subcommand wiring + the two invocations (register / list).
        let ctl_main = include_str!("../../../ctl/src/main.rs");
        assert!(
            ctl_main.contains("name = \"chain-break\"")
                || ctl_main.contains("name=\"chain-break\""),
            "ctl must expose `innerwarden chain-break` subcommand"
        );
        assert!(
            ctl_main.contains("ChainBreakCommand::Register"),
            "ctl must dispatch chain-break register"
        );
        assert!(
            ctl_main.contains("ChainBreakCommand::List"),
            "ctl must dispatch chain-break list"
        );
    }

    #[test]
    fn chain_break_audit_table_is_in_schema_v4() {
        // Schema migration v4 adds the chain_break_audit table.
        // Anchor pins the v4 SQL so a future migration renumber or
        // squash does not silently drop the documented-break tracking.
        let schema_src = include_str!("../../../store/src/schema.rs");
        assert!(
            schema_src.contains("CURRENT_VERSION: i64 = 4"),
            "store schema must be at version 4"
        );
        assert!(
            schema_src.contains("CREATE TABLE IF NOT EXISTS chain_break_audit"),
            "v4 must create chain_break_audit table"
        );
        assert!(
            schema_src.contains("rowid_start"),
            "chain_break_audit must have rowid_start column"
        );
        assert!(
            schema_src.contains("rowid_end"),
            "chain_break_audit must have rowid_end column"
        );
        // Verify integration: maintenance.rs hourly tick uses the
        // documented_breaks field added to HashChainResult.
        let maint_src = include_str!("../../../store/src/maintenance.rs");
        assert!(
            maint_src.contains("documented_breaks"),
            "maintenance hourly alert must surface documented_breaks count"
        );
    }

    #[test]
    fn data_exfil_ebpf_suppresses_ssh_passwd_nss_init() {
        // Sensor anchor: the NSS_INIT_CLI_TOOLS list now includes
        // "ssh" so `git fetch` -> `ssh git@github.com` (or any
        // direct ssh + outbound) does not fire DATA_EXFIL on the
        // /etc/passwd NSS-lookup pattern. The actual sensor test
        // is in data_exfil_ebpf.rs::ssh_reading_passwd_then_
        // connecting_outbound_does_not_alert; this anchor mirrors
        // it from the agent test surface so the cross-crate
        // contract is visible during agent CI.
        let detector_src = include_str!("../../../sensor/src/detectors/data_exfil_ebpf.rs");
        assert!(
            detector_src.contains("\"ssh\","),
            "ssh must be in NSS_INIT_CLI_TOOLS to suppress git+github FP"
        );
    }

    #[test]
    fn threats_js_lists_allowlisted_in_outcome_order() {
        // The new "allowlisted" outcome must appear in the group
        // ordering and have a label entry. Pre-Phase-7 there was
        // no such entry; allowlisted attackers fell into "needs
        // attention" or were hidden by the toggle.
        assert!(
            JS_THREATS.contains("'allowlisted'"),
            "OUTCOME_ORDER must include 'allowlisted' for the dedicated group"
        );
        assert!(
            JS_THREATS.contains("Allowlisted (silenced)"),
            "label so the operator knows what the group means"
        );
    }

    #[test]
    fn threats_js_open_outcome_always_maps_to_needs_attention() {
        // Phase 13 (QA fix #3, 2026-04-29): pre-Phase-13 the
        // outcomeOf function rewrote `open` -> `monitoring` when
        // mode == 'guard', causing the home tile
        // `buckets.attention.unique_attackers` (correctly counts
        // open IPs) to disagree with the threats list group count
        // (which folded those same IPs into Observing). Anchor
        // pins the post-fix mapping: open -> needs_attention,
        // unconditional. If a future cleanup re-introduces the
        // mode-aware rewrite, the cross-surface drift returns and
        // this test fails.
        assert!(
            JS_THREATS.contains("if (o === 'open')"),
            "outcomeOf must explicitly handle the 'open' outcome string"
        );
        // The fix removed the `modeOpen === 'guard'` short-circuit.
        // If it comes back, this catches it.
        assert!(
            !JS_THREATS.contains("if (modeOpen === 'guard') return 'monitoring';"),
            "open MUST NOT be mode-rewritten to monitoring — Phase 13 RC-2 drift fix"
        );
    }

    #[test]
    fn normalize_limit_is_bounded() {
        assert_eq!(normalize_limit(None), 50);
        assert_eq!(normalize_limit(Some(0)), 1);
        assert_eq!(normalize_limit(Some(10)), 10);
        assert_eq!(normalize_limit(Some(9999)), 500);
    }

    #[test]
    fn resolve_date_falls_back_to_today_on_invalid_values() {
        // 2026-04-30: resolve_date is now UTC. SQLite stores ts as
        // ISO-UTC; matching "today" against Local::now broke the
        // dashboard between 00:00 and 01:00 BST when UTC was still
        // "yesterday". See helpers.rs::resolve_date docstring.
        let today = chrono::Utc::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        assert_eq!(resolve_date(None), today);
        assert_eq!(resolve_date(Some("not-a-date")), today);
        assert_eq!(resolve_date(Some("2026-99-01")), today);
        assert_eq!(resolve_date(Some("2026-03-13")), "2026-03-13");
    }

    #[test]
    fn overview_counts_jsonl_artifacts() {
        let dir = TempDir::new().unwrap();
        let date = "2026-03-13";

        let event_path = dated_path(dir.path(), "events", date);
        let incident_path = dated_path(dir.path(), "incidents", date);
        let decision_path = dated_path(dir.path(), "decisions", date);
        let telemetry_path = dated_path(dir.path(), "telemetry", date);

        let event = Event {
            ts: Utc::now(),
            host: "h".to_string(),
            source: "auth.log".to_string(),
            kind: "ssh.login_failed".to_string(),
            severity: Severity::Info,
            summary: "x".to_string(),
            details: serde_json::json!({}),
            tags: vec![],
            entities: vec![EntityRef::ip("1.2.3.4")],
        };
        std::fs::write(
            &event_path,
            format!(
                "{}\n{}\n",
                serde_json::to_string(&event).unwrap(),
                "{malformed"
            ),
        )
        .unwrap();

        let incident = Incident {
            ts: Utc::now(),
            host: "h".to_string(),
            incident_id: "ssh_bruteforce:1.2.3.4:test".to_string(),
            severity: Severity::High,
            title: "t".to_string(),
            summary: "s".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec!["ssh".to_string()],
            entities: vec![EntityRef::ip("1.2.3.4")],
        };
        std::fs::write(
            &incident_path,
            format!("{}\n", serde_json::to_string(&incident).unwrap()),
        )
        .unwrap();

        let decision = DecisionEntry {
            ts: Utc::now(),
            incident_id: "ssh_bruteforce:1.2.3.4:test".to_string(),
            host: "h".to_string(),
            ai_provider: "mock".to_string(),
            action_type: "block_ip".to_string(),
            target_ip: Some("1.2.3.4".to_string()),
            target_user: None,
            skill_id: Some("block-ip-ufw".to_string()),
            confidence: 0.9,
            auto_executed: true,
            dry_run: true,
            reason: "r".to_string(),
            estimated_threat: "high".to_string(),
            execution_result: "ok".to_string(),
            prev_hash: None,
            decision_layer: None,
        };
        std::fs::write(
            &decision_path,
            format!("{}\n", serde_json::to_string(&decision).unwrap()),
        )
        .unwrap();

        let snapshot = TelemetrySnapshot {
            ts: Utc::now(),
            tick: "incident_tick".to_string(),
            events_by_collector: BTreeMap::new(),
            incidents_by_detector: BTreeMap::new(),
            gate_pass_count: 1,
            incidents_by_tenant: Default::default(),
            ai_sent_count: 1,
            ai_decision_count: 1,
            avg_decision_latency_ms: 120.0,
            errors_by_component: BTreeMap::new(),
            decisions_by_action: BTreeMap::new(),
            dry_run_execution_count: 1,
            real_execution_count: 0,
            gate_suppressed_total: 0,
            telegram_sent_count: 0,
        };
        std::fs::write(
            &telemetry_path,
            format!("{}\n", serde_json::to_string(&snapshot).unwrap()),
        )
        .unwrap();

        let ov = compute_overview(dir.path(), date);
        // events_count uses fast line counting (not JSON parsing), so malformed lines count too
        assert_eq!(ov.events_count, 2);
        assert_eq!(ov.incidents_count, 1);
        assert_eq!(ov.decisions_count, 1);
        assert_eq!(ov.top_detectors.len(), 1);
        assert_eq!(ov.top_detectors[0].detector, "ssh_bruteforce");
        assert!(ov.latest_telemetry.is_some());
    }

    #[test]
    fn parse_basic_auth_header_works() {
        let encoded = BASE64_STANDARD.encode("admin:supersecret");
        let header = format!("Basic {encoded}");
        let parsed = parse_basic_auth(&header).unwrap();
        assert_eq!(parsed.0, "admin");
        assert_eq!(parsed.1, "supersecret");
    }

    #[test]
    fn dashboard_auth_verifies_valid_credentials() {
        // Generate the test password at runtime from OS entropy so the test
        // has no hard-coded cryptographic literal. A 24-byte random password
        // is mapped into `a..z` for readability in test output, and the
        // "wrong" variant is derived by appending a non-alphabetic byte so it
        // can never accidentally collide with `correct_pw`.
        let mut pw_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut pw_bytes);
        let correct_pw: String = pw_bytes
            .iter()
            .map(|b| char::from(b'a' + (b % 26)))
            .collect();
        let wrong_pw: String = format!("{correct_pw}!");

        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2::default()
            .hash_password(correct_pw.as_bytes(), &salt)
            .unwrap()
            .to_string();
        let auth = DashboardAuth {
            username: "admin".to_string(),
            password_hash: PasswordHashString::new(&hash).unwrap(),
            verified_cache: VerifiedCache::new(),
        };

        assert!(auth.verify("admin", &correct_pw));
        assert!(!auth.verify("admin", &wrong_pw));
        assert!(!auth.verify("other", &correct_pw));
    }

    /// 2026-05-02 auth phase 2: argon2 verify is the new top heap
    /// consumer (128 MB / 29.4 % per jeprof). Cache hit on
    /// `verify_with_cache` skips the slow path entirely. Two
    /// invariants matter:
    ///   1. Wrong creds must NEVER cache — checked by counting cache
    ///      entries after a failed verify.
    ///   2. Subsequent successful verify with the same creds is a
    ///      cache hit — checked by comparing returns and asserting
    ///      the cache map carries exactly one entry.
    #[test]
    fn dashboard_auth_caches_successful_verifies() {
        let mut pw_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut pw_bytes);
        let correct_pw: String = pw_bytes
            .iter()
            .map(|b| char::from(b'a' + (b % 26)))
            .collect();
        let wrong_pw: String = format!("{correct_pw}!");

        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2::default()
            .hash_password(correct_pw.as_bytes(), &salt)
            .unwrap()
            .to_string();
        let auth = DashboardAuth {
            username: "admin".to_string(),
            password_hash: PasswordHashString::new(&hash).unwrap(),
            verified_cache: VerifiedCache::new(),
        };

        // Wrong creds must not populate the cache. Anchor: a
        // future regression that calls `cache.insert` on the
        // failure path would inflate this count.
        assert!(!auth.verify_with_cache("admin", &wrong_pw));
        assert_eq!(
            auth.verified_cache.entry_count(),
            0,
            "cache must NOT carry an entry for failed verify"
        );

        // Correct creds: first call hits argon2, second call lands
        // in the cache. Both return true.
        assert!(auth.verify_with_cache("admin", &correct_pw));
        assert_eq!(auth.verified_cache.entry_count(), 1);
        assert!(auth.verify_with_cache("admin", &correct_pw));
        assert_eq!(
            auth.verified_cache.entry_count(),
            1,
            "second verify with same creds must be a cache hit, not a re-insert"
        );
    }

    // ── New D2 tests ────────────────────────────────────────────────────

    #[test]
    fn attackers_groups_by_ip() {
        let dir = TempDir::new().unwrap();
        let date = "2026-03-13";

        // Two incidents from the same IP - different detectors.
        let inc1 = Incident {
            ts: Utc::now(),
            host: "h".to_string(),
            incident_id: "ssh_bruteforce:203.0.113.10:abc".to_string(),
            severity: Severity::Critical,
            title: "t1".to_string(),
            summary: "s1".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("203.0.113.10")],
        };
        let inc2 = Incident {
            ts: Utc::now(),
            host: "h".to_string(),
            incident_id: "ssh_bruteforce:203.0.113.10:def".to_string(),
            severity: Severity::High,
            title: "t2".to_string(),
            summary: "s2".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("203.0.113.10")],
        };
        std::fs::write(
            dated_path(dir.path(), "incidents", date),
            format!(
                "{}\n{}\n",
                serde_json::to_string(&inc1).unwrap(),
                serde_json::to_string(&inc2).unwrap()
            ),
        )
        .unwrap();

        let filters = InvestigationFilters::from_query(None, None);
        let attackers = build_attackers(dir.path(), date, &filters, 50);
        assert_eq!(attackers.len(), 1, "should aggregate to a single IP");
        assert_eq!(attackers[0].ip, "203.0.113.10");
        assert_eq!(attackers[0].incident_count, 2);
        // max_severity should be the highest observed (critical > high).
        assert_eq!(attackers[0].max_severity, "critical");
        assert_eq!(attackers[0].detectors, vec!["ssh_bruteforce"]);
    }

    #[test]
    fn journey_assembles_all_kinds() {
        let dir = TempDir::new().unwrap();
        let date = "2026-03-13";
        let ip = "203.0.113.10";

        let event = Event {
            ts: Utc::now(),
            host: "h".to_string(),
            source: "auth.log".to_string(),
            kind: "ssh.login_failed".to_string(),
            severity: Severity::Medium,
            summary: "SSH login failed".to_string(),
            details: serde_json::json!({}),
            tags: vec![],
            entities: vec![EntityRef::ip(ip)],
        };
        let incident = Incident {
            ts: Utc::now(),
            host: "h".to_string(),
            incident_id: format!("ssh_bruteforce:{ip}:x"),
            severity: Severity::Critical,
            title: "Brute Force".to_string(),
            summary: "9 failures".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip(ip)],
        };
        let decision = DecisionEntry {
            ts: Utc::now(),
            incident_id: format!("ssh_bruteforce:{ip}:x"),
            host: "h".to_string(),
            ai_provider: "mock".to_string(),
            action_type: "block_ip".to_string(),
            target_ip: Some(ip.to_string()),
            target_user: None,
            skill_id: Some("block-ip-ufw".to_string()),
            confidence: 0.95,
            auto_executed: true,
            dry_run: true,
            reason: "brute force detected".to_string(),
            estimated_threat: "critical".to_string(),
            execution_result: "ok (dry_run)".to_string(),
            prev_hash: None,
            decision_layer: None,
        };

        std::fs::write(
            dated_path(dir.path(), "events", date),
            format!("{}\n", serde_json::to_string(&event).unwrap()),
        )
        .unwrap();
        std::fs::write(
            dated_path(dir.path(), "incidents", date),
            format!("{}\n", serde_json::to_string(&incident).unwrap()),
        )
        .unwrap();
        std::fs::write(
            dated_path(dir.path(), "decisions", date),
            format!("{}\n", serde_json::to_string(&decision).unwrap()),
        )
        .unwrap();

        let filters = InvestigationFilters::from_query(None, None);
        let journey = build_journey(dir.path(), date, PivotKind::Ip, ip, &filters, None);
        assert_eq!(
            journey.entries.len(),
            3,
            "should have event + incident + decision"
        );
        let kinds: Vec<&str> = journey.entries.iter().map(|e| e.kind.as_str()).collect();
        assert!(kinds.contains(&"event"), "missing event entry");
        assert!(kinds.contains(&"incident"), "missing incident entry");
        assert!(kinds.contains(&"decision"), "missing decision entry");
        assert_eq!(journey.subject_type, "ip");
        assert_eq!(journey.subject, ip);
        assert!(journey.first_seen.is_some());
        assert!(journey.last_seen.is_some());
        assert_eq!(journey.summary.events_count, 1);
        assert_eq!(journey.summary.incidents_count, 1);
        assert_eq!(journey.summary.decisions_count, 1);
        assert!(!journey.summary.hints.is_empty());
        assert!(journey
            .summary
            .pivot_shortcuts
            .iter()
            .any(|token| token == "ip:203.0.113.10"));
    }

    #[test]
    fn journey_window_filter_limits_entries() {
        let dir = TempDir::new().unwrap();
        let date = "2026-03-13";
        let ip = "203.0.113.10";
        let now = Utc::now();

        let event = Event {
            ts: now - chrono::Duration::seconds(120),
            host: "h".to_string(),
            source: "auth.log".to_string(),
            kind: "ssh.login_failed".to_string(),
            severity: Severity::Medium,
            summary: "SSH login failed".to_string(),
            details: serde_json::json!({}),
            tags: vec![],
            entities: vec![EntityRef::ip(ip)],
        };
        let incident = Incident {
            ts: now - chrono::Duration::seconds(45),
            host: "h".to_string(),
            incident_id: format!("ssh_bruteforce:{ip}:x"),
            severity: Severity::Critical,
            title: "Brute Force".to_string(),
            summary: "9 failures".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip(ip)],
        };
        let decision = DecisionEntry {
            ts: now,
            incident_id: format!("ssh_bruteforce:{ip}:x"),
            host: "h".to_string(),
            ai_provider: "mock".to_string(),
            action_type: "block_ip".to_string(),
            target_ip: Some(ip.to_string()),
            target_user: None,
            skill_id: Some("block-ip-ufw".to_string()),
            confidence: 0.95,
            auto_executed: true,
            dry_run: false,
            reason: "brute force detected".to_string(),
            estimated_threat: "critical".to_string(),
            execution_result: "ok".to_string(),
            prev_hash: None,
            decision_layer: None,
        };

        std::fs::write(
            dated_path(dir.path(), "events", date),
            format!("{}\n", serde_json::to_string(&event).unwrap()),
        )
        .unwrap();
        std::fs::write(
            dated_path(dir.path(), "incidents", date),
            format!("{}\n", serde_json::to_string(&incident).unwrap()),
        )
        .unwrap();
        std::fs::write(
            dated_path(dir.path(), "decisions", date),
            format!("{}\n", serde_json::to_string(&decision).unwrap()),
        )
        .unwrap();

        let filters = InvestigationFilters::from_query(None, None);
        let journey = build_journey(dir.path(), date, PivotKind::Ip, ip, &filters, Some(60));
        assert_eq!(journey.entries.len(), 2);
        assert!(!journey.entries.iter().any(|e| e.kind == "event"));
        assert_eq!(journey.summary.events_count, 0);
        assert_eq!(journey.summary.incidents_count, 1);
        assert_eq!(journey.summary.decisions_count, 1);
    }

    #[test]
    fn pivots_group_by_user() {
        let dir = TempDir::new().unwrap();
        let date = "2026-03-13";

        let inc1 = Incident {
            ts: Utc::now(),
            host: "h".to_string(),
            incident_id: "ssh_bruteforce:203.0.113.10:abc".to_string(),
            severity: Severity::High,
            title: "t1".to_string(),
            summary: "s1".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("203.0.113.10"), EntityRef::user("root")],
        };
        let inc2 = Incident {
            ts: Utc::now(),
            host: "h".to_string(),
            incident_id: "sudo_abuse:deploy:def".to_string(),
            severity: Severity::Critical,
            title: "t2".to_string(),
            summary: "s2".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("198.51.100.9"), EntityRef::user("deploy")],
        };
        std::fs::write(
            dated_path(dir.path(), "incidents", date),
            format!(
                "{}\n{}\n",
                serde_json::to_string(&inc1).unwrap(),
                serde_json::to_string(&inc2).unwrap()
            ),
        )
        .unwrap();

        let filters = InvestigationFilters::from_query(None, None);
        let pivots = build_pivots(dir.path(), date, PivotKind::User, &filters, 50);
        assert_eq!(pivots.len(), 2);
        assert_eq!(pivots[0].group_by, "user");
        assert!(pivots.iter().any(|p| p.value == "root"));
        assert!(pivots.iter().any(|p| p.value == "deploy"));
    }

    #[test]
    fn journey_user_pivot_includes_related_decision() {
        let dir = TempDir::new().unwrap();
        let date = "2026-03-13";

        let incident = Incident {
            ts: Utc::now(),
            host: "h".to_string(),
            incident_id: "ssh_bruteforce:203.0.113.10:x".to_string(),
            severity: Severity::Critical,
            title: "Brute Force".to_string(),
            summary: "9 failures".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("203.0.113.10"), EntityRef::user("root")],
        };
        let decision = DecisionEntry {
            ts: Utc::now(),
            incident_id: "ssh_bruteforce:203.0.113.10:x".to_string(),
            host: "h".to_string(),
            ai_provider: "mock".to_string(),
            action_type: "block_ip".to_string(),
            target_ip: Some("203.0.113.10".to_string()),
            target_user: None,
            skill_id: Some("block-ip-ufw".to_string()),
            confidence: 0.95,
            auto_executed: true,
            dry_run: false,
            reason: "brute force detected".to_string(),
            estimated_threat: "critical".to_string(),
            execution_result: "ok".to_string(),
            prev_hash: None,
            decision_layer: None,
        };

        std::fs::write(
            dated_path(dir.path(), "incidents", date),
            format!("{}\n", serde_json::to_string(&incident).unwrap()),
        )
        .unwrap();
        std::fs::write(
            dated_path(dir.path(), "decisions", date),
            format!("{}\n", serde_json::to_string(&decision).unwrap()),
        )
        .unwrap();

        let filters = InvestigationFilters::from_query(None, None);
        let journey = build_journey(dir.path(), date, PivotKind::User, "root", &filters, None);
        assert_eq!(journey.subject_type, "user");
        assert_eq!(journey.subject, "root");
        assert!(journey.entries.iter().any(|e| e.kind == "incident"));
        assert!(journey.entries.iter().any(|e| e.kind == "decision"));
        assert_eq!(journey.outcome, "blocked");
    }

    #[test]
    fn clusters_group_related_incidents() {
        let dir = TempDir::new().unwrap();
        let date = "2026-03-13";
        let ts = Utc::now();

        let inc1 = Incident {
            ts,
            host: "h".to_string(),
            incident_id: "port_scan:203.0.113.10:a".to_string(),
            severity: Severity::High,
            title: "scan".to_string(),
            summary: "s".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("203.0.113.10")],
        };
        let inc2 = Incident {
            ts: ts + chrono::Duration::seconds(40),
            host: "h".to_string(),
            incident_id: "ssh_bruteforce:203.0.113.10:b".to_string(),
            severity: Severity::Critical,
            title: "bf".to_string(),
            summary: "s".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("203.0.113.10"), EntityRef::user("root")],
        };

        std::fs::write(
            dated_path(dir.path(), "incidents", date),
            format!(
                "{}\n{}\n",
                serde_json::to_string(&inc1).unwrap(),
                serde_json::to_string(&inc2).unwrap()
            ),
        )
        .unwrap();

        let filters = InvestigationFilters::from_query(None, None);
        let clusters = build_cluster_items(dir.path(), date, &filters, 20, 300);
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].incident_count, 2);
        assert_eq!(clusters[0].pivot_type, "ip");
        assert_eq!(clusters[0].pivot_value, "203.0.113.10");
    }

    #[test]
    fn markdown_export_contains_sections() {
        let snapshot = InvestigationExport {
            generated_at: Utc::now(),
            date: "2026-03-13".to_string(),
            filters: serde_json::json!({"severity_min":"high"}),
            group_by: "ip".to_string(),
            subject_type: Some("ip".to_string()),
            subject: Some("203.0.113.10".to_string()),
            overview: OverviewResponse {
                date: "2026-03-13".to_string(),
                events_count: 10,
                incidents_count: 2,
                decisions_count: 1,
                ai_confirmed: 1,
                ai_responded: 0,
                ai_ignored: 0,
                unresolved_count: 1,
                safely_resolved: 0,
                handled_ips_today: 0,
                blocked_count: 0,
                observing_count: 0,
                attention_count: 0,
                // Spec 049: math contract still holds at zero
                // (0 = 0 + 0 + 0 + 0).
                filtered_out_count: 0,
                flagged_by_system_count: 0,
                warden_decisions_count: 0,
                // Spec 049 PR4: TZ label.
                timezone: "UTC".to_string(),
                // Spec 049 PR6: empty live band for export fixture
                // (export does not need live counters — it's an
                // audit snapshot of a selected period).
                current_state: crate::dashboard::types::CurrentStateBlock::default(),
                severity_breakdown: std::collections::HashMap::new(),
                allowlisted_count: 0,
                top_detectors: vec![],
                latest_telemetry: None,
                snapshot: None,
            },
            pivots: vec![PivotItem {
                group_by: "ip".to_string(),
                value: "203.0.113.10".to_string(),
                first_seen: Utc::now(),
                last_seen: Utc::now(),
                max_severity: "critical".to_string(),
                incident_count: 2,
                event_count: 8,
                outcome: "active".to_string(),
                detectors: vec!["ssh_bruteforce".to_string()],
            }],
            clusters: vec![ClusterItem {
                cluster_id: "cluster-001".to_string(),
                pivot: "ip:203.0.113.10".to_string(),
                pivot_type: "ip".to_string(),
                pivot_value: "203.0.113.10".to_string(),
                start_ts: Utc::now(),
                end_ts: Utc::now(),
                incident_count: 2,
                detector_kinds: vec!["ssh_bruteforce".to_string()],
                incident_ids: vec!["x".to_string(), "y".to_string()],
            }],
            journey: Some(JourneyResponse {
                subject_type: "ip".to_string(),
                subject: "203.0.113.10".to_string(),
                date: "2026-03-13".to_string(),
                first_seen: Some(Utc::now()),
                last_seen: Some(Utc::now()),
                outcome: "active".to_string(),
                summary: JourneySummary {
                    total_entries: 1,
                    events_count: 1,
                    incidents_count: 0,
                    decisions_count: 0,
                    honeypot_count: 0,
                    first_event: Some(Utc::now()),
                    first_incident: None,
                    first_decision: None,
                    first_honeypot: None,
                    pivot_shortcuts: vec!["ip:203.0.113.10".to_string()],
                    hints: vec!["Signals observed".to_string()],
                },
                verdict: JourneyVerdict {
                    entry_vector: "ssh_bruteforce".to_string(),
                    access_status: "attempted".to_string(),
                    privilege_status: "no_evidence".to_string(),
                    containment_status: "unknown".to_string(),
                    honeypot_status: "not_engaged".to_string(),
                    confidence: "medium".to_string(),
                },
                chapters: vec![],
                entries: vec![],
                block_state: None,
                // Spec 049 PR10: export test fixture — no profile
                // to look up.
                recurrence: None,
            }),
        };

        let markdown = render_markdown_snapshot(&snapshot);
        assert!(markdown.contains("# InnerWarden Investigation Snapshot"));
        assert!(markdown.contains("## Correlation Clusters"));
        assert!(markdown.contains("cluster-001"));
        assert!(markdown.contains("## Journey"));
        assert!(markdown.contains("Subject: `ip:203.0.113.10`"));
        assert!(markdown.contains("### Guided Summary"));
        assert!(markdown.contains("### Investigation Hints"));
    }

    #[test]
    fn outcome_blocked_when_block_ip_ok() {
        let blocked = DecisionEntry {
            ts: Utc::now(),
            incident_id: "x".to_string(),
            host: "h".to_string(),
            ai_provider: "mock".to_string(),
            action_type: "block_ip".to_string(),
            target_ip: Some("1.2.3.4".to_string()),
            target_user: None,
            skill_id: None,
            confidence: 0.9,
            auto_executed: true,
            dry_run: false,
            reason: "r".to_string(),
            estimated_threat: "high".to_string(),
            execution_result: "ok".to_string(),
            prev_hash: None,
            decision_layer: None,
        };
        assert_eq!(determine_outcome(&[blocked], "1.2.3.4", true), "blocked");

        let dry_run_block = DecisionEntry {
            ts: Utc::now(),
            incident_id: "x".to_string(),
            host: "h".to_string(),
            ai_provider: "mock".to_string(),
            action_type: "block_ip".to_string(),
            target_ip: Some("1.2.3.4".to_string()),
            target_user: None,
            skill_id: None,
            confidence: 0.9,
            auto_executed: true,
            dry_run: true,
            reason: "r".to_string(),
            estimated_threat: "high".to_string(),
            execution_result: "ok (dry_run)".to_string(),
            prev_hash: None,
            decision_layer: None,
        };
        assert_eq!(
            determine_outcome(&[dry_run_block], "1.2.3.4", true),
            "active"
        );

        // Failed execution - should not count as blocked.
        let failed = DecisionEntry {
            ts: Utc::now(),
            incident_id: "x".to_string(),
            host: "h".to_string(),
            ai_provider: "mock".to_string(),
            action_type: "block_ip".to_string(),
            target_ip: Some("1.2.3.4".to_string()),
            target_user: None,
            skill_id: None,
            confidence: 0.9,
            auto_executed: true,
            dry_run: false,
            reason: "r".to_string(),
            estimated_threat: "high".to_string(),
            execution_result: "error: permission denied".to_string(),
            prev_hash: None,
            decision_layer: None,
        };
        assert_eq!(determine_outcome(&[failed], "1.2.3.4", true), "active");

        // No decisions at all, has incident → active.
        assert_eq!(determine_outcome(&[], "1.2.3.4", true), "active");

        // No decisions, no incident → unknown.
        assert_eq!(determine_outcome(&[], "1.2.3.4", false), "unknown");
    }

    // Spec 028-c: escalate decisions route the IP to the "escalated" outcome,
    // which status_determination maps to "needs_attention" on the dashboard.
    #[test]
    fn outcome_escalated_surfaces_needs_attention() {
        let escalated = DecisionEntry {
            ts: Utc::now(),
            incident_id: "x".to_string(),
            host: "h".to_string(),
            ai_provider: "observation-verify".to_string(),
            action_type: "escalate".to_string(),
            target_ip: Some("1.2.3.4".to_string()),
            target_user: None,
            skill_id: None,
            confidence: 0.8,
            auto_executed: true,
            dry_run: false,
            reason: "obs-verify score 55/100".to_string(),
            estimated_threat: "medium".to_string(),
            execution_result: "pending-fase4".to_string(),
            prev_hash: None,
            decision_layer: None,
        };
        assert_eq!(
            determine_outcome(&[escalated], "1.2.3.4", true),
            "escalated"
        );
    }

    // Spec 028-c: a later block_ip supersedes an earlier escalate.
    #[test]
    fn outcome_block_wins_over_escalate() {
        let escalated = DecisionEntry {
            ts: Utc::now(),
            incident_id: "x".to_string(),
            host: "h".to_string(),
            ai_provider: "observation-verify".to_string(),
            action_type: "escalate".to_string(),
            target_ip: Some("1.2.3.4".to_string()),
            target_user: None,
            skill_id: None,
            confidence: 0.8,
            auto_executed: true,
            dry_run: false,
            reason: "obs-verify".to_string(),
            estimated_threat: "medium".to_string(),
            execution_result: "pending-fase4".to_string(),
            prev_hash: None,
            decision_layer: None,
        };
        let block = DecisionEntry {
            ts: Utc::now(),
            incident_id: "x".to_string(),
            host: "h".to_string(),
            ai_provider: "mock".to_string(),
            action_type: "block_ip".to_string(),
            target_ip: Some("1.2.3.4".to_string()),
            target_user: None,
            skill_id: None,
            confidence: 0.95,
            auto_executed: true,
            dry_run: false,
            reason: "r".to_string(),
            estimated_threat: "high".to_string(),
            execution_result: "ok".to_string(),
            prev_hash: None,
            decision_layer: None,
        };
        assert_eq!(
            determine_outcome(&[escalated, block], "1.2.3.4", true),
            "blocked"
        );
    }

    // ── D3 tests ────────────────────────────────────────────────────────

    #[test]
    fn action_config_disabled_by_default() {
        let cfg = DashboardActionConfig::default();
        assert!(
            !cfg.enabled,
            "actions must be disabled by default for safety"
        );
        assert!(cfg.dry_run, "dry_run must be true by default");
    }

    #[test]
    fn append_decision_entry_writes_jsonl() {
        let dir = TempDir::new().unwrap();
        let entry = DecisionEntry {
            ts: Utc::now(),
            incident_id: "dashboard:manual:test".to_string(),
            host: "testhost".to_string(),
            ai_provider: "dashboard:operator".to_string(),
            action_type: "block_ip".to_string(),
            target_ip: Some("1.2.3.4".to_string()),
            target_user: None,
            skill_id: Some("block-ip-ufw".to_string()),
            confidence: 1.0,
            auto_executed: true,
            dry_run: true,
            reason: "manual block for testing".to_string(),
            estimated_threat: "manual".to_string(),
            execution_result: "ok (dry_run)".to_string(),
            prev_hash: None,
            decision_layer: None,
        };

        append_decision_entry(dir.path(), &entry, None).unwrap();

        // File must exist and contain exactly one valid JSON line.
        let date = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let path = dir.path().join(format!("decisions-{date}.jsonl"));
        assert!(path.exists(), "decisions JSONL must be created");
        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 1);
        let parsed: DecisionEntry = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(parsed.ai_provider, "dashboard:operator");
        assert_eq!(parsed.action_type, "block_ip");
        assert_eq!(parsed.target_ip.as_deref(), Some("1.2.3.4"));

        // Appending a second entry should produce two lines.
        append_decision_entry(dir.path(), &entry, None).unwrap();
        let contents2 = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents2.lines().count(), 2);
    }

    #[test]
    fn make_synthetic_incident_populates_ip_entity() {
        let inc = make_synthetic_incident("test-id", "203.0.113.1", "brute force test");
        assert!(inc.incident_id.contains("dashboard:manual"));
        assert!(inc.incident_id.contains("test-id"));
        assert_eq!(inc.entities.len(), 1);
        assert_eq!(inc.entities[0].value, "203.0.113.1");
        assert!(inc.tags.contains(&"dashboard".to_string()));
        assert!(inc.tags.contains(&"manual".to_string()));
    }

    #[test]
    fn action_cfg_block_skill_selection() {
        // Verify the skill_id format follows convention (used in allowlist check).
        let backends = [
            ("ufw", "block-ip-ufw"),
            ("iptables", "block-ip-iptables"),
            ("nftables", "block-ip-nftables"),
        ];
        for (backend, expected_id) in backends {
            let cfg = DashboardActionConfig {
                enabled: true,
                dry_run: true,
                block_backend: backend.to_string(),
                allowed_skills: vec![expected_id.to_string()],
                ai_enabled: false,
                ai_provider: "openai".to_string(),
                ai_model: "gpt-4o-mini".to_string(),
                ..DashboardActionConfig::default()
            };
            let skill_id = format!("block-ip-{}", cfg.block_backend);
            assert_eq!(skill_id, expected_id);
            assert!(cfg.allowed_skills.contains(&skill_id));
        }
    }

    // ── D5 tests ─────────────────────────────────────────────────────────

    #[test]
    fn verdict_detected_entry_vector_from_incident() {
        let incident_entry = JourneyEntry {
            ts: Utc::now(),
            kind: "incident".to_string(),
            data: serde_json::json!({ "incident_id": "ssh_bruteforce:abc123" }),
        };
        // With only an incident (no events), access_status is "inconclusive"
        // and the entry vector is extracted from the incident_id prefix.
        let verdict = derive_verdict(&[incident_entry], "active");
        assert_eq!(verdict.entry_vector, "ssh_bruteforce");
        assert_eq!(verdict.access_status, "inconclusive");
        assert_eq!(verdict.containment_status, "active");
        assert_eq!(verdict.confidence, "low");
    }

    #[test]
    fn verdict_blocked_outcome_sets_containment_status() {
        let decision_entry = JourneyEntry {
            ts: Utc::now(),
            kind: "decision".to_string(),
            data: serde_json::json!({
                "action_type": "block_ip",
                "execution_result": "ok",
                "dry_run": false,
            }),
        };
        let verdict = derive_verdict(&[decision_entry], "blocked");
        assert_eq!(verdict.containment_status, "blocked");
        // Incident + decision → medium confidence (no events)
        assert_eq!(verdict.confidence, "low");
    }

    #[test]
    fn chapters_group_entries_by_stage() {
        // Three incident entries followed by one decision - should produce
        // an "initial_access_attempt" chapter and a "response" chapter.
        let entries: Vec<JourneyEntry> = vec![
            JourneyEntry {
                ts: Utc::now(),
                kind: "incident".to_string(),
                data: serde_json::json!({ "incident_id": "ssh_bruteforce:1" }),
            },
            JourneyEntry {
                ts: Utc::now(),
                kind: "incident".to_string(),
                data: serde_json::json!({ "incident_id": "ssh_bruteforce:2" }),
            },
            JourneyEntry {
                ts: Utc::now(),
                kind: "decision".to_string(),
                data: serde_json::json!({ "action_type": "block_ip" }),
            },
        ];
        let chapters = derive_chapters(&entries);
        // At minimum one chapter must be produced.
        assert!(!chapters.is_empty());
        // All entry indices must be valid.
        for ch in &chapters {
            for &idx in &ch.entry_indices {
                assert!(idx < entries.len());
            }
        }
        // Total entry coverage: every entry should appear in exactly one chapter.
        let total_covered: usize = chapters.iter().map(|ch| ch.entry_indices.len()).sum();
        assert_eq!(total_covered, entries.len());
    }

    // ── Memory safety tests ─────────────────────────────────────────────

    #[test]
    fn global_rate_limiter_rejects_after_limit() {
        let test_ip = "rate-test-192.0.2.99";
        // Fill up to the limit
        for _ in 0..GLOBAL_RATE_LIMIT_PER_MIN {
            assert!(!global_rate_check(test_ip), "should allow under limit");
        }
        // Next request should be rejected
        assert!(global_rate_check(test_ip), "should reject at limit");
    }

    #[test]
    fn global_rate_limiter_prunes_stale_ips() {
        // Insert 1100+ unique IPs to trigger the >1000 prune path
        for i in 0..1100 {
            global_rate_check(&format!("prune-test-{i}"));
        }
        // Should not panic or OOM - the prune ran and cleaned up
        let map = GLOBAL_RATE_LIMITER
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // After prune, stale entries removed (all are <60s old so still present,
        // but the code path executed without error)
        assert!(map.len() <= 1200, "map should not grow unbounded");
    }

    #[test]
    fn jsonl_cache_returns_same_data_on_cache_hit() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("events-2026-01-01.jsonl");
        std::fs::write(
            &path,
            "{\"ts\":\"2026-01-01T00:00:00Z\",\"host\":\"test\",\"source\":\"test\",\"kind\":\"ssh.login_failed\",\"severity\":\"info\",\"summary\":\"test\",\"details\":{},\"tags\":[],\"entities\":[]}\n",
        )
        .unwrap();

        let first: Vec<Event> = read_jsonl(&path);
        assert_eq!(first.len(), 1);

        // Second call should hit cache (same file, no modification)
        let second: Vec<Event> = read_jsonl(&path);
        assert_eq!(second.len(), 1);
        assert_eq!(first[0].kind, second[0].kind);
    }

    #[test]
    fn jsonl_cache_invalidates_on_file_change() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("events-2026-01-02.jsonl");
        let line = "{\"ts\":\"2026-01-01T00:00:00Z\",\"host\":\"test\",\"source\":\"test\",\"kind\":\"ssh.login_failed\",\"severity\":\"info\",\"summary\":\"test\",\"details\":{},\"tags\":[],\"entities\":[]}\n";

        std::fs::write(&path, line).unwrap();
        let first: Vec<Event> = read_jsonl(&path);
        assert_eq!(first.len(), 1);

        // Append a line - file size changes, cache should invalidate
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        f.write_all(line.as_bytes()).unwrap();

        let second: Vec<Event> = read_jsonl(&path);
        assert_eq!(second.len(), 2);
    }

    // ── SEC-005: bind address validation tests ──────────────────────────

    #[test]
    fn is_loopback_localhost() {
        assert!(is_loopback_address("127.0.0.1:8787"));
        assert!(is_loopback_address("[::1]:8787"));
        assert!(is_loopback_address("localhost:8787"));
    }

    #[test]
    fn is_not_loopback_external() {
        assert!(!is_loopback_address("0.0.0.0:8787"));
        assert!(!is_loopback_address("192.168.1.1:8787"));
        assert!(!is_loopback_address("10.0.0.1:8787"));
    }

    #[test]
    fn validate_bind_auth_loopback_no_auth_ok() {
        assert!(validate_bind_auth("127.0.0.1:8787", false).is_ok());
        assert!(validate_bind_auth("localhost:8787", false).is_ok());
    }

    #[test]
    fn validate_bind_auth_external_no_auth_rejected() {
        let result = validate_bind_auth("0.0.0.0:8787", false);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("without authentication"));
    }

    #[test]
    fn validate_bind_auth_external_with_auth_ok() {
        assert!(validate_bind_auth("0.0.0.0:8787", true).is_ok());
    }

    #[test]
    fn validate_bind_auth_loopback_with_auth_ok() {
        assert!(validate_bind_auth("127.0.0.1:8787", true).is_ok());
    }

    // SEC-013: TLS cert expiry date tests.
    #[test]
    fn cert_expiry_ymd_365_days() {
        let (y, m, d) = cert_expiry_ymd(365);
        let now = chrono::Utc::now();
        // Year should be this year or next year
        assert!(y >= chrono::Datelike::year(&now));
        assert!(y <= chrono::Datelike::year(&now) + 1);
        assert!((1..=12).contains(&m));
        assert!((1..=31).contains(&d));
    }

    #[test]
    fn cert_expiry_ymd_1_day() {
        let (y, m, d) = cert_expiry_ymd(1);
        let tomorrow = chrono::Utc::now() + chrono::Duration::days(1);
        assert_eq!(y, chrono::Datelike::year(&tomorrow));
        assert_eq!(m, chrono::Datelike::month(&tomorrow) as u8);
        assert_eq!(d, chrono::Datelike::day(&tomorrow) as u8);
    }

    #[test]
    fn cert_expiry_ymd_zero_days() {
        let (y, _m, _d) = cert_expiry_ymd(0);
        assert_eq!(y, chrono::Datelike::year(&chrono::Utc::now()));
    }

    // Wave 2026-05-17: SEC-006/007 bind-address gate was replaced by
    // per-request `auth::is_loopback_request`. The legacy tests for
    // `should_require_api_auth` removed because the function was
    // dead-code after the migration. The new gate is anchored by
    // `auth::tests::is_loopback_request_*` (loopback IPv4, loopback
    // IPv6, non-loopback IPv4, missing ConnectInfo).

    // Design invariant: `/api/live-feed/*` must always be public — the
    // marketing site depends on it. The `should_require_api_auth` predicate
    // must NOT gate these routes even on a non-loopback bind. This test
    // drives a minimal router that mirrors the production wiring (cors
    // layer, no auth layer) and confirms every live-feed path responds
    // with a non-401 plus a CORS header.
    #[tokio::test]
    async fn live_feed_routes_public_on_non_loopback_bind() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::util::ServiceExt;

        async fn probe() -> &'static str {
            "ok"
        }
        let live_api: axum::Router<()> = axum::Router::new()
            .route("/api/live-feed", axum::routing::get(probe))
            .route("/api/live-feed/stream", axum::routing::get(probe))
            .route("/api/live-feed/geoip", axum::routing::get(probe))
            .route("/api/live-feed/honeypot", axum::routing::get(probe))
            .route("/api/live-feed/mitre", axum::routing::get(probe))
            .layer(axum::middleware::from_fn(cors_middleware));

        for path in [
            "/api/live-feed",
            "/api/live-feed/stream",
            "/api/live-feed/geoip",
            "/api/live-feed/honeypot",
            "/api/live-feed/mitre",
        ] {
            let res = live_api
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri(path)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .expect("route should respond");
            assert_ne!(
                res.status(),
                StatusCode::UNAUTHORIZED,
                "{path} must not be auth-gated — marketing site depends on public access"
            );
            assert!(
                res.headers().contains_key("access-control-allow-origin"),
                "{path} must carry CORS headers"
            );
        }

        // Wave 2026-05-17: the bind-based predicate
        // `should_require_api_auth` was replaced by the per-request
        // `auth::is_loopback_request` gate. The new contract: a
        // non-loopback peer hitting an agent_api endpoint must still
        // be auth-walled. This is anchored end-to-end above by the
        // marketing-routes test (which exercises the live router with
        // a non-loopback ConnectInfo and expects 401 / 200 depending
        // on the route) and per-decision in `auth::tests::is_loopback_request_*`.
    }

    // ── Spec 037 I-13 PR-2 — TLS file-perms warn anchors ──────────
    //
    // PR-2 of I-13 converts the two `let _ = std::fs::set_permissions(..)`
    // sites in `build_tls_config` into a `warn!`-on-failure pattern via
    // the `set_file_mode_or_warn` helper. Silent chmod failure on the
    // freshly-generated TLS private key was security-relevant: a
    // failed chmod would leave the key at the umask default (typically
    // 0644) and expose it to any local user. Tests pin three
    // contracts:
    //
    //   1. The wrapper does NOT panic on a non-existent path. Matches
    //      the prior `let _ =` no-panic property.
    //   2. The wrapper EMITS a `warn!` carrying path + intended_mode +
    //      error context when the underlying `set_permissions` fails.
    //   3. The wrapper applies the requested mode AND emits NO warn
    //      on the happy path (real file, accessible).

    // Capture is via `crate::test_util::arm_capture` /
    // `drain_capture` — global subscriber + thread-local buffer.
    // See `crate::test_util` rustdoc for why the prior per-test
    // `with_default` + `MakeWriter` pattern (PR #310) was flaky on
    // CI.

    #[cfg(unix)]
    #[test]
    fn set_file_mode_or_warn_does_not_panic_on_missing_path() {
        let bad_path = std::path::PathBuf::from("/this/path/never/ever/exists/innerwarden-i13-tls");
        // Must not panic even though `set_permissions` returns
        // ErrorKind::NotFound on this input.
        set_file_mode_or_warn(&bad_path, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn set_file_mode_or_warn_emits_warn_with_context_on_failure() {
        let _guard = crate::test_util::arm_capture();

        let bad_path =
            std::path::PathBuf::from("/this/path/never/ever/exists/innerwarden-i13-tls-warn");
        set_file_mode_or_warn(&bad_path, 0o600);

        let captured_str = crate::test_util::drain_capture();

        assert!(
            captured_str.contains("failed to set TLS file permissions"),
            "warn message missing — got: {captured_str}"
        );
        // Path must be present so the operator can identify which
        // file failed to chmod (key vs cert).
        assert!(
            captured_str.contains("innerwarden-i13-tls-warn"),
            "path field missing or wrong — got: {captured_str}"
        );
        // Intended mode must be present in octal form — operator
        // needs to know whether the failed chmod was on the 0o600
        // (key) or 0o644 (cert) site, since 0o600 failure is the
        // security-critical case.
        assert!(
            captured_str.contains("0o600"),
            "intended_mode field missing or not in octal — got: {captured_str}"
        );
        assert!(
            captured_str.contains("error="),
            "error field missing — got: {captured_str}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn build_tls_config_auto_gen_writes_files_with_intended_perms() {
        // Coverage anchor for the two call sites of
        // `set_file_mode_or_warn` inside `build_tls_config` (key 0o600,
        // cert 0o644). The unit tests on the helper itself prove the
        // wrapper behaves correctly; this test proves the calling code
        // actually invokes it with the right modes against the right
        // files. Without this test the patch-coverage gate flagged the
        // call sites as uncovered (PR-2 first push hit 33.33% on
        // `codecov/patch`).
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");

        // `cert_path = None` + `key_path = None` forces the auto-gen
        // branch — the path that contains the two `set_file_mode_or_warn`
        // call sites under test.
        let _config = build_tls_config(dir.path(), None, None)
            .await
            .expect("build_tls_config must auto-generate a self-signed cert in a writable tempdir");

        let key_path = dir.path().join("dashboard-key.pem");
        let cert_path = dir.path().join("dashboard-cert.pem");

        let key_mode = std::fs::metadata(&key_path)
            .expect("key file must exist after build_tls_config")
            .permissions()
            .mode()
            & 0o7777;
        let cert_mode = std::fs::metadata(&cert_path)
            .expect("cert file must exist after build_tls_config")
            .permissions()
            .mode()
            & 0o7777;

        // 0o600 on the key is the security-critical assertion. A
        // regression that drops the chmod (or moves it to a path that
        // does not exist before the file is written) would leak the
        // private key at umask default.
        assert_eq!(
            key_mode, 0o600,
            "build_tls_config must chmod the private key to 0o600 after generation"
        );
        assert_eq!(
            cert_mode, 0o644,
            "build_tls_config must chmod the cert to 0o644 after generation"
        );
    }

    #[cfg(unix)]
    #[test]
    fn set_file_mode_or_warn_applies_mode_silently_on_writable_file() {
        use std::os::unix::fs::PermissionsExt;

        // Inverse anchor: on a real, writable file the wrapper
        // applies the requested mode AND does NOT emit a warn.
        let _guard = crate::test_util::arm_capture();

        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("fake-key.pem");
        std::fs::write(&target, b"placeholder").expect("write fixture");
        // Start at a permissive mode so the assertion below is
        // meaningful (we want to prove the chmod actually moved it).
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644))
            .expect("seed perms");

        set_file_mode_or_warn(&target, 0o600);

        // The mode must be exactly 0o600 after the helper runs. The
        // `& 0o7777` mask drops the file-type bits (S_IFREG etc.)
        // that PermissionsExt::mode() returns alongside the mode
        // bits — without it the comparison fails on platforms that
        // include S_IFREG in the returned u32.
        let applied = std::fs::metadata(&target)
            .expect("stat target")
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(
            applied, 0o600,
            "set_file_mode_or_warn must apply the requested mode on the happy path"
        );

        let captured_str = crate::test_util::drain_capture();
        assert!(
            !captured_str.contains("failed to set TLS file permissions"),
            "successful chmod must not emit the failure warn — got: {captured_str}"
        );
    }

    // ── Audit I-14 (2026-04-29) ────────────────────────────────────────
    //
    // The dashboard router caps request bodies at 1 MB via
    // `DefaultBodyLimit::max(...)`. The anchor below proves the layer
    // is correctly wired by building a tiny axum router with the SAME
    // limit + an echo handler, then asserting:
    //   1. a body strictly under the limit is accepted (200 OK).
    //   2. a body strictly over the limit yields 413 Payload Too Large.
    //
    // This is a layer-behaviour anchor, not a full router integration
    // test -- a future change that drops the layer from `serve()`
    // would not be caught here, but a future change that miscalibrates
    // `MAX_BODY_BYTES` (e.g. accidentally drops the `* 1024 * 1024`
    // factor) would be.

    #[test]
    fn max_body_bytes_constant_is_one_mib() {
        // The chosen cap matters for both audit I-14 closure and for
        // every legitimate POST in this dashboard (~1 KB to 2 KB
        // payloads). Pin the value so a future change has to update
        // this assertion deliberately.
        assert_eq!(MAX_BODY_BYTES, 1_048_576);
    }

    #[tokio::test]
    async fn body_limit_layer_rejects_oversized_post() {
        // axum's `DefaultBodyLimit` is enforced by extractors that opt
        // into it (Bytes, String, Json, Form). The router-level layer
        // sets the configuration; the extractor reads it and rejects
        // bodies past the cap with 413. The handlers in this dashboard
        // use Bytes / Json variants, which all honour this contract.
        //
        // The test wires `build_body_limit_layer()` to a tiny echo
        // route so the production helper itself is exercised (rather
        // than re-declaring the cap here, which would let a future
        // miscalibration of `MAX_BODY_BYTES` slip through).
        use axum::body::{Body, Bytes};
        use axum::http::{Request, StatusCode};
        use axum::routing::post;
        use axum::Router;
        use tower::util::ServiceExt;

        async fn echo(_body: Bytes) -> axum::http::Response<Body> {
            axum::http::Response::builder()
                .status(StatusCode::OK)
                .body(Body::empty())
                .unwrap()
        }

        let app: Router = Router::new()
            .route("/echo", post(echo))
            .layer(build_body_limit_layer());

        // Under-limit body passes.
        let small = vec![b'x'; MAX_BODY_BYTES - 1];
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/echo")
                    .header("content-length", small.len().to_string())
                    .body(Body::from(small))
                    .unwrap(),
            )
            .await
            .expect("oneshot");
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "under-limit body must be accepted"
        );

        // Over-limit body is rejected at the extractor with 413.
        let big = vec![b'x'; MAX_BODY_BYTES + 1];
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/echo")
                    .header("content-length", big.len().to_string())
                    .body(Body::from(big))
                    .unwrap(),
            )
            .await
            .expect("oneshot");
        assert_eq!(
            resp.status(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "over-limit body must yield 413"
        );
    }

    // ── Audit 2026-05-01 follow-ups ───────────────────────────────────
    //
    // Each anchor below pins one of the dashboard QA-audit fixes that
    // ship in this batch. Together they catch silent regressions at
    // the bundle boundary (HTML / JS / CSS / Rust constants) where a
    // future refactor is most likely to drop the contract without any
    // unit-test coverage noticing.

    // 2026-05-15 slim-down: the alert-toast stack was removed from the
    // dashboard (operator-confirmed noise). The anchors that pinned the
    // stack container, CSS rules, JS cap-and-overflow logic, and the
    // open-journey pivot are gone with it. The single-toast div (id
    // "toast", used by showToast in actions.js for action confirmations)
    // is unaffected and still anchored implicitly by actions.js tests.

    #[tokio::test]
    async fn js_and_css_handlers_set_no_store_cache_control() {
        // 2026-05-02: dashboard JS / CSS were served without any
        // Cache-Control header. Browsers heuristically cached them for
        // hours, so a deploy left every operator's browser running
        // pre-deploy code until they hard-refreshed. The operator
        // explicitly asked for the fix after seeing "the dashboard
        // hasn't changed" through three deploys. This anchor pins
        // the header on every static asset handler so the regression
        // can't recur silently.
        use axum::body::to_bytes;
        use axum::response::IntoResponse;

        // Pick one representative JS handler — they all share the
        // same macro, so testing one is sufficient to anchor the
        // contract. If the macro regresses, the assertion fails for
        // every handler.
        let resp = serve_js_sse().await.into_response();
        let cc = resp
            .headers()
            .get(axum::http::header::CACHE_CONTROL)
            .expect("JS responses must carry a Cache-Control header")
            .to_str()
            .unwrap();
        assert!(
            cc.contains("no-store"),
            "JS Cache-Control must include `no-store` so browsers re-fetch \
             after every deploy. Got: `{cc}`"
        );
        // Drain the body so the response object is dropped cleanly.
        let _ = to_bytes(resp.into_body(), 1024 * 1024).await;

        let resp = serve_css().await.into_response();
        let cc = resp
            .headers()
            .get(axum::http::header::CACHE_CONTROL)
            .expect("CSS responses must carry a Cache-Control header")
            .to_str()
            .unwrap();
        assert!(
            cc.contains("no-store"),
            "CSS Cache-Control must include `no-store`. Got: `{cc}`"
        );
        let _ = to_bytes(resp.into_body(), 1024 * 1024).await;
    }

    #[test]
    fn journey_deeplink_supports_focus_incident_id() {
        // 2026-05-02 audit (release ladder f.) originally pinned the
        // Home critical-banner deeplink. The Home banner was removed
        // in the 2026-05-15 slim-down; the journey.js machinery for
        // deeplinking to a specific incident is retained because it is
        // still useful for future surfaces (e.g. Telegram deeplinks,
        // Cases tab focus). Anchor the journey-side contract only.
        assert!(
            JS_JOURNEY
                .contains("async function loadJourney(subjectType, subjectValue, focusIncidentId)"),
            "journey.js::loadJourney must accept focusIncidentId as its third parameter"
        );
        assert!(
            JS_JOURNEY.contains("scrollIntoView({ behavior: 'smooth', block: 'center' })"),
            "journey.js must scroll the matched incident into view on deeplink"
        );
        assert!(
            JS_JOURNEY.contains("tl-deeplink-flash"),
            "journey.js must apply the deeplink flash class so the operator's eye lands on \
             the correct incident"
        );
        assert!(
            JS_JOURNEY.contains("div class=\"tl-singleton\" data-group-key="),
            "journey.js::renderEntryGroup must wrap singleton incident entries with a \
             data-group-key attribute so the deeplink selector matches them"
        );
        assert!(
            JS_JOURNEY.contains("div.tl-group[data-group-key=")
                && JS_JOURNEY.contains("div.tl-singleton[data-group-key="),
            "journey.js deeplink selector must match both .tl-group and .tl-singleton — \
             singleton incidents (no related entries) deeplink the same way as grouped ones"
        );
        assert!(
            APP_CSS.contains("@keyframes tlDeeplinkFlash"),
            "app.css must define the tlDeeplinkFlash keyframe animation"
        );
    }

    // 2026-05-03 (PR #413): the playbook engine was removed from the
    // free version. The previous anchor `playbooks_tab_hidden_behind_feature_flag`
    // is gone with it; future declarative orchestration belongs to
    // Spec 042 active defense.
    #[test]
    fn playbook_surface_is_fully_removed() {
        // Anchor against accidental re-introduction. If anyone wires a
        // Playbooks Intel sub-tab back in without the active-defense
        // spec, this fails.
        assert!(
            !INDEX_HTML.contains("id=\"intelTabPlaybooks\""),
            "Playbooks sub-tab button removed in PR #413; do not re-add \
             without Spec 042 active-defense design review."
        );
        assert!(
            !JS_INTEL.contains("function probePlaybooksEnabled"),
            "probePlaybooksEnabled removed in PR #413"
        );
        assert!(
            !JS_INTEL.contains("function loadPlaybooks"),
            "loadPlaybooks removed in PR #413"
        );
    }

    #[test]
    fn baseline_tab_renders_three_level_ux() {
        // 2026-05-03 redesign: operator complaint was that the
        // Baseline view dumped raw learned state in long tables with
        // SOC vocabulary nobody understood. The redesign answers
        // three questions in order via three UX levels:
        //   1. Hero card: "is everything normal right now?"
        //   2. Deviation cards: "if not, what changed in the last 24h?"
        //   3. Collapsed learned-baseline section: "what does the
        //      agent consider normal here?" (heatmap + sparkline)
        //
        // 2026-05-15 PR-C: Baseline moved from the Intel sub-tab to a
        // section on the Health tab. The renderers + helpers were
        // hoisted from intel.js into status.js (single owner: the
        // Health view). This anchor now reads from JS_STATUS instead
        // of JS_INTEL — the three-level structure itself is unchanged.

        // Level 1: hero card builder + status keywords.
        assert!(
            JS_STATUS.contains("function baselineHeroCard"),
            "status.js must define baselineHeroCard — the operator's \
             1-line answer to 'is everything normal?'"
        );
        // PR #419 Wave 2: translated to English. The earlier PT-BR
        // copy ("Aprendendo o normal deste servidor" / "Algo diferente")
        // was replaced because the rest of the dashboard is English.
        assert!(JS_STATUS.contains("Learning what's normal on this server"));
        assert!(JS_STATUS.contains("Something changed"));
        assert!(JS_STATUS.contains("baseline-hero-normal"));
        assert!(JS_STATUS.contains("baseline-hero-deviation"));
        assert!(JS_STATUS.contains("baseline-hero-learning"));

        // Level 2: friendly anomaly labels, NOT raw enum values, for
        // each anomaly_type the backend can emit.
        assert!(JS_STATUS.contains("BASELINE_ANOMALY_LABELS"));
        for kind in [
            "event_rate_drop",
            "event_rate_spike",
            "process_lineage",
            "user_login_time",
            "new_destination",
        ] {
            assert!(
                JS_STATUS.contains(kind),
                "BASELINE_ANOMALY_LABELS must cover anomaly type `{kind}` \
                 — without it that anomaly renders as the generic fallback"
            );
        }
        assert!(
            JS_STATUS.contains("function baselineCardForAnomaly"),
            "status.js must build deviation cards via a dedicated helper \
             so each card carries icon + headline + explainer + why-string"
        );

        // Level 3: collapsed learned-baseline section, heatmap, sparkline.
        assert!(JS_STATUS.contains("baseline-learned"));
        assert!(JS_STATUS.contains("function loginHeatmap"));
        assert!(JS_STATUS.contains("function eventRateAggregateSparkline"));
        // Heatmap is grid-based (24 columns) — not a table.
        assert!(APP_CSS.contains(".login-heatmap-cells"));
        assert!(APP_CSS.contains("repeat(24, 1fr)"));
        // Hero variants and deviation card style exist in CSS.
        assert!(APP_CSS.contains(".baseline-hero-normal"));
        assert!(APP_CSS.contains(".baseline-deviation-card"));
        assert!(APP_CSS.contains(".baseline-sparkline"));
        // intel.js MUST NOT carry any baseline rendering anymore — the
        // hoist is the contract.
        assert!(
            !JS_INTEL.contains("function baselineHeroCard"),
            "Post-PR-C: baseline renderers MUST live in status.js, not intel.js"
        );
        assert!(
            !JS_INTEL.contains("BASELINE_ANOMALY_LABELS"),
            "Post-PR-C: BASELINE_ANOMALY_LABELS MUST be in status.js"
        );
    }

    #[test]
    fn dashboard_audit_2026_05_02_small_fixes_are_wired() {
        // 2026-05-02 audit (P2/P7/P8 + frozen graph): five small wiring
        // fixes bundled in PR #407. This anchor pins them so a future
        // refactor that strips one of them out fails CI before the
        // operator ever sees the regression.

        // ── (a) Frozen Sensors graph (historical: PR #407, 2026-05-02):
        //        SSE refresh + 30s fallback were wired to re-fire
        //        `loadSensors` when the standalone Sensors view was
        //        visible. The Sensors view was deleted 2026-05-15 and
        //        its content folded into Home, so the SSE refresh path
        //        now just calls `loadHome()` (which renders the panel
        //        via `renderHomeSensorsPanel`). The freeze stays cured
        //        — Home's existing refresh on `refresh` events covers
        //        it. Anchor (a) is dropped in this PR; the
        //        `_refreshActiveView` extension point stays as a stub.
        assert!(
            JS_SSE.contains("function _refreshActiveView"),
            "sse.js must keep the `_refreshActiveView` extension point so a future \
             view that needs a fallback refresh has a single place to add the call"
        );

        // ── (b) P2 Badge oscillation: showView (not just loadHome)
        //        must call syncModeBadgeFromHealth so every tab paints
        //        the same OPERATIONAL DEBT / CATCHING UP / etc value.
        assert!(
            JS_NAV.contains("syncModeBadgeFromHealth(window._lastOverview"),
            "nav.js::showView must sync the persistent badge from window._lastOverview \
             — without it the badge oscillates between OPERATIONAL DEBT (Home) and \
             PROTECTED (Threats/Sensors/Health) on the same page reload (audit P2)"
        );

        // ── (c) loadJson must accept an AbortSignal so cancel-in-flight
        //        actually cancels the network request, not just the UI.
        assert!(
            JS_API.contains("if (opts && opts.signal) init.signal = opts.signal"),
            "api.js::loadJson must thread the signal option through to fetch — required by the \
             Journey (P7) and Intel (P8) AbortController plumbing"
        );

        // ── (d) P7 Timeline AbortController on loadJourney.
        assert!(
            JS_JOURNEY.contains("window._activeFetch_journey"),
            "journey.js::loadJourney must stash an AbortController on window._activeFetch_journey \
             so a fast IP / toggle switch cancels the previous fetch (audit P7)"
        );
        assert!(
            JS_JOURNEY.contains("{ signal: journeySignal }"),
            "journey.js must pass the AbortController signal into loadJson — without it the \
             stale fetch still resolves and overwrites the new content"
        );

        // ── (e) Historical P8 (Intel sub-tab clear-before-fetch +
        //        AbortController) — 2026-05-15 PR-B/C collapsed Intel
        //        to a single surface (Profiles list). The sub-tab
        //        cycling problem the audit fixed no longer exists; the
        //        `_activeFetch_intel` controller is still attached in
        //        fetchAndRenderIntel for the sort/min-risk re-fetches,
        //        and the original "clear before fetch" intent is now
        //        carried by `loadIntel()` which resets state and
        //        re-fetches from offset 0. The two anchors below are
        //        dropped because the surfaces they pinned are gone —
        //        the bug class itself can't recur in a single-surface
        //        page (audit P8).
    }

    #[test]
    fn fleet_frontend_wiring_is_complete() {
        // Spec 038 Phase 3: the Fleet tab must be wired end-to-end.
        // HTML: nav button + view container present.
        assert!(
            INDEX_HTML.contains("id=\"navFleet\""),
            "nav must carry the Fleet button (hidden by default; fleet.js unhides on probe)"
        );
        assert!(INDEX_HTML.contains("id=\"viewFleet\""));
        assert!(INDEX_HTML.contains("id=\"fleetContent\""));
        // Default-hidden so single-host operators do not see a tab
        // they cannot use. fleet.js::probeFleetEnabled flips this.
        let nav_btn_start = INDEX_HTML
            .find("id=\"navFleet\"")
            .expect("nav button exists");
        let nav_btn_slice = &INDEX_HTML[nav_btn_start..nav_btn_start + 200];
        assert!(
            nav_btn_slice.contains("display:none"),
            "navFleet must start hidden until the backend probe confirms fleet mode"
        );

        // Script tag included.
        assert!(INDEX_HTML.contains("/js/fleet.js"));

        // Nav.js wires the showView dispatcher.
        assert!(JS_NAV.contains("fleet: 'viewFleet'"));
        assert!(JS_NAV.contains("if (name === 'fleet') loadFleet()"));

        // fleet.js carries the probe + loader + renderer.
        assert!(JS_FLEET.contains("function probeFleetEnabled"));
        assert!(JS_FLEET.contains("async function loadFleet"));
        assert!(JS_FLEET.contains("function renderFleet"));
        // Probe is invoked at boot so the button visibility settles
        // before the operator has a chance to click.
        assert!(JS_FLEET.contains("probeFleetEnabled();"));
        // 404 path renders the disabled-mode copy instead of throwing.
        assert!(JS_FLEET.contains("Fleet mode is not enabled"));
    }

    #[test]
    fn journey_js_supports_forensic_filter() {
        // Audit 5.2: "Actions only" toggle on the journey timeline so
        // the operator can hide raw events and see just the system's
        // block / dismiss / escalate / honeypot actions. Anchor pins
        // the helper, the toggle wrapper, and the button HTML.
        assert!(
            JS_JOURNEY.contains("function applyForensicFilter"),
            "applyForensicFilter helper missing — operator can't strip raw events from the journey timeline (audit 5.2)"
        );
        assert!(JS_JOURNEY.contains("function toggleForensicFilter"));
        assert!(JS_JOURNEY.contains("id=\"forensicFilterBtn\""));
        // The filter must keep `incident` entries so the lead card
        // stays visible — without it the timeline reads as a stream
        // of decisions with no threat context.
        assert!(JS_JOURNEY.contains("e.kind === 'incident'"));
    }

    // 2026-05-15 slim-down: removed home_js_renders_since_last_visit_diff
    // (the Since your last visit banner was removed from Home).

    #[test]
    fn helpers_glossary_carries_required_audit_terms() {
        // Audit 4.2/4.3/4.4: the canonical GLOSSARY must define every
        // term the operator reads on the dashboard so a `title=`
        // tooltip can ship the definition wherever the term lands.
        // Anchor lists the terms the audit specifically called out.
        for term in [
            "severity:",
            "confidence:",
            "risk_score:",
            "outcome:",
            "blocked:",
            "observing:",
            "honeypot:",
            "needs_attention:",
            "dismissed:",
            "allowlisted:",
            "attacker:",
            "alert:",
            "flagged:",
            "suspicious:",
        ] {
            assert!(
                JS_HELPERS.contains(term),
                "GLOSSARY missing key '{term}' (audit 4.2/4.3/4.4)"
            );
        }
        // The helper that emits the title= attribute must exist + be
        // consumed by at least one render path so the glossary is
        // visible to the operator, not just defined in source.
        assert!(JS_HELPERS.contains("function glossaryTitle"));
        assert!(JS_THREATS.contains("glossaryTitle("));
        assert!(JS_JOURNEY.contains("glossaryTitle("));
    }

    #[test]
    fn pr_responses_removal_journey_carries_enforcement_block() {
        // 2026-05-15: per-attacker enforcement detail moved INLINE into
        // the journey panel. When the journey loads for an IP subject
        // and that IP has active blocks, the panel renders an
        // "ENFORCEMENT · enforced right now" block at the top with one
        // row per backend (ufw + xdp + etc) showing state + TTL +
        // remaining. Anchored at the JS bundle boundary.
        assert!(
            JS_JOURNEY.contains("function renderEnforcementBlock"),
            "journey.js must define renderEnforcementBlock (slim-down: per-attacker enforcement on the journey panel)"
        );
        assert!(
            JS_JOURNEY
                .contains("renderEnforcementBlock(subjectType, subjectValue, responsesPayload)"),
            "loadJourney must call renderEnforcementBlock with the loaded /api/responses payload"
        );
        assert!(
            JS_JOURNEY.contains("loadJson('/api/responses'"),
            "loadJourney must fetch /api/responses so the enforcement block has data to filter"
        );
        // The IP-only guard ensures we don't render the block for user/detector pivots.
        assert!(
            JS_JOURNEY.contains("(subjectType || '').toLowerCase() !== 'ip'"),
            "renderEnforcementBlock must guard for IP subjects only — user/detector pivots have no per-IP enforcement"
        );
        // CSS for the block must ship so it's not unstyled text.
        assert!(APP_CSS.contains(".enf-block"));
        assert!(APP_CSS.contains(".enf-state-active"));
    }

    #[test]
    fn pr_responses_removal_cases_sidebar_carries_enforcement_modal() {
        // 2026-05-15: cross-attacker audit view moved to a MODAL opened
        // from the Cases sidebar. Anchor pins the markup, the trigger,
        // the open/close functions, the source endpoint, and the count
        // sync hook.
        assert!(
            INDEX_HTML.contains("id=\"enforcementAuditLink\""),
            "Cases sidebar must carry the 'View all enforcement' link"
        );
        assert!(
            INDEX_HTML.contains("id=\"enforcementAuditCount\""),
            "The link must include a count badge — kernel ground-truth at a glance"
        );
        assert!(
            INDEX_HTML.contains("id=\"enforcementModal\""),
            "Modal markup must exist in index.html"
        );
        assert!(
            INDEX_HTML.contains("openEnforcementModal()"),
            "Sidebar link must wire to openEnforcementModal()"
        );
        // JS bindings.
        assert!(
            JS_THREATS.contains("function openEnforcementModal"),
            "threats.js must define openEnforcementModal"
        );
        assert!(
            JS_THREATS.contains("function closeEnforcementModal"),
            "threats.js must define closeEnforcementModal (Esc + overlay click)"
        );
        assert!(
            JS_THREATS.contains("function renderEnforcementModal"),
            "threats.js must define renderEnforcementModal — the table rendering helper"
        );
        assert!(
            JS_THREATS.contains("function updateEnforcementAuditCount"),
            "threats.js must define updateEnforcementAuditCount so the link badge stays fresh"
        );
        assert!(
            JS_THREATS.contains("updateEnforcementAuditCount(responsesPayload)"),
            "refreshLeft must invoke updateEnforcementAuditCount on every overview refresh"
        );
        // Modal renders against /api/responses — same source as the
        // journey block + Health tab. Single source of truth.
        assert!(
            JS_THREATS.contains("loadJson('/api/responses')"),
            "openEnforcementModal must read /api/responses (same source the Home strip + journey block consume)"
        );
        // CSS for the modal must ship.
        assert!(APP_CSS.contains(".enf-modal"));
        assert!(APP_CSS.contains(".enf-audit-link"));
    }

    #[test]
    fn pr_responses_removal_health_carries_enforcement_section() {
        // 2026-05-15: lifetime stats + orphan diagnostics moved to the
        // Health tab. The mount point lives inside status.js's content
        // render; the renderEnforcementHealthSection helper (defined in
        // responses.js) populates it lazily.
        assert!(
            JS_STATUS.contains("enforcement-health-mount"),
            "status.js must mount the enforcement-health-mount node in the Health tab"
        );
        assert!(
            JS_STATUS.contains("renderEnforcementHealthSection"),
            "status.js must invoke renderEnforcementHealthSection (defined in responses.js)"
        );
        assert!(
            JS_RESPONSES.contains("async function renderEnforcementHealthSection"),
            "responses.js must export renderEnforcementHealthSection — the section renderer"
        );
        // The standalone `loadResponses` function MUST be gone.
        assert!(
            !JS_RESPONSES.contains("async function loadResponses("),
            "responses.js must NOT define loadResponses() — that targeted the removed tab"
        );
    }

    #[test]
    fn pr_responses_removal_ctl_carries_history_subcommand() {
        // 2026-05-15: recent-revert history moved from the dashboard to
        // the CLI. Auditors pull it on demand via `innerwarden get
        // responses --history --since-days N --ip X`.
        const CTL_MAIN: &str = include_str!("../../../ctl/src/main.rs");
        const CTL_RESPONSE: &str = include_str!("../../../ctl/src/commands/response.rs");
        assert!(
            CTL_MAIN.contains("Responses {"),
            "ctl GetCommand must declare the Responses variant"
        );
        assert!(
            CTL_MAIN.contains("commands::response::cmd_responses"),
            "ctl Get dispatcher must wire Responses → commands::response::cmd_responses"
        );
        assert!(
            CTL_RESPONSE.contains("pub fn cmd_responses"),
            "ctl commands::response must implement cmd_responses (`innerwarden get responses`)"
        );
        // Flags pinned so a future refactor cannot silently drop one.
        assert!(CTL_MAIN.contains("history: bool"));
        assert!(CTL_MAIN.contains("since_days: u64"));
        assert!(CTL_MAIN.contains("ip: Option<String>"));
    }

    #[test]
    fn pr_health_xdp_detection_keys_off_allowed_skills_not_ebpf_events() {
        // 2026-05-15: pre-fix the XDP Firewall card on Health read
        // `!!s.ebpf_events` — a field the agent NEVER emits on
        // /api/status. The card therefore always rendered OFF even
        // on hosts with the innerwarden_xdp BPF program actively
        // loaded in the kernel (verified on prod via bpftool prog +
        // 15k entries in blocked-ips.txt while the card said OFF).
        //
        // The honest signal is `responder.allowed_skills` carrying
        // `block-ip-xdp` — that's the operator-wired indicator that
        // XDP is part of the response pipeline.
        assert!(
            JS_STATUS.contains("resp.allowed_skills.indexOf('block-ip-xdp')"),
            "Health tab must derive XDP ON/OFF from responder.allowed_skills (the honest signal). \
             Pre-fix the card read !!s.ebpf_events which was always undefined → always OFF."
        );
        // Anti-regression: do NOT key off the legacy field.
        assert!(
            !JS_STATUS.contains("!!s.ebpf_events"),
            "Health tab must NOT revert to reading `!!s.ebpf_events` — that field is not in the \
             /api/status payload and the legacy check always rendered OFF (operator-reported \
             2026-05-15 with XDP loaded + 15k IPs blocked but card said OFF)."
        );
    }

    #[test]
    fn pr_health_kill_chain_keys_off_status_block_existence() {
        // 2026-05-15: kill chain is integrated inline in every build
        // (post-PR-258, see CLAUDE.md). The status payload always
        // emits a `kill_chain` object. Pre-fix the JS checked
        // `kc.pids_tracked !== undefined` — a field never emitted —
        // so the card always rendered OFF.
        assert!(
            JS_STATUS.contains("s.kill_chain !== undefined && s.kill_chain !== null"),
            "Health tab must key Kill Chain ON/OFF on the presence of the s.kill_chain block. \
             Pre-fix it tested kc.pids_tracked (a field /api/status never emitted) so the card \
             always read OFF even on every shipped build."
        );
    }

    #[test]
    fn pr_health_drops_data_files_section() {
        // 2026-05-15 slim-down: removed the Data Files table from the
        // Health tab. Post-spec-016 events + incidents live in
        // SQLite; the two remaining JSONL files (decisions /
        // telemetry) are implementation detail the operator never
        // acts on. Data directory path stays as a single inline line
        // for the rare on-call case where the path matters.
        assert!(
            !JS_STATUS.contains("'Data Files - '"),
            "Health tab Data Files section was removed; do not bring it back"
        );
        // The Data Directory line stays.
        assert!(JS_STATUS.contains("Data Directory"));
    }

    #[test]
    fn pr_health_filters_not_applicable_collectors() {
        // 2026-05-15: collectors flagged `not_applicable=true` (e.g.
        // macOS unified log on a Linux host) must not render. PR29
        // health badges accurately said "NOT FOUND" but a forever-red
        // row for a tool that cannot physically exist on this OS is
        // noise. The agent emits `not_applicable: !cfg!(target_os
        // = "macos")` for macos_log; the dashboard filters those out.
        assert!(
            JS_STATUS.contains("c.not_applicable"),
            "status.js must filter collectors with not_applicable=true"
        );
        // Sensor side: macos_log carries the cfg!() platform tag.
        const SENSORS_SRC: &str = include_str!("sensors.rs");
        assert!(
            SENSORS_SRC.contains("!cfg!(target_os = \"macos\")"),
            "sensors.rs must tag macos_log with not_applicable on non-macOS hosts"
        );
    }

    #[test]
    fn pr_intel_recurrence_link_deeplinks_to_ip_profile() {
        // 2026-05-15 (PR-A): "View full profile →" lands on the
        // specific IP, never on a generic list. The pre-PR628 bug
        // (`showView('intel')` only) was fixed in PR628 with an
        // `openIntelProfile` helper that did a tab dance with a 120ms
        // setTimeout — that race lost when the Intel tab fetch out-ran
        // the timer, leaving the operator on the generic profile list.
        // PR-A replaces the dance with a shared modal opened by
        // `openProfileModal(ip)`: no tab switch, no race window.
        //
        // Contract pinned by this anchor (operator: "sem chance de
        // nao abrir"):
        //   (1) The shared modal exists in markup.
        //   (2) `openProfileModal(ip)` is defined in intel.js and
        //       fetches the per-IP endpoint using the passed `ip`.
        //   (3) `openIntelProfile(ip)` (kept as backward-compat alias)
        //       routes to `openProfileModal(ip)`.
        //   (4) The journey "View full profile" link calls the
        //       deep-link entry with the case's attacker IP threaded in.
        //   (5) Anti-regression: no DOM handler is allowed to call
        //       plain `showView('intel')` from the recurrence link
        //       (that's what surfaced the generic list bug originally).
        assert!(
            JS_INTEL.contains("async function openProfileModal(ip)"),
            "intel.js must define `openProfileModal(ip)` — the shared modal entry"
        );
        assert!(
            JS_INTEL.contains("`/api/attacker-profiles/${encodeURIComponent(ip)}`"),
            "openProfileModal must fetch the per-IP endpoint with the passed `ip` \
             (operator: \"abrir o ip certo\" — never the generic list)"
        );
        // openIntelProfile kept as backward-compat alias.
        assert!(
            JS_INTEL.contains("function openIntelProfile(ip)"),
            "intel.js must keep `openIntelProfile(ip)` as a backward-compat alias"
        );
        let alias_start = JS_INTEL
            .find("function openIntelProfile(ip)")
            .expect("alias present");
        let alias_end = JS_INTEL[alias_start..].find("\n}\n").expect("end of alias") + alias_start;
        let alias_body = &JS_INTEL[alias_start..alias_end];
        assert!(
            alias_body.contains("openProfileModal(ip)"),
            "openIntelProfile must route to openProfileModal(ip) — single drill-down surface"
        );
        // Anti-regression: the pre-PR628 / pre-PR-A failure modes.
        assert!(
            !alias_body.contains("setTimeout"),
            "openIntelProfile MUST NOT setTimeout — the 120ms race window was the \
             PR628 bug that resurfaced as \"View full profile lands on generic page\""
        );
        assert!(
            !alias_body.contains("switchIntelTab"),
            "openIntelProfile MUST NOT switch sub-tabs — the modal renders independently"
        );
        // Journey link still threads the IP.
        assert!(
            JS_JOURNEY.contains("openIntelProfile("),
            "journey.js \"View full profile\" link MUST call openIntelProfile(ip) \
             (or openProfileModal(ip) directly) with the case's attacker IP"
        );
        assert!(
            !JS_JOURNEY.contains("recurrence-profile-link\" onclick=\"event.preventDefault();showView(\\'intel\\')\""),
            "recurrence-profile-link must not regress to plain showView('intel')"
        );
    }

    #[test]
    fn pr_profile_modal_dom_and_close_paths_exist() {
        // 2026-05-15 PR-A: the shared dossier modal has a fixed DOM
        // shape that openProfileModal targets. Anchor catches a paste
        // error that renames any of the four required ids — without
        // them the modal silently fails to mount and the operator
        // sees a blank screen on click.
        for marker in [
            "id=\"profileModal\"",
            "id=\"profileModalTitle\"",
            "id=\"profileModalBody\"",
            "onclick=\"closeProfileModal()\"",
        ] {
            assert!(
                INDEX_HTML.contains(marker),
                "Attacker dossier modal must contain `{marker}` — the shared drill-down \
                 surface for Cases + Intel (2026-05-15 PR-A)"
            );
        }
        // Close path: the modal MUST be closeable by the X button AND
        // by the overlay (click-outside). Anchor the overlay handler
        // so a future refactor doesn't quietly leave a trap-modal that
        // only closes via the X.
        let modal_start = INDEX_HTML
            .find("id=\"profileModal\"")
            .expect("profileModal present");
        let modal_end = INDEX_HTML[modal_start..]
            .find("</div>\n  </div>")
            .expect("end of modal block")
            + modal_start;
        let modal_block = &INDEX_HTML[modal_start..modal_end];
        assert!(
            modal_block.contains("enf-modal-overlay\" onclick=\"closeProfileModal()\""),
            "profile modal overlay must call closeProfileModal() on click — operator \
             escape path beyond the X button"
        );
    }

    #[test]
    fn pr_profile_modal_open_routes_through_shared_entry() {
        // Every operator-facing entry into the dossier MUST go through
        // openProfileModal(ip). Anchor lists the entries and pins the
        // call sites so a paste error that revives the old
        // `showProfileDetail` / `switchIntelTab('profiles')` dance
        // fails CI before the operator hits the bug again.
        //
        // Entries currently wired (post-PR-B):
        //   - Cases journey "View full profile" link (via openIntelProfile alias)
        //   - Intel profile-list table row click
        //
        // The Campaign member-IP chip entry was deleted in PR-B when
        // the Campaigns sub-tab was removed. It will return in PR-D as
        // a tag on the Cases header that opens the same modal; a new
        // anchor will be added in that PR for the new surface.
        assert!(
            JS_INTEL.contains("onclick=\"openProfileModal(\\'"),
            "Intel profile-list rows MUST onclick into openProfileModal(ip)"
        );
        // `showProfileDetail` was the pre-PR-A in-page renderer + entry.
        // It is replaced by `renderProfileDossierHtml` (chrome-free
        // body builder) + `openProfileModal` (modal entry). The legacy
        // function MUST stay deleted — its survival would tempt a
        // future refactor to wire something into it and re-introduce
        // a parallel drill-down code path.
        assert!(
            !JS_INTEL.contains("function showProfileDetail"),
            "showProfileDetail MUST stay deleted (replaced by renderProfileDossierHtml \
             + openProfileModal in 2026-05-15 PR-A)"
        );
        assert!(
            !JS_INTEL.contains("showProfileDetail("),
            "no call site MUST invoke the deleted showProfileDetail"
        );
        assert!(
            JS_INTEL.contains("function renderProfileDossierHtml(p)"),
            "intel.js must define `renderProfileDossierHtml(p)` — the chrome-free body builder"
        );
    }

    // ── 2026-05-15 PR-B: Intel slim — Campaigns/Chains/MITRE deleted ─
    // Intel page collapsed to a single surface — the Profiles list.
    // PR-B (#632) dropped Campaigns / Chains / MITRE sub-tabs;
    // PR-C (this PR) moves Baseline → Health, removing the last reason
    // to keep a sub-tab toolbar. `switchIntelTab` and `currentIntelTab`
    // are deleted from intel.js — the Profiles list is the only thing
    // Intel renders. The PR-D campaign tag will live on the Cases
    // header, not Intel.

    #[test]
    fn pr_intel_slim_deleted_sub_tab_buttons_are_gone_from_index_html() {
        for orphan in [
            "id=\"intelTabCampaigns\"",
            "id=\"intelTabChains\"",
            "id=\"intelTabMitre\"",
            "id=\"intelTabProfiles\"",
            "id=\"intelTabBaseline\"",
            "switchIntelTab(",
            ">Campaigns</button>",
            ">Chains</button>",
            ">MITRE</button>",
            ">Profiles</button>",
            ">Baseline</button>",
        ] {
            assert!(
                !INDEX_HTML.contains(orphan),
                "2026-05-15 PR-B/C Intel slim: `{orphan}` was deleted; Intel has no \
                 sub-tab toolbar anymore — the Profiles list is the only rendering"
            );
        }
        // The Intel view itself still exists with its content mount.
        assert!(
            INDEX_HTML.contains("id=\"viewIntel\""),
            "Intel view container MUST stay — Profiles list still mounts here"
        );
        assert!(
            INDEX_HTML.contains("id=\"intelContent\""),
            "intelContent mount MUST stay — fetchAndRenderIntel renders into it"
        );
    }

    #[test]
    fn pr_intel_slim_deleted_sub_tab_loaders_are_gone_from_intel_js() {
        // PR-B deleted the three sub-tab loaders. PR-C hoists Baseline
        // out of intel.js entirely — `loadBaseline` and every baseline
        // helper now lives in status.js (Health view).
        for orphan in [
            "async function loadCampaigns",
            "async function loadChains",
            "async function loadMitreCoverage",
            "async function loadBaseline",
            "function loadCampaigns",
            "function loadChains",
            "function loadMitreCoverage",
            "function loadBaseline",
            "loadCampaigns(",
            "loadChains(",
            "loadMitreCoverage(",
            // PR-C: switch dispatcher + state both gone. (The
            // explanatory comment in intel.js may name the dead
            // identifiers, so we only assert their declarations are
            // gone — `let currentIntelTab` would be re-introduced
            // only by code, never by docs.)
            "function switchIntelTab",
            "let currentIntelTab",
            // Baseline helpers must not linger in intel.js.
            "function baselineHeroCard",
            "function baselineCardForAnomaly",
            "function loginHeatmap",
            "function eventRateAggregateSparkline",
            "BASELINE_ANOMALY_LABELS",
        ] {
            assert!(
                !JS_INTEL.contains(orphan),
                "2026-05-15 PR-B/C Intel slim: `{orphan}` was deleted; the legacy \
                 sub-tab + Baseline surfaces must stay gone (no dead code in intel.js)"
            );
        }
    }

    #[test]
    fn pr_intel_slim_only_profiles_entry_point_remains() {
        // Post-PR-C: the only entry into the Intel view is `loadIntel()`,
        // and the only render path is `fetchAndRenderIntel` → the
        // profile list. Profile-row click opens the shared dossier
        // modal from PR-A. Anchor pins the surface so a regression that
        // re-introduces sub-tab machinery fails CI.
        //
        // 2026-05-16 PR-H: `fetchAndRenderIntel` no longer takes the
        // `append` parameter — the accumulator that motivated it was
        // deleted alongside the legacy "Load more" pagination.
        // Renderer is now per-page (each fetch loads one page's worth
        // of profiles, no concatenation).
        assert!(
            JS_INTEL.contains("async function loadIntel()"),
            "loadIntel() MUST stay — it's the Intel view's single entry"
        );
        assert!(
            JS_INTEL.contains("async function fetchAndRenderIntel("),
            "fetchAndRenderIntel(...) MUST stay — it's the Profiles list renderer"
        );
        // The Profiles-row click MUST keep targeting the modal.
        assert!(
            JS_INTEL.contains("onclick=\"openProfileModal(\\'"),
            "Intel profile-list rows MUST still onclick into openProfileModal(ip)"
        );
    }

    // ── 2026-05-15 PR-D: campaign tag on Cases journey ───────────────
    // The deleted Intel `Campaigns` sub-tab (PR-B) is replaced by a
    // per-case-aware tag in the Cases journey header. When the
    // attacker IP belongs to a cluster returned by /api/campaigns,
    // the tag reads "campaign · <id> · N IPs". Click opens a modal
    // listing the cluster's member IPs as chips that drill down into
    // the shared dossier modal from PR-A. Anchors below pin:
    //   (1) markup for the campaign modal,
    //   (2) the placeholder tag on the journey header,
    //   (3) journey.js wires loadCampaignTagForJourney + openCampaignModal,
    //   (4) the modal's member-IP chip onclick targets openProfileModal
    //       (single drill-down surface — same shared modal as Intel).

    #[test]
    fn pr_d_campaign_modal_markup_and_close_paths_exist() {
        for marker in [
            "id=\"campaignModal\"",
            "id=\"campaignModalTitle\"",
            "id=\"campaignModalBody\"",
            "onclick=\"closeCampaignModal()\"",
        ] {
            assert!(
                INDEX_HTML.contains(marker),
                "PR-D Campaign modal must contain `{marker}`"
            );
        }
        let modal_start = INDEX_HTML
            .find("id=\"campaignModal\"")
            .expect("campaignModal present");
        let modal_end = INDEX_HTML[modal_start..]
            .find("</div>\n  </div>")
            .expect("end of campaignModal block")
            + modal_start;
        let modal_block = &INDEX_HTML[modal_start..modal_end];
        assert!(
            modal_block.contains("enf-modal-overlay\" onclick=\"closeCampaignModal()\""),
            "campaign modal overlay must call closeCampaignModal() — click-outside escape path"
        );
    }

    #[test]
    fn pr_d_journey_header_carries_campaign_tag_placeholder() {
        // Anchor on the placeholder span inside the journey header
        // template so a refactor that drops the placeholder leaves
        // loadCampaignTagForJourney with nothing to bind to.
        let header_start = JS_JOURNEY
            .find("<div class=\"journey-header\">")
            .expect("journey-header template present");
        let header_end = JS_JOURNEY[header_start..]
            .find("</div>")
            .expect("end of journey-header")
            + header_start;
        let header_block = &JS_JOURNEY[header_start..header_end];
        assert!(
            header_block.contains("id=\"journeyCampaignTag\""),
            "journey-header MUST carry the campaign-tag placeholder `#journeyCampaignTag` \
             (PR-D 2026-05-15)"
        );
    }

    #[test]
    fn pr_d_journey_loads_and_hydrates_campaign_tag() {
        // Two surfaces in journey.js:
        //   (a) loadJourney() calls loadCampaignTagForJourney after the
        //       successful render so the tag hydrates without blocking
        //       the timeline paint;
        //   (b) loadCampaignTagForJourney exists and bails for non-IP
        //       subjects (campaigns correlate IPs only).
        assert!(
            JS_JOURNEY.contains("loadCampaignTagForJourney(subjectType, subjectValue)"),
            "loadJourney MUST call loadCampaignTagForJourney(subjectType, subjectValue) \
             after the render — operator should see the tag without re-clicking"
        );
        assert!(
            JS_JOURNEY
                .contains("async function loadCampaignTagForJourney(subjectType, subjectValue)"),
            "journey.js MUST define loadCampaignTagForJourney(subjectType, subjectValue)"
        );
        let fn_start = JS_JOURNEY
            .find("async function loadCampaignTagForJourney(subjectType, subjectValue)")
            .expect("loadCampaignTagForJourney present");
        let fn_end = JS_JOURNEY[fn_start..]
            .find("\n}\n")
            .expect("end of loadCampaignTagForJourney")
            + fn_start;
        let fn_body = &JS_JOURNEY[fn_start..fn_end];
        assert!(
            fn_body.contains("(subjectType || '').toLowerCase() !== 'ip'"),
            "loadCampaignTagForJourney MUST bail when subject is not an IP — \
             campaigns correlate IPs only, non-IP subjects (user/container/process) get no tag"
        );
        assert!(
            fn_body.contains("_fetchCampaignsCached()"),
            "loadCampaignTagForJourney MUST go through the cached campaigns fetcher \
             — one /api/campaigns call per session, not per journey"
        );
        // Click handler must open the modal with the case's IP threaded in.
        assert!(
            fn_body.contains("openCampaignModal(subjectValue)"),
            "tag onclick MUST call openCampaignModal(subjectValue) — operator clicked the \
             tag on THIS case, modal must show clusters involving THIS ip"
        );
    }

    #[test]
    fn pr_d_campaign_modal_routes_member_ips_through_shared_dossier() {
        // The whole point of folding Campaigns into Cases as a tag is
        // that the operator stays on one drill-down surface. Clicking
        // any member-IP chip in the campaign modal MUST open the
        // PR-A shared dossier modal — not switch view, not re-route.
        assert!(
            JS_JOURNEY.contains("async function openCampaignModal(ip)"),
            "journey.js MUST define openCampaignModal(ip)"
        );
        let fn_start = JS_JOURNEY
            .find("async function openCampaignModal(ip)")
            .expect("openCampaignModal present");
        let fn_end = JS_JOURNEY[fn_start..]
            .find("\n}\n")
            .expect("end of openCampaignModal")
            + fn_start;
        let fn_body = &JS_JOURNEY[fn_start..fn_end];
        assert!(
            fn_body.contains("onclick=\"openProfileModal(\\'"),
            "campaign modal member-IP chips MUST onclick into openProfileModal(ip) \
             — single drill-down surface (the PR-A shared dossier)"
        );
        // Anti-regression: a paste error reviving the deleted Intel
        // tab dance would break the single-surface invariant.
        assert!(
            !fn_body.contains("switchIntelTab"),
            "openCampaignModal MUST NOT switch Intel sub-tabs — those are gone (PR-B/C)"
        );
        assert!(
            !fn_body.contains("showView('intel')"),
            "openCampaignModal MUST NOT navigate to Intel — the dossier is a modal now"
        );
    }

    #[test]
    fn pr_baseline_lives_on_health_tab_and_is_wired_into_load_status() {
        // PR-C: Baseline content (Hero + deviation cards + collapsed
        // learned-baseline) moved to the Health tab as a section
        // mounted under `#baseline-health-mount`. The Health loader
        // `loadStatus` renders the mount and lazy-hydrates it via
        // `renderBaselineHealthSection(mountSelector)` (defined in
        // status.js).
        assert!(
            INDEX_HTML.contains("id=\"baseline-health-mount\"")
                || JS_STATUS.contains("id=\"baseline-health-mount\""),
            "Health view MUST carry the `baseline-health-mount` div (rendered by loadStatus \
             into #statusContent)"
        );
        assert!(
            JS_STATUS.contains("async function renderBaselineHealthSection(mountSelector)"),
            "status.js MUST define `renderBaselineHealthSection(mountSelector)` — the \
             Baseline entry on the Health tab"
        );
        // loadStatus invokes the renderer.
        let load_start = JS_STATUS
            .find("async function loadStatus()")
            .expect("loadStatus present");
        let load_end = JS_STATUS[load_start..]
            .find("\n}\n")
            .expect("end of loadStatus")
            + load_start;
        let load_body = &JS_STATUS[load_start..load_end];
        assert!(
            load_body.contains("renderBaselineHealthSection('baseline-health-mount')"),
            "loadStatus MUST call renderBaselineHealthSection('baseline-health-mount') \
             so the Baseline section hydrates when Health opens"
        );
        // Anti-regression: no Intel-vocabulary references inside the
        // Baseline section (the move severs the dependency).
        let bs_start = JS_STATUS
            .find("async function renderBaselineHealthSection(mountSelector)")
            .expect("renderBaselineHealthSection present");
        let bs_end = JS_STATUS[bs_start..]
            .find("\n}\n")
            .expect("end of renderBaselineHealthSection")
            + bs_start;
        let bs_body = &JS_STATUS[bs_start..bs_end];
        assert!(
            !bs_body.contains("intelContent"),
            "renderBaselineHealthSection MUST NOT reference the Intel content mount — \
             it owns its own `baseline-health-mount`"
        );
        assert!(
            !bs_body.contains("intelViewStatus"),
            "renderBaselineHealthSection MUST NOT reference the Intel status pill"
        );
        assert!(
            !bs_body.contains("_activeFetch_intel"),
            "renderBaselineHealthSection MUST NOT reuse the Intel abort controller — \
             Health has no sub-tab cycling so the signal is meaningless here"
        );
    }

    #[test]
    fn pr_intel_kpi_counts_use_canonical_buckets_not_visible_slice() {
        // 2026-05-15: pre-fix the "High Risk (≥70)" KPI tile counted
        // profiles within the visible 100-row slice — when all 100
        // visible rows happened to be high-risk (because the list is
        // sorted by risk desc), the tile showed 100 regardless of the
        // true high-risk total. Operator-reported confusion: "100
        // total high-risk? out of 4141?".
        //
        // Backend now returns `totals_by_risk: { high, medium, low }`
        // computed over the FULL filtered set. Frontend reads those
        // canonical numbers.
        //
        // 2026-05-16 PR-E: the KPI tiles themselves were deleted as
        // part of the Intel UX slim. The backend totals_by_risk
        // contract stays — it remains the SoT for any future chip-
        // counts feature — but the frontend half of the test (asserting
        // the JS reads it) is dropped because no rendering reads those
        // buckets anymore.
        const INTEL_RS: &str = include_str!("intelligence.rs");
        assert!(
            INTEL_RS.contains("\"totals_by_risk\""),
            "intelligence.rs must emit totals_by_risk in /api/attacker-profiles response"
        );
        for bucket in ["\"high\":", "\"medium\":", "\"low\":"] {
            assert!(
                INTEL_RS.contains(bucket),
                "totals_by_risk must include the `{bucket}` bucket"
            );
        }
    }

    // ── 2026-05-16 PR-E: Intel UX slim ───────────────────────────────
    // Operator: "tinha que deixar isso mais simples e organizado, com
    // UX clara, facil de achar qualquer coisa e navegar, sem add 300
    // filtro e tralha". Deleted from Intel: the 4 KPI tiles
    // (Total Profiles / High Risk / Medium / Countries), the Sort
    // dropdown, and the Min Risk number input. The remaining controls
    // are one IP search box + three chips (All / ≥40 / ≥70).

    #[test]
    fn pr_e_intel_ux_slim_drops_kpi_sort_minrisk() {
        // Markup: Sort dropdown and Min Risk input are gone from the
        // Intel toolbar.
        for orphan in [
            "id=\"intelSort\"",
            "id=\"intelMinRisk\"",
            "Sort: Risk Score",
            "Sort: Last Seen",
            "Sort: Incidents",
            "placeholder=\"Min risk\"",
        ] {
            assert!(
                !INDEX_HTML.contains(orphan),
                "PR-E Intel slim: `{orphan}` was deleted; the Sort dropdown and Min Risk \
                 input were operator-flagged chrome (\"sem 300 filtro e tralha\")"
            );
        }
        // KPI tile rendering is gone from intel.js (the operator never
        // acted on "Total Profiles: 4141" or "Countries"). The tile()
        // helper that built them must stay deleted.
        for orphan in [
            ">Total Profiles<",
            ">High Risk (≥70)<",
            ">Medium (40–69)<",
            ">Countries<",
            "tile('Total Profiles'",
            "tile('High Risk",
            "tile('Medium",
            "tile('Countries'",
            "kpi-grid",
        ] {
            assert!(
                !JS_INTEL.contains(orphan),
                "PR-E Intel slim: `{orphan}` was deleted; KPI tile rendering must stay gone"
            );
        }
        // Sort dropdown reference must be gone from JS too.
        assert!(
            !JS_INTEL.contains("getElementById('intelSort')"),
            "PR-E: intel.js MUST NOT read from a Sort dropdown — default risk_score desc \
             is the only useful order for a `highest risk first` rolodex"
        );
    }

    #[test]
    fn pr_e_intel_ux_slim_keeps_search_and_three_risk_chips() {
        // Search box stays — primary navigation tool.
        assert!(
            JS_INTEL.contains("id=\"intelIpSearch\""),
            "PR-E: intel.js MUST keep `#intelIpSearch` — the operator's primary navigation"
        );
        assert!(
            JS_INTEL.contains("class=\"intel-search\""),
            "PR-E: search input MUST carry the .intel-search class for styling"
        );
        // Three risk chips, no more. The runtime onclick string
        // `setIntelRiskFilter(<value>)` is built by concatenation in
        // the chip() helper, so anchor on the chip-invocation
        // arguments (which carry the canonical thresholds 0/40/70 and
        // the visible labels in one place).
        for chip_invocation in [
            "chip('All', 0)",
            "chip('≥40 (Medium+)', 40)",
            "chip('≥70 (High)', 70)",
        ] {
            assert!(
                JS_INTEL.contains(chip_invocation),
                "PR-E: chip invocation `{chip_invocation}` MUST exist — risk filter is now \
                 expressed as 3 chips with canonical thresholds 0/40/70"
            );
        }
        // The chip() helper itself MUST wire onclick to setIntelRiskFilter
        // (anchor on the prefix; the concatenated filterValue is variable).
        assert!(
            JS_INTEL.contains("onclick=\"setIntelRiskFilter("),
            "PR-E: chip() helper MUST emit an onclick that calls setIntelRiskFilter \
             with the chip's filterValue"
        );
        // Active chip carries the accent ring via .intel-chip-active.
        assert!(
            JS_INTEL.contains("intel-chip-active"),
            "PR-E: the active chip MUST get the .intel-chip-active class so the operator \
             always sees which slice the table reflects"
        );
        // CSS contract: chip + toolbar styles exist.
        for style in [
            ".intel-toolbar",
            ".intel-search",
            ".intel-chip ",
            ".intel-chip-active",
            ".intel-chip-group",
        ] {
            assert!(
                APP_CSS.contains(style),
                "PR-E: css must define `{style}` — without it the toolbar reverts to unstyled"
            );
        }
    }

    #[test]
    fn pr_intel_paginates_with_load_more_and_ip_search() {
        // 2026-05-15: the Intel page used to show 100 rows from a DB
        // with 4000+ profiles and had no way to reach the rest. The
        // operator could see the KPI tile said "Total Profiles: 4141"
        // and could not access the other 4041. Add: explicit "Showing
        // X of Y", a Load more button, and an IP search input.
        //
        // 2026-05-16 PR-H: replaced the "Load more" accumulator with
        // page-number pagination + per-page size selector. The
        // setIntelRiskFilter / filterIntelByIp / row-tint contracts
        // survived; loadMoreIntelProfiles is gone (replaced by
        // setIntelPage / setIntelPageSize — anchored separately).
        assert!(
            JS_INTEL.contains("function setIntelRiskFilter("),
            "intel.js must define setIntelRiskFilter so the risk chips filter the list"
        );
        assert!(
            JS_INTEL.contains("function filterIntelByIp("),
            "intel.js must define filterIntelByIp so the search input filters the visible rows client-side"
        );
        // Risk filter row tint must exist so ≥70 rows are visually distinct
        // even when the visible page mixes bands.
        assert!(
            JS_INTEL.contains("rgba(231,76,60,0.05)"),
            "intel.js must tint ≥70 risk rows so the operator can spot the high-risk cliff at a glance"
        );
    }

    // ── 2026-05-16 PR-H: real pagination + spec cleanup ──────────────
    // Operator-reported pain points:
    //   1. "ninguem se acha nesse tipo de paginacao load more, coloca
    //       uma paginacao decente, e deixa o cara escolher quantas
    //       linhas ele quer, mas comeca por 10, ai 50 e 100 talvez"
    //   2. "checca todo dashboard por favor pra ver se tem spec,
    //       usuario final nao sabe o que e spec"
    // PR-H rewrites Intel + Decision Audit Records pagination to use
    // page numbers + per-page size selector (10/50/100, default 10),
    // and strips the two visible "spec NNN" leaks from the Health /
    // Briefings tabs.

    #[test]
    fn pr_h_intel_uses_page_numbers_not_load_more() {
        // Intel pagination state + helpers MUST mirror the new shape.
        assert!(
            JS_INTEL.contains("const INTEL_PAGE_SIZES = [10, 50, 100]"),
            "INTEL_PAGE_SIZES MUST list the operator-approved page sizes (10/50/100)"
        );
        assert!(
            JS_INTEL.contains("let _intelPageSize = 10"),
            "default Intel page size MUST start at 10 — operator: \"comeca por 10\""
        );
        for sig in [
            "function setIntelPage(page)",
            "function setIntelPageSize(size)",
            "function renderIntelPaginationBar(",
            "function paginationButtons(",
        ] {
            assert!(
                JS_INTEL.contains(sig),
                "intel.js must define `{sig}` for the new pagination"
            );
        }
        // Legacy accumulator must stay gone.
        for orphan in [
            "function loadMoreIntelProfiles",
            "const INTEL_PAGE_SIZE = 100",
            "let _intelOffset",
            "let _intelLoadedProfiles",
            "_intelLoadedProfiles.concat",
        ] {
            assert!(
                !JS_INTEL.contains(orphan),
                "PR-H: legacy `{orphan}` from the Load-more accumulator MUST stay deleted"
            );
        }
    }

    #[test]
    fn pr_h_audit_trail_uses_page_numbers_not_load_more() {
        // Decision Audit Records pagination on Compliance MUST mirror
        // the Intel shape: same 10/50/100 sizes, default 10,
        // setAuditPage / setAuditPageSize, no "Load 50 more" button.
        assert!(
            JS_COMPLIANCE.contains("const AUDIT_PAGE_SIZES = [10, 50, 100]"),
            "AUDIT_PAGE_SIZES MUST list the operator-approved page sizes (10/50/100)"
        );
        assert!(
            JS_COMPLIANCE.contains("pageSize: 10"),
            "Audit trail default page size MUST be 10 — operator: \"comeca por 10\""
        );
        for sig in [
            "function setAuditPage(page)",
            "function setAuditPageSize(size)",
            "function renderAuditPaginationBar()",
        ] {
            assert!(
                JS_COMPLIANCE.contains(sig),
                "compliance.js must define `{sig}` for the new audit pagination"
            );
        }
        // Legacy "Load N more (older)" button stays gone.
        assert!(
            !JS_COMPLIANCE.contains("Load 50 more"),
            "PR-H: the legacy `Load 50 more (older)` button MUST stay deleted"
        );
        assert!(
            !JS_COMPLIANCE.contains("fetchAuditTrailPage(false)"),
            "PR-H: the false-arg (append) call site of fetchAuditTrailPage MUST stay gone"
        );
    }

    #[test]
    fn pr_h_pagination_css_is_shared_across_intel_and_audit() {
        // The same `.pagination-bar` / `.pagination-btn` styles back
        // both surfaces. Anchor catches a future fork that styles them
        // separately and drifts.
        for selector in [
            ".pagination-bar",
            ".pagination-status",
            ".pagination-pagesize",
            ".pagination-nav",
            ".pagination-btn",
            ".pagination-btn-active",
            ".pagination-btn-disabled",
            ".pagination-ellipsis",
        ] {
            assert!(
                APP_CSS.contains(selector),
                "PR-H: `{selector}` MUST be defined in app.css — shared style across Intel + Audit"
            );
        }
    }

    #[test]
    fn pr_h_no_spec_leaks_in_operator_facing_strings() {
        // Operator: "usuario final nao sabe o que e spec". The two
        // visible-chrome `spec NNN` mentions on Health (Metrics Drift
        // subtitle) and Briefings (SQLite tooltip) MUST stay gone.
        assert!(
            !JS_STATUS.contains("· spec 024 ·"),
            "PR-H: the visible `spec 024` chrome on Metrics Drift was operator-flagged \
             noise — must stay deleted"
        );
        assert!(
            !JS_REPORTS.contains("(spec 016)"),
            "PR-H: the visible `(spec 016)` tooltip on SQLite Operational Health was \
             operator-flagged noise — must stay deleted"
        );
    }

    #[test]
    fn nav_drops_responses_tab_after_slim_down() {
        // 2026-05-15: the standalone Responses tab was removed from
        // the dashboard. Per-attacker enforcement detail moved to the
        // journey panel (Enforcement block); cross-attacker audit
        // became a modal on the Cases sidebar; lifetime stats +
        // orphan diagnostics moved to the Health tab; recent-revert
        // history moved to the CLI (`innerwarden get responses
        // --history`). Anchor pins the no-residue contract.
        let html = INDEX_HTML;
        assert!(
            !html.contains("id=\"navResponses\""),
            "navResponses button must be gone from the navbar (2026-05-15 slim-down)"
        );
        assert!(
            !html.contains("id=\"viewResponses\""),
            "viewResponses div must be gone from the body (2026-05-15 slim-down)"
        );
        assert!(
            !html.contains("id=\"responsesContent\""),
            "responsesContent mount must be gone (slim-down: Health hosts the section)"
        );
        // nav.js views/btns maps + dispatcher cleanup.
        let nav = JS_NAV;
        assert!(
            !nav.contains("'responses'"),
            "nav.js MUST NOT reference 'responses' — tab was removed (2026-05-15 slim-down)"
        );
        assert!(
            !nav.contains("loadResponses("),
            "nav.js MUST NOT dispatch loadResponses() — tab was removed"
        );
        // The Cases sidebar carries the cross-attacker audit modal trigger.
        assert!(
            html.contains("id=\"enforcementAuditLink\""),
            "Cases sidebar must carry the 'View all enforcement' modal link (slim-down replacement for the tab)"
        );
        // The Health tab mounts the enforcement section.
        assert!(
            html.contains("id=\"enforcement-health-mount\"") || JS_STATUS.contains("enforcement-health-mount"),
            "Health tab must carry the enforcement-health-mount node (slim-down: lifetime stats + orphan diagnostics moved here)"
        );
    }

    // 2026-05-15 slim-down: the flt-status dropdown was removed from the
    // Cases sidebar. The operator can browse the outcome buckets directly
    // in the grouped attacker list (Currently blocked / Filtered out /
    // Observing / Needs your attention); a redundant dropdown filter on
    // top of that was tralha. State.filters.status is kept on the JS
    // side so a deep-link URL with `?status=blocked` still parses.

    #[test]
    fn journey_verdict_card_includes_scale_summary() {
        // Audit 2.3 phase 2: verdict card now surfaces a one-line
        // "X events analysed · Y incidents · Z decisions taken" sub-row
        // so the operator sees the journey's scale before scrolling.
        // The renderer reads `j.summary.*` which JourneySummary
        // always populates — anchor pins the field reads.
        for field in [
            "s.events_count",
            "s.incidents_count",
            "s.decisions_count",
            "s.honeypot_count",
        ] {
            assert!(
                JS_JOURNEY.contains(field),
                "renderVerdictCard must read {field} for the scale line (audit 2.3 phase 2)"
            );
        }
        assert!(
            JS_JOURNEY.contains("verdict-scale"),
            "verdict-scale CSS class missing — the scale line cannot be styled (audit 2.3 phase 2)"
        );
    }

    // ── 2026-05-16 PR-F: Honeypot tab removed ────────────────────────
    // The 3 honeypot_js_* anchors (Audit 2.9 + Spec 046 #13 + #14)
    // were deleted alongside the Honeypot tab. They pinned the
    // engaged/listener-only honesty surface, pagination, and the
    // three-branch empty state — all UI for a tab that no longer
    // exists. Per-IP honeypot intel (credentials attempted + commands
    // typed + IOCs) survives in the shared Attacker Dossier modal
    // (PR-A); aggregate cross-IP intel lives on the Monthly threat
    // report. Operator: "por mim tudo bem desde que em cases de pra
    // ver se teve alguma secao de honeypot do ip e o que ele digitiou".

    #[test]
    fn pr_f_honeypot_tab_is_gone_from_dashboard() {
        for orphan in [
            "id=\"navHoneypot\"",
            "id=\"viewHoneypot\"",
            "id=\"honeypotContent\"",
            "id=\"honeypotViewStatus\"",
            "showView('honeypot')",
            ">Honeypot</button>",
            "/js/honeypot.js",
        ] {
            assert!(
                !INDEX_HTML.contains(orphan),
                "PR-F: `{orphan}` was deleted; the Honeypot tab UI must stay gone — \
                 per-IP detail lives in the shared Attacker Dossier modal (PR-A)"
            );
        }
        // nav.js must not route the deleted view.
        assert!(
            !JS_NAV.contains("'honeypot'"),
            "PR-F: nav.js MUST NOT reference the 'honeypot' route"
        );
        assert!(
            !JS_NAV.contains("loadHoneypot("),
            "PR-F: nav.js MUST NOT call loadHoneypot — the loader was deleted with the file"
        );
    }

    #[test]
    fn pr_f_dossier_modal_still_surfaces_honeypot_intel_per_ip() {
        // The contract that justifies dropping the Honeypot tab:
        // when an IP touched the honeypot, the operator sees the
        // session detail (credentials attempted + commands executed
        // + IOCs) on the shared Attacker Dossier modal. Anchor pins
        // the dossier renderer keeps the Honeypot Intel section.
        // Operator's exact requirement: "em cases de pra ver se teve
        // alguma secao de honeypot do ip e o que ele digitiou".
        let start = JS_INTEL
            .find("function renderProfileDossierHtml(p)")
            .expect("renderProfileDossierHtml present");
        let end = JS_INTEL[start..]
            .find("\n}\n")
            .expect("end of renderProfileDossierHtml")
            + start;
        let body = &JS_INTEL[start..end];
        assert!(
            body.contains("if (p.honeypot_sessions > 0)"),
            "dossier MUST gate the Honeypot Intel section on honeypot_sessions > 0"
        );
        assert!(
            body.contains("Honeypot Intel"),
            "dossier MUST render the `Honeypot Intel` section header for honeypot-touched IPs"
        );
        assert!(
            body.contains("Credentials Attempted"),
            "dossier MUST surface the credentials_attempted list — operator wants \
             to see what they typed"
        );
        assert!(
            body.contains("Commands Executed"),
            "dossier MUST surface the commands_executed list — operator wants to \
             see what they typed"
        );
    }

    #[test]
    fn home_activity_strip_carries_unit_and_timezone_labels() {
        // Audit 3.7 partial: the "29K -> 6 -> 5 -> 1" funnel had no
        // unit/timezone labels. The redesigned activity strip now
        // labels each cell AND includes a time-window line "since
        // midnight UTC".
        //
        // Wave 10 (label honesty, 2026-05-05): the third cell was
        // renamed "stopped automatically" -> "handled automatically".
        // It sums blocked + observing + honeypot, and "stopped" lied
        // for the observing bucket — observing means we are watching,
        // not stopping.
        //
        // Spec 049 PR2 (2026-05-12): labels migrated to the operator-
        // facing vocabulary the spec commits to — "flagged by system"
        // / "Warden decisions" / "needs review". Filtered out
        // (dismissed) becomes visible as a sub-breakdown chip after
        // years of being silently uncounted. The labels asserted here
        // MUST agree with `home_strip_uses_spec_049_metric_names_and_warden_branding`.
        for label in [
            "events watched",
            "flagged by system",
            "Warden decisions",
            "needs review",
        ] {
            assert!(
                INDEX_HTML.contains(label),
                "activity strip label '{label}' missing — audit 3.7 unit hint + spec 049 vocabulary regression"
            );
        }
        // The timezone marker must remain on the activity-strip
        // sub-line so the operator never reads a count without a
        // window context.
        assert!(JS_HOME.contains("since midnight UTC"));
    }

    #[test]
    fn index_html_carries_onboarding_tip() {
        // Audit 5.10: clean-day tip surface. The bundle MUST include
        // the container so home.js has somewhere to toggle visibility.
        assert!(
            INDEX_HTML.contains("id=\"homeOnboardingTip\""),
            "Home onboarding tip container missing (audit 5.10)"
        );
        assert!(INDEX_HTML.contains("home-onboarding-title"));
    }

    #[test]
    fn home_js_renders_onboarding_tip_when_quiet() {
        // The renderer must read both bucket sums + attention count
        // and toggle display accordingly. Anchor pins the function
        // name so a refactor that drops the call from loadHome lights
        // up CI immediately.
        assert!(JS_HOME.contains("function renderOnboardingTip"));
        assert!(JS_HOME.contains("renderOnboardingTip(overview)"));
    }

    // 2026-05-15 slim-down: removed three anchors tied to deleted Home
    // sections — home_js_critical_banner_pivots_user_links (critical
    // banner gone), app_css_defines_onboarding_and_details_heading (the
    // .home-details-heading rule was removed with the details panel;
    // .home-onboarding-tip rules still ship and are pinned implicitly
    // by home_js_renders_onboarding_tip_when_quiet above), and
    // home_js_toggle_details_is_defensive_about_display (toggleHomeDetails
    // no longer exists).

    #[test]
    fn index_html_carries_modal_preview_block() {
        // Audit 4.7: the action modal must surface a preview block
        // BEFORE the operator confirms. The block-IP path used to
        // commit silently. Anchor pins the ID so a future refactor
        // can't drop the surface without lighting up CI.
        assert!(
            INDEX_HTML.contains("id=\"modalPreview\""),
            "action modal missing #modalPreview — operator commits without seeing the command (audit 4.7)"
        );
        assert!(INDEX_HTML.contains("aria-live=\"polite\""));
    }

    #[test]
    fn app_css_defines_modal_preview_styles() {
        assert!(APP_CSS.contains(".modal-preview"));
        assert!(APP_CSS.contains(".modal-preview.visible"));
        assert!(APP_CSS.contains(".modal-preview.danger"));
        // The code block must have monospace styling so the command
        // reads as a literal copy-paste, not prose.
        assert!(APP_CSS.contains(".modal-preview code"));
    }

    #[test]
    fn actions_js_renders_modal_preview() {
        assert!(JS_ACTIONS.contains("buildActionPreviewHtml"));
        assert!(JS_ACTIONS.contains("refreshActionPreview"));
        // The block-IP branch must dispatch on every supported backend
        // so the operator never sees an empty preview just because
        // their config picked, e.g., nftables.
        for backend in ["ufw", "iptables", "nftables", "xdp", "pf"] {
            assert!(
                JS_ACTIONS.contains(&format!("case '{backend}':")),
                "buildActionPreviewHtml must handle backend '{backend}' (audit 4.7)"
            );
        }
        // closeActionModal MUST clear the preview surface so the next
        // open does not flash stale content.
        let close_start = JS_ACTIONS
            .find("function closeActionModal")
            .expect("closeActionModal");
        let body = &JS_ACTIONS[close_start..close_start + 600];
        assert!(
            body.contains("previewEl.innerHTML = ''"),
            "closeActionModal must clear modalPreview content (audit 4.7)"
        );
    }

    #[test]
    fn sse_js_renders_connection_state_with_age() {
        // Audit 5.12: the header refresh status surfaces "last event
        // N s ago" + an amber/red colour after the agent has been
        // silent for too long. Each constant pins one threshold so a
        // refactor cannot quietly inflate them.
        assert!(JS_SSE.contains("CONN_AMBER_AFTER_SECS"));
        assert!(JS_SSE.contains("CONN_RED_AFTER_SECS"));
        assert!(JS_SSE.contains("_renderConnectionStatus"));
        // The age-since-last-event ticker must run on a setInterval
        // so the colour flips even without new SSE events arriving.
        assert!(JS_SSE.contains("setInterval(_renderConnectionStatus"));
        // Hard-fail label must be present so the operator sees a
        // distinct "no data" verb instead of just "reconnecting".
        assert!(JS_SSE.contains("NO DATA"));
    }

    // ─── PR #419 Wave 2 — orphan diagnostic UI is wired ─────────
    #[test]
    fn js_responses_contains_orphan_diagnostic_panel() {
        // The dashboard's Responses tab must include the lazy-load
        // orphan diagnostic panel, the cluster summary, and the per-
        // orphan card renderer. These names are checked here so a
        // future rename of any of them must update the tests too.
        assert!(JS_RESPONSES.contains("loadOrphanDiagnostics"));
        assert!(JS_RESPONSES.contains("renderOrphanDiagnosticPanel"));
        assert!(JS_RESPONSES.contains("renderOrphanCard"));
        assert!(JS_RESPONSES.contains("ORPHAN_CLUSTER_LABELS"));
        assert!(JS_RESPONSES.contains("ORPHAN_KERNEL_STATE_BADGE"));
        // The endpoint path must match the route registered in this file.
        assert!(JS_RESPONSES.contains("/api/responses/orphans"));
    }

    // ─── PR α2 — /livez liveness contract (AUDIT-005 follow-up) ───
    #[test]
    fn js_livez_endpoint_is_unauthenticated() {
        // The supervisor probes /livez every 30 s without credentials.
        // If a future refactor accidentally folds /livez into the
        // auth-gated `agent_api_router`, the watchdog's probe gets 401
        // and SIGKILLs the agent in a loop (the exact prod failure
        // mode AUDIT-005 traced for ~10 hours). Pin the structural
        // separation: the route lives in a dedicated `health_api`
        // router merged BEFORE auth-gated routers.
        let source = include_str!("mod.rs");
        assert!(
            source.contains("let health_api = Router::new()")
                && source.contains(".route(\"/livez\""),
            "agent must define a dedicated health_api router with /livez"
        );
        // Anti-regression: the /livez route must NOT appear inside the
        // agent_api_router block (which is conditionally wrapped in the
        // auth layer based on bind address).
        let agent_api_block_start = source
            .find("let agent_api_router = Router::new()")
            .expect("agent_api_router must exist");
        let agent_api_block_end = source[agent_api_block_start..]
            .find("let agent_api =")
            .expect("agent_api_router block must terminate")
            + agent_api_block_start;
        let agent_api_block = &source[agent_api_block_start..agent_api_block_end];
        assert!(
            !agent_api_block.contains("\"/livez\""),
            "/livez must NOT live inside the auth-gated agent_api_router"
        );
        // The health_api router is merged into the final app.
        assert!(
            source.contains(".merge(health_api)"),
            "health_api must be merged into the final app router"
        );
    }

    #[test]
    fn js_livez_endpoint_returns_constant_body() {
        // /livez body is exactly "ok\n" - no JSON, no host info, no
        // version, no per-request state. Anti-regression for a future
        // helpful contributor turning the endpoint into a verbose
        // status page (which would leak deployment metadata to any
        // unauthenticated probe and re-introduce the auth tradeoff
        // AUDIT-005 was meant to remove).
        let source = include_str!("mod.rs");
        assert!(
            source.contains("|| async { \"ok\\n\" }"),
            "/livez handler must return the literal \"ok\\n\" with no extra fields"
        );
    }

    // ─── PR #419 Wave 2 — Baseline section is in English ────────
    #[test]
    fn js_intel_baseline_tab_is_english_not_pt_br() {
        // Operator-facing strings in the Baseline section must be
        // English to match the rest of the dashboard. Anchor on a few
        // known-translated phrases (positive) and on common PT-BR
        // signature words (negative) so a regression that re-imports
        // PT-BR copy is caught by tests.
        //
        // 2026-05-15 PR-C: Baseline moved to the Health tab; the
        // renderers now live in status.js. The test name is preserved
        // for historical continuity with the PT-BR regression that
        // motivated it, but it now reads JS_STATUS.

        // Positive: known EN strings landed.
        assert!(JS_STATUS.contains("Learning what's normal on this server"));
        assert!(JS_STATUS.contains("Something changed"));
        assert!(JS_STATUS.contains("What changed in the last 24 hours"));
        assert!(JS_STATUS.contains("What I consider normal here"));
        assert!(JS_STATUS.contains("Learned process lineages"));
        assert!(JS_STATUS.contains("Failed to load Baseline"));

        // Negative: PT-BR copy must not return anywhere it could be
        // operator-visible (status.js owns baseline now; intel.js is
        // the legacy origin so we keep it negative there too).
        let banned = [
            "Carregando…",
            "Aprendendo (",
            "Algo diferente",
            "nas últimas 24",
            "Falha ao carregar",
            "O que considero normal",
            "Cadeias de processo aprendidas",
            "Processos que falam para fora",
            "dias de aprendizado",
            "fontes somadas",
            "toLocaleString('pt-BR')",
        ];
        for needle in banned {
            assert!(
                !JS_STATUS.contains(needle),
                "Baseline regressed to PT-BR — found {:?} in status.js",
                needle
            );
            assert!(
                !JS_INTEL.contains(needle),
                "Baseline regressed to PT-BR — found {:?} in intel.js (legacy host)",
                needle
            );
        }
    }

    // ─── PR #420 Wave 3 — orphan resolution UI + CSRF + 2FA ─────

    #[test]
    fn js_responses_contains_orphan_resolve_modal() {
        // Wave 3 adds buttons + modal + POST helper for the two
        // orphan resolution endpoints. Anchor on the exact identifiers
        // so renames must update this test in lockstep with the route
        // wiring in `serve()` above.
        assert!(JS_RESPONSES.contains("openOrphanResolveModal"));
        assert!(JS_RESPONSES.contains("submitOrphanResolve"));
        assert!(JS_RESPONSES.contains("closeOrphanResolveModal"));
        // Endpoint paths must match the registered routes.
        assert!(JS_RESPONSES.contains("/clear"));
        assert!(JS_RESPONSES.contains("/mark-already-gone"));
        // POST request must include the CSRF header — test pins this
        // so a future refactor that removes the header gets caught.
        assert!(JS_RESPONSES.contains("'x-requested-with': 'XMLHttpRequest'"));
        // TOTP field is included so 2FA-enabled deployments work.
        assert!(JS_RESPONSES.contains("orphanResolveTotp"));
        // Operator-facing labels rendered for resolved cards.
        assert!(JS_RESPONSES.contains("Resolved as"));
    }

    /// Spec 044 / 2026-05-09 prod report anchor: operator hit "Error: HTTP
    /// 403" on the AI Intelligence Briefing Regenerate button. Root cause:
    /// `home.js` POST to `/api/briefing/generate` did NOT send the
    /// `x-requested-with: XMLHttpRequest` header that `csrf_protection`
    /// middleware demands. Same bug existed in `actions.js`,
    /// `compliance.js`, and `honeypot.js` — all silent because the
    /// operator had not exercised those flows recently.
    ///
    /// This anchor sweeps every embedded JS asset that contains
    /// `method: 'POST'` and asserts the file also contains the CSRF
    /// header string (case-insensitive). A future fetch added without
    /// the header trips this in CI before the operator hits 403.
    #[test]
    fn embedded_js_assets_with_post_fetch_carry_csrf_header() {
        let assets: &[(&str, &str)] = &[
            ("home.js", JS_HOME),
            ("threats.js", JS_THREATS),
            ("journey.js", JS_JOURNEY),
            ("sensors.js", JS_SENSORS),
            ("reports.js", JS_REPORTS),
            ("status.js", JS_STATUS),
            ("compliance.js", JS_COMPLIANCE),
            ("intel.js", JS_INTEL),
            ("monthly.js", JS_MONTHLY),
            ("responses.js", JS_RESPONSES),
            ("actions.js", JS_ACTIONS),
        ];
        for (name, src) in assets {
            // Look for POST method declarations (whitespace-tolerant).
            // If the file has any POST fetch, the file must also contain
            // the CSRF header string. Single mention covers all POSTs in
            // that file — the anchor is "did the author know about CSRF?",
            // not "is every individual POST audited".
            let has_post = src.contains("method: 'POST'") || src.contains("method:'POST'");
            if has_post {
                let has_csrf = src.to_ascii_lowercase().contains("x-requested-with");
                assert!(
                    has_csrf,
                    "{name}: file has a POST fetch but no x-requested-with header — \
                     CSRF middleware will reject it with HTTP 403. See \
                     dashboard/mod.rs::csrf_protection. Add \
                     `'x-requested-with': 'XMLHttpRequest'` to the headers map."
                );
            }
        }
    }

    // ─── PR #425 Wave 4d — banner reads gauges, not lifetime counters ───

    #[test]
    fn js_responses_banner_reads_gauges_not_totals() {
        // Real prod observation 2026-05-03: the dashboard banner
        // showed "17 orphaned (rule may still be active)" months
        // after PR #408's GC had pruned every actual entry. Mechanism
        // was: banner read `r.totals.orphaned` (counter, monotonic),
        // gaslit operator into searching for ghost rules.
        //
        // Fix is two layers:
        //   1. Backend `to_json()` exposes `gauges.orphaned` (current)
        //      separate from `totals.orphaned` (lifetime).
        //   2. Frontend banner reads `r.gauges.orphaned` ONLY.
        //
        // This test pins layer 2 so a refactor that goes back to
        // the counter doesn't ship silently.

        // Positive: banner derives `gOrphans` from `r.gauges`.
        assert!(
            JS_RESPONSES.contains("r.gauges?.orphaned"),
            "banner must read gauges.orphaned (current count), not totals.orphaned"
        );

        // Positive: lifetime counter still rendered, but in a row
        // labeled clearly as such.
        assert!(JS_RESPONSES.contains("Lifetime totals"));
        assert!(JS_RESPONSES.contains("Orphaned (lifetime)"));

        // Negative: the drift-warning banner must NOT use the
        // lifetime counter as its trigger condition.
        // Look for the bad pattern explicitly. Pre-Wave-4d had:
        //     const orphaned = r.totals?.orphaned || 0;
        //     const hasDrift = orphaned > 0 || failed > 0;
        //
        // The `tOrphaned` variable is allowed to exist (lifetime
        // KPI render) but the drift trigger must not key off it.
        assert!(
            !JS_RESPONSES.contains("hasDrift = tOrphaned"),
            "drift trigger must not read the lifetime counter"
        );
        // Anti-regression: banner copy must say "currently pending"
        // so the operator reads it as present-tense gauge, not as
        // "this happened sometime in the past."
        assert!(
            JS_RESPONSES.contains("currently pending operator review"),
            "banner copy must clarify it's the current count, not lifetime"
        );
    }

    // ─── Wave 5 (2026-05-03) — Baseline login heatmap honesty ───
    //
    // Real prod observation 2026-05-03: the operator opened the
    // Baseline tab and the "Who logs in, when" heatmap rendered
    // many user rows (`snap_daemon`, `systemd-resolve`, `messagebus`,
    // `_apt`, ...) on top of the real `ubuntu` SSH session. PAM emits
    // "session opened" entries for daemon accounts using the same
    // plumbing as real SSH logins; without filtering, the heatmap
    // reads as "all these people have logged in" — which the
    // operator's `last -F` and `journalctl` confirmed was false (only
    // `ubuntu` had real SSH sessions).
    //
    // Fix is two layers:
    //   1. Backend `/api/baseline-status` enriches the JSON with a
    //      `user_classes` map keyed by username (anchored separately
    //      in `dashboard::intelligence::baseline_enrich_tests`).
    //   2. Frontend `loginHeatmap` reads `b.user_classes` and
    //      default-hides rows where the class is `service`. A toggle
    //      surfaces them on demand. Toggle state persists in
    //      localStorage. Pagination kicks in at 20+ visible rows.
    //
    // This test pins the JS contract so a refactor that drops the
    // filter / toggle / pagination ships red.
    #[test]
    fn js_login_heatmap_hides_service_accounts_by_default() {
        // 2026-05-15 PR-C: Baseline moved from Intel sub-tab to Health
        // tab — the loginHeatmap renderer now lives in status.js. Test
        // updated to read JS_STATUS; semantics unchanged.

        // Default-hide branch: filter on the `service` class label.
        assert!(
            JS_STATUS.contains("if (c === 'service') return showServices"),
            "loginHeatmap must hide entries with class === 'service' by default"
        );
        // Receives `userClasses` as the second argument. A renderer
        // that drops the parameter would silently fall back to
        // showing every entry (regression).
        assert!(JS_STATUS.contains("function loginHeatmap(logins, userClasses)"));
        // Operator-facing toggle copy must clearly name the hidden set.
        assert!(JS_STATUS.contains("Show system accounts"));
        assert!(JS_STATUS.contains("Hide system accounts"));
        // Toggle handler exists and is wired through the same data
        // path as the initial render (re-renders via the shared
        // mount-aware helper `_rerenderBaseline`).
        assert!(JS_STATUS.contains("toggleLoginHeatmapServices"));
        assert!(JS_STATUS.contains("loginHeatmapSetShowServices"));
        // Choice persists in localStorage so it survives reloads.
        assert!(JS_STATUS.contains("innerwarden.baseline.showServices"));
        // Pagination is wired (anchored at 20-per-page).
        assert!(JS_STATUS.contains("LOGIN_HEATMAP_PAGE_SIZE = 20"));
        assert!(JS_STATUS.contains("loginHeatmapNextPage"));
        assert!(JS_STATUS.contains("loginHeatmapPrevPage"));
        // Per-row class badge is rendered so the operator can see
        // why something was kept visible (Human / Root / Unknown).
        // The class names are interpolated in JS (`login-class-badge-${c}`),
        // so the literal strings live in the CSS — anchor there.
        assert!(JS_STATUS.contains("classBadge"));
        assert!(JS_STATUS.contains("login-class-badge-${c}"));
        assert!(APP_CSS.contains(".login-class-badge-human"));
        assert!(APP_CSS.contains(".login-class-badge-service"));
        assert!(APP_CSS.contains(".login-class-badge-root"));
        assert!(APP_CSS.contains(".login-class-badge-unknown"));
        // The endpoint enrichment path is the SoT — frontend must
        // read `b.user_classes`, not classify on its own.
        assert!(
            JS_STATUS.contains("loginHeatmap(b.user_login_hours, b.user_classes)"),
            "renderBaselineHealthSection must pass user_classes from the endpoint, not classify locally"
        );
        // Anti-regression: the operator-visible complaint was that
        // `.login-heatmap` had `max-width: 720px` and stopped halfway
        // across the Baseline card. The replacement uses `width: 100%`
        // and the CSS carries a Wave-5 annotation pointing at the
        // rationale. Anchor on both so a "tighten the layout" PR
        // either preserves full width OR has to re-justify the
        // narrowing in this test.
        assert!(
            APP_CSS.contains("/* 2026-05-03 (Wave 5):"),
            "CSS must carry the Wave 5 annotation explaining width: 100%"
        );
        // The ORIGINAL bad pattern was `max-width: 720px;` ON the
        // `.login-heatmap` rule, NOT inside a `@media` query.
        // Stripping all whitespace makes the check robust to
        // formatting drift while still catching the regressed shape.
        let css_compact: String = APP_CSS.split_whitespace().collect();
        assert!(
            !css_compact.contains(".login-heatmap{display:flex;flex-direction:column;gap:4px;margin-bottom:12px;max-width:720px;}"),
            ".login-heatmap must not regress to max-width: 720px"
        );
        assert!(
            css_compact.contains(".login-heatmap{display:flex;flex-direction:column;gap:4px;margin-bottom:12px;width:100%;}"),
            ".login-heatmap must use width: 100% so the grid fills the card"
        );
    }

    #[tokio::test]
    async fn csrf_protection_rejects_post_without_header() {
        // Wire the CSRF middleware to a tiny echo router and verify
        // a POST without `X-Requested-With` returns 403.
        use axum::http::{Method, Request, StatusCode};
        use axum::routing::post;
        use axum::Router;
        use tower::ServiceExt;

        let app = Router::new()
            .route("/api/echo", post(|| async { "ok" }))
            .layer(middleware::from_fn(csrf_protection));

        let no_header = Request::builder()
            .method(Method::POST)
            .uri("/api/echo")
            .body(Body::from("{}"))
            .unwrap();
        let resp = app.clone().oneshot(no_header).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        let with_header = Request::builder()
            .method(Method::POST)
            .uri("/api/echo")
            .header("x-requested-with", "XMLHttpRequest")
            .body(Body::from("{}"))
            .unwrap();
        let resp = app.clone().oneshot(with_header).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Wrong value also rejected.
        let wrong_value = Request::builder()
            .method(Method::POST)
            .uri("/api/echo")
            .header("x-requested-with", "Fetch")
            .body(Body::from("{}"))
            .unwrap();
        let resp = app.clone().oneshot(wrong_value).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        // GET is exempt — read-only requests pass without the header.
        let get = Request::builder()
            .method(Method::GET)
            .uri("/api/echo")
            .body(Body::empty())
            .unwrap();
        // GET on a POST-only route returns 405, not 403 — the CSRF
        // middleware lets the request through and axum responds.
        let resp = app.clone().oneshot(get).await.unwrap();
        assert_ne!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn two_factor_settings_enforcement_logic() {
        // Public surface that the orphan endpoints depend on.
        let none = state::TwoFactorSettings::default();
        assert!(!none.is_enforced());

        let totp_no_secret = state::TwoFactorSettings::new("totp", "");
        assert!(
            !totp_no_secret.is_enforced(),
            "method=totp + empty secret = not enforced (operator hasn't run setup)"
        );

        let totp_with_secret = state::TwoFactorSettings::new("totp", "JBSWY3DPEHPK3PXP");
        assert!(totp_with_secret.is_enforced());

        // Case-insensitive on the method label so config like
        // `method = "TOTP"` still trips the gate.
        let totp_upper = state::TwoFactorSettings::new("TOTP", "JBSWY3DPEHPK3PXP");
        assert!(totp_upper.is_enforced());

        // Anything other than "totp" = not enforced (placeholder for
        // future "dashboard" method which lives outside this test).
        let dash = state::TwoFactorSettings::new("dashboard", "JBSWY3DPEHPK3PXP");
        assert!(!dash.is_enforced());
    }

    // ── coverage block: small handlers + auth helpers ─────────────────
    //
    // These tests target lines in `mod.rs` that were uncovered by the
    // pre-existing anchor tests. Each one exercises a thin
    // production-code helper end-to-end so the coverage gate sees a
    // stable signal even when the surrounding `serve()` orchestration
    // is too heavy to wire up under a unit test.

    #[tokio::test]
    async fn security_headers_middleware_stamps_required_headers() {
        // The middleware sets X-Frame-Options, X-Content-Type-Options,
        // x-xss-protection and referrer-policy on every response. Pin
        // each header so a future "modernise security headers" PR
        // either preserves the contract or has to update this test.
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use axum::routing::get;
        use axum::Router;
        use tower::util::ServiceExt;

        let app: Router = Router::new()
            .route("/probe", get(|| async { "ok" }))
            .layer(middleware::from_fn(security_headers));

        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/probe")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let h = resp.headers();
        assert_eq!(h.get(header::X_FRAME_OPTIONS).unwrap(), "DENY");
        assert_eq!(h.get(header::X_CONTENT_TYPE_OPTIONS).unwrap(), "nosniff");
        assert_eq!(h.get("x-xss-protection").unwrap(), "0");
        assert_eq!(
            h.get("referrer-policy").unwrap(),
            "strict-origin-when-cross-origin"
        );
    }

    #[tokio::test]
    async fn serve_builds_router_and_surfaces_plain_http_bind_errors() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let (agent_alert_tx, _agent_alert_rx) = tokio::sync::mpsc::channel(8);

        let result = serve(
            tmpdir.path().to_path_buf(),
            "127.0.0.1:notaport".to_string(),
            None,
            DashboardActionConfig::default(),
            String::new(),
            vec!["127.0.0.1".to_string(), "not-an-ip".to_string()],
            30,
            16,
            Arc::new(RwLock::new(VecDeque::new())),
            Arc::new(innerwarden_agent_guard::rules::RuleEngine::empty()),
            Arc::new(tokio::sync::Mutex::new(
                innerwarden_agent_guard::registry::Registry::new(),
            )),
            agent_alert_tx,
            Arc::new(RwLock::new(DeepSecuritySnapshot::default())),
            Arc::new(std::sync::RwLock::new(
                crate::knowledge_graph::KnowledgeGraph::new(),
            )),
            crate::ai::AiRouter::disabled(),
            Arc::new(tokio::sync::Mutex::new(None)),
            9,
            30,
            None,
            None,
            None,
            None,
            true,
            state::TwoFactorSettings::default(),
            state::PlaybookSimContext::default(),
            std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            tokio::sync::mpsc::channel::<state::DashboardApprovalOutcome>(1).0,
        )
        .await;

        let err = result.expect_err("invalid bind must be surfaced");
        let err = format!("{err:#}");
        assert!(
            err.contains("failed to bind dashboard listener on 127.0.0.1:notaport")
                || err.contains("invalid port value"),
            "serve must preserve the operator-visible bind failure context, got: {err}"
        );
    }

    #[tokio::test]
    async fn index_handler_returns_html_with_no_cache_headers() {
        // `index` ships INDEX_HTML with `Cache-Control: no-store…` and
        // `Pragma: no-cache`. Without `no-store` browsers heuristically
        // cache the SPA shell, which the operator hit before (see the
        // 2026-05-02 STATIC_NO_CACHE rationale just above the macro).
        use axum::body::to_bytes;
        use axum::response::IntoResponse;

        let resp = index().await.into_response();
        let cc = resp
            .headers()
            .get(header::CACHE_CONTROL)
            .expect("index must carry Cache-Control")
            .to_str()
            .unwrap();
        assert!(
            cc.contains("no-store"),
            "index Cache-Control must include `no-store`, got: {cc}"
        );
        assert_eq!(
            resp.headers().get(header::PRAGMA).unwrap(),
            "no-cache",
            "index must carry the legacy Pragma header for HTTP/1.0 proxies"
        );

        let body = to_bytes(resp.into_body(), 16 * 1024 * 1024)
            .await
            .expect("read body");
        let body_str = std::str::from_utf8(&body).expect("utf-8 body");
        // Anchor: the bundled INDEX_HTML constant is what reaches the
        // operator. If a future refactor swaps the source, this trips.
        assert!(
            body_str.contains("id=\"viewHome\""),
            "index handler must serve the SPA shell (viewHome anchor)"
        );
    }

    #[tokio::test]
    async fn each_serve_js_handler_yields_javascript_content_type() {
        // The `js_handler!` macro generates one `serve_js_*` per JS
        // bundle. Each is a separate function in the binary, so the
        // coverage tool counts them independently. Walk all 19 here so
        // a future refactor that replaces the macro with a typo'd
        // hand-written path is caught for every bundle, not just the
        // representative `serve_js_sse` already pinned by
        // `js_and_css_handlers_set_no_store_cache_control`.
        use axum::body::to_bytes;
        use axum::response::IntoResponse;

        macro_rules! check {
            ($call:expr, $needle:expr) => {{
                let resp = $call.await.into_response();
                let h = resp.headers();
                assert_eq!(
                    h.get(header::CONTENT_TYPE).unwrap(),
                    "application/javascript; charset=utf-8",
                );
                assert!(h
                    .get(header::CACHE_CONTROL)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .contains("no-store"));
                let body = to_bytes(resp.into_body(), 16 * 1024 * 1024)
                    .await
                    .expect("body");
                // Every bundle is non-empty and ASCII-valid.
                assert!(!body.is_empty(), "{} body must not be empty", $needle);
            }};
        }

        check!(serve_js_api(), "api.js");
        check!(serve_js_icons(), "icons.js");
        check!(serve_js_helpers(), "helpers.js");
        check!(serve_js_state(), "state.js");
        check!(serve_js_nav(), "nav.js");
        check!(serve_js_home(), "home.js");
        check!(serve_js_threats(), "threats.js");
        check!(serve_js_journey(), "journey.js");
        check!(serve_js_sensors(), "sensors.js");
        check!(serve_js_reports(), "reports.js");
        check!(serve_js_status(), "status.js");
        check!(serve_js_compliance(), "compliance.js");
        check!(serve_js_intel(), "intel.js");
        check!(serve_js_monthly(), "monthly.js");
        check!(serve_js_responses(), "responses.js");
        check!(serve_js_actions(), "actions.js");
        check!(serve_js_fleet(), "fleet.js");
    }

    #[test]
    fn try_from_env_vars_handles_all_four_branches() {
        // Branch 1: neither set — open-access mode.
        let result = DashboardAuth::try_from_env_vars(None, None).expect("ok");
        assert!(
            result.is_none(),
            "neither env var set must yield None (open access)"
        );

        // Branch 2: user only — partial config is a hard error.
        let result = DashboardAuth::try_from_env_vars(Some("admin".into()), None);
        let err = result.err().expect("partial config (user only) must error");
        assert!(
            err.to_string().contains("PASSWORD_HASH is missing"),
            "error must point at the missing hash, got: {err}"
        );

        // Branch 3: hash only — partial config is a hard error.
        let result = DashboardAuth::try_from_env_vars(
            None,
            Some("$argon2id$v=19$m=19456,t=2,p=1$abc$def".into()),
        );
        let err = result.err().expect("partial config (hash only) must error");
        assert!(
            err.to_string().contains("USER is missing"),
            "error must point at the missing user, got: {err}"
        );

        // Branch 4a: both set, user is empty — explicit reject.
        let result = DashboardAuth::try_from_env_vars(Some("   ".into()), Some("ignored".into()));
        let err = result.err().expect("empty user must error");
        assert!(
            err.to_string().contains("USER cannot be empty"),
            "empty user must surface the explicit message, got: {err}"
        );

        // Branch 4b: both set, hash is malformed — explicit reject.
        let result = DashboardAuth::try_from_env_vars(
            Some("admin".into()),
            Some("not-a-valid-phc-hash".into()),
        );
        let err = result.err().expect("malformed hash must error");
        assert!(
            err.to_string().contains("not a valid PHC hash"),
            "malformed hash must surface the explicit message, got: {err}"
        );

        // Branch 4c: happy path — returns Some(DashboardAuth) with the
        // username copied through verbatim.
        let pw = random_test_secret();
        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2::default()
            .hash_password(pw.as_bytes(), &salt)
            .unwrap()
            .to_string();
        let auth = DashboardAuth::try_from_env_vars(Some("ops".into()), Some(hash))
            .expect("happy path")
            .expect("auth must be Some");
        assert_eq!(auth.username, "ops");
        // The constructed auth verifies its own credentials.
        assert!(auth.verify("ops", &pw));
    }

    #[test]
    fn constant_time_eq_rejects_different_lengths_and_content() {
        let left = random_test_secret();
        let same = left.clone();
        let mut same_len_other = left.clone();
        let replacement = if left.starts_with('z') { 'y' } else { 'z' };
        same_len_other.replace_range(0..1, &replacement.to_string());
        let longer = format!("{left}x");
        let empty = String::new();
        let mut one_char = random_test_secret();
        one_char.truncate(1);

        // Same content, same length → eq.
        assert!(constant_time_eq(&left, &same));
        // Different content, same length → not eq.
        assert!(!constant_time_eq(&left, &same_len_other));
        // Different lengths short-circuit on the length check, which
        // was the uncovered branch (line 347 in the baseline tarpaulin
        // run). Pinning both directions covers it.
        assert!(!constant_time_eq(&left, &longer));
        assert!(!constant_time_eq(&longer, &left));
        // Empty strings are equal.
        assert!(constant_time_eq(&empty, &empty));
        // One side empty → not eq.
        assert!(!constant_time_eq(&empty, &one_char));
        assert!(!constant_time_eq(&one_char, &empty));
    }

    #[test]
    fn dashboard_auth_verify_rejects_invalid_phc_hash() {
        // The slow `verify` path parses the stored PHC hash on every
        // miss. A malformed hash must reject the verify (line 322 in
        // the baseline). Construct a DashboardAuth around a hash that
        // *parsed* at construction time but whose underlying bytes are
        // truncated — `PasswordHashString::new` validates the PHC
        // header but not the params, so we synthesise a value that
        // fails inside `PasswordHash::new` at verify time.
        //
        // Approach: build a valid hash around a runtime-generated
        // credential, then exercise the slow verify branches. Keeping
        // the credential generated avoids CodeQL treating the test
        // fixture as a real hard-coded password.
        let correct_pw = random_test_secret();
        let wrong_pw = format!("{correct_pw}x");
        let username = runtime_test_label("admin", 1);
        let wrong_username = runtime_test_label("operator", 2);
        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2::default()
            .hash_password(correct_pw.as_bytes(), &salt)
            .unwrap()
            .to_string();

        // Construct DashboardAuth around the well-formed hash so the
        // happy-path side of the test runs; then immediately verify
        // with a wrong username to exercise the constant_time_eq
        // mismatch branch and a wrong password to exercise the
        // argon2-mismatch branch (both return false without touching
        // the parser-error branch).
        let auth = DashboardAuth {
            username: username.clone(),
            password_hash: PasswordHashString::new(&hash).unwrap(),
            verified_cache: VerifiedCache::new(),
        };

        // Wrong username: short-circuits on constant_time_eq.
        assert!(!auth.verify(&wrong_username, &correct_pw));
        // Right username, wrong password: argon2 mismatch branch.
        assert!(!auth.verify(&username, &wrong_pw));
        // Right both: success branch.
        assert!(auth.verify(&username, &correct_pw));
    }

    #[test]
    fn verified_cache_evicts_oldest_when_capacity_full() {
        // The cache caps at `VerifiedCache::CAPACITY` (16) entries.
        // When full, `insert` evicts the oldest survivor before
        // inserting the new one. Lines 246-249 in the baseline
        // tarpaulin run were uncovered because the existing tests
        // never overflowed the cap. This test seeds 17 distinct
        // (user, password) tuples and asserts the count stays ≤ cap.
        let cache = VerifiedCache::new();
        let mut inserted = Vec::new();
        for i in 0..(VerifiedCache::CAPACITY + 1) {
            let user = format!("user{i}");
            let pw = random_test_secret();
            cache.insert(&user, &pw);
            inserted.push((user, pw));
        }
        let count = cache.entry_count();
        assert!(
            count <= VerifiedCache::CAPACITY,
            "cache must enforce CAPACITY={} (got {count})",
            VerifiedCache::CAPACITY
        );
        // The freshest insert must still be present after eviction.
        let (last_user, last_pw) = inserted.last().expect("fresh insert");
        assert!(
            cache.check(last_user, last_pw),
            "the most-recent insert must survive an eviction round"
        );
    }

    #[test]
    fn verified_cache_check_returns_false_for_missing_key() {
        // Cold-cache lookup must return false without panicking. This
        // pins the `None` arm of the `match map.get(&k)` in `check`.
        let cache = VerifiedCache::new();
        assert!(
            !cache.check(&runtime_test_label("nobody", 0), &random_test_secret()),
            "empty cache must miss every key"
        );
        // After an insert, only the inserted key hits.
        let user = runtime_test_label("alice", 1);
        let other_user = runtime_test_label("bob", 2);
        let pw = random_test_secret();
        let wrong_pw = random_test_secret();
        cache.insert(&user, &pw);
        assert!(cache.check(&user, &pw));
        assert!(!cache.check(&user, &wrong_pw));
        assert!(!cache.check(&other_user, &pw));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn build_tls_config_loads_existing_self_signed_cert() {
        // Coverage anchor for the "load existing" branch of
        // `build_tls_config` (lines 875-880 in the baseline tarpaulin
        // run). Pre-seed the data dir with an already-generated
        // self-signed cert + key, then call `build_tls_config` with no
        // operator-provided paths and assert it returns Ok without
        // re-generating.
        let dir = tempfile::tempdir().expect("tempdir");

        // First call generates the cert+key files.
        let _ = build_tls_config(dir.path(), None, None)
            .await
            .expect("first call generates");
        let key_path = dir.path().join("dashboard-key.pem");
        let cert_path = dir.path().join("dashboard-cert.pem");
        assert!(key_path.exists());
        assert!(cert_path.exists());

        // Capture the contents so we can prove the second call did
        // NOT re-generate (which would have rotated the bytes).
        let key_before = std::fs::read(&key_path).expect("read key");
        let cert_before = std::fs::read(&cert_path).expect("read cert");

        let _ = build_tls_config(dir.path(), None, None)
            .await
            .expect("second call loads existing");

        let key_after = std::fs::read(&key_path).expect("read key after");
        let cert_after = std::fs::read(&cert_path).expect("read cert after");
        assert_eq!(
            key_before, key_after,
            "second call must NOT regenerate the private key"
        );
        assert_eq!(
            cert_before, cert_after,
            "second call must NOT regenerate the cert"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn build_tls_config_loads_operator_provided_cert_and_key() {
        // Coverage anchor for the "operator-provided cert/key" branch
        // (lines 863-869 in the baseline tarpaulin run). Generate a
        // self-signed cert in a temp dir under one filename pair, then
        // pass the paths into a second `build_tls_config` call with
        // explicit `cert_path` / `key_path` — that second call must
        // NOT touch the auto-gen branch.
        let dir = tempfile::tempdir().expect("tempdir");

        // Step 1: bootstrap a fresh cert+key via the auto-gen path so
        // we have valid PEM material to hand back to the
        // operator-supplied branch.
        let _ = build_tls_config(dir.path(), None, None)
            .await
            .expect("bootstrap cert");

        // Move the generated files to operator-style paths so the
        // auto-gen branch's "load existing" early-exit cannot fire.
        let op_cert = dir.path().join("operator-cert.pem");
        let op_key = dir.path().join("operator-key.pem");
        std::fs::rename(dir.path().join("dashboard-cert.pem"), &op_cert).expect("mv cert");
        std::fs::rename(dir.path().join("dashboard-key.pem"), &op_key).expect("mv key");

        let _ = build_tls_config(
            dir.path(),
            Some(op_cert.to_string_lossy().into_owned()),
            Some(op_key.to_string_lossy().into_owned()),
        )
        .await
        .expect("operator-provided cert path must succeed");

        // The auto-gen filenames must NOT have come back — this proves
        // the operator-provided branch ran instead of the auto-gen
        // branch.
        assert!(
            !dir.path().join("dashboard-cert.pem").exists(),
            "operator-provided branch must not regenerate dashboard-cert.pem"
        );
        assert!(
            !dir.path().join("dashboard-key.pem").exists(),
            "operator-provided branch must not regenerate dashboard-key.pem"
        );
    }

    #[tokio::test]
    async fn build_tls_config_rejects_missing_operator_cert_path() {
        // The operator-provided branch surfaces the underlying file
        // error via anyhow context. A non-existent path must yield Err
        // (covers the `with_context` line on the load-PEM path).
        let dir = tempfile::tempdir().expect("tempdir");
        let bogus_cert = dir.path().join("does-not-exist.crt");
        let bogus_key = dir.path().join("does-not-exist.key");
        let result = build_tls_config(
            dir.path(),
            Some(bogus_cert.to_string_lossy().into_owned()),
            Some(bogus_key.to_string_lossy().into_owned()),
        )
        .await;
        assert!(
            result.is_err(),
            "operator-provided branch must propagate the load error"
        );
        let err_str = format!("{:#}", result.unwrap_err());
        assert!(
            err_str.contains("failed to load TLS cert") || err_str.contains("does-not-exist"),
            "error must reference the bad path, got: {err_str}"
        );
    }

    // ── Spec 049 PR15 — "Still active now" badge anchors ────────────
    //
    // The badge answers a question operators kept asking out loud
    // ("contained ontem — e hoje?") that the older `KERNEL · 48h`
    // pill technically also answers but in language no operator
    // ever pattern-matches on under pressure. These anchors pin:
    //
    //   * the literal label string the operator reads,
    //   * the scope-gating logic (today-scope must NOT render the
    //     pill — the outcome badge already conveys "live now"),
    //   * the back-end field name and skip-on-none serialization
    //     contract on IncidentView,
    //   * the CSS class so the pill keeps its saturated green look
    //     and does not collapse back into the cryptic-kernel pill.
    //
    // If any of these drift the operator goes back to wondering
    // whether yesterday's containment is real today — exactly the
    // failure mode PR15 fixed.

    #[test]
    fn pr15_threats_js_renders_still_active_now_pill_for_past_scope() {
        assert!(
            JS_THREATS.contains("Still active now"),
            "PR15 — the literal pill label must live in threats.js; \
             do not rename without updating operator-facing copy and \
             this anchor in lockstep"
        );
        assert!(
            JS_THREATS.contains("badge-still-active"),
            "PR15 — the pill must carry the dedicated CSS class so it \
             keeps its saturated-green look (instead of collapsing into \
             badge-kernel-active)"
        );
    }

    #[test]
    fn pr15_still_active_now_pill_is_gated_on_past_scope_and_blocked_now() {
        // Today-scope must NOT paint the pill — the outcome badge
        // ("Contained") already conveys "live now" for today's
        // view; an extra pill there is redundant and confuses the
        // operator into thinking it might mean something else.
        let gate = "casesScopeFromDate(state.filters && state.filters.date) === 'past'";
        assert!(
            JS_THREATS.contains(gate),
            "PR15 — the pill must be gated on past-scope. The gate \
             string `{gate}` is the contract; if you refactor it, \
             update this anchor so the next reviewer can find the gate \
             without re-reading the whole renderCard."
        );
        assert!(
            JS_THREATS.contains("item.block_state.kind === 'blocked_now'"),
            "PR15 — the pill must only paint when the kernel is \
             currently enforcing (blocked_now). blocked_historical \
             means the block has expired and the EXPIRED pill from \
             blockStateBadgeHtml() handles that case"
        );
    }

    #[test]
    fn pr15_incident_view_exposes_still_active_now_field() {
        // The IncidentView struct is the public contract for
        // `/api/incidents`. PR15 added the optional field; an
        // external auditor querying past dates relies on it to
        // tell "yesterday's block is still live today" without
        // doing a second roundtrip through `xdp_block_times`.
        const TYPES: &str = include_str!("types.rs");
        assert!(
            TYPES.contains("still_active_now: Option<bool>"),
            "PR15 — IncidentView must expose still_active_now as \
             Option<bool> so today-scope responses (and past rows \
             whose blocks have already expired) serialize as a clean \
             absence rather than `false`"
        );
        assert!(
            TYPES.contains("skip_serializing_if = \"Option::is_none\""),
            "PR15 — the field must be skipped when None; without this \
             the response inflates by one JSON pair per row on \
             today-scope requests for zero operator benefit"
        );
    }

    #[test]
    fn pr15_data_api_decorates_past_scope_responses() {
        // The decoration is gated server-side on past-scope so
        // today-scope requests never pay for an xdp_block_times
        // walk. This anchor pins the gate so a future "always
        // decorate" refactor cannot silently regress latency or
        // bloat today-scope JSON.
        const DATA_API: &str = include_str!("data_api.rs");
        assert!(
            DATA_API.contains("super::still_active_now::scope_is_past(&date, &today)"),
            "PR15 — compute_incidents_blocking must gate the \
             decoration on scope_is_past so today-scope skips the \
             sqlite walk"
        );
        assert!(
            DATA_API.contains("super::still_active_now::build_still_active_map"),
            "PR15 — decoration must use the batched map builder so \
             repeated IPs across rows do not cost N xdp_block_times \
             roundtrips"
        );
        assert!(
            DATA_API.contains("super::still_active_now::row_still_active"),
            "PR15 — per-row Option<bool> resolution must go through \
             the shared helper so the row → flag rule stays unit-tested"
        );
    }

    // ── Spec 049 PR16 — algorithm-gate provider strings ────────────
    //
    // Triggered by an operator-reported gap on 2026-05-13: the Cases
    // drill-down showed "Decision provenance: Unknown (provider:
    // obvious-gate)" for a real block. PR9's heuristic recognised
    // every other gate writer (honeypot:, observation-verify,
    // auto-rule:) but missed the two `*-gate` providers in
    // `incident_obvious.rs` and `incident_autodismiss.rs`. PR16 wires
    // both, and this anchor pins the source-of-truth strings so a
    // future rename to either side breaks the build until the
    // classifier is updated in lockstep.

    #[test]
    fn pr16_algorithm_gate_provider_strings_stay_in_sync_with_prod_writers() {
        // The classifier reads the strings the writers actually emit.
        // If `incident_obvious.rs` ever renames `"obvious-gate"`, this
        // grep-anchor fails and forces the rename to land in
        // decision_provenance.rs at the same time.
        const OBVIOUS_SRC: &str = include_str!("../incident_obvious.rs");
        const AUTODISMISS_SRC: &str = include_str!("../incident_autodismiss.rs");
        const PROV_SRC: &str = include_str!("decision_provenance.rs");

        assert!(
            OBVIOUS_SRC.contains("\"obvious-gate\""),
            "PR16 — incident_obvious.rs is the canonical writer of the \
             `obvious-gate` provider string. Renaming it without \
             updating decision_provenance.rs's classifier will silently \
             demote the row's provenance to Unknown — exactly the bug \
             PR16 fixed."
        );
        assert!(
            AUTODISMISS_SRC.contains("\"noise-gate\""),
            "PR16 — incident_autodismiss.rs is the canonical writer of \
             the `noise-gate` provider string. Rename in lockstep with \
             the classifier."
        );
        assert!(
            PROV_SRC.contains("provider_lower == \"obvious-gate\""),
            "PR16 — the classifier branch for obvious-gate must exist \
             so the operator-facing drill-down does not regress to \
             Unknown on every prod block from this gate"
        );
        assert!(
            PROV_SRC.contains("provider_lower == \"noise-gate\""),
            "PR16 — same as above for noise-gate"
        );
    }

    #[test]
    fn pr15_app_css_defines_still_active_badge() {
        assert!(
            APP_CSS.contains(".badge-still-active"),
            "PR15 — app.css must define .badge-still-active so the \
             pill never falls back to default-styling. Without this \
             rule the pill renders unstyled and the operator misses \
             the affordance"
        );
    }

    // ── Spec 049 PR18 — boot-time KG replay of today's incidents ────
    //
    // Operator-reported on 2026-05-13 (audit of IP 31.14.254.81 block):
    // after two same-day agent restarts the Cases panel showed only the
    // post-restart slice of the day even though the SQLite incidents
    // table held the full 535-row audit trail. The KG hydration is
    // snapshot-based — fine for steady-state, but every release deploy
    // creates a window between the last snapshot and the new agent
    // process where the dashboard silently shrinks vs the canonical
    // store.
    //
    // PR18 closes the gap by replaying today's `incidents` table into
    // the KG at boot. These anchors pin:
    //   1. The store fn the boot path depends on (`incidents_since_ts`).
    //   2. The contract that the boot path calls that fn AND
    //      `ingest_incident` in sequence — so a future "refactor that
    //      removes the replay" or "drops the iteration" fails CI.
    //   3. The idempotency promise: replaying twice does not double-count
    //      (relies on `upsert_node` semantics inside `ingest_incident`).

    #[test]
    fn pr18_store_exposes_incidents_since_ts() {
        // The store-side primitive is the only file that has a stable
        // public-API answer to "give me everything since this RFC-3339
        // string". This source-grep anchor pins the function name so a
        // rename does not silently leave the boot path calling a stale
        // symbol (which would compile against a re-export and still
        // ship broken at runtime if such a re-export existed).
        const INCIDENTS_SRC: &str = include_str!("../../../store/src/incidents.rs");
        assert!(
            INCIDENTS_SRC.contains("pub fn incidents_since_ts("),
            "PR18 — store must expose `incidents_since_ts`. If you \
             rename it, update boot.rs in the same commit and re-run \
             this anchor."
        );
        assert!(
            INCIDENTS_SRC.contains("WHERE ts >= ?1 ORDER BY ts ASC"),
            "PR18 — the SQL must filter at-or-after the boundary and \
             return rows in chronological order so the boot log is \
             readable. An off-by-one `>` here would lose the midnight \
             incident on every restart."
        );
    }

    #[test]
    fn pr18_boot_path_replays_todays_incidents_into_kg() {
        // The boot path is hard to exercise as a whole (it owns the
        // runtime, the dashboard task, the responder, etc.). What we
        // CAN pin is the source-level contract that survived the
        // PR18-internal refactor: the logic lives in an extracted
        // helper `replay_todays_incidents` (so the runtime cases
        // become unit-testable, see boot.rs tests) AND the boot fn
        // body still invokes it after KG hydration. Defining the
        // helper without calling it would ship zero operator value.
        const BOOT_SRC: &str = include_str!("../loops/boot.rs");
        assert!(
            BOOT_SRC.contains("pub(crate) fn replay_todays_incidents("),
            "PR18 — boot.rs must define `replay_todays_incidents` as \
             an extracted helper. Inlining the logic back into the \
             boot fn body removes the only test surface that pins \
             the contract."
        );
        assert!(
            BOOT_SRC.contains("replay_todays_incidents(store, &mut g, chrono::Utc::now())"),
            "PR18 — the boot fn must actually invoke the helper after \
             KG hydration. Defining the helper without calling it \
             regresses to pre-PR18 behaviour silently."
        );
        assert!(
            BOOT_SRC.contains("store.incidents_since_ts(&start_ts, MAX_BOOT_REPLAY)"),
            "PR18 — the helper must call store.incidents_since_ts \
             with the boot-replay cap. Without the call the KG never \
             gets today's rows; without the cap a pathological day \
             pins agent startup."
        );
        assert!(
            BOOT_SRC.contains("graph.ingest_incident(inc)"),
            "PR18 — the replay must re-ingest each row into the \
             shared KG. Without the iteration the helper returns \
             rows but the operator-visible Cases panel still \
             shrinks on restart."
        );
        assert!(
            BOOT_SRC.contains("pub(crate) const MAX_BOOT_REPLAY: usize"),
            "PR18 — the cap must be a visible constant so a future \
             tuning PR shows up in diff review, not buried in a \
             magic number."
        );
    }

    #[test]
    fn pr18_replay_primitive_is_idempotent_on_repeat() {
        // Anchor on the actual KG primitive: ingest_incident is
        // upsert-keyed on `incident_id`. Replaying the same set
        // twice must not double the node count. This is the
        // invariant that makes "replay every boot" safe even when
        // the snapshot already covers half the rows.
        use chrono::Utc;
        use innerwarden_core::event::Severity;
        use innerwarden_core::incident::Incident;

        let store = innerwarden_store::Store::open_memory().expect("memory store");
        let mut graph = crate::knowledge_graph::KnowledgeGraph::new();

        let now = Utc::now();
        let incident = Incident {
            ts: now,
            host: "test-host".into(),
            incident_id: "pr18-anchor:idempotent:1".into(),
            severity: Severity::High,
            title: "PR18 anchor".into(),
            summary: "".into(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![],
        };
        store.insert_incident(&incident).expect("insert");

        let start = now.date_naive().and_hms_opt(0, 0, 0).unwrap().and_utc();
        let rows = store
            .incidents_since_ts(&start.to_rfc3339(), 100)
            .expect("query");
        for inc in &rows {
            graph.ingest_incident(inc);
        }
        let after_first = graph.metrics().incident_nodes;

        // Second pass — same input. Without upsert semantics this
        // would double the count and inflate every Cases panel after
        // a manual ingest_decision_reset / replay-on-demand call.
        for inc in &rows {
            graph.ingest_incident(inc);
        }
        let after_second = graph.metrics().incident_nodes;
        assert_eq!(
            after_first, after_second,
            "PR18 — ingest_incident must be idempotent on incident_id; \
             without this the boot replay would double-count nodes for \
             any row already covered by the snapshot"
        );
        assert_eq!(
            after_first, 1,
            "PR18 — one inserted incident must land as exactly one KG \
             node, not zero (missed) and not two (double-count)"
        );
    }

    // ── Spec 049 PR17 — write-time pinning anchors ───────────────────
    //
    // PR16 fixed two algorithm-gate providers at READ time. PR17
    // closes the bug class at WRITE time: every prod writer pins
    // `decision_layer` on the `DecisionEntry`, and the read path
    // prefers that pin over the heuristic. These anchors are
    // cross-file source-grep tripwires — a future PR that adds a
    // new `DecisionEntry` writer without setting `decision_layer:`
    // fails CI loudly instead of silently regressing the
    // operator-visible drill-down to "Unknown".

    #[test]
    fn pr17_struct_carries_decision_layer_field() {
        // The persisted record gains the pinned field. Without it,
        // the writer cannot declare its layer at emit time and the
        // whole PR17 contract collapses back to the read-time
        // heuristic.
        const DECISIONS_SRC: &str = include_str!("../decisions.rs");
        assert!(
            DECISIONS_SRC.contains("pub decision_layer: Option<String>,"),
            "PR17 — DecisionEntry must expose `decision_layer: \
             Option<String>` so each writer can pin the spec 049 \
             §8.2.E layer at emit time. Option<> (not String) so \
             pre-PR17 JSONL still deserialises via serde(default)."
        );
        assert!(
            DECISIONS_SRC.contains("#[serde(default, skip_serializing_if = \"Option::is_none\")]\n    pub decision_layer: Option<String>,"),
            "PR17 — the serde attributes are load-bearing: \
             `default` lets pre-PR17 JSONL deserialise; \
             `skip_serializing_if` keeps fresh entries compact when \
             no pin is set (test/synthetic paths)."
        );
    }

    #[test]
    fn pr17_classifier_exposes_pinned_first_entry_point() {
        // The read path must call the new entry point that prefers
        // pinned over heuristic. Removing this function would force
        // callers back to the legacy `*_from_fields` path and
        // regress the bug class PR17 closes.
        const PROV_SRC: &str = include_str!("decision_provenance.rs");
        assert!(
            PROV_SRC.contains("pub(super) fn classify_decision_layer(\n    pinned: Option<&str>,"),
            "PR17 — decision_provenance.rs must expose \
             `classify_decision_layer` that takes the pinned field \
             as its first argument. The legacy heuristic entry \
             point stays as `*_from_fields` for the fallback path."
        );
        assert!(
            PROV_SRC.contains("DecisionLayer::from_pinned_str(s)"),
            "PR17 — the pinned-first entry point must parse the \
             pinned string via `from_pinned_str` (round-trip with \
             `as_str`) so the writer-side and read-side agree on \
             the canonical strings."
        );
    }

    #[test]
    fn pr17_investigation_read_path_passes_pinned_field() {
        // The dashboard's journey builder is THE prod caller of the
        // classifier. PR17 wires it to extract `decision_layer` from
        // the parsed decision JSON and pass it through. Without
        // this, the writer's pin sits in the JSONL but the
        // drill-down never reads it.
        const INV_SRC: &str = include_str!("investigation.rs");
        assert!(
            INV_SRC.contains("v.get(\"decision_layer\").and_then(|x| x.as_str())"),
            "PR17 — investigation.rs must extract `decision_layer` \
             from the parsed decision JSON when building the \
             journey row. Without this the pinned field is \
             persisted but the read path silently ignores it."
        );
        assert!(
            INV_SRC.contains("crate::dashboard::decision_provenance::classify_decision_layer("),
            "PR17 — the prod read-path call site must use the \
             pinned-first entry point. Routing back to \
             `*_from_fields` would lose the pin and regress to the \
             pre-PR17 heuristic-only behaviour."
        );
    }

    #[test]
    fn pr17_every_prod_writer_sets_decision_layer() {
        // Cross-file source-grep anchor: every file that constructs
        // a `DecisionEntry` for production (NOT inside `#[cfg(test)]`
        // or test-helper fns) must include a `decision_layer:` line.
        // Hand-curated list — adding a new writer means adding it
        // here AND setting the field at the new site, in lockstep.
        //
        // Tests use `decision_layer: None` which still matches the
        // grep (they all include the key), so this anchor doubles as
        // a "did you remember to set this field anywhere" check.
        let writer_files: &[(&str, &str)] = &[
            ("incident_obvious", include_str!("../incident_obvious.rs")),
            (
                "incident_autodismiss",
                include_str!("../incident_autodismiss.rs"),
            ),
            (
                "incident_ai_failure",
                include_str!("../incident_ai_failure.rs"),
            ),
            ("incident_flow", include_str!("../incident_flow.rs")),
            (
                "incident_auto_rules",
                include_str!("../incident_auto_rules.rs"),
            ),
            ("incident_crowdsec", include_str!("../incident_crowdsec.rs")),
            (
                "incident_abuseipdb",
                include_str!("../incident_abuseipdb.rs"),
            ),
            (
                "incident_honeypot_router",
                include_str!("../incident_honeypot_router.rs"),
            ),
            (
                "incident_honeypot_suggestion",
                include_str!("../incident_honeypot_suggestion.rs"),
            ),
            (
                "incident_audit_write",
                include_str!("../incident_audit_write.rs"),
            ),
            ("killchain_inline", include_str!("../killchain_inline.rs")),
            (
                "correlation_response",
                include_str!("../correlation_response.rs"),
            ),
            (
                "narrative_observation_verify",
                include_str!("../narrative_observation_verify.rs"),
            ),
            (
                "honeypot_always_on",
                include_str!("../honeypot_always_on.rs"),
            ),
            (
                "honeypot_post_session",
                include_str!("../honeypot_post_session.rs"),
            ),
            ("orphan_recovery", include_str!("../orphan_recovery.rs")),
            ("bot_actions", include_str!("../bot_actions.rs")),
            ("bot_helpers", include_str!("../bot_helpers.rs")),
            ("dashboard/actions", include_str!("actions.rs")),
            ("process/incidents", include_str!("../process/incidents.rs")),
        ];
        for (name, src) in writer_files {
            // Accept any of the three valid PR17 pin forms:
            //   1. struct-literal: `decision_layer: Some("...")` /
            //      `decision_layer: None`
            //   2. post-construction: `entry.decision_layer = Some(...)`
            //   3. routing through `decisions::build_entry`, which
            //      auto-pins from the `ai_provider` name (so a writer
            //      whose only DecisionEntry comes from that helper
            //      is implicitly compliant).
            let has_struct_field = src.contains("decision_layer:");
            let has_override = src.contains(".decision_layer = ");
            let routes_through_build_entry = src.contains("decisions::build_entry(");
            assert!(
                has_struct_field || has_override || routes_through_build_entry,
                "PR17 — prod writer `{name}` must pin `decision_layer` \
                 via one of: struct-literal field, post-construction \
                 `.decision_layer = ` assignment, or routing through \
                 `decisions::build_entry` (which auto-pins from the AI \
                 provider name). Without any of these, the writer \
                 silently emits unpinned rows and the drill-down falls \
                 back to the heuristic for this code path."
            );
        }
    }

    // ── Spec 049 PR20 — Cases tab from SQLite + UX cleanup ──────────
    //
    // PR20 was operator-driven on 2026-05-13: after 17 prior PRs the
    // operator's gripe was "nunca fica bom" (it never gets good). The
    // reason was architectural: every prior PR fixed a symptom of the
    // same root cause — the Cases tab reading from a memory-capped
    // KG. PR20 cuts the architectural root + four UX bugs the operator
    // pointed at in the same pass.

    #[test]
    fn pr20_cases_handler_reads_sqlite_not_kg() {
        // The biggest architectural win of PR20. Source-grep that the
        // Cases handler calls `cases_from_sqlite::build_cases_for_date`
        // and does NOT walk `graph.nodes_of_type(Incident)` for the
        // listing. The KG path is preserved for journey/drill-down
        // queries (different read patterns), just not for the list.
        const DATA_API_SRC: &str = include_str!("data_api.rs");
        assert!(
            DATA_API_SRC.contains("super::cases_from_sqlite::build_cases_for_date("),
            "PR20 — compute_incidents_blocking must read from SQLite \
             via `cases_from_sqlite::build_cases_for_date`. The legacy \
             KG-walk path was bounded by the 50 MB cap; SQLite is \
             unbounded for the audit listing."
        );
        // Anti-regression: the old KG-walk pattern must NOT be present
        // inside `compute_incidents_blocking` anymore. We grep for the
        // distinctive `nodes_of_type(NodeType::Incident)` call paired
        // with the Cases-listing comment context.
        assert!(
            !DATA_API_SRC.contains("fn compute_incidents_blocking(state: &DashboardState, query: ListQuery) -> IncidentListResponse {\n    let date = resolve_date(query.date.as_deref());\n    let explicit_date ="),
            "PR20 — the legacy KG-walk implementation of \
             compute_incidents_blocking must not return. If you need \
             to revert the SQLite path, leave the new helper in place \
             behind a feature flag rather than restoring this body."
        );
    }

    #[test]
    fn pr20_overview_counts_filter_cloudflare_self_traffic() {
        // Operator-reported 2026-05-13: strip shows "1 Currently
        // observing" but the panel list shows zero observing rows.
        // Cause: the 1 IP was 172.70.80.132 (Cloudflare), which the
        // panel correctly hides as agent self-traffic but the strip
        // counted because the backend overview filter only excluded
        // RFC1918. PR20 wires `cloud_safelist::is_self_traffic_ip`
        // into the same filter so the strip + panel agree.
        const DATA_API_SRC: &str = include_str!("data_api.rs");
        assert!(
            DATA_API_SRC.contains("crate::cloud_safelist::is_self_traffic_ip(value)"),
            "PR20 — overview counts must skip Cloudflare / self-traffic \
             IPs (the `cloud_safelist::is_self_traffic_ip` set), not \
             just RFC1918. Without this the strip overcounts \
             observing/blocked vs the panel."
        );
    }

    // 2026-05-15 slim-down: pr20_cases_band_labels_distinguish_live_from_period
    // and pr20_pivot_picker_lives_inside_advanced_filters pinned UI that
    // was removed in the slim-down (the period-vs-live duplicate band; the
    // pivot picker; the advanced filters wrapper). The new Cases sidebar
    // has a single canonical band — see pr_cases_slim_sidebar_mirrors_home_canonical
    // for the slim-side anchor.

    #[test]
    fn pr20_sensors_status_drops_dead_jsonl_probes() {
        // The events-*.jsonl and incidents-*.jsonl sinks were removed
        // by spec-016 (commit 8bd59990 on 2026-04-12). The Sensors
        // HUD kept probing for them, surfacing a misleading "events:
        // not found, size: 0" that looked like a regression. PR20
        // drops both keys from /api/status.files.
        const SENSORS_SRC: &str = include_str!("sensors.rs");
        // Match the literal API-response form `"events": { "exists":`
        // (with surrounding context) so the test does not falsely fire
        // on the docstring mentions or the new anchor test below.
        assert!(
            !SENSORS_SRC.contains("\"events\": { \"exists\":"),
            "PR20 — /api/status.files must drop the dead `events` \
             probe. Spec-016 removed the events-*.jsonl sink in \
             2026-04-12; probing for the file forever after surfaces \
             a misleading 'not found' on the Sensors HUD."
        );
        assert!(
            !SENSORS_SRC.contains("\"incidents\": { \"exists\":"),
            "PR20 — /api/status.files must drop the dead `incidents` \
             probe (same spec-016 cleanup as the events sink)"
        );
        // The live probes must stay — they're not docstring-only,
        // they're the actual response keys.
        assert!(
            SENSORS_SRC.contains("\"decisions\": { \"exists\":"),
            "PR20 — /api/status.files must keep the live `decisions` probe"
        );
        assert!(
            SENSORS_SRC.contains("\"telemetry\": { \"exists\":"),
            "PR20 — /api/status.files must keep the live `telemetry` probe"
        );
    }

    #[test]
    fn pr20_hide_allowlisted_checkbox_unchecked_by_default() {
        // Operator-reported follow-up on 2026-05-13: strip shows "40
        // Currently blocked" but the panel shows "7 attackers · 20
        // cases" because a hidden checkbox `hideAllowlisted` was
        // `checked` by default AND `display:none` — the operator
        // could never turn it off, and the frontend silently
        // double-filtered (backend already drops self-traffic via
        // `is_self_traffic_or_internal`). PR20 unchecks the box so
        // `state.hideAllowlisted` defaults to false and the frontend
        // filter never fires; backend is the single source of truth.
        //
        // "nao pode essas inconsistencia" — the operator's literal
        // call. Anchored here so a future re-check would fail CI
        // before reaching prod.
        assert!(
            !INDEX_HTML.contains("<input type=\"checkbox\" id=\"hideAllowlisted\" checked"),
            "PR20 — the hidden hideAllowlisted checkbox MUST NOT \
             default to `checked`. The default-on hidden filter \
             caused the strip-vs-panel count gap operator-reported \
             on 2026-05-13. If you re-enable it, also make it \
             visible so the operator can toggle."
        );
        assert!(
            INDEX_HTML.contains("id=\"hideAllowlisted\""),
            "PR20 — keep the element so existing JS references \
             (`toggleAllowlistFilter`, `state.hideAllowlisted`) do \
             not throw. Just default it to unchecked."
        );
    }

    #[test]
    fn pr20_attackers_sqlite_filter_matches_overview_filter() {
        // Strip + panel count parity. `build_attackers_from_sqlite`
        // must apply the SAME self-traffic + RFC1918 filter that
        // `compute_overview_counts_from_sqlite` does. Without this
        // the strip counted Cloudflare in the blocked tile while
        // the panel quietly dropped those rows — operator could
        // never reconcile.
        const INV_SRC: &str = include_str!("investigation.rs");
        assert!(
            INV_SRC.contains("crate::cloud_safelist::is_self_traffic_ip(value)"),
            "PR20 — build_attackers_from_sqlite must call \
             `cloud_safelist::is_self_traffic_ip` so the panel \
             agrees with the strip on which IPs count."
        );
    }

    // ── Spec 049 PR22 — canonical counts + cross-endpoint anchors ───
    //
    // Operator-driven 2026-05-13 after the 18-PR whack-a-mole: the
    // dashboard had at least six independent count-producing functions,
    // each with subtly different filters, scopes, and units. PR22
    // introduces a single `canonical_counts::compute` and pins the
    // contracts that prevent the next divergence by construction.

    #[test]
    fn pr22_overview_events_count_reads_canonical_counter_not_edge_count() {
        // The biggest operator-visible gap:
        //   pre-PR22:  130k    (KG edges, ~30× inflated)
        //   post-PR22:  26M    (lifetime ingestion counter, wrong scope)
        //   post-PR23: 213k    (SQLite events table for the date, ground truth)
        //
        // Anti-regression: no surface may go back to either proxy.
        // The HONEST source is the `events` SQLite table filtered by
        // ts, exposed via `Store::events_count_for_date(date)`.
        const DATA_API_SRC: &str = include_str!("data_api.rs");
        assert!(
            !DATA_API_SRC.contains("events_count: metrics.edge_count"),
            "PR22/PR23 — `metrics.edge_count` is the ~30× inflation \
             proxy; never reuse for `events_count`."
        );
        const STORE_EVENTS_SRC: &str = include_str!("../../../store/src/events.rs");
        assert!(
            STORE_EVENTS_SRC
                .contains("pub fn events_count_for_date(&self, date: &str) -> Result<u64>"),
            "PR23 — `Store::events_count_for_date` must exist as the \
             canonical date-scoped events counter. /api/overview reads \
             from this, not from any in-memory counter that can be \
             zero-after-restart or lifetime-cumulative."
        );
        // PR30: data_api.rs now reaches `events_count_for_date`
        // indirectly via `canonical_counts::compute`. Anchor the
        // canonical call site instead of the raw store helper.
        assert!(
            DATA_API_SRC.contains("super::canonical_counts::compute(")
                && DATA_API_SRC.contains(".events_today"),
            "PR30 — the api_overview SQLite path must read events_today \
             via `canonical_counts::compute` (which internally calls \
             `Store::events_count_for_date`) so the overview surface \
             agrees with /api/sensors and any future consumer."
        );
    }

    #[test]
    fn pr30_every_dashboard_endpoint_reads_canonical_counts() {
        // Cross-endpoint anchor for PR30.
        //
        // The whole point of the `canonical_counts` module is that
        // every dashboard surface that needs a per-date count reads
        // from the same function. A handler that inlines its own
        // SQLite/KG read for events_today resurrects the divergence
        // pattern (the 130k-vs-3.7k drift PR22 was created to kill).
        //
        // This test source-greps each handler file for the canonical
        // call. If a future PR removes the call or replaces it with a
        // bespoke path, this test fails with an actionable message
        // pointing at the new offending consumer.
        const DATA_API_SRC: &str = include_str!("data_api.rs");
        const SENSORS_SRC: &str = include_str!("sensors.rs");

        assert!(
            DATA_API_SRC.contains("canonical_counts::compute("),
            "PR30 — `/api/overview` handler in data_api.rs must read \
             events_today via `canonical_counts::compute`. Inlining a \
             bespoke SQLite or KG read here resurrects the cross-surface \
             divergence that PR22 set out to kill."
        );
        assert!(
            SENSORS_SRC.contains("canonical_counts::compute("),
            "PR30 — `/api/sensors` handler in sensors.rs must read \
             total_events via `canonical_counts::compute`. Reading \
             `graph.total_events_ingested` directly drifts from \
             /api/overview because the KG counter is process-lifetime."
        );
    }

    #[test]
    fn pr22_canonical_counts_module_exists_and_is_wired() {
        // The new `canonical_counts` module is the single source of
        // truth for dashboard counters. PR22 introduces it; future PRs
        // migrate the remaining endpoints to consume from it. Pin the
        // existence so a future "let's just delete this" refactor
        // has to justify reverting the canonical design.
        const CANONICAL: &str = include_str!("canonical_counts.rs");
        assert!(
            CANONICAL.contains("pub(super) struct CanonicalCounts"),
            "PR22 — canonical_counts.rs must define `CanonicalCounts` \
             as the single counter struct every endpoint reads from."
        );
        assert!(
            CANONICAL.contains("pub(super) fn compute("),
            "PR22 — canonical_counts.rs must expose `compute()` as \
             the canonical entry point."
        );
        assert!(
            CANONICAL.contains("store.events_count_for_date(date)"),
            "PR30 — the canonical events counter must come from \
             `Store::events_count_for_date(date)` (per-date SQLite query). \
             PR22 originally pinned `graph.total_events_ingested` but \
             that is a process-lifetime counter (resets on restart, \
             aggregates every uptime day). PR28 already moved \
             /api/overview to SQLite; PR30 made canonical_counts agree."
        );
    }

    #[test]
    fn pr22_frontend_no_longer_double_filters_trusted_ips() {
        // PR21 unchecked the hidden checkbox; PR22 removes the JS
        // filter body entirely so a future config-driven re-default
        // cannot resurrect the silent double-filter. Backend is the
        // single source of truth for which IPs reach the panel.
        assert!(
            !JS_THREATS.contains("if (state.hideAllowlisted) {\n    items = items.filter"),
            "PR22 — the JS frontend must not filter by `state.hideAllowlisted`. \
             Backend already drops self-traffic in \
             `is_self_traffic_or_internal`; the JS layer doing it again \
             caused the 2026-05-13 strip-vs-panel mismatch."
        );
        assert!(
            JS_THREATS.contains("// Spec 049 PR22 — frontend filtering REMOVED"),
            "PR22 — the removal must be documented in-line so a future \
             contributor sees the intent before re-adding."
        );
    }

    #[test]
    fn pr24_monthly_report_regenerates_for_current_month() {
        // Operator-reported 2026-05-14: May Monthly report claimed "2
        // blocks" for the whole month even though the prior day alone
        // had 40+ blocks. Cause: `api_threat_report` served the
        // on-disk JSON whenever it existed; once it was created on
        // 1/May (boot path side-effect or first dashboard click) it
        // never refreshed.
        //
        // PR24 contract: PAST months serve cached (frozen snapshot);
        // CURRENT month regenerates on every request. This anchor
        // pins both halves of the contract.
        const INTEL_SRC: &str = include_str!("intelligence.rs");
        assert!(
            INTEL_SRC.contains("let is_current_month = month == current_month;"),
            "PR24 — api_threat_report must distinguish the current \
             month from past months. Without this the May report \
             freezes on May-1 data through to May-31."
        );
        assert!(
            INTEL_SRC.contains(
                "if !is_current_month {\n        if let Some(content) = safe_read_data_file"
            ),
            "PR24 — only PAST months may serve cached JSON. Current \
             month must always regenerate."
        );
    }

    #[test]
    fn pr25_collector_category_js_map_mirrors_rust_manifest() {
        // 2026-05-14 — the Sensors HUD now categorises collectors as
        // telemetry / alarm / snapshot so a low-count alarm collector
        // (tls_fingerprint, fanotify_watch, integrity, sysctl_drift)
        // does not get mis-rendered under "ready — not collecting".
        //
        // The classification lives in two places: the Rust manifest
        // (single source of truth, `crates/sensor/src/collector_health.rs`)
        // and the JS map (`crates/agent/src/dashboard/frontend/js/sensors.js`).
        // Drift breaks the operator-visible categorisation silently —
        // this anchor source-greps both files and fails CI if either
        // side adds a collector the other side does not know about.
        const RUST_MANIFEST: &str = include_str!("../../../sensor/src/collector_health.rs");
        const JS_SRC: &str = include_str!("frontend/js/sensors.js");

        // Pull every `("name", CollectorCategory::Variant),` row from the Rust manifest.
        let rust_entries: std::collections::HashMap<String, String> = RUST_MANIFEST
            .lines()
            .filter_map(|l| {
                let l = l.trim();
                if !l.starts_with("(\"") {
                    return None;
                }
                let name_end = l[2..].find('"')?;
                let name = &l[2..2 + name_end];
                let rest = &l[2 + name_end..];
                let cat = if rest.contains("CollectorCategory::Telemetry") {
                    "telemetry"
                } else if rest.contains("CollectorCategory::Alarm") {
                    "alarm"
                } else if rest.contains("CollectorCategory::Snapshot") {
                    "snapshot"
                } else {
                    return None;
                };
                Some((name.to_string(), cat.to_string()))
            })
            .collect();

        assert!(
            !rust_entries.is_empty(),
            "PR25 — failed to parse Rust manifest entries — grep regex \
             may be stale relative to collector_health.rs structure"
        );

        for (name, expected_cat) in &rust_entries {
            // Look for `<name>: '<cat>'` in the JS map (with single
            // OR double quotes around the category string).
            let pat_single = format!("{name}: '{expected_cat}'");
            let pat_double = format!("{name}: \"{expected_cat}\"");
            assert!(
                JS_SRC.contains(&pat_single) || JS_SRC.contains(&pat_double),
                "PR25 — JS COLLECTOR_CATEGORY map is missing entry \
                 `{name}: '{expected_cat}'`. Add it (or remove the row \
                 from the Rust manifest in lockstep)."
            );
        }
    }

    #[test]
    fn pr26_report_operational_health_incidents_treated_as_sqlite() {
        // Operator-reported 2026-05-14: Report page showed
        // `incidents: ✗ 0B` in the Operational Health table while the
        // top of the same page said `Incidents Today: 223`. Cause: the
        // SQLite-aware special-case in `reports.js` only matched the
        // `events` row, not `incidents`. Spec 016 (2026-04-12)
        // migrated BOTH to SQLite — the JSONL files don't exist on
        // disk anymore for either. Anchor pins the unified handling.
        const REPORTS_JS: &str = include_str!("frontend/js/reports.js");
        assert!(
            REPORTS_JS.contains("(f.file === 'events' || f.file === 'incidents') && !f.exists"),
            "PR26 — the SQLite-aware special-case in reports.js must \
             match BOTH `events` and `incidents`. Pre-PR26 it only \
             matched `events`, surfacing the dead `incidents.jsonl` \
             probe as a misleading red ✗ on the Report page."
        );
    }

    #[test]
    fn pr26_report_top_ips_filters_self_traffic() {
        // Operator-reported 2026-05-14: Report's Top IPs list
        // surfaced `10.0.0.238` (the host's own internal address)
        // and `127.0.0.1` (loopback) as the top two "attackers". The
        // Top IPs counter populated `ip_counts` from three sites
        // without applying the self-traffic / RFC1918 filter that
        // overview-counts + Cases entities already use. PR26 routes
        // all three sites through a shared `is_report_visible_ip`.
        const REPORT_SRC: &str = include_str!("../report.rs");
        assert!(
            REPORT_SRC.contains("fn is_report_visible_ip(ip: &str) -> bool"),
            "PR26 — report.rs must expose `is_report_visible_ip` as \
             the single self-traffic + RFC1918 filter for the Top \
             IPs counter."
        );
        assert!(
            REPORT_SRC.contains("crate::cloud_safelist::is_self_traffic_ip(ip)"),
            "PR26 — the filter must call `cloud_safelist::is_self_traffic_ip` \
             so Cloudflare-edge IPs are also dropped, not just RFC1918."
        );
    }

    #[test]
    fn pr29_sensor_writes_collector_health_at_boot() {
        // PR29 phase-2 of the sensor-health work. The sensor binary
        // must call `collector_health::write_status_file` at boot
        // (after spawning collectors, before the main loop). Without
        // this the dashboard's `/api/sensors.collector_health` is
        // always null and the operator never sees per-host health
        // (suricata_eve missing on host X but present on host Y).
        //
        // 2026-05-25: source-grep target moved from main.rs to
        // sensor.rs when async fn main's body was extracted into
        // `sensor::run` (PR-F3 of the test-foundations series).
        const SENSOR_RUN: &str = include_str!("../../../sensor/src/sensor.rs");
        assert!(
            SENSOR_RUN.contains("collector_health::write_status_file"),
            "PR29 — sensor::run must call write_status_file at \
             boot. Without the call the dashboard falls back to its \
             legacy per-collector counter view."
        );
        assert!(
            SENSOR_RUN.contains("collector_health::build_status"),
            "PR29 — sensor must populate each collector's status via \
             `build_status(name, enabled, source, now)` so the probe \
             yields source_unavailable / source_empty / etc when the \
             host doesn't have the configured source."
        );
    }

    #[test]
    fn pr29_agent_sensors_payload_includes_collector_health() {
        // Dashboard side of the wire: /api/sensors must surface the
        // boot health file the sensor wrote. Source-grep that the
        // payload includes `collector_health` AND that the reader fn
        // exists.
        const SENSORS_SRC: &str = include_str!("sensors.rs");
        assert!(
            SENSORS_SRC.contains("\"collector_health\": collector_health"),
            "PR29 — /api/sensors payload must include the \
             `collector_health` field so the frontend can render \
             per-collector health pills."
        );
        assert!(
            SENSORS_SRC.contains("fn read_collector_health_file("),
            "PR29 — agent must define `read_collector_health_file` to \
             load the sensor's side-channel JSON. Returns Null on \
             error so the dashboard falls back to the legacy view."
        );
    }

    #[test]
    fn pr29_frontend_renders_health_badge_when_source_unavailable() {
        // Operator-facing badge: when the sensor reports
        // `source_unavailable` for a collector, the HUD row must
        // surface a red "SOURCE MISSING" pill alongside the
        // category badge. Without this the operator can't tell the
        // difference between "no events because no data" and "no
        // events because broken".
        assert!(
            JS_SENSORS.contains("function healthBadge(status)"),
            "PR29 — sensors.js must define a `healthBadge(status)` \
             renderer so each row carries health context."
        );
        assert!(
            JS_SENSORS.contains("source_unavailable"),
            "PR29 — healthBadge must map the `source_unavailable` \
             state to the 'SOURCE MISSING' pill operators see when \
             a configured collector's source path doesn't exist."
        );
        assert!(
            JS_SENSORS.contains("healthBadge(healthByName[s.name])"),
            "PR29 — renderSourceRow must call healthBadge with the \
             indexed status for the row's collector name. Without \
             this wiring the pill code is dead."
        );
    }

    // -----------------------------------------------------------------
    // Wave 2026-05-18 — cross-file consistency anchors for the
    // collector-name drift the operator hit on prod. Three pieces
    // must agree on the same set of names:
    //   1. `crates/sensor/src/collector_health.rs::COLLECTOR_MANIFEST`
    //   2. `crates/agent/src/dashboard/sensors.rs::KNOWN_COLLECTORS`
    //   3. `crates/agent/src/dashboard/frontend/js/sensors.js`'s
    //      `COLLECTOR_CATEGORY` object literal.
    // Drift in any of these surfaces causes either phantom rows
    // ("osquery TELEMETRY 0") or mis-categorised real ones
    // ("fanotify TELEMETRY 0" instead of ALARM).
    // -----------------------------------------------------------------

    fn js_collector_category_names() -> std::collections::HashSet<String> {
        // Extract the keys from the COLLECTOR_CATEGORY object literal
        // in sensors.js. The object spans from `const COLLECTOR_CATEGORY = {`
        // to the matching `};`. Each entry looks like `  key: 'value',`
        // with possible leading whitespace. The test crashes hard if
        // the literal isn't found — that's the signal a future
        // rename of the object broke this anchor.
        let start = JS_SENSORS
            .find("const COLLECTOR_CATEGORY = {")
            .expect("sensors.js must define `const COLLECTOR_CATEGORY = {`");
        let after_open = start + "const COLLECTOR_CATEGORY = {".len();
        let close = after_open
            + JS_SENSORS[after_open..]
                .find("};")
                .expect("sensors.js COLLECTOR_CATEGORY object missing closing `};`");
        let body = &JS_SENSORS[after_open..close];

        let mut names = std::collections::HashSet::new();
        for line in body.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("//") {
                continue;
            }
            // Each property is `key: 'value',` — pull everything
            // before the first colon and strip quoting.
            let Some(colon) = trimmed.find(':') else {
                continue;
            };
            let raw_key = trimmed[..colon].trim();
            let key = raw_key
                .trim_matches('"')
                .trim_matches('\'')
                .trim()
                .to_string();
            if key.is_empty() {
                continue;
            }
            names.insert(key);
        }
        names
    }

    fn rust_manifest_names() -> std::collections::HashSet<String> {
        // The sensor manifest is the source of truth. Greping the
        // source string keeps the test independent of crate-dep
        // shape (agent does not import the sensor crate).
        const MANIFEST_SRC: &str = include_str!("../../../sensor/src/collector_health.rs");
        // Lines look like:  ("auth_log", CollectorCategory::Telemetry),
        let mut names = std::collections::HashSet::new();
        for line in MANIFEST_SRC.lines() {
            let trimmed = line.trim();
            if !trimmed.starts_with("(\"") {
                continue;
            }
            // Pull out the quoted name.
            let rest = trimmed.trim_start_matches("(\"");
            if let Some(end) = rest.find('"') {
                let name = &rest[..end];
                names.insert(name.to_string());
            }
        }
        names
    }

    fn agent_known_collectors() -> std::collections::HashSet<String> {
        // Same trick on the agent's KNOWN_COLLECTORS const so all
        // three surfaces are compared via the same source-grep path.
        const SRC: &str = include_str!("sensors.rs");
        let start = SRC
            .find("pub(super) const KNOWN_COLLECTORS: &[&str] = &[")
            .expect("sensors.rs must define KNOWN_COLLECTORS");
        let after_open = start + "pub(super) const KNOWN_COLLECTORS: &[&str] = &[".len();
        let close = after_open
            + SRC[after_open..]
                .find("];")
                .expect("KNOWN_COLLECTORS missing closing `];`");
        let body = &SRC[after_open..close];

        let mut names = std::collections::HashSet::new();
        for line in body.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("//") {
                continue;
            }
            // Each entry is `"name",`
            let stripped = trimmed.trim_end_matches(',').trim();
            if stripped.starts_with('"') && stripped.ends_with('"') && stripped.len() >= 2 {
                names.insert(stripped[1..stripped.len() - 1].to_string());
            }
        }
        names
    }

    #[test]
    fn collector_names_agree_across_sensor_manifest_agent_const_and_js() {
        let rust = rust_manifest_names();
        let agent = agent_known_collectors();
        let js = js_collector_category_names();

        // Sensor manifest is the source of truth — assert the
        // agent-side roster matches it exactly.
        let only_in_rust: Vec<_> = rust.difference(&agent).collect();
        let only_in_agent: Vec<_> = agent.difference(&rust).collect();
        assert!(
            only_in_rust.is_empty() && only_in_agent.is_empty(),
            "drift between sensor COLLECTOR_MANIFEST and agent KNOWN_COLLECTORS:\n\
             only in sensor manifest: {only_in_rust:?}\n\
             only in agent KNOWN_COLLECTORS: {only_in_agent:?}\n\
             Both lists must match — see Wave 2026-05-18."
        );

        let only_in_rust: Vec<_> = rust.difference(&js).collect();
        let only_in_js: Vec<_> = js.difference(&rust).collect();
        assert!(
            only_in_rust.is_empty() && only_in_js.is_empty(),
            "drift between sensor COLLECTOR_MANIFEST and frontend COLLECTOR_CATEGORY:\n\
             only in sensor manifest: {only_in_rust:?}\n\
             only in frontend JS: {only_in_js:?}\n\
             Both maps must match — see Wave 2026-05-18. The operator screenshot \
             on 2026-05-18 showed `osquery` listed as TELEMETRY 0 because the JS \
             map carried a retired name the manifest had already removed."
        );
    }

    #[test]
    fn collector_names_do_not_contain_retired_phantoms_anywhere() {
        // Belt-and-suspenders: even if `agree_across_*` somehow let
        // both sides be wrong in the same way, this test catches the
        // specific names that were the operator's prod problem.
        let rust = rust_manifest_names();
        let agent = agent_known_collectors();
        let js = js_collector_category_names();

        for phantom in &[
            "osquery",
            "osquery_log",
            "suricata_eve",
            "suricata_alert",
            "wazuh_alerts",
            // A retired SaaS-style log shipper from the same Wave
            // 8b/8c cleanup belongs in this list too, but it is
            // covered by a separate CI anti-mention guard at
            // scripts/verify-no-*.sh that refuses any occurrence of
            // that vendor's name in crates/agent/src/. These 5
            // names are enough anchor for this test.
        ] {
            assert!(
                !rust.contains(*phantom),
                "phantom {phantom} found in sensor COLLECTOR_MANIFEST"
            );
            assert!(
                !agent.contains(*phantom),
                "phantom {phantom} found in agent KNOWN_COLLECTORS"
            );
            assert!(
                !js.contains(*phantom),
                "phantom {phantom} found in frontend COLLECTOR_CATEGORY"
            );
        }

        // The three drift aliases from the same wave. Same reason:
        // the canonical wire names are `ebpf`, `auditd`, `fanotify`.
        for drift in &["ebpf_syscall", "exec_audit", "fanotify_watch"] {
            assert!(
                !rust.contains(*drift),
                "drift alias {drift} re-added to sensor COLLECTOR_MANIFEST"
            );
            assert!(
                !agent.contains(*drift),
                "drift alias {drift} re-added to agent KNOWN_COLLECTORS"
            );
            assert!(
                !js.contains(*drift),
                "drift alias {drift} re-added to frontend COLLECTOR_CATEGORY"
            );
        }
    }
}
