use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use chrono::{DateTime, Utc};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use super::types::AdvisoryEntry;

// ── SSE types ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub(crate) struct SsePayload {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

pub(crate) type EventTx = broadcast::Sender<SsePayload>;

pub(crate) static SSE_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);
pub(crate) const MAX_SSE_CONNECTIONS: usize = 50;

pub(crate) struct SseGuard;

impl Drop for SseGuard {
    fn drop(&mut self) {
        SSE_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------------------
// Issue #71: Dashboard 2FA approval endpoints
// ---------------------------------------------------------------------------

/// The outcome of an approve or deny decision, sent back to the agent loop
/// via the `approval_outcome_tx` channel.
#[derive(Debug, Clone)]
pub(crate) struct DashboardApprovalOutcome {
    pub incident_id: String,
    pub approved: bool,
    /// Username of the operator who acted.
    pub operator: String,
    /// Whether the TOTP code was verified (true = verified or not enforced).
    /// The raw code is intentionally NOT stored here to avoid CWE-532 leakage
    /// if the struct is ever serialised or logged.
    pub totp_verified: bool,
}

/// Request body used by the 2FA approve and deny handlers.
#[derive(Debug, Deserialize, Default)]
pub(crate) struct TwoFaActionRequest {
    /// 6-digit TOTP code (approve only; ignored on deny).
    #[serde(default)]
    pub totp: String,
    /// Optional denial reason (deny only; ignored on approve).
    #[serde(default)]
    pub reason: String,
}

/// Configuration for dashboard-initiated actions (D3).
/// Mirrors `ResponderConfig` but is owned by the dashboard independently.
#[derive(Debug, Clone)]
pub struct DashboardActionConfig {
    /// Show action buttons in the UI. When false, actions are hidden entirely.
    pub enabled: bool,
    /// Dry-run mode: log intent but do not execute system commands.
    pub dry_run: bool,
    /// Firewall backend for IP blocking: "ufw" | "iptables" | "nftables".
    pub block_backend: String,
    /// Skills the operator is allowed to invoke from the dashboard.
    pub allowed_skills: Vec<String>,
    /// Whether the AI analysis is enabled.
    pub ai_enabled: bool,
    /// AI provider name (openai | anthropic | ollama).
    pub ai_provider: String,
    /// AI model in use.
    pub ai_model: String,
    /// Whether GeoIP enrichment is enabled.
    pub geoip_enabled: bool,
    /// Whether AbuseIPDB enrichment is enabled.
    pub abuseipdb_enabled: bool,
    /// AbuseIPDB auto-block threshold (0 = disabled).
    pub abuseipdb_auto_block_threshold: u8,
    /// Honeypot mode: "off" | "demo" | "listener".
    pub honeypot_mode: String,
    /// Honeypot listener port (Spec 046 follow-up). Threaded into the
    /// AI explanation pipeline so the Feynman prompt can call out
    /// "this hit the honeypot port" when the incident's `dst_port`
    /// matches.
    pub honeypot_port: u16,
    /// Whether Telegram notifications are enabled.
    pub telegram_enabled: bool,
    /// Whether Slack notifications are enabled.
    pub slack_enabled: bool,
    /// Whether Discord notifications are enabled.
    pub discord_enabled: bool,
    /// Whether Cloudflare integration is enabled.
    pub cloudflare_enabled: bool,
    /// Whether CrowdSec integration is enabled.
    pub crowdsec_enabled: bool,
    /// Webhook payload format: "default" | "pagerduty" | "opsgenie".
    pub webhook_format: String,
    /// Whether sudo_protection detector is enabled.
    pub sudo_protection_enabled: bool,
    /// Whether execution_guard detector is enabled.
    pub execution_guard_enabled: bool,
    /// Whether mesh collaborative defense is enabled.
    pub mesh_enabled: bool,
    /// Whether web push notifications are configured.
    pub web_push_enabled: bool,
    /// Whether Shield DDoS module is enabled.
    pub shield_enabled: bool,
    /// Whether Threat DNA fingerprinting is enabled.
    pub dna_enabled: bool,
    /// Data retention: events keep days.
    pub retention_events_days: usize,
    /// Data retention: incidents keep days.
    pub retention_incidents_days: usize,
    /// Data retention: decisions keep days (audit trail).
    pub retention_decisions_days: usize,
    /// Data retention: telemetry keep days.
    pub retention_telemetry_days: usize,
    /// Data retention: reports keep days.
    pub retention_reports_days: usize,
    /// Allowlisted IPs (trusted, dashboard can filter them out).
    pub trusted_ips: Vec<String>,
    /// Allowlisted users.
    pub trusted_users: Vec<String>,
    /// System prompt used for every AI-driven chat / briefing surface (Home
    /// briefing, Threats drill-down explain, Telegram /ask, daily briefing
    /// cron). Populated from `cfg.telegram.bot.personality` at dashboard
    /// init so the three surfaces share one voice. Empty string falls back
    /// to the previous hardcoded prompts (preserves old behaviour in tests
    /// and when the operator explicitly blanks personality).
    pub ai_personality: String,
}

impl Default for DashboardActionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            dry_run: true,
            block_backend: "ufw".to_string(),
            allowed_skills: vec!["block-ip-ufw".to_string()],
            ai_enabled: false,
            ai_provider: "openai".to_string(),
            ai_model: "gpt-4o-mini".to_string(),
            geoip_enabled: false,
            abuseipdb_enabled: false,
            abuseipdb_auto_block_threshold: 0,
            honeypot_mode: "off".to_string(),
            honeypot_port: 2222,
            telegram_enabled: false,
            slack_enabled: false,
            discord_enabled: false,
            cloudflare_enabled: false,
            crowdsec_enabled: false,
            webhook_format: "default".to_string(),
            sudo_protection_enabled: false,
            execution_guard_enabled: false,
            mesh_enabled: false,
            web_push_enabled: false,
            shield_enabled: false,
            dna_enabled: false,
            retention_events_days: 7,
            retention_incidents_days: 30,
            retention_decisions_days: 90,
            retention_telemetry_days: 14,
            retention_reports_days: 30,
            trusted_ips: vec![],
            trusted_users: vec![],
            ai_personality: String::new(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct DashboardState {
    pub(super) data_dir: PathBuf,
    /// D3: operator-initiated action configuration.
    pub(super) action_cfg: Arc<DashboardActionConfig>,
    /// D6: SSE broadcast channel sender.
    pub(super) event_tx: EventTx,
    /// Web Push: VAPID public key (base64url) served to subscribing browsers.
    /// Empty string when web push is not configured.
    pub(super) web_push_vapid_public_key: String,
    /// True when auth is configured but dashboard is exposed over HTTP on
    /// a non-localhost address. Actions are disabled in this mode.
    pub(super) insecure_http: bool,
    /// Auto-sleep: timestamp of last request. After 15 min of inactivity,
    /// the dashboard returns a lightweight "sleeping" page instead of
    /// reading JSONL files.
    pub(super) last_activity: Arc<std::sync::atomic::AtomicU64>,
    /// Cached sensor API response (30s TTL) to avoid re-reading events file on every request.
    pub(super) sensor_cache: Arc<tokio::sync::Mutex<(u64, serde_json::Value)>>,
    /// Trusted reverse-proxy IPs - only honour X-Forwarded-For / X-Real-IP
    /// when the connecting socket IP is in this set.
    pub(super) trusted_proxies: Arc<Vec<IpAddr>>,
    /// Active sessions: token → Session.
    pub(super) sessions: Arc<RwLock<HashMap<String, Session>>>,
    /// Session inactivity timeout in minutes.
    pub(super) session_timeout_minutes: u64,
    /// Maximum concurrent sessions.
    pub(super) max_sessions: usize,
    /// Advisory cache: recent deny/review command analyses for correlation.
    pub(super) advisory_cache: Arc<RwLock<VecDeque<AdvisoryEntry>>>,
    /// Agent Guard registry: connected AI agents and their sessions.
    pub(super) agent_registry: Arc<tokio::sync::Mutex<innerwarden_agent_guard::registry::Registry>>,
    /// ATR rule engine for command analysis.
    pub(super) rule_engine: Arc<innerwarden_agent_guard::rules::RuleEngine>,
    /// Channel to notify the main agent loop when an AI agent attempts something dangerous.
    pub(super) agent_alert_tx: tokio::sync::mpsc::Sender<AgentGuardAlert>,
    /// Deep security snapshot: firmware, hypervisor, killchain, DNA status.
    pub(super) deep_security: Arc<RwLock<DeepSecuritySnapshot>>,
    /// Shared knowledge graph for live queries (not snapshot file).
    pub(super) knowledge_graph: Arc<std::sync::RwLock<crate::knowledge_graph::KnowledgeGraph>>,
    /// Spec 029 PR-C.2: capability router. Replaces the legacy
    /// single `ai_provider` field. Briefing / explain endpoints
    /// resolve by capability (Generate / Explain) so the dashboard
    /// works whether the operator runs a full LLM, a classifier-
    /// only deployment, or rules-only mode with no AI at all.
    pub(super) ai_router: crate::ai::AiRouter,
    /// Latest AI intelligence briefing.
    pub(super) latest_briefing: Arc<tokio::sync::Mutex<Option<crate::briefing::Briefing>>>,
    /// Briefing schedule (hour, minute).
    pub(super) briefing_hour: u8,
    pub(super) briefing_minute: u8,
    /// SQLite store for blob reads (Phase 6: try blob before JSON file).
    pub(super) sqlite_store: Option<Arc<innerwarden_store::Store>>,
    /// MSSP fleet state cache (spec 038 Phase 1). `None` when
    /// `[fleet].enabled = false` so the route handler returns 404
    /// for `/api/fleet/hosts` instead of an empty list.
    pub(super) fleet_state: Option<crate::fleet::FleetState>,
    /// PR #420 Wave 3: 2FA settings consulted by sensitive POST
    /// endpoints (orphan clear / mark-already-gone). Cloned from
    /// `[security]` config at boot. When `method == "none"` the
    /// 2FA gate is bypassed; otherwise `totp_secret` is verified
    /// against the operator-supplied code.
    pub(super) two_factor: Arc<TwoFactorSettings>,
    /// Spec 056 Phase 5b: config the `POST /api/playbook/test` simulate
    /// handler needs to faithfully reproduce a real playbook run (rules
    /// dir + the same safety-floor inputs `matches_incident` uses). Kept
    /// as a small clone so the simulate endpoint does not pull the whole
    /// `AgentConfig` into `DashboardState`.
    pub(super) playbook_sim: Arc<PlaybookSimContext>,
    // ── Issue #71: Dashboard 2FA approval endpoints ──────────────────────
    /// Pending confirmations visible to the dashboard 2FA endpoints.
    /// Shared with the main agent loop via `AgentState.dashboard_pending`;
    /// populated by `decision_confirmation.rs` when a Telegram confirmation
    /// is created, consumed by `/api/2fa/approve` and `/api/2fa/deny`.
    pub(crate) pending_approvals: Arc<Mutex<HashMap<String, crate::telegram::PendingConfirmation>>>,
    /// Optional channel for sending approve/deny outcomes back to the
    /// agent loop. `None` in tests and in standalone dashboard mode
    /// (outcomes are fire-and-forget in those cases).
    pub(crate) approval_outcome_tx: Option<tokio::sync::mpsc::Sender<DashboardApprovalOutcome>>,
}

/// Inputs the playbook-test simulate endpoint feeds into the executor so
/// a dry-run matches what the live incident loop would do.
#[derive(Clone, Default)]
pub(crate) struct PlaybookSimContext {
    /// Operator playbook dir (`cfg.playbooks.rules_dir`). Built-ins are
    /// always loaded on top; empty path -> built-ins only.
    pub(crate) rules_dir: std::path::PathBuf,
    /// `cfg.allowlist.trusted_ips` — the same list the block-ip floor and
    /// `ip_not_in: ["$trusted_ips"]` conditions consult.
    pub(crate) trusted_ips: Vec<String>,
    /// Host asset tags for `conditions.asset_tags`. Empty until spec 058
    /// server-profiles populates it (mirrors the live path today).
    pub(crate) asset_tags: Vec<String>,
}

/// PR #420 Wave 3: thin clone of the operator's 2FA config used by
/// dashboard handlers. Kept separate from `crate::config::SecurityConfig`
/// so we don't pull the whole config tree into `DashboardState`.
#[derive(Clone, Default)]
pub struct TwoFactorSettings {
    /// "none" / "totp" / "dashboard". Anything other than "totp" is
    /// treated as no 2FA — handler-level gates short-circuit to OK.
    pub(crate) method: String,
    /// Base32-encoded TOTP secret. Empty means 2FA effectively disabled
    /// even if `method == "totp"` (operator hasn't run `configure 2fa`).
    pub(crate) totp_secret: String,
}

impl TwoFactorSettings {
    /// Construct from the operator's `[security]` config. Matches the
    /// field names used in `crate::config::SecurityConfig` so callers
    /// at boot can pass through directly.
    pub fn new(method: impl Into<String>, totp_secret: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            totp_secret: totp_secret.into(),
        }
    }

    /// True when the gate should be enforced. False when 2FA is
    /// disabled by config (`method != "totp"` or no secret stored).
    pub(crate) fn is_enforced(&self) -> bool {
        self.method.eq_ignore_ascii_case("totp") && !self.totp_secret.is_empty()
    }
}

/// Aggregated status from integrated security modules.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct DeepSecuritySnapshot {
    pub firmware_trust_score: Option<f64>,
    pub firmware_last_audit: Option<String>,
    pub hypervisor_environment: Option<String>,
    pub hypervisor_trust_score: Option<f64>,
    pub killchain_pids_tracked: usize,
    pub killchain_pre_chains: usize,
    pub killchain_full_matches: usize,
    pub dna_fingerprints: usize,
    pub dna_anomaly_alerts: usize,
    pub dna_attack_chains: usize,
}

/// Alert emitted when an AI agent attempts a dangerous action.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AgentGuardAlert {
    pub ts: chrono::DateTime<Utc>,
    pub agent_name: String,
    pub command: String,
    pub risk_score: u32,
    pub severity: String,
    pub recommendation: String,
    pub signals: Vec<String>,
    pub atr_rule_ids: Vec<String>,
    pub explanation: String,
    /// The tenant the calling agent's container belongs to (spec 084), so a
    /// multi-tenant fleet can attribute + investigate each guard check per
    /// tenant in the incident layer (agent-guard-events JSONL → Loki). Omitted
    /// from the JSON when absent so existing single-tenant logs are unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
}

// ── Session ─────────────────────────────────────────────────────────────

#[derive(Clone)]
pub(crate) struct Session {
    pub(super) username: String,
    pub(super) created_at: DateTime<Utc>,
    pub(super) last_activity: Arc<AtomicI64>,
    pub(super) client_ip: String,
}

impl Session {
    pub(crate) fn is_expired(&self, timeout_minutes: u64) -> bool {
        let last = self.last_activity.load(Ordering::Relaxed);
        let last_dt = DateTime::from_timestamp(last, 0).unwrap_or(self.created_at);
        Utc::now().signed_duration_since(last_dt).num_minutes() as u64 > timeout_minutes
    }

    pub(crate) fn touch(&self) {
        self.last_activity
            .store(Utc::now().timestamp(), Ordering::Relaxed);
    }
}

pub(crate) fn generate_session_token() -> String {
    let mut bytes = [0u8; 32]; // 256 bits
    OsRng.fill_bytes(&mut bytes);
    // Format as hex without external crate
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
pub(super) fn test_dashboard_state(data_dir: &std::path::Path) -> DashboardState {
    let (event_tx, _) = broadcast::channel(8);
    let (agent_alert_tx, _rx) = tokio::sync::mpsc::channel(8);
    DashboardState {
        data_dir: data_dir.to_path_buf(),
        action_cfg: Arc::new(DashboardActionConfig::default()),
        event_tx,
        web_push_vapid_public_key: String::new(),
        insecure_http: false,
        last_activity: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        sensor_cache: Arc::new(tokio::sync::Mutex::new((0, serde_json::json!({})))),
        trusted_proxies: Arc::new(Vec::new()),
        sessions: Arc::new(RwLock::new(HashMap::new())),
        session_timeout_minutes: 30,
        max_sessions: 16,
        advisory_cache: Arc::new(RwLock::new(VecDeque::new())),
        agent_registry: Arc::new(tokio::sync::Mutex::new(
            innerwarden_agent_guard::registry::Registry::new(),
        )),
        rule_engine: Arc::new(innerwarden_agent_guard::rules::RuleEngine::empty()),
        agent_alert_tx,
        deep_security: Arc::new(RwLock::new(DeepSecuritySnapshot::default())),
        knowledge_graph: Arc::new(RwLock::new(crate::knowledge_graph::KnowledgeGraph::new())),
        ai_router: crate::ai::AiRouter::disabled(),
        latest_briefing: Arc::new(tokio::sync::Mutex::new(None)),
        briefing_hour: 0,
        briefing_minute: 0,
        sqlite_store: None,
        fleet_state: None,
        two_factor: Arc::new(TwoFactorSettings::default()),
        playbook_sim: Arc::new(PlaybookSimContext::default()),
        pending_approvals: Arc::new(Mutex::new(HashMap::new())),
        approval_outcome_tx: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dashboard_action_config_defaults() {
        let cfg = DashboardActionConfig::default();
        // Validation of primary security defaults
        assert!(!cfg.enabled, "actions should be disabled by default");
        assert!(cfg.dry_run, "dry run should be enabled by default");
        assert_eq!(cfg.block_backend, "ufw", "ufw should be default backend");
        assert_eq!(cfg.allowed_skills, vec!["block-ip-ufw".to_string()]);
        assert_eq!(cfg.retention_incidents_days, 30);
    }

    #[test]
    fn test_sse_connection_guards() {
        // Reset counter
        SSE_CONNECTIONS.store(0, Ordering::Relaxed);

        let mut guards = Vec::new();
        // Simulate clients connecting
        for _ in 0..5 {
            SSE_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
            guards.push(SseGuard);
        }
        assert_eq!(SSE_CONNECTIONS.load(Ordering::Relaxed), 5);

        // Simulate clients dropping
        drop(guards);
        assert_eq!(SSE_CONNECTIONS.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_deep_security_snapshot_defaults() {
        let snapshot = DeepSecuritySnapshot::default();
        assert!(snapshot.firmware_trust_score.is_none());
        assert_eq!(snapshot.killchain_pids_tracked, 0);
        assert_eq!(snapshot.dna_fingerprints, 0);
    }
}
