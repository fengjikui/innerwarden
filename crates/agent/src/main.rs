// Clippy 1.95 promotes `unnecessary_sort_by` to a default-deny lint, but
// `sort_by_key(|x| Reverse(...))` is less readable than the explicit
// `sort_by(|a, b| b.x.cmp(&a.x))` pattern used throughout the agent for
// reverse-sort leaderboards (threat report, attacker intel, MITRE heatmap).
// Keep the existing style workspace-wide for this crate.
#![allow(clippy::unnecessary_sort_by)]

// Use jemalloc on Linux - the default glibc allocator fragments memory and
// never returns it to the OS, causing apparent "leaks" under sustained load.
// jemalloc aggressively returns unused pages via madvise(MADV_DONTNEED).
//
// Spec 035 PR-A2 phase 1: this allocator is disabled when the
// `dhat-heap` feature is active so DHAT's allocator can take its
// place for heap-budget tests. The two `#[global_allocator]` statics
// below are mutually exclusive by cfg construction:
//   - jemalloc:  cfg(all(not(target_os = "macos"), not(feature = "dhat-heap")))
//   - dhat:      cfg(feature = "dhat-heap")
// These cfg gates cannot both match simultaneously, so only one
// `#[global_allocator]` ever exists in a given build. If a future
// refactor breaks this invariant Rust emits "duplicate lang item"
// and the build fails — that diagnostic IS the compile-time guarantee
// (an explicit `compile_error!` macro cannot observe the state of
// another cfg-gated item without producing the same duplicate-lang
// error first).
#[cfg(all(target_os = "linux", not(feature = "dhat-heap")))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

// Spec 035 PR-A2 phase 1: DHAT global allocator. Replaces jemalloc
// (Linux) or the system allocator (macOS) when the `dhat-heap`
// feature is active. DHAT records every allocation, so this binary
// runs noticeably slower and MUST NOT ship to production. The feature
// exists to drive heap-budget regression tests under
// `cargo test -p innerwarden-agent --features dhat-heap ...`.
#[cfg(feature = "dhat-heap")]
#[global_allocator]
static DHAT_ALLOC: dhat::Alloc = dhat::Alloc;

// Spec 030: embed jemalloc runtime configuration in the binary so
// operators do not need to set a MALLOC_CONF env var to get
// production-ready memory behaviour.
//
// - `background_thread:true` runs purging off the hot path.
// - `dirty_decay_ms:1000` returns dirty pages to the OS after 1 s of
//   idleness (default is 10 s). A security agent has spiky
//   allocation patterns (JSON parsing, graph rebuilds, tokenizer
//   batches) and the lower decay keeps RSS close to the working set
//   instead of the recent peak.
// - `muzzy_decay_ms:1000` does the same for muzzy pages (the state
//   between "dirty" and "returned to the OS"). Matching the dirty
//   interval gives a single predictable decay window.
//
// Linux-only; the macOS and Windows builds use the system allocator so
// this symbol is not needed there.
#[cfg(all(target_os = "linux", not(test)))]
#[allow(non_upper_case_globals)]
#[export_name = "malloc_conf"]
pub static MALLOC_CONF: &[u8] = b"background_thread:true,dirty_decay_ms:1000,muzzy_decay_ms:1000\0";

mod abuseipdb;
mod abuseipdb_report_budget;
mod agent_context;
mod agent_discovery;
mod agent_registry_reconcile;
mod ai;
mod allowlist;
mod attacker_intel;
mod baseline;
mod bot_actions;
mod bot_commands;
mod bot_helpers;
mod briefing;
mod capped_log;
mod circuit_breaker;
mod cloud_safelist;
mod cloudflare;
mod cloudflare_attribution;
mod config;
mod correlation;
mod correlation_engine;
mod correlation_engine_yaml;
mod correlation_response;
mod crowdsec;
mod dashboard;
mod data_retention;
mod decision_block_ip;
mod decision_confirmation;
mod decision_cooldown;
mod decision_honeypot;
mod decision_skill_actions;
mod decisions;
mod detector_catalog;
mod discord;
mod dna_inline;
mod dns_guard_export;
mod dns_guard_ingest;
mod dshield;
mod environment_profile;
mod execution_gate_arm;
mod execution_gate_aya;
mod execution_gate_monitor;
mod firmware_tick;
mod fleet;
mod forensics;
mod geo_cache;
mod geoip;
mod honeypot_always_on;
mod honeypot_post_session;
mod hypervisor_tick;
mod incident_abuseipdb;
mod incident_action_report;
mod incident_advisory;
mod incident_ai_context;
mod incident_ai_failure;
mod incident_attacker_profile;
mod incident_audit_write;
mod incident_auto_rules;
mod incident_autodismiss;
mod incident_crowdsec;
mod incident_decision_eval;
mod incident_enrichment;
mod incident_execution_gate;
mod incident_flow;
mod incident_forensics;
mod incident_honeypot_router;
mod incident_honeypot_suggestion;
mod incident_notifications;
mod incident_obvious;
mod incident_post_decision;
mod incident_prelude;
mod incident_reputation;
mod incident_untouchable;
mod ioc;
mod ip_reputation;
mod kg_decide_features;
mod kg_fp_suppression;
mod killchain_inline;
mod knowledge_graph;
mod learned_suppression;
mod loops;
mod lsm_policy;
mod managed_agent_guard;
mod mesh;
mod mitre;
mod narrative;
mod narrative_anomaly;
mod narrative_autofp;
mod narrative_daily_summary;
mod narrative_incident_ingest;
mod narrative_observation_verify;
mod needs_review_timeout;
#[allow(
    dead_code,
    unused_imports,
    unused_variables,
    clippy::needless_range_loop
)]
mod neural_lifecycle;
mod notification_channels;
mod notification_gate;
mod notification_pipeline;
mod observation_verify;
mod operator_actions;
mod operator_exec_trust;
mod operator_trust;
mod orphan_recovery;
mod pcap_capture;
mod playbook_engine;
mod posture;
mod process;
mod process_health;
#[allow(dead_code)]
mod reader;
mod report;
mod response_lifecycle;
mod scoring;
mod shield_inline;
mod skill_gate;
mod skills;
mod slack;
#[allow(dead_code)]
mod soc_checks;
mod state_store;
// Spec 036 (audit I-04): TaskGroup primitive for graceful shutdown.
// First migration (PR-2) wires firmware-alert spawns and the Telegram
// polling loop through this group; honeypot listener migrates in a
// dedicated PR (shutdown contract change). Call sites are free to
// use `state.task_group.spawn(...)`.
mod silent_stream_alarm;
mod task_group;
mod telegram;
mod telemetry;
mod telemetry_tick;
mod tenancy;
mod text_util;
mod threat_feeds;
mod threat_report;
mod trust_rules;
#[allow(dead_code)]
mod trust_scoring;
#[allow(dead_code)]
mod two_factor;
// Only compiled with the on-device classifier; its sole caller is
// `LocalClassifier::decide` (spec 071 Part A), which is feature-gated the same.
#[cfg(feature = "local-classifier")]
mod warden_context_gate;
mod warden_labels;
mod web_push;
mod webhook;
mod xdp_availability;
#[allow(dead_code)]
mod zero_trust;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

#[cfg(test)]
use crate::bot_helpers::{
    parse_telegram_triage_action, sanitize_allowlist_process_name, TelegramTriageAction,
};
use anyhow::Result;
use clap::Parser;
use tracing::{debug, warn};

#[derive(Parser)]
#[command(
    name = "innerwarden-agent",
    version,
    about = "Interpretive layer - reads sensor JSONL, generates narratives, and auto-responds to incidents"
)]
struct Cli {
    /// Path to the sensor data directory (where events-*.jsonl and incidents-*.jsonl live)
    #[arg(long, default_value = "/var/lib/innerwarden")]
    data_dir: PathBuf,

    /// Path to agent config TOML (narrative, webhook, ai, responder settings). Optional.
    #[arg(long)]
    config: Option<PathBuf>,

    /// Run once (process new entries then exit) instead of continuous mode
    #[arg(long)]
    once: bool,

    /// Generate a trial operational report from existing artifacts and exit
    #[arg(long)]
    report: bool,

    /// Replay a captured incidents JSONL file through the SOC playbooks in
    /// dry-run and print a report of what they WOULD do (no skills fire, no
    /// audit written), then exit. Validates playbooks against real incident
    /// history without waiting for live traffic.
    #[arg(long, value_name = "INCIDENTS_JSONL")]
    playbook_replay: Option<PathBuf>,

    /// Output directory for generated reports (default: same as --data-dir)
    #[arg(long)]
    report_dir: Option<PathBuf>,

    /// Run read-only local dashboard server and exit this process only on SIGTERM/SIGINT
    #[arg(long)]
    dashboard: bool,

    /// Bind address for dashboard mode (default: localhost only — use 0.0.0.0:8787 to expose)
    #[arg(long, default_value = "127.0.0.1:8787")]
    dashboard_bind: String,

    /// Path to TLS certificate file (PEM). If not set, dashboard auto-generates
    /// a self-signed cert and serves on HTTPS.
    #[arg(long)]
    tls_cert: Option<String>,

    /// Path to TLS private key file (PEM). Required if --tls-cert is set.
    #[arg(long)]
    tls_key: Option<String>,

    /// Disable TLS and serve dashboard over plain HTTP (NOT recommended for
    /// production). Default: HTTPS with auto-generated self-signed cert.
    #[arg(long)]
    insecure_no_tls: bool,

    /// Utility: generate Argon2 password hash for dashboard auth and exit.
    #[arg(long)]
    dashboard_generate_password_hash: bool,

    /// Poll interval in seconds for the narrative slow loop (default: 30)
    #[arg(long, default_value = "30")]
    interval: u64,

    /// Internal: run honeypot sandbox worker mode.
    #[arg(long, hide = true)]
    honeypot_sandbox_runner: bool,

    /// Internal: path to honeypot sandbox runner spec JSON.
    #[arg(long, hide = true)]
    honeypot_sandbox_spec: Option<PathBuf>,

    /// Internal: path to honeypot sandbox runner result JSON.
    #[arg(long, hide = true)]
    honeypot_sandbox_result: Option<PathBuf>,

    /// Spec 015 one-shot migration: load today's dated graph snapshot,
    /// delete `graph_user_creation` false-positive incidents and
    /// brute-force User nodes, then save and exit. Never runs unless this
    /// flag is passed explicitly. Creates a backup of the snapshot as
    /// `<name>.bak-015` before writing.
    #[arg(long)]
    cleanup_015_graph_signal_quality: bool,

    /// Spec 015 follow-up: load today's dated graph snapshot and set the
    /// `research_only` flag on every Incident whose connected IPs are
    /// 100% self-traffic (cloud providers, Telegram, GeoIP, Canonical,
    /// OCI peers). Incidents are preserved for neural training — only
    /// the operator dashboard filter changes. Creates a backup as
    /// `<name>.bak-015-researchonly-<stamp>` before writing.
    #[arg(long)]
    backfill_015_research_only: bool,

    /// One-shot: force the autoencoder's nightly training routine to run
    /// immediately (instead of waiting for 03:00 UTC). Reads events from
    /// `innerwarden.db`, trains `anomaly-model.bin` in place, then exits.
    /// Used after a feature-layout bump (or after a stale / saturated model
    /// is detected in production) so the operator doesn't have to wait a
    /// whole day for the baseline to recalibrate.
    #[arg(long)]
    retrain_anomaly: bool,

    /// Offline backtest: train the autoencoder on events BEFORE
    /// `--backtest-cutoff`, score the held-out events after it, and report
    /// whether the host-anomaly score separates incidents the agent acted on
    /// (real) from ones it dismissed (false positive). Measures if the
    /// autoencoder would help if it acted — no training leakage. Then exits.
    #[arg(long)]
    backtest_anomaly: bool,

    /// Cutoff date (YYYY-MM-DD) for `--backtest-anomaly`: events before it
    /// train the model, events on/after it are the held-out scoring period.
    #[arg(long, value_name = "YYYY-MM-DD")]
    backtest_cutoff: Option<String>,

    /// Parse `--config <path>` against the strict AgentConfig schema, print a
    /// short OK summary on success or the parse error on failure, then exit
    /// without booting the agent. Used by `innerwarden config validate` and
    /// by `scripts/deploy-prod.sh` to refuse a deploy whose `agent.toml` has
    /// unknown / typo'd keys (Wave 9e, anchor for AUDIT-002).
    #[arg(long)]
    validate_config_only: bool,
}

// ---------------------------------------------------------------------------
// Shared agent state (passed through tick functions)
// ---------------------------------------------------------------------------

/// Accumulates event/incident stats incrementally for narrative generation.
/// Avoids re-reading the full events file every 5 minutes.
#[derive(Default)]
struct NarrativeAccumulator {
    /// Event counts by kind (e.g. "ssh.login_failed" → 42)
    events_by_kind: HashMap<String, usize>,
    /// IP mention counts
    ip_counts: HashMap<String, usize>,
    /// User mention counts
    user_counts: HashMap<String, usize>,
    /// Total events seen today
    total_events: usize,
    /// All incidents seen today (small - typically <100)
    incidents: Vec<innerwarden_core::incident::Incident>,
    /// Date this accumulator is for (resets on date change)
    date: String,
}

impl NarrativeAccumulator {
    /// Maximum unique IPs/users to track. Narrative only uses top 10,
    /// so keeping 500 is generous while preventing unbounded growth.
    const MAX_ENTITY_ENTRIES: usize = 500;

    fn ingest_events(&mut self, events: &[innerwarden_core::event::Event]) {
        for ev in events {
            self.total_events += 1;
            *self.events_by_kind.entry(ev.kind.clone()).or_insert(0) += 1;
            for entity in &ev.entities {
                match entity.r#type {
                    innerwarden_core::entities::EntityType::Ip
                        if (self.ip_counts.contains_key(&entity.value)
                            || self.ip_counts.len() < Self::MAX_ENTITY_ENTRIES) =>
                    {
                        *self.ip_counts.entry(entity.value.clone()).or_insert(0) += 1;
                    }
                    innerwarden_core::entities::EntityType::User
                        if (self.user_counts.contains_key(&entity.value)
                            || self.user_counts.len() < Self::MAX_ENTITY_ENTRIES) =>
                    {
                        *self.user_counts.entry(entity.value.clone()).or_insert(0) += 1;
                    }
                    _ => {}
                }
            }
        }
    }

    fn ingest_incidents(&mut self, incidents: &[innerwarden_core::incident::Incident]) {
        self.incidents.extend_from_slice(incidents);
        // Cap at 500 incidents - narrative only needs recent ones for the report
        if self.incidents.len() > 500 {
            let drain = self.incidents.len() - 500;
            self.incidents.drain(..drain);
        }
    }

    fn reset_for_date(&mut self, date: &str) {
        if self.date != date {
            self.events_by_kind.clear();
            self.ip_counts.clear();
            self.user_counts.clear();
            self.total_events = 0;
            self.incidents.clear();
            self.date = date.to_string();
        }
    }

    /// Build synthetic Events from counters for narrative::generate.
    /// Caps total at 2000 events to prevent memory explosion on busy hosts.
    /// Uses proportional sampling when total exceeds cap.
    fn synthetic_events(&self) -> Vec<innerwarden_core::event::Event> {
        use innerwarden_core::{entities::EntityRef, event::Event};
        const MAX_SYNTHETIC: usize = 2000;

        let total: usize = self.events_by_kind.values().sum();
        let scale = if total > MAX_SYNTHETIC {
            MAX_SYNTHETIC as f64 / total as f64
        } else {
            1.0
        };

        let mut events = Vec::with_capacity(MAX_SYNTHETIC.min(total) + 20);
        for (kind, count) in &self.events_by_kind {
            let n = ((*count as f64) * scale).ceil() as usize;
            for _ in 0..n.max(1) {
                events.push(Event {
                    ts: chrono::Utc::now(),
                    host: String::new(),
                    source: String::new(),
                    kind: kind.clone(),
                    severity: innerwarden_core::event::Severity::Info,
                    summary: String::new(),
                    details: serde_json::Value::Null,
                    tags: vec![],
                    entities: vec![],
                });
            }
        }

        // Top IPs (max 10, 1 event each)
        for (ip, _) in self.ip_counts.iter().take(10) {
            events.push(Event {
                ts: chrono::Utc::now(),
                host: String::new(),
                source: String::new(),
                kind: "synthetic.entity".to_string(),
                severity: innerwarden_core::event::Severity::Info,
                summary: String::new(),
                details: serde_json::Value::Null,
                tags: vec![],
                entities: vec![EntityRef::ip(ip)],
            });
        }
        for (user, _) in self.user_counts.iter().take(10) {
            events.push(Event {
                ts: chrono::Utc::now(),
                host: String::new(),
                source: String::new(),
                kind: "synthetic.entity".to_string(),
                severity: innerwarden_core::event::Severity::Info,
                summary: String::new(),
                details: serde_json::Value::Null,
                tags: vec![],
                entities: vec![EntityRef::user(user)],
            });
        }
        events
    }
}

/// A queued UI setting change from a Telegram Settings button, applied by the
/// main loop (which owns `cfg`). Lets those buttons actuate at runtime instead
/// of printing a "run on server" CLI hint.
#[derive(Debug, Clone)]
pub(crate) enum SettingChange {
    /// Operator profile: `true` = simple (lay), `false` = technical. Flips alert
    /// language + re-registers the profile-scoped command menu.
    Profile(bool),
    /// Alert sensitivity for the bot channel: `"quiet" | "normal" | "verbose"`.
    Sensitivity(String),
}

struct AgentState {
    skill_registry: skills::SkillRegistry,
    blocklist: skills::Blocklist,
    correlator: correlation::TemporalCorrelator,
    telemetry: telemetry::TelemetryState,
    telemetry_writer: Option<telemetry::TelemetryWriter>,
    /// Spec 029: capability router. Call sites resolve providers by
    /// role (classifier vs llm) via `provider_for(Capability::X)`.
    /// Back-compat test in `ai::router::back_compat_tests` guarantees
    /// that a router built from a single legacy provider resolves
    /// every capability identically to pre-029 code.
    ai_router: ai::AiRouter,
    decision_writer: Option<decisions::DecisionWriter>,
    /// Tracks when the daily narrative was last written so we can enforce a
    /// minimum interval and avoid rewriting on every 30-second tick.
    last_narrative_at: Option<std::time::Instant>,
    /// Date for which we last sent the daily Telegram digest (avoids re-sending).
    last_daily_summary_telegram: Option<chrono::NaiveDate>,
    /// Telegram daily budget: how many immediate notifications sent today.
    /// Resets when the date changes.
    #[allow(dead_code)]
    telegram_daily_sent: u32,
    /// Date the daily budget counter applies to.
    #[allow(dead_code)]
    telegram_budget_date: Option<chrono::NaiveDate>,
    /// Incidents deferred from Telegram (not immediate threats) — accumulated
    /// per-detector for the daily digest breakdown.
    telegram_deferred: std::collections::HashMap<String, u32>,
    /// Telegram client for T.1 notifications and T.2 approvals (None when disabled).
    telegram_client: Option<Arc<telegram::TelegramClient>>,
    /// Pending T.2 operator confirmations keyed by incident_id.
    /// Stores the original decision and incident so the action can be executed when approved.
    pending_confirmations: HashMap<
        String,
        (
            telegram::PendingConfirmation,
            ai::AiDecision,
            innerwarden_core::incident::Incident,
        ),
    >,
    /// Receives approval results from the Telegram polling task.
    /// Drained at the start of every incident tick via try_recv.
    approval_rx: Option<tokio::sync::mpsc::Receiver<telegram::ApprovalResult>>,
    /// Notification pipeline — groups incidents by detector+entity to reduce noise.
    grouping_engine: notification_pipeline::GroupingEngine,
    /// Environment profile — cloud/VM detection, human UIDs, services.
    environment_profile: environment_profile::EnvironmentProfile,
    /// Last time the periodic env census ran. Spec 005 Phase 6.
    last_env_census_at: Option<std::time::Instant>,
    /// Host posture snapshot — sshd / sudo / firewall / listeners. Read by
    /// the severity downgrade engine (spec 044 Phase 3, not yet wired).
    /// Refreshed on a 10 min slow-loop tick (Phase 2.2). Best-effort:
    /// when probes fail the snapshot is "permissive" and the downgrade
    /// engine keeps alerts at their original severity.
    #[allow(dead_code)] // Read by Phase 3 downgrade engine (not yet wired).
    host_posture: posture::HostPosture,
    /// Last time the host posture was refreshed. Drives the slow-loop
    /// 10 min cadence (read in `loops/boot.rs` posture refresh block)
    /// and the dashboard "stale snapshot" warning (Phase 2.3).
    last_host_posture_at: Option<std::time::Instant>,
    /// Neural autoencoder anomaly engine — learns "normal" and flags novel patterns.
    anomaly_engine: neural_lifecycle::AnomalyEngine,
    /// Neural incidents pending processing — buffered here because the agent
    /// cannot append to the sensor's incidents file (different user).
    neural_incidents: Vec<innerwarden_core::incident::Incident>,
    /// In-memory trust rules: set of "detector:action" strings.
    /// Loaded from data_dir/trust-rules.json at startup; updated live when operator clicks "Always".
    trust_rules: std::collections::HashSet<String>,
    /// CrowdSec LAPI sync state (None when crowdsec.enabled = false).
    crowdsec: Option<crowdsec::CrowdSecState>,
    /// AbuseIPDB client for IP reputation enrichment (None when disabled).
    abuseipdb: Option<abuseipdb::AbuseIpDbClient>,
    /// GeoIP client for IP geolocation enrichment via ip-api.com (None when disabled).
    geoip_client: Option<geoip::GeoIpClient>,
    /// Slack client for incident notifications (None when disabled).
    slack_client: Option<slack::SlackClient>,
    /// Discord client for incident notifications (None when disabled).
    discord_client: Option<discord::DiscordClient>,
    /// Cloudflare integration client (None when disabled).
    cloudflare_client: Option<cloudflare::CloudflareClient>,
    /// Circuit breaker: when tripped by a high-volume incident burst, AI analysis
    /// is suspended until this timestamp. None = circuit breaker not tripped.
    circuit_breaker_until: Option<chrono::DateTime<chrono::Utc>>,
    /// Pending operator honeypot choices keyed by IP.
    /// When Telegram is configured and AI recommends Honeypot, execution is deferred
    /// until the operator picks an action via the 4-button inline keyboard.
    pending_honeypot_choices: HashMap<String, PendingHoneypotChoice>,
    /// Local IP reputation: per-IP history used for adaptive block TTL.
    /// Persisted to `ip-reputation.json` every slow-loop tick.
    ip_reputations: HashMap<String, LocalIpReputation>,
    /// Whether LSM enforcement has been auto-enabled this session.
    lsm_enabled: bool,
    /// Mesh collaborative defense network (None when mesh.enabled = false).
    mesh: Option<mesh::MeshIntegration>,
    /// Rate limiter: timestamps of recent block actions (rolling 1-minute window).
    /// Prevents false-positive cascades from blocking too many IPs at once.
    recent_blocks: std::collections::VecDeque<chrono::DateTime<chrono::Utc>>,
    /// XDP blocklist entries with timestamps and per-IP TTL for adaptive expiration.
    /// Periodically cleaned: IPs older than their individual TTL are removed.
    xdp_block_times: HashMap<String, (chrono::DateTime<chrono::Utc>, i64)>,
    /// Per-IP exponential backoff for XDP cleanup that keeps failing for a
    /// NON-transient reason (e.g. the agent lacks sudo/privilege to run
    /// `bpftool map delete`, so every tick's retry is futile). Value is
    /// `(consecutive_failures, next_retry_at)`. Without this, a single stuck
    /// entry re-spawns `sudo bpftool` every slow-loop tick forever — observed
    /// on a non-root deploy as 44k failed sudo-auths + 44k WARN lines in 7
    /// days. Runtime-only (not persisted); a fresh boot retries immediately,
    /// which is correct because privilege may have been granted since.
    xdp_cleanup_backoff: HashMap<String, (u32, chrono::DateTime<chrono::Utc>)>,
    /// Unified response lifecycle: tracks all active responses (block IP, container,
    /// nginx, sudo) with TTL, auto-revert, manual revert, and Prometheus metrics.
    response_lifecycle: response_lifecycle::ResponseLifecycle,
    /// AbuseIPDB report queue - IPs are held for ABUSEIPDB_REPORT_DELAY_SECS
    /// before reporting, giving time for false-positive correction.
    abuseipdb_report_queue: Vec<(String, String, String, chrono::DateTime<chrono::Utc>)>,
    /// Incremental narrative accumulator - avoids re-reading events file.
    narrative_acc: NarrativeAccumulator,
    /// Legacy: was byte offset for JSONL incident reading. SQLite cursor is
    /// now stored in the database itself. Kept to avoid churning test state structs.
    #[allow(dead_code)]
    narrative_incidents_offset: u64,
    /// Forensics capture - grabs /proc state for High/Critical process incidents.
    forensics: forensics::ForensicsCapture,
    /// Persistent state store (redb) - cooldowns, block_counts, ip_reputations,
    /// xdp_block_times, trust_rules. Primary source of truth for reads.
    store: state_store::StateStore,
    sqlite_store: Option<Arc<innerwarden_store::Store>>,
    /// Path used to (re-)open `sqlite_store`. Persisted on the state so
    /// `try_recover_sqlite_store` can lazily retry the open after a
    /// boot-time `database is locked` race; pre-2026-04-23 a failed
    /// initial open left the store as `None` for the entire process
    /// lifetime, silently dropping every SQLite-mediated write
    /// (graph snapshots, blob writes, cursor updates).
    sqlite_store_path: std::path::PathBuf,
    /// Last attempted reopen instant — guards against tight retry loops
    /// when the underlying error is permanent (e.g. disk full).
    sqlite_reopen_last_attempt: Option<std::time::Instant>,
    /// SQLite maintenance scheduler (None when sqlite_store is None).
    maintenance_scheduler: Option<innerwarden_store::maintenance::MaintenanceScheduler>,
    /// Attacker intelligence profiles: IP → unified profile.
    attacker_profiles: HashMap<String, attacker_intel::AttackerProfile>,
    /// Last attacker intel consolidation timestamp (5-minute interval).
    last_intel_consolidation_at: Option<std::time::Instant>,
    /// Cross-layer correlation engine: detects multi-stage attack chains.
    correlation_engine: correlation_engine::CorrelationEngine,
    /// Baseline learning: detects anomalies from normal behavior.
    baseline: baseline::BaselineStore,
    /// Selective packet capture on incidents.
    pcap_capture: pcap_capture::PcapCapture,
    /// V10 neural scoring model — replaced by autoencoder (anomaly_engine).
    /// Kept for API compatibility; will be removed in v0.9.
    #[allow(dead_code)]
    scoring_engine: scoring::ScoringEngine,
    /// Firmware incident cooldown: timestamp of last firmware trust_degraded incident.
    /// Prevents duplicate alerts when trust score is persistently low (e.g., VMs).
    last_firmware_incident_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Hypervisor incident cooldown: timestamp of last hypervisor trust_degraded incident.
    last_hypervisor_incident_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Cached hypervisor environment classification (updated by hypervisor_tick).
    /// Used by firmware_tick for VM detection and by other modules for context.
    hypervisor_environment: Option<innerwarden_hypervisor::Environment>,
    /// Kill chain PID tracker — processes eBPF events and detects attack patterns.
    killchain_tracker: innerwarden_killchain::tracker::PidTracker,
    /// Timestamp of last kill chain stale-PID cleanup.
    last_killchain_cleanup: std::time::Instant,
    /// Threat DNA engine — behavioral fingerprinting, anomaly detection, attack chain tracking.
    dna_state: dna_inline::DnaState,
    /// DDoS Shield engine — rate limiting, SYN tracking, escalation, XDP blocking.
    shield_state: Option<shield_inline::ShieldState>,
    /// Shared deep security snapshot for dashboard API.
    deep_security_snapshot:
        Option<std::sync::Arc<std::sync::RwLock<dashboard::DeepSecuritySnapshot>>>,
    /// Timestamp of last DNA state persistence.
    last_dna_save: std::time::Instant,
    /// Phase 7B (audit RC-2 / 2026-04-29): timestamp of the last
    /// orphan-recovery sweep. Slow_loop runs the sweep every 10
    /// minutes — finds incidents >1h old with no decision (deploy
    /// orphans, AI skips, provider outages) and writes a final
    /// `dismiss` decision so they leave the operator-visible
    /// "Stuck" bucket. Without this the dashboard accumulates
    /// dead-weight stuck count forever.
    last_orphan_recovery: std::time::Instant,
    /// Spec 062 Phase 2 — last needs_review-timeout sweep tick.
    last_needs_review_timeout: std::time::Instant,
    /// Spec 076 phase 2 — last block-enforcement reconcile tick (re-applies
    /// firewall rules that silently dropped while their record stayed Active).
    last_block_enforcement_reconcile: std::time::Instant,
    /// Spec 081 follow-up — last agent-guard registry reconcile tick. Throttles
    /// the slow-loop auto-registration / dead-pid pruning of co-located AI agents
    /// (see `agent_registry_reconcile`) to ~5 min so the response-side verifier's
    /// `by_pid` hint survives agent restarts without a per-tick `/proc` scan.
    last_agent_registry_reconcile: std::time::Instant,
    /// One-shot signal from the Telegram `/mode` command (set deep in the
    /// command handler, which only has `&mut state`) up to the main loop, which
    /// owns `cfg`, applies the change via `agent_context::apply_guardian_mode`,
    /// then persists it to agent.toml. Kept as a signal (not a separate
    /// override) so the mutated `cfg` stays the single source of truth for every
    /// `cfg.responder.*` enforcement read, with no per-site threading and no gap.
    pending_mode_change: Option<telegram::GuardianMode>,
    /// One-shot signals from the Telegram Settings buttons (profile / alert
    /// sensitivity) up to the main loop, same pattern as `pending_mode_change`:
    /// the handler only has `&mut state`, the loop owns `cfg`, applies +
    /// persists, and re-registers the command menu when the profile flips. This
    /// is what makes those buttons ACTUATE instead of printing a CLI hint.
    pending_setting_changes: Vec<SettingChange>,
    /// Dynamic allowlist loaded from /etc/innerwarden/allowlist.toml.
    /// Hot-reloaded every 60s. Merged with static config allowlist at check time.
    dynamic_trusted_ips: Vec<String>,
    dynamic_trusted_users: Vec<String>,
    dynamic_trusted_processes: Vec<String>,
    /// IPs of active operator SSH sessions (trusted_users). Never blocked.
    /// Value = last time the session was confirmed active via `who`.
    operator_ips: std::collections::HashMap<String, std::time::Instant>,
    /// Last time we refreshed operator_ips from `who -i`.
    last_operator_refresh: std::time::Instant,
    /// Suppressed incident patterns (user-configurable via CLI/dashboard).
    suppressed_incident_ids: std::collections::HashSet<String>,
    /// Threat feed client for external intelligence (None when disabled).
    threat_feed: Option<threat_feeds::ThreatFeedClient>,
    /// Timestamp of last baseline anomaly detection (for score fusion with autoencoder).
    last_baseline_anomaly_ts: Option<chrono::DateTime<chrono::Utc>>,
    /// Timestamp of last autoencoder anomaly detection (for score fusion with baseline).
    last_autoencoder_anomaly_ts: Option<chrono::DateTime<chrono::Utc>>,
    /// Latest autoencoder anomaly score (0.0-1.0). Used as signal to boost confidence
    /// in decisions made by other detectors. Reset each tick.
    latest_anomaly_score: Option<f32>,
    /// Two-factor authentication state (pending actions, brute force protection).
    two_factor_state: two_factor::TwoFactorState,
    /// Issue #71: shared map bridging the agent loop and dashboard 2FA endpoints.
    /// Populated by `decision_confirmation.rs` when a pending confirmation is created;
    /// the dashboard `/api/2fa/pending` handler reads from it.
    dashboard_pending: std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<String, crate::telegram::PendingConfirmation>>,
    >,
    /// Issue #71: receives approve/deny outcomes from the dashboard 2FA endpoints.
    /// Drained at the start of every incident tick, parallel to `approval_rx`.
    dashboard_approval_rx:
        Option<tokio::sync::mpsc::Receiver<crate::dashboard::state::DashboardApprovalOutcome>>,
    /// Knowledge graph — in-memory directed graph for attack context (shared with dashboard).
    knowledge_graph: std::sync::Arc<std::sync::RwLock<knowledge_graph::KnowledgeGraph>>,
    /// Graph-based detector state (cooldowns).
    graph_detector_state: knowledge_graph::detectors::GraphDetectorState,
    /// Timestamp of last knowledge graph snapshot save.
    last_graph_snapshot: std::time::Instant,
    /// Notification gate burst tracker — counts contained threats for burst summary.
    notification_burst_tracker: notification_gate::BurstTracker,
    /// Spec 005 Phase 7 — implicit operator feedback (ignore-driven demotion).
    feedback_tracker: notification_pipeline::FeedbackTracker,
    /// Last time the feedback tracker ticked 24h-old pendings into ignores.
    last_feedback_tick_at: Option<std::time::Instant>,
    /// Spec 036 (audit I-04) PR-2: TaskGroup for graceful shutdown of
    /// migrated spawn sites. Cheap `Arc`-wrapped type — cloning into
    /// spawn call sites is trivial. This PR tracks firmware alert
    /// spawns and the Telegram polling loop; subsequent PRs register
    /// more sites. No SIGTERM handler is wired yet (that is a separate
    /// PR under operator approval), so in production today the group
    /// is tracked but `shutdown()` is never called — tasks keep
    /// running until the process exits, same as before. The group
    /// becomes load-bearing the moment the signal handler lands.
    task_group: task_group::TaskGroup,
    /// Spec 081 — managed-agent coexistence. The SAME live agent-guard registry
    /// the dashboard mutates via `agent connect` (shared `Arc`), so the
    /// response-side `managed_agent_guard` verifier consulted in the slow-loop
    /// (kernel PID-block + userspace IP-block paths) sees operator-vouched
    /// agents the instant they connect. Plus a shared signature index for the
    /// live cmdline re-ID step.
    agent_registry: Arc<tokio::sync::Mutex<innerwarden_agent_guard::registry::Registry>>,
    signature_index: Arc<innerwarden_agent_guard::signatures::SignatureIndex>,
}

/// Tracks a deferred honeypot-or-block decision waiting for operator input via Telegram.
struct PendingHoneypotChoice {
    #[allow(dead_code)]
    ip: String,
    incident_id: String,
    incident: innerwarden_core::incident::Incident,
    expires_at: chrono::DateTime<chrono::Utc>,
}

pub(crate) use decision_cooldown::DECISION_COOLDOWN_SECS;
pub(crate) use decision_cooldown::{
    decision_cooldown_candidates, decision_cooldown_key_for_decision, load_last_narrative_instant,
    load_startup_decision_state, notification_cooldown_keys, ABUSEIPDB_REPORT_DELAY_SECS,
    DECISION_COOLDOWN_RETENTION_SECS, MAX_BLOCKS_PER_MINUTE, NOTIFICATION_COOLDOWN_RETENTION_SECS,
    NOTIFICATION_COOLDOWN_SECS,
};
pub(crate) use ip_reputation::{
    adaptive_block_ttl_secs, append_blocked_ip, load_ip_reputations, persist_ip_reputations,
    scan_honeypot_for_profiles, LocalIpReputation,
};
pub(crate) use trust_rules::{
    append_trust_rule, enable_lsm_enforcement, is_trusted, load_trust_rules, should_auto_enable_lsm,
};
// Constants re-exported from decision_cooldown (kept here for backward compat)

// Cooldown functions moved to decision_cooldown.rs

// (cooldown functions, startup state loaders, and narrative instant moved to decision_cooldown.rs)

// Trust rules and LSM enforcement moved to trust_rules.rs

// ---------------------------------------------------------------------------
// Spec 015: one-shot cleanup of graph_user_creation false positives and
// brute-force User node pollution. Invoked via
// `innerwarden-agent --cleanup-015-graph-signal-quality`. Non-destructive
// outside that flag: the function below loads today's dated snapshot,
// writes a timestamped backup, applies the migration, and saves the result.
// ---------------------------------------------------------------------------

pub(crate) use process::post_decision::{
    append_honeypot_marker_event, execute_decision, honeypot_runtime,
};

// ---------------------------------------------------------------------------
// Tracing-capture test utilities (Spec 037 I-13 follow-up #3, refactored)
// ---------------------------------------------------------------------------
//
// The original PR #310 fix (a crate-level `TRACING_CAPTURE_LOCK`
// `Mutex<()>` plus per-test `tracing::subscriber::with_default(...)`)
// reduced flakiness but did not eliminate it: even with the Mutex
// serialising tests, the per-test thread-local dispatcher
// occasionally failed to receive an event fired on its own thread
// (~25 % `make test` failure rate post-fix; CI hit it twice in a
// row). Replaced by a global capture subscriber + thread-local
// buffer in `crate::test_util`. See that module's rustdoc for the
// full root cause + fix rationale.
//
// `TRACING_CAPTURE_LOCK` no longer exists; tests call
// `crate::test_util::arm_capture()` (returns a guard that holds the
// new shared lock) and `crate::test_util::drain_capture()`.
#[cfg(test)]
mod test_util;

#[tokio::main]
async fn main() -> Result<()> {
    // Load .env file if present (fail-silent - production uses real env vars)
    match dotenvy::dotenv() {
        Ok(path) => debug!("loaded env from {}", path.display()),
        Err(dotenvy::Error::Io(_)) => {} // no .env file - that's fine
        Err(e) => warn!("could not parse .env file: {e}"),
    }

    // 2026-05-01: include `telegram_audit=info` so the
    // `info!(target: "telegram_audit", ...)` lines from
    // `crates/agent/src/telegram/client.rs::post_json_with_response`
    // reach journald. Pre-fix the audit target sat outside the
    // `innerwarden_agent` namespace and was filtered out — operator
    // had no journald visibility into outgoing Telegram traffic
    // (daily digests, menu callbacks, manual approvals all silent).
    // The persistent audit lives in `data_dir/telegram-sent.jsonl`
    // (see `telegram::client::write_audit_jsonl`) so journald log
    // rotation does not lose the trail.
    init_tracing()?;

    let cli = Cli::parse();

    // --validate-config-only: parse the agent.toml against the strict
    // schema, print OK + a section count summary, exit 0 on success or
    // exit 1 on parse error. Used by `innerwarden config validate` (the
    // ctl subcommand) and by `scripts/deploy-prod.sh` step [-1/4] to
    // refuse a deploy whose agent.toml has unknown keys. Wave 9e anchor
    // for AUDIT-002 ("agent.toml [data_retention] silently ignored").
    if cli.validate_config_only {
        return run_validate_config_only(cli);
    }

    // --playbook-replay: offline batch validation of playbooks against a
    // captured incidents JSONL. Dry-run only, prints a report, exits.
    if cli.playbook_replay.is_some() {
        return run_playbook_replay(cli).await;
    }

    loops::boot::run_agent(cli).await
}

/// Implements `--playbook-replay <file>`: load playbooks (built-ins +
/// operator dir), run every incident in the JSONL through them in dry-run,
/// and print a [`playbook_engine::replay::ReplayReport`]. No skills fire,
/// no audit is written.
async fn run_playbook_replay(cli: Cli) -> Result<()> {
    let path = cli
        .playbook_replay
        .clone()
        .expect("guarded by is_some() at call site");
    let cfg = match &cli.config {
        Some(p) => config::load(p)?,
        None => config::AgentConfig::default(),
    };

    let content = std::fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("read incidents file {}: {e}", path.display()))?;
    let mut incidents = Vec::new();
    let mut skipped = 0usize;
    for line in content.lines() {
        let l = line.trim();
        if l.is_empty() {
            continue;
        }
        match serde_json::from_str::<innerwarden_core::incident::Incident>(l) {
            Ok(inc) => incidents.push(inc),
            Err(_) => skipped += 1,
        }
    }

    // Faithful matching: `$cloud_safelist` conditions consult the static
    // cloud ranges, which are lazily populated by this init (the live agent
    // does it at boot).
    crate::cloud_safelist::init();
    crate::cloud_safelist::init_operator_self_infra(&cfg.allowlist.self_infra_ips);

    let rules_dir = std::path::Path::new(&cfg.playbooks.rules_dir);
    let playbooks = playbook_engine::load_dir(rules_dir).unwrap_or_else(|e| {
        eprintln!("warn: could not load operator playbooks ({e}); using built-ins only");
        playbook_engine::load_builtins().unwrap_or_default()
    });
    let registry = crate::skills::SkillRegistry::default_builtin();

    let report = playbook_engine::replay::replay_incidents(
        &playbooks,
        &registry,
        &cfg.allowlist.trusted_ips,
        &cfg.agent.tags, // host asset tags ([agent] tags), mirrors live path
        &incidents,
    )
    .await;

    if skipped > 0 {
        println!("(skipped {skipped} unparseable line(s))\n");
    }
    println!(
        "Loaded {} playbook(s) from built-ins + {}\n",
        playbooks.len(),
        cfg.playbooks.rules_dir
    );
    print!("{}", report.render());
    Ok(())
}

/// Implements `--validate-config-only`. Lives in main.rs (not boot.rs) so the
/// validate path does not pull in any of run_agent's heavyweight init - the
/// goal is "parse + exit" and nothing else, so the deploy-prod pre-flight
/// runs in milliseconds even on a slow box.
fn run_validate_config_only(cli: Cli) -> Result<()> {
    let path = cli
        .config
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("--validate-config-only requires --config <path>"))?;
    if !path.exists() {
        anyhow::bail!(
            "--validate-config-only: config file not found at {}\n\
             (no error: a missing file would default to AgentConfig::default(), \
             which is fine at runtime but a likely operator mistake at deploy time)",
            path.display()
        );
    }
    match config::load(path) {
        Ok(_cfg) => {
            println!(
                "OK: {} parsed against strict AgentConfig schema (Wave 9e).",
                path.display()
            );
            println!("All sections / keys recognised; deny_unknown_fields gate would not refuse this config.");
            Ok(())
        }
        Err(e) => {
            // Operator-friendly error. The serde error chain already names the
            // unknown field + section; print the chain so the operator sees
            // which line of agent.toml to fix.
            eprintln!(
                "FAIL: {} did NOT parse against strict AgentConfig schema.",
                path.display()
            );
            eprintln!("Reason: {:#}", e);
            eprintln!();
            eprintln!(
                "Wave 9e enforcement: agent.toml fields must match the AgentConfig struct exactly."
            );
            eprintln!("Common fixes:");
            eprintln!("  - Section [data_retention] is now also accepted via serde alias for [data]; if your");
            eprintln!("    file uses [data_retention] and STILL fails, check inner field names (events_keep_days,");
            eprintln!("    incidents_keep_days, filestore_max_size_mb, etc) against `crates/agent/src/config.rs`.");
            eprintln!("  - Typo'd keys: cross-check against the same struct.");
            eprintln!("  - Unknown sections: remove or rename to match.");
            std::process::exit(1);
        }
    }
}

/// Build the tracing env-filter shared by every tracing init path. Pure
/// so the unit test below can compare directives without reaching into
/// process-global state.
fn build_tracing_env_filter() -> Result<tracing_subscriber::EnvFilter> {
    Ok(tracing_subscriber::EnvFilter::from_default_env()
        .add_directive("innerwarden_agent=info".parse()?)
        .add_directive("telegram_audit=info".parse()?)
        // 2026-05-01 (audit-ui spec): the maintenance scheduler emits
        // `info!` log lines from `innerwarden_store::maintenance` for the
        // steady-state path ("hash chain intact (documented breaks
        // tolerated)", "kv expired cleanup", etc.). Without this directive
        // those drop at the default WARN level, which means a successful
        // hourly tick is invisible (operator only sees output when
        // something is broken). Same family as the telegram_audit gap
        // PR #357 closed.
        .add_directive("innerwarden_store=info".parse()?))
}

/// Wave 9f (AUDIT-009 root): true iff the process is being captured by
/// systemd's journal stream. Pure helper so tests do not have to mutate
/// process-global env vars - we pass the env value in as an argument.
///
/// systemd sets `JOURNAL_STREAM=<dev>:<inode>` on services launched via a
/// unit file, so the binary's stdout/stderr go into the journal. Reading
/// that env var is the documented way to detect the case (man:systemd.exec
/// "Environment Variables Set or Propagated by the Manager"). When the
/// variable is set we route tracing through `tracing-journald` so each
/// record gets a real `PRIORITY=` field, instead of letting journald
/// guess the priority off the captured plain stdout text.
///
/// `#[allow(dead_code)]` outside Linux: the only non-test caller is the
/// Linux-cfg branch in `init_tracing`. macOS / dev-shell builds never
/// reach the call site, but the unit tests below DO build and exercise
/// the function on every platform - hence the `cfg_attr(not(test), ...)`.
#[cfg_attr(not(test), allow(dead_code))]
fn use_journald_layer(journal_stream: Option<&str>) -> bool {
    journal_stream.is_some_and(|v| !v.is_empty())
}

/// Set up tracing for the agent binary. Routes through `tracing-journald`
/// when running under systemd, plain stdout fmt subscriber otherwise. See
/// [`use_journald_layer`] for the systemd-detection contract.
fn init_tracing() -> Result<()> {
    let env_filter = build_tracing_env_filter()?;

    #[cfg(target_os = "linux")]
    {
        let journal_stream = std::env::var("JOURNAL_STREAM").ok();
        if use_journald_layer(journal_stream.as_deref()) {
            // Systemd-managed run: emit structured journal records. WARN /
            // ERROR get PRIORITY=4/3 so `journalctl -p warning` filters
            // work. Record fields land as JOURNAL_FIELD entries which
            // operators can `grep` with `journalctl _JOURNAL_FIELD=...`.
            // If the journald socket is unreachable for any reason fall
            // back to fmt so the agent still boots.
            use tracing_subscriber::layer::SubscriberExt;
            use tracing_subscriber::util::SubscriberInitExt;
            match tracing_journald::layer() {
                Ok(layer) => {
                    tracing_subscriber::registry()
                        .with(env_filter)
                        .with(layer)
                        .init();
                    return Ok(());
                }
                Err(e) => {
                    eprintln!(
                        "tracing-journald layer unavailable ({e}); falling back to stdout fmt subscriber"
                    );
                }
            }
        }
    }
    // Off-systemd, dev shell, macOS: stdout fmt with the existing env-filter.
    tracing_subscriber::fmt().with_env_filter(env_filter).init();
    Ok(())
}

#[cfg(test)]
mod tests;
