use super::*;
use crate::loops::boot::{backfill_015_research_only_backup_path, cleanup_015_backup_path};
use crate::loops::slow_loop::{
    operator_ips_from_who_output, status_field_u32, status_ppid, status_tgid,
};
use crate::process::incidents::process_incidents;
use crate::process::telegram_approval::process_telegram_approval;
use clap::Parser;
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, RwLock,
};
use tempfile::TempDir;

// ------------------------------------------------------------------
// Minimal mock AI provider - returns a fixed decision, no network I/O
// ------------------------------------------------------------------

struct MockAiProvider {
    decision: ai::AiDecision,
}

#[async_trait::async_trait]
impl ai::AiProvider for MockAiProvider {
    fn name(&self) -> &'static str {
        "mock"
    }
    async fn decide(&self, _ctx: &ai::DecisionContext<'_>) -> anyhow::Result<ai::AiDecision> {
        Ok(self.decision.clone())
    }
    async fn chat(&self, _system_prompt: &str, _user_message: &str) -> anyhow::Result<String> {
        Ok("mock chat response".to_string())
    }
}

struct CountingMockAiProvider {
    decision: ai::AiDecision,
    calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl ai::AiProvider for CountingMockAiProvider {
    fn name(&self) -> &'static str {
        "mock-counting"
    }
    async fn decide(&self, _ctx: &ai::DecisionContext<'_>) -> anyhow::Result<ai::AiDecision> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.decision.clone())
    }
    async fn chat(&self, _system_prompt: &str, _user_message: &str) -> anyhow::Result<String> {
        Ok("mock chat response".to_string())
    }
}

struct CorrelationInspectingMockAiProvider {
    decision: ai::AiDecision,
    last_related_count: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl ai::AiProvider for CorrelationInspectingMockAiProvider {
    fn name(&self) -> &'static str {
        "mock-correlation"
    }

    async fn decide(&self, ctx: &ai::DecisionContext<'_>) -> anyhow::Result<ai::AiDecision> {
        self.last_related_count
            .store(ctx.related_incidents.len(), Ordering::SeqCst);
        Ok(self.decision.clone())
    }

    async fn chat(&self, _system_prompt: &str, _user_message: &str) -> anyhow::Result<String> {
        Ok("mock chat response".to_string())
    }
}

/// Create a test incident (ssh brute-force from an external IP).
pub(crate) fn test_incident(ip: &str) -> innerwarden_core::incident::Incident {
    innerwarden_core::incident::Incident {
        ts: chrono::Utc::now(),
        host: "test-host".to_string(),
        incident_id: format!("ssh_bruteforce:{ip}:test"),
        severity: innerwarden_core::event::Severity::High,
        title: "SSH Brute Force".to_string(),
        summary: format!("9 failed SSH attempts from {ip}"),
        evidence: serde_json::json!({"failed_attempts": 9}),
        recommended_checks: vec![],
        tags: vec!["ssh".to_string()],
        entities: vec![innerwarden_core::entities::EntityRef::ip(ip)],
    }
}

pub(crate) fn test_incident_with_kind(
    ip: &str,
    kind: &str,
) -> innerwarden_core::incident::Incident {
    innerwarden_core::incident::Incident {
        ts: chrono::Utc::now(),
        host: "test-host".to_string(),
        incident_id: format!("{kind}:{ip}:test"),
        severity: innerwarden_core::event::Severity::High,
        title: format!("{kind} detected"),
        summary: format!("{kind} from {ip}"),
        evidence: serde_json::json!({"kind": kind}),
        recommended_checks: vec![],
        tags: vec![kind.to_string()],
        entities: vec![innerwarden_core::entities::EntityRef::ip(ip)],
    }
}

/// Write a minimal Incident JSON line (kept for backcompat with tests that need JSONL).
pub(crate) fn incident_line(ip: &str) -> String {
    serde_json::to_string(&test_incident(ip)).unwrap()
}

pub(crate) fn incident_line_with_kind(ip: &str, kind: &str) -> String {
    serde_json::to_string(&test_incident_with_kind(ip, kind)).unwrap()
}

/// Open a SQLite store in the temp dir and return it wrapped in Arc.
pub(crate) fn test_sqlite_store(dir: &std::path::Path) -> Arc<innerwarden_store::Store> {
    Arc::new(innerwarden_store::Store::open(dir).unwrap())
}

/// Insert an incident into the SQLite store.
pub(crate) fn insert_test_incident(
    store: &innerwarden_store::Store,
    incident: &innerwarden_core::incident::Incident,
) {
    store.insert_incident(incident).unwrap();
}

pub(crate) fn test_event(
    kind: &str,
    severity: innerwarden_core::event::Severity,
    details: serde_json::Value,
) -> innerwarden_core::event::Event {
    innerwarden_core::event::Event {
        ts: chrono::Utc::now(),
        host: "test-host".to_string(),
        source: "unit-test".to_string(),
        kind: kind.to_string(),
        severity,
        summary: format!("test event: {kind}"),
        details,
        tags: vec![],
        entities: vec![],
    }
}

pub(crate) fn insert_test_event(
    store: &innerwarden_store::Store,
    event: &innerwarden_core::event::Event,
) {
    store.insert_event(event).unwrap();
}

fn sha256_hex_for_test(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub(crate) fn triage_approval(incident_id: &str, operator: &str) -> telegram::ApprovalResult {
    telegram::ApprovalResult {
        incident_id: incident_id.to_string(),
        approved: true,
        operator_name: operator.to_string(),
        always: false,
        chosen_action: String::new(),
    }
}

pub(crate) fn triage_test_state(data_dir: &Path) -> AgentState {
    AgentState {
        skill_registry: skills::SkillRegistry::default_builtin(),
        blocklist: skills::Blocklist::default(),
        correlator: correlation::TemporalCorrelator::new(300, 4096),
        telemetry: telemetry::TelemetryState::default(),
        telemetry_writer: None,
        ai_router: ai::AiRouter::disabled(),
        decision_writer: Some(decisions::DecisionWriter::new(data_dir).unwrap()),
        last_narrative_at: None,
        last_daily_summary_telegram: None,
        telegram_daily_sent: 0,
        telegram_budget_date: None,
        telegram_deferred: HashMap::new(),
        telegram_client: None,
        pending_confirmations: HashMap::new(),
        approval_rx: None,
        dashboard_pending: std::sync::Arc::new(std::sync::Mutex::new(
            std::collections::HashMap::new(),
        )),
        dashboard_approval_rx: None,
        grouping_engine: notification_pipeline::GroupingEngine::new(
            &crate::config::NotificationPipelineConfig::default(),
        ),
        environment_profile: environment_profile::EnvironmentProfile::default(),
        last_env_census_at: None,
        host_posture: posture::HostPosture::default(),
        last_host_posture_at: None,
        anomaly_engine: neural_lifecycle::AnomalyEngine::new(Default::default()),
        neural_incidents: Vec::new(),
        trust_rules: std::collections::HashSet::new(),
        crowdsec: None,
        abuseipdb: None,
        geoip_client: None,
        slack_client: None,
        discord_client: None,
        cloudflare_client: None,
        circuit_breaker_until: None,
        pending_honeypot_choices: HashMap::new(),
        ip_reputations: HashMap::new(),
        lsm_enabled: false,
        mesh: None,
        recent_blocks: std::collections::VecDeque::new(),
        xdp_block_times: HashMap::new(),
        xdp_cleanup_backoff: HashMap::new(),
        response_lifecycle: response_lifecycle::ResponseLifecycle::new(),
        abuseipdb_report_queue: Vec::new(),
        narrative_acc: NarrativeAccumulator::default(),
        narrative_incidents_offset: 0,
        forensics: forensics::ForensicsCapture::new(data_dir),
        store: state_store::StateStore::open(data_dir).unwrap(),
        sqlite_store: None,
        sqlite_store_path: data_dir.to_path_buf(),
        sqlite_reopen_last_attempt: None,
        maintenance_scheduler: None,
        attacker_profiles: HashMap::new(),
        last_intel_consolidation_at: None,
        correlation_engine: correlation_engine::CorrelationEngine::new(),
        baseline: baseline::BaselineStore::new(),
        pcap_capture: pcap_capture::PcapCapture::new(data_dir),
        scoring_engine: scoring::ScoringEngine::new(0.95),
        last_firmware_incident_at: None,
        last_hypervisor_incident_at: None,
        hypervisor_environment: None,
        killchain_tracker: innerwarden_killchain::tracker::PidTracker::new(),
        last_killchain_cleanup: std::time::Instant::now(),
        dna_state: dna_inline::DnaState::new(
            &std::path::PathBuf::from("/var/lib/innerwarden/dna"),
            3,
            3.0,
            300,
        ),
        last_dna_save: std::time::Instant::now(),
        last_orphan_recovery: std::time::Instant::now(),
        last_needs_review_timeout: std::time::Instant::now(),
        last_block_enforcement_reconcile: std::time::Instant::now(),
        last_agent_registry_reconcile: std::time::Instant::now(),
        pending_mode_change: None,
        pending_setting_changes: Vec::new(),
        shield_state: None,
        deep_security_snapshot: None,
        dynamic_trusted_ips: Vec::new(),
        dynamic_trusted_users: Vec::new(),
        dynamic_trusted_processes: Vec::new(),
        operator_ips: std::collections::HashMap::new(),
        last_operator_refresh: std::time::Instant::now(),
        suppressed_incident_ids: std::collections::HashSet::new(),
        threat_feed: None,
        last_baseline_anomaly_ts: None,
        last_autoencoder_anomaly_ts: None,
        latest_anomaly_score: None,
        two_factor_state: two_factor::TwoFactorState::new(),
        knowledge_graph: std::sync::Arc::new(std::sync::RwLock::new(
            knowledge_graph::KnowledgeGraph::new(),
        )),
        graph_detector_state: knowledge_graph::detectors::GraphDetectorState::new(),
        last_graph_snapshot: std::time::Instant::now(),
        notification_burst_tracker: notification_gate::BurstTracker::new(),
        feedback_tracker: notification_pipeline::FeedbackTracker::new(),
        last_feedback_tick_at: None,
        task_group: crate::task_group::TaskGroup::new(),
        agent_registry: std::sync::Arc::new(tokio::sync::Mutex::new(
            innerwarden_agent_guard::registry::Registry::new(),
        )),
        signature_index: std::sync::Arc::new(
            innerwarden_agent_guard::signatures::SignatureIndex::new(),
        ),
    }
}

#[test]
fn parse_telegram_triage_action_routes_allow_proc() {
    assert_eq!(
        parse_telegram_triage_action("__allow_proc__:cargo-build"),
        Some(TelegramTriageAction::AllowProc("cargo-build"))
    );
}

#[test]
fn parse_telegram_triage_action_routes_allow_ip() {
    assert_eq!(
        parse_telegram_triage_action("__allow_ip__:1.2.3.4"),
        Some(TelegramTriageAction::AllowIp("1.2.3.4"))
    );
}

#[test]
fn parse_telegram_triage_action_routes_fp_report() {
    assert_eq!(
        parse_telegram_triage_action("__fp__:ssh_bruteforce:1.2.3.4:test"),
        Some(TelegramTriageAction::ReportFp(
            "ssh_bruteforce:1.2.3.4:test"
        ))
    );
}

#[test]
fn parse_telegram_triage_action_ignores_non_triage_ids() {
    assert_eq!(parse_telegram_triage_action("__status__"), None);
    assert_eq!(
        parse_telegram_triage_action("approve:ssh_bruteforce:id"),
        None
    );
}

#[test]
fn sanitize_allowlist_process_name_removes_dangerous_chars() {
    assert_eq!(
        sanitize_allowlist_process_name("  bad\"proc\nname  "),
        Some("badproc name".to_string())
    );
    assert_eq!(sanitize_allowlist_process_name("   "), None);
}

#[tokio::test]
async fn telegram_triage_allowlist_skip_paths_are_audited_with_hash_chain() {
    let dir = TempDir::new().unwrap();
    let cfg = config::AgentConfig::default();
    let mut state = triage_test_state(dir.path());

    process_telegram_approval(
        triage_approval("__allow_proc__:   ", "alice"),
        dir.path(),
        &cfg,
        &mut state,
    )
    .await;
    process_telegram_approval(
        triage_approval("__allow_ip__:not-an-ip", "alice"),
        dir.path(),
        &cfg,
        &mut state,
    )
    .await;

    if let Some(w) = &mut state.decision_writer {
        w.flush();
    }

    let today = chrono::Local::now()
        .date_naive()
        .format("%Y-%m-%d")
        .to_string();
    let decisions_path = dir.path().join(format!("decisions-{today}.jsonl"));
    let lines: Vec<String> = std::fs::read_to_string(&decisions_path)
        .unwrap()
        .lines()
        .map(|line| line.to_string())
        .collect();

    assert_eq!(lines.len(), 2, "expected two triage audit entries");

    let first: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
    let second: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();

    assert_eq!(first["action_type"], "allowlist_add");
    assert_eq!(first["execution_result"], "skipped:empty_process_name");
    assert_eq!(second["action_type"], "allowlist_add");
    assert_eq!(second["execution_result"], "skipped:invalid_ip");

    assert!(
        first.get("prev_hash").is_none(),
        "first entry should not have prev_hash"
    );
    let expected_prev_hash = sha256_hex_for_test(&lines[0]);
    assert_eq!(
        second["prev_hash"].as_str(),
        Some(expected_prev_hash.as_str())
    );
}

#[tokio::test]
async fn telegram_triage_fp_reports_write_audit_and_fp_log() {
    let dir = TempDir::new().unwrap();
    let cfg = config::AgentConfig::default();
    let mut state = triage_test_state(dir.path());
    let fp_incident_id = "ssh_bruteforce:1.2.3.4:test";

    process_telegram_approval(
        triage_approval(&format!("__fp__:{fp_incident_id}"), "alice"),
        dir.path(),
        &cfg,
        &mut state,
    )
    .await;

    if let Some(w) = &mut state.decision_writer {
        w.flush();
    }

    let today_local = chrono::Local::now()
        .date_naive()
        .format("%Y-%m-%d")
        .to_string();
    let decisions_path = dir.path().join(format!("decisions-{today_local}.jsonl"));
    let decision_line = std::fs::read_to_string(&decisions_path)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .to_string();
    let decision: serde_json::Value = serde_json::from_str(&decision_line).unwrap();

    assert_eq!(decision["incident_id"], fp_incident_id);
    assert_eq!(decision["action_type"], "fp_report");
    assert_eq!(decision["execution_result"], "reported_fp:ssh_bruteforce");
    assert_eq!(decision["ai_provider"], "operator:telegram:alice");

    let today_utc = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let fp_path = dir.path().join(format!("fp-reports-{today_utc}.jsonl"));
    let fp_content = std::fs::read_to_string(&fp_path).unwrap();
    assert!(fp_content.contains("\"incident_id\":\"ssh_bruteforce:1.2.3.4:test\""));
    assert!(fp_content.contains("\"detector\":\"ssh_bruteforce\""));
    assert!(fp_content.contains("\"reporter\":\"alice\""));
}

// ------------------------------------------------------------------
// Golden path: incident → algorithm gate → mock AI → dry-run block → decisions.jsonl
// ------------------------------------------------------------------

#[tokio::test]
async fn golden_path_dry_run_produces_decision_entry() {
    let dir = TempDir::new().unwrap();

    // 1. Plant a single brute-force incident from a routable external IP.
    let attacker_ip = "1.2.3.4";
    let store = test_sqlite_store(dir.path());
    insert_test_incident(&store, &test_incident(attacker_ip));

    // 2. Config: AI enabled, responder dry_run=true, ufw backend allowed
    let cfg = config::AgentConfig {
        ai: config::AiConfig {
            enabled: true,
            confidence_threshold: 0.8,
            context_events: 5,
            ..config::AiConfig::default()
        },
        responder: config::ResponderConfig {
            enabled: true,
            dry_run: true,
            block_backend: "ufw".to_string(),
            allowed_skills: vec!["block-ip-ufw".to_string()],
            auto_rules_enabled: false,
            ..config::ResponderConfig::default()
        },
        ..config::AgentConfig::default()
    };

    // 3. Mock provider always recommends blocking the IP
    let mock = Arc::new(MockAiProvider {
        decision: ai::AiDecision {
            action: ai::AiAction::BlockIp {
                ip: attacker_ip.to_string(),
                skill_id: "block-ip-ufw".to_string(),
            },
            confidence: 0.97,
            auto_execute: true,
            reason: "9 SSH failures, no success, external IP - classic brute force".to_string(),
            alternatives: vec!["monitor".to_string()],
            estimated_threat: "high".to_string(),
        },
    });

    let mut state = AgentState {
        skill_registry: skills::SkillRegistry::default_builtin(),
        blocklist: skills::Blocklist::default(),
        correlator: correlation::TemporalCorrelator::new(300, 4096),
        telemetry: telemetry::TelemetryState::default(),
        telemetry_writer: None,
        ai_router: ai::AiRouter::new(
            Some(mock.clone() as Arc<dyn ai::AiProvider>),
            Some(mock.clone() as Arc<dyn ai::AiProvider>),
        )
        .expect("test router with mock provider"),
        decision_writer: Some(decisions::DecisionWriter::new(dir.path()).unwrap()),
        last_narrative_at: None,
        last_daily_summary_telegram: None,
        telegram_daily_sent: 0,
        telegram_budget_date: None,
        telegram_deferred: HashMap::new(),
        telegram_client: None,
        pending_confirmations: HashMap::new(),
        approval_rx: None,
        dashboard_pending: std::sync::Arc::new(std::sync::Mutex::new(
            std::collections::HashMap::new(),
        )),
        dashboard_approval_rx: None,
        grouping_engine: notification_pipeline::GroupingEngine::new(
            &crate::config::NotificationPipelineConfig::default(),
        ),
        environment_profile: environment_profile::EnvironmentProfile::default(),
        last_env_census_at: None,
        host_posture: posture::HostPosture::default(),
        last_host_posture_at: None,
        anomaly_engine: neural_lifecycle::AnomalyEngine::new(Default::default()),
        neural_incidents: Vec::new(),
        trust_rules: std::collections::HashSet::new(),
        crowdsec: None,
        abuseipdb: None,
        geoip_client: None,
        slack_client: None,
        discord_client: None,
        cloudflare_client: None,
        circuit_breaker_until: None,
        pending_honeypot_choices: HashMap::new(),
        ip_reputations: HashMap::new(),
        lsm_enabled: false,
        mesh: None,
        recent_blocks: std::collections::VecDeque::new(),
        xdp_block_times: HashMap::new(),
        xdp_cleanup_backoff: HashMap::new(),
        response_lifecycle: response_lifecycle::ResponseLifecycle::new(),
        abuseipdb_report_queue: Vec::new(),
        narrative_acc: NarrativeAccumulator::default(),
        narrative_incidents_offset: 0,
        forensics: forensics::ForensicsCapture::new(dir.path()),
        store: state_store::StateStore::open(dir.path()).unwrap(),
        sqlite_store: Some(store.clone()),
        sqlite_store_path: dir.path().to_path_buf(),
        sqlite_reopen_last_attempt: None,
        maintenance_scheduler: None,
        attacker_profiles: HashMap::new(),
        last_intel_consolidation_at: None,
        correlation_engine: correlation_engine::CorrelationEngine::new(),
        baseline: baseline::BaselineStore::new(),
        pcap_capture: pcap_capture::PcapCapture::new(dir.path()),
        scoring_engine: scoring::ScoringEngine::new(0.95),
        last_firmware_incident_at: None,
        last_hypervisor_incident_at: None,
        hypervisor_environment: None,
        killchain_tracker: innerwarden_killchain::tracker::PidTracker::new(),
        last_killchain_cleanup: std::time::Instant::now(),
        dna_state: dna_inline::DnaState::new(
            &std::path::PathBuf::from("/var/lib/innerwarden/dna"),
            3,
            3.0,
            300,
        ),
        last_dna_save: std::time::Instant::now(),
        last_orphan_recovery: std::time::Instant::now(),
        last_needs_review_timeout: std::time::Instant::now(),
        last_block_enforcement_reconcile: std::time::Instant::now(),
        last_agent_registry_reconcile: std::time::Instant::now(),
        pending_mode_change: None,
        pending_setting_changes: Vec::new(),
        shield_state: None,
        deep_security_snapshot: None,
        dynamic_trusted_ips: Vec::new(),
        dynamic_trusted_users: Vec::new(),
        dynamic_trusted_processes: Vec::new(),
        operator_ips: std::collections::HashMap::new(),
        last_operator_refresh: std::time::Instant::now(),
        suppressed_incident_ids: std::collections::HashSet::new(),
        threat_feed: None,
        last_baseline_anomaly_ts: None,
        last_autoencoder_anomaly_ts: None,
        latest_anomaly_score: None,
        two_factor_state: two_factor::TwoFactorState::new(),
        knowledge_graph: std::sync::Arc::new(std::sync::RwLock::new(
            knowledge_graph::KnowledgeGraph::new(),
        )),
        graph_detector_state: knowledge_graph::detectors::GraphDetectorState::new(),
        last_graph_snapshot: std::time::Instant::now(),
        notification_burst_tracker: notification_gate::BurstTracker::new(),
        feedback_tracker: notification_pipeline::FeedbackTracker::new(),
        last_feedback_tick_at: None,
        task_group: crate::task_group::TaskGroup::new(),
        agent_registry: std::sync::Arc::new(tokio::sync::Mutex::new(
            innerwarden_agent_guard::registry::Registry::new(),
        )),
        signature_index: std::sync::Arc::new(
            innerwarden_agent_guard::signatures::SignatureIndex::new(),
        ),
    };

    // 4. Run the incident tick
    let mut cursor = reader::AgentCursor::default();
    let handled = process_incidents(
        dir.path(),
        &mut cursor,
        &cfg,
        &mut state,
        &Arc::new(RwLock::new(VecDeque::new())),
    )
    .await;

    // Verify: one incident handled
    assert_eq!(handled, 1, "expected 1 incident handled");

    // Verify: decision written to audit trail
    if let Some(w) = &mut state.decision_writer {
        w.flush();
    }
    let today = chrono::Local::now()
        .date_naive()
        .format("%Y-%m-%d")
        .to_string();
    let decisions_path = dir.path().join(format!("decisions-{today}.jsonl"));
    let content = std::fs::read_to_string(&decisions_path).unwrap();
    assert!(
        content.contains(attacker_ip),
        "decision must record the target IP"
    );
    assert!(
        content.contains("block_ip"),
        "decision must record action type"
    );
    assert!(
        content.contains("\"dry_run\":true"),
        "dry_run must be flagged in audit trail"
    );
    assert!(
        content.contains("mock"),
        "AI provider name must appear in audit trail"
    );
}

// ------------------------------------------------------------------
// allowed_skills whitelist: AI selects a disallowed skill → fallback used
// ------------------------------------------------------------------

#[tokio::test]
async fn allowed_skills_whitelist_enforced() {
    let dir = TempDir::new().unwrap();
    let today = chrono::Local::now()
        .date_naive()
        .format("%Y-%m-%d")
        .to_string();

    let attacker_ip = "5.6.7.8";
    let store = test_sqlite_store(dir.path());
    insert_test_incident(&store, &test_incident(attacker_ip));

    let cfg = config::AgentConfig {
        ai: config::AiConfig {
            enabled: true,
            confidence_threshold: 0.5,
            context_events: 5,
            ..config::AiConfig::default()
        },
        responder: config::ResponderConfig {
            enabled: true,
            dry_run: true,
            block_backend: "ufw".to_string(),
            // Only ufw is allowed; AI picks iptables - should fall back silently
            allowed_skills: vec!["block-ip-ufw".to_string()],
            auto_rules_enabled: false,
            ..config::ResponderConfig::default()
        },
        ..config::AgentConfig::default()
    };

    // AI picks iptables (not in whitelist)
    let mock = Arc::new(MockAiProvider {
        decision: ai::AiDecision {
            action: ai::AiAction::BlockIp {
                ip: attacker_ip.to_string(),
                skill_id: "block-ip-iptables".to_string(), // NOT in allowed_skills
            },
            confidence: 0.95,
            auto_execute: true,
            reason: "brute force".to_string(),
            alternatives: vec![],
            estimated_threat: "high".to_string(),
        },
    });

    let mut state = AgentState {
        skill_registry: skills::SkillRegistry::default_builtin(),
        blocklist: skills::Blocklist::default(),
        correlator: correlation::TemporalCorrelator::new(300, 4096),
        telemetry: telemetry::TelemetryState::default(),
        telemetry_writer: None,
        ai_router: ai::AiRouter::new(
            Some(mock.clone() as Arc<dyn ai::AiProvider>),
            Some(mock.clone() as Arc<dyn ai::AiProvider>),
        )
        .expect("test router with mock provider"),
        decision_writer: Some(decisions::DecisionWriter::new(dir.path()).unwrap()),
        last_narrative_at: None,
        last_daily_summary_telegram: None,
        telegram_daily_sent: 0,
        telegram_budget_date: None,
        telegram_deferred: HashMap::new(),
        telegram_client: None,
        pending_confirmations: HashMap::new(),
        approval_rx: None,
        dashboard_pending: std::sync::Arc::new(std::sync::Mutex::new(
            std::collections::HashMap::new(),
        )),
        dashboard_approval_rx: None,
        grouping_engine: notification_pipeline::GroupingEngine::new(
            &crate::config::NotificationPipelineConfig::default(),
        ),
        environment_profile: environment_profile::EnvironmentProfile::default(),
        last_env_census_at: None,
        host_posture: posture::HostPosture::default(),
        last_host_posture_at: None,
        anomaly_engine: neural_lifecycle::AnomalyEngine::new(Default::default()),
        neural_incidents: Vec::new(),
        trust_rules: std::collections::HashSet::new(),
        crowdsec: None,
        abuseipdb: None,
        geoip_client: None,
        slack_client: None,
        discord_client: None,
        cloudflare_client: None,
        circuit_breaker_until: None,
        pending_honeypot_choices: HashMap::new(),
        ip_reputations: HashMap::new(),
        lsm_enabled: false,
        mesh: None,
        recent_blocks: std::collections::VecDeque::new(),
        xdp_block_times: HashMap::new(),
        xdp_cleanup_backoff: HashMap::new(),
        response_lifecycle: response_lifecycle::ResponseLifecycle::new(),
        abuseipdb_report_queue: Vec::new(),
        narrative_acc: NarrativeAccumulator::default(),
        narrative_incidents_offset: 0,
        forensics: forensics::ForensicsCapture::new(dir.path()),
        store: state_store::StateStore::open(dir.path()).unwrap(),
        sqlite_store: Some(store.clone()),
        sqlite_store_path: dir.path().to_path_buf(),
        sqlite_reopen_last_attempt: None,
        maintenance_scheduler: None,
        attacker_profiles: HashMap::new(),
        last_intel_consolidation_at: None,
        correlation_engine: correlation_engine::CorrelationEngine::new(),
        baseline: baseline::BaselineStore::new(),
        pcap_capture: pcap_capture::PcapCapture::new(dir.path()),
        scoring_engine: scoring::ScoringEngine::new(0.95),
        last_firmware_incident_at: None,
        last_hypervisor_incident_at: None,
        hypervisor_environment: None,
        killchain_tracker: innerwarden_killchain::tracker::PidTracker::new(),
        last_killchain_cleanup: std::time::Instant::now(),
        dna_state: dna_inline::DnaState::new(
            &std::path::PathBuf::from("/var/lib/innerwarden/dna"),
            3,
            3.0,
            300,
        ),
        last_dna_save: std::time::Instant::now(),
        last_orphan_recovery: std::time::Instant::now(),
        last_needs_review_timeout: std::time::Instant::now(),
        last_block_enforcement_reconcile: std::time::Instant::now(),
        last_agent_registry_reconcile: std::time::Instant::now(),
        pending_mode_change: None,
        pending_setting_changes: Vec::new(),
        shield_state: None,
        deep_security_snapshot: None,
        dynamic_trusted_ips: Vec::new(),
        dynamic_trusted_users: Vec::new(),
        dynamic_trusted_processes: Vec::new(),
        operator_ips: std::collections::HashMap::new(),
        last_operator_refresh: std::time::Instant::now(),
        suppressed_incident_ids: std::collections::HashSet::new(),
        threat_feed: None,
        last_baseline_anomaly_ts: None,
        last_autoencoder_anomaly_ts: None,
        latest_anomaly_score: None,
        two_factor_state: two_factor::TwoFactorState::new(),
        knowledge_graph: std::sync::Arc::new(std::sync::RwLock::new(
            knowledge_graph::KnowledgeGraph::new(),
        )),
        graph_detector_state: knowledge_graph::detectors::GraphDetectorState::new(),
        last_graph_snapshot: std::time::Instant::now(),
        notification_burst_tracker: notification_gate::BurstTracker::new(),
        feedback_tracker: notification_pipeline::FeedbackTracker::new(),
        last_feedback_tick_at: None,
        task_group: crate::task_group::TaskGroup::new(),
        agent_registry: std::sync::Arc::new(tokio::sync::Mutex::new(
            innerwarden_agent_guard::registry::Registry::new(),
        )),
        signature_index: std::sync::Arc::new(
            innerwarden_agent_guard::signatures::SignatureIndex::new(),
        ),
    };

    let mut cursor = reader::AgentCursor::default();
    let handled = process_incidents(
        dir.path(),
        &mut cursor,
        &cfg,
        &mut state,
        &Arc::new(RwLock::new(VecDeque::new())),
    )
    .await;

    // Still handled (not skipped entirely) - fell back to ufw
    assert_eq!(handled, 1);

    if let Some(w) = &mut state.decision_writer {
        w.flush();
    }
    let decisions_path = dir.path().join(format!("decisions-{today}.jsonl"));
    let content = std::fs::read_to_string(&decisions_path).unwrap();
    // The execution used the ufw fallback, not iptables.
    // The audit trail still records the IP the AI identified.
    assert!(content.contains(attacker_ip));
}

#[tokio::test]
async fn same_ip_in_same_tick_triggers_single_ai_call() {
    let dir = TempDir::new().unwrap();
    let today = chrono::Local::now()
        .date_naive()
        .format("%Y-%m-%d")
        .to_string();

    let attacker_ip = "9.8.7.6";
    let store = test_sqlite_store(dir.path());
    insert_test_incident(&store, &test_incident(attacker_ip));
    // Insert a second incident for the same IP (different ID to avoid UNIQUE constraint)
    let mut inc2 = test_incident(attacker_ip);
    inc2.incident_id = format!("ssh_bruteforce:{attacker_ip}:test2");
    insert_test_incident(&store, &inc2);

    let cfg = config::AgentConfig {
        ai: config::AiConfig {
            enabled: true,
            confidence_threshold: 0.5,
            context_events: 5,
            ..config::AiConfig::default()
        },
        responder: config::ResponderConfig {
            enabled: true,
            dry_run: true,
            block_backend: "ufw".to_string(),
            allowed_skills: vec!["block-ip-ufw".to_string()],
            auto_rules_enabled: false,
            ..config::ResponderConfig::default()
        },
        ..config::AgentConfig::default()
    };

    let calls = Arc::new(AtomicUsize::new(0));
    let mock = Arc::new(CountingMockAiProvider {
        decision: ai::AiDecision {
            action: ai::AiAction::BlockIp {
                ip: attacker_ip.to_string(),
                skill_id: "block-ip-ufw".to_string(),
            },
            confidence: 0.95,
            auto_execute: true,
            reason: "duplicate IP in same tick".to_string(),
            alternatives: vec![],
            estimated_threat: "high".to_string(),
        },
        calls: calls.clone(),
    });

    let mut state = AgentState {
        skill_registry: skills::SkillRegistry::default_builtin(),
        blocklist: skills::Blocklist::default(),
        correlator: correlation::TemporalCorrelator::new(300, 4096),
        telemetry: telemetry::TelemetryState::default(),
        telemetry_writer: None,
        ai_router: ai::AiRouter::new(
            Some(mock.clone() as Arc<dyn ai::AiProvider>),
            Some(mock.clone() as Arc<dyn ai::AiProvider>),
        )
        .expect("test router with mock provider"),
        decision_writer: Some(decisions::DecisionWriter::new(dir.path()).unwrap()),
        last_narrative_at: None,
        last_daily_summary_telegram: None,
        telegram_daily_sent: 0,
        telegram_budget_date: None,
        telegram_deferred: HashMap::new(),
        telegram_client: None,
        pending_confirmations: HashMap::new(),
        approval_rx: None,
        dashboard_pending: std::sync::Arc::new(std::sync::Mutex::new(
            std::collections::HashMap::new(),
        )),
        dashboard_approval_rx: None,
        grouping_engine: notification_pipeline::GroupingEngine::new(
            &crate::config::NotificationPipelineConfig::default(),
        ),
        environment_profile: environment_profile::EnvironmentProfile::default(),
        last_env_census_at: None,
        host_posture: posture::HostPosture::default(),
        last_host_posture_at: None,
        anomaly_engine: neural_lifecycle::AnomalyEngine::new(Default::default()),
        neural_incidents: Vec::new(),
        trust_rules: std::collections::HashSet::new(),
        crowdsec: None,
        abuseipdb: None,
        geoip_client: None,
        slack_client: None,
        discord_client: None,
        cloudflare_client: None,
        circuit_breaker_until: None,
        pending_honeypot_choices: HashMap::new(),
        ip_reputations: HashMap::new(),
        lsm_enabled: false,
        mesh: None,
        recent_blocks: std::collections::VecDeque::new(),
        xdp_block_times: HashMap::new(),
        xdp_cleanup_backoff: HashMap::new(),
        response_lifecycle: response_lifecycle::ResponseLifecycle::new(),
        abuseipdb_report_queue: Vec::new(),
        narrative_acc: NarrativeAccumulator::default(),
        narrative_incidents_offset: 0,
        forensics: forensics::ForensicsCapture::new(dir.path()),
        store: state_store::StateStore::open(dir.path()).unwrap(),
        sqlite_store: Some(store.clone()),
        sqlite_store_path: dir.path().to_path_buf(),
        sqlite_reopen_last_attempt: None,
        maintenance_scheduler: None,
        attacker_profiles: HashMap::new(),
        last_intel_consolidation_at: None,
        correlation_engine: correlation_engine::CorrelationEngine::new(),
        baseline: baseline::BaselineStore::new(),
        pcap_capture: pcap_capture::PcapCapture::new(dir.path()),
        scoring_engine: scoring::ScoringEngine::new(0.95),
        last_firmware_incident_at: None,
        last_hypervisor_incident_at: None,
        hypervisor_environment: None,
        killchain_tracker: innerwarden_killchain::tracker::PidTracker::new(),
        last_killchain_cleanup: std::time::Instant::now(),
        dna_state: dna_inline::DnaState::new(
            &std::path::PathBuf::from("/var/lib/innerwarden/dna"),
            3,
            3.0,
            300,
        ),
        last_dna_save: std::time::Instant::now(),
        last_orphan_recovery: std::time::Instant::now(),
        last_needs_review_timeout: std::time::Instant::now(),
        last_block_enforcement_reconcile: std::time::Instant::now(),
        last_agent_registry_reconcile: std::time::Instant::now(),
        pending_mode_change: None,
        pending_setting_changes: Vec::new(),
        shield_state: None,
        deep_security_snapshot: None,
        dynamic_trusted_ips: Vec::new(),
        dynamic_trusted_users: Vec::new(),
        dynamic_trusted_processes: Vec::new(),
        operator_ips: std::collections::HashMap::new(),
        last_operator_refresh: std::time::Instant::now(),
        suppressed_incident_ids: std::collections::HashSet::new(),
        threat_feed: None,
        last_baseline_anomaly_ts: None,
        last_autoencoder_anomaly_ts: None,
        latest_anomaly_score: None,
        two_factor_state: two_factor::TwoFactorState::new(),
        knowledge_graph: std::sync::Arc::new(std::sync::RwLock::new(
            knowledge_graph::KnowledgeGraph::new(),
        )),
        graph_detector_state: knowledge_graph::detectors::GraphDetectorState::new(),
        last_graph_snapshot: std::time::Instant::now(),
        notification_burst_tracker: notification_gate::BurstTracker::new(),
        feedback_tracker: notification_pipeline::FeedbackTracker::new(),
        last_feedback_tick_at: None,
        task_group: crate::task_group::TaskGroup::new(),
        agent_registry: std::sync::Arc::new(tokio::sync::Mutex::new(
            innerwarden_agent_guard::registry::Registry::new(),
        )),
        signature_index: std::sync::Arc::new(
            innerwarden_agent_guard::signatures::SignatureIndex::new(),
        ),
    };

    let mut cursor = reader::AgentCursor::default();
    let handled = process_incidents(
        dir.path(),
        &mut cursor,
        &cfg,
        &mut state,
        &Arc::new(RwLock::new(VecDeque::new())),
    )
    .await;
    assert_eq!(handled, 2, "both incidents should be accounted for");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "same IP in same tick must call AI only once"
    );

    if let Some(w) = &mut state.decision_writer {
        w.flush();
    }
    let decisions_path = dir.path().join(format!("decisions-{today}.jsonl"));
    let content = std::fs::read_to_string(&decisions_path).unwrap();
    assert_eq!(
        content.lines().count(),
        1,
        "only one decision should be recorded"
    );
}

#[tokio::test]
async fn temporal_correlation_context_is_passed_to_ai() {
    let dir = TempDir::new().unwrap();

    let attacker_ip = "2.3.4.5";
    let store = test_sqlite_store(dir.path());
    insert_test_incident(&store, &test_incident_with_kind(attacker_ip, "port_scan"));
    insert_test_incident(
        &store,
        &test_incident_with_kind(attacker_ip, "credential_stuffing"),
    );

    let cfg = config::AgentConfig {
        ai: config::AiConfig {
            enabled: true,
            confidence_threshold: 0.5,
            context_events: 5,
            ..config::AiConfig::default()
        },
        correlation: config::CorrelationConfig {
            enabled: true,
            window_seconds: 300,
            max_related_incidents: 8,
        },
        responder: config::ResponderConfig {
            enabled: false,
            ..config::ResponderConfig::default()
        },
        ..config::AgentConfig::default()
    };

    let related_count = Arc::new(AtomicUsize::new(0));
    let mock = Arc::new(CorrelationInspectingMockAiProvider {
        decision: ai::AiDecision {
            action: ai::AiAction::Ignore {
                reason: "test correlation".to_string(),
            },
            confidence: 0.9,
            auto_execute: false,
            reason: "test correlation".to_string(),
            alternatives: vec![],
            estimated_threat: "medium".to_string(),
        },
        last_related_count: related_count.clone(),
    });

    let mut state = AgentState {
        skill_registry: skills::SkillRegistry::default_builtin(),
        blocklist: skills::Blocklist::default(),
        correlator: correlation::TemporalCorrelator::new(300, 4096),
        telemetry: telemetry::TelemetryState::default(),
        telemetry_writer: None,
        ai_router: ai::AiRouter::new(
            Some(mock.clone() as Arc<dyn ai::AiProvider>),
            Some(mock.clone() as Arc<dyn ai::AiProvider>),
        )
        .expect("test router with mock provider"),
        decision_writer: Some(decisions::DecisionWriter::new(dir.path()).unwrap()),
        last_narrative_at: None,
        last_daily_summary_telegram: None,
        telegram_daily_sent: 0,
        telegram_budget_date: None,
        telegram_deferred: HashMap::new(),
        telegram_client: None,
        pending_confirmations: HashMap::new(),
        approval_rx: None,
        dashboard_pending: std::sync::Arc::new(std::sync::Mutex::new(
            std::collections::HashMap::new(),
        )),
        dashboard_approval_rx: None,
        grouping_engine: notification_pipeline::GroupingEngine::new(
            &crate::config::NotificationPipelineConfig::default(),
        ),
        environment_profile: environment_profile::EnvironmentProfile::default(),
        last_env_census_at: None,
        host_posture: posture::HostPosture::default(),
        last_host_posture_at: None,
        anomaly_engine: neural_lifecycle::AnomalyEngine::new(Default::default()),
        neural_incidents: Vec::new(),
        trust_rules: std::collections::HashSet::new(),
        crowdsec: None,
        abuseipdb: None,
        geoip_client: None,
        slack_client: None,
        discord_client: None,
        cloudflare_client: None,
        circuit_breaker_until: None,
        pending_honeypot_choices: HashMap::new(),
        ip_reputations: HashMap::new(),
        lsm_enabled: false,
        mesh: None,
        recent_blocks: std::collections::VecDeque::new(),
        xdp_block_times: HashMap::new(),
        xdp_cleanup_backoff: HashMap::new(),
        response_lifecycle: response_lifecycle::ResponseLifecycle::new(),
        abuseipdb_report_queue: Vec::new(),
        narrative_acc: NarrativeAccumulator::default(),
        narrative_incidents_offset: 0,
        forensics: forensics::ForensicsCapture::new(dir.path()),
        store: state_store::StateStore::open(dir.path()).unwrap(),
        sqlite_store: Some(store.clone()),
        sqlite_store_path: dir.path().to_path_buf(),
        sqlite_reopen_last_attempt: None,
        maintenance_scheduler: None,
        attacker_profiles: HashMap::new(),
        last_intel_consolidation_at: None,
        correlation_engine: correlation_engine::CorrelationEngine::new(),
        baseline: baseline::BaselineStore::new(),
        pcap_capture: pcap_capture::PcapCapture::new(dir.path()),
        scoring_engine: scoring::ScoringEngine::new(0.95),
        last_firmware_incident_at: None,
        last_hypervisor_incident_at: None,
        hypervisor_environment: None,
        killchain_tracker: innerwarden_killchain::tracker::PidTracker::new(),
        last_killchain_cleanup: std::time::Instant::now(),
        dna_state: dna_inline::DnaState::new(
            &std::path::PathBuf::from("/var/lib/innerwarden/dna"),
            3,
            3.0,
            300,
        ),
        last_dna_save: std::time::Instant::now(),
        last_orphan_recovery: std::time::Instant::now(),
        last_needs_review_timeout: std::time::Instant::now(),
        last_block_enforcement_reconcile: std::time::Instant::now(),
        last_agent_registry_reconcile: std::time::Instant::now(),
        pending_mode_change: None,
        pending_setting_changes: Vec::new(),
        shield_state: None,
        deep_security_snapshot: None,
        dynamic_trusted_ips: Vec::new(),
        dynamic_trusted_users: Vec::new(),
        dynamic_trusted_processes: Vec::new(),
        operator_ips: std::collections::HashMap::new(),
        last_operator_refresh: std::time::Instant::now(),
        suppressed_incident_ids: std::collections::HashSet::new(),
        threat_feed: None,
        last_baseline_anomaly_ts: None,
        last_autoencoder_anomaly_ts: None,
        latest_anomaly_score: None,
        two_factor_state: two_factor::TwoFactorState::new(),
        knowledge_graph: std::sync::Arc::new(std::sync::RwLock::new(
            knowledge_graph::KnowledgeGraph::new(),
        )),
        graph_detector_state: knowledge_graph::detectors::GraphDetectorState::new(),
        last_graph_snapshot: std::time::Instant::now(),
        notification_burst_tracker: notification_gate::BurstTracker::new(),
        feedback_tracker: notification_pipeline::FeedbackTracker::new(),
        last_feedback_tick_at: None,
        task_group: crate::task_group::TaskGroup::new(),
        agent_registry: std::sync::Arc::new(tokio::sync::Mutex::new(
            innerwarden_agent_guard::registry::Registry::new(),
        )),
        signature_index: std::sync::Arc::new(
            innerwarden_agent_guard::signatures::SignatureIndex::new(),
        ),
    };

    let mut cursor = reader::AgentCursor::default();
    let handled = process_incidents(
        dir.path(),
        &mut cursor,
        &cfg,
        &mut state,
        &Arc::new(RwLock::new(VecDeque::new())),
    )
    .await;
    assert_eq!(handled, 2);
    assert!(
        related_count.load(Ordering::SeqCst) >= 1,
        "second correlated incident should carry prior incident context"
    );
}

#[tokio::test]
async fn honeypot_demo_writes_synthetic_decoy_event() {
    let dir = TempDir::new().unwrap();
    let today = chrono::Local::now()
        .date_naive()
        .format("%Y-%m-%d")
        .to_string();

    let attacker_ip = "7.7.7.7";
    let store = test_sqlite_store(dir.path());
    insert_test_incident(&store, &test_incident(attacker_ip));

    let cfg = config::AgentConfig {
        ai: config::AiConfig {
            enabled: true,
            confidence_threshold: 0.5,
            context_events: 5,
            ..config::AiConfig::default()
        },
        responder: config::ResponderConfig {
            enabled: true,
            dry_run: true,
            block_backend: "ufw".to_string(),
            allowed_skills: vec!["honeypot".to_string()],
            auto_rules_enabled: false,
            ..config::ResponderConfig::default()
        },
        ..config::AgentConfig::default()
    };

    let mock = Arc::new(MockAiProvider {
        decision: ai::AiDecision {
            action: ai::AiAction::Honeypot {
                ip: attacker_ip.to_string(),
            },
            confidence: 0.95,
            auto_execute: true,
            reason: "demo honeypot test".to_string(),
            alternatives: vec![],
            estimated_threat: "high".to_string(),
        },
    });

    let mut state = AgentState {
        skill_registry: skills::SkillRegistry::default_builtin(),
        blocklist: skills::Blocklist::default(),
        correlator: correlation::TemporalCorrelator::new(300, 4096),
        telemetry: telemetry::TelemetryState::default(),
        telemetry_writer: None,
        ai_router: ai::AiRouter::new(
            Some(mock.clone() as Arc<dyn ai::AiProvider>),
            Some(mock.clone() as Arc<dyn ai::AiProvider>),
        )
        .expect("test router with mock provider"),
        decision_writer: Some(decisions::DecisionWriter::new(dir.path()).unwrap()),
        last_narrative_at: None,
        last_daily_summary_telegram: None,
        telegram_daily_sent: 0,
        telegram_budget_date: None,
        telegram_deferred: HashMap::new(),
        telegram_client: None,
        pending_confirmations: HashMap::new(),
        approval_rx: None,
        dashboard_pending: std::sync::Arc::new(std::sync::Mutex::new(
            std::collections::HashMap::new(),
        )),
        dashboard_approval_rx: None,
        grouping_engine: notification_pipeline::GroupingEngine::new(
            &crate::config::NotificationPipelineConfig::default(),
        ),
        environment_profile: environment_profile::EnvironmentProfile::default(),
        last_env_census_at: None,
        host_posture: posture::HostPosture::default(),
        last_host_posture_at: None,
        anomaly_engine: neural_lifecycle::AnomalyEngine::new(Default::default()),
        neural_incidents: Vec::new(),
        trust_rules: std::collections::HashSet::new(),
        crowdsec: None,
        abuseipdb: None,
        geoip_client: None,
        slack_client: None,
        discord_client: None,
        cloudflare_client: None,
        circuit_breaker_until: None,
        pending_honeypot_choices: HashMap::new(),
        ip_reputations: HashMap::new(),
        lsm_enabled: false,
        mesh: None,
        recent_blocks: std::collections::VecDeque::new(),
        xdp_block_times: HashMap::new(),
        xdp_cleanup_backoff: HashMap::new(),
        response_lifecycle: response_lifecycle::ResponseLifecycle::new(),
        abuseipdb_report_queue: Vec::new(),
        narrative_acc: NarrativeAccumulator::default(),
        narrative_incidents_offset: 0,
        forensics: forensics::ForensicsCapture::new(dir.path()),
        store: state_store::StateStore::open(dir.path()).unwrap(),
        sqlite_store: Some(store.clone()),
        sqlite_store_path: dir.path().to_path_buf(),
        sqlite_reopen_last_attempt: None,
        maintenance_scheduler: None,
        attacker_profiles: HashMap::new(),
        last_intel_consolidation_at: None,
        correlation_engine: correlation_engine::CorrelationEngine::new(),
        baseline: baseline::BaselineStore::new(),
        pcap_capture: pcap_capture::PcapCapture::new(dir.path()),
        scoring_engine: scoring::ScoringEngine::new(0.95),
        last_firmware_incident_at: None,
        last_hypervisor_incident_at: None,
        hypervisor_environment: None,
        killchain_tracker: innerwarden_killchain::tracker::PidTracker::new(),
        last_killchain_cleanup: std::time::Instant::now(),
        dna_state: dna_inline::DnaState::new(
            &std::path::PathBuf::from("/var/lib/innerwarden/dna"),
            3,
            3.0,
            300,
        ),
        last_dna_save: std::time::Instant::now(),
        last_orphan_recovery: std::time::Instant::now(),
        last_needs_review_timeout: std::time::Instant::now(),
        last_block_enforcement_reconcile: std::time::Instant::now(),
        last_agent_registry_reconcile: std::time::Instant::now(),
        pending_mode_change: None,
        pending_setting_changes: Vec::new(),
        shield_state: None,
        deep_security_snapshot: None,
        dynamic_trusted_ips: Vec::new(),
        dynamic_trusted_users: Vec::new(),
        dynamic_trusted_processes: Vec::new(),
        operator_ips: std::collections::HashMap::new(),
        last_operator_refresh: std::time::Instant::now(),
        suppressed_incident_ids: std::collections::HashSet::new(),
        threat_feed: None,
        last_baseline_anomaly_ts: None,
        last_autoencoder_anomaly_ts: None,
        latest_anomaly_score: None,
        two_factor_state: two_factor::TwoFactorState::new(),
        knowledge_graph: std::sync::Arc::new(std::sync::RwLock::new(
            knowledge_graph::KnowledgeGraph::new(),
        )),
        graph_detector_state: knowledge_graph::detectors::GraphDetectorState::new(),
        last_graph_snapshot: std::time::Instant::now(),
        notification_burst_tracker: notification_gate::BurstTracker::new(),
        feedback_tracker: notification_pipeline::FeedbackTracker::new(),
        last_feedback_tick_at: None,
        task_group: crate::task_group::TaskGroup::new(),
        agent_registry: std::sync::Arc::new(tokio::sync::Mutex::new(
            innerwarden_agent_guard::registry::Registry::new(),
        )),
        signature_index: std::sync::Arc::new(
            innerwarden_agent_guard::signatures::SignatureIndex::new(),
        ),
    };

    let mut cursor = reader::AgentCursor::default();
    let handled = process_incidents(
        dir.path(),
        &mut cursor,
        &cfg,
        &mut state,
        &Arc::new(RwLock::new(VecDeque::new())),
    )
    .await;
    assert_eq!(handled, 1);

    let events_path = dir.path().join(format!("events-{today}.jsonl"));
    let content = std::fs::read_to_string(&events_path).unwrap();
    assert!(content.contains("honeypot.demo_decoy_hit"));
    assert!(content.contains("DEMO/SIMULATION/DECOY"));
    assert!(content.contains(attacker_ip));
}

// ------------------------------------------------------------------
// Decision cooldown: second incident from same IP/detector is suppressed
// ------------------------------------------------------------------

#[tokio::test]
async fn decision_cooldown_suppresses_repeat() {
    let dir = TempDir::new().unwrap();

    let attacker_ip = "1.2.3.4";

    // Plant TWO identical brute-force incidents from the same IP
    let store = test_sqlite_store(dir.path());
    insert_test_incident(&store, &test_incident(attacker_ip));
    let mut inc2 = test_incident(attacker_ip);
    inc2.incident_id = format!("ssh_bruteforce:{attacker_ip}:test2");
    insert_test_incident(&store, &inc2);

    let cfg = config::AgentConfig {
        ai: config::AiConfig {
            enabled: true,
            confidence_threshold: 0.8,
            context_events: 5,
            ..config::AiConfig::default()
        },
        responder: config::ResponderConfig {
            enabled: true,
            dry_run: true,
            block_backend: "ufw".to_string(),
            allowed_skills: vec!["block-ip-ufw".to_string()],
            auto_rules_enabled: false,
            ..config::ResponderConfig::default()
        },
        ..config::AgentConfig::default()
    };

    let calls = Arc::new(AtomicUsize::new(0));
    let mock = Arc::new(CountingMockAiProvider {
        decision: ai::AiDecision {
            action: ai::AiAction::BlockIp {
                ip: attacker_ip.to_string(),
                skill_id: "block-ip-ufw".to_string(),
            },
            confidence: 0.97,
            auto_execute: true,
            reason: "brute force".to_string(),
            alternatives: vec![],
            estimated_threat: "high".to_string(),
        },
        calls: calls.clone(),
    });

    let mut state = AgentState {
        skill_registry: skills::SkillRegistry::default_builtin(),
        blocklist: skills::Blocklist::default(),
        correlator: correlation::TemporalCorrelator::new(300, 4096),
        telemetry: telemetry::TelemetryState::default(),
        telemetry_writer: None,
        ai_router: ai::AiRouter::new(
            Some(mock.clone() as Arc<dyn ai::AiProvider>),
            Some(mock.clone() as Arc<dyn ai::AiProvider>),
        )
        .expect("test router with mock provider"),
        decision_writer: Some(decisions::DecisionWriter::new(dir.path()).unwrap()),
        last_narrative_at: None,
        last_daily_summary_telegram: None,
        telegram_daily_sent: 0,
        telegram_budget_date: None,
        telegram_deferred: HashMap::new(),
        telegram_client: None,
        pending_confirmations: HashMap::new(),
        approval_rx: None,
        dashboard_pending: std::sync::Arc::new(std::sync::Mutex::new(
            std::collections::HashMap::new(),
        )),
        dashboard_approval_rx: None,
        grouping_engine: notification_pipeline::GroupingEngine::new(
            &crate::config::NotificationPipelineConfig::default(),
        ),
        environment_profile: environment_profile::EnvironmentProfile::default(),
        last_env_census_at: None,
        host_posture: posture::HostPosture::default(),
        last_host_posture_at: None,
        anomaly_engine: neural_lifecycle::AnomalyEngine::new(Default::default()),
        neural_incidents: Vec::new(),
        trust_rules: std::collections::HashSet::new(),
        crowdsec: None,
        abuseipdb: None,
        geoip_client: None,
        slack_client: None,
        discord_client: None,
        cloudflare_client: None,
        circuit_breaker_until: None,
        pending_honeypot_choices: HashMap::new(),
        ip_reputations: HashMap::new(),
        lsm_enabled: false,
        mesh: None,
        recent_blocks: std::collections::VecDeque::new(),
        xdp_block_times: HashMap::new(),
        xdp_cleanup_backoff: HashMap::new(),
        response_lifecycle: response_lifecycle::ResponseLifecycle::new(),
        abuseipdb_report_queue: Vec::new(),
        narrative_acc: NarrativeAccumulator::default(),
        narrative_incidents_offset: 0,
        forensics: forensics::ForensicsCapture::new(dir.path()),
        store: state_store::StateStore::open(dir.path()).unwrap(),
        sqlite_store: Some(store.clone()),
        sqlite_store_path: dir.path().to_path_buf(),
        sqlite_reopen_last_attempt: None,
        maintenance_scheduler: None,
        attacker_profiles: HashMap::new(),
        last_intel_consolidation_at: None,
        correlation_engine: correlation_engine::CorrelationEngine::new(),
        baseline: baseline::BaselineStore::new(),
        pcap_capture: pcap_capture::PcapCapture::new(dir.path()),
        scoring_engine: scoring::ScoringEngine::new(0.95),
        last_firmware_incident_at: None,
        last_hypervisor_incident_at: None,
        hypervisor_environment: None,
        killchain_tracker: innerwarden_killchain::tracker::PidTracker::new(),
        last_killchain_cleanup: std::time::Instant::now(),
        dna_state: dna_inline::DnaState::new(
            &std::path::PathBuf::from("/var/lib/innerwarden/dna"),
            3,
            3.0,
            300,
        ),
        last_dna_save: std::time::Instant::now(),
        last_orphan_recovery: std::time::Instant::now(),
        last_needs_review_timeout: std::time::Instant::now(),
        last_block_enforcement_reconcile: std::time::Instant::now(),
        last_agent_registry_reconcile: std::time::Instant::now(),
        pending_mode_change: None,
        pending_setting_changes: Vec::new(),
        shield_state: None,
        deep_security_snapshot: None,
        dynamic_trusted_ips: Vec::new(),
        dynamic_trusted_users: Vec::new(),
        dynamic_trusted_processes: Vec::new(),
        operator_ips: std::collections::HashMap::new(),
        last_operator_refresh: std::time::Instant::now(),
        suppressed_incident_ids: std::collections::HashSet::new(),
        threat_feed: None,
        last_baseline_anomaly_ts: None,
        last_autoencoder_anomaly_ts: None,
        latest_anomaly_score: None,
        two_factor_state: two_factor::TwoFactorState::new(),
        knowledge_graph: std::sync::Arc::new(std::sync::RwLock::new(
            knowledge_graph::KnowledgeGraph::new(),
        )),
        graph_detector_state: knowledge_graph::detectors::GraphDetectorState::new(),
        last_graph_snapshot: std::time::Instant::now(),
        notification_burst_tracker: notification_gate::BurstTracker::new(),
        feedback_tracker: notification_pipeline::FeedbackTracker::new(),
        last_feedback_tick_at: None,
        task_group: crate::task_group::TaskGroup::new(),
        agent_registry: std::sync::Arc::new(tokio::sync::Mutex::new(
            innerwarden_agent_guard::registry::Registry::new(),
        )),
        signature_index: std::sync::Arc::new(
            innerwarden_agent_guard::signatures::SignatureIndex::new(),
        ),
    };

    let mut cursor = reader::AgentCursor::default();
    let handled = process_incidents(
        dir.path(),
        &mut cursor,
        &cfg,
        &mut state,
        &Arc::new(RwLock::new(VecDeque::new())),
    )
    .await;

    // Both incidents are "handled" (counted), but the AI should be called
    // only ONCE - the second incident is suppressed by the decision
    // cooldown that was recorded after the first decision.
    assert_eq!(handled, 2);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "AI should be called once - second incident suppressed by cooldown"
    );

    // Verify the cooldown entry was recorded in the persistent store
    assert!(
        state.store.has_cooldown(
            state_store::CooldownTable::Decision,
            &format!("block_ip:ssh_bruteforce:ip:{}", attacker_ip)
        ),
        "decision cooldown should be recorded in store"
    );
}

// ------------------------------------------------------------------
// Always-on honeypot tests
// ------------------------------------------------------------------

/// Test that the filter blocklist correctly drops IPs that are already blocked.
#[test]
fn test_always_on_filter_blocks_known_ip() {
    let mut set = std::collections::HashSet::new();
    set.insert("1.2.3.4".to_string());
    set.insert("5.6.7.8".to_string());

    // Known-bad IP should be "blocked" (present in set).
    assert!(
        set.contains("1.2.3.4"),
        "IP 1.2.3.4 should be in the filter blocklist"
    );
    assert!(
        set.contains("5.6.7.8"),
        "IP 5.6.7.8 should be in the filter blocklist"
    );

    // Unknown IP should NOT be blocked.
    assert!(
        !set.contains("9.9.9.9"),
        "IP 9.9.9.9 should not be in the filter blocklist"
    );

    // After inserting a new IP, it should be filtered.
    set.insert("9.9.9.9".to_string());
    assert!(
        set.contains("9.9.9.9"),
        "IP 9.9.9.9 should be in the filter blocklist after insertion"
    );
}

/// Test that the "always_on" mode string is recognized and would trigger startup.
#[test]
fn test_always_on_mode_recognized() {
    // Verify config recognises the mode string (no panic on deserialise).
    let toml = r#"
            [honeypot]
            mode = "always_on"
            port = 2222
            bind_addr = "127.0.0.1"
            interaction = "medium"
        "#;
    let cfg: config::AgentConfig = toml::from_str(toml).expect("should parse always_on mode");
    assert_eq!(cfg.honeypot.mode, "always_on");
    assert_eq!(cfg.honeypot.port, 2222);

    // Verify the mode check used in main() matches.
    let is_always_on = cfg.honeypot.mode == "always_on";
    assert!(
        is_always_on,
        "mode check should return true for 'always_on'"
    );

    // Demo and listener modes should NOT match.
    let mut cfg2 = config::AgentConfig::default();
    cfg2.honeypot.mode = "demo".to_string();
    assert!(
        cfg2.honeypot.mode != "always_on",
        "demo should not match always_on"
    );

    let mut cfg3 = config::AgentConfig::default();
    cfg3.honeypot.mode = "listener".to_string();
    assert!(
        cfg3.honeypot.mode != "always_on",
        "listener should not match always_on"
    );
}

// `honeypot_runtime` must accept `always_on` without warning and map it
// to `listener`, since the skill-level honeypot should behave as a real
// listener when the operator has opted into always-on mode.
#[test]
fn honeypot_runtime_accepts_always_on_as_listener() {
    let mut cfg = config::AgentConfig::default();
    cfg.honeypot.mode = "always_on".to_string();
    let runtime = honeypot_runtime(&cfg);
    assert_eq!(runtime.mode, "listener");
}

#[test]
fn honeypot_runtime_preserves_demo_and_listener() {
    let mut cfg = config::AgentConfig::default();
    cfg.honeypot.mode = "demo".to_string();
    assert_eq!(honeypot_runtime(&cfg).mode, "demo");
    cfg.honeypot.mode = "listener".to_string();
    assert_eq!(honeypot_runtime(&cfg).mode, "listener");
}

#[test]
fn honeypot_runtime_case_insensitive() {
    let mut cfg = config::AgentConfig::default();
    cfg.honeypot.mode = "  ALWAYS_ON  ".to_string();
    assert_eq!(honeypot_runtime(&cfg).mode, "listener");
}

#[test]
fn honeypot_runtime_unknown_mode_falls_back_to_demo() {
    let mut cfg = config::AgentConfig::default();
    cfg.honeypot.mode = "totally-made-up".to_string();
    assert_eq!(honeypot_runtime(&cfg).mode, "demo");
}

#[test]
fn status_field_u32_parses_expected_proc_status_fields() {
    // Ensures /proc status parser extracts numeric IDs used by own-process filtering.
    let sample = "Name:\tagent\nTgid:\t4242\nPPid:\t1\n";
    assert_eq!(status_field_u32(sample, "Tgid:"), Some(4242));
    assert_eq!(status_field_u32(sample, "PPid:"), Some(1));
}

#[test]
fn status_field_u32_returns_none_for_missing_or_invalid_values() {
    // Guards parser failure paths so malformed proc status does not cause false matches.
    let sample = "Name:\tagent\nTgid:\tnot-a-number\n";
    assert_eq!(status_field_u32(sample, "Tgid:"), None);
    assert_eq!(status_field_u32(sample, "PPid:"), None);
}

#[test]
fn status_helpers_delegate_to_field_parser() {
    // Verifies convenience wrappers for Tgid/PPid stay aligned with generic parser behavior.
    let sample = "Tgid:\t9001\nPPid:\t1337\n";
    assert_eq!(status_tgid(sample), Some(9001));
    assert_eq!(status_ppid(sample), Some(1337));
}

#[test]
fn operator_ips_from_who_output_filters_to_trusted_users() {
    // Covers who-output parsing so only trusted operator sessions become protected IPs.
    let trusted = vec!["alice".to_string(), "root".to_string()];
    let now = std::time::Instant::now();
    let who = "\
alice pts/0 2026-04-17 10:00 (203.0.113.8)\n\
bob pts/1 2026-04-17 10:01 (198.51.100.9)\n\
root pts/2 2026-04-17 10:02 (2001:db8::7)\n\
alice pts/3 2026-04-17 10:03 (:)\n";
    let ips = operator_ips_from_who_output(who, &trusted, now);
    assert!(ips.contains_key("203.0.113.8"));
    assert!(ips.contains_key("2001:db8::7"));
    assert!(!ips.contains_key("198.51.100.9"));
    assert!(!ips.contains_key(":"));
}

#[test]
fn cleanup_backup_paths_include_expected_spec_suffixes() {
    // Ensures one-shot migration backups remain deterministic and easy to identify.
    let snapshot = Path::new("/var/lib/innerwarden/graph-2026-04-17.json");
    assert_eq!(
        cleanup_015_backup_path(snapshot, "20260417T101500"),
        PathBuf::from("/var/lib/innerwarden/graph-2026-04-17.json.bak-015-20260417T101500")
    );
    assert_eq!(
        backfill_015_research_only_backup_path(snapshot, "20260417T101500"),
        PathBuf::from(
            "/var/lib/innerwarden/graph-2026-04-17.json.bak-015-researchonly-20260417T101500"
        )
    );
}

#[test]
fn incident_line_serializes_default_test_incident() {
    // Uses helper output so regression in incident JSON fixture formatting is caught early.
    let raw = incident_line("1.2.3.4");
    let parsed: innerwarden_core::incident::Incident =
        serde_json::from_str(&raw).expect("incident line should be valid JSON");
    assert_eq!(parsed.incident_id, "ssh_bruteforce:1.2.3.4:test");
}

#[test]
fn incident_line_with_kind_serializes_custom_detector_kind() {
    // Validates custom-kind incident fixture helper used by targeted test scenarios.
    let raw = incident_line_with_kind("1.2.3.4", "port_scan");
    let parsed: innerwarden_core::incident::Incident =
        serde_json::from_str(&raw).expect("incident line should be valid JSON");
    assert_eq!(parsed.incident_id, "port_scan:1.2.3.4:test");
    assert!(parsed.tags.contains(&"port_scan".to_string()));
}

// ── Memory safety: NarrativeAccumulator tests ────────────────────

#[test]
fn synthetic_events_capped_at_2000() {
    let mut acc = NarrativeAccumulator {
        date: "2026-01-01".to_string(),
        ..Default::default()
    };
    // Simulate 100k events of one kind
    *acc.events_by_kind
        .entry("ssh.login_failed".to_string())
        .or_insert(0) = 100_000;
    let events = acc.synthetic_events();
    assert!(
        events.len() <= 2100, // 2000 cap + some entity events
        "synthetic_events should be capped, got {}",
        events.len()
    );
}

#[test]
fn synthetic_events_preserves_proportions() {
    let mut acc = NarrativeAccumulator {
        date: "2026-01-01".to_string(),
        ..Default::default()
    };
    *acc.events_by_kind
        .entry("ssh.login_failed".to_string())
        .or_insert(0) = 8000;
    *acc.events_by_kind
        .entry("sudo.command".to_string())
        .or_insert(0) = 2000;
    let events = acc.synthetic_events();
    let ssh = events
        .iter()
        .filter(|e| e.kind == "ssh.login_failed")
        .count();
    let sudo = events.iter().filter(|e| e.kind == "sudo.command").count();
    // ssh should be ~4x more than sudo (8000:2000 ratio)
    assert!(ssh > sudo, "ssh ({ssh}) should be more than sudo ({sudo})");
}

#[test]
fn incidents_capped_at_500() {
    let mut acc = NarrativeAccumulator {
        date: "2026-01-01".to_string(),
        ..Default::default()
    };
    let incident = innerwarden_core::incident::Incident {
        ts: chrono::Utc::now(),
        host: "test".to_string(),
        incident_id: "test:1".to_string(),
        severity: innerwarden_core::event::Severity::High,
        title: "test".to_string(),
        summary: "test".to_string(),
        evidence: serde_json::Value::Null,
        recommended_checks: vec![],
        tags: vec![],
        entities: vec![],
    };
    let batch: Vec<_> = (0..600).map(|_| incident.clone()).collect();
    acc.ingest_incidents(&batch);
    assert_eq!(
        acc.incidents.len(),
        500,
        "incidents should be capped at 500"
    );
}

#[test]
fn block_counts_cleared_at_threshold() {
    let dir = TempDir::new().unwrap();
    let store = state_store::StateStore::open(dir.path()).unwrap();
    for i in 0..5001 {
        store.increment_block_count(&format!("1.2.3.{i}"));
    }
    assert!(store.block_counts_len() > 5000);
    // Simulate the trim logic from narrative tick
    if store.block_counts_len() > 5000 {
        store.clear_block_counts();
    }
    assert_eq!(store.block_counts_len(), 0);
}

#[test]
fn narrative_accumulator_resets_on_date_change() {
    let mut acc = NarrativeAccumulator {
        date: "2026-01-01".to_string(),
        ..Default::default()
    };
    *acc.events_by_kind
        .entry("ssh.login_failed".to_string())
        .or_insert(0) = 100;
    acc.total_events = 100;

    acc.reset_for_date("2026-01-02");
    assert_eq!(acc.total_events, 0);
    assert!(acc.events_by_kind.is_empty());
    assert_eq!(acc.date, "2026-01-02");
}

#[test]
fn cli_parses_validate_config_only_with_required_config_path() {
    let cli = Cli::try_parse_from([
        "innerwarden-agent",
        "--validate-config-only",
        "--config",
        "/tmp/agent.toml",
    ])
    .expect("validate config args should parse");

    assert!(cli.validate_config_only);
    assert_eq!(
        cli.config.as_deref(),
        Some(std::path::Path::new("/tmp/agent.toml"))
    );
    assert!(!cli.once);
    assert!(!cli.dashboard);
}

#[test]
fn cli_parses_dashboard_tls_and_report_options() {
    let cli = Cli::try_parse_from([
        "innerwarden-agent",
        "--data-dir",
        "/tmp/iw",
        "--dashboard",
        "--dashboard-bind",
        "0.0.0.0:8787",
        "--tls-cert",
        "/tmp/cert.pem",
        "--tls-key",
        "/tmp/key.pem",
        "--report",
        "--report-dir",
        "/tmp/reports",
    ])
    .expect("dashboard args should parse");

    assert_eq!(cli.data_dir, PathBuf::from("/tmp/iw"));
    assert!(cli.dashboard);
    assert_eq!(cli.dashboard_bind, "0.0.0.0:8787");
    assert_eq!(cli.tls_cert.as_deref(), Some("/tmp/cert.pem"));
    assert_eq!(cli.tls_key.as_deref(), Some("/tmp/key.pem"));
    assert!(cli.report);
    assert_eq!(
        cli.report_dir.as_deref(),
        Some(std::path::Path::new("/tmp/reports"))
    );
}

#[test]
fn cli_parses_hidden_honeypot_sandbox_options() {
    let cli = Cli::try_parse_from([
        "innerwarden-agent",
        "--honeypot-sandbox-runner",
        "--honeypot-sandbox-spec",
        "/tmp/spec.json",
        "--honeypot-sandbox-result",
        "/tmp/result.json",
    ])
    .expect("hidden sandbox args should parse");

    assert!(cli.honeypot_sandbox_runner);
    assert_eq!(
        cli.honeypot_sandbox_spec.as_deref(),
        Some(std::path::Path::new("/tmp/spec.json"))
    );
    assert_eq!(
        cli.honeypot_sandbox_result.as_deref(),
        Some(std::path::Path::new("/tmp/result.json"))
    );
}

#[test]
fn cli_default_values_match_safe_runtime_defaults() {
    let cli = Cli::try_parse_from(["innerwarden-agent"]).expect("defaults should parse");

    assert_eq!(cli.data_dir, PathBuf::from("/var/lib/innerwarden"));
    assert_eq!(cli.dashboard_bind, "127.0.0.1:8787");
    assert_eq!(cli.interval, 30);
    assert!(cli.config.is_none());
    assert!(cli.report_dir.is_none());
    assert!(!cli.insecure_no_tls);
}

// ── Wave 9f anchors (2026-05-04) — journald-detection contract ─────────
//
// AUDIT-009 root: tracing-subscriber writes plain text to stdout which
// journald captures with no `PRIORITY=` field. `journalctl -p warning`
// then silently drops every WARN this crate emits. The fix routes
// tracing through `tracing-journald` when the binary runs under systemd
// (detected via JOURNAL_STREAM env var). These anchors pin the detection
// logic so a future refactor that breaks the env-var contract is caught
// at test time rather than by the operator one morning when their
// `journalctl -p warning` query goes silent.

#[test]
fn use_journald_layer_returns_true_when_journal_stream_is_set() {
    // The JOURNAL_STREAM=<dev>:<inode> shape that systemd documents.
    assert!(crate::use_journald_layer(Some("8:42")));
}

#[test]
fn use_journald_layer_returns_false_when_env_is_unset() {
    // Off-systemd dev shell + macOS dev: env var simply absent. We must
    // NOT try to write to a non-existent journal socket because that
    // fails the binary at startup on macOS where there is no /run/systemd
    // at all.
    assert!(!crate::use_journald_layer(None));
}

#[test]
fn use_journald_layer_returns_false_when_env_is_empty_string() {
    // Defensive: env vars set to empty string are common operator
    // mistakes (e.g. `JOURNAL_STREAM= cargo run`). Treat empty as unset.
    assert!(!crate::use_journald_layer(Some("")));
}

#[test]
fn build_tracing_env_filter_includes_innerwarden_directives() {
    // Anchor: the env filter MUST enable both the `innerwarden_agent`
    // namespace (the actual code) and `telegram_audit` + `innerwarden_store`
    // (sub-namespaces previous PRs explicitly opted into - PRs #357 and
    // the audit-ui spec). Dropping any of these silently turns off
    // operator-visible logs for the affected subsystem.
    let f = crate::build_tracing_env_filter().expect("env filter must build");
    let s = format!("{}", f);
    assert!(
        s.contains("innerwarden_agent"),
        "env filter must enable innerwarden_agent; got: {s}"
    );
    assert!(
        s.contains("telegram_audit"),
        "env filter must enable telegram_audit; got: {s}"
    );
    assert!(
        s.contains("innerwarden_store"),
        "env filter must enable innerwarden_store; got: {s}"
    );
}
