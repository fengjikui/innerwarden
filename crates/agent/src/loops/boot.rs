use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Instant;

use anyhow::{Context, Result};
use chrono::{Datelike as _, Timelike as _};
use tracing::{info, warn};

use crate::dashboard::AdvisoryEntry;
use crate::*;

// ---------------------------------------------------------------------------
// Spec 015: one-shot cleanup of graph_user_creation false positives and
// brute-force User node pollution. Invoked via
// `innerwarden-agent --cleanup-015-graph-signal-quality`. Non-destructive
// outside that flag: the function below loads today's dated snapshot,
// writes a timestamped backup, applies the migration, and saves the result.
// ---------------------------------------------------------------------------
pub(crate) fn run_cleanup_015(data_dir: &std::path::Path) -> Result<()> {
    use chrono::Local;
    use std::fs;

    let snapshot_path = knowledge_graph::KnowledgeGraph::dated_snapshot_path(data_dir);
    if !snapshot_path.exists() {
        anyhow::bail!(
            "No dated snapshot found at {} — run the agent at least once first",
            snapshot_path.display()
        );
    }

    // Backup the raw snapshot bytes before touching anything, so the
    // operator can always roll back if the migration does something
    // unexpected. Name it with a timestamp so repeated runs don't clobber.
    let stamp = Local::now().format("%Y%m%dT%H%M%S");
    let backup_path = cleanup_015_backup_path(&snapshot_path, &stamp.to_string());
    fs::copy(&snapshot_path, &backup_path)
        .with_context(|| format!("failed to back up snapshot to {}", backup_path.display()))?;
    println!(
        "spec 015 cleanup: backed up snapshot to {}",
        backup_path.display()
    );

    // Load, mutate, save.
    let mut graph = knowledge_graph::KnowledgeGraph::load_snapshot(&snapshot_path);
    let report = knowledge_graph::migrations::cleanup_015_graph_signal_quality(&mut graph);
    graph.save_snapshot(&snapshot_path).with_context(|| {
        format!(
            "failed to save cleaned snapshot to {}",
            snapshot_path.display()
        )
    })?;

    println!("spec 015 cleanup complete:");
    println!("  snapshot             : {}", snapshot_path.display());
    println!("  backup               : {}", backup_path.display());
    println!("  nodes before         : {}", report.nodes_before);
    println!("  nodes after          : {}", report.nodes_after);
    println!(
        "  graph_user_creation  : {} incident node(s) removed",
        report.graph_user_creation_incidents_removed
    );
    println!(
        "  brute-force users    : {} User node(s) removed",
        report.brute_force_user_nodes_removed
    );
    if !report.removed_user_names.is_empty() {
        println!("  removed users        : (names redacted)");
    }
    Ok(())
}

pub(crate) fn run_backfill_015_research_only(data_dir: &std::path::Path) -> Result<()> {
    use chrono::Local;
    use std::fs;

    cloud_safelist::init();

    let snapshot_path = knowledge_graph::KnowledgeGraph::dated_snapshot_path(data_dir);
    if !snapshot_path.exists() {
        anyhow::bail!(
            "No dated snapshot found at {} — run the agent at least once first",
            snapshot_path.display()
        );
    }

    let stamp = Local::now().format("%Y%m%dT%H%M%S");
    let backup_path = backfill_015_research_only_backup_path(&snapshot_path, &stamp.to_string());
    fs::copy(&snapshot_path, &backup_path)
        .with_context(|| format!("failed to back up snapshot to {}", backup_path.display()))?;
    println!(
        "spec 015 research-only backfill: backed up snapshot to {}",
        backup_path.display()
    );

    let mut graph = knowledge_graph::KnowledgeGraph::load_snapshot(&snapshot_path);
    let report = knowledge_graph::migrations::backfill_research_only_flag(&mut graph);
    graph.save_snapshot(&snapshot_path).with_context(|| {
        format!(
            "failed to save cleaned snapshot to {}",
            snapshot_path.display()
        )
    })?;

    println!("spec 015 research-only backfill complete:");
    println!("  snapshot       : {}", snapshot_path.display());
    println!("  backup         : {}", backup_path.display());
    println!("  scanned        : {}", report.incidents_scanned);
    println!("  flagged        : {}", report.incidents_flagged);
    if !report.by_detector.is_empty() {
        println!("  by detector    :");
        let mut top: Vec<(&String, &usize)> = report.by_detector.iter().collect();
        top.sort_by(|a, b| b.1.cmp(a.1));
        for (det, n) in top.iter().take(15) {
            println!("    {det:<28} {n}");
        }
    }
    Ok(())
}
/// One-shot: force the nightly autoencoder training run to happen now.
/// Invoked via `innerwarden-agent --retrain-anomaly`. Reads events from
/// `innerwarden.db`, trains, saves `anomaly-model.bin`, and prints the
/// resulting baseline so the operator can check that scores will diversify.
pub(crate) fn run_retrain_anomaly(cli: &crate::Cli) -> Result<()> {
    let sqlite_store: Option<std::sync::Arc<innerwarden_store::Store>> =
        match innerwarden_store::Store::open(&cli.data_dir) {
            Ok(s) => {
                info!(
                    path = %cli.data_dir.join("innerwarden.db").display(),
                    "sqlite store opened for retrain"
                );
                Some(std::sync::Arc::new(s))
            }
            Err(e) => {
                warn!("sqlite store unavailable: {e:#} — falling back to JSONL scan");
                None
            }
        };

    let config = neural_lifecycle::AnomalyConfig {
        data_dir: cli.data_dir.clone(),
        ..neural_lifecycle::AnomalyConfig::default()
    };

    let mut engine = neural_lifecycle::AnomalyEngine::new(config);
    engine
        .train_nightly_with_store(sqlite_store.as_deref())
        .map_err(|e| anyhow::anyhow!("autoencoder training failed: {e}"))?;

    println!("autoencoder retrain complete:");
    println!("  maturity       : {:.2}", engine.maturity);
    println!("  cycles         : {}", engine.training_cycles);
    println!(
        "  model saved    : {}",
        cli.data_dir.join("anomaly-model.bin").display()
    );
    println!(
        "  previous       : {} (rotated)",
        cli.data_dir.join("anomaly-model.prev.bin").display()
    );
    Ok(())
}

/// Offline autoencoder backtest (`innerwarden-agent --backtest-anomaly`).
/// Reads events + decisions from the data dir, splits at the cutoff, and prints
/// whether the host-anomaly score separates real (acted) incidents from
/// dismissed (FP) ones. See `neural_lifecycle::run_anomaly_backtest`.
pub(crate) fn run_backtest_anomaly(cli: &crate::Cli) -> Result<()> {
    let store = innerwarden_store::Store::open(&cli.data_dir)
        .map_err(|e| anyhow::anyhow!("open store: {e:#}"))?;

    // Events → BacktestEvent (ts, kind, identity tokens for novelty detection).
    let rows = store
        .events_since(0, 5_000_000)
        .map_err(|e| anyhow::anyhow!("read events: {e:#}"))?;
    let mut events: Vec<neural_lifecycle::BacktestEvent> = rows
        .into_iter()
        .map(|(_, e)| {
            let mut tokens = Vec::new();
            let d = &e.details;
            let comm = d.get("comm").and_then(|v| v.as_str());
            if let Some(c) = comm {
                tokens.push(format!("comm:{c}"));
            }
            if let Some(dst) = d
                .get("dst_ip")
                .or_else(|| d.get("src_ip"))
                .and_then(|v| v.as_str())
            {
                tokens.push(format!("dst:{dst}"));
            }
            if let (Some(pc), Some(c)) = (d.get("parent_comm").and_then(|v| v.as_str()), comm) {
                tokens.push(format!("lin:{pc}>{c}"));
            }
            neural_lifecycle::BacktestEvent::new(e.ts, &e.kind, tokens)
        })
        .collect();
    events.sort_by_key(|e| e.ts);
    if events.len() < 200 {
        anyhow::bail!("only {} events in store — need more history", events.len());
    }

    // Decisions: (ts, action_type) from every decisions-*.jsonl.
    let mut decisions: Vec<(chrono::DateTime<chrono::Utc>, String)> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&cli.data_dir) {
        for entry in rd.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.starts_with("decisions-") || !name.ends_with(".jsonl") {
                continue;
            }
            let Ok(content) = std::fs::read_to_string(entry.path()) else {
                continue;
            };
            for line in content.lines() {
                let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                    continue;
                };
                let (Some(ts), Some(action)) = (
                    v.get("ts").and_then(|x| x.as_str()),
                    v.get("action_type").and_then(|x| x.as_str()),
                ) else {
                    continue;
                };
                if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(ts) {
                    decisions.push((dt.with_timezone(&chrono::Utc), action.to_string()));
                }
            }
        }
    }

    // Cutoff: explicit `--backtest-cutoff YYYY-MM-DD`, else 70% of the event
    // time-span (70% train / 30% held-out scoring).
    let (min_ts, max_ts) = (events.first().unwrap().ts, events.last().unwrap().ts);
    let cutoff = match cli.backtest_cutoff.as_deref() {
        Some(d) => chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d")
            .map_err(|e| anyhow::anyhow!("bad --backtest-cutoff: {e}"))?
            .and_hms_opt(0, 0, 0)
            .unwrap()
            .and_utc(),
        None => min_ts + (max_ts - min_ts) * 7 / 10,
    };

    println!("=== autoencoder backtest ===");
    println!(
        "  events           : {} ({}  ..  {})",
        events.len(),
        min_ts.format("%Y-%m-%d %H:%M"),
        max_ts.format("%Y-%m-%d %H:%M")
    );
    println!("  cutoff           : {}", cutoff.to_rfc3339());

    // Run BOTH variants so the novelty feature's effect is directly comparable.
    for use_novelty in [false, true] {
        let report =
            neural_lifecycle::run_anomaly_backtest(&events, &decisions, cutoff, use_novelty)
                .map_err(|e| anyhow::anyhow!("backtest: {e}"))?;
        let label = if use_novelty {
            "WITH novelty features"
        } else {
            "plain (event-kind only)"
        };
        println!("\n  --- {label} ---");
        println!(
            "  train/scored windows : {} / {}",
            report.train_windows, report.scored_windows
        );
        let sep = report.real_mean_score - report.fp_mean_score;
        println!(
            "  decision sep         : real {:.3} vs FP {:.3}  = {sep:+.3} ({})",
            report.real_mean_score,
            report.fp_mean_score,
            if sep.abs() <= 0.03 {
                "flat"
            } else if sep > 0.0 {
                "real higher"
            } else {
                "inverted"
            }
        );
        // The guard-dog metric: do the LOUDEST barks point at genuine novelty?
        let nov_sep = report.novelty_mean_score - report.seen_mean_score;
        println!(
            "  novelty windows      : {} of {} scored ({:.1}%)",
            report.novelty_windows,
            report.scored_windows,
            100.0 * report.novelty_windows as f64 / report.scored_windows.max(1) as f64
        );
        println!(
            "  novelty vs seen score: novel {:.3} vs seen {:.3} = {nov_sep:+.3} ({})",
            report.novelty_mean_score,
            report.seen_mean_score,
            if nov_sep > 0.05 {
                "BARKS LOUDER on novelty — guard-dog signal"
            } else if nov_sep.abs() <= 0.05 {
                "flat — novelty doesn't bark louder"
            } else {
                "inverted"
            }
        );
        let base_rate = 100.0 * report.novelty_windows as f64 / report.scored_windows.max(1) as f64;
        let top_rate =
            100.0 * report.top1pct_on_novelty as f64 / report.top1pct_count.max(1) as f64;
        println!(
            "  top-1% loudest barks : {} of {} are on novel windows ({:.1}% vs {:.1}% base rate — {})",
            report.top1pct_on_novelty,
            report.top1pct_count,
            top_rate,
            base_rate,
            if top_rate > base_rate * 1.5 {
                "concentrated on novelty ✓"
            } else {
                "no better than chance"
            }
        );
    }
    Ok(())
}

pub(crate) fn cleanup_015_backup_path(snapshot_path: &Path, stamp: &str) -> PathBuf {
    snapshot_path.with_extension(format!("json.bak-015-{stamp}"))
}

pub(crate) fn backfill_015_research_only_backup_path(snapshot_path: &Path, stamp: &str) -> PathBuf {
    snapshot_path.with_extension(format!("json.bak-015-researchonly-{stamp}"))
}

/// Build the primary AI provider used for the spec-029 capability
/// router. Three branches:
/// - `enabled = false` → `None` (rules-only mode)
/// - `enabled = true`, build succeeds → `Some(Arc<dyn AiProvider>)`
/// - `enabled = true`, build fails → log warning, `None`
///
/// Extracted from `run_agent` so the branch logic is reachable from a
/// unit test without spinning up the agent loop.
pub(crate) fn build_primary_provider(
    ai_cfg: &crate::config::AiConfig,
    block_backend: &str,
) -> Option<Arc<dyn ai::AiProvider>> {
    if !ai_cfg.enabled {
        return None;
    }
    match ai::build_provider(ai_cfg, block_backend) {
        Ok(p) => Some(Arc::from(p)),
        Err(e) => {
            warn!("failed to create AI provider: {e:#}");
            None
        }
    }
}

/// Deadline the agent allows registered tasks to drain when a SIGTERM
/// or SIGINT arrives. Long-lived tasks (the Telegram polling loop
/// today; firmware alerts and honeypot listener in follow-up PRs)
/// observe `state.task_group.token().cancelled()` and are expected to
/// exit promptly; fire-and-forget tasks (Telegram alert HTTP calls)
/// run to completion or get counted as timed-out in the
/// `ShutdownReport`. 5 seconds is the conventional window — long
/// enough for a single HTTP round-trip, short enough that an
/// unresponsive agent does not delay operator-initiated restarts.
const GRACEFUL_SHUTDOWN_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

/// Pure decision helper for the slow-loop's "every N seconds, only if
/// there is something to consolidate" pattern. Extracted from the
/// inline `should_consolidate = ... && !state.attacker_profiles.is_empty()`
/// expression at the slow-loop tick body so the time + state interaction
/// is unit-testable without spinning up the full agent.
///
/// Returns true when:
/// - The interval has elapsed since the last tick (or no tick has run yet), AND
/// - There is something to consolidate (the state is non-empty).
///
/// Pre-extraction every refactor of the slow-loop tick block had to
/// re-derive this two-condition gate at every call site. The pure
/// helper pins the contract: skipping the second condition would
/// schedule pointless empty consolidation work; skipping the first
/// would consolidate every tick.
pub(crate) fn should_run_periodic_tick(
    last_run_at: Option<std::time::Instant>,
    interval_secs: u64,
    has_work: bool,
) -> bool {
    let due = last_run_at
        .map(|t| t.elapsed().as_secs() >= interval_secs)
        .unwrap_or(true);
    due && has_work
}

/// Cap on how many `incidents` rows the boot-time replay walks. A real
/// production day stays below 10k rows; the cap is loose enough that no
/// honest workload ever truncates and tight enough that a pathological
/// runaway day cannot pin agent startup.
pub(crate) const MAX_BOOT_REPLAY: usize = 100_000;

/// Spec 049 PR18 — replay today's `incidents` rows into the in-memory
/// `KnowledgeGraph` at boot.
///
/// **Why this exists.** KG hydration on boot is snapshot-based. The
/// snapshot cadence is "periodic" — at best minutes old, at worst a
/// full day old when the operator deploys a new release before the
/// daily snapshot has captured the day. Anything the sensor wrote to
/// the `incidents` table between the last snapshot and the restart is
/// in the canonical store but absent from the in-memory KG. The
/// dashboard's Cases panel reads `nodes_of_type(Incident)` off the
/// KG, so post-restart it silently shrinks even though the audit
/// trail in SQLite is intact.
///
/// Operator-reported on 2026-05-13: after two same-day agent restarts
/// (PR15 deploy 11:08 UTC, PR16 deploy 12:11 UTC) the dashboard
/// showed only the post-12:14 slice of the day (141 KG Incident
/// nodes vs 535 SQLite rows). The block of `31.14.254.81` at
/// 12:30:36 was correctly persisted to SQLite but harder to find on
/// the dashboard than it should have been because the surrounding
/// context had been wiped by the snapshot-hydration cycle.
///
/// **Contract.** Query every `incidents` row whose `ts` is at or
/// after the start of `now`'s calendar day (UTC), bounded by
/// `MAX_BOOT_REPLAY`, and re-ingest each into the graph via
/// `ingest_incident`. The ingest is idempotent on `incident_id` (via
/// `upsert_node`) so rows the snapshot already covered are no-ops;
/// rows it missed get added. Errors from the store query are logged
/// and swallowed — a degraded boot (partial KG) is better than a
/// failed boot.
///
/// `now` is taken as a parameter (instead of called via
/// `Utc::now()`) so unit tests can pin the boundary deterministically.
pub(crate) fn replay_todays_incidents(
    store: &innerwarden_store::Store,
    graph: &mut crate::knowledge_graph::KnowledgeGraph,
    now: chrono::DateTime<chrono::Utc>,
) {
    let start_of_day_utc = now
        .date_naive()
        .and_hms_opt(0, 0, 0)
        .expect("00:00:00 is a valid time")
        .and_utc();
    let start_ts = start_of_day_utc.to_rfc3339();
    match store.incidents_since_ts(&start_ts, MAX_BOOT_REPLAY) {
        Ok(today_incidents) => {
            let before = graph.metrics().incident_nodes;
            for inc in &today_incidents {
                graph.ingest_incident(inc);
            }
            let after = graph.metrics().incident_nodes;
            tracing::info!(
                sqlite_rows = today_incidents.len(),
                kg_incidents_before = before,
                kg_incidents_after = after,
                "boot: replayed today's incidents into KG"
            );
        }
        Err(e) => tracing::warn!(
            error = %e,
            "boot: failed to replay today's incidents — KG will reflect only the snapshot"
        ),
    }
}

/// Decide how to surface a `ShutdownReport` to the operator log. Pure
/// function so the emit-level contract is unit-testable without a
/// tracing subscriber harness (see spec 036 PR-3 tests below).
fn summarize_shutdown(report: crate::task_group::ShutdownReport) -> (tracing::Level, String) {
    if report.timed_out > 0 {
        (
            tracing::Level::WARN,
            format!(
                "task_group shutdown abandoned {} of {} task(s) past deadline (joined: {}, deadline: {:?})",
                report.timed_out, report.total, report.joined, GRACEFUL_SHUTDOWN_DEADLINE
            ),
        )
    } else {
        (
            tracing::Level::INFO,
            format!(
                "task_group shutdown drained {} task(s) cleanly",
                report.joined
            ),
        )
    }
}

/// Emit `summarize_shutdown`'s verdict at the chosen level. Split out
/// from the summary builder because `tracing::event!` cannot take a
/// runtime Level — it expands at macro time — so the dispatch has to
/// live at the call site.
fn log_shutdown_report(report: crate::task_group::ShutdownReport) {
    let (level, msg) = summarize_shutdown(report);
    match level {
        tracing::Level::WARN => tracing::warn!("{}", msg),
        _ => tracing::info!("{}", msg),
    }
}

pub(crate) async fn run_agent(cli: crate::Cli) -> Result<()> {
    if cli.dashboard_generate_password_hash {
        dashboard::generate_password_hash_interactive()?;
        return Ok(());
    }

    if cli.honeypot_sandbox_runner {
        let spec = cli
            .honeypot_sandbox_spec
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("missing --honeypot-sandbox-spec"))?;
        let result = cli
            .honeypot_sandbox_result
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("missing --honeypot-sandbox-result"))?;
        skills::builtin::run_honeypot_sandbox_worker(spec, result).await?;
        return Ok(());
    }

    if cli.cleanup_015_graph_signal_quality {
        return run_cleanup_015(&cli.data_dir);
    }

    if cli.backfill_015_research_only {
        return run_backfill_015_research_only(&cli.data_dir);
    }

    if cli.retrain_anomaly {
        return run_retrain_anomaly(&cli);
    }

    if cli.backtest_anomaly {
        return run_backtest_anomaly(&cli);
    }

    if cli.report {
        let out_dir = cli.report_dir.as_deref().unwrap_or(&cli.data_dir);
        if let Some(d) = cli.report_dir.as_deref() {
            std::fs::create_dir_all(d)
                .with_context(|| format!("failed to create report-dir {}", d.display()))?;
        }
        let out = report::generate(&cli.data_dir, out_dir)?;
        info!(
            analyzed_date = %out.report.analyzed_date,
            markdown = %out.markdown_path.display(),
            json = %out.json_path.display(),
            "trial report generated"
        );
        println!(
            "Trial report generated:\n  {}\n  {}",
            out.markdown_path.display(),
            out.json_path.display()
        );
        return Ok(());
    }

    // Load config (optional - all fields have sensible defaults).
    // Done before dashboard check so action config can be wired in.
    // `mut` so the Telegram `/mode` command can flip the responder guardian
    // mode live (applied to this owned cfg in the main loop, then persisted).
    // Mutating cfg in place keeps it the single source of truth for every
    // downstream `cfg.responder.*` enforcement read (no per-site override).
    let mut cfg = match &cli.config {
        Some(path) => config::load(path)?,
        None => config::AgentConfig::default(),
    };

    // Validate Telegram config early to fail fast on misconfiguration
    cfg.telegram.validate()?;
    // Validate [ai.shadow] (sample_rate range etc.) — same fail-fast
    // philosophy. After RESULTS_V3 (2026-05-11) operators may set
    // `sample_rate = 0.1` to keep a drift sample at 1/10 cost; a
    // typo'd `1.1` or `-0.5` must error at startup, not silently clamp.
    cfg.ai.shadow.validate()?;

    // Initialize cloud provider IP safelist (Google, AWS, Azure, Cloudflare, etc.)
    cloud_safelist::init();
    // Operator's own-infrastructure IPs (config-driven, empty by default): the
    // operator's other boxes seen as a remote source are self-traffic, so they
    // stay out of the operator + public feeds while detection continues.
    cloud_safelist::init_operator_self_infra(&cfg.allowlist.self_infra_ips);

    // Deep security snapshot: shared between agent (updates) and dashboard (reads).
    let deep_security_snapshot = std::sync::Arc::new(std::sync::RwLock::new(
        dashboard::DeepSecuritySnapshot::default(),
    ));

    // Open SQLite store early so the graph can try loading from it.
    // Wrapped in Arc so it can be shared with the dashboard task.
    let sqlite_store: Option<Arc<innerwarden_store::Store>> =
        match innerwarden_store::Store::open(&cli.data_dir) {
            Ok(s) => {
                info!(path = %cli.data_dir.join("innerwarden.db").display(), "sqlite store opened");
                Some(Arc::new(s))
            }
            Err(e) => {
                warn!("sqlite store unavailable: {e:#}");
                None
            }
        };

    // One-time migration from legacy files (JSONL + JSON → SQLite)
    if let Some(ref sq) = sqlite_store {
        if innerwarden_store::Store::has_legacy_files(&cli.data_dir) {
            match sq.migrate_from_legacy(&cli.data_dir) {
                Ok(report) => info!("legacy migration done: {report}"),
                Err(e) => warn!("legacy migration failed: {e:#}"),
            }
        }
    }

    // Shared knowledge graph: try SQLite store first, fall back to file-based dated snapshot.
    let shared_graph = std::sync::Arc::new(std::sync::RwLock::new({
        let from_store = sqlite_store
            .as_deref()
            .and_then(knowledge_graph::KnowledgeGraph::load_from_store);
        if let Some(g) = from_store {
            g
        } else {
            knowledge_graph::KnowledgeGraph::load_today_snapshot(&cli.data_dir)
        }
    }));

    // Spec 049 PR18 — boot-time replay of today's incidents.
    // See `replay_todays_incidents` doc for the operator-facing
    // rationale and the failure mode this closes.
    if let Some(store) = sqlite_store.as_deref() {
        let mut g = shared_graph.write().unwrap();
        replay_todays_incidents(store, &mut g, chrono::Utc::now());
    }

    // Advisory cache: shared between dashboard (writes advisory denials) and
    // the incident processing loop (checks for advisory violations).
    let advisory_cache: Arc<RwLock<VecDeque<AdvisoryEntry>>> =
        Arc::new(RwLock::new(VecDeque::new()));

    // Agent-guard snitch alert channel. Created before the dashboard block
    // so the receiver can be used in the dispatch task spawned later.
    let (agent_alert_tx, mut agent_alert_rx) =
        tokio::sync::mpsc::channel::<dashboard::AgentGuardAlert>(64);

    // Spec 081 — managed-agent coexistence. Build the agent-guard registry ONCE
    // here and share the SAME `Arc<Mutex<Registry>>` between the dashboard (which
    // mutates it via `agent connect`) and the main agent loop's response-side
    // `managed_agent_guard` verifier (kernel PID-block + userspace IP-block). The
    // registry rehydrates from the on-disk snapshot so a watchdog binary swap
    // does not drop operator-vouched agents (missing snapshot = empty registry,
    // corrupt = warn + empty). Built unconditionally because `AgentState` always
    // needs it, even when the dashboard task is disabled.
    let agent_registry: Arc<tokio::sync::Mutex<innerwarden_agent_guard::registry::Registry>> = {
        let snapshot_path = cli.data_dir.join("agent-guard-registry.json");
        let reg = match innerwarden_agent_guard::registry::Registry::restore_from(&snapshot_path) {
            Ok(reg) => {
                if reg.count_total() > 0 {
                    info!(
                        path = %snapshot_path.display(),
                        agents = reg.count_agents(),
                        tools = reg.count_tools(),
                        "agent-guard registry restored from snapshot (shared with response gate)",
                    );
                }
                reg
            }
            Err(e) => {
                warn!(error = %e, path = %snapshot_path.display(), "failed to restore agent-guard registry; starting empty");
                innerwarden_agent_guard::registry::Registry::new()
            }
        };
        Arc::new(tokio::sync::Mutex::new(reg))
    };
    let signature_index: Arc<innerwarden_agent_guard::signatures::SignatureIndex> =
        Arc::new(innerwarden_agent_guard::signatures::SignatureIndex::new());

    // Build the primary AI provider and capability router ONCE, before
    // the dashboard spawn. Both the dashboard task and the main agent
    // loop share the same `Arc`-wrapped provider and the same router
    // (which is `Clone`-cheap because it only holds `Arc<dyn AiProvider>`
    // handles). Constructing them here instead of twice (once for the
    // dashboard at line ~351, once for the agent at line ~661) avoids
    // re-parsing the ONNX classifier model and re-initialising provider
    // HTTP clients — measured saving ≈200 MB transient heap during boot
    // (jeprof on 2026-04-22). Branch logic is in `build_primary_provider`
    // so the `enabled / build-err / disabled` paths are unit-tested
    // without spinning up the rest of the agent.
    let ai_provider = build_primary_provider(&cfg.ai, &cfg.responder.block_backend);
    // Anti-silent guard (readiness audit B5/B1 theme): a role section
    // that names a provider but resolves inactive only happens when the
    // operator set `enabled = false` explicitly. That is a footgun - the
    // configured (and possibly downloaded) model is NOT used. Say so
    // loudly instead of letting Decide quietly run on the fallback.
    for (role, role_cfg) in [("ai.warden", &cfg.ai.classifier), ("ai.llm", &cfg.ai.llm)] {
        if role_cfg.is_provider_set_but_disabled() {
            warn!(
                role,
                provider = %role_cfg.provider,
                "[{role}] has provider configured but `enabled = false` - this slot is NOT used; \
                 remove `enabled = false` (or set it true) to activate the configured provider"
            );
        }
    }
    let ai_router = ai::router::build_from_config(
        ai_provider.as_ref().map(Arc::clone),
        &cfg.ai.classifier,
        &cfg.ai.llm,
        Some(&cfg.ai.shadow),
        cfg.ai.confidence_threshold,
        &cfg.responder.block_backend,
        |slot, provider_name| {
            info!(
                slot,
                provider = provider_name,
                "AI router: per-role slot configured"
            );
        },
        |slot, provider_name, err| {
            warn!(
                slot,
                provider = provider_name,
                "failed to build per-role provider, falling back to primary: {err:#}"
            );
        },
    );
    info!(router = %ai_router.describe(), "AI router ready");

    // Enforcement posture: make "is this agent actually defending the host,
    // or only watching?" explicit in the boot log. A fresh install ships
    // monitor-only by design; operators tailing journald should not have to
    // reverse-engineer that from two scattered `[responder]` flags.
    let posture = innerwarden_core::policy::EnforcementPosture::from_responder(
        cfg.responder.enabled,
        cfg.responder.dry_run,
    );
    if posture.is_enforcing() {
        info!(posture = posture.tag(), "{}", posture.headline());
    } else {
        warn!(
            posture = posture.tag(),
            "{} {}",
            posture.headline(),
            posture.cta().unwrap_or("")
        );
    }

    // Fleet (MSSP multi-host) — spec 038 Phase 1. The state cache is
    // pre-seeded with the configured host roster so the very first
    // `/api/fleet/hosts` call after boot returns the shape, not an
    // empty list. The background poller is spawned only when fleet
    // mode is enabled AND the host list is non-empty so a misplaced
    // `enabled = true` with no hosts does not log the empty-list
    // warning every 30 s.
    let fleet_state = if cfg.fleet.enabled && !cfg.fleet.hosts.is_empty() {
        let state = crate::fleet::FleetState::from_config(&cfg.fleet.hosts);
        let cfg_for_poller = std::sync::Arc::new(cfg.fleet.clone());
        let _join = crate::fleet::poller::spawn(state.clone(), cfg_for_poller);
        info!(
            host_count = cfg.fleet.hosts.len(),
            interval_secs = cfg.fleet.poll_interval_seconds,
            "fleet poller spawned"
        );
        Some(state)
    } else {
        None
    };

    // Issue #71: create the shared bridge before the dashboard spawn so
    // both the spawn closure and AgentState can each take a handle.
    // Declared here (before the dashboard gate) so AgentState init at the
    // bottom of this function can always reference them, even when the
    // dashboard is disabled (the sender is simply dropped).
    let dashboard_pending_map: std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<String, crate::telegram::PendingConfirmation>>,
    > = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    let (dashboard_approval_tx, dashboard_approval_rx) =
        tokio::sync::mpsc::channel::<crate::dashboard::state::DashboardApprovalOutcome>(32);

    // Dashboard spawn is gated by both the CLI flag AND the config
    // toggle. CLI `--dashboard` is the historical opt-in; the config
    // field (default `true`) lets the operator switch the dashboard
    // off without changing the systemd unit's ExecStart line — useful
    // for headless deployments that share a binary with interactive
    // installs. Skipping the spawn block also avoids the
    // agent-guard regex compile (~36 MB live per jeprof 2026-05-02)
    // and the HTTP/TLS runtime, cutting roughly 50-70 MB RSS.
    if cli.dashboard && cfg.dashboard.enabled {
        let auth = dashboard::DashboardAuth::try_from_env()?;
        let action_cfg = dashboard::DashboardActionConfig {
            enabled: cfg.responder.enabled,
            dry_run: cfg.responder.dry_run,
            block_backend: cfg.responder.block_backend.clone(),
            allowed_skills: cfg.responder.allowed_skills.clone(),
            ai_enabled: cfg.ai.enabled,
            ai_provider: cfg.ai.provider.clone(),
            ai_model: cfg.ai.model.clone(),
            geoip_enabled: cfg.geoip.enabled,
            abuseipdb_enabled: cfg.abuseipdb.enabled,
            abuseipdb_auto_block_threshold: cfg.abuseipdb.auto_block_threshold,
            honeypot_mode: cfg.honeypot.mode.clone(),
            honeypot_port: cfg.honeypot.port,
            telegram_enabled: cfg.telegram.enabled,
            slack_enabled: cfg.slack.enabled,
            discord_enabled: cfg.discord.enabled,
            cloudflare_enabled: cfg.cloudflare.enabled,
            crowdsec_enabled: cfg.crowdsec.enabled,
            webhook_format: cfg.webhook.format.clone(),
            sudo_protection_enabled: cfg
                .responder
                .allowed_skills
                .iter()
                .any(|s| s.contains("suspend-user")),
            execution_guard_enabled: cfg
                .responder
                .allowed_skills
                .iter()
                .any(|s| s.contains("execution")),
            mesh_enabled: cfg.mesh.enabled,
            web_push_enabled: !cfg.web_push.vapid_public_key.is_empty(),
            shield_enabled: cfg.cloudflare.enabled,
            dna_enabled: true, // DNA fingerprinting is always active
            retention_events_days: cfg.data.events_keep_days,
            retention_incidents_days: cfg.data.incidents_keep_days,
            retention_decisions_days: cfg.data.decisions_keep_days,
            retention_telemetry_days: cfg.data.telemetry_keep_days,
            retention_reports_days: cfg.data.reports_keep_days,
            trusted_ips: cfg.allowlist.trusted_ips.clone(),
            trusted_users: cfg.allowlist.trusted_users.clone(),
            ai_personality: cfg.telegram.bot.personality.clone(),
        };
        let dashboard_data_dir = cli.data_dir.clone();
        // Config-driven bind takes precedence over the `--dashboard-bind` CLI
        // flag, so dashboard access is set in ONE place (`[dashboard] bind` in
        // agent.toml via `innerwarden dashboard expose/local`) without editing
        // the systemd unit. `None` = fall back to the flag (loopback default).
        let dashboard_bind = cfg
            .dashboard
            .bind
            .clone()
            .unwrap_or_else(|| cli.dashboard_bind.clone());
        let web_push_pub_key = cfg.web_push.vapid_public_key.clone();
        let trusted_proxies = cfg.dashboard.trusted_proxies.clone();
        let session_timeout_minutes = cfg.dashboard.session_timeout_minutes;
        let max_sessions = cfg.dashboard.max_sessions;
        let dashboard_advisory_cache = advisory_cache.clone();

        // Load ATR rule engine: embedded community corpus (always present, no
        // deploy step) plus any operator overlay rules dropped in the on-disk
        // rules dir. Previously this loaded ONLY from disk, but the deploy
        // script only ever copies `rules/sigma` there, so the ATR engine ran
        // empty in prod — embedding fixes that.
        let rules_dir = std::path::Path::new("/etc/innerwarden/rules");
        let rule_engine = std::sync::Arc::new(
            innerwarden_agent_guard::rules::RuleEngine::load_with_overlay(rules_dir),
        );
        info!(
            atr_rules = rule_engine.rule_count(),
            "agent-guard ATR rule engine ready"
        );

        let agent_alert_tx = agent_alert_tx.clone();
        // Spec 081: hand the dashboard the SAME shared registry the response
        // gate uses, so `agent connect` mutations are visible to the verifier.
        let dashboard_registry = agent_registry.clone();
        let deep_security = deep_security_snapshot.clone();
        let dashboard_graph = shared_graph.clone();
        // Share the router built above with the dashboard. `AiRouter` is
        // `Clone` and only holds `Arc` handles, so this does not duplicate
        // any provider state.
        let dashboard_router = ai_router.clone();
        let dashboard_briefing = Arc::new(tokio::sync::Mutex::new(None::<briefing::Briefing>));
        let briefing_hour = cfg.briefing.hour;
        let briefing_minute = cfg.briefing.minute;
        let dashboard_store = sqlite_store.clone();
        let tls_cert = cli.tls_cert.clone();
        let tls_key = cli.tls_key.clone();
        let insecure_no_tls = cli.insecure_no_tls;

        // PR #420 Wave 3: thread 2FA config into the dashboard so the
        // sensitive POST endpoints (orphan clear / mark-already-gone)
        // can gate on operator-provided TOTP codes. `[security]` is
        // optional in the TOML; absent → no 2FA, same as method = "none".
        let dashboard_two_factor = match cfg.security.as_ref() {
            Some(sec) => dashboard::TwoFactorSettings::new(
                sec.two_factor_method.clone(),
                sec.totp_secret.clone(),
            ),
            None => dashboard::TwoFactorSettings::default(),
        };

        // Spec 056 Phase 5b: inputs for the playbook-test simulate
        // endpoint. asset_tags mirror the live incident path = the host's
        // `[agent] tags` (spec 058 minimal slice).
        let dashboard_playbook_sim = dashboard::PlaybookSimContext {
            rules_dir: std::path::PathBuf::from(&cfg.playbooks.rules_dir),
            trusted_ips: cfg.allowlist.trusted_ips.clone(),
            asset_tags: cfg.agent.tags.clone(),
        };

        // 2026-05-18 fix: write the discovery hint file to
        // /run/innerwarden/ BEFORE spawning the dashboard task, so
        // any AI agent process on the box (OpenClaw, Codex CLI, n8n,
        // etc.) can read it the moment the dashboard is reachable.
        //
        // The earlier ship of this code put the file under
        // `cli.data_dir` (/var/lib/innerwarden). That dir is created
        // by the install script as 0770 innerwarden:innerwarden — so
        // even with the file at 0644, peer agents running as
        // `ubuntu` could not traverse into the dir to reach it. The
        // operator saw "Permission denied" from OpenClaw on the
        // first day. /run/innerwarden/ is created world-traversable
        // (0755) by `write_discovery` itself, no install-script
        // change required.
        //
        // Fail-soft: a write error here (read-only volume, exotic
        // FS) must not abort agent boot — the dashboard still works,
        // we just lose the discovery affordance for peer agents.
        let discovery_runtime_dir =
            std::path::Path::new(crate::agent_discovery::PROD_DISCOVERY_DIR);
        match crate::agent_discovery::write_discovery(
            discovery_runtime_dir,
            &dashboard_bind,
            !cli.insecure_no_tls,
            env!("CARGO_PKG_VERSION"),
        ) {
            Ok(path) => info!(path = %path.display(), "agent discovery file written"),
            Err(e) => {
                warn!(error = %e, "failed to write agent discovery file (peer agents may not auto-discover us)")
            }
        }

        // Clone the Arc before moving into the spawn closure so
        // AgentState init below can still hold the original handle.
        let dashboard_pending_for_serve = dashboard_pending_map.clone();
        tokio::spawn(async move {
            if let Err(e) = dashboard::serve(
                dashboard_data_dir,
                dashboard_bind,
                auth,
                action_cfg,
                web_push_pub_key,
                trusted_proxies,
                session_timeout_minutes,
                max_sessions,
                dashboard_advisory_cache,
                rule_engine,
                dashboard_registry,
                agent_alert_tx,
                deep_security,
                dashboard_graph,
                dashboard_router,
                dashboard_briefing,
                briefing_hour,
                briefing_minute,
                dashboard_store,
                fleet_state,
                tls_cert,
                tls_key,
                insecure_no_tls,
                dashboard_two_factor,
                dashboard_playbook_sim,
                dashboard_pending_for_serve,
                dashboard_approval_tx,
            )
            .await
            {
                warn!(error = %e, "dashboard exited with error");
            }
        });
    }

    info!(
        data_dir = %cli.data_dir.display(),
        mode = if cli.once { "once" } else { "continuous" },
        narrative = cfg.narrative.enabled,
        webhook = cfg.webhook.enabled,
        ai = cfg.ai.enabled,
        correlation = cfg.correlation.enabled,
        correlation_window_secs = cfg.correlation.window_seconds,
        telemetry = cfg.telemetry.enabled,
        honeypot_mode = %cfg.honeypot.mode,
        honeypot_bind_addr = %cfg.honeypot.bind_addr,
        honeypot_services = ?cfg.honeypot.services,
        honeypot_ssh_port = cfg.honeypot.port,
        honeypot_http_port = cfg.honeypot.http_port,
        honeypot_isolation_profile = %cfg.honeypot.isolation_profile,
        honeypot_forensics_keep_days = cfg.honeypot.forensics_keep_days,
        honeypot_forensics_max_total_mb = cfg.honeypot.forensics_max_total_mb,
        honeypot_sandbox = cfg.honeypot.sandbox.enabled,
        honeypot_containment_mode = %cfg.honeypot.containment.mode,
        honeypot_containment_jail_runner = %cfg.honeypot.containment.jail_runner,
        honeypot_containment_jail_profile = %cfg.honeypot.containment.jail_profile,
        honeypot_external_handoff = cfg.honeypot.external_handoff.enabled,
        honeypot_external_handoff_allowlist = cfg.honeypot.external_handoff.enforce_allowlist,
        honeypot_external_handoff_signature = cfg.honeypot.external_handoff.signature_enabled,
        honeypot_external_handoff_attestation = cfg.honeypot.external_handoff.attestation_enabled,
        honeypot_pcap_handoff = cfg.honeypot.pcap_handoff.enabled,
        honeypot_redirect = cfg.honeypot.redirect.enabled,
        responder = cfg.responder.enabled,
        dry_run = cfg.responder.dry_run,
        // Build provenance baked in by `crates/agent/build.rs`. Surfaced
        // here so an operator who suspects a stale binary (e.g. a fix
        // looks shipped on github but not in prod behaviour) can verify
        // the running build's source by grepping `journalctl -u
        // innerwarden-agent | grep build_commit` against `git rev-parse
        // HEAD`. See Wave 9d (2026-05-04 prod incident) for the failure
        // mode this anchors against.
        build_commit = env!("INNERWARDEN_BUILD_COMMIT"),
        build_dirty = env!("INNERWARDEN_BUILD_DIRTY"),
        "innerwarden-agent v{} starting",
        env!("CARGO_PKG_VERSION")
    );

    // Clean up old summaries on startup
    if cfg.narrative.enabled {
        if let Err(e) = narrative::cleanup_old(&cli.data_dir, cfg.narrative.keep_days) {
            warn!("failed to clean up old summaries: {e:#}");
        }
    }

    // Clean up old data files on startup
    let removed = data_retention::cleanup(&cli.data_dir, &cfg.data);
    if removed > 0 {
        info!(removed, "data_retention: cleaned up old files on startup");
    }
    let (fs_removed, fs_bytes) = data_retention::cleanup_filestore(&cli.data_dir, &cfg.data);
    if fs_removed > 0 {
        info!(
            files = fs_removed,
            bytes = fs_bytes,
            "data_retention: pruned filestore on startup"
        );
    }

    // Build shared agent state
    // Pre-populate blocklist + decision cooldowns from recent (today + yesterday)
    // decision files so that IPs we already decided to block are skipped after a
    // restart, even in dry-run mode.
    let (decisions_bl, startup_cooldowns) = load_startup_decision_state(&cli.data_dir, false);

    let startup_blocklist = {
        let mut bl = if cfg.responder.enabled && !cfg.responder.dry_run {
            skills::Blocklist::load_from_ufw().await
        } else {
            skills::Blocklist::default()
        };
        // Merge IPs from recent decision files
        for ip in decisions_bl.as_vec() {
            bl.insert(ip);
        }
        bl
    };

    let telemetry_telegram_sent_counter = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let telemetry_gate_suppressed_counter =
        std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));

    // Build Telegram client (None when disabled or misconfigured)
    let telegram_client: Option<Arc<telegram::TelegramClient>> = if cfg.telegram.enabled {
        let token = cfg.telegram.resolved_bot_token();
        let chat_id = cfg.telegram.resolved_chat_id();
        if token.is_empty() || chat_id.is_empty() {
            warn!("telegram.enabled = true but bot_token/chat_id not configured - disabling");
            None
        } else {
            let dashboard_url = if cfg.telegram.dashboard_url.is_empty() {
                None
            } else {
                Some(cfg.telegram.dashboard_url.clone())
            };
            match telegram::TelegramClient::new(token, chat_id, dashboard_url) {
                Ok(mut c) => {
                    c.set_telegram_sent_counter(telemetry_telegram_sent_counter.clone());
                    // 2026-05-01: persistent audit trail for every
                    // outgoing telegram message. See
                    // `client.rs::post_json_with_response` writer +
                    // the operator question that prompted this:
                    // "auditar o que funciona" had no usable answer
                    // because daily-digest / menu / callback sends
                    // were invisible (env_filter dropped them and
                    // notification-feedback.jsonl only logs
                    // incident-driven sends).
                    let audit_path = cli.data_dir.join("telegram-sent.jsonl");
                    c.set_audit_jsonl_path(audit_path.clone());
                    // 2026-05-01: parallel durable record of FAILED
                    // sends. Operator queries this file to find
                    // messages that the system intended to send but
                    // could not (HTTP transport, JSON parse, API
                    // ok=false). See client.rs::audit_failed_send.
                    c.set_failed_jsonl_path(cli.data_dir.join("telegram-failed.jsonl"));
                    if cfg.telegram.dev_mode {
                        c.dev_mode = true;
                        info!("Telegram dev mode ON — FP review button on every notification");
                    }
                    info!(
                        audit_path = %audit_path.display(),
                        "Telegram client initialised (T.1 notifications enabled)"
                    );
                    Some(Arc::new(c))
                }
                Err(e) => {
                    warn!("failed to create Telegram client: {e:#}");
                    None
                }
            }
        }
    } else {
        None
    };

    // Build Slack client (None when disabled or unconfigured)
    let slack_client: Option<slack::SlackClient> = if cfg.slack.enabled {
        let url = cfg.slack.resolved_webhook_url();
        if url.is_empty() {
            warn!("slack.enabled = true but webhook_url not configured - disabling");
            None
        } else {
            match slack::SlackClient::new(&url) {
                Ok(c) => {
                    info!("Slack notifications enabled");
                    Some(c)
                }
                Err(e) => {
                    warn!("failed to create Slack client: {e:#}");
                    None
                }
            }
        }
    } else {
        None
    };

    let discord_client: Option<discord::DiscordClient> = if cfg.discord.enabled {
        let url = cfg.discord.resolved_webhook_url();
        if url.is_empty() {
            warn!("discord.enabled = true but webhook_url not configured - disabling");
            None
        } else {
            match discord::DiscordClient::new(&url) {
                Ok(c) => {
                    info!("Discord notifications enabled");
                    Some(c)
                }
                Err(e) => {
                    warn!("failed to create Discord client: {e:#}");
                    None
                }
            }
        }
    } else {
        None
    };

    // Create approval channel - polling task is spawned after state is built (continuous mode only)
    let (approval_tx, approval_rx_for_state) =
        tokio::sync::mpsc::channel::<telegram::ApprovalResult>(64);

    let store = state_store::StateStore::open(&cli.data_dir).unwrap_or_else(|e| {
        tracing::warn!(error = %e, "state store open failed - using fresh store");
        state_store::StateStore::open(&std::env::temp_dir()).expect("fallback store")
    });

    // Seed the persistent store with decision cooldowns loaded from recent JSONL files.
    // This ensures restart continuity: IPs already decided on won't be re-evaluated.
    for (key, ts) in &startup_cooldowns {
        store.set_cooldown(state_store::CooldownTable::Decision, key, *ts);
    }

    // Spawn snitch alert dispatch task (uses cloned notification clients).
    {
        let tg = telegram_client.clone();
        let sc_url = if cfg.slack.enabled {
            cfg.slack.resolved_webhook_url()
        } else {
            String::new()
        };
        let wh_url = cfg.webhook.url.clone();
        let wh_enabled = cfg.webhook.enabled;
        let wh_timeout = cfg.webhook.timeout_secs;
        let wh_format = cfg.webhook.format.clone();
        let alert_data_dir = cli.data_dir.clone();
        // Also persist each alert as a dashboard incident so blocked/flagged
        // AI-agent actions surface as Cases (not only jsonl + Telegram).
        let alert_sqlite_store = sqlite_store.clone();
        let alert_host = std::env::var("HOSTNAME")
            .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
            .unwrap_or_else(|_| "unknown".to_string());
        tokio::spawn(async move {
            let sc = if !sc_url.is_empty() {
                slack::SlackClient::new(&sc_url).ok()
            } else {
                None
            };
            let mut cooldowns: std::collections::HashMap<String, tokio::time::Instant> =
                std::collections::HashMap::new();
            while let Some(alert) = agent_alert_rx.recv().await {
                // 60s cooldown per agent+command hash.
                let key = format!(
                    "{}:{}",
                    alert.agent_name,
                    innerwarden_core::audit::sha256_hex(&alert.command)
                );
                let now = tokio::time::Instant::now();
                if let Some(last) = cooldowns.get(&key) {
                    if now.duration_since(*last) < std::time::Duration::from_secs(60) {
                        continue;
                    }
                }
                cooldowns.insert(key, now);
                cooldowns
                    .retain(|_, v| now.duration_since(*v) < std::time::Duration::from_secs(300));

                info!(
                    agent = %alert.agent_name,
                    command = %alert.command,
                    severity = %alert.severity,
                    recommendation = %alert.recommendation,
                    "agent-guard snitch alert"
                );

                // JSONL audit trail (write first, before network calls that may block).
                {
                    let today = chrono::Local::now().date_naive().format("%Y-%m-%d");
                    let path = alert_data_dir.join(format!("agent-guard-events-{today}.jsonl"));
                    match serde_json::to_string(&alert) {
                        Ok(line) => {
                            use std::io::Write;
                            match std::fs::OpenOptions::new()
                                .create(true)
                                .append(true)
                                .open(&path)
                            {
                                Ok(mut f) => {
                                    if let Err(e) = writeln!(f, "{line}") {
                                        warn!(error = %e, path = %path.display(), "failed to write agent-guard event");
                                    }
                                }
                                Err(e) => {
                                    warn!(error = %e, path = %path.display(), "failed to open agent-guard events file")
                                }
                            }
                        }
                        Err(e) => warn!(error = %e, "failed to serialize agent-guard alert"),
                    }
                }

                // Dashboard case: persist the alert as an incident so the
                // guardrail's actions show up in the Cases / live-feed UI, not
                // only in the jsonl audit + chat notification. Idempotent
                // (incident_id carries the alert ts; store does INSERT OR
                // IGNORE). Blocking SQLite write → spawn_blocking.
                if let Some(sq) = alert_sqlite_store.clone() {
                    let incident = crate::dashboard::agent_guard_incident::alert_to_incident(
                        &alert,
                        &alert_host,
                    );
                    match tokio::task::spawn_blocking(move || sq.insert_incident(&incident)).await {
                        Ok(Ok(_)) => {}
                        Ok(Err(e)) => {
                            warn!(error = %e, "failed to persist agent-guard incident")
                        }
                        Err(e) => {
                            warn!(error = %e, "agent-guard incident persist task join failed")
                        }
                    }
                }

                // Telegram notification.
                if let Some(ref tg) = tg {
                    if let Err(e) = tg.send_agent_guard_alert(&alert).await {
                        warn!(error = %e, "agent-guard Telegram alert failed");
                    }
                }

                // Slack notification.
                if let Some(ref sc) = sc {
                    if let Err(e) = sc.send_agent_guard_alert(&alert).await {
                        warn!(error = %e, "agent-guard Slack alert failed");
                    }
                }

                // Webhook notification.
                if wh_enabled {
                    if let Err(e) =
                        webhook::send_agent_guard_alert(&wh_url, wh_timeout, &alert, &wh_format)
                            .await
                    {
                        warn!(error = %e, "agent-guard webhook alert failed");
                    }
                }
            }
        });
    }

    let mut state = AgentState {
        skill_registry: skills::SkillRegistry::default_builtin(),
        blocklist: startup_blocklist,
        correlator: correlation::TemporalCorrelator::new(cfg.correlation.window_seconds, 4096),
        telemetry: telemetry::TelemetryState::with_external_counters(
            telemetry_telegram_sent_counter.clone(),
            telemetry_gate_suppressed_counter.clone(),
        ),
        telemetry_writer: if cfg.telemetry.enabled {
            match telemetry::TelemetryWriter::new(&cli.data_dir) {
                Ok(w) => Some(w),
                Err(e) => {
                    warn!("failed to create telemetry writer: {e:#}");
                    None
                }
            }
        } else {
            None
        },
        ai_router,
        // Decision writer is always created — Layer 1/2 decisions are written
        // even without AI. Previously gated on cfg.ai.enabled which caused
        // zero audit trail when AI was disabled or during agent restarts.
        // Pass the sqlite store so every JSONL write is mirrored into the
        // `decisions` table; dashboards, `/metrics`, and the scenario-qa
        // drift harness all query sqlite, so without the mirror they were
        // reading a table untouched since the legacy migration.
        decision_writer: match decisions::DecisionWriter::with_store(
            &cli.data_dir,
            sqlite_store.clone(),
        ) {
            Ok(w) => Some(w),
            Err(e) => {
                warn!("failed to create decision writer: {e:#}");
                None
            }
        },
        last_narrative_at: load_last_narrative_instant(&cli.data_dir),
        // Hydrate the daily briefing dedup marker from kv_state so a
        // restart after `daily_summary_hour` does not re-emit today's
        // digest. Pre-2026-05-09 this defaulted to `None` and every
        // restart fired a fresh "Daily Security Briefing" message.
        last_daily_summary_telegram: store.get_last_daily_briefing_date(),
        telegram_daily_sent: 0,
        telegram_budget_date: None,
        telegram_deferred: HashMap::new(),
        telegram_client,
        pending_confirmations: HashMap::new(),
        approval_rx: None, // set below in continuous mode
        dashboard_pending: dashboard_pending_map.clone(),
        dashboard_approval_rx: Some(dashboard_approval_rx),
        grouping_engine: notification_pipeline::GroupingEngine::new(&cfg.notifications),
        environment_profile: {
            // 2026-05-03: load auto-detected profile, then merge in
            // operator-supplied service account extras from
            // `[environment] service_users_extra` /
            // `service_uids_extra`. This is the user-extension
            // surface for the trusted-services classification used
            // by the graph detectors. Static config today; future
            // PR (Wave 3) wires a runtime API endpoint that appends
            // here under a 2FA gate.
            let mut profile =
                environment_profile::load_or_bootstrap(&cli.data_dir, &cfg.environment);
            profile.merge_operator_service_extras(
                &cfg.environment.service_users_extra,
                &cfg.environment.service_uids_extra,
            );
            profile
        },
        last_env_census_at: None,
        host_posture: {
            // Spec 044 Phase 2 (2026-05-09): take an initial posture
            // snapshot at boot so the severity downgrade engine has a
            // baseline before the first slow-loop refresh tick. Probes
            // are best-effort — failures log a warn! and the snapshot
            // is "permissive" until the next refresh.
            posture::refresh_and_save(&cli.data_dir)
        },
        last_host_posture_at: Some(std::time::Instant::now()),
        anomaly_engine: neural_lifecycle::AnomalyEngine::new(neural_lifecycle::AnomalyConfig {
            data_dir: cli.data_dir.clone(),
            ..Default::default()
        }),
        neural_incidents: Vec::new(),
        trust_rules: load_trust_rules(&cli.data_dir),
        crowdsec: if cfg.crowdsec.enabled {
            info!(url = %cfg.crowdsec.url, "CrowdSec integration enabled");
            Some(crowdsec::CrowdSecState::new(&cfg.crowdsec))
        } else {
            None
        },
        abuseipdb: if cfg.abuseipdb.enabled {
            let key = abuseipdb::resolve_api_key(&cfg.abuseipdb.api_key);
            if key.is_empty() {
                warn!("abuseipdb.enabled=true but no API key found - disabling enrichment");
                None
            } else {
                info!(
                    "AbuseIPDB enrichment enabled (max_age_days={})",
                    cfg.abuseipdb.max_age_days
                );
                // 2026-05-08 (fix/abuseipdb-telegram-honesty):
                // operator's prod 2026-05-07 had `auto_block_threshold = 1`
                // which silently auto-blocks any IP with even one
                // historical AbuseIPDB report — including AWS/Azure/GCP
                // edge IPs that have a single FP. The Telegram alert
                // then claimed "known threat" for score 8/100, which
                // damaged operator trust. AbuseIPDB's own UI labels
                // anything below 25 as "low risk"; the docstring on
                // the config field recommends 75-90. Anything ≤ 25
                // is almost certainly a misconfiguration. Emit a
                // single-line WARN at boot so the operator sees it
                // alongside the "AbuseIPDB enrichment enabled" line.
                let t = cfg.abuseipdb.auto_block_threshold;
                if (1..=25).contains(&t) {
                    warn!(
                        threshold = t,
                        "abuseipdb.auto_block_threshold = {t} is implausibly low \
                         (AbuseIPDB labels < 25 as 'low risk'). Auto-block will \
                         fire on IPs with little or no real evidence — including \
                         cloud-edge / CDN IPs that get one historical FP report. \
                         Recommended: 75 (aggressive) or 90 (conservative). Set \
                         to 0 to disable the auto-block path entirely while \
                         keeping enrichment."
                    );
                }
                Some(abuseipdb::AbuseIpDbClient::new(
                    key,
                    cfg.abuseipdb.max_age_days,
                ))
            }
        } else {
            None
        },
        geoip_client: if cfg.geoip.enabled {
            info!("GeoIP enrichment enabled (ip-api.com, free tier)");
            Some(geoip::GeoIpClient::new())
        } else {
            None
        },
        slack_client,
        discord_client,
        cloudflare_client: if cfg.cloudflare.enabled {
            let token = cloudflare::resolve_api_token(&cfg.cloudflare.api_token);
            if token.is_empty() || cfg.cloudflare.zone_id.is_empty() {
                warn!(
                    "cloudflare.enabled=true but api_token or zone_id not configured - disabling"
                );
                None
            } else {
                info!(zone_id = %cfg.cloudflare.zone_id, "Cloudflare IP block push enabled");
                Some(cloudflare::CloudflareClient::with_prefix(
                    cfg.cloudflare.zone_id.clone(),
                    token,
                    cfg.cloudflare.block_notes_prefix.clone(),
                ))
            }
        } else {
            None
        },
        circuit_breaker_until: None,
        pending_honeypot_choices: HashMap::new(),
        // SQLite is canonical; JSON fallback covers data dirs that predate
        // the migration. The next persist tick syncs SQLite, so the fallback
        // path is self-healing on subsequent boots.
        ip_reputations: {
            let from_store = ip_reputation::load_ip_reputations_from_store(&store);
            if from_store.is_empty() {
                let from_json = load_ip_reputations(&cli.data_dir);
                if !from_json.is_empty() {
                    info!(
                        count = from_json.len(),
                        "warm-cache: SQLite ip_reputations empty, loaded from legacy JSON (will sync to SQLite on next slow-loop tick)"
                    );
                }
                from_json
            } else {
                info!(
                    count = from_store.len(),
                    "warm-cache: loaded ip_reputations from SQLite canonical"
                );
                from_store
            }
        },
        lsm_enabled: false,
        mesh: if cfg.mesh.enabled {
            match mesh::MeshIntegration::new(&cfg.mesh, &cli.data_dir) {
                Ok(m) => {
                    info!(node_id = %m.node_id(), peers = m.peer_count(), "Mesh network enabled");
                    Some(m)
                }
                Err(e) => {
                    warn!(error = %e, "Mesh network init failed");
                    None
                }
            }
        } else {
            None
        },
        // Spec 037 I-07 slice 2: warm-cache the rate-limiter window
        // from the SQLite `recent_blocks` namespace. Pre-PR the
        // `VecDeque` reset on every boot, letting a burst of
        // `MAX_BLOCKS_PER_MINUTE` blocks land in the first second
        // after a crash. The loader filters to the same 60s window
        // that the runtime `retain` enforces, prunes stale rows
        // during the read, and degrades to an empty deque on a store
        // read error (matching pre-PR behaviour in that case).
        recent_blocks: store.load_recent_blocks_within(60),
        // Spec 037 PR-1 (I-02 slice 1): warm-cache from the SQLite
        // `xdp_block_times` namespace so TTL accounting survives a
        // restart. Pre-PR the map was reset on every boot; adaptive
        // TTL expiration for previously-blocked IPs was lost and
        // the cleanup loop would sit idle until fresh blocks landed.
        // `load_xdp_block_times` degrades to an empty map on a store
        // read error (logged `warn!`), matching pre-PR behaviour in
        // the degraded case.
        xdp_block_times: store.load_xdp_block_times(),
        xdp_cleanup_backoff: HashMap::new(),
        response_lifecycle: response_lifecycle::ResponseLifecycle::load_snapshot(
            &cli.data_dir,
            sqlite_store.as_deref(),
        ),
        abuseipdb_report_queue: Vec::new(),
        narrative_acc: NarrativeAccumulator::default(),
        narrative_incidents_offset: 0,
        forensics: forensics::ForensicsCapture::new(&cli.data_dir),
        store,
        baseline: {
            let mut b = baseline::BaselineStore::load(&cli.data_dir, sqlite_store.as_deref());
            // 2026-05-03 (Wave 5b): one-shot prune of pollution from
            // pre-Wave-5b baselines that recorded brute-force usernames
            // (`Admin`, `AdminGPON`, `1234`, special chars) as if they
            // were real logins. Idempotent — pure-Linux usernames
            // (ubuntu, snap_daemon, _apt, ...) pass through unchanged.
            let removed = b.prune_invalid_users();
            if removed > 0 {
                info!(
                    removed,
                    "baseline: pruned {removed} invalid user_login_hours entries (Wave 5b cleanup)"
                );
            }
            b
        },
        sqlite_store: sqlite_store.clone(),
        sqlite_store_path: cli.data_dir.clone(),
        sqlite_reopen_last_attempt: None,
        maintenance_scheduler: if sqlite_store.is_some() {
            Some(innerwarden_store::maintenance::MaintenanceScheduler::new())
        } else {
            None
        },
        attacker_profiles: HashMap::new(), // loaded from redb below
        last_intel_consolidation_at: None,
        correlation_engine: correlation_engine::CorrelationEngine::from_yaml_dir(
            std::path::Path::new("/etc/innerwarden/rules/correlation"),
        ),
        pcap_capture: pcap_capture::PcapCapture::new(&cli.data_dir),
        scoring_engine: scoring::ScoringEngine::new(0.95),
        last_firmware_incident_at: None,
        last_hypervisor_incident_at: None,
        hypervisor_environment: None,
        killchain_tracker: innerwarden_killchain::tracker::PidTracker::new()
            .with_timeout(cfg.killchain.session_timeout_secs)
            .with_pre_chain_threshold(cfg.killchain.pre_chain_threshold)
            .with_excluded_comms(
                killchain_inline::KILLCHAIN_SELF_EXCLUDED_COMMS
                    .iter()
                    .copied(),
            ),
        last_killchain_cleanup: std::time::Instant::now(),
        dna_state: dna_inline::DnaState::new(
            &cli.data_dir.join("dna"),
            cfg.dna.min_sequence,
            cfg.dna.anomaly_threshold,
            cfg.dna.session_timeout_secs,
        ),
        shield_state: if cfg.shield.enabled {
            Some(shield_inline::ShieldState::new(
                &cli.data_dir.join("shield"),
                &cfg.shield.bpf_path,
                cfg.shield.dry_run,
                &cfg.shield.cloudflare_failover,
                &cfg.shield.origin_lockdown,
            ))
        } else {
            None
        },
        last_dna_save: std::time::Instant::now(),
        // Phase 7B: stagger the first orphan-recovery sweep by ~5 min
        // post-boot so it doesn't race with the in-flight incident
        // processing right after a restart.
        last_orphan_recovery: std::time::Instant::now() - std::time::Duration::from_secs(5 * 60),
        last_needs_review_timeout: std::time::Instant::now()
            - std::time::Duration::from_secs(5 * 60),
        // Offset so the first reconcile runs ~1 min after boot — catches blocks
        // dropped while the agent was down / a stale reloaded set, fast.
        last_block_enforcement_reconcile: std::time::Instant::now()
            - std::time::Duration::from_secs(4 * 60),
        // Offset so the first agent-guard registry reconcile runs ~1 min after
        // boot — re-registers a co-located agent that restarted (new pid) while
        // the agent was down, before the next incident could sever it.
        last_agent_registry_reconcile: std::time::Instant::now()
            - std::time::Duration::from_secs(4 * 60),
        pending_mode_change: None,
        pending_setting_changes: Vec::new(),
        deep_security_snapshot: Some(deep_security_snapshot.clone()),
        dynamic_trusted_ips: Vec::new(),
        dynamic_trusted_users: Vec::new(),
        dynamic_trusted_processes: Vec::new(),
        operator_ips: std::collections::HashMap::new(),
        last_operator_refresh: std::time::Instant::now(),
        suppressed_incident_ids: firmware_tick::load_suppressed_ids(&cli.data_dir),
        threat_feed: None, // initialized below if configured
        last_baseline_anomaly_ts: None,
        last_autoencoder_anomaly_ts: None,
        latest_anomaly_score: None,
        two_factor_state: two_factor::TwoFactorState::new(),
        knowledge_graph: shared_graph.clone(),
        graph_detector_state: knowledge_graph::detectors::GraphDetectorState::new(),
        last_graph_snapshot: std::time::Instant::now(),
        notification_burst_tracker: notification_gate::BurstTracker::new(),
        feedback_tracker: notification_pipeline::FeedbackTracker::new(),
        last_feedback_tick_at: None,
        task_group: crate::task_group::TaskGroup::new(),
        // Spec 081 — managed-agent coexistence: the SAME registry shared with the
        // dashboard (built above), so the response gate sees `agent connect`s live.
        agent_registry: agent_registry.clone(),
        signature_index: signature_index.clone(),
    };

    // Spec 005 Phase 7: replay persisted feedback so demotions survive
    // restarts. Events older than IGNORE_WINDOW_SECS still contribute to
    // the ignore tally; only the `pending` projection is freshness-filtered.
    {
        let replay_now = chrono::Utc::now();
        let events = notification_pipeline::feedback_store::load(&cli.data_dir);
        for event in &events {
            state.feedback_tracker.replay_event(event, replay_now);
        }
        if !events.is_empty() {
            info!(
                count = events.len(),
                pending = state.feedback_tracker.pending_count(),
                "notification feedback replayed"
            );
        }
    }

    // Seed operator IPs from active SSH sessions (who -i).
    // Only publickey SSH sessions from trusted_users are considered operators.
    // IPs are dynamic — they expire when the session ends (refreshed every 30s).
    crate::loops::slow_loop::refresh_operator_ips(&mut state, &cfg.allowlist);
    state.last_operator_refresh = std::time::Instant::now();

    // Load attacker intelligence profiles from persistent store
    state.attacker_profiles = attacker_intel::load_from_store(&state.store);
    if !state.attacker_profiles.is_empty() {
        info!(
            profiles = state.attacker_profiles.len(),
            "loaded attacker profiles from state store"
        );
    }

    // 2026-05-04 (Wave 7a): one-shot anchor recalibration on every
    // boot. Production observation 2026-05-04: every observe() was
    // returning `score="1.000"` because the trained percentile
    // anchors did not represent the current event distribution —
    // every reconstruction error landed past `anchors.last()`, so
    // the spec-033 Phase 0 tanh extrapolation saturated near 1.0,
    // and the +9.9% boost in `incident_decision_eval` fired on
    // every triggered incident as a constant offset (zero
    // discriminative value).
    //
    // Recalibration walks the last ~10k events from SQLite through
    // the same pipeline `observe()` uses, collects per-window MSEs,
    // and rebuilds the anchor table from that fresh distribution.
    // Cheap (~seconds) and best-effort: any failure leaves the
    // existing anchors in place. Falls back to the next nightly
    // retrain (`train_nightly_with_store`) for full model recovery
    // if the recalibration alone does not restore signal.
    // Copilot #5 fix: SQLite read + JSON deserialize + feature
    // extraction are synchronous CPU/IO. Wrap in `block_in_place` on
    // multi-thread runtimes so we do not stall tokio worker threads
    // during boot — same pattern as `run_events_src_ip_backfill_in_place`
    // in `slow_loop.rs`. On a current_thread runtime (tests,
    // `#[tokio::test]` default) `block_in_place` panics, so the
    // synchronous fallback runs there. Both branches produce the
    // same observable effect; only the worker-transfer hint
    // differs.
    if let Some(ref sq) = state.sqlite_store {
        let multi_thread = tokio::runtime::Handle::try_current()
            .map(|h| h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread)
            .unwrap_or(false);
        let mut run_recal = || {
            const BOOT_RECALIBRATION_SAMPLE: i64 = 10_000;
            match sq.events_max_id() {
                Ok(max_id) => {
                    let after = max_id.saturating_sub(BOOT_RECALIBRATION_SAMPLE);
                    match sq.events_since(after, BOOT_RECALIBRATION_SAMPLE as usize) {
                        Ok(rows) => {
                            let events: Vec<innerwarden_core::event::Event> =
                                rows.into_iter().map(|(_, ev)| ev).collect();
                            if events.is_empty() {
                                info!(
                                    "anomaly: skipping boot recalibration (no events in store yet)"
                                );
                            } else {
                                match state
                                    .anomaly_engine
                                    .recalibrate_anchors_from_events(&events)
                                {
                                    Ok(samples) => info!(
                                        samples,
                                        events_read = events.len(),
                                        "anomaly: boot anchor recalibration complete"
                                    ),
                                    Err(e) => warn!(
                                        "anomaly: boot recalibration failed (keeping existing anchors): {e}"
                                    ),
                                }
                            }
                        }
                        Err(e) => warn!("anomaly: boot recalibration sqlite read failed: {e}"),
                    }
                }
                Err(e) => warn!("anomaly: boot recalibration max-id read failed: {e}"),
            }
        };
        if multi_thread {
            tokio::task::block_in_place(run_recal);
        } else {
            run_recal();
        }
    } else {
        info!("anomaly: skipping boot recalibration (no sqlite store)");
    }

    // Initialize threat feed client if VT API key or IOC feed URLs are configured
    {
        let vt_key = if cfg.threat_feeds.virustotal_api_key.is_empty() {
            threat_feeds::resolve_vt_api_key("")
        } else {
            cfg.threat_feeds.virustotal_api_key.clone()
        };
        let feed_urls = cfg.threat_feeds.effective_urls();
        if !feed_urls.is_empty() {
            info!(
                feeds = feed_urls.len(),
                "threat feeds: {} URLs configured",
                feed_urls.len()
            );
        }
        let client = threat_feeds::ThreatFeedClient::new(
            vt_key,
            feed_urls,
            &cli.data_dir,
            sqlite_store.as_deref(),
        );
        let feed_state = client.state();
        if feed_state.total_iocs > 0 {
            info!(
                ips = feed_state.malicious_ips.len(),
                domains = feed_state.malicious_domains.len(),
                hashes = feed_state.malicious_hashes.len(),
                "threat feeds: loaded cached IOCs"
            );
        }
        state.threat_feed = Some(client);
    }

    if !state.ip_reputations.is_empty() {
        info!(
            count = state.ip_reputations.len(),
            "loaded local IP reputations from disk"
        );
    }

    if let Some(ref mesh_node) = state.mesh {
        match mesh_node.start_listener().await {
            Ok((addr, _handle)) => info!(addr = %addr, "mesh listener started"),
            Err(e) => warn!(error = %e, "mesh listener failed to start"),
        }
    }

    // Discover mesh peer identities (ping each, learn their public keys).
    // Must happen after listener starts so peers can ping us back.
    if let Some(ref mut mesh_node) = state.mesh {
        mesh_node.discover_peers().await;
        info!(
            peers = mesh_node.peer_count(),
            "mesh peer discovery complete"
        );
    }

    // Legacy cursor kept for test compatibility (tests still pass AgentCursor)
    let mut cursor = reader::AgentCursor::default();

    if cli.once {
        let handled = crate::process::incidents::process_incidents(
            &cli.data_dir,
            &mut cursor,
            &cfg,
            &mut state,
            &advisory_cache,
        )
        .await;
        let new_events = crate::loops::slow_loop::process_narrative_tick(
            &cli.data_dir,
            &mut cursor,
            &cfg,
            &mut state,
        )
        .await?;
        if let Some(w) = &mut state.decision_writer {
            w.flush();
        }
        if let Some(w) = &mut state.telemetry_writer {
            w.flush();
        }
        // Spec 036 PR-3: drain any tasks registered via `task_group`
        // before exit. Once-mode typically has zero persistent spawns
        // today, so this is a near-instant no-op — but if a future
        // migration adds one, this line ensures a clean drain in both
        // modes without duplicating the call path.
        let report = state.task_group.shutdown(GRACEFUL_SHUTDOWN_DEADLINE).await;
        log_shutdown_report(report);
        info!(new_events, incidents_handled = handled, "run complete");
    } else {
        // Activate approval channel and start Telegram polling task
        state.approval_rx = Some(approval_rx_for_state);
        if let Some(ref tg) = state.telegram_client {
            // Register persistent command menu (fire-and-forget), scoped to the
            // operator's profile so a lay user sees the tiny 5-command menu.
            tg.set_commands(cfg.telegram.is_simple_profile()).await;
            let tg_clone = tg.clone();
            // Spec 036 PR-2: register the long-lived Telegram polling
            // loop in the agent's TaskGroup so SIGTERM-driven shutdown
            // (wired in a later PR) cancels the long-poll and drains
            // the task within the deadline. The wrapper races
            // `run_polling` against `token.cancelled()` at the call
            // site — `run_polling` itself is untouched, which keeps
            // its six existing test fixtures passing unchanged.
            let token = state.task_group.token();
            state.task_group.spawn_or_log(
                "telegram-polling",
                Box::pin(async move {
                    tokio::select! {
                        _ = tg_clone.run_polling(approval_tx) => {}
                        _ = token.cancelled() => {
                            info!("telegram polling: shutdown signaled, exiting");
                        }
                    }
                }),
            );
            info!("Telegram polling task started (T.2 approvals enabled)");
        }

        // Boot self-test: verify self-awareness is working.
        crate::loops::slow_loop::boot_self_test();

        // One-time backfill: reconcile JSONL decisions with the knowledge graph.
        // Fixes historical incidents where auto-block gates wrote to JSONL but
        // not to the graph (incident_obvious + incident_crowdsec before the fix).
        crate::loops::slow_loop::backfill_graph_decisions(&cli.data_dir, &mut state);

        // Always-on honeypot: permanent SSH listener from startup.
        // Spec 036 PR-4: cancellation flows through the agent's unified
        // `state.task_group` — the listener observes
        // `token.cancelled()` in its accept loop and exits cleanly
        // when SIGTERM/SIGINT triggers `task_group.shutdown()`. The
        // pre-PR-4 `tokio::sync::watch::Receiver<bool>` mechanism is
        // gone; we no longer hold a sender at the caller level.
        if cfg.honeypot.mode == "always_on" {
            // Build a filter blocklist pre-populated from today's + yesterday's decisions.
            let initial_blocked: std::collections::HashSet<String> = {
                let (bl, _) = load_startup_decision_state(&cli.data_dir, false);
                bl.as_vec().into_iter().collect()
            };
            let filter_bl = std::sync::Arc::new(std::sync::Mutex::new(initial_blocked));

            let port = cfg.honeypot.port;
            let bind_addr = cfg.honeypot.bind_addr.clone();
            let max_auth = cfg.honeypot.ssh_max_auth_attempts;
            let abuseipdb_client = if cfg.abuseipdb.enabled {
                let key = abuseipdb::resolve_api_key(&cfg.abuseipdb.api_key);
                if key.is_empty() {
                    None
                } else {
                    Some(std::sync::Arc::new(abuseipdb::AbuseIpDbClient::new(
                        key,
                        cfg.abuseipdb.max_age_days,
                    )))
                }
            } else {
                None
            };
            let abuseipdb_threshold = cfg.abuseipdb.auto_block_threshold;
            // Spec 029 PR-C.2: honeypot always-on uses the AI provider
            // for short attack-profile explanations of auth attempts.
            // Prefer Explain, fall back to any LLM (typical deploy has
            // only one anyway). Logic lives in `AiRouter::explain_or_any_llm`
            // so it is unit-tested without spawning the honeypot loop.
            let ai_clone = state.ai_router.explain_or_any_llm();
            let tg_clone = state.telegram_client.clone();
            let gate_counter = state.telemetry.gate_suppressed_counter();
            let data_dir_clone = cli.data_dir.clone();
            let store_clone = state.sqlite_store.clone();
            let responder_enabled = cfg.responder.enabled;
            let dry_run = cfg.responder.dry_run;
            let block_backend = cfg.responder.block_backend.clone();
            let allowed_skills = cfg.responder.allowed_skills.clone();
            let interaction = cfg.honeypot.interaction.clone();
            // 2026-05-10 (skill_gate): plumb operator trusted_ips into the
            // honeypot listener so its auto-block paths route through
            // `skill_gate::gate_block_ip` and respect
            // `cfg.allowlist.trusted_ips` just like the canonical
            // `decision_block_ip` path.
            let trusted_ips = cfg.allowlist.trusted_ips.clone();
            let token = state.task_group.token();

            state.task_group.spawn_or_log(
                "honeypot-always-on",
                Box::pin(async move {
                    honeypot_always_on::run_always_on_honeypot(
                        port,
                        bind_addr,
                        max_auth,
                        filter_bl,
                        ai_clone,
                        tg_clone,
                        gate_counter,
                        abuseipdb_client,
                        abuseipdb_threshold,
                        data_dir_clone,
                        store_clone,
                        responder_enabled,
                        dry_run,
                        block_backend,
                        allowed_skills,
                        interaction,
                        trusted_ips,
                        token,
                    )
                    .await;
                }),
            );
        }

        let ai_poll = cfg.ai.incident_poll_secs;
        info!(
            narrative_interval_secs = cli.interval,
            incident_interval_secs = ai_poll,
            "entering continuous mode"
        );

        let mut narrative_ticker =
            tokio::time::interval(tokio::time::Duration::from_secs(cli.interval));
        let mut incident_ticker = tokio::time::interval(tokio::time::Duration::from_secs(ai_poll));
        let mut crowdsec_ticker = tokio::time::interval(tokio::time::Duration::from_secs(
            cfg.crowdsec.poll_secs.max(10),
        ));
        let mut mesh_ticker =
            tokio::time::interval(tokio::time::Duration::from_secs(cfg.mesh.poll_secs.max(10)));
        let mut firmware_ticker = tokio::time::interval(tokio::time::Duration::from_secs(
            cfg.firmware.poll_secs.max(60),
        ));
        let mut hypervisor_ticker = tokio::time::interval(tokio::time::Duration::from_secs(
            cfg.hypervisor.poll_secs.max(60),
        ));

        // Graceful-shutdown signal. On unix this is SIGTERM; on Windows
        // (spec 085 Phantom-on-Windows Phase 0) it is CtrlShutdown
        // (service-stop / logoff). Both expose `async fn recv(&mut self)`
        // so the `sigterm.recv()` select arm below is platform-agnostic.
        #[cfg(unix)]
        let mut sigterm = {
            use tokio::signal::unix::{signal, SignalKind};
            signal(SignalKind::terminate())?
        };
        #[cfg(not(unix))]
        let mut sigterm = tokio::signal::windows::ctrl_shutdown()?;

        // Spec 084 P0 1C (hardening): refresh the Kubernetes pod -> tenant cache
        // in a DEDICATED task. It previously lived in the narrative `select!`
        // arm, where a heavy incident-processing tick (AI-triaging a flood
        // backlog) starves the other arms — but a flood is exactly when
        // per-tenant attribution must stay current (validated on test001: under
        // a k3s + rogue flood the narrative arm never ran, so the cache stayed
        // empty). A dedicated task is immune to the main loop's per-tick cost.
        // Self-rate-limited (maybe_refresh checks refresh_secs) and inert unless
        // `[tenancy] enabled`, so non-k8s hosts spawn nothing.
        if cfg.tenancy.enabled {
            let tcfg = cfg.tenancy.clone();
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(std::time::Duration::from_secs(
                    tcfg.refresh_secs.clamp(15, 3600),
                ));
                loop {
                    ticker.tick().await;
                    crate::tenancy::maybe_refresh(&tcfg).await;
                }
            });
        }

        loop {
            // Apply a live `/mode` change requested via Telegram on the previous
            // tick. Done here, in the loop that owns `cfg`, so the mutation is
            // borrow-clean and every subsequent enforcement read sees the new
            // mode. Also persist the two keys to agent.toml for restart
            // durability (best-effort; the in-memory flip already took effect).
            if let Some(mode) = crate::agent_context::take_and_apply_pending_mode(
                &mut cfg,
                &mut state.pending_mode_change,
                cli.config.as_deref(),
            ) {
                info!(
                    mode = ?mode,
                    responder_enabled = cfg.responder.enabled,
                    dry_run = cfg.responder.dry_run,
                    "guardian mode changed live via Telegram /mode"
                );
            }
            // Apply queued Settings changes (profile / sensitivity) the same way:
            // mutate the owned cfg + persist, and re-register the command menu
            // when the profile flips so the operator immediately sees the right
            // (lay vs technical) menu.
            if !state.pending_setting_changes.is_empty() {
                let changes = std::mem::take(&mut state.pending_setting_changes);
                let mut profile_flipped = false;
                for change in &changes {
                    if let Some(label) = crate::agent_context::apply_setting_change(
                        &mut cfg,
                        change,
                        cli.config.as_deref(),
                    ) {
                        if matches!(change, crate::SettingChange::Profile(_)) {
                            profile_flipped = true;
                        }
                        info!(change = %label, "Telegram setting applied live");
                    }
                }
                if profile_flipped {
                    if let Some(ref tg) = state.telegram_client {
                        tg.set_commands(cfg.telegram.is_simple_profile()).await;
                    }
                }
            }
            let shutdown = tokio::select! {
                _ = incident_ticker.tick() => {
                    crate::loops::fast_loop::run_incident_tick(
                        &cli.data_dir,
                        &mut cursor,
                        &cfg,
                        &mut state,
                        &advisory_cache,
                    ).await;
                    false
                }
                _ = narrative_ticker.tick() => {
                    match crate::loops::slow_loop::process_narrative_tick(
                        &cli.data_dir,
                        &mut cursor,
                        &cfg,
                        &mut state,
                    ).await {
                        Ok(n) => {
                            if n > 0 {
                                info!(new_events = n, "narrative tick");
                            }
                        }
                        Err(e) => {
                            state.telemetry.observe_error("narrative_tick");
                            warn!("narrative tick error: {e:#}");
                        }
                    }
                    // Tick notification pipeline — emit group summaries for
                    // groups that hit count threshold or expired windows.
                    {
                        let summaries = state.grouping_engine.tick();
                        if !summaries.is_empty() {
                            // Spec 005 Phase 8 — optional AI batch triage.
                            // When enabled, one AI call classifies every
                            // summary (URGENT / INFO / SUPPRESS); URGENT
                            // always gets through, SUPPRESS always drops,
                            // INFO falls back to the per-channel filter. On
                            // AI failure, classifications stay unset and the
                            // normal filter path runs — spec § fallback.
                            let batch_classes: Option<Vec<notification_pipeline::BatchClassification>> =
                                if cfg.ai.batch_triage {
                                    // Spec 029 PR-C.2: batch triage is a
                                    // classification task (incident group
                                    // → category label). Classify role.
                                    if let Some(provider) =
                                        state.ai_router.provider_for(crate::ai::Capability::Classify)
                                    {
                                        notification_pipeline::run_batch_triage(
                                            provider.as_ref(),
                                            &summaries,
                                        )
                                        .await
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                };
                            let tg_level = cfg.telegram.channel_notifications.notification_level;
                            let tg_summaries: Vec<String> = summaries
                                .iter()
                                .enumerate()
                                .filter(|(idx, s)| {
                                    use notification_pipeline::BatchClassification;
                                    match batch_classes.as_ref().and_then(|v| v.get(*idx)) {
                                        Some(BatchClassification::Urgent) => true,
                                        Some(BatchClassification::Suppress) => false,
                                        // Info or no triage: defer to normal filter.
                                        _ => {
                                            notification_pipeline::should_notify_summary(s, tg_level)
                                                && notification_pipeline::is_immediate_threat_summary(s)
                                        }
                                    }
                                })
                                .map(|(_, s)| s.format_html())
                                .collect();
                            if !tg_summaries.is_empty() {
                                if let Some(ref tg) = state.telegram_client {
                                    let digest = tg_summaries.join("\n");
                                    if let Err(e) = tg.send_raw_html(&digest).await {
                                        warn!("Telegram group summary failed: {e:#}");
                                    }
                                }
                            }
                        }
                        // Spec 005 T017: snapshot active groups to disk so the
                        // dashboard can serve /api/incident-groups without
                        // holding a lock on AgentState. Best-effort — failures
                        // are logged and never break the tick.
                        let snap = state.grouping_engine.snapshot_json();
                        let path = cli.data_dir.join("incident-groups.json");
                        if let Err(e) = std::fs::write(
                            &path,
                            serde_json::to_string(&snap).unwrap_or_else(|_| "{}".into()),
                        ) {
                            warn!(path = %path.display(), "incident-groups snapshot failed: {e}");
                        }
                    }

                    // Refresh operator IPs from active SSH sessions (every 30s).
                    // Expired sessions are removed so dynamic IPs don't stay protected forever.
                    if state.last_operator_refresh.elapsed() >= std::time::Duration::from_secs(30) {
                        crate::loops::slow_loop::refresh_operator_ips(
                            &mut state,
                            &cfg.allowlist,
                        );
                        state.last_operator_refresh = std::time::Instant::now();
                    }

                    // Hot-reload response rules from /etc/innerwarden/rules/event_pipeline/.
                    // This includes dashboard "Trust IP" entries: they are written
                    // as ordinary suppress_response/scope:ip rules into the same
                    // dir (see operator_trust.rs), so YamlResponseRules picks them
                    // up here and drops expired ones via the expires_at check.
                    {
                        let rules_dir = std::path::Path::new("/etc/innerwarden/rules/event_pipeline");
                        let yaml_rules = crate::allowlist::YamlResponseRules::load(rules_dir);
                        state.dynamic_trusted_ips = yaml_rules.trusted_ips;
                        state.dynamic_trusted_users = yaml_rules.trusted_users;
                        state.dynamic_trusted_processes = yaml_rules.trusted_processes;
                    }

                    // Hot-reload correlation rules from /etc/innerwarden/rules/correlation/.
                    // Re-reads YAML files every slow-loop tick (cheap when nothing
                    // changed; 68+ rule recompile when files mutate).
                    {
                        let rules_dir = std::path::Path::new("/etc/innerwarden/rules/correlation");
                        match crate::correlation_engine_yaml::load_rules_dir(rules_dir) {
                            Ok(new_rules) => {
                                let old_count = state.correlation_engine.rule_count();
                                let new_count = new_rules.len();
                                if new_count != old_count {
                                    tracing::info!(
                                        old = old_count,
                                        new = new_count,
                                        "correlation_engine: rule count changed, reloading"
                                    );
                                }
                                state.correlation_engine.replace_rules(new_rules);
                            }
                            Err(e) => tracing::warn!("correlation_engine reload failed: {e}"),
                        }
                    }

                    // Autoencoder nightly training — at 3 AM UTC.
                    //
                    // The training routine is synchronous and CPU-heavy: it
                    // reads tens of thousands of events from SQLite, builds
                    // feature windows, runs N epochs of gradient descent on
                    // the autoencoder, then writes the model. Production hang
                    // observed on 2026-04-25 03:00 UTC: running this inline
                    // in the async tick blocked the tokio main thread for
                    // the entire training duration; meanwhile other tasks
                    // (dashboard handlers holding `state.knowledge_graph`'s
                    // `std::sync::RwLock`, mesh ticker holding its own
                    // locks, the v2 src_ip backfill mid-transaction) all
                    // ended up in `futex_wait` cycles — classic AB-BA
                    // deadlock with no progress, 19 threads stuck.
                    //
                    // `block_in_place` tells the multi-thread tokio runtime
                    // "I'm about to do CPU/blocking work; transfer my
                    // workers." Other tokio tasks keep making progress on
                    // sibling worker threads. The training future is
                    // unchanged from the caller's view; only the runtime
                    // scheduling property differs. Requires a multi-thread
                    // runtime (we have one via `#[tokio::main]` default —
                    // single-thread would panic).
                    {
                        let hour = chrono::Utc::now().hour();
                        // Operator override for validation runs (tested 2026-04-25
                        // after the AB-BA deadlock at 03:00 UTC). Default 3 keeps
                        // production behavior unchanged. Setting to the current
                        // hour, restarting the agent, and observing one cycle
                        // proves the `block_in_place` wrapper above prevents the
                        // hang without waiting 24h for the natural trigger.
                        let trigger_hour: u32 = std::env::var("INNERWARDEN_AUTOENCODER_TRAIN_HOUR")
                            .ok()
                            .and_then(|s| s.parse::<u32>().ok())
                            .filter(|h| *h <= 23)
                            .unwrap_or(3);
                        if hour == trigger_hour {
                            let today_key = format!("anomaly_train:{}", chrono::Utc::now().format("%Y-%m-%d"));
                            if !state.store.has_cooldown(state_store::CooldownTable::Decision, &today_key) {
                                info!(trigger_hour, "autoencoder: triggering nightly training");
                                // Spec 062 Phase 6a: report how full the warden
                                // label corpus is. We do NOT consume it on-host
                                // yet (the autoencoder stays unsupervised, the
                                // warden ONNX is the shipped artifact) — this
                                // log is the honest signal that the channel is
                                // accumulating gold + weak labels for offline
                                // re-distillation.
                                {
                                    let today = chrono::Utc::now()
                                        .format("%Y-%m-%d")
                                        .to_string();
                                    let labels_today = crate::warden_labels::count_labels_for_date(
                                        &cli.data_dir,
                                        &today,
                                    );
                                    info!(
                                        labels_today,
                                        "warden_labels: human-label corpus size for today (offline re-distillation channel)"
                                    );
                                }
                                // Open a dedicated `Store` for the training run instead
                                // of borrowing `state.sqlite_store`. Training reads
                                // tens of thousands of events synchronously and can
                                // hold a connection from the agent's r2d2 pool
                                // (max_size = 4) for several minutes. On 2026-04-26
                                // 03:00 UTC this pinned a connection while the
                                // slow_loop's other SQLite writers (events_since
                                // cursor, KG snapshot save, response_lifecycle
                                // persist) tried to grab the remaining slots; pool
                                // exhaustion cascaded into a tokio runtime deadlock
                                // (18/19 threads in `futex_wait_queue`), the same
                                // pattern observed on 2026-04-25 02:59 UTC.
                                //
                                // A dedicated `Store` opens its own r2d2 pool
                                // against the same `innerwarden.db` file (SQLite
                                // WAL mode supports concurrent connections from
                                // separate pools — sensor + agent already do this
                                // routinely). The dedicated pool drops at the end
                                // of the match arm, freeing its connections.
                                //
                                // Same pattern `run_retrain_anomaly` (CLI
                                // `--retrain-anomaly`) has used since spec 016
                                // (boot.rs:124-148): isolated training,
                                // independent connection lifecycle.
                                match innerwarden_store::Store::open(&cli.data_dir) {
                                    Ok(dedicated_store) => {
                                        info!(
                                            "autoencoder: opening dedicated store for nightly training (isolated from slow_loop pool)"
                                        );
                                        let result = tokio::task::block_in_place(|| {
                                            state.anomaly_engine.train_nightly_with_store(
                                                Some(&dedicated_store),
                                            )
                                        });
                                        match result {
                                            Ok(()) => {
                                                info!(
                                                    maturity = format!("{:.2}", state.anomaly_engine.maturity),
                                                    cycles = state.anomaly_engine.training_cycles,
                                                    "autoencoder: training complete"
                                                );
                                                state.store.set_cooldown(
                                                    state_store::CooldownTable::Decision,
                                                    &today_key,
                                                    chrono::Utc::now(),
                                                );
                                            }
                                            Err(e) => warn!(error = %e, "autoencoder training failed"),
                                        }
                                        // dedicated_store drops here — its 4
                                        // r2d2 connections close, returning fd
                                        // budget to the OS.
                                    }
                                    Err(e) => {
                                        warn!(
                                            error = %e,
                                            "autoencoder: cannot open dedicated store, skipping nightly training"
                                        );
                                    }
                                }
                            }
                        }
                    }

                    // Defender brain daily retrain — at 3:30 AM UTC (after autoencoder at 3 AM).
                    // Brain retrain block removed: defender_brain replaced
                    // by SecureBERT classifier provider routed through the
                    // AI router. Local Warden Model inference happens in the
                    // hot path, no nightly retrain needed.

                    // Trim in-memory structures to prevent unbounded memory growth.
                    state.blocklist.trim_if_needed(10_000);
                    // 2026-05-08 (fix/cooldown-retention-matches-longest-semantic):
                    // each cooldown table gets its own retention horizon — the
                    // Decision table needs 24h to cover the repeat-offender
                    // 86400s cooldown_cutoff, the Notification table is fine
                    // at 2h because all notification windows are minutes-scale.
                    // Pre-fix the trim was 2h for both, which silently nuked
                    // repeat-offender's 24h cooldown rows after only 2h and
                    // re-fired the same /16 block every 2h until the IP
                    // dropped out of `ip_reputations`.
                    let now = chrono::Utc::now();
                    let decision_cutoff = now
                        - chrono::Duration::seconds(crate::DECISION_COOLDOWN_RETENTION_SECS);
                    let notification_cutoff = now
                        - chrono::Duration::seconds(crate::NOTIFICATION_COOLDOWN_RETENTION_SECS);
                    state
                        .store
                        .retain_cooldowns(state_store::CooldownTable::Decision, decision_cutoff);
                    state.store.retain_cooldowns(
                        state_store::CooldownTable::Notification,
                        notification_cutoff,
                    );
                    // Cap block_counts to 5000 entries
                    if state.store.block_counts_len() > 5000 {
                        state.store.clear_block_counts();
                    }
                    // Cap ip_reputations and persist to disk for dashboard
                    if state.ip_reputations.len() > 10000 {
                        // Keep only the top 5000 by reputation_score
                        let mut entries: Vec<_> = state.ip_reputations.drain().collect();
                        entries.sort_by(|a, b| b.1.reputation_score.partial_cmp(&a.1.reputation_score).unwrap_or(std::cmp::Ordering::Equal));
                        entries.truncate(5000);
                        state.ip_reputations = entries.into_iter().collect();
                    }
                    persist_ip_reputations(
                        &cli.data_dir,
                        &state.ip_reputations,
                        Some(&state.store),
                    );

                    // ── Safeguard: XDP TTL - expire old blocklist entries ──
                    //
                    // Only removes the local bookkeeping entry after the kernel
                    // command succeeds (or confirms the entry was already gone).
                    // Transient failures keep the local state so a subsequent
                    // tick retries — preventing drift between `xdp_block_times`
                    // and the actual blocklist BPF map.
                    {
                        let now_utc = chrono::Utc::now();
                        let expired_ips: Vec<String> = state.xdp_block_times
                            .iter()
                            .filter(|(_, (ts, ttl))| {
                                let cutoff = *ts + chrono::Duration::seconds(*ttl);
                                now_utc > cutoff
                            })
                            .map(|(ip, _)| ip.clone())
                            .collect();
                        for ip in &expired_ips {
                            // Skip IPs whose cleanup keeps failing for a
                            // NON-transient reason (e.g. the agent lacks the
                            // privilege to run `sudo bpftool`). They sit in an
                            // exponential backoff so we don't re-spawn sudo and
                            // re-log every 30s tick. Without this a single stuck
                            // entry produced 44k failed sudo-auths + 44k WARN
                            // lines in 7 days on a non-root deploy.
                            if let Some((_, next_retry)) = state.xdp_cleanup_backoff.get(ip) {
                                if now_utc < *next_retry {
                                    continue;
                                }
                            }
                            // Wave 4 (AUDIT-WAVE4-XDP-IPV6, Copilot review on
                            // PR #462): route through the shared helper so v4
                            // and v6 entries both reach the matching pin path.
                            // Pre-fix this only parsed `Ipv4Addr` and dropped
                            // every v6 entry as "poison", leaving the kernel
                            // V6 map populated forever after TTL expiry.
                            let Some((map_pin, key_args)) = crate::skills::builtin::xdp_blocklist_pin_for_ip(ip) else {
                                // Genuinely unparseable - drop from state to
                                // avoid a poison entry; can't act on kernel.
                                warn!(ip, "XDP cleanup: unparseable IP in xdp_block_times, dropping local entry");
                                state.xdp_block_times.remove(ip);
                                state.xdp_cleanup_backoff.remove(ip);
                                // Spec 037 PR-1: mirror the remove in SQLite so
                                // warm-cache on next boot does not resurrect the
                                // poison entry.
                                state.store.remove_xdp_block_time(ip);
                                continue;
                            };
                            let ttl_secs = state.xdp_block_times.get(ip).map(|(_, t)| *t).unwrap_or(0);
                            let mut argv: Vec<String> = vec![
                                "bpftool".into(),
                                "map".into(),
                                "delete".into(),
                                "pinned".into(),
                                map_pin.into(),
                                "key".into(),
                            ];
                            argv.extend(key_args);
                            let output = tokio::process::Command::new("sudo")
                                .args(&argv[..])
                                .output().await;
                            match output {
                                Ok(out) if out.status.success() => {
                                    state.xdp_block_times.remove(ip);
                                    state.xdp_cleanup_backoff.remove(ip);
                                    // Spec 037 PR-1: mirror remove in SQLite so
                                    // the warm-cache does not resurrect an
                                    // already-expired block on next boot.
                                    state.store.remove_xdp_block_time(ip);
                                    info!(ip, ttl_secs, "XDP adaptive TTL expired - removed from blocklist");
                                }
                                Ok(out) => {
                                    let stderr = String::from_utf8_lossy(&out.stderr);
                                    let lower = stderr.to_lowercase();
                                    // Same classifier as response_lifecycle: if the
                                    // entry is already gone, call it a success.
                                    let already_absent = lower.contains("no such")
                                        || lower.contains("not found")
                                        || lower.contains("does not exist");
                                    if already_absent {
                                        state.xdp_block_times.remove(ip);
                                        state.xdp_cleanup_backoff.remove(ip);
                                        // Spec 037 PR-1: same mirror reason.
                                        state.store.remove_xdp_block_time(ip);
                                        info!(ip, ttl_secs, "XDP cleanup: entry already absent in kernel map, local state cleared");
                                    } else if crate::skills::builtin::is_xdp_privilege_failure(&lower) {
                                        // Non-transient: the agent cannot run
                                        // `sudo bpftool` (no sudoers rule / no
                                        // tty / not root). Retrying every tick is
                                        // futile and floods the log + pam auth.
                                        // Back off exponentially and log only on
                                        // the FIRST failure and again once the
                                        // cap is reached — not every tick.
                                        let entry = state.xdp_cleanup_backoff.entry(ip.clone()).or_insert((0, now_utc));
                                        entry.0 = entry.0.saturating_add(1);
                                        let backoff = crate::skills::builtin::xdp_cleanup_backoff_secs(entry.0);
                                        entry.1 = now_utc + chrono::Duration::seconds(backoff);
                                        if entry.0 == 1 || backoff >= 3600 {
                                            warn!(
                                                ip,
                                                ttl_secs,
                                                consecutive_failures = entry.0,
                                                backoff_secs = backoff,
                                                stderr = %stderr.trim(),
                                                "XDP cleanup cannot proceed (agent lacks privilege to run bpftool) - backing off; entry kept for drift visibility. Block backend may be ufw/iptables, or run the agent as root for XDP TTL cleanup."
                                            );
                                        }
                                    } else {
                                        // Transient kernel/map drift - keep local
                                        // state and retry next tick as before.
                                        warn!(
                                            ip,
                                            ttl_secs,
                                            status = ?out.status,
                                            stderr = %stderr.trim(),
                                            "XDP cleanup FAILED - keeping local state to retry next tick (kernel/local drift protection)"
                                        );
                                    }
                                }
                                Err(e) => {
                                    // Spawn failure (e.g. bpftool/sudo binary
                                    // missing) is also non-transient - back off
                                    // instead of re-spawning every tick.
                                    let entry = state.xdp_cleanup_backoff.entry(ip.clone()).or_insert((0, now_utc));
                                    entry.0 = entry.0.saturating_add(1);
                                    let backoff = crate::skills::builtin::xdp_cleanup_backoff_secs(entry.0);
                                    entry.1 = now_utc + chrono::Duration::seconds(backoff);
                                    if entry.0 == 1 || backoff >= 3600 {
                                        warn!(
                                            ip,
                                            error = %e,
                                            consecutive_failures = entry.0,
                                            backoff_secs = backoff,
                                            "XDP cleanup: bpftool spawn failed - backing off; entry kept for drift visibility"
                                        );
                                    }
                                }
                            }
                        }
                    }

                    // ── Response Lifecycle: unified TTL cleanup ──
                    // Handles auto-revert for ufw, iptables, nftables (backends that
                    // didn't have TTL before). XDP/container/nginx/sudo still use
                    // their existing cleanup above; the lifecycle tracks them for
                    // dashboard visibility.
                    //
                    // State machine: stage_pending_reverts transitions Active→RevertPending
                    // (or restages RevertFailed with retry budget); we then execute each
                    // revert and report back via mark_reverted / mark_revert_failed.
                    // Entries are NEVER declared complete until the backend command has
                    // confirmed success (or been classified as already_absent). Orphaned
                    // entries — retries exhausted — are logged at WARN level; dashboards
                    // and Prometheus surface the drift.
                    {
                        let reverts = state.response_lifecycle.stage_pending_reverts();
                        let mut n_ok = 0usize;
                        let mut n_orphaned = 0usize;
                        for revert in &reverts {
                            match response_lifecycle::execute_revert(revert, cfg.responder.dry_run).await {
                                Ok(()) => {
                                    state.response_lifecycle.mark_reverted(&revert.id, "expired");
                                    n_ok += 1;
                                }
                                Err(err) => {
                                    let outcome = state
                                        .response_lifecycle
                                        .mark_revert_failed(&revert.id, err.clone());
                                    if let response_lifecycle::FailureOutcome::Orphaned {
                                        backend,
                                        target,
                                        last_error,
                                        ..
                                    } = outcome
                                    {
                                        n_orphaned += 1;
                                        // Surface is deliberately WARN log +
                                        // Prometheus counter + dashboard state,
                                        // not push notification. Orphaned means
                                        // "local/kernel state drift" — that's an
                                        // observability concern for a technical
                                        // operator watching logs/metrics, not an
                                        // interrupt-worthy pager event. Telegram
                                        // and Slack pushes are reserved for
                                        // incident-level signals.
                                        warn!(
                                            id = %revert.id,
                                            ?backend,
                                            %target,
                                            %last_error,
                                            "response ORPHANED — rule may still be active; check responses dashboard"
                                        );
                                    }
                                }
                            }
                        }
                        if n_ok > 0 || n_orphaned > 0 {
                            info!(
                                reverted = n_ok,
                                orphaned = n_orphaned,
                                "response lifecycle tick"
                            );
                        }
                        // 2026-05-02 audit B3: prune orphaned history
                        // entries older than 7 days. The auditor saw
                        // 17 orphaned responses sitting >48 h with no
                        // GC path. The 7-day window is generous —
                        // operators have time to investigate fresh
                        // orphans before they age out. Other
                        // completion reasons (expired / manual /
                        // already_absent) are unaffected; they are
                        // legitimate audit trail bounded only by the
                        // 1000-entry history cap.
                        const ORPHAN_GC_AGE_SECS: i64 = 7 * 24 * 3600;
                        state
                            .response_lifecycle
                            .gc_orphaned_responses(ORPHAN_GC_AGE_SECS);
                        // Two sinks, one struct-of-truth:
                        //   1. dashboard view (`to_json`) — feeds `/metrics`
                        //      and `/api/responses` which read `active_count`,
                        //      `state_counts.*`, `totals.*` from this shape.
                        //      History reversed + capped at 50 for display.
                        //   2. canonical persistence snapshot (`to_snapshot`,
                        //      v2) — feeds `load_snapshot` on the next boot.
                        //      Natural order, full history, preserves
                        //      `revert_handle` and `next_id`.
                        let view = state.response_lifecycle.to_json();
                        let view_path = cli.data_dir.join("responses.json");
                        if let Ok(data) = serde_json::to_string(&view) {
                            if let Some(ref sq) = state.sqlite_store {
                                if let Err(e) = sq.set_blob("responses", &data) {
                                    warn!("failed to write responses blob: {e}");
                                }
                            }
                            let _ = tokio::fs::write(&view_path, data).await;
                        }
                        let snapshot = state.response_lifecycle.to_snapshot();
                        let snapshot_path = cli.data_dir.join("responses.snapshot.json");
                        if let Ok(data) = serde_json::to_string(&snapshot) {
                            if let Some(ref sq) = state.sqlite_store {
                                if let Err(e) = sq.set_blob("responses_snapshot", &data) {
                                    warn!("failed to write responses_snapshot blob: {e}");
                                }
                            }
                            let _ = tokio::fs::write(&snapshot_path, data).await;
                        }
                    }

                    // ── Neural score → BPF map (Active Defence) ──
                    // Write the latest anomaly score to the kernel's NEURAL_SCORE map
                    // so the LSM hook can enforce ML-based decisions at wire speed.
                    #[cfg(target_os = "linux")]
                    {
                        let score = state.anomaly_engine.latest_score();
                        if score > 0.0 {
                            let score_fixed = (score * 65536.0) as i32; // Q16.16
                            let threshold_fixed = (0.75_f32 * 65536.0) as i32; // default 0.75
                            const NEURAL_SCORE_PIN: &str = "/sys/fs/bpf/innerwarden/neural_score";
                            if std::path::Path::new(NEURAL_SCORE_PIN).exists() {
                                // Write score (key 0)
                                let _ = tokio::process::Command::new("sudo")
                                    .args([
                                        "bpftool", "map", "update", "pinned", NEURAL_SCORE_PIN,
                                        "key", "0", "0", "0", "0",
                                        "value",
                                        &(score_fixed as u32 & 0xff).to_string(),
                                        &((score_fixed as u32 >> 8) & 0xff).to_string(),
                                        &((score_fixed as u32 >> 16) & 0xff).to_string(),
                                        &((score_fixed as u32 >> 24) & 0xff).to_string(),
                                        "any",
                                    ])
                                    .output()
                                    .await;
                                // Write threshold (key 1)
                                let _ = tokio::process::Command::new("sudo")
                                    .args([
                                        "bpftool", "map", "update", "pinned", NEURAL_SCORE_PIN,
                                        "key", "1", "0", "0", "0",
                                        "value",
                                        &(threshold_fixed as u32 & 0xff).to_string(),
                                        &((threshold_fixed as u32 >> 8) & 0xff).to_string(),
                                        &((threshold_fixed as u32 >> 16) & 0xff).to_string(),
                                        &((threshold_fixed as u32 >> 24) & 0xff).to_string(),
                                        "any",
                                    ])
                                    .output()
                                    .await;
                            }
                        }
                    }

                    // ── Safeguard: flush AbuseIPDB delayed report queue ──
                    // Defense-in-depth: even though `check_block_eligibility_with_safelist`
                    // refuses blocks on cloud-provider IPs, the queue can carry
                    // entries queued before the fix deployed. Reporting a
                    // Cloudflare edge to AbuseIPDB pollutes the public feed
                    // AND burns our 1k/day report quota — the operator email
                    // on 2026-04-18 ("You've exhausted your daily limit of
                    // 1,000 requests for report endpoint") was direct
                    // fallout of the CL-008 cascade. Filter one more time
                    // before sending.
                    {
                        let report_cutoff = chrono::Utc::now() - chrono::Duration::seconds(ABUSEIPDB_REPORT_DELAY_SECS);
                        let ready: Vec<_> = state.abuseipdb_report_queue
                            .iter()
                            .filter(|(_, _, _, ts)| *ts < report_cutoff)
                            .cloned()
                            .collect();
                        let today = chrono::Local::now()
                            .date_naive()
                            .format("%Y-%m-%d")
                            .to_string();
                        let daily_cap = cfg.abuseipdb.report_daily_cap;
                        // Plan every decision up-front in a pure helper so
                        // the full decision matrix (cloud safelist → dedup →
                        // cap) is unit-testable without a Tokio runtime or
                        // a live AbuseIPDB client. The slow loop here only
                        // keeps the I/O (HTTP call + commit write).
                        let outcomes = abuseipdb_report_budget::plan_queue_flush(
                            &ready,
                            state.sqlite_store.as_deref(),
                            cloud_safelist::identify_provider,
                            &today,
                            daily_cap,
                        );
                        if let Some(ref client) = state.abuseipdb {
                            // Top-5 #4 (AUDIT-WAVE-T5-4, 2026-05-06):
                            // forward the bool from `client.report()` so
                            // `dispatch_flush_outcomes` only consumes a
                            // daily-quota slot when AbuseIPDB returned 2xx.
                            // Pre-fix the closure swallowed the bool and
                            // a 5xx would still consume the slot.
                            abuseipdb_report_budget::dispatch_flush_outcomes(
                                outcomes,
                                state.sqlite_store.as_deref(),
                                |ip, categories, comment| async move {
                                    client.report(&ip, &categories, &comment).await
                                },
                            )
                            .await;
                        }
                        state.abuseipdb_report_queue.retain(|(_, _, _, ts)| *ts >= report_cutoff);
                    }

                    let removed = data_retention::cleanup(&cli.data_dir, &cfg.data);
                    if removed > 0 {
                        info!(removed, "data_retention: cleaned up old files");
                    }
                    let (fs_removed, fs_bytes) =
                        data_retention::cleanup_filestore(&cli.data_dir, &cfg.data);
                    if fs_removed > 0 {
                        info!(
                            files = fs_removed,
                            bytes = fs_bytes,
                            "data_retention: pruned filestore"
                        );
                    }

                    // Spec 030: compress warm-tier JSONL files past the
                    // `warm_gzip_days` threshold. Runs alongside the
                    // delete sweep (once per slow tick) so a long-idle
                    // agent catches up in one pass. The call is a no-op
                    // when `warm_gzip_days = 0`.
                    let (compressed, bytes_saved) =
                        data_retention::gzip_warm_jsonl(&cli.data_dir, &cfg.data);
                    if compressed > 0 {
                        info!(
                            compressed,
                            bytes_saved,
                            "data_retention: gzipped warm-tier files"
                        );
                    }

                    // ── SQLite maintenance (time-gated inside tick) ──
                    if let (Some(ref mut sched), Some(ref sq)) =
                        (&mut state.maintenance_scheduler, &state.sqlite_store)
                    {
                        let integrity_alerts = sched.tick(sq);
                        if !integrity_alerts.is_empty() {
                            for alert in &integrity_alerts {
                                warn!(alert = %alert, "DATABASE SECURITY ALERT");
                            }
                            if let Some(tg) = &state.telegram_client {
                                let msg = format!(
                                    "\u{1f6a8} <b>Database Security Alert</b>\n\n{}\n\n\
                                     <i>Possible tampering or corruption detected. \
                                     Investigate immediately.</i>",
                                    integrity_alerts
                                        .iter()
                                        .map(|a| format!("\u{2022} {a}"))
                                        .collect::<Vec<_>>()
                                        .join("\n")
                                );
                                if let Err(e) = tg.send_text_message(&msg).await {
                                    warn!("failed to send integrity alert: {e:#}");
                                }
                            }
                        }
                    }

                    // ── Memory housekeeping: cap unbounded HashMaps ──
                    {
                        const MAX_IP_REPUTATIONS: usize = 2000;
                        if state.ip_reputations.len() > MAX_IP_REPUTATIONS {
                            let mut entries: Vec<_> = state.ip_reputations.drain().collect();
                            entries.sort_by(|a, b| {
                                b.1.reputation_score
                                    .partial_cmp(&a.1.reputation_score)
                                    .unwrap_or(std::cmp::Ordering::Equal)
                            });
                            entries.truncate(MAX_IP_REPUTATIONS);
                            state.ip_reputations = entries.into_iter().collect();
                        }

                        // Expire pending Telegram confirmations older than 30 minutes
                        let confirm_cutoff =
                            chrono::Utc::now() - chrono::Duration::minutes(30);
                        state
                            .pending_confirmations
                            .retain(|_, (pc, _, _)| pc.created_at > confirm_cutoff);

                        // Expire pending honeypot choices past their deadline
                        let now_utc = chrono::Utc::now();
                        state
                            .pending_honeypot_choices
                            .retain(|_, choice| choice.expires_at > now_utc);

                        // ── Threat feed poll + save ──
                        if let Some(ref mut tf) = state.threat_feed {
                            tf.poll_feeds().await;
                            tf.save(&cli.data_dir, state.sqlite_store.as_deref());
                        }

                        // ── Pcap capture cooldown cleanup ──
                        state.pcap_capture.cleanup();

                        // ── Process-health self-observation ──
                        // Detects child-process leaks (e.g. tcpdump that
                        // never exits) at the service boundary instead of
                        // waiting for someone to notice on the host.
                        {
                            let snapshot = crate::process_health::ProcessHealth::snapshot();
                            if snapshot.looks_stuck() {
                                warn!(
                                    children = snapshot.children_total,
                                    oldest_age_secs = ?snapshot.oldest_child_age_secs,
                                    by_comm = ?snapshot.children_by_comm,
                                    "process_health: unusual child-process state; possible spawn leak"
                                );
                            }
                        }

                        // ── 2FA pending action expiry cleanup ──
                        state.two_factor_state.cleanup_expired();

                        // ── Baseline rate anomaly check + save ──
                        {
                            // Disambiguate auth_log silence: a drop that
                            // coincides with active firewall blocking is the
                            // agent dropping scanners before sshd logs them
                            // (benign), not silence-as-compromise.
                            let blocks_this_hour =
                                crate::decisions::count_block_ips_in_current_hour(
                                    &cli.data_dir,
                                    chrono::Utc::now(),
                                );
                            let rate_anomalies =
                                state.baseline.check_rate_anomalies(blocks_this_hour);
                            for anomaly in &rate_anomalies {
                                info!(
                                    anomaly_type = ?anomaly.anomaly_type,
                                    severity = ?anomaly.severity,
                                    "baseline rate anomaly: {}",
                                    anomaly.description
                                );
                                // 2026-05-03: surface rate anomalies on the
                                // dashboard's Baseline tab. observe_event-time
                                // anomalies already record themselves; these
                                // come from the periodic rate sweep so the
                                // record happens here.
                                state.baseline.record_anomaly(anomaly, None);
                            }
                            state.baseline.save(&cli.data_dir, state.sqlite_store.as_deref());
                        }

                        // ── Attacker intelligence consolidation (every 5 min) ──
                        const INTEL_INTERVAL_SECS: u64 = 300;
                        if should_run_periodic_tick(
                            state.last_intel_consolidation_at,
                            INTEL_INTERVAL_SECS,
                            !state.attacker_profiles.is_empty(),
                        ) {
                            // Backfill enrichment for profiles missing GeoIP/AbuseIPDB
                            incident_enrichment::backfill_enrichment(&mut state).await;
                            // DShield (ISC) community reputation — opt-in, read-only.
                            incident_enrichment::dshield_backfill(
                                &mut state,
                                cfg.dshield.enabled,
                            )
                            .await;
                            // Scan honeypot sessions for known attacker IPs
                            scan_honeypot_for_profiles(
                                &cli.data_dir,
                                &mut state.attacker_profiles,
                            );

                            attacker_intel::consolidation_tick(
                                &mut state.attacker_profiles,
                                &state.store,
                                &cli.data_dir,
                                state.sqlite_store.as_deref(),
                            );
                            state.last_intel_consolidation_at = Some(Instant::now());
                        }

                        // ── Feedback tracker tick (spec 005 Phase 7) ──
                        //
                        // Once per hour: any pending notification that has
                        // aged past 24h converts into an ignore event. Once
                        // a (detector, entity_type) key accumulates 3 ignores,
                        // future non-critical notifications are demoted.
                        {
                            let feedback_interval = std::time::Duration::from_secs(3_600);
                            let due = state
                                .last_feedback_tick_at
                                .map(|t| t.elapsed() >= feedback_interval)
                                .unwrap_or(true);
                            if due {
                                let events =
                                    state.feedback_tracker.tick(chrono::Utc::now());
                                if !events.is_empty() {
                                    if let Err(e) =
                                        notification_pipeline::feedback_store::append_many(
                                            &cli.data_dir,
                                            &events,
                                        )
                                    {
                                        warn!("feedback tick persist failed: {e:#}");
                                    }
                                }
                                state.last_feedback_tick_at = Some(Instant::now());
                            }
                        }

                        // ── Environment periodic census (spec 005 Phase 6) ──
                        //
                        // Re-profiles the environment every
                        // `census_interval_hours`, diffs against the stored
                        // profile, appends diffs to census-YYYY-MM-DD.jsonl, and
                        // emits incidents for suspicious additions (new human
                        // UID, new cron). Service drift is audit-only.
                        {
                            let interval = std::time::Duration::from_secs(
                                cfg.environment.census_interval_hours.saturating_mul(3600),
                            );
                            let due = state
                                .last_env_census_at
                                .map(|t| t.elapsed() >= interval)
                                .unwrap_or(true);
                            if due && cfg.environment.auto_profile && interval.as_secs() > 0 {
                                let host = std::env::var("HOSTNAME")
                                    .or_else(|_| {
                                        std::fs::read_to_string("/etc/hostname")
                                            .map(|s| s.trim().to_string())
                                    })
                                    .unwrap_or_else(|_| "unknown".to_string());
                                let outcome = environment_profile::run_census(
                                    &cli.data_dir,
                                    &cfg.environment,
                                    &state.environment_profile,
                                    &host,
                                );
                                if let Some(new_profile) = outcome.new_profile {
                                    state.environment_profile = new_profile;
                                }
                                if !outcome.incidents.is_empty() {
                                    if let Some(store) = state.sqlite_store.as_ref() {
                                        for inc in &outcome.incidents {
                                            if let Err(e) = store.insert_incident(inc) {
                                                warn!(
                                                    "census incident persist failed: {e:#}"
                                                );
                                            }
                                        }
                                    }
                                }
                                state.last_env_census_at = Some(Instant::now());
                            }
                        }

                        // Spec 044 Phase 2.2 (2026-05-09): refresh host
                        // posture every 10 min so operator changes
                        // (sshd_config edit, port opened, sudoers
                        // modified) are picked up before the daily
                        // briefing. The downgrade engine (Phase 3)
                        // refuses to demote based on a snapshot older
                        // than ~30 min — a 10 min cadence keeps the
                        // freshness margin while shell-out cost stays
                        // bounded.
                        {
                            const POSTURE_REFRESH_INTERVAL: std::time::Duration =
                                std::time::Duration::from_secs(10 * 60);
                            let due = state
                                .last_host_posture_at
                                .map(|t| t.elapsed() >= POSTURE_REFRESH_INTERVAL)
                                .unwrap_or(true);
                            if due {
                                state.host_posture =
                                    posture::refresh_and_save(&cli.data_dir);
                                state.last_host_posture_at = Some(Instant::now());
                            }
                        }

                        // Cap attacker profiles to 10,000 by risk score
                        const MAX_ATTACKER_PROFILES: usize = 10_000;
                        if state.attacker_profiles.len() > MAX_ATTACKER_PROFILES {
                            let mut entries: Vec<_> =
                                state.attacker_profiles.drain().collect();
                            entries.sort_by(|a, b| b.1.risk_score.cmp(&a.1.risk_score));
                            entries.truncate(MAX_ATTACKER_PROFILES);
                            state.attacker_profiles = entries.into_iter().collect();
                        }

                        // ── Monthly threat report auto-generation (1st of month) ──
                        {
                            let today = chrono::Local::now().date_naive();
                            if today.day() == 1 {
                                let prev_month = (today - chrono::Duration::days(1))
                                    .format("%Y-%m")
                                    .to_string();
                                if !threat_report::report_exists(&cli.data_dir, &prev_month) {
                                    let profiles = state.attacker_profiles.clone();
                                    let data_dir = cli.data_dir.clone();
                                    tokio::spawn(async move {
                                        match threat_report::generate_monthly(
                                            &data_dir,
                                            &prev_month,
                                            &profiles,
                                        ) {
                                            Ok(report) => {
                                                if let Err(e) =
                                                    threat_report::write_report(&report, &data_dir)
                                                {
                                                    warn!(
                                                        "monthly report write failed: {e:#}"
                                                    );
                                                } else {
                                                    info!(
                                                        month = %prev_month,
                                                        "monthly threat report generated"
                                                    );
                                                }
                                            }
                                            Err(e) => {
                                                warn!(
                                                    "monthly report generation failed: {e:#}"
                                                );
                                            }
                                        }
                                    });
                                }
                            }
                        }
                    }

                    false
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("SIGINT received - shutting down");
                    true
                }
                _ = crowdsec_ticker.tick() => {
                    if let Some(ref mut cs) = state.crowdsec {
                        crowdsec::sync_threat_list(cs).await;
                    }
                    false
                }
                _ = mesh_ticker.tick() => {
                    info!("mesh ticker fired");
                    if let Some(ref mut m) = state.mesh {
                        m.rediscover_if_needed().await;
                        let result = m.tick();
                        if !result.block_ips.is_empty() || m.staged_count() > 0 {
                            info!(staged = m.staged_count(), new_blocks = result.block_ips.len(), "mesh tick");
                        }
                        // Notify Telegram about new mesh blocks (gated).
                        for (ip, ttl) in &result.block_ips {
                            info!(ip, ttl, "mesh: new block from peer network");
                            state.blocklist.insert(ip.clone());
                            // Mesh blocks are always contained -> daily briefing only.
                            let ctx = notification_gate::NotificationContext::for_mesh_block();
                            let gate_counter = state.telemetry.gate_suppressed_counter();
                            let verdict = notification_gate::should_notify_with_counter(
                                &ctx,
                                gate_counter.as_ref(),
                            );
                            match verdict {
                                notification_gate::NotificationVerdict::SendNow => {
                                    if let Some(ref tg) = state.telegram_client {
                                        let msg = format!(
                                            "\u{1f310} <b>MESH NETWORK</b>\n\n\
                                             Peer node detected threat from <code>{ip}</code>\n\
                                             Action: blocked for {}h (auto-revert)",
                                            ttl / 3600
                                        );
                                        let tg = tg.clone();
                                        tokio::spawn(async move {
                                            let _ = tg.send_alert_html(&msg).await;
                                        });
                                    }
                                }
                                notification_gate::NotificationVerdict::DailyBriefingOnly => {
                                    *state.telegram_deferred.entry("mesh".to_string()).or_insert(0) += 1;
                                    let category = notification_gate::burst_category("mesh");
                                    if let Some(mut summary) = state
                                        .notification_burst_tracker
                                        .record_contained(category, Some(ip.as_str()))
                                    {
                                        let host = notification_gate::resolve_host_id(
                                            &cfg.agent.tags,
                                            &state.knowledge_graph,
                                        );
                                        summary.host = host.clone();
                                        if let Some(ref tg) = state.telegram_client {
                                            let msg = notification_gate::format_burst_summary(&host, &summary);
                                            let tg = tg.clone();
                                            tokio::spawn(async move {
                                                let _ = tg.send_alert_html(&msg).await;
                                            });
                                        }
                                    }
                                }
                                notification_gate::NotificationVerdict::Drop => {}
                            }
                        }
                        if !result.unblock_ips.is_empty() {
                            info!(
                                expired = result.unblock_ips.len(),
                                "mesh: TTL expired blocks removed"
                            );
                        }

                        // Spec 062 Phase 6b: apply inbound suppression advisories
                        // under THIS host's local second gate (corroborate-only,
                        // never originate). Logic lives in the unit-tested
                        // `apply_advisory_suppressions` helper.
                        let advisories = m.drain_advisory_suppressions();
                        if !advisories.is_empty() {
                            let applied = crate::mesh::apply_advisory_suppressions(
                                m,
                                &advisories,
                                state.sqlite_store.as_deref(),
                                cfg.learning.mesh_suppression_corroboration,
                                &cli.data_dir,
                                chrono::Utc::now(),
                            );
                            info!(
                                received = advisories.len(),
                                applied,
                                "mesh: drained suppression advisories (advisory-only, local-gated)"
                            );
                        }

                        m.persist().ok();
                    }
                    false
                }
                _ = firmware_ticker.tick() => {
                    // Diagnostic (2026-05-19): firmware_tick observed silent
                    // on Oracle prod for 13+ h despite cfg.firmware.enabled=true
                    // and binary containing all firmware_tick code paths. Log
                    // unconditionally so we can distinguish "arm never selected"
                    // from "selected but skipped" from "selected but emitted nothing".
                    info!(
                        enabled = cfg.firmware.enabled,
                        poll_secs = cfg.firmware.poll_secs,
                        "firmware_ticker.tick() fired"
                    );
                    if cfg.firmware.enabled {
                        firmware_tick::process_firmware_tick(&cli.data_dir, &cfg, &mut state)
                            .await;
                    }
                    false
                }
                _ = hypervisor_ticker.tick() => {
                    // Same diagnostic as firmware_ticker above (sister arm).
                    info!(
                        enabled = cfg.hypervisor.enabled,
                        poll_secs = cfg.hypervisor.poll_secs,
                        "hypervisor_ticker.tick() fired"
                    );
                    if cfg.hypervisor.enabled {
                        hypervisor_tick::process_hypervisor_tick(&cli.data_dir, &cfg, &mut state)
                            .await;
                    }
                    false
                }
                _ = sigterm.recv() => {
                    info!("SIGTERM received - shutting down");
                    true
                }
            };

            if shutdown {
                // Spec 036 PR-4: the honeypot listener is registered
                // in `state.task_group`, so the `shutdown()` below
                // cancels its token alongside every other migrated
                // task. No separate watch-channel send is needed —
                // the pre-PR-4 `always_on_shutdown_tx.send(true)`
                // that used to live here is gone.
                if let Some(w) = &mut state.decision_writer {
                    w.flush();
                }
                if let Some(w) = &mut state.telemetry_writer {
                    w.flush();
                }
                // Spec 036 PR-3: the first production behavior change
                // of the I-04 arc. TaskGroup tracks the Telegram
                // polling loop (PR-2) and every future migration;
                // `shutdown` cancels the shared token, closes the
                // tracker, and waits up to the deadline for tasks to
                // drain. The resulting `ShutdownReport` is surfaced
                // at `info!` (clean drain) or `warn!` (any
                // timed_out>0) so the operator log shows whether the
                // SIGTERM was honored within the window. Writers are
                // flushed BEFORE the drain so `decision_writer`'s
                // hash-chain gets its terminal fsync even if a
                // migrated task times out.
                let report = state.task_group.shutdown(GRACEFUL_SHUTDOWN_DEADLINE).await;
                log_shutdown_report(report);
                break;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn once_cli(data_dir: std::path::PathBuf) -> crate::Cli {
        crate::Cli {
            data_dir,
            config: None,
            once: true,
            report: false,
            playbook_replay: None,
            report_dir: None,
            dashboard: false,
            dashboard_bind: "127.0.0.1:8787".to_string(),
            tls_cert: None,
            tls_key: None,
            insecure_no_tls: false,
            dashboard_generate_password_hash: false,
            interval: 30,
            honeypot_sandbox_runner: false,
            honeypot_sandbox_spec: None,
            honeypot_sandbox_result: None,
            cleanup_015_graph_signal_quality: false,
            backfill_015_research_only: false,
            retrain_anomaly: false,
            backtest_anomaly: false,
            backtest_cutoff: None,
            validate_config_only: false,
        }
    }

    #[test]
    fn cleanup_015_requires_snapshot() {
        let dir = TempDir::new().expect("tempdir");
        let err = run_cleanup_015(dir.path()).expect_err("snapshot should be required");
        let msg = format!("{err:#}");
        assert!(msg.contains("No dated snapshot found"));
    }

    #[test]
    fn backfill_015_requires_snapshot() {
        let dir = TempDir::new().expect("tempdir");
        let err =
            run_backfill_015_research_only(dir.path()).expect_err("snapshot should be required");
        let msg = format!("{err:#}");
        assert!(msg.contains("No dated snapshot found"));
    }

    #[test]
    fn cleanup_015_creates_timestamped_backup_when_snapshot_exists() {
        let dir = TempDir::new().expect("tempdir");
        let snapshot_path = knowledge_graph::KnowledgeGraph::dated_snapshot_path(dir.path());
        let graph = knowledge_graph::KnowledgeGraph::new();
        graph
            .save_snapshot(&snapshot_path)
            .expect("save baseline snapshot");

        run_cleanup_015(dir.path()).expect("cleanup should succeed");

        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read dir")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .to_string()
            })
            .collect();
        assert!(
            entries.iter().any(|name| name.contains(".bak-015-")),
            "cleanup should create a .bak-015-* backup"
        );
    }

    #[test]
    fn backfill_015_creates_timestamped_backup_when_snapshot_exists() {
        let dir = TempDir::new().expect("tempdir");
        let snapshot_path = knowledge_graph::KnowledgeGraph::dated_snapshot_path(dir.path());
        let graph = knowledge_graph::KnowledgeGraph::new();
        graph
            .save_snapshot(&snapshot_path)
            .expect("save baseline snapshot");

        run_backfill_015_research_only(dir.path()).expect("backfill should succeed");

        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read dir")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .to_string()
            })
            .collect();
        assert!(
            entries
                .iter()
                .any(|name| name.contains(".bak-015-researchonly-")),
            "backfill should create a .bak-015-researchonly-* backup"
        );
    }

    #[test]
    fn retrain_anomaly_errors_on_empty_data_dir() {
        // Operator-triggered retrain must surface the training error back up
        // instead of exiting 0 and giving a false-positive "all done". An
        // empty data_dir has no events + no JSONL → train_nightly_with_store
        // returns "insufficient data" → run_retrain_anomaly must bubble that.
        let dir = TempDir::new().expect("tempdir");
        let cli = once_cli(dir.path().to_path_buf());
        let result = run_retrain_anomaly(&cli);
        assert!(result.is_err(), "empty dir must fail, got {result:?}");
        let msg = format!("{:#}", result.err().expect("err"));
        assert!(
            msg.contains("insufficient") || msg.contains("autoencoder"),
            "error message should mention training failure, got: {msg}"
        );
    }

    #[test]
    fn retrain_anomaly_writes_model_with_seeded_store() {
        // Happy path: when the SQLite store has enough events to form ≥100
        // windows, the one-shot flag trains a model and leaves it in
        // data_dir so the running agent picks it up on next tick.
        use chrono::Utc;
        use innerwarden_core::entities::EntityRef;
        use innerwarden_core::event::{Event, Severity};

        let dir = TempDir::new().expect("tempdir");
        let store = innerwarden_store::Store::open(dir.path()).expect("on-disk store");
        let kinds = [
            "file.read_access",
            "shell.command_exec",
            "network.outbound_connect",
            "http.request",
            "tcp_stream.ssh",
        ];
        let mut events = Vec::new();
        // 1000 events keeps the training slice above MIN_TRAIN_WINDOWS after
        // the 20% holdout split introduced in the percentile-scoring fix.
        for i in 0..1000 {
            let kind = kinds[i % kinds.len()];
            events.push(Event {
                ts: Utc::now(),
                host: "h".into(),
                source: "t".into(),
                kind: kind.into(),
                severity: Severity::Info,
                summary: "".into(),
                details: serde_json::json!({"src_ip": "1.2.3.4"}),
                tags: vec![],
                entities: vec![EntityRef::ip("1.2.3.4")],
            });
        }
        store
            .insert_events_batch(&events)
            .expect("seed events into on-disk store");
        // Drop the handle so run_retrain_anomaly can reopen without SQLite
        // lock contention.
        drop(store);

        let cli = once_cli(dir.path().to_path_buf());
        run_retrain_anomaly(&cli).expect("retrain should succeed on a populated store");
        assert!(
            dir.path().join("anomaly-model.bin").exists(),
            "retrain must produce anomaly-model.bin"
        );
    }

    #[tokio::test]
    async fn run_agent_once_boots_with_empty_data_dir() {
        let dir = TempDir::new().expect("tempdir");
        let cli = once_cli(dir.path().to_path_buf());
        let result = run_agent(cli).await;
        assert!(result.is_ok(), "run_agent once-mode failed: {result:?}");
    }

    #[tokio::test]
    async fn run_agent_report_mode_generates_trial_report_files() {
        let dir = TempDir::new().expect("tempdir");
        let mut cli = once_cli(dir.path().to_path_buf());
        cli.report = true;
        cli.once = false;

        let result = run_agent(cli).await;
        assert!(result.is_ok(), "run_agent report-mode failed: {result:?}");
    }

    #[tokio::test]
    async fn run_agent_once_with_dashboard_enabled() {
        let dir = TempDir::new().expect("tempdir");
        let mut cli = once_cli(dir.path().to_path_buf());
        cli.dashboard = true;
        cli.dashboard_bind = "127.0.0.1:0".to_string();

        let result = run_agent(cli).await;
        assert!(
            result.is_ok(),
            "run_agent dashboard once-mode failed: {result:?}"
        );
    }

    /// Pin the four-corner truth table of `should_run_periodic_tick`:
    /// (no prior tick × any-work) and (elapsed × any-work). The
    /// "no prior tick" arm is the boot path — extracting this helper
    /// from inline let bindings in the slow-loop tick was prompted by
    /// the boot.rs coverage push (PR #486 follow-up); the assertions
    /// below pin the post-extraction contract that the slow-loop
    /// callers now depend on.
    #[test]
    fn should_run_periodic_tick_truth_table() {
        // Boot path: no prior tick yet, work is empty → still skip
        // (would have been a wasted no-op tick).
        assert!(!should_run_periodic_tick(None, 300, false));

        // Boot path with work present → run.
        assert!(should_run_periodic_tick(None, 300, true));

        // Recent prior tick (well under interval) + work → skip.
        // Pin the time gate.
        let recent = std::time::Instant::now();
        assert!(!should_run_periodic_tick(Some(recent), 300, true));

        // Prior tick has elapsed past the interval, no work → skip.
        // Pin the work gate (the second condition the inline code
        // used to enforce separately at the call site).
        let long_ago = std::time::Instant::now()
            .checked_sub(std::time::Duration::from_secs(600))
            .expect("instant arithmetic");
        assert!(!should_run_periodic_tick(Some(long_ago), 300, false));

        // Prior tick has elapsed past the interval AND work present
        // → run.
        assert!(should_run_periodic_tick(Some(long_ago), 300, true));
    }

    /// Bug 4 follow-up coverage anchor (2026-05-07): exercise the
    /// `cli.cleanup_015_graph_signal_quality` dispatch branch of
    /// `run_agent`. The branch returns the underlying error verbatim
    /// when no snapshot exists. Pins the dispatch wiring (without a
    /// snapshot the function bails with "No dated snapshot found").
    #[tokio::test]
    async fn run_agent_dispatches_cleanup_015_flag() {
        let dir = TempDir::new().expect("tempdir");
        let mut cli = once_cli(dir.path().to_path_buf());
        cli.cleanup_015_graph_signal_quality = true;
        let err = run_agent(cli)
            .await
            .expect_err("empty data_dir must surface the snapshot-missing error");
        assert!(format!("{err:#}").contains("No dated snapshot"));
    }

    /// Bug 4 follow-up coverage anchor: same as above for the
    /// `backfill_015_research_only` dispatch branch.
    #[tokio::test]
    async fn run_agent_dispatches_backfill_015_flag() {
        let dir = TempDir::new().expect("tempdir");
        let mut cli = once_cli(dir.path().to_path_buf());
        cli.backfill_015_research_only = true;
        let err = run_agent(cli)
            .await
            .expect_err("empty data_dir must surface the snapshot-missing error");
        assert!(format!("{err:#}").contains("No dated snapshot"));
    }

    /// Bug 4 follow-up coverage anchor: exercise the
    /// `cli.retrain_anomaly` dispatch branch of `run_agent`. With an
    /// empty data_dir the underlying `run_retrain_anomaly` returns
    /// "insufficient data"; what matters here is that `run_agent`
    /// routes the flag at all (the flag dispatch was previously
    /// uncovered because the standalone function tests bypassed
    /// `run_agent`).
    #[tokio::test]
    async fn run_agent_dispatches_retrain_anomaly_flag() {
        let dir = TempDir::new().expect("tempdir");
        let mut cli = once_cli(dir.path().to_path_buf());
        cli.retrain_anomaly = true;
        let err = run_agent(cli).await.expect_err("empty dir must fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("insufficient") || msg.contains("autoencoder"),
            "should surface training error, got: {msg}"
        );
    }

    /// Bug 4 follow-up coverage anchor: report-mode WITH a
    /// `report_dir` set hits the `create_dir_all` branch of
    /// `run_agent`'s report dispatch (the existing
    /// `run_agent_report_mode_generates_trial_report_files` test
    /// passes `report_dir = None` so the Some-branch was uncovered).
    #[tokio::test]
    async fn run_agent_report_mode_with_explicit_report_dir_creates_it() {
        let dir = TempDir::new().expect("tempdir");
        let report_out = dir.path().join("reports");
        let mut cli = once_cli(dir.path().to_path_buf());
        cli.report = true;
        cli.once = false;
        cli.report_dir = Some(report_out.clone());
        let result = run_agent(cli).await;
        assert!(result.is_ok(), "report-mode must succeed: {result:?}");
        assert!(
            report_out.exists(),
            "run_agent must create the configured report_dir"
        );
    }

    /// Bug 4 follow-up coverage anchor (2026-05-07): the four
    /// run_agent integration tests above all use `cli.once = true`,
    /// which short-circuits the entire `else` branch of the
    /// once/non-once split. That branch contains 700+ lines of
    /// orchestration: telegram polling spawn, honeypot always-on,
    /// kill-chain inline, DNA inline, mesh listener, threat-feed
    /// init, and the slow-loop `tokio::select!` block — i.e. the
    /// production hot path for a long-running agent. Without an
    /// integration test exercising that branch the file's line
    /// coverage stalls at the once-mode floor (~34%).
    ///
    /// Approach: drive `run_agent` with `cli.once = false` and the
    /// feature-rich config used by the once-mode test below, but
    /// wrap it in a `tokio::time::timeout` so the test cancels the
    /// future after the spawn phase completes. The timeout drop
    /// propagates to tokio's runtime, aborts the slow-loop, and
    /// returns. We only assert the run did not panic — coverage of
    /// the spawn paths is the actual deliverable.
    ///
    /// Multi-thread runtime is required because honeypot-always-on
    /// uses `block_in_place` for the AbuseIPDB lookup, which panics
    /// on the single-thread current-thread runtime that
    /// `#[tokio::test]` defaults to.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn run_agent_non_once_spawns_orchestration_paths() {
        let dir = TempDir::new().expect("tempdir");
        let cfg_path = dir.path().join("agent.toml");
        let mut cfg_file = std::fs::File::create(&cfg_path).expect("create config");
        // Same feature-rich config shape as the once-mode test below,
        // but with [honeypot] mode=always_on so the non-once branch's
        // honeypot spawn fires (the once test cannot reach that code).
        writeln!(
            cfg_file,
            r#"
[ai]
enabled = true
provider = "ollama"
model = "llama3.2"
base_url = "http://127.0.0.1:11434"

[responder]
enabled = true
dry_run = true
block_backend = "ufw"
allowed_skills = ["block-ip-ufw", "honeypot", "suspend-user-sudo", "kill-process", "block-container"]

[telegram]
enabled = false
bot_token = ""
chat_id = ""

[slack]
enabled = true
webhook_url = ""

[cloudflare]
enabled = true
api_token = ""
zone_id = ""

[abuseipdb]
enabled = false
api_key = ""

[crowdsec]
enabled = true

[geoip]
enabled = true

[fail2ban]
enabled = true

[mesh]
enabled = true
bind = "127.0.0.1:0"
peers = []

[threat_feeds]
ioc_feed_urls = []

[webhook]
enabled = true
url = "http://127.0.0.1:9/hooks"

[honeypot]
mode = "always_on"
port = 0
bind_addr = "127.0.0.1"
ssh_max_auth_attempts = 1
interaction = "reject"
"#
        )
        .expect("write config");

        // Seed a minimal events JSONL so the slow-loop's narrative
        // tick has something to read (covers the
        // `events.is_empty() == false` branch and the downstream
        // ingest paths).
        let today = chrono::Utc::now().format("%Y-%m-%d");
        let events_path = dir.path().join(format!("events-{today}.jsonl"));
        std::fs::write(
            &events_path,
            r#"{"ts":"2026-05-07T00:00:00Z","host":"h","source":"t","kind":"shell.command_exec","severity":"Info","summary":"","details":{"src_ip":"203.0.113.1"}}
{"ts":"2026-05-07T00:00:01Z","host":"h","source":"t","kind":"network.outbound_connect","severity":"Info","summary":"","details":{"src_ip":"203.0.113.1"}}
"#,
        )
        .expect("seed events");
        // Seed a minimal incidents JSONL so the grouping engine has
        // input on the slow-loop's first tick (covers the non-empty
        // group-summary path).
        let incidents_path = dir.path().join(format!("incidents-{today}.jsonl"));
        std::fs::write(
            &incidents_path,
            r#"{"ts":"2026-05-07T00:00:00Z","host":"h","incident_id":"ssh_bruteforce:1","severity":"Medium","title":"SSH brute","summary":"","tags":["ssh_bruteforce"],"entities":[{"r#type":"Ip","value":"203.0.113.1"}],"evidence":{},"recommended_checks":[]}
"#,
        )
        .expect("seed incidents");

        let mut cli = once_cli(dir.path().to_path_buf());
        cli.config = Some(cfg_path);
        cli.once = false;
        // Dashboard on a random local port — exercises the dashboard
        // spawn block (lines 423-538) AND its serve body in non-once
        // mode where the spawned task gets polled long enough to start.
        cli.dashboard = true;
        cli.dashboard_bind = "127.0.0.1:0".to_string();
        cli.insecure_no_tls = true;
        // Fast interval so the slow-loop body fires multiple times
        // within the timeout window.
        cli.interval = 1;

        let data_dir = dir.path().to_path_buf();

        // 8s budget: enough to clear the synchronous spawn block,
        // let the slow-loop tick several times (interval=1s), and
        // fire the per-tick paths (narrative ingest, grouping engine
        // tick, snapshot persist, allowlist hot-reload, operator IPs
        // refresh). Short enough that the overall workspace test
        // run is not noticeably slower.
        // Run the agent loop until the grouping-engine tick produces its
        // on-disk side effect, rather than sleeping a fixed budget.
        // `run_agent` never returns on its own, so the old
        // `timeout(8s, run_agent)` ALWAYS burned the full 8s AND was flaky
        // on slower hardware where the slow-loop tick had not landed within
        // that window (observed failing 2 of 3 runs in isolation on a slow
        // box). Poll for the file and finish the instant it appears, with a
        // generous 30s ceiling so a loaded CI box still passes
        // deterministically. The loop is meant to run forever, so if
        // `run_agent` returns/panics on its own first, that is the bug we
        // surface.
        //
        // `incident-groups.json` is written on every grouping-engine tick
        // (boot.rs:1527). Its presence proves the slow-loop select! arm
        // fired and the group-snapshot path executed end-to-end.
        let groups_snapshot = data_dir.join("incident-groups.json");
        let poll_target = groups_snapshot.clone();
        let wait_for_snapshot = async {
            loop {
                if poll_target.exists() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        };
        let outcome = tokio::select! {
            biased;
            r = run_agent(cli) => Err(format!("{r:?}")),
            res = tokio::time::timeout(std::time::Duration::from_secs(30), wait_for_snapshot) => Ok(res.is_ok()),
        };
        match outcome {
            Err(early) => {
                panic!("run_agent must keep running until cancelled — got early return: {early}")
            }
            Ok(false) => panic!(
                "slow-loop must write incident-groups.json within 30s — \
                 missing file means the grouping-engine tick never executed"
            ),
            Ok(true) => {}
        }

        let groups_body = std::fs::read_to_string(&groups_snapshot).expect("read snapshot");
        assert!(
            groups_body.starts_with('{') || groups_body.starts_with('['),
            "incident-groups.json must be JSON, got: {groups_body:.80}"
        );
        // The dashboard reads this file directly; if it's not valid
        // JSON the dashboard's /api/incident-groups endpoint breaks
        // for the operator.
        serde_json::from_str::<serde_json::Value>(&groups_body)
            .expect("incident-groups.json must parse as JSON");

        // 2) After 8s with the dashboard enabled, the SQLite store
        //    file must be open and on disk. `Store::open` is called
        //    early in run_agent (boot.rs:315) and creates
        //    innerwarden.db inside data_dir. Confirms the SQLite
        //    init path executed end-to-end (it can fail silently
        //    when the data_dir is not writable; this assertion catches
        //    the silent-fail regression where slot logs "sqlite store
        //    unavailable" but the run otherwise looks healthy).
        assert!(
            data_dir.join("innerwarden.db").exists(),
            "Store::open must materialise innerwarden.db on first boot"
        );
    }

    #[tokio::test]
    async fn run_agent_once_with_feature_rich_config_exercises_optional_paths() {
        let dir = TempDir::new().expect("tempdir");
        let cfg_path = dir.path().join("agent.toml");
        let mut cfg_file = std::fs::File::create(&cfg_path).expect("create config");
        writeln!(
            cfg_file,
            r#"
[ai]
enabled = true
provider = "ollama"
model = "llama3.2"
base_url = "http://127.0.0.1:11434"

[responder]
enabled = true
dry_run = true
block_backend = "ufw"
allowed_skills = ["block-ip-ufw", "honeypot", "suspend-user-sudo", "kill-process", "block-container"]

[telegram]
enabled = true
bot_token = "bot-token"
chat_id = "1234"
dev_mode = true

[slack]
enabled = true
webhook_url = ""

[cloudflare]
enabled = true
api_token = ""
zone_id = ""

[abuseipdb]
enabled = true
api_key = ""

[crowdsec]
enabled = true

[geoip]
enabled = true

[fail2ban]
enabled = true

[mesh]
enabled = true
bind = "127.0.0.1:0"
peers = []

[threat_feeds]
ioc_feed_urls = ["https://example.invalid/ioc-feed.txt"]

[webhook]
enabled = true
url = "http://127.0.0.1:9/hooks"
"#
        )
        .expect("write config");

        let mut cli = once_cli(dir.path().to_path_buf());
        cli.config = Some(cfg_path);

        let result = run_agent(cli).await;
        assert!(
            result.is_ok(),
            "run_agent feature-rich config failed: {result:?}"
        );
    }

    // ── build_primary_provider ───────────────────────────────────────

    #[test]
    fn build_primary_provider_returns_none_when_disabled() {
        let mut cfg = crate::config::AiConfig::default();
        cfg.enabled = false;
        assert!(build_primary_provider(&cfg, "ufw").is_none());
    }

    #[test]
    fn build_primary_provider_returns_none_on_unknown_provider() {
        // `provider = "this-does-not-exist"` makes `ai::build_provider`
        // return `Err`, which `build_primary_provider` swallows into
        // `None` after logging. Guards against accidentally turning the
        // build error into a panic.
        let mut cfg = crate::config::AiConfig::default();
        cfg.enabled = true;
        cfg.provider = "this-does-not-exist".into();
        assert!(build_primary_provider(&cfg, "ufw").is_none());
    }

    #[test]
    fn build_primary_provider_returns_some_for_ollama_default() {
        // Ollama's `build_provider` does not require a network connection
        // at construction time — it just stores the base URL. So a
        // default Ollama config produces a real provider handle without
        // tests needing a running ollama server.
        let mut cfg = crate::config::AiConfig::default();
        cfg.enabled = true;
        cfg.provider = "ollama".into();
        assert!(build_primary_provider(&cfg, "ufw").is_some());
    }

    #[test]
    fn build_primary_provider_accepts_iptables_backend_signature() {
        // Top-5 #3 anchor (AUDIT-WAVE-T5-3, 2026-05-06): the
        // `block_backend` parameter must reach build_provider so the
        // LocalClassifier branch picks up the operator-configured
        // firewall variant. Pre-fix the signature did not even accept
        // it - the classifier's skill_id was hardcoded to
        // `block-ip-ufw`. We can't observe the classifier's internal
        // field from this layer (no local-classifier feature on stub
        // builds); the variant observation lives next to
        // `build_action_from_prediction` in `local_classifier.rs::tests`.
        // This anchor pins the call shape.
        let mut cfg = crate::config::AiConfig::default();
        cfg.enabled = true;
        cfg.provider = "ollama".into();
        assert!(build_primary_provider(&cfg, "iptables").is_some());
    }

    // ─────────────────────────────────────────────────────────────────
    // Spec 036 PR-2 migration anchors — telegram-polling → TaskGroup
    // ─────────────────────────────────────────────────────────────────
    //
    // These tests mirror the `tokio::select!` pattern at the migrated
    // spawn site above (grep for `state.task_group.spawn("telegram-polling"`
    // in the non-once branch of run_agent). They exercise the wrapper
    // structure — NOT `TelegramClient::run_polling` itself, which has
    // six dedicated tests in `crates/agent/src/telegram/client.rs` and
    // must not be disturbed by this migration. The migration guarantee
    // these tests anchor: the polling task (a) exits promptly when the
    // TaskGroup's token is cancelled, and (b) exits naturally when
    // `run_polling` returns on its own (error path / connection drop).

    #[tokio::test]
    async fn telegram_polling_wrapper_exits_promptly_on_token_cancel() {
        use std::time::Duration;

        let tg = crate::task_group::TaskGroup::new();
        let token = tg.token();

        // Stand-in for `tg_clone.run_polling(approval_tx)` — a future
        // that would loop forever on its own. Observation of
        // `token.cancelled()` at the wrapper level is what lets the
        // outer task terminate without touching `run_polling`.
        tg.spawn("telegram-polling", async move {
            tokio::select! {
                _ = std::future::pending::<()>() => {
                    // `run_polling` substitute: never completes on its own.
                    unreachable!("pending() must not resolve");
                }
                _ = token.cancelled() => {
                    // Normal shutdown path.
                }
            }
        })
        .expect("spawn under fresh group");

        // 50 ms of work followed by a shutdown with a generous deadline.
        // The polling wrapper must exit via the `cancelled()` arm almost
        // immediately — the test fails if shutdown times out.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let report = tg.shutdown(Duration::from_secs(1)).await;
        assert_eq!(report.total, 1);
        assert_eq!(
            report.joined, 1,
            "wrapper must observe cancellation and exit within deadline"
        );
        assert_eq!(report.timed_out, 0);
    }

    #[tokio::test]
    async fn telegram_polling_wrapper_exits_when_inner_future_resolves() {
        use std::time::Duration;

        let tg = crate::task_group::TaskGroup::new();
        let token = tg.token();

        // Stand-in: `run_polling` returns on its own (e.g., the
        // connection dropped and the polling loop bubbled an error).
        // The wrapper must propagate that exit without needing a cancel.
        tg.spawn("telegram-polling", async move {
            tokio::select! {
                _ = async { /* returns immediately */ } => {
                    // `run_polling` substitute: resolves right away.
                }
                _ = token.cancelled() => {
                    unreachable!("cancelled() arm must lose the race");
                }
            }
        })
        .expect("spawn under fresh group");

        // Task should be gone almost instantly — no cancel was sent.
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(
            tg.len(),
            0,
            "wrapper must have exited via the inner-future arm already"
        );

        // Shutdown on an empty group is a no-op and must not panic.
        let report = tg.shutdown(Duration::from_millis(50)).await;
        assert_eq!(report.total, 0);
    }

    // ─────────────────────────────────────────────────────────────────
    // Spec 036 PR-3 — SIGTERM handler + task_group.shutdown() wiring
    // ─────────────────────────────────────────────────────────────────
    //
    // The signal-listener side of this wiring (SIGTERM/SIGINT select!
    // arms) is pre-existing in `run_agent` and lands its exit via the
    // same `if shutdown { ... break; }` block we now extended. Signal
    // delivery itself is hard to unit-test without spawning a child
    // process, so that path is covered by operator-run canary.
    //
    // What IS unit-tested here is the operator-visibility contract
    // the shutdown path introduces: when `shutdown()` returns a
    // report, the boot loop must log at WARN if any task timed out,
    // and INFO otherwise. Those are the two log-level transitions an
    // operator reads during a deploy to decide whether the shutdown
    // was honored — a regression that flips them silently would
    // mask abandoned tasks under a calm-looking INFO line.

    #[test]
    fn summarize_shutdown_emits_info_level_when_all_tasks_joined() {
        // Happy path: every task drained within the deadline. Log
        // must be INFO — a WARN here would cry-wolf the operator
        // every clean SIGTERM.
        let report = crate::task_group::ShutdownReport {
            total: 3,
            joined: 3,
            timed_out: 0,
        };
        let (level, msg) = summarize_shutdown(report);
        assert_eq!(level, tracing::Level::INFO);
        assert!(
            msg.contains("drained 3 task(s) cleanly"),
            "message must describe the clean-drain outcome: got {msg:?}"
        );
    }

    #[test]
    fn summarize_shutdown_emits_warn_level_when_any_task_timed_out() {
        // Degraded path: at least one task ignored cancellation or
        // was mid-IO when the deadline elapsed. Log must be WARN —
        // a silent INFO here would hide abandoned tasks from
        // post-deploy log audits.
        let report = crate::task_group::ShutdownReport {
            total: 5,
            joined: 3,
            timed_out: 2,
        };
        let (level, msg) = summarize_shutdown(report);
        assert_eq!(level, tracing::Level::WARN);
        assert!(
            msg.contains("abandoned 2 of 5"),
            "message must name both timed_out and total: got {msg:?}"
        );
        assert!(
            msg.contains("joined: 3"),
            "message must also surface the joined count: got {msg:?}"
        );
    }

    #[test]
    fn summarize_shutdown_handles_empty_group_cleanly() {
        // Edge case: SIGTERM arrives before any migrated spawn has
        // registered. Zero tasks, zero timed_out → INFO with a
        // trivially-phrased message. Guards against a "drained 0
        // tasks" log becoming a sarcastic-looking WARN.
        let report = crate::task_group::ShutdownReport {
            total: 0,
            joined: 0,
            timed_out: 0,
        };
        let (level, _msg) = summarize_shutdown(report);
        assert_eq!(
            level,
            tracing::Level::INFO,
            "empty group must not be flagged as degraded shutdown"
        );
    }

    #[tokio::test]
    async fn log_shutdown_report_runs_without_panic_on_both_outcomes() {
        // Belt-and-suspenders: the dispatcher between the returned
        // Level and the actual `tracing::info!`/`tracing::warn!`
        // macros is the one place summarize_shutdown's verdict gets
        // plumbed. A future refactor that forgets the WARN arm
        // silently misdirects the log — running both paths here
        // guards against a compile-time `match` regression.
        log_shutdown_report(crate::task_group::ShutdownReport {
            total: 1,
            joined: 1,
            timed_out: 0,
        });
        log_shutdown_report(crate::task_group::ShutdownReport {
            total: 2,
            joined: 0,
            timed_out: 2,
        });
        // If we reach here without panic, both branches are safe.
    }

    // ── Wave 9d (2026-05-04) anchors — build provenance ──────────────────
    //
    // Wave 9d root cause: a fix merged to `main` for hours was not in the
    // binary running on prod because `cargo build --release` ran from a
    // stale source tree. The agent restarted "clean" and the operator
    // believed the fix was live. 1000+ false-positive correlation chains
    // continued firing for two days before anyone noticed.
    //
    // The anchor is two-sided:
    //   - `crates/agent/build.rs` bakes `INNERWARDEN_BUILD_COMMIT` +
    //     `INNERWARDEN_BUILD_DIRTY` into the binary so the running source
    //     can be verified post-deploy.
    //   - `scripts/deploy-prod.sh` refuses to deploy when the remote
    //     checkout is behind `origin/main`.
    //
    // These tests pin the env-var contract at compile time so a future
    // contributor cannot remove `build.rs` (or rename the env vars)
    // without the boot-log macro failing to compile.

    #[test]
    fn build_commit_env_is_set_and_well_formed() {
        // env! is evaluated at compile time. If `crates/agent/build.rs`
        // does not emit `cargo:rustc-env=INNERWARDEN_BUILD_COMMIT=...`
        // this test does not even build, which is the strongest possible
        // anchor against accidental removal.
        let sha = env!("INNERWARDEN_BUILD_COMMIT");
        assert!(
            !sha.is_empty(),
            "INNERWARDEN_BUILD_COMMIT must not be empty"
        );
        // Either a hex SHA prefix (real git checkout) or the explicit
        // `unknown` fallback that build.rs emits when git is unavailable
        // (vendored sources, source tarball, CI image without `.git`).
        // Reject anything else - the boot log surfaces this verbatim and
        // an arbitrary string would mislead the operator at incident time.
        let valid =
            sha == "unknown" || (sha.len() >= 7 && sha.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(
            valid,
            "INNERWARDEN_BUILD_COMMIT={sha:?} must be a hex SHA prefix or the literal \"unknown\""
        );
    }

    #[test]
    fn build_dirty_env_is_a_canonical_bool_string() {
        // `INNERWARDEN_BUILD_DIRTY` is consumed by the boot log as a
        // tracing field, so the value must be a stable canonical form -
        // the operator greps for `build_dirty=true` to find binaries
        // built from a dirty working tree.
        let dirty = env!("INNERWARDEN_BUILD_DIRTY");
        assert!(
            dirty == "true" || dirty == "false",
            "INNERWARDEN_BUILD_DIRTY={dirty:?} must be exactly \"true\" or \"false\""
        );
    }

    /// Wave 4 (AUDIT-WAVE4-XDP-IPV6) anchor: the boot-loop adaptive
    /// XDP TTL cleanup path (the actual prod path, not the
    /// `xdp_unblock_ip` helper) must dispatch IPv6 entries to
    /// `BLOCKLIST_V6_PIN`. Pre-fix it parsed only Ipv4Addr and
    /// dropped every v6 entry as "poison", leaving the kernel V6
    /// map populated forever. Caught by Copilot review on PR #462.
    ///
    /// Pin via source-grep (same pattern as the `js_*` dashboard
    /// anchors) because the TTL loop is buried inside a 1500-line
    /// async fn that is impractical to invoke from a unit test
    /// without the full `AgentState`. The grep ensures the loop
    /// routes through the shared `xdp_blocklist_pin_for_ip` helper
    /// (which is itself unit-tested for v4/v6 dispatch + None on
    /// garbage). Refactors that bypass the helper fail this test.
    #[test]
    fn xdp_ttl_cleanup_calls_v6_pin_for_ipv6_entries() {
        let src = include_str!("boot.rs");

        // Strip comment lines and lines containing string literals
        // before the pattern check so the assertion below can talk
        // about the bad pattern in its own comments / panic messages
        // without false-positiving on itself.
        let code_only: String = src
            .lines()
            .filter(|line| {
                let t = line.trim_start();
                !(t.starts_with("//") || t.starts_with("/*") || t.starts_with("*"))
            })
            .filter(|line| !line.contains('"'))
            .collect::<Vec<_>>()
            .join("\n");

        // Helper must be wired in (active code, not just docs).
        assert!(
            code_only.contains("xdp_blocklist_pin_for_ip(ip)"),
            "boot loop must dispatch XDP cleanup through the shared \
             xdp_blocklist_pin_for_ip helper — the pre-fix code parsed \
             only Ipv4Addr and silently dropped v6 entries"
        );

        // Pre-fix shape must NOT come back as active code. The pre-fix
        // call site was the IPv4-only parse against an `ip` variable
        // inside the xdp_block_times expiry loop.
        assert!(
            !code_only.contains("ip.parse::<std::net::Ipv4Addr>()"),
            "boot loop must NOT call the IPv4-only parse against an \
             xdp_block_times entry — use the shared helper so v6 entries \
             also reach bpftool"
        );
    }

    // ── Spec 049 PR18 — replay_todays_incidents tests ────────────────
    //
    // Operator-driven: on 2026-05-13 the agent ran for several hours
    // covering hundreds of incidents, then absorbed two same-day
    // restarts and lost ~73% of the day from its in-memory KG. The
    // extracted `replay_todays_incidents` helper closes that gap. These
    // tests pin every observable axis of the contract so a future
    // refactor (or a "performance optimization" that swaps the for-loop
    // for something smarter) cannot regress the audit-trail promise.

    fn replay_test_incident(
        id: &str,
        ts: chrono::DateTime<chrono::Utc>,
    ) -> innerwarden_core::incident::Incident {
        innerwarden_core::incident::Incident {
            ts,
            host: "test-host".into(),
            incident_id: id.into(),
            severity: innerwarden_core::event::Severity::High,
            title: "Replay anchor".into(),
            summary: "".into(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![],
        }
    }

    #[test]
    fn replay_todays_incidents_ingests_todays_rows_into_empty_kg() {
        // The hot-path operator-visible promise: after agent restart,
        // an empty KG receives every today-row from the canonical
        // store. The 31.14.254.81 case from 2026-05-13: SQLite had the
        // proto_anomaly incident, the KG didn't, the operator saw it
        // missing from Cases. Post-PR18 this test guarantees the row
        // arrives.
        let store = innerwarden_store::Store::open_memory().expect("memory store");
        let mut graph = crate::knowledge_graph::KnowledgeGraph::new();

        let day = chrono::NaiveDate::from_ymd_opt(2026, 5, 13).unwrap();
        let now = day.and_hms_opt(15, 30, 0).unwrap().and_utc();
        let midmorning = day.and_hms_opt(8, 0, 0).unwrap().and_utc();
        let afternoon = day.and_hms_opt(14, 30, 0).unwrap().and_utc();

        store
            .insert_incident(&replay_test_incident("today-1", midmorning))
            .unwrap();
        store
            .insert_incident(&replay_test_incident("today-2", afternoon))
            .unwrap();

        assert_eq!(
            graph.metrics().incident_nodes,
            0,
            "precondition: KG starts empty"
        );

        super::replay_todays_incidents(&store, &mut graph, now);

        assert_eq!(
            graph.metrics().incident_nodes,
            2,
            "PR18 — both of today's incidents must be in the KG after replay"
        );
    }

    #[test]
    fn replay_todays_incidents_excludes_prior_day_rows() {
        // Boundary anchor that mirrors the store-side
        // `incidents_since_ts_returns_rows_at_or_after_start`: at the
        // boot-helper level, yesterday's rows must not bleed into
        // today's KG. Operator wants today's audit slice when the
        // picker is on today; mixing yesterday silently inflates
        // both totals and tile counts.
        let store = innerwarden_store::Store::open_memory().expect("memory store");
        let mut graph = crate::knowledge_graph::KnowledgeGraph::new();

        let day = chrono::NaiveDate::from_ymd_opt(2026, 5, 13).unwrap();
        let now = day.and_hms_opt(15, 30, 0).unwrap().and_utc();
        let yesterday_evening = day
            .pred_opt()
            .unwrap()
            .and_hms_opt(23, 30, 0)
            .unwrap()
            .and_utc();
        let today_morning = day.and_hms_opt(0, 30, 0).unwrap().and_utc();

        store
            .insert_incident(&replay_test_incident("yesterday-row", yesterday_evening))
            .unwrap();
        store
            .insert_incident(&replay_test_incident("today-row", today_morning))
            .unwrap();

        super::replay_todays_incidents(&store, &mut graph, now);

        assert_eq!(
            graph.metrics().incident_nodes,
            1,
            "PR18 — only today's row must be ingested; yesterday's row must be filtered by the start-of-day boundary"
        );
    }

    #[test]
    fn replay_todays_incidents_is_idempotent_on_repeat() {
        // Snapshot-then-replay overlap case: at boot, the snapshot may
        // already contain half of today's incidents. The replay walks
        // ALL of today's SQLite rows — overlapping ones must not
        // double-count via `upsert_node` semantics on `incident_id`.
        // Without this, every boot would inflate the KG against itself
        // and the dashboard counts would skew higher than reality.
        let store = innerwarden_store::Store::open_memory().expect("memory store");
        let mut graph = crate::knowledge_graph::KnowledgeGraph::new();

        let day = chrono::NaiveDate::from_ymd_opt(2026, 5, 13).unwrap();
        let now = day.and_hms_opt(12, 0, 0).unwrap().and_utc();
        store
            .insert_incident(&replay_test_incident(
                "idempotent-row",
                day.and_hms_opt(6, 0, 0).unwrap().and_utc(),
            ))
            .unwrap();

        super::replay_todays_incidents(&store, &mut graph, now);
        let after_first = graph.metrics().incident_nodes;
        super::replay_todays_incidents(&store, &mut graph, now);
        let after_second = graph.metrics().incident_nodes;

        assert_eq!(after_first, 1, "first replay must land the single row");
        assert_eq!(
            after_second, after_first,
            "PR18 — second replay of the same data must NOT double-count"
        );
    }

    #[test]
    fn replay_todays_incidents_is_noop_on_empty_store() {
        // Edge case: the agent boots on a clean install (no incidents
        // yet today). The helper must succeed silently — the operator's
        // first hour on a new host should not be polluted with warn
        // logs about the empty result set.
        let store = innerwarden_store::Store::open_memory().expect("memory store");
        let mut graph = crate::knowledge_graph::KnowledgeGraph::new();
        let now = chrono::Utc::now();

        super::replay_todays_incidents(&store, &mut graph, now);

        assert_eq!(
            graph.metrics().incident_nodes,
            0,
            "PR18 — empty store, empty KG, no-op result"
        );
    }

    #[test]
    fn replay_todays_incidents_does_not_disturb_pre_existing_kg_nodes() {
        // The snapshot already populated the KG before the replay
        // runs. The replay must merge into it, not wipe it. This is
        // the realistic prod case — boot loads snapshot, then replay
        // tops up today's tail. Asserts the merge contract rather
        // than the (wrong) replace contract.
        let store = innerwarden_store::Store::open_memory().expect("memory store");
        let mut graph = crate::knowledge_graph::KnowledgeGraph::new();

        // Pre-seed the KG with an unrelated yesterday-incident as if
        // the snapshot had restored it.
        let yesterday_inc = replay_test_incident(
            "from-snapshot:yesterday",
            chrono::Utc::now() - chrono::Duration::days(1),
        );
        graph.ingest_incident(&yesterday_inc);
        let before = graph.metrics().incident_nodes;
        assert_eq!(before, 1, "precondition: snapshot-restored node present");

        // Now drop today's row into the store and run the replay.
        let day = chrono::Utc::now().date_naive();
        let now = day.and_hms_opt(15, 0, 0).unwrap().and_utc();
        store
            .insert_incident(&replay_test_incident(
                "from-replay:today",
                day.and_hms_opt(8, 0, 0).unwrap().and_utc(),
            ))
            .unwrap();

        super::replay_todays_incidents(&store, &mut graph, now);

        assert_eq!(
            graph.metrics().incident_nodes,
            2,
            "PR18 — pre-existing snapshot nodes must survive; replay merges new rows in"
        );
    }

    #[test]
    fn replay_todays_incidents_uses_utc_start_of_day_not_local() {
        // The boundary is UTC. If a future refactor swaps to
        // `Local::now()` or `date_naive()` against a local TZ, an
        // operator in UTC+9 would see today's first 9 hours missing
        // from the dashboard after every restart. Pin the UTC contract.
        let store = innerwarden_store::Store::open_memory().expect("memory store");
        let mut graph = crate::knowledge_graph::KnowledgeGraph::new();

        // 00:00 UTC on a specific day — the boundary row.
        let utc_midnight = chrono::NaiveDate::from_ymd_opt(2026, 5, 13)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap()
            .and_utc();
        store
            .insert_incident(&replay_test_incident("utc-midnight", utc_midnight))
            .unwrap();

        // `now` is 06:00 UTC on the same day. The boundary computed
        // from this must INCLUDE the 00:00 UTC row.
        let now = utc_midnight + chrono::Duration::hours(6);
        super::replay_todays_incidents(&store, &mut graph, now);

        assert_eq!(
            graph.metrics().incident_nodes,
            1,
            "PR18 — the UTC 00:00 boundary row must be included when `now` is later the same UTC day"
        );
    }

    #[test]
    fn replay_todays_incidents_walks_in_chronological_order() {
        // The store-side `incidents_since_ts` returns rows ORDER BY ts
        // ASC. The helper must preserve that order when it iterates
        // into `ingest_incident` so the KG's `first_seen` / `last_seen`
        // edges land in the right sequence. The order is observable
        // via the `ts` field on the resulting Incident node.
        use crate::knowledge_graph::types::{Node, NodeType};

        let store = innerwarden_store::Store::open_memory().expect("memory store");
        let mut graph = crate::knowledge_graph::KnowledgeGraph::new();

        let base = chrono::NaiveDate::from_ymd_opt(2026, 5, 13)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap()
            .and_utc();
        store
            .insert_incident(&replay_test_incident(
                "order-third",
                base + chrono::Duration::hours(3),
            ))
            .unwrap();
        store
            .insert_incident(&replay_test_incident(
                "order-first",
                base + chrono::Duration::hours(1),
            ))
            .unwrap();
        store
            .insert_incident(&replay_test_incident(
                "order-second",
                base + chrono::Duration::hours(2),
            ))
            .unwrap();

        let now = base + chrono::Duration::hours(4);
        super::replay_todays_incidents(&store, &mut graph, now);

        // Collect the Incident nodes' (id, ts) pairs and verify they
        // were ingested in ascending ts order.
        let mut seen: Vec<(String, chrono::DateTime<chrono::Utc>)> = graph
            .nodes_of_type(NodeType::Incident)
            .iter()
            .filter_map(|&id| match graph.get_node(id) {
                Some(Node::Incident {
                    incident_id, ts, ..
                }) => Some((incident_id.clone(), *ts)),
                _ => None,
            })
            .collect();
        seen.sort_by_key(|(_, ts)| *ts);
        let ids: Vec<&str> = seen.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["order-first", "order-second", "order-third"],
            "PR18 — the chronological iteration must reach ingest_incident in ts-ascending order"
        );
    }

    #[test]
    fn max_boot_replay_cap_is_loose_enough_for_a_real_day() {
        // The cap protects against pathological days (DoS, runaway
        // detector loop) but must not truncate honest workloads. The
        // operator's worst measured prod day is ~10k incidents; the
        // cap is set 10x above that. This anchor pins the floor so a
        // future "let's drop it to 10k" refactor must justify itself
        // and update the comment in lockstep.
        assert!(
            super::MAX_BOOT_REPLAY >= 100_000,
            "PR18 — MAX_BOOT_REPLAY must stay >= 100k so the worst measured \
             prod day (~10k incidents) fits 10x over"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────
// Spec 035 PR-A2 phase 4 — run_agent boot heap-budget anchor
// ─────────────────────────────────────────────────────────────────────
//
// Standing gate on the cumulative allocation cost of the agent boot
// path. `run_agent` walks every first-run initialiser: config parse,
// sqlite open, schema migrations, agent-cursor restore, attacker
// profile / IP reputation / baseline warm-cache loads, AI router
// build, decision writer open, telegram/slack/webhook clients,
// honeypot bootstrap, dashboard option (here disabled), and the first
// slow-loop tick. A regression in any of these surfaces here as boot
// RSS growth in production — exactly the class the audit flagged as
// RECURRING (see `.claude-local/RECURRING_BUGS.md` "Memory regressions
// on follow-up PRs").
//
// **What is measured**: `dhat::HeapStats::total_bytes` delta across a
// single `run_agent(cli).await` call with `cli.once = true`. Counts
// cumulative new allocations during boot + first tick + graceful
// shutdown. Same metric as phases 2 and 3.
//
// **No warm-up**: unlike the per-call anchors in phases 2 and 3, boot
// is a once-per-process event. The measurement IS the first boot;
// there is nothing to amortise.
//
// **Fixture**: `once_cli` is the minimal-config path already used by
// `run_agent_once_boots_with_empty_data_dir`. No config file — all
// defaults. This is the DETERMINISTIC floor; a feature-rich config
// would load more subsystems and inflate the budget with
// config-sensitive variance. The existing feature-rich test covers
// the FAT boot path for correctness (not memory); the minimal path
// is the right target for a trend gate.
//
// **Thread-safety / mandatory `--test-threads=1`**: identical
// constraint to phases 2 and 3. DHAT's `HeapStats::get()` reads a
// process-global counter; concurrent tests contaminate the delta.
//
// **Budget relationship to the spec's "500 MB" target**: the spec
// 035 A2 draft named this test `boot_total_alloc_under_500MB`. That
// number was an aspirational ceiling, not a measurement. The actual
// minimal-boot allocation is orders of magnitude smaller (see
// baseline below). Pinning the budget at 500 MB would fail to catch
// the regressions the gate is meant to catch; the real-measurement +
// 10 % formula from phases 2 and 3 applies here too.

#[cfg(all(test, feature = "dhat-heap"))]
mod heap_budget {
    use super::*;
    use tempfile::TempDir;

    /// Baselined on 2026-04-24 against the minimal-config once-mode
    /// boot path (`once_cli_for_heap_budget` below).
    ///
    /// First-run measurement: **1_686_513 bytes (1.61 MiB)** cumulative
    /// new allocations during a single `run_agent(cli).await` where
    /// `cli.once = true` — empty tempdir-backed data_dir, no config
    /// file, all defaults. Peak live heap during the same window was
    /// **1_621_294 bytes (1.55 MiB)**, i.e. very little of what gets
    /// allocated is released before boot ends (AgentState and the
    /// in-memory KG accumulate and remain until Drop).
    ///
    /// Budget = ceil(measurement × 1.10 / 100 KiB) × 100 KiB
    ///        = ceil(1_855_164 / 102_400) × 102_400
    ///        = 19 × 102_400
    ///        = 1_945_600 bytes (1.86 MiB, ~15.4 % headroom over
    ///          baseline — slightly above 10 % because the 100-KiB
    ///          rounding lifts the nominal 10 % boundary).
    ///
    /// **Orders of magnitude below the spec's "500 MB" aspirational
    /// target.** The spec 035 A2 draft named this test
    /// `boot_total_alloc_under_500MB`, but that number came from a
    /// top-of-envelope guess about prod RSS — not a real DHAT
    /// measurement. Actual minimal boot allocates 1.6 MiB of new heap,
    /// so pinning the budget at 500 MB would fail to catch a
    /// 200× regression. Setting the budget at real-measurement × 1.10
    /// means the gate actually catches the regressions it is meant to
    /// catch.
    ///
    /// A deliberate raise requires updating this constant AND the
    /// matching line in `.claude-local/IMPACT.md` "Memory layout"
    /// (landing in phase 5) in the same PR, with the reason.
    // Raised from 1_945_600 (1.86 MiB) -> 2_900_000 (2.77 MiB) on
    // 2026-05-28 for spec 055 Phase 2: the correlation engine now loads
    // 68 rules from embedded YAML at boot via
    // `CorrelationEngine::from_yaml_dir()` instead of const arrays. YAML
    // parsing allocates ~760 KiB of transient Strings (rule ids, names,
    // kind_patterns) during boot. The previous `builtin_rules()` const
    // array path is still available for short-lived engines but the
    // production boot path now exercises the YAML path so operators can
    // hot-reload rules. See spec 055.
    const BUDGET_TOTAL_BYTES: u64 = 2_900_000;

    /// Minimal CLI fixture mirroring `once_cli` in the sibling `tests`
    /// module. Kept local to this module so the DHAT test does not
    /// reach across `#[cfg(test)]` visibility boundaries — the cost is
    /// ~15 LOC of duplication that move in lockstep with the real
    /// `crate::Cli` shape (if `Cli` gains a field, compilation fails
    /// here and in `tests::once_cli` at the same time).
    fn once_cli_for_heap_budget(data_dir: std::path::PathBuf) -> crate::Cli {
        crate::Cli {
            data_dir,
            config: None,
            once: true,
            report: false,
            playbook_replay: None,
            report_dir: None,
            dashboard: false,
            dashboard_bind: "127.0.0.1:8787".to_string(),
            tls_cert: None,
            tls_key: None,
            insecure_no_tls: false,
            dashboard_generate_password_hash: false,
            interval: 30,
            validate_config_only: false,
            honeypot_sandbox_runner: false,
            honeypot_sandbox_spec: None,
            honeypot_sandbox_result: None,
            cleanup_015_graph_signal_quality: false,
            backfill_015_research_only: false,
            retrain_anomaly: false,
            backtest_anomaly: false,
            backtest_cutoff: None,
        }
    }

    #[tokio::test]
    async fn run_agent_once_allocates_under_budget() {
        let _profiler = dhat::Profiler::builder().testing().build();

        let dir = TempDir::new().expect("tempdir");
        let cli = once_cli_for_heap_budget(dir.path().to_path_buf());

        let before = dhat::HeapStats::get();
        run_agent(cli).await.expect("run_agent once-mode");
        let after = dhat::HeapStats::get();

        let delta_total = after.total_bytes - before.total_bytes;
        let delta_max = after.max_bytes.saturating_sub(before.max_bytes);
        eprintln!(
            "run_agent once boot heap budget — total_bytes delta: \
             {delta_total} bytes ({:.2} MiB), max_bytes delta: \
             {delta_max} bytes ({:.2} MiB)",
            delta_total as f64 / (1024.0 * 1024.0),
            delta_max as f64 / (1024.0 * 1024.0),
        );

        assert!(
            delta_total <= BUDGET_TOTAL_BYTES,
            "run_agent once-mode allocated {delta_total} bytes during boot \
             ({:.2} MiB), budget is {BUDGET_TOTAL_BYTES} bytes ({:.2} MiB). \
             If this is a deliberate raise, update BUDGET_TOTAL_BYTES here \
             AND the matching line in .claude-local/IMPACT.md \"Memory \
             layout\" in the same PR, with the reason.",
            delta_total as f64 / (1024.0 * 1024.0),
            BUDGET_TOTAL_BYTES as f64 / (1024.0 * 1024.0),
        );
    }
}
