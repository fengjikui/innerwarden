//! Persistence / privilege-abuse / defense-evasion graph detectors (persistence, service stop, sudo abuse, log tampering).
//!
//! Spec 068 relocation: moved verbatim out of the former monolithic
//! `knowledge_graph/detectors.rs`. No logic change.

use super::*;

// ── 7. Persistence via Graph ────────────────────────────────────────────
// Replaces: crontab_persistence + systemd_persistence + ssh_key_injection
// Graph query: Process→Wrote→File where File.path matches persistence locations

pub(super) fn detect_persistence(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let cutoff = now - Duration::seconds(300);
    let active = graph.active_nodes_since(cutoff);

    let persistence_patterns: &[(&str, &str, &str)] = &[
        ("/etc/cron", "crontab_persistence", "T1053.003"),
        ("/var/spool/cron", "crontab_persistence", "T1053.003"),
        ("/etc/systemd/", "systemd_persistence", "T1543.002"),
        ("/usr/lib/systemd/", "systemd_persistence", "T1543.002"),
        ("authorized_keys", "ssh_key_injection", "T1098.004"),
    ];

    for &proc_id in &active {
        if !matches!(graph.get_node(proc_id), Some(Node::Process { .. })) {
            continue;
        }
        for edge in graph.outgoing_edges(proc_id) {
            if edge.relation != Relation::Wrote || edge.ts < cutoff {
                continue;
            }

            let file_path = match graph.get_node(edge.to) {
                Some(Node::File { path, .. }) => path.clone(),
                _ => continue,
            };

            for &(pattern, detector_name, mitre) in persistence_patterns {
                if !file_path.contains(pattern) {
                    continue;
                }

                let key = format!("graph_persist:{}:{}", detector_name, proc_id);
                if !state.check_and_set(&key, now, 600) {
                    continue;
                }

                let proc_label = graph
                    .get_node(proc_id)
                    .map(|n| n.label())
                    .unwrap_or_default();

                incidents.push(Incident {
                    ts: now,
                    host: host.to_string(),
                    incident_id: format!("graph_{}:{}:{}", detector_name, proc_id, now.timestamp()),
                    severity: Severity::High,
                    title: format!("Persistence: {} wrote to {}", proc_label, file_path),
                    summary: format!(
                        "Process {} wrote to persistence location {}",
                        proc_label, file_path
                    ),
                    evidence: serde_json::json!({
                        "source": "knowledge_graph",
                        "detector": format!("graph_{}", detector_name),
                        "process": proc_label,
                        "path": file_path,
                    }),
                    recommended_checks: vec![
                        format!("Inspect {}", file_path),
                        format!("Check process tree of {}", proc_label),
                    ],
                    tags: vec![mitre.to_string()],
                    entities: vec![EntityRef::path(&file_path)],
                });
                break; // One match per file
            }
        }
    }

    incidents
}

// 10. Security service stopped (systemctl stop innerwarden/fail2ban/auditd/etc)
pub(super) fn detect_service_stop(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let security_services = [
        "innerwarden",
        "fail2ban",
        "auditd",
        "rsyslog",
        "syslog",
        "iptables",
        "nftables",
        "ufw",
        "firewalld",
        "apparmor",
        "selinux",
    ];

    for &pid_id in graph.nodes_of_type(NodeType::Process).iter() {
        let comm = match graph.get_node(pid_id) {
            Some(Node::Process { comm, .. }) => comm.clone(),
            _ => continue,
        };
        if comm != "systemctl" && comm != "service" {
            continue;
        }
        // Get args from edge properties (summary field or event details)
        let args_str = graph
            .outgoing_edges(pid_id)
            .iter()
            .filter_map(|e| e.properties.get("summary").and_then(|v| v.as_str()))
            .next()
            .unwrap_or("")
            .to_lowercase();
        if !args_str.contains("stop") && !args_str.contains("disable") {
            continue;
        }
        let stopped = security_services.iter().find(|s| args_str.contains(**s));
        let Some(svc) = stopped else { continue };

        let key = format!("graph_svc_stop:{}", svc);
        if !state.check_and_set(&key, now, 300) {
            continue;
        }

        incidents.push(Incident {
            ts: now,
            host: host.to_string(),
            incident_id: format!("graph_service_stop:{}:{}", svc, now.timestamp()),
            severity: Severity::Critical,
            title: format!("Security service stopped: {}", svc),
            summary: format!(
                "Process '{}' stopped security service '{}'. This may indicate defense evasion.",
                comm, svc
            ),
            evidence: serde_json::json!({
                "source": "knowledge_graph",
                "detector": "graph_service_stop",
                "process": comm,
                "service": svc,
                "args": args_str,
            }),
            recommended_checks: vec![
                format!(
                    "Check if {} is still running: systemctl status {}",
                    svc, svc
                ),
                "Review who initiated the stop".to_string(),
            ],
            tags: vec!["T1562.001".to_string()],
            entities: vec![],
        });
    }
    incidents
}

// 12. Log tampering (non-standard processes writing to /var/log)
pub(super) fn detect_log_tampering(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let log_writers = [
        "rsyslog",
        "syslog-ng",
        "journald",
        "systemd-journal",
        "logrotate",
        "systemd",
        "auditd",
        "innerwarden-sensor",
        "innerwarden-agent",
    ];

    for &pid_id in graph.nodes_of_type(NodeType::Process).iter() {
        let comm = match graph.get_node(pid_id) {
            Some(Node::Process { comm, .. }) => comm.clone(),
            _ => continue,
        };
        if log_writers.iter().any(|w| comm == *w) {
            continue;
        }

        for edge in graph.outgoing_edges(pid_id) {
            if edge.relation != Relation::Wrote
                && edge.relation != Relation::Deleted
                && edge.relation != Relation::Truncated
            {
                continue;
            }
            let file_path = match graph.get_node(edge.to) {
                Some(Node::File { path, .. }) => path.clone(),
                _ => continue,
            };
            if !file_path.starts_with("/var/log/") {
                continue;
            }

            let key = format!("graph_logtamp:{}:{}", comm, file_path);
            if !state.check_and_set(&key, now, 600) {
                continue;
            }

            incidents.push(Incident {
                ts: now,
                host: host.to_string(),
                incident_id: format!("graph_log_tampering:{}:{}", comm, now.timestamp()),
                severity: Severity::High,
                title: format!("Log tampering: {} modified {}", comm, file_path),
                summary: format!(
                    "Non-standard process '{}' modified log file '{}'. This may indicate log tampering to cover tracks.",
                    comm, file_path
                ),
                evidence: serde_json::json!({
                    "source": "knowledge_graph",
                    "detector": "graph_log_tampering",
                    "process": comm,
                    "file": file_path,
                    "action": format!("{:?}", edge.relation),
                }),
                recommended_checks: vec![
                    format!("Check integrity of {}", file_path),
                    format!("Investigate process {}", comm),
                ],
                tags: vec!["T1070.002".to_string()],
                entities: vec![],
            });
        }
    }
    incidents
}

// 23. Sudo abuse — burst of sudo commands from one user
pub(super) fn detect_sudo_abuse(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let window = Duration::seconds(60);
    let threshold = 10;

    for &uid in graph.nodes_of_type(NodeType::User).iter() {
        let name = match graph.get_node(uid) {
            Some(Node::User { name, .. }) => name.clone(),
            _ => continue,
        };
        if name == "root" {
            continue; // root doesn't need sudo
        }

        // SudoAs edges go Process→User, so look at incoming edges on User
        let sudo_count = graph
            .incoming_edges(uid)
            .iter()
            .filter(|e| e.relation == Relation::SudoAs && now - e.ts < window)
            .count();

        if sudo_count < threshold {
            continue;
        }

        let key = format!("graph_sudoabuse:{}", name);
        if !state.check_and_set(&key, now, 1800) {
            continue;
        }

        incidents.push(Incident {
            ts: now,
            host: host.to_string(),
            incident_id: format!("graph_sudo_abuse:{}:{}", name, now.timestamp()),
            severity: Severity::High,
            title: format!("Sudo abuse: {} ran {} sudo commands in 1m", name, sudo_count),
            summary: format!(
                "User '{}' executed {} sudo commands in 1 minute. May indicate privilege abuse or automated exploitation.",
                name, sudo_count
            ),
            evidence: serde_json::json!({
                "source": "knowledge_graph",
                "detector": "graph_sudo_abuse",
                "user": name,
                "sudo_count": sudo_count,
            }),
            recommended_checks: vec![
                format!("Check sudo log: journalctl _COMM=sudo | grep {}", name),
                format!("Suspend user: innerwarden suspend-user {}", name),
            ],
            tags: vec!["T1548.003".to_string()],
            entities: vec![EntityRef::user(&name)],
        });
    }
    incidents
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).expect("test timestamp must be valid")
    }

    #[test]
    fn detect_persistence_fires_for_systemd_write() {
        let mut graph = KnowledgeGraph::new();
        let now = ts(600);
        let process = graph.ensure_process(1234, 1, "payload", 1000, now);
        let file = graph.ensure_file("/etc/systemd/system/backdoor.service");
        graph.add_edge(Edge::new(process, file, Relation::Wrote, now));

        let mut state = GraphDetectorState::new();
        let incidents = detect_persistence(&graph, &mut state, "host", now);

        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].severity, Severity::High);
        assert!(incidents[0].title.contains("Persistence"));
        assert!(incidents[0].tags.iter().any(|tag| tag == "T1543.002"));
    }

    #[test]
    fn detect_persistence_ignores_non_persistence_write() {
        let mut graph = KnowledgeGraph::new();
        let now = ts(600);
        let process = graph.ensure_process(1234, 1, "payload", 1000, now);
        let file = graph.ensure_file("/tmp/harmless.txt");
        graph.add_edge(Edge::new(process, file, Relation::Wrote, now));

        let mut state = GraphDetectorState::new();
        let incidents = detect_persistence(&graph, &mut state, "host", now);

        assert!(incidents.is_empty());
    }

    #[test]
    fn detect_service_stop_fires_for_security_service_disable() {
        let mut graph = KnowledgeGraph::new();
        let now = ts(600);
        let systemctl = graph.ensure_process(42, 1, "systemctl", 0, now);
        graph.add_edge(
            Edge::new(systemctl, systemctl, Relation::Executed, now)
                .with_prop("summary", "systemctl disable auditd"),
        );

        let mut state = GraphDetectorState::new();
        let incidents = detect_service_stop(&graph, &mut state, "host", now);

        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].severity, Severity::Critical);
        assert_eq!(incidents[0].evidence["service"], "auditd");
        assert!(incidents[0].tags.iter().any(|tag| tag == "T1562.001"));
    }

    #[test]
    fn detect_service_stop_ignores_non_stop_actions() {
        let mut graph = KnowledgeGraph::new();
        let now = ts(600);
        let systemctl = graph.ensure_process(42, 1, "systemctl", 0, now);
        graph.add_edge(
            Edge::new(systemctl, systemctl, Relation::Executed, now)
                .with_prop("summary", "systemctl status auditd"),
        );

        let mut state = GraphDetectorState::new();
        let incidents = detect_service_stop(&graph, &mut state, "host", now);

        assert!(incidents.is_empty());
    }

    #[test]
    fn detect_log_tampering_fires_for_nonstandard_log_delete() {
        let mut graph = KnowledgeGraph::new();
        let now = ts(600);
        let process = graph.ensure_process(77, 1, "cleanup", 1000, now);
        let file = graph.ensure_file("/var/log/auth.log");
        graph.add_edge(Edge::new(process, file, Relation::Deleted, now));

        let mut state = GraphDetectorState::new();
        let incidents = detect_log_tampering(&graph, &mut state, "host", now);

        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].severity, Severity::High);
        assert_eq!(incidents[0].evidence["action"], "Deleted");
        assert!(incidents[0].tags.iter().any(|tag| tag == "T1070.002"));
    }

    #[test]
    fn detect_log_tampering_ignores_trusted_log_writer() {
        let mut graph = KnowledgeGraph::new();
        let now = ts(600);
        let rsyslog = graph.ensure_process(77, 1, "rsyslog", 0, now);
        let file = graph.ensure_file("/var/log/syslog");
        graph.add_edge(Edge::new(rsyslog, file, Relation::Wrote, now));

        let mut state = GraphDetectorState::new();
        let incidents = detect_log_tampering(&graph, &mut state, "host", now);

        assert!(incidents.is_empty());
    }

    #[test]
    fn detect_sudo_abuse_fires_for_ten_sudo_edges_in_window() {
        let mut graph = KnowledgeGraph::new();
        let user = graph.ensure_user("attacker");
        for i in 0..10 {
            let at = ts(i * 5);
            let process = graph.ensure_process(1000 + i as u32, 1, "sudo", 0, at);
            graph.add_edge(Edge::new(process, user, Relation::SudoAs, at));
        }

        let mut state = GraphDetectorState::new();
        let incidents = detect_sudo_abuse(&graph, &mut state, "host", ts(55));

        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].severity, Severity::High);
        assert_eq!(incidents[0].evidence["sudo_count"], 10);
        assert!(incidents[0].tags.iter().any(|tag| tag == "T1548.003"));
    }

    #[test]
    fn detect_sudo_abuse_ignores_bursts_below_threshold() {
        let mut graph = KnowledgeGraph::new();
        let user = graph.ensure_user("operator");
        for i in 0..9 {
            let at = ts(i * 5);
            let process = graph.ensure_process(1000 + i as u32, 1, "sudo", 0, at);
            graph.add_edge(Edge::new(process, user, Relation::SudoAs, at));
        }

        let mut state = GraphDetectorState::new();
        let incidents = detect_sudo_abuse(&graph, &mut state, "host", ts(55));

        assert!(incidents.is_empty());
    }
}
