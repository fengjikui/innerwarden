//! Reconnaissance / discovery graph detectors (threat-intel, discovery burst, protocol anomaly, port scan, credential stuffing, scanner UA).
//!
//! Spec 068 relocation: moved verbatim out of the former monolithic
//! `knowledge_graph/detectors.rs`. No logic change.

use super::*;

// ── 1. Threat Intel via Graph ───────────────────────────────────────────
// Replaces: threat_intel detector (per-event IP checking)
// Graph query: all Process→ConnectedTo→Ip where Ip.datasets is non-empty

pub(super) fn detect_threat_intel(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let hits = graph.threat_intel_hits();

    for (proc_id, ip_id, dataset) in hits {
        let key = format!("graph_ti:{}:{}", ip_id, dataset);
        if !state.check_and_set(&key, now, 300) {
            continue;
        }

        let proc_label = graph
            .get_node(proc_id)
            .map(|n| n.label())
            .unwrap_or_default();
        let ip_addr = match graph.get_node(ip_id) {
            Some(Node::Ip { addr, .. }) => addr.clone(),
            _ => continue,
        };

        incidents.push(Incident {
            ts: now,
            host: host.to_string(),
            incident_id: format!("graph_threat_intel:{}:{}", ip_addr, now.timestamp()),
            severity: Severity::High,
            title: format!(
                "Threat intel match: {} → {} ({})",
                proc_label, ip_addr, dataset
            ),
            summary: format!(
                "Process {} connected to IP {} which is in threat dataset '{}'.",
                proc_label, ip_addr, dataset
            ),
            evidence: serde_json::json!({
                "source": "knowledge_graph",
                "detector": "graph_threat_intel",
                "process": proc_label,
                "ip": ip_addr,
                "dataset": dataset,
            }),
            recommended_checks: vec![
                format!("Check process {}", proc_label),
                format!("Investigate IP {} in threat feeds", ip_addr),
            ],
            tags: vec!["T1071".to_string()],
            entities: vec![EntityRef::ip(&ip_addr)],
        });
    }

    incidents
}

// ── 6. Discovery Burst via Graph ────────────────────────────────────────
// Replaces: discovery_burst detector (counting recon commands per user)
// Graph query: User with >5 Read edges to sensitive files in <60s

pub(super) fn detect_discovery_burst_calibrated(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
    ctx: &CalibrationContext,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let cutoff = now - Duration::seconds(60);
    let threshold = 5;

    // Group: User → count of processes that executed in window
    for user_id in graph.nodes_of_type(NodeType::User) {
        let user_name = match graph.get_node(user_id) {
            Some(Node::User { name, .. }) => name.clone(),
            _ => continue,
        };

        // Count processes that have RunAs edge to this user in the window
        let recent_procs: Vec<NodeId> = graph
            .incoming_edges(user_id)
            .iter()
            .filter(|e| e.relation == Relation::RunAs && e.ts >= cutoff)
            .map(|e| e.from)
            .collect();

        // Count Read edges to sensitive files from those processes
        let mut sensitive_reads = 0;
        for &proc_id in &recent_procs {
            for edge in graph.outgoing_edges(proc_id) {
                if edge.relation == Relation::Read && edge.ts >= cutoff {
                    if let Some(Node::File {
                        is_sensitive: true, ..
                    }) = graph.get_node(edge.to)
                    {
                        sensitive_reads += 1;
                    }
                }
            }
        }

        // Also count Executed edges (process spawns = discovery commands)
        let exec_count = recent_procs.len();

        let total = sensitive_reads + exec_count;

        // 2026-05-03: graduated thresholds by user class.
        //   Root + Human → 3x (operators legitimately run discovery
        //     during deploys, debugging, recon-as-defense).
        //   Service → 5x (snap refresh, apt update, systemd-* spawn
        //     bursts of processes during routine work).
        //   Unknown → 1x (strict — covers attackers / compromised
        //     low-uid services).
        let user_class = ctx.classify_user(&user_name);
        let adjusted_threshold = match user_class {
            UserClass::Root | UserClass::Human => threshold * 3,
            UserClass::Service => threshold * 5,
            UserClass::Unknown => threshold,
        };
        // 2026-05-03: when activity is over the standard threshold
        // but below the elevated one, the alert is suppressed
        // because of the user class. Record it so /metrics can
        // surface it — invisible suppression is a known
        // anti-pattern (operator can't audit what's being hidden).
        if total >= threshold && total < adjusted_threshold {
            *state
                .suppressed_counts
                .entry(("discovery_burst".to_string(), user_class_label(user_class)))
                .or_insert(0) += 1;
        }

        if total >= adjusted_threshold {
            let key = format!("graph_discovery:{}", user_name);
            if !state.check_and_set(&key, now, 1800) {
                continue;
            }

            // 2026-05-03 (Wave 5b PR-4): cap severity at Medium for
            // Service-class users. snap_daemon doing 92 actions in
            // 60 s during a routine `snap refresh` legitimately
            // exceeds even the 5x multiplier; firing HIGH (which
            // pushes a red-banner alert to the operator's site
            // home) is operator-misleading. Operator's verbatim
            // 2026-05-03 report: "RED on home, only if server was
            // compromised: HIGH: Graph Discovery Burst — user
            // uid:584788 (92 actions in 60s)". uid 584788 is
            // snap_daemon (verified in /etc/passwd). The signal is
            // still recorded (Medium → still visible in journey +
            // Telegram digest), just not in the
            // "drop-everything" surface.
            let user_class = ctx.classify_user(&user_name);
            let severity = if matches!(user_class, UserClass::Service) {
                Severity::Medium
            } else if total >= adjusted_threshold * 2 {
                Severity::High
            } else {
                Severity::Medium
            };

            incidents.push(Incident {
                ts: now,
                host: host.to_string(),
                incident_id: format!("graph_discovery_burst:{}:{}", user_name, now.timestamp()),
                severity,
                title: format!("Discovery burst: user {} ({} actions in 60s)", user_name, total),
                summary: format!(
                    "User {} performed {} process executions and {} sensitive file reads in 60 seconds",
                    user_name, exec_count, sensitive_reads
                ),
                evidence: serde_json::json!({
                    "source": "knowledge_graph",
                    "detector": "graph_discovery_burst",
                    "user": user_name,
                    "user_class": user_class_label(user_class),
                    "exec_count": exec_count,
                    "sensitive_reads": sensitive_reads,
                }),
                recommended_checks: vec!["Check for reconnaissance activity".to_string()],
                tags: vec!["T1087".to_string()],
                entities: vec![EntityRef::user(&user_name)],
            });
        }
    }

    incidents
}

// 20. Proto anomaly — aggregated by source IP
pub(super) fn detect_proto_anomaly_aggregated(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let window = Duration::seconds(300);
    let threshold = 5;

    for &ip_id in graph.nodes_of_type(NodeType::Ip).iter() {
        let (addr, is_internal) = match graph.get_node(ip_id) {
            Some(Node::Ip {
                addr, is_internal, ..
            }) => (addr.clone(), *is_internal),
            _ => continue,
        };
        if is_internal {
            continue;
        }

        // Count anomalous connections in window (edges with "malformed" or "anomaly" in properties)
        let anomaly_count = graph
            .edges_in_window(ip_id, Relation::ConnectedTo, now, window)
            .iter()
            .filter(|e| {
                e.properties
                    .get("summary")
                    .and_then(|v| v.as_str())
                    .map(|s| {
                        s.contains("malformed") || s.contains("anomal") || s.contains("invalid")
                    })
                    .unwrap_or(false)
            })
            .count();

        // Also count all connections (fan-out detection)
        let total_conn = graph.count_edges_in_window(ip_id, Relation::ConnectedTo, now, window);

        if anomaly_count < threshold && total_conn < 20 {
            continue;
        }

        let key = format!("graph_proto_agg:{}", addr);
        if !state.check_and_set(&key, now, 600) {
            continue;
        }

        let severity = if anomaly_count >= 10 {
            Severity::High
        } else {
            Severity::Medium
        };
        incidents.push(Incident {
            ts: now,
            host: host.to_string(),
            incident_id: format!("graph_proto_anomaly:{}:{}", addr, now.timestamp()),
            severity,
            title: format!("Protocol anomaly: {} from {} ({} connections in 5m)", anomaly_count, addr, total_conn),
            summary: format!(
                "IP {} sent {} anomalous connections ({} total) in 5 minutes. May indicate scanning or exploitation attempts.",
                addr, anomaly_count, total_conn
            ),
            evidence: serde_json::json!({
                "source": "knowledge_graph",
                "detector": "graph_proto_anomaly",
                "ip": addr,
                "anomaly_count": anomaly_count,
                "total_connections": total_conn,
            }),
            recommended_checks: vec![
                format!("Check connections: ss -tn | grep {}", addr),
            ],
            tags: vec!["T1190".to_string()],
            entities: vec![EntityRef::ip(&addr)],
        });
    }
    incidents
}

// 21. Port scan — count distinct ports per source IP
pub(super) fn detect_port_scan(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let window = Duration::seconds(60);
    let threshold = 10; // 10+ distinct ports in 1 minute

    for &ip_id in graph.nodes_of_type(NodeType::Ip).iter() {
        let (addr, is_internal) = match graph.get_node(ip_id) {
            Some(Node::Ip {
                addr, is_internal, ..
            }) => (addr.clone(), *is_internal),
            _ => continue,
        };
        if is_internal {
            continue;
        }

        let distinct_ports =
            graph.count_distinct_targets_in_window(ip_id, Relation::ScannedPort, now, window);
        if distinct_ports < threshold {
            continue;
        }

        let key = format!("graph_portscan:{}", addr);
        if !state.check_and_set(&key, now, 600) {
            continue;
        }

        incidents.push(Incident {
            ts: now,
            host: host.to_string(),
            incident_id: format!("graph_port_scan:{}:{}", addr, now.timestamp()),
            severity: Severity::Medium,
            title: format!("Port scan: {} probed {} ports in 1m", addr, distinct_ports),
            summary: format!(
                "IP {} probed {} distinct ports in 1 minute. Indicates network reconnaissance.",
                addr, distinct_ports
            ),
            evidence: serde_json::json!({
                "source": "knowledge_graph",
                "detector": "graph_port_scan",
                "ip": addr,
                "distinct_ports": distinct_ports,
            }),
            recommended_checks: vec![format!("Block scanner: innerwarden block-ip {}", addr)],
            tags: vec!["T1046".to_string()],
            entities: vec![EntityRef::ip(&addr)],
        });
    }
    incidents
}

// 22. Credential stuffing — many distinct usernames from same IP
pub(super) fn detect_credential_stuffing(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let window = Duration::seconds(300);
    let threshold = 5; // 5+ distinct users tried from same IP

    for &ip_id in graph.nodes_of_type(NodeType::Ip).iter() {
        let (addr, is_internal) = match graph.get_node(ip_id) {
            Some(Node::Ip {
                addr, is_internal, ..
            }) => (addr.clone(), *is_internal),
            _ => continue,
        };
        if is_internal {
            continue;
        }

        // Count distinct users with LoggedInFrom edges from this IP
        let auth_edges = graph.incoming_edges(ip_id);
        let distinct_users: HashSet<NodeId> = auth_edges
            .iter()
            .filter(|e| e.relation == Relation::LoggedInFrom && now - e.ts < window)
            .map(|e| e.from)
            .collect();

        if distinct_users.len() < threshold {
            continue;
        }

        let key = format!("graph_credstuff:{}", addr);
        if !state.check_and_set(&key, now, 600) {
            continue;
        }

        let user_names: Vec<String> = distinct_users
            .iter()
            .filter_map(|&uid| graph.get_node(uid).map(|n| n.label().to_string()))
            .take(10)
            .collect();

        incidents.push(Incident {
            ts: now,
            host: host.to_string(),
            incident_id: format!("graph_credential_stuffing:{}:{}", addr, now.timestamp()),
            severity: Severity::High,
            title: format!("Credential stuffing: {} tried {} users in 5m", addr, distinct_users.len()),
            summary: format!(
                "IP {} attempted login as {} distinct users in 5 minutes: {}. Indicates credential stuffing attack.",
                addr, distinct_users.len(), user_names.join(", ")
            ),
            evidence: serde_json::json!({
                "source": "knowledge_graph",
                "detector": "graph_credential_stuffing",
                "ip": addr,
                "distinct_users": distinct_users.len(),
                "usernames": user_names,
            }),
            recommended_checks: vec![
                format!("Block attacker: innerwarden block-ip {}", addr),
            ],
            tags: vec!["T1110.004".to_string()],
            entities: vec![EntityRef::ip(&addr)],
        });
    }
    incidents
}

// 17. Scanner User-Agent detection (known security scanners probing the server)
pub(super) fn detect_scanner_ua(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let scanner_patterns = [
        "nmap",
        "nikto",
        "sqlmap",
        "zap",
        "burp",
        "gobuster",
        "dirbuster",
        "wfuzz",
        "ffuf",
        "nuclei",
        "whatweb",
        "masscan",
        "acunetix",
    ];

    // Check all Ip nodes for HttpRequestTo edges with scanner UA
    for &ip_id in graph.nodes_of_type(NodeType::Ip).iter() {
        let addr = match graph.get_node(ip_id) {
            Some(Node::Ip {
                addr, is_internal, ..
            }) => {
                if *is_internal {
                    continue;
                }
                addr.clone()
            }
            _ => continue,
        };

        for edge in graph.outgoing_edges(ip_id) {
            if edge.relation != Relation::HttpRequestTo {
                continue;
            }
            let ua = edge
                .properties
                .get("user_agent")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let ua_lower = ua.to_lowercase();
            let matched = scanner_patterns.iter().find(|p| ua_lower.contains(**p));
            let Some(scanner) = matched else { continue };

            let key = format!("graph_scanner:{}:{}", addr, scanner);
            if !state.check_and_set(&key, now, 600) {
                continue;
            }

            incidents.push(Incident {
                ts: now,
                host: host.to_string(),
                incident_id: format!("graph_scanner_ua:{}:{}", addr, now.timestamp()),
                severity: Severity::Medium,
                title: format!("Security scanner detected: {} from {}", scanner, addr),
                summary: format!(
                    "IP {} sent HTTP requests with security scanner User-Agent matching '{}'. Indicates active reconnaissance.",
                    addr, scanner
                ),
                evidence: serde_json::json!({
                    "source": "knowledge_graph",
                    "detector": "graph_scanner_ua",
                    "ip": addr,
                    "scanner": scanner,
                    "user_agent": ua,
                }),
                recommended_checks: vec![
                    format!("Check access logs for IP {}", addr),
                ],
                tags: vec!["T1595.002".to_string()],
                entities: vec![EntityRef::ip(&addr)],
            });
        }
    }
    incidents
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000 + secs, 0).expect("test timestamp must be valid")
    }

    fn add_runas_actions(
        graph: &mut KnowledgeGraph,
        user_name: &str,
        count: u32,
        now: DateTime<Utc>,
    ) {
        let user = graph.ensure_user(user_name);
        for i in 0..count {
            let process = graph.ensure_process(10_000 + i, 1, "recon", 1000, now);
            graph.add_edge(Edge::new(process, user, Relation::RunAs, now));
        }
    }

    fn add_proto_connections(
        graph: &mut KnowledgeGraph,
        source_ip: NodeId,
        target_ip: NodeId,
        count: u32,
        summary: &str,
        now: DateTime<Utc>,
    ) {
        for i in 0..count {
            graph.add_edge(
                Edge::new(
                    source_ip,
                    target_ip,
                    Relation::ConnectedTo,
                    now - Duration::seconds(i as i64),
                )
                .with_prop("summary", summary),
            );
        }
    }

    #[test]
    fn detect_threat_intel_fires_for_ip_dataset_hit() {
        let mut graph = KnowledgeGraph::new();
        let now = ts(60);
        let process = graph.ensure_process(1234, 1, "curl", 1000, now);
        let ip = graph.add_node(Node::Ip {
            addr: "203.0.113.10".into(),
            is_internal: false,
            datasets: vec!["sslbl".into()],
            risk_score: 90,
            is_tor: false,
            first_seen: now,
            last_seen: now,
            attempted_usernames: Vec::new(),
        });
        graph.add_edge(Edge::new(process, ip, Relation::ConnectedTo, now));

        let mut state = GraphDetectorState::new();
        let incidents = detect_threat_intel(&graph, &mut state, "host", now);

        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].severity, Severity::High);
        assert_eq!(incidents[0].evidence["dataset"], "sslbl");
        assert!(incidents[0].tags.iter().any(|tag| tag == "T1071"));
    }

    #[test]
    fn detect_threat_intel_ignores_ip_without_dataset() {
        let mut graph = KnowledgeGraph::new();
        let now = ts(60);
        let process = graph.ensure_process(1234, 1, "curl", 1000, now);
        let ip = graph.ensure_ip("203.0.113.11", now);
        graph.add_edge(Edge::new(process, ip, Relation::ConnectedTo, now));

        let mut state = GraphDetectorState::new();
        let incidents = detect_threat_intel(&graph, &mut state, "host", now);

        assert!(incidents.is_empty());
    }

    #[test]
    fn detect_discovery_burst_unknown_user_threshold_fires_medium() {
        let mut graph = KnowledgeGraph::new();
        let now = ts(100);
        add_runas_actions(&mut graph, "unknown-user", 5, now);

        let mut state = GraphDetectorState::new();
        let incidents = detect_discovery_burst_calibrated(
            &graph,
            &mut state,
            "host",
            now,
            &CalibrationContext::default(),
        );

        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].severity, Severity::Medium);
        assert_eq!(incidents[0].evidence["user_class"], "unknown");
        assert_eq!(incidents[0].evidence["exec_count"], 5);
    }

    #[test]
    fn detect_discovery_burst_unknown_user_double_threshold_fires_high() {
        let mut graph = KnowledgeGraph::new();
        let now = ts(100);
        add_runas_actions(&mut graph, "unknown-user", 10, now);

        let mut state = GraphDetectorState::new();
        let incidents = detect_discovery_burst_calibrated(
            &graph,
            &mut state,
            "host",
            now,
            &CalibrationContext::default(),
        );

        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].severity, Severity::High);
        assert_eq!(incidents[0].evidence["exec_count"], 10);
    }

    #[test]
    fn detect_discovery_burst_human_user_under_adjusted_threshold_is_suppressed() {
        let mut graph = KnowledgeGraph::new();
        let now = ts(100);
        add_runas_actions(&mut graph, "alice", 6, now);
        let ctx = CalibrationContext {
            human_user_names: vec!["alice".into()],
            ..Default::default()
        };

        let mut state = GraphDetectorState::new();
        let incidents = detect_discovery_burst_calibrated(&graph, &mut state, "host", now, &ctx);

        assert!(incidents.is_empty());
        assert_eq!(
            state
                .suppressed_counts
                .get(&("discovery_burst".to_string(), "human")),
            Some(&1)
        );
    }

    #[test]
    fn detect_proto_anomaly_fires_medium_at_anomaly_threshold() {
        let mut graph = KnowledgeGraph::new();
        let now = ts(200);
        let source = graph.ensure_ip("203.0.113.20", now);
        let target = graph.ensure_ip("203.0.113.21", now);
        add_proto_connections(
            &mut graph,
            source,
            target,
            5,
            "malformed packet header",
            now,
        );

        let mut state = GraphDetectorState::new();
        let incidents = detect_proto_anomaly_aggregated(&graph, &mut state, "host", now);

        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].severity, Severity::Medium);
        assert_eq!(incidents[0].evidence["anomaly_count"], 5);
    }

    #[test]
    fn detect_proto_anomaly_fires_high_at_high_threshold() {
        let mut graph = KnowledgeGraph::new();
        let now = ts(200);
        let source = graph.ensure_ip("203.0.113.30", now);
        let target = graph.ensure_ip("203.0.113.31", now);
        add_proto_connections(
            &mut graph,
            source,
            target,
            10,
            "invalid protocol preface",
            now,
        );

        let mut state = GraphDetectorState::new();
        let incidents = detect_proto_anomaly_aggregated(&graph, &mut state, "host", now);

        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].severity, Severity::High);
        assert_eq!(incidents[0].evidence["anomaly_count"], 10);
    }

    #[test]
    fn detect_proto_anomaly_ignores_below_threshold_noise() {
        let mut graph = KnowledgeGraph::new();
        let now = ts(200);
        let source = graph.ensure_ip("203.0.113.40", now);
        let target = graph.ensure_ip("203.0.113.41", now);
        add_proto_connections(
            &mut graph,
            source,
            target,
            4,
            "malformed packet header",
            now,
        );

        let mut state = GraphDetectorState::new();
        let incidents = detect_proto_anomaly_aggregated(&graph, &mut state, "host", now);

        assert!(incidents.is_empty());
    }

    #[test]
    fn detect_port_scan_fires_for_ten_distinct_ports() {
        let mut graph = KnowledgeGraph::new();
        let now = ts(300);
        let source = graph.ensure_ip("203.0.113.50", now);
        for port in 1..=10 {
            let target = graph.ensure_port(port, "tcp");
            graph.add_edge(Edge::new(source, target, Relation::ScannedPort, now));
        }

        let mut state = GraphDetectorState::new();
        let incidents = detect_port_scan(&graph, &mut state, "host", now);

        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].severity, Severity::Medium);
        assert_eq!(incidents[0].evidence["distinct_ports"], 10);
        assert!(incidents[0].tags.iter().any(|tag| tag == "T1046"));
    }

    #[test]
    fn detect_port_scan_ignores_below_threshold() {
        let mut graph = KnowledgeGraph::new();
        let now = ts(300);
        let source = graph.ensure_ip("203.0.113.60", now);
        for port in 1..=9 {
            let target = graph.ensure_port(port, "tcp");
            graph.add_edge(Edge::new(source, target, Relation::ScannedPort, now));
        }

        let mut state = GraphDetectorState::new();
        let incidents = detect_port_scan(&graph, &mut state, "host", now);

        assert!(incidents.is_empty());
    }
}
