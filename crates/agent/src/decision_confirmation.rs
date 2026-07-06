use crate::{ai, config, telegram, AgentState};

/// Execute operator confirmation flow:
/// Telegram approval request first, then webhook fallback when configured.
pub(crate) async fn execute_request_confirmation(
    summary: &str,
    decision: &ai::AiDecision,
    incident: &innerwarden_core::incident::Incident,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) -> (String, bool) {
    let req_detector = crate::agent_context::incident_detector(&incident.incident_id).to_string();
    let req_action = decision.action.name();
    let ttl = cfg.telegram.approval_ttl_secs;
    let now = chrono::Utc::now();

    // T.2 - send an inline-keyboard approval request via Telegram when enabled.
    // Capture the message id so the Telegram callback can edit the message; it
    // stays 0 when no Telegram message is sent (dashboard-only deployments).
    let mut telegram_message_id = 0;
    let mut channel: Option<&str> = None;
    if let Some(tg) = state.telegram_client.clone() {
        match tg
            .send_confirmation_request(incident, summary, req_action, decision.confidence, ttl)
            .await
        {
            Ok(msg_id) => {
                telegram_message_id = msg_id;
                channel = Some("Telegram");
            }
            Err(e) => tracing::warn!("Telegram confirmation request failed: {e:#}"),
        }
    }

    // Fallback notification: webhook when Telegram did not deliver. Best-effort -
    // a failed webhook must NOT drop the confirmation, which is still registered
    // below for dashboard approval.
    if channel.is_none() && cfg.webhook.enabled && !cfg.webhook.url.is_empty() {
        let payload = serde_json::json!({
            "type": "confirmation_required",
            "incident_id": incident.incident_id,
            "summary": summary,
            "decision_reason": decision.reason,
        });
        let client = reqwest::Client::new();
        match client.post(&cfg.webhook.url).json(&payload).send().await {
            Ok(_) => channel = Some("webhook"),
            Err(e) => tracing::warn!("confirmation webhook failed: {e}"),
        }
    }

    // Issue #71: register the pending confirmation so BOTH the Telegram callback
    // AND the dashboard 2FA endpoints can approve/deny it, independent of the
    // notification channel. This registration previously lived only inside the
    // Telegram-success branch, so a dashboard-only operator (no Telegram) got an
    // always-empty pending list and could never approve anything.
    let pending = telegram::PendingConfirmation {
        incident_id: incident.incident_id.clone(),
        telegram_message_id,
        action_description: summary.to_string(),
        created_at: now,
        expires_at: now + chrono::Duration::seconds(ttl as i64),
        detector: req_detector,
        action_name: req_action.to_string(),
    };
    if let Ok(mut map) = state.dashboard_pending.lock() {
        map.insert(incident.incident_id.clone(), pending.clone());
    }
    state.pending_confirmations.insert(
        incident.incident_id.clone(),
        (pending, decision.clone(), incident.clone()),
    );

    let status = match channel {
        Some("Telegram") => "pending: confirmation requested via Telegram (dashboard-approvable)",
        Some("webhook") => "pending: confirmation sent via webhook (dashboard-approvable)",
        _ => "pending: confirmation registered for dashboard approval",
    };
    (status.to_string(), false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn test_decision() -> ai::AiDecision {
        ai::AiDecision {
            action: ai::AiAction::RequestConfirmation {
                summary: "Need operator approval".to_string(),
            },
            confidence: 0.8,
            auto_execute: false,
            reason: "sensitive action".to_string(),
            alternatives: vec!["monitor".to_string()],
            estimated_threat: "high".to_string(),
        }
    }

    #[tokio::test]
    async fn registers_pending_for_dashboard_without_telegram_or_webhook() {
        // Issue #71 regression: on a dashboard-only deployment (no Telegram, no
        // webhook) the confirmation MUST still be registered so the dashboard
        // 2FA endpoints have something to approve. Previously the maps were only
        // populated on the Telegram-success path, leaving the dashboard blind.
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = config::AgentConfig::default();
        let incident = crate::tests::test_incident("203.0.113.10");

        let (status, pushed) = execute_request_confirmation(
            "please confirm",
            &test_decision(),
            &incident,
            &cfg,
            &mut state,
        )
        .await;

        assert_eq!(
            status,
            "pending: confirmation registered for dashboard approval"
        );
        assert!(!pushed);
        // Registered in BOTH the internal map (for execution) and the
        // dashboard-visible map (for /api/2fa/pending).
        assert!(state
            .pending_confirmations
            .contains_key(&incident.incident_id));
        let dash = state.dashboard_pending.lock().expect("lock");
        assert!(dash.contains_key(&incident.incident_id));
        assert_eq!(
            dash[&incident.incident_id].telegram_message_id, 0,
            "no Telegram message id on a dashboard-only registration"
        );
    }

    #[tokio::test]
    async fn webhook_fallback_reports_success() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let mut cfg = config::AgentConfig::default();

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("local addr");
        cfg.webhook.enabled = true;
        cfg.webhook.url = format!("http://{addr}/confirm");

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut buf = [0_u8; 4096];
            let _ = socket.read(&mut buf).await;
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .expect("write response");
        });

        let incident = crate::tests::test_incident("203.0.113.11");
        let (status, pushed) = execute_request_confirmation(
            "confirm via webhook",
            &test_decision(),
            &incident,
            &cfg,
            &mut state,
        )
        .await;

        server.await.expect("server task");
        assert_eq!(
            status,
            "pending: confirmation sent via webhook (dashboard-approvable)"
        );
        assert!(!pushed);
        // The confirmation is registered for dashboard approval even on the
        // webhook path (issue #71).
        assert!(state
            .pending_confirmations
            .contains_key(&incident.incident_id));
    }

    #[tokio::test]
    async fn webhook_fallback_reports_error() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let mut cfg = config::AgentConfig::default();
        cfg.webhook.enabled = true;
        // Port 9 should fail quickly on localhost when no listener is present.
        cfg.webhook.url = "http://127.0.0.1:9/confirm".to_string();
        let incident = crate::tests::test_incident("203.0.113.12");

        let (status, pushed) = execute_request_confirmation(
            "confirm via broken webhook",
            &test_decision(),
            &incident,
            &cfg,
            &mut state,
        )
        .await;

        // A failed webhook is best-effort: it must NOT drop the confirmation.
        // The action stays registered for dashboard approval (issue #71).
        assert_eq!(
            status,
            "pending: confirmation registered for dashboard approval"
        );
        assert!(!pushed);
        assert!(state
            .pending_confirmations
            .contains_key(&incident.incident_id));
    }
}
