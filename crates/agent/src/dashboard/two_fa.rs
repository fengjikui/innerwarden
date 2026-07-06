// Dashboard 2FA approval endpoints (Issue #71)
//
// Three REST endpoints that give the web dashboard feature-parity with the
// Telegram TOTP approval flow so operators can approve or deny pending
// security-action confirmation requests directly from the dashboard.
//
// Endpoints:
//   GET  /api/2fa/pending                   — list pending requests + deadlines
//   POST /api/2fa/approve/:approval_id      — approve (session token + TOTP)
//   POST /api/2fa/deny/:approval_id         — reject approval (no TOTP needed)
//
// Security model:
//   All three endpoints sit behind the standard `auth_layer` (Basic / Bearer
//   session token) and the `csrf_protection` middleware (requires the
//   `X-Requested-With: XMLHttpRequest` header on state-changing requests).
//
//   The approve endpoint additionally requires a valid TOTP code when
//   `[security].method = "totp"` — same gate as orphan-resolution and
//   trust-exec. The deny endpoint does NOT require TOTP: refusing a guarded
//   action can never cause harm.
//
// Shared state:
//   `DashboardState.pending_approvals` is an `Arc<Mutex<HashMap>>` shared with
//   the main agent loop via `AgentState.dashboard_pending`. It is populated by
//   `decision_confirmation.rs` when a Telegram confirmation request is created,
//   and consumed here on approve/deny. The agent loop drains
//   `DashboardState.approval_outcome_tx` each tick and executes or discards the
//   pending action via the same `process_telegram_approval` path used by
//   the Telegram handler.
//
// Design considerations:
//   - We intentionally peek before validating the TOTP code (see
//     `api_2fa_approve`). TOTP validation against a non-existent ID is a
//     wasted computation but not a security issue because the endpoints are
//     already auth-gated. The chosen order (validate ID → validate TOTP →
//     remove) avoids a silent discard of a valid entry if the caller types
//     the wrong ID while the TOTP window is still open.
//   - `DashboardApprovalOutcome.totp_verified` is a boolean, not the raw
//     code, to comply with CWE-532 (no credentials in log/struct fields).
//   - The deny body (`reason`) is optional — clients that send no body at
//     all still receive a 200, preventing brittle API contract violations.
//   - The `approval_id` in the URL is the `incident_id` of the pending
//     confirmation (the natural map key), matching the `approval_id` field
//     in the GET response.

use super::*;

/// Maximum length for an `approval_id` path segment (mirrors orphan-id limit).
const MAX_APPROVAL_ID_LEN: usize = 128;

// ---------------------------------------------------------------------------
// Response DTO for GET /api/2fa/pending
// ---------------------------------------------------------------------------

/// One pending confirmation entry returned by the GET endpoint.
/// Wraps `telegram::PendingConfirmation` without exposing Telegram-specific
/// fields (e.g. `telegram_message_id`).
#[derive(Serialize)]
struct PendingApprovalItem {
    /// ID to use in the approve/deny URL paths (equals `incident_id`).
    approval_id: String,
    incident_id: String,
    action_description: String,
    detector: String,
    action_name: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

#[derive(Serialize)]
struct PendingApprovalsResponse {
    total: usize,
    pending: Vec<PendingApprovalItem>,
}

// ---------------------------------------------------------------------------
// GET /api/2fa/pending
// ---------------------------------------------------------------------------

/// List all non-expired pending 2FA confirmation requests.
///
/// Returns an empty list when there are no pending items or when the map has
/// not been populated (e.g. standalone dashboard without the agent loop).
/// Expired entries are filtered in the response; they are lazily pruned from
/// the map by the background cleanup task in `serve()`.
pub(super) async fn api_2fa_pending(State(state): State<DashboardState>) -> impl IntoResponse {
    let now = Utc::now();
    let map = state
        .pending_approvals
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    let mut items: Vec<PendingApprovalItem> = map
        .iter()
        .filter(|(_, pc)| now < pc.expires_at)
        .map(|(incident_id, pc)| PendingApprovalItem {
            approval_id: incident_id.clone(),
            incident_id: pc.incident_id.clone(),
            action_description: pc.action_description.clone(),
            detector: pc.detector.clone(),
            action_name: pc.action_name.clone(),
            created_at: pc.created_at,
            expires_at: pc.expires_at,
        })
        .collect();

    // Sort by expiry ascending so the most time-critical request is first.
    items.sort_by_key(|item| item.expires_at);

    let total = items.len();
    Json(PendingApprovalsResponse {
        total,
        pending: items,
    })
}

// ---------------------------------------------------------------------------
// POST /api/2fa/approve/:approval_id
// ---------------------------------------------------------------------------

/// Approve a pending 2FA confirmation request.
///
/// Order of operations (important for correctness and auditability):
///   1. Validate `approval_id` format.
///   2. Peek at the map to confirm the entry exists and is not yet expired
///      **before** validating the TOTP code — prevents silent discard of a
///      valid entry caused by a caller typo in the ID.
///   3. Validate TOTP code (when enforcement is on).
///   4. Remove the entry atomically so a second concurrent approve cannot
///      double-fire.
///   5. Write audit row.
///   6. Notify agent loop via `approval_outcome_tx` (best-effort).
pub(super) async fn api_2fa_approve(
    State(state): State<DashboardState>,
    axum::extract::Path(approval_id): axum::extract::Path<String>,
    user: Option<axum::Extension<crate::dashboard::auth::AuthenticatedUser>>,
    Json(body): Json<TwoFaActionRequest>,
) -> Response {
    // ── 1. Validate approval_id format ──────────────────────────────────
    if approval_id.is_empty() || approval_id.len() > MAX_APPROVAL_ID_LEN {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid approval_id" })),
        )
            .into_response();
    }

    // ── 2. Peek — confirm entry exists and is not yet expired ────────────
    // Hold the lock only long enough to clone what we need, then release
    // before TOTP verification (which involves crypto).
    let peek = {
        let map = state
            .pending_approvals
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        map.get(&approval_id).cloned()
    };

    let Some(pc) = peek else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "approval request not found or already resolved"
            })),
        )
            .into_response();
    };

    if Utc::now() > pc.expires_at {
        // Remove the stale entry while we have the chance.
        state
            .pending_approvals
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&approval_id);
        return (
            StatusCode::GONE,
            Json(serde_json::json!({ "error": "approval request has expired" })),
        )
            .into_response();
    }

    // ── 3. Validate TOTP ────────────────────────────────────────────────
    if let Err(e) = crate::dashboard::agent_api::verify_dashboard_totp(&state, &body.totp) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": e })),
        )
            .into_response();
    }

    // ── 4. Remove atomically (second caller gets NOT_FOUND) ─────────────
    let removed = state
        .pending_approvals
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&approval_id);

    // Guard against a TOCTOU race where another request removed it between
    // our peek and this remove (extremely unlikely but handled for safety).
    if removed.is_none() {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "approval request was resolved concurrently"
            })),
        )
            .into_response();
    }

    let operator = user
        .map(|axum::Extension(u)| u.0)
        .unwrap_or_else(|| crate::dashboard::auth::AuthenticatedUser::ANONYMOUS.to_string());

    // ── 5. Audit trail ───────────────────────────────────────────────────
    let _ = innerwarden_core::audit::append_admin_action(
        &state.data_dir,
        &mut innerwarden_core::audit::AdminActionEntry {
            ts: Utc::now(),
            operator: operator.clone(),
            source: "dashboard".into(),
            action: "2fa_approve".into(),
            target: approval_id.clone(),
            parameters: serde_json::json!({
                "incident_id": pc.incident_id,
                "action_description": pc.action_description,
                "detector": pc.detector,
                "action_name": pc.action_name,
                "two_factor": if state.two_factor.is_enforced() { "enforced" } else { "none" },
            }),
            result: "success".into(),
            prev_hash: None,
        },
    );

    info!(
        operator = %operator,
        approval_id = %approval_id,
        incident_id = %pc.incident_id,
        detector = %pc.detector,
        "2FA approval granted via dashboard",
    );

    // ── 6. Notify agent loop ─────────────────────────────────────────────
    // `try_send` is fire-and-forget: the agent loop drains this channel on
    // its next tick. A full channel means the loop is busy; the operator can
    // retry (the request is already removed so a retry will get NOT_FOUND and
    // know the decision was recorded).
    if let Some(tx) = &state.approval_outcome_tx {
        let _ = tx.try_send(DashboardApprovalOutcome {
            incident_id: pc.incident_id.clone(),
            approved: true,
            operator,
            totp_verified: true,
        });
    }

    Json(serde_json::json!({
        "approved": true,
        "approval_id": approval_id,
        "incident_id": pc.incident_id,
        "action_description": pc.action_description,
    }))
    .into_response()
}

// ---------------------------------------------------------------------------
// POST /api/2fa/deny/:approval_id
// ---------------------------------------------------------------------------

/// Deny a pending 2FA confirmation request.
///
/// Does NOT require a TOTP code — refusing a guarded action can never cause
/// harm. The request body is entirely optional: a deny with no JSON body is
/// valid and records an empty reason in the audit row.
///
/// Returns 410 Gone (rather than 200) when the entry has already expired so
/// operators know the deadline passed before they acted.
pub(super) async fn api_2fa_deny(
    State(state): State<DashboardState>,
    axum::extract::Path(approval_id): axum::extract::Path<String>,
    user: Option<axum::Extension<crate::dashboard::auth::AuthenticatedUser>>,
    // Body is optional: `None` when the client sends no body at all.
    body: Option<Json<TwoFaActionRequest>>,
) -> Response {
    // ── 1. Validate approval_id format ──────────────────────────────────
    if approval_id.is_empty() || approval_id.len() > MAX_APPROVAL_ID_LEN {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid approval_id" })),
        )
            .into_response();
    }

    let reason = body.map(|Json(b)| b.reason).unwrap_or_default();

    // ── 2. Remove atomically ────────────────────────────────────────────
    let entry = {
        let mut map = state
            .pending_approvals
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        map.remove(&approval_id)
    };

    let Some(pc) = entry else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "approval request not found or already resolved"
            })),
        )
            .into_response();
    };

    if Utc::now() > pc.expires_at {
        return (
            StatusCode::GONE,
            Json(serde_json::json!({ "error": "approval request has expired" })),
        )
            .into_response();
    }

    let operator = user
        .map(|axum::Extension(u)| u.0)
        .unwrap_or_else(|| crate::dashboard::auth::AuthenticatedUser::ANONYMOUS.to_string());

    // ── 3. Audit trail ───────────────────────────────────────────────────
    let _ = innerwarden_core::audit::append_admin_action(
        &state.data_dir,
        &mut innerwarden_core::audit::AdminActionEntry {
            ts: Utc::now(),
            operator: operator.clone(),
            source: "dashboard".into(),
            action: "2fa_deny".into(),
            target: approval_id.clone(),
            parameters: serde_json::json!({
                "incident_id": pc.incident_id,
                "action_description": pc.action_description,
                "detector": pc.detector,
                "action_name": pc.action_name,
                "reason": reason,
            }),
            result: "denied".into(),
            prev_hash: None,
        },
    );

    info!(
        operator = %operator,
        approval_id = %approval_id,
        incident_id = %pc.incident_id,
        detector = %pc.detector,
        "2FA approval denied via dashboard",
    );

    // ── 4. Notify agent loop ─────────────────────────────────────────────
    if let Some(tx) = &state.approval_outcome_tx {
        let _ = tx.try_send(DashboardApprovalOutcome {
            incident_id: pc.incident_id.clone(),
            approved: false,
            operator,
            totp_verified: false,
        });
    }

    Json(serde_json::json!({
        "approved": false,
        "approval_id": approval_id,
        "incident_id": pc.incident_id,
        "action_description": pc.action_description,
    }))
    .into_response()
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a `PendingConfirmation` keyed by `incident_id`.
    fn make_pending(incident_id: &str, expired: bool) -> crate::telegram::PendingConfirmation {
        let now = Utc::now();
        let expires_at = if expired {
            now - chrono::Duration::minutes(10)
        } else {
            now + chrono::Duration::minutes(30)
        };
        crate::telegram::PendingConfirmation {
            incident_id: incident_id.to_string(),
            telegram_message_id: 0,
            action_description: format!("block IP for incident {incident_id}"),
            created_at: now - chrono::Duration::minutes(5),
            expires_at,
            detector: "ssh_brute_force".to_string(),
            action_name: "block_ip".to_string(),
        }
    }

    // ── pending map mechanics ────────────────────────────────────────────

    #[test]
    fn pending_approvals_map_insert_and_remove() {
        let store: Arc<
            Mutex<std::collections::HashMap<String, crate::telegram::PendingConfirmation>>,
        > = Arc::new(Mutex::new(std::collections::HashMap::new()));

        store
            .lock()
            .unwrap()
            .insert("inc-abc".to_string(), make_pending("inc-abc", false));

        {
            let map = store.lock().unwrap();
            assert!(map.contains_key("inc-abc"));
            assert_eq!(map["inc-abc"].incident_id, "inc-abc");
        }

        store.lock().unwrap().remove("inc-abc");
        assert!(store.lock().unwrap().is_empty());
    }

    // ── GET /api/2fa/pending ─────────────────────────────────────────────

    #[tokio::test]
    async fn api_2fa_pending_returns_empty_when_no_requests() {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::dashboard::state::test_dashboard_state(dir.path());
        let resp = api_2fa_pending(State(state)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["total"], 0);
        assert!(json["pending"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn api_2fa_pending_filters_expired_requests() {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::dashboard::state::test_dashboard_state(dir.path());

        {
            let mut map = state.pending_approvals.lock().unwrap();
            map.insert("active".to_string(), make_pending("active", false));
            map.insert("expired".to_string(), make_pending("expired", true));
        }

        let resp = api_2fa_pending(State(state)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["total"], 1);
        assert_eq!(json["pending"][0]["approval_id"], "active");
    }

    #[tokio::test]
    async fn api_2fa_pending_sorts_by_deadline_ascending() {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::dashboard::state::test_dashboard_state(dir.path());
        let now = Utc::now();

        {
            let mut map = state.pending_approvals.lock().unwrap();
            let mut sooner = make_pending("sooner", false);
            sooner.expires_at = now + chrono::Duration::minutes(10);
            let mut later = make_pending("later", false);
            later.expires_at = now + chrono::Duration::minutes(60);
            map.insert("later".to_string(), later);
            map.insert("sooner".to_string(), sooner);
        }

        let resp = api_2fa_pending(State(state)).await.into_response();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["pending"][0]["approval_id"], "sooner");
        assert_eq!(json["pending"][1]["approval_id"], "later");
    }

    // ── approve: approval_id validation ──────────────────────────────────

    #[tokio::test]
    async fn api_2fa_approve_rejects_empty_approval_id() {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::dashboard::state::test_dashboard_state(dir.path());

        let resp = api_2fa_approve(
            State(state),
            axum::extract::Path(String::new()),
            None,
            Json(TwoFaActionRequest::default()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn api_2fa_approve_rejects_oversized_approval_id() {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::dashboard::state::test_dashboard_state(dir.path());
        let long_id = "x".repeat(MAX_APPROVAL_ID_LEN + 1);

        let resp = api_2fa_approve(
            State(state),
            axum::extract::Path(long_id),
            None,
            Json(TwoFaActionRequest::default()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn api_2fa_approve_returns_not_found_for_unknown_id() {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::dashboard::state::test_dashboard_state(dir.path());

        let resp = api_2fa_approve(
            State(state),
            axum::extract::Path("no-such-id".to_string()),
            None,
            Json(TwoFaActionRequest::default()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn api_2fa_approve_returns_gone_for_expired_entry() {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::dashboard::state::test_dashboard_state(dir.path());
        state
            .pending_approvals
            .lock()
            .unwrap()
            .insert("exp".to_string(), make_pending("exp", true));

        let resp = api_2fa_approve(
            State(state),
            axum::extract::Path("exp".to_string()),
            None,
            Json(TwoFaActionRequest::default()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::GONE);
    }

    // ── approve: success paths ────────────────────────────────────────────

    #[tokio::test]
    async fn api_2fa_approve_succeeds_when_2fa_not_enforced() {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::dashboard::state::test_dashboard_state(dir.path());
        state
            .pending_approvals
            .lock()
            .unwrap()
            .insert("inc-ok".to_string(), make_pending("inc-ok", false));

        let resp = api_2fa_approve(
            State(state),
            axum::extract::Path("inc-ok".to_string()),
            None,
            Json(TwoFaActionRequest::default()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["approved"], true);
        assert_eq!(json["approval_id"], "inc-ok");
    }

    #[tokio::test]
    async fn api_2fa_approve_removes_entry_from_map() {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::dashboard::state::test_dashboard_state(dir.path());
        state
            .pending_approvals
            .lock()
            .unwrap()
            .insert("inc-rm".to_string(), make_pending("inc-rm", false));

        let resp = api_2fa_approve(
            State(state.clone()),
            axum::extract::Path("inc-rm".to_string()),
            None,
            Json(TwoFaActionRequest::default()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            state
                .pending_approvals
                .lock()
                .unwrap()
                .get("inc-rm")
                .is_none(),
            "entry must be removed from map after approve"
        );
    }

    #[tokio::test]
    async fn api_2fa_approve_notifies_channel() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = crate::dashboard::state::test_dashboard_state(dir.path());
        let (tx, mut rx) = tokio::sync::mpsc::channel::<DashboardApprovalOutcome>(8);
        state.approval_outcome_tx = Some(tx);
        state
            .pending_approvals
            .lock()
            .unwrap()
            .insert("inc-ch".to_string(), make_pending("inc-ch", false));

        let resp = api_2fa_approve(
            State(state),
            axum::extract::Path("inc-ch".to_string()),
            None,
            Json(TwoFaActionRequest::default()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        let outcome = rx
            .try_recv()
            .expect("channel must have received an outcome");
        assert!(outcome.approved);
        assert_eq!(outcome.incident_id, "inc-ch");
        assert!(outcome.totp_verified);
    }

    #[tokio::test]
    async fn api_2fa_approve_wrong_totp_returns_unauthorized() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = crate::dashboard::state::test_dashboard_state(dir.path());
        // Enable TOTP enforcement with a known test secret.
        state.two_factor = std::sync::Arc::new(crate::dashboard::state::TwoFactorSettings::new(
            "totp",
            "JBSWY3DPEHPK3PXP",
        ));
        state
            .pending_approvals
            .lock()
            .unwrap()
            .insert("inc-bad".to_string(), make_pending("inc-bad", false));

        let resp = api_2fa_approve(
            State(state),
            axum::extract::Path("inc-bad".to_string()),
            None,
            // "000000" is virtually never a valid TOTP code at any given moment.
            Json(TwoFaActionRequest {
                totp: "000000".to_string(),
                reason: String::new(),
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ── deny: validation and optional body ───────────────────────────────

    #[tokio::test]
    async fn api_2fa_deny_rejects_empty_approval_id() {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::dashboard::state::test_dashboard_state(dir.path());

        let resp = api_2fa_deny(State(state), axum::extract::Path(String::new()), None, None).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn api_2fa_deny_accepts_no_body() {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::dashboard::state::test_dashboard_state(dir.path());
        state
            .pending_approvals
            .lock()
            .unwrap()
            .insert("d1".to_string(), make_pending("d1", false));

        let resp = api_2fa_deny(
            State(state),
            axum::extract::Path("d1".to_string()),
            None,
            None, // simulates client that sends no JSON body
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["approved"], false);
    }

    #[tokio::test]
    async fn api_2fa_deny_returns_not_found_for_unknown_id() {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::dashboard::state::test_dashboard_state(dir.path());

        let resp = api_2fa_deny(
            State(state),
            axum::extract::Path("ghost".to_string()),
            None,
            None,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn api_2fa_deny_removes_entry_from_map() {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::dashboard::state::test_dashboard_state(dir.path());
        state
            .pending_approvals
            .lock()
            .unwrap()
            .insert("rem".to_string(), make_pending("rem", false));

        let resp = api_2fa_deny(
            State(state.clone()),
            axum::extract::Path("rem".to_string()),
            None,
            None,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        assert!(
            state.pending_approvals.lock().unwrap().get("rem").is_none(),
            "entry must be removed from map after deny"
        );
    }

    // ── deny: success paths ───────────────────────────────────────────────

    #[tokio::test]
    async fn api_2fa_deny_notifies_channel() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = crate::dashboard::state::test_dashboard_state(dir.path());
        let (tx, mut rx) = tokio::sync::mpsc::channel::<DashboardApprovalOutcome>(8);
        state.approval_outcome_tx = Some(tx);
        state
            .pending_approvals
            .lock()
            .unwrap()
            .insert("inc-deny".to_string(), make_pending("inc-deny", false));

        let resp = api_2fa_deny(
            State(state),
            axum::extract::Path("inc-deny".to_string()),
            None,
            None,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        let outcome = rx
            .try_recv()
            .expect("channel must have received an outcome");
        assert!(!outcome.approved);
        assert_eq!(outcome.incident_id, "inc-deny");
    }

    #[tokio::test]
    async fn api_2fa_deny_with_reason_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::dashboard::state::test_dashboard_state(dir.path());
        state
            .pending_approvals
            .lock()
            .unwrap()
            .insert("inc-rsn".to_string(), make_pending("inc-rsn", false));

        let resp = api_2fa_deny(
            State(state),
            axum::extract::Path("inc-rsn".to_string()),
            None,
            Some(Json(TwoFaActionRequest {
                totp: String::new(),
                reason: "false positive — known scanner".to_string(),
            })),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["approved"], false);
        assert_eq!(json["approval_id"], "inc-rsn");
    }
}
