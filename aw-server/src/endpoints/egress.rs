use aw_datastore::{Datastore, DatastoreError};
use aw_egress::{
    policy_diff, verify_and_activate, EgressProxy, EgressUserPolicyPreview,
    PolicyBundleErrorV1, VerifiedPolicyV1,
};
use aw_models::{
    EgressApprovalScopeV1, EgressApprovalV1, EgressPolicyDiffV1, EgressPolicyV1,
    EgressPreviewV1, EgressReceiptV1, EgressRequestV1, EgressUserPolicyV1,
    SignedEgressPolicyBundleV1,
};
use chrono::{DateTime, Utc};
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::State;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use crate::endpoints::{HttpErrorJson, ServerState};

#[derive(Clone)]
pub struct EgressPolicyTrust {
    keys: HashMap<String, Vec<u8>>,
    activation_gate: Arc<Mutex<()>>,
}

impl EgressPolicyTrust {
    /// Release builds pass only independently reviewed embedded public keys.
    pub fn from_release_keys(keys: HashMap<String, Vec<u8>>) -> Self {
        Self { keys, activation_gate: Arc::new(Mutex::new(())) }
    }

    fn key_count(&self) -> usize { self.keys.len() }
}

impl Default for EgressPolicyTrust {
    fn default() -> Self { Self::from_release_keys(HashMap::new()) }
}

impl fmt::Debug for EgressPolicyTrust {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EgressPolicyTrust").field("trusted_key_count", &self.keys.len()).finish()
    }
}

#[derive(Debug, Serialize)]
pub struct EgressStatusV1 {
    pub schema_version: u16,
    pub kill_switch_enabled: bool,
    pub policy_bundle_stored: bool,
    pub policy_bundle_version: Option<u64>,
    pub trusted_policy_keys: usize,
    pub outbound_enabled: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KillSwitchRequest {
    enabled: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendEgressRequest {
    preview_id: String,
    approval_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateEgressApprovalRequest {
    preview_id: String,
    scope: EgressApprovalScopeV1,
    expires_at: Option<DateTime<Utc>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptEgressPolicyRequest {
    accept: bool,
    bundle: SignedEgressPolicyBundleV1,
    expected_diff: EgressPolicyDiffV1,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptUserPolicyRequest {
    preview_id: String,
}

fn bundle_error(error: PolicyBundleErrorV1, trust: &EgressPolicyTrust) -> HttpErrorJson {
    let status = match error {
        PolicyBundleErrorV1::StaleVersion | PolicyBundleErrorV1::HardDenyRollback => Status::Conflict,
        PolicyBundleErrorV1::UnknownSigner if trust.key_count() == 0 => Status::ServiceUnavailable,
        PolicyBundleErrorV1::UnknownSigner => Status::Forbidden,
        _ => Status::UnprocessableEntity,
    };
    HttpErrorJson::new(status, "The signed outbound policy could not be verified.".into())
}

fn verified_stored_policy(
    datastore: &Datastore,
    trust: &EgressPolicyTrust,
) -> Result<Option<(SignedEgressPolicyBundleV1, EgressUserPolicyV1, VerifiedPolicyV1)>, HttpErrorJson> {
    let Some((bundle, user_policy)) = datastore.get_egress_policy_state().map_err(|_| {
        HttpErrorJson::new(Status::ServiceUnavailable, "Privacy Firewall policy is unavailable; outbound requests remain blocked.".into())
    })? else { return Ok(None); };
    let verified = verify_and_activate(&bundle, &user_policy, &trust.keys, None)
        .map_err(|error| bundle_error(error, trust))?;
    Ok(Some((bundle, user_policy, verified)))
}

pub(super) fn active_policy(datastore: &Datastore, trust: &EgressPolicyTrust) -> Result<VerifiedPolicyV1, HttpErrorJson> {
    verified_stored_policy(datastore, trust)?
        .map(|(_, _, verified)| verified)
        .ok_or_else(|| HttpErrorJson::new(Status::ServiceUnavailable, "No trusted outbound policy is configured.".into()))
}

fn verified_candidate(
    datastore: &Datastore,
    trust: &EgressPolicyTrust,
    bundle: &SignedEgressPolicyBundleV1,
) -> Result<(EgressUserPolicyV1, VerifiedPolicyV1, EgressPolicyDiffV1), HttpErrorJson> {
    let stored = verified_stored_policy(datastore, trust)?;
    let user_policy = match stored.as_ref() {
        Some((_, user_policy, _)) => user_policy.clone(),
        None => datastore.get_egress_user_policy().map_err(HttpErrorJson::from)?,
    };
    let current = stored.as_ref().map(|(_, _, verified)| verified.policy());
    let next = verify_and_activate(bundle, &user_policy, &trust.keys, current)
        .map_err(|error| bundle_error(error, trust))?;
    let mut previous = current.cloned().unwrap_or_else(empty_policy);
    if current.is_none() {
        previous.user_rules = user_policy.user_rules.clone();
        previous.safe_zone_patterns = user_policy.safe_zone_patterns.clone();
        previous.after_hours = user_policy.after_hours.clone();
    }
    let diff = policy_diff(&previous, next.policy());
    Ok((user_policy, next, diff))
}

fn user_policy_base(
    datastore: &Datastore,
    trust: &EgressPolicyTrust,
) -> Result<(EgressPolicyV1, EgressUserPolicyV1), HttpErrorJson> {
    if let Some((_, user_policy, verified)) = verified_stored_policy(datastore, trust)? {
        return Ok((verified.policy().clone(), user_policy));
    }
    let user_policy = datastore.get_egress_user_policy().map_err(HttpErrorJson::from)?;
    let mut policy = empty_policy();
    policy.user_rules = user_policy.user_rules.clone();
    policy.safe_zone_patterns = user_policy.safe_zone_patterns.clone();
    policy.after_hours = user_policy.after_hours.clone();
    Ok((policy, user_policy))
}

fn empty_policy() -> EgressPolicyV1 {
    EgressPolicyV1 {
        schema_version: 1,
        version: 0,
        hard_deny_version: 0,
        destinations: Vec::new(),
        purposes: Vec::new(),
        organization_rules: Vec::new(),
        user_rules: Vec::new(),
        safe_zone_patterns: Vec::new(),
        after_hours: None,
    }
}

fn proxy_error(reason: aw_models::EgressReasonCodeV1) -> HttpErrorJson {
    let status = match reason {
        aw_models::EgressReasonCodeV1::KillSwitch => Status::Forbidden,
        aw_models::EgressReasonCodeV1::ApprovalExpired | aw_models::EgressReasonCodeV1::PolicyChanged => Status::Conflict,
        _ => Status::Forbidden,
    };
    let reason = serde_json::to_string(&reason).unwrap_or_else(|_| "\"denied\"".into());
    HttpErrorJson::new(status, format!("Outbound request denied: {reason}"))
}

#[get("/status")]
pub fn status(
    state: &State<ServerState>,
    proxy: &State<EgressProxy>,
    trust: &State<EgressPolicyTrust>,
) -> Result<Json<EgressStatusV1>, HttpErrorJson> {
    let kill_switch_enabled = proxy.kill_switch_enabled().map_err(proxy_error)?;
    let policy = state.datastore.get_egress_policy_state().map_err(|_| {
        HttpErrorJson::new(Status::ServiceUnavailable, "Privacy Firewall policy is unavailable; outbound requests remain blocked.".into())
    })?;
    let policy_bundle_version = policy.as_ref().map(|(bundle, _)| bundle.bundle.version);
    let policy_bundle_stored = policy.is_some();
    // No product release signing key is configured in this development candidate.
    let trusted_policy_keys = trust.key_count();
    let outbound_enabled = !kill_switch_enabled && active_policy(&state.datastore, trust.inner()).is_ok();
    Ok(Json(EgressStatusV1 {
        schema_version: 1,
        kill_switch_enabled,
        policy_bundle_stored,
        policy_bundle_version,
        trusted_policy_keys,
        outbound_enabled,
    }))
}

#[get("/receipts?<limit>")]
pub fn receipts(
    limit: Option<usize>,
    state: &State<ServerState>,
) -> Result<Json<Vec<EgressReceiptV1>>, HttpErrorJson> {
    state.datastore.get_egress_receipts(limit.unwrap_or(100).min(100))
        .map(Json)
        .map_err(DatastoreError::into)
}

#[get("/approvals?<limit>")]
pub async fn approvals(
    limit: Option<usize>,
    state: &State<ServerState>,
) -> Result<Json<Vec<EgressApprovalV1>>, HttpErrorJson> {
    let datastore = state.datastore.clone();
    rocket::tokio::task::spawn_blocking(move || {
        datastore.get_egress_approvals(limit.unwrap_or(50).min(100), Utc::now())
            .map(Json)
            .map_err(HttpErrorJson::from)
    })
    .await
    .map_err(|_| HttpErrorJson::new(Status::ServiceUnavailable, "Privacy Firewall approvals are unavailable.".into()))?
}

#[get("/user-policy")]
pub async fn user_policy(state: &State<ServerState>) -> Result<Json<EgressUserPolicyV1>, HttpErrorJson> {
    let datastore = state.datastore.clone();
    rocket::tokio::task::spawn_blocking(move || datastore.get_egress_user_policy().map(Json).map_err(DatastoreError::into))
        .await
        .map_err(|_| HttpErrorJson::new(Status::ServiceUnavailable, "Privacy Firewall policy is unavailable.".into()))?
}

#[post("/user-policy/diff", data = "<draft>", format = "application/json")]
pub async fn preview_user_policy(
    draft: Json<EgressUserPolicyV1>,
    state: &State<ServerState>,
    trust: &State<EgressPolicyTrust>,
    proxy: &State<EgressProxy>,
) -> Result<Json<EgressUserPolicyPreview>, HttpErrorJson> {
    let datastore = state.datastore.clone();
    let trust = trust.inner().clone();
    let proxy = proxy.inner().clone();
    let draft = draft.into_inner();
    draft.validate().map_err(|_| HttpErrorJson::new(Status::BadRequest, "Invalid local privacy policy.".into()))?;
    rocket::tokio::task::spawn_blocking(move || {
        let (current, user) = user_policy_base(&datastore, &trust)?;
        proxy.preview_user_policy(&current, &user, &draft, Utc::now())
            .map(Json)
            .map_err(proxy_error)
    })
        .await
        .map_err(|_| HttpErrorJson::new(Status::ServiceUnavailable, "Privacy Firewall policy is unavailable.".into()))?
}

#[put("/user-policy/accept", data = "<request>", format = "application/json")]
pub async fn accept_user_policy(
    request: Json<AcceptUserPolicyRequest>,
    state: &State<ServerState>,
    trust: &State<EgressPolicyTrust>,
    proxy: &State<EgressProxy>,
) -> Result<Status, HttpErrorJson> {
    let preview_id = request.preview_id.clone();
    let datastore = state.datastore.clone();
    let trust = trust.inner().clone();
    let proxy = proxy.inner().clone();
    rocket::tokio::task::spawn_blocking(move || {
        proxy.with_policy_update(|| {
            let _activation = trust.activation_gate.lock()
                .map_err(|_| HttpErrorJson::new(Status::ServiceUnavailable, "Privacy Firewall policy is unavailable.".into()))?;
            let (current, current_user) = user_policy_base(&datastore, &trust)?;
            let (expected, accepted) = proxy.accept_user_policy(&preview_id, &current, Utc::now())
                .map_err(proxy_error)?;
            if expected != current_user {
                return Err(HttpErrorJson::new(Status::Conflict, "Local privacy rules changed after review.".into()));
            }
            datastore.store_egress_user_policy(&accepted).map_err(HttpErrorJson::from)?;
            Ok(Status::Ok)
        }).map_err(proxy_error)?
    })
    .await
    .map_err(|_| HttpErrorJson::new(Status::ServiceUnavailable, "Privacy Firewall policy is unavailable.".into()))?
}

#[get("/policy")]
pub async fn policy(
    state: &State<ServerState>,
    trust: &State<EgressPolicyTrust>,
) -> Result<Json<EgressPolicyV1>, HttpErrorJson> {
    let datastore = state.datastore.clone();
    let trust = trust.inner().clone();
    rocket::tokio::task::spawn_blocking(move || {
        active_policy(&datastore, &trust).map(|verified| Json(verified.policy().clone()))
    })
    .await
    .map_err(|_| HttpErrorJson::new(Status::ServiceUnavailable, "Privacy Firewall policy is unavailable.".into()))?
}

#[post("/policy/diff", data = "<bundle>", format = "application/json")]
pub async fn policy_diff_preview(
    bundle: Json<SignedEgressPolicyBundleV1>,
    state: &State<ServerState>,
    trust: &State<EgressPolicyTrust>,
) -> Result<Json<EgressPolicyDiffV1>, HttpErrorJson> {
    let datastore = state.datastore.clone();
    let trust = trust.inner().clone();
    let bundle = bundle.into_inner();
    rocket::tokio::task::spawn_blocking(move || {
        verified_candidate(&datastore, &trust, &bundle).map(|(_, _, diff)| Json(diff))
    })
    .await
    .map_err(|_| HttpErrorJson::new(Status::ServiceUnavailable, "Privacy Firewall policy is unavailable.".into()))?
}

#[put("/policy/accept", data = "<request>", format = "application/json")]
pub async fn accept_policy(
    request: Json<AcceptEgressPolicyRequest>,
    state: &State<ServerState>,
    trust: &State<EgressPolicyTrust>,
    proxy: &State<EgressProxy>,
) -> Result<Status, HttpErrorJson> {
    let request = request.into_inner();
    if !request.accept {
        return Err(HttpErrorJson::new(Status::BadRequest, "Policy diff acceptance is required.".into()));
    }
    let datastore = state.datastore.clone();
    let trust = trust.inner().clone();
    let proxy = proxy.inner().clone();
    rocket::tokio::task::spawn_blocking(move || {
        proxy.with_policy_update(|| {
            let _gate = trust.activation_gate.lock()
                .map_err(|_| HttpErrorJson::new(Status::ServiceUnavailable, "Privacy Firewall policy is unavailable.".into()))?;
            let (user_policy, _verified, actual_diff) = verified_candidate(&datastore, &trust, &request.bundle)?;
            if actual_diff != request.expected_diff {
                return Err(HttpErrorJson::new(Status::Conflict, "The policy changed after its diff was reviewed.".into()));
            }
            datastore.store_egress_policy_state(&request.bundle, &user_policy)
                .map_err(HttpErrorJson::from)?;
            Ok(Status::Ok)
        }).map_err(proxy_error)?
    })
    .await
    .map_err(|_| HttpErrorJson::new(Status::ServiceUnavailable, "Privacy Firewall policy is unavailable.".into()))?
}

#[delete("/approvals")]
pub async fn revoke_approvals(state: &State<ServerState>) -> Result<Status, HttpErrorJson> {
    let datastore = state.datastore.clone();
    rocket::tokio::task::spawn_blocking(move || datastore.clear_egress_approvals().map(|_| Status::Ok).map_err(DatastoreError::into))
        .await
        .map_err(|_| HttpErrorJson::new(Status::ServiceUnavailable, "Privacy Firewall approvals are unavailable.".into()))?
}

#[post("/approve", data = "<request>", format = "application/json")]
pub async fn approve(
    request: Json<CreateEgressApprovalRequest>,
    state: &State<ServerState>,
    proxy: &State<EgressProxy>,
    trust: &State<EgressPolicyTrust>,
) -> Result<Json<EgressApprovalV1>, HttpErrorJson> {
    let request = request.into_inner();
    let datastore = state.datastore.clone();
    let proxy = proxy.inner().clone();
    let trust = trust.inner().clone();
    rocket::tokio::task::spawn_blocking(move || {
        let send_guard = proxy.begin_send().map_err(proxy_error)?;
        let policy = active_policy(&datastore, &trust)?;
        let now = Utc::now();
        let offset = chrono::Local::now().offset().local_minus_utc();
        let approved = send_guard.approve(
            &policy, &request.preview_id, request.scope, request.expires_at, now, offset,
        ).map_err(proxy_error)?;
        datastore.get_egress_approval(approved.approval_id(), now)
            .map_err(HttpErrorJson::from)?
            .map(Json)
            .ok_or_else(|| HttpErrorJson::new(Status::Conflict, "Approval expired before it could be loaded.".into()))
    })
    .await
    .map_err(|_| HttpErrorJson::new(Status::ServiceUnavailable, "Outbound approval is unavailable.".into()))?
}

#[post("/kill-switch", data = "<request>", format = "application/json")]
pub async fn set_kill_switch(
    request: Json<KillSwitchRequest>,
    proxy: &State<EgressProxy>,
) -> Result<Status, HttpErrorJson> {
    let proxy = proxy.inner().clone();
    let enabled = request.enabled;
    rocket::tokio::task::spawn_blocking(move || proxy.set_kill_switch(enabled))
        .await
        .map_err(|_| HttpErrorJson::new(Status::ServiceUnavailable, "Outbound control is unavailable.".into()))?
        .map_err(proxy_error)?;
    Ok(Status::Ok)
}

#[post("/preview", data = "<request>", format = "application/json")]
pub async fn preview(
    request: Json<EgressRequestV1>,
    state: &State<ServerState>,
    proxy: &State<EgressProxy>,
    trust: &State<EgressPolicyTrust>,
) -> Result<Json<EgressPreviewV1>, HttpErrorJson> {
    let datastore = state.datastore.clone();
    let proxy = proxy.inner().clone();
    let trust = trust.inner().clone();
    let request = request.into_inner();
    let offset = chrono::Local::now().offset().local_minus_utc();
    let decision = rocket::tokio::task::spawn_blocking(move || {
        let policy = active_policy(&datastore, &trust)?;
        let destination_id = request.destination_id.clone();
        let purpose_id = request.purpose_id.clone();
        let retention_id = request.retention_id.clone();
        let destination_origin = policy.policy().destinations.iter()
            .find(|item| item.id == destination_id)
            .and_then(|item| item.https_origin.clone());
        let retention_disclosure = policy.policy().purposes.iter()
            .find(|item| item.id == purpose_id && item.retention_id == retention_id)
            .map(|item| item.retention_disclosure.clone());
        let preview = proxy.preview(&policy, request, Utc::now(), offset);
        Ok::<_, HttpErrorJson>(EgressPreviewV1 {
            schema_version: 1,
            destination_id,
            destination_origin,
            purpose_id,
            retention_id,
            retention_disclosure,
            decision: preview,
        })
    }).await.map_err(|_| HttpErrorJson::new(Status::ServiceUnavailable, "Outbound preview is unavailable.".into()))??;
    Ok(Json(decision))
}

#[post("/send", data = "<request>", format = "application/json")]
pub async fn send(
    request: Json<SendEgressRequest>,
    state: &State<ServerState>,
    proxy: &State<EgressProxy>,
    trust: &State<EgressPolicyTrust>,
) -> Result<Json<EgressReceiptV1>, HttpErrorJson> {
    let datastore = state.datastore.clone();
    let proxy = proxy.inner().clone();
    let trust = trust.inner().clone();
    let preview_id = request.preview_id.clone();
    let approval_id = request.approval_id.clone();
    let receipt = rocket::tokio::task::spawn_blocking(move || {
        let send_guard = proxy.begin_send().map_err(proxy_error)?;
        let policy = active_policy(&datastore, &trust)?;
        let now = Utc::now();
        let offset = chrono::Local::now().offset().local_minus_utc();
        send_guard.send_approval(&policy, &preview_id, &approval_id, now, offset).map_err(proxy_error)
    }).await.map_err(|_| HttpErrorJson::new(Status::ServiceUnavailable, "Outbound proxy is unavailable.".into()))??;
    Ok(Json(receipt))
}
