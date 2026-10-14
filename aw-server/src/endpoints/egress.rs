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

pub(crate) fn active_policy(datastore: &Datastore, trust: &EgressPolicyTrust) -> Result<VerifiedPolicyV1, HttpErrorJson> {
    verified_stored_policy(datastore, trust)?
        .map(|(_, _, verified)| verified)
        .ok_or_else(|| HttpErrorJson::new(Status::ServiceUnavailable, "No trusted outbound policy is configured.".into()))
}

fn verified_candidate(
    datastore: &Datastore,
    trust: &EgressPolicyTrust,
    bundle: &SignedEgressPolicyBundleV1,
) -> Result<(EgressUserPolicyV1, VerifiedPolicyV1, EgressPolicyDiffV1), HttpErrorJson> {
    let stored = datastore
        .get_egress_policy_state()
        .map_err(HttpErrorJson::from)?;
    let user_policy = match stored.as_ref() {
        Some((_, user)) => user.clone(),
        None => datastore
            .get_egress_user_policy()
            .map_err(HttpErrorJson::from)?,
    };
    let (next, diff) = verified_candidate_in_state(
        trust,
        bundle,
        stored.as_ref().map(|(bundle, _)| bundle),
        &user_policy,
    )?;
    Ok((user_policy, next, diff))
}

fn policy_in_state(
    trust: &EgressPolicyTrust,
    bundle: Option<&SignedEgressPolicyBundleV1>,
    user: &EgressUserPolicyV1,
) -> Result<EgressPolicyV1, HttpErrorJson> {
    if let Some(bundle) = bundle {
        return verify_and_activate(bundle, user, &trust.keys, None)
            .map(|verified| verified.policy().clone())
            .map_err(|error| bundle_error(error, trust));
    }
    let mut policy = empty_policy();
    policy.user_rules = user.user_rules.clone();
    policy.safe_zone_patterns = user.safe_zone_patterns.clone();
    policy.after_hours = user.after_hours.clone();
    Ok(policy)
}

fn verified_candidate_in_state(
    trust: &EgressPolicyTrust,
    bundle: &SignedEgressPolicyBundleV1,
    current_bundle: Option<&SignedEgressPolicyBundleV1>,
    user: &EgressUserPolicyV1,
) -> Result<(VerifiedPolicyV1, EgressPolicyDiffV1), HttpErrorJson> {
    let previous = policy_in_state(trust, current_bundle, user)?;
    let current = current_bundle.map(|_| &previous);
    let next = verify_and_activate(bundle, user, &trust.keys, current)
        .map_err(|error| bundle_error(error, trust))?;
    let diff = policy_diff(&previous, next.policy());
    Ok((next, diff))
}

fn user_policy_base(
    datastore: &Datastore,
    trust: &EgressPolicyTrust,
) -> Result<(EgressPolicyV1, EgressUserPolicyV1), HttpErrorJson> {
    let stored = datastore
        .get_egress_policy_state()
        .map_err(HttpErrorJson::from)?;
    let user = match stored.as_ref() {
        Some((_, user)) => user.clone(),
        None => datastore
            .get_egress_user_policy()
            .map_err(HttpErrorJson::from)?,
    };
    let policy = policy_in_state(trust, stored.as_ref().map(|(bundle, _)| bundle), &user)?;
    Ok((policy, user))
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

#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SyncPolicyFirewallReviewV1 {
    SignedBundle {
        diff: EgressPolicyDiffV1,
    },
    UserPolicy {
        preview_id: String,
        diff: EgressPolicyDiffV1,
    },
}

#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
#[derive(Debug, Serialize)]
pub struct SyncPolicyReviewV1 {
    pub policy: aw_models::SyncPolicyPreviewV1,
    pub firewall: Option<SyncPolicyFirewallReviewV1>,
}

#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
fn proposed_user(
    value: &aw_models::SyncPolicyValueV1,
) -> Result<EgressUserPolicyV1, DatastoreError> {
    if value.present {
        serde_json::from_value(value.value.clone()).map_err(|_| firewall_review_error())
    } else {
        Ok(EgressUserPolicyV1 {
            schema_version: 1,
            user_rules: Vec::new(),
            safe_zone_patterns: Vec::new(),
            after_hours: None,
        })
    }
}

#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
fn firewall_review_error() -> DatastoreError {
    DatastoreError::InvalidImport(
        "The Firewall policy could not be accepted from this review.".into(),
    )
}

#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
pub fn preview_sync_policy(
    datastore: &Datastore,
    trust: &EgressPolicyTrust,
    proxy: &EgressProxy,
    candidate_id: &str,
) -> Result<SyncPolicyReviewV1, HttpErrorJson> {
    let policy = datastore
        .preview_sync_policy_candidate(candidate_id)
        .map_err(HttpErrorJson::from)?;
    let firewall = match policy.candidate.field.as_str() {
        "egress.signed_bundle" => {
            let bundle = serde_json::from_value(policy.proposed.value.clone())
                .map_err(|_| HttpErrorJson::from(firewall_review_error()))?;
            Some(SyncPolicyFirewallReviewV1::SignedBundle {
                diff: preview_local_policy(datastore, trust, &bundle)?,
            })
        }
        "egress.user_policy" => {
            let draft = proposed_user(&policy.proposed).map_err(HttpErrorJson::from)?;
            let (current, user) = user_policy_base(datastore, trust)?;
            let preview = proxy
                .preview_user_policy(&current, &user, &draft, Utc::now())
                .map_err(proxy_error)?;
            Some(SyncPolicyFirewallReviewV1::UserPolicy {
                preview_id: preview.preview_id,
                diff: preview.diff,
            })
        }
        _ => None,
    };
    let fresh = datastore
        .preview_sync_policy_candidate(candidate_id)
        .map_err(HttpErrorJson::from)?;
    if fresh.expected_review_sha256 != policy.expected_review_sha256 {
        return Err(HttpErrorJson::new(
            Status::Conflict,
            "The policy changed while its review was prepared.".into(),
        ));
    }
    Ok(SyncPolicyReviewV1 { policy, firewall })
}

#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
pub fn choose_sync_policy(
    datastore: &Datastore,
    trust: &EgressPolicyTrust,
    proxy: &EgressProxy,
    request: aw_models::SyncPolicyChoiceRequestV1,
    firewall: Option<SyncPolicyFirewallReviewV1>,
) -> Result<aw_models::SyncPolicyChoiceResultV1, HttpErrorJson> {
    if request.decision == aw_models::SyncPolicyDecisionV1::KeepLocal {
        return datastore
            .choose_sync_policy(request)
            .map_err(HttpErrorJson::from);
    }
    let preview = datastore
        .preview_sync_policy_candidate(&request.candidate_id)
        .map_err(HttpErrorJson::from)?;
    if !preview.candidate.field.starts_with("egress.") {
        return datastore
            .choose_sync_policy(request)
            .map_err(HttpErrorJson::from);
    }
    let review = firewall.ok_or_else(|| HttpErrorJson::from(firewall_review_error()))?;
    proxy
        .with_policy_update(|| {
            let _activation = trust.activation_gate.lock().map_err(|_| {
                HttpErrorJson::new(
                    Status::ServiceUnavailable,
                    "Privacy Firewall policy is unavailable.".into(),
                )
            })?;
            let trust = trust.clone();
            let proxy = proxy.clone();
            // The worker callback uses its transaction snapshot and RAM previews only; no datastore requests.
            let gate = aw_datastore::SyncPolicyActivationGateV1::new(move |context| {
                match (&review, context.field) {
                    (SyncPolicyFirewallReviewV1::SignedBundle { diff }, "egress.signed_bundle") => {
                        let bundle = serde_json::from_value(context.proposed.value.clone())
                            .map_err(|_| firewall_review_error())?;
                        let (_, actual) = verified_candidate_in_state(
                            &trust,
                            &bundle,
                            context.current_bundle,
                            context.current_user,
                        )
                        .map_err(|_| firewall_review_error())?;
                        if &actual != diff {
                            return Err(firewall_review_error());
                        }
                    }
                    (
                        SyncPolicyFirewallReviewV1::UserPolicy { preview_id, diff },
                        "egress.user_policy",
                    ) => {
                        let current =
                            policy_in_state(&trust, context.current_bundle, context.current_user)
                                .map_err(|_| firewall_review_error())?;
                        let draft = proposed_user(context.proposed)?;
                        let mut next = current.clone();
                        next.user_rules = draft.user_rules.clone();
                        next.safe_zone_patterns = draft.safe_zone_patterns.clone();
                        next.after_hours = draft.after_hours.clone();
                        if &policy_diff(&current, &next) != diff {
                            return Err(firewall_review_error());
                        }
                        let (expected, accepted) = proxy
                            .accept_user_policy(preview_id, &current, Utc::now())
                            .map_err(|_| firewall_review_error())?;
                        if &expected != context.current_user || accepted != draft {
                            return Err(firewall_review_error());
                        }
                    }
                    _ => return Err(firewall_review_error()),
                }
                Ok(())
            });
            datastore
                .choose_sync_policy_with_activation(request, Some(gate))
                .map_err(HttpErrorJson::from)
        })
        .map_err(proxy_error)?
}

#[get("/status")]
pub fn status(
    state: &State<ServerState>,
    proxy: &State<EgressProxy>,
    trust: &State<EgressPolicyTrust>,
) -> Result<Json<EgressStatusV1>, HttpErrorJson> {
    local_egress_status(&state.datastore, proxy.inner(), trust.inner()).map(Json)
}

pub(crate) fn local_egress_status(
    datastore: &Datastore, proxy: &EgressProxy, trust: &EgressPolicyTrust,
) -> Result<EgressStatusV1, HttpErrorJson> {
    let kill_switch_enabled = proxy.kill_switch_enabled().map_err(proxy_error)?;
    let policy = datastore.get_egress_policy_state().map_err(|_| {
        HttpErrorJson::new(Status::ServiceUnavailable, "Privacy Firewall policy is unavailable; outbound requests remain blocked.".into())
    })?;
    let policy_bundle_version = policy.as_ref().map(|(bundle, _)| bundle.bundle.version);
    let policy_bundle_stored = policy.is_some();
    // No product release signing key is configured in this development candidate.
    let trusted_policy_keys = trust.key_count();
    let outbound_enabled = !kill_switch_enabled && active_policy(datastore, trust).is_ok();
    Ok(EgressStatusV1 {
        schema_version: 1,
        kill_switch_enabled,
        policy_bundle_stored,
        policy_bundle_version,
        trusted_policy_keys,
        outbound_enabled,
    })
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
        preview_local_policy(&datastore, &trust, &bundle).map(Json)
    })
    .await
    .map_err(|_| HttpErrorJson::new(Status::ServiceUnavailable, "Privacy Firewall policy is unavailable.".into()))?
}

pub(crate) fn preview_local_policy(
    datastore: &Datastore, trust: &EgressPolicyTrust, bundle: &SignedEgressPolicyBundleV1,
) -> Result<EgressPolicyDiffV1, HttpErrorJson> {
    verified_candidate(datastore, trust, bundle).map(|(_, _, diff)| diff)
}

pub(crate) fn accept_local_policy(
    datastore: &Datastore, trust: &EgressPolicyTrust, proxy: &EgressProxy,
    bundle: &SignedEgressPolicyBundleV1, expected_diff: &EgressPolicyDiffV1, accepted: bool,
) -> Result<(), HttpErrorJson> {
    if !accepted {
        return Err(HttpErrorJson::new(Status::BadRequest, "Policy diff acceptance is required.".into()));
    }
    proxy.with_policy_update(|| {
        let _gate = trust.activation_gate.lock()
            .map_err(|_| HttpErrorJson::new(Status::ServiceUnavailable, "Privacy Firewall policy is unavailable.".into()))?;
        let (user_policy, _verified, actual_diff) = verified_candidate(datastore, trust, bundle)?;
        if &actual_diff != expected_diff {
            return Err(HttpErrorJson::new(Status::Conflict, "The policy changed after its diff was reviewed.".into()));
        }
        datastore.store_egress_policy_state(bundle, &user_policy).map_err(HttpErrorJson::from)
    }).map_err(proxy_error)?
}

#[put("/policy/accept", data = "<request>", format = "application/json")]
pub async fn accept_policy(
    request: Json<AcceptEgressPolicyRequest>,
    state: &State<ServerState>,
    trust: &State<EgressPolicyTrust>,
    proxy: &State<EgressProxy>,
) -> Result<Status, HttpErrorJson> {
    let request = request.into_inner();
    let datastore = state.datastore.clone();
    let trust = trust.inner().clone();
    let proxy = proxy.inner().clone();
    rocket::tokio::task::spawn_blocking(move || {
        accept_local_policy(&datastore, &trust, &proxy, &request.bundle, &request.expected_diff, request.accept)
            .map(|_| Status::Ok)
    })
    .await
    .map_err(|_| HttpErrorJson::new(Status::ServiceUnavailable, "Privacy Firewall policy is unavailable.".into()))?
}

#[delete("/approvals")]
pub async fn revoke_approvals(proxy: &State<EgressProxy>) -> Result<Status, HttpErrorJson> {
    let proxy=proxy.inner().clone();
    rocket::tokio::task::spawn_blocking(move || proxy.revoke_approvals().map(|_| Status::Ok).map_err(proxy_error))
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
