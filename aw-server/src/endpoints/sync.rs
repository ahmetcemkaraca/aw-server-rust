use aw_datastore::{Datastore, DatastoreError, SyncBaselineProgressV1, SyncTombstoneIdentityV1};
use aw_egress::{EgressProxy, EgressSyncRelayTransportV1};
use aw_models::{EgressPolicyV1, EgressDestinationStatusV1, SyncEnvelopeV1, SYNC_EGRESS_PURPOSE_V1};
use aw_sync_e2ee::{
    SyncHttpObjectStoreV1, SyncObjectStoreErrorV1, SyncObjectStoreV1,
    SyncRelayRequestV1, SyncRelayResponseV1, SyncTombstoneAckProofV1,
    SyncTombstoneDeletionPermitV1,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::State;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::endpoints::{EgressPolicyTrust, HttpErrorJson, ServerState};
use crate::sync_control::SyncControl;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncEgressControlRequest {
    pub(crate) enabled: bool,
    pub(crate) destination_id: Option<String>,
    pub(crate) purpose_id: Option<String>,
}

#[derive(Serialize)]
pub struct SyncEgressControlResponse {
    enabled: bool,
    destination_id: Option<String>,
    purpose_id: Option<String>,
    preparing: bool,
    baseline: Option<SyncBaselineProgressV1>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncRelayHttpRequest {
    destination_id: String,
    purpose_id: String,
    request: SyncRelayRequestV1,
    #[serde(default)]
    tombstones: Vec<SyncTombstoneRequest>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PutSyncObjectRequest {
    envelope: SyncEnvelopeV1,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteSyncObjectRequest {
    tombstones: Vec<SyncTombstoneRequest>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncTombstoneRequest {
    origin_device_id: String,
    local_event_id: u64,
    tombstone_counter: u64,
}

#[derive(Serialize)]
pub struct PutSyncObjectResponse {
    inserted: bool,
}

#[derive(Serialize)]
pub struct SyncObjectPageResponse {
    objects: Vec<SyncEnvelopeV1>,
    next_cursor: Option<String>,
}

fn store_error(error: DatastoreError) -> HttpErrorJson {
    let status = match error {
        DatastoreError::Locked | DatastoreError::MpscError
        | DatastoreError::Uninitialized(_) | DatastoreError::OldDbVersion(_) => Status::ServiceUnavailable,
        DatastoreError::InternalError(_) | DatastoreError::InvalidImport(_) => Status::Conflict,
        _ => Status::BadRequest,
    };
    HttpErrorJson::new(status, "The encrypted sync object operation could not be completed.".into())
}

fn tombstone_identity(request: SyncTombstoneRequest) -> Result<SyncTombstoneIdentityV1, HttpErrorJson> {
    let origin_device_id: [u8; 16] = URL_SAFE_NO_PAD.decode(request.origin_device_id)
        .map_err(|_| HttpErrorJson::new(Status::BadRequest, "Invalid opaque tombstone device ID.".into()))?
        .try_into()
        .map_err(|_| HttpErrorJson::new(Status::BadRequest, "Invalid opaque tombstone device ID.".into()))?;
    Ok(SyncTombstoneIdentityV1 {
        origin_device_id,
        local_event_id: request.local_event_id,
        tombstone_counter: request.tombstone_counter,
    })
}

#[post("/objects", data = "<request>", format = "application/json")]
pub async fn put_object(
    request: Json<PutSyncObjectRequest>,
    state: &State<ServerState>,
) -> Result<(Status, Json<PutSyncObjectResponse>), HttpErrorJson> {
    let envelope = request.into_inner().envelope;
    envelope.validate()
        .map_err(|_| HttpErrorJson::new(Status::BadRequest, "Invalid encrypted sync envelope.".into()))?;
    let datastore = state.datastore.clone();
    let inserted = rocket::tokio::task::spawn_blocking(move || {
        datastore.put_sync_object(envelope, Utc::now().to_rfc3339()).map_err(store_error)
    }).await
        .map_err(|_| HttpErrorJson::new(Status::ServiceUnavailable, "Sync object storage is unavailable.".into()))??;
    Ok((if inserted { Status::Created } else { Status::Ok }, Json(PutSyncObjectResponse { inserted })))
}

#[get("/objects/<object_id>")]
pub async fn get_object(
    object_id: String,
    state: &State<ServerState>,
) -> Result<Json<SyncEnvelopeV1>, HttpErrorJson> {
    let datastore = state.datastore.clone();
    rocket::tokio::task::spawn_blocking(move || {
        datastore.get_sync_object(object_id).map_err(HttpErrorJson::from)?
            .map(Json)
            .ok_or_else(|| HttpErrorJson::new(Status::NotFound, "Sync object not found.".into()))
    }).await
        .map_err(|_| HttpErrorJson::new(Status::ServiceUnavailable, "Sync object storage is unavailable.".into()))?
}

#[get("/objects?<vault_id>&<after>&<limit>")]
pub async fn list_objects(
    vault_id: String,
    after: Option<String>,
    limit: Option<usize>,
    state: &State<ServerState>,
) -> Result<Json<SyncObjectPageResponse>, HttpErrorJson> {
    let datastore = state.datastore.clone();
    rocket::tokio::task::spawn_blocking(move || {
        datastore.list_sync_objects(vault_id, after, limit.unwrap_or(16).min(64))
            .map(|page| Json(SyncObjectPageResponse { objects: page.objects, next_cursor: page.next_cursor }))
            .map_err(HttpErrorJson::from)
    }).await
        .map_err(|_| HttpErrorJson::new(Status::ServiceUnavailable, "Sync object storage is unavailable.".into()))?
}

#[delete("/objects/<object_id>", data = "<request>", format = "application/json")]
pub async fn delete_object(
    object_id: String,
    request: Json<DeleteSyncObjectRequest>,
    state: &State<ServerState>,
) -> Result<Json<PutSyncObjectResponse>, HttpErrorJson> {
    let datastore = state.datastore.clone();
    let tombstones = request.into_inner().tombstones.into_iter()
        .map(tombstone_identity)
        .collect::<Result<Vec<_>, _>>()?;
    rocket::tokio::task::spawn_blocking(move || {
        datastore.delete_sync_object_after_tombstones(
            object_id,
            tombstones,
            Utc::now().to_rfc3339(),
        ).map(|deleted| Json(PutSyncObjectResponse { inserted: deleted }))
            .map_err(store_error)
    }).await
        .map_err(|_| HttpErrorJson::new(Status::ServiceUnavailable, "Sync object storage is unavailable.".into()))?
}

#[get("/history?<limit>")]
pub async fn history(
    limit: Option<usize>,
    state: &State<ServerState>,
) -> Result<Json<Vec<aw_datastore::SyncObjectHistoryV1>>, HttpErrorJson> {
    let datastore = state.datastore.clone();
    rocket::tokio::task::spawn_blocking(move || {
        datastore.list_sync_object_history(limit.unwrap_or(100).min(1000))
            .map(Json)
            .map_err(HttpErrorJson::from)
    }).await
        .map_err(|_| HttpErrorJson::new(Status::ServiceUnavailable, "Sync object history is unavailable.".into()))?
}

pub(crate) fn local_sync_status(datastore: &Datastore) -> Result<SyncEgressControlResponse, HttpErrorJson> {
    let consent = datastore.sync_egress_consent().map_err(HttpErrorJson::from)?;
    let baseline = datastore.sync_baseline_progress().map_err(HttpErrorJson::from)?;
    Ok(SyncEgressControlResponse {
        enabled: consent.is_some(),
        destination_id: consent.as_ref().map(|value| value.destination_id.clone()),
        purpose_id: consent.map(|value| value.purpose_id),
        preparing: baseline.as_ref().is_some_and(|progress| !progress.complete),
        baseline,
    })
}

fn sync_destination_available(policy: &EgressPolicyV1, destination_id: &str, purpose_id: &str) -> bool {
    purpose_id == SYNC_EGRESS_PURPOSE_V1
        && policy.purposes.iter().any(|purpose| purpose.id == purpose_id && purpose.destination_id == destination_id)
        && policy.destinations.iter().any(|destination| destination.id == destination_id
            && matches!(destination.status, EgressDestinationStatusV1::Available
                | EgressDestinationStatusV1::Beta | EgressDestinationStatusV1::Experimental))
}

pub(crate) fn run_local_sync(
    datastore: &Datastore, trust: &EgressPolicyTrust, proxy: &EgressProxy,
) -> Result<Value, (HttpErrorJson, bool)> {
    let denied = |message: &str| (HttpErrorJson::new(Status::Forbidden, message.into()), false);
    proxy.require_sync_access(Utc::now()).map_err(|_| denied("A current signed paid sync entitlement is required."))?;
    if !proxy.sync_enabled().map_err(|_| denied("Network sync is not enabled by local consent."))? {
        return Err(denied("Network sync is not enabled by local consent."));
    }
    let consent = datastore.sync_egress_consent().map_err(|error| (HttpErrorJson::from(error), false))?
        .ok_or_else(|| denied("No signed sync destination is selected."))?;
    let policy = super::egress::active_policy(datastore, trust)
        .map_err(|_| denied("The signed sync policy is unavailable or untrusted."))?;
    if !sync_destination_available(policy.policy(), &consent.destination_id, &consent.purpose_id) {
        return Err(denied("Sync is not permitted by the active signed policy."));
    }
    let transport = EgressSyncRelayTransportV1::new(proxy.clone(), policy);
    let remote = SyncHttpObjectStoreV1::new(consent.destination_id, consent.purpose_id, transport)
        .map_err(|_| denied("The signed sync destination is invalid."))?;
    SyncControl::new().sync_operations(datastore, &remote).map_err(|error| (
        HttpErrorJson::new(if error.retryable { Status::ServiceUnavailable } else { Status::Conflict },
            "Encrypted sync did not complete; local operation data remains in the encrypted vault.".into()),
        error.retryable,
    ))
}

pub(crate) fn set_local_sync_enabled(
    datastore: &Datastore, trust: &EgressPolicyTrust, proxy: &EgressProxy,
    request: &SyncEgressControlRequest, create_snapshot: bool,
) -> Result<SyncEgressControlResponse, HttpErrorJson> {
    if !request.enabled {
        proxy.set_sync_enabled(false, None, None)
            .map_err(|_| HttpErrorJson::new(Status::Forbidden, "Sync remains unavailable under the current privacy controls.".into()))?;
        return local_sync_status(datastore);
    }
    proxy.require_sync_access(Utc::now())
        .map_err(|_| HttpErrorJson::new(Status::Forbidden, "A current signed paid sync entitlement is required.".into()))?;
    let destination_id = request.destination_id.as_deref().ok_or_else(|| {
        HttpErrorJson::new(Status::BadRequest, "Select a signed sync destination.".into())
    })?;
    let purpose_id = request.purpose_id.as_deref().ok_or_else(|| {
        HttpErrorJson::new(Status::BadRequest, "Select a signed sync purpose.".into())
    })?;
    if purpose_id != SYNC_EGRESS_PURPOSE_V1 {
        return Err(HttpErrorJson::new(Status::Forbidden, "Only the signed sync purpose can enable synchronization.".into()));
    }
    let policy = super::egress::active_policy(datastore, trust)?;
    if !sync_destination_available(policy.policy(), destination_id, purpose_id) {
        return Err(HttpErrorJson::new(Status::Forbidden, "The sync purpose is not in the signed destination policy.".into()));
    }
    if proxy.kill_switch_enabled().unwrap_or(true) {
        return Err(HttpErrorJson::new(Status::Forbidden, "Sync is paused by the egress kill switch.".into()));
    }
    let preparing = datastore.sync_baseline_progress().map_err(HttpErrorJson::from)?
        .is_some_and(|progress| !progress.complete);
    if create_snapshot && !preparing {
        SyncControl::new().invoke(datastore, "create_current_sync_snapshot", serde_json::json!({}))
            .map_err(|message| HttpErrorJson::new(Status::Forbidden, message))?;
    }
    let progress = SyncControl::new().prepare_sync_baseline(datastore, 128)
        .map_err(|_| HttpErrorJson::new(Status::Forbidden, "Sync baseline preparation requires recovery and a trusted current-epoch device.".into()))?;
    if !progress.complete {
        proxy.set_sync_enabled(false, None, None)
            .map_err(|_| HttpErrorJson::new(Status::Forbidden, "Sync consent could not be paused during baseline preparation.".into()))?;
        return Ok(SyncEgressControlResponse {
            enabled: false, destination_id: None, purpose_id: None, preparing: true, baseline: Some(progress),
        });
    }
    let refreshed_policy = super::egress::active_policy(datastore, trust)?;
    if !sync_destination_available(refreshed_policy.policy(), destination_id, purpose_id)
        || proxy.kill_switch_enabled().unwrap_or(true) {
        return Err(HttpErrorJson::new(Status::Forbidden, "Sync is no longer permitted by current privacy controls.".into()));
    }
    proxy.set_sync_enabled(true, Some(destination_id.into()), Some(purpose_id.into()))
        .map_err(|_| HttpErrorJson::new(Status::Forbidden, "Sync remains unavailable under the current privacy controls.".into()))?;
    Ok(SyncEgressControlResponse {
        enabled: true, destination_id: Some(destination_id.into()), purpose_id: Some(purpose_id.into()),
        preparing: false, baseline: Some(progress),
    })
}

#[get("/enabled")]
pub async fn sync_enabled(state: &State<ServerState>) -> Result<Json<SyncEgressControlResponse>, HttpErrorJson> {
    let datastore = state.datastore.clone();
    rocket::tokio::task::spawn_blocking(move || local_sync_status(&datastore).map(Json)).await
        .map_err(|_| HttpErrorJson::new(Status::ServiceUnavailable, "Sync state is unavailable.".into()))?
}

#[post("/run")]
pub async fn run_sync(
    state: &State<ServerState>, trust: &State<EgressPolicyTrust>, proxy: &State<EgressProxy>,
) -> Result<Json<Value>, HttpErrorJson> {
    let datastore = state.datastore.clone();
    let trust = trust.inner().clone();
    let proxy = proxy.inner().clone();
    rocket::tokio::task::spawn_blocking(move || run_local_sync(&datastore, &trust, &proxy)
        .map(Json).map_err(|(error, _)| error)).await
        .map_err(|_| HttpErrorJson::new(Status::ServiceUnavailable, "Sync task stopped.".into()))?
}

#[post("/enabled", data = "<request>", format = "application/json")]
pub async fn set_sync_enabled(
    request: Json<SyncEgressControlRequest>, state: &State<ServerState>,
    trust: &State<EgressPolicyTrust>, proxy: &State<EgressProxy>,
) -> Result<Json<SyncEgressControlResponse>, HttpErrorJson> {
    let request = request.into_inner();
    let datastore = state.datastore.clone();
    let proxy = proxy.inner().clone();
    let trust = trust.inner().clone();
    rocket::tokio::task::spawn_blocking(move || set_local_sync_enabled(&datastore, &trust, &proxy, &request, false).map(Json)).await
        .map_err(|_| HttpErrorJson::new(Status::ServiceUnavailable, "Sync state is unavailable.".into()))?
}

#[post("/relay", data = "<request>", format = "application/json")]
pub async fn relay_request(
    request: Json<SyncRelayHttpRequest>,
    state: &State<ServerState>,
    trust: &State<EgressPolicyTrust>,
    proxy: &State<EgressProxy>,
) -> Result<Json<SyncRelayResponseV1>, HttpErrorJson> {
    let request = request.into_inner();
    request.request.validate().map_err(|_| HttpErrorJson::new(Status::BadRequest, "Invalid opaque sync request.".into()))?;
    if request.request.operation==aw_sync_e2ee::SyncRelayOperationV1::DeleteSelectedBackup {return Err(HttpErrorJson::new(Status::Forbidden,"Selected backup deletion requires its dedicated reviewed workflow.".into()));}
    let datastore = state.datastore.clone();
    let trust = trust.inner().clone();
    let proxy = proxy.inner().clone();
    rocket::tokio::task::spawn_blocking(move || {
        proxy.require_sync_access(Utc::now()).map_err(|_| {
            HttpErrorJson::new(Status::Forbidden, "A current signed paid sync entitlement is required.".into())
        })?;
        let deleting = request.request.operation == aw_sync_e2ee::SyncRelayOperationV1::DeleteAfterTombstone;
        if deleting && request.tombstones.is_empty() {
            return Err(HttpErrorJson::new(Status::BadRequest, "Remote delete requires tombstone acknowledgements.".into()));
        }
        if !deleting && !request.tombstones.is_empty() {
            return Err(HttpErrorJson::new(Status::BadRequest, "Tombstone acknowledgements are only valid for delete.".into()));
        }
        let deletion_permit = if deleting {
            let proofs = request.tombstones.into_iter().map(|tombstone| {
                let identity = tombstone_identity(tombstone)?;
                let state = datastore.sync_tombstone_ack_state(
                    identity.origin_device_id,
                    identity.local_event_id,
                    identity.tombstone_counter,
                ).map_err(store_error)?;
                Ok(SyncTombstoneAckProofV1::new(
                    state.active_device_ids.iter().map(|id| URL_SAFE_NO_PAD.encode(id)).collect(),
                    state.acknowledged_device_ids.iter().map(|id| URL_SAFE_NO_PAD.encode(id)).collect(),
                ))
            }).collect::<Result<Vec<_>, HttpErrorJson>>()?;
            let object_id = request.request.object_id.as_deref()
                .ok_or_else(|| HttpErrorJson::new(Status::BadRequest, "Remote delete needs an opaque object ID.".into()))?;
            Some(SyncTombstoneDeletionPermitV1::authorize(object_id, &proofs)
                .map_err(|_| HttpErrorJson::new(Status::Conflict, "Remote delete is waiting for active-device acknowledgements.".into()))?)
        } else {
            None
        };
        let policy = super::egress::active_policy(&datastore, &trust)?;
        let transport = EgressSyncRelayTransportV1::new(proxy, policy);
        let store = SyncHttpObjectStoreV1::new(request.destination_id, request.purpose_id, transport)
            .map_err(|_| HttpErrorJson::new(Status::ServiceUnavailable, "Signed sync relay is unavailable.".into()))?;
        let result = match request.request.operation {
            aw_sync_e2ee::SyncRelayOperationV1::PutIfAbsent => {
                let envelope = request.request.envelope.as_ref()
                    .ok_or_else(|| HttpErrorJson::new(Status::BadRequest, "Put request has no encrypted envelope.".into()))?;
                store.put_if_absent(envelope).map(|inserted| SyncRelayResponseV1 {
                    schema_version: 1,
                    inserted: Some(inserted),
                    ..Default::default()
                })
            }
            aw_sync_e2ee::SyncRelayOperationV1::Get => {
                let object_id = request.request.object_id.as_deref()
                    .ok_or_else(|| HttpErrorJson::new(Status::BadRequest, "Get request has no object ID.".into()))?;
                store.get(object_id).map(|envelope| SyncRelayResponseV1 {
                    schema_version: 1,
                    envelope,
                    ..Default::default()
                })
            }
            aw_sync_e2ee::SyncRelayOperationV1::ListOpaqueHeads => {
                let vault_id = request.request.vault_id.as_deref()
                    .ok_or_else(|| HttpErrorJson::new(Status::BadRequest, "List request has no vault ID.".into()))?;
                store.list_opaque_heads(vault_id).map(|objects| SyncRelayResponseV1 {
                    schema_version: 1,
                    objects,
                    ..Default::default()
                })
            }
            aw_sync_e2ee::SyncRelayOperationV1::DeleteSelectedBackup => return Err(HttpErrorJson::new(Status::Forbidden,"Selected backup deletion requires its dedicated reviewed workflow.".into())),
            aw_sync_e2ee::SyncRelayOperationV1::DeleteAfterTombstone => {
                let permit = deletion_permit.as_ref()
                    .ok_or_else(|| HttpErrorJson::new(Status::BadRequest, "Delete request has no tombstone permit.".into()))?;
                store.delete_after_tombstone(permit).map(|deleted| SyncRelayResponseV1 {
                    schema_version: 1,
                    deleted: Some(deleted),
                    ..Default::default()
                })
            }
        };
        result.map(Json).map_err(|error| {
                let status = match error {
                    SyncObjectStoreErrorV1::ObjectConflict => Status::Conflict,
                    SyncObjectStoreErrorV1::InvalidEnvelope | SyncObjectStoreErrorV1::InvalidObjectId => Status::BadRequest,
                    _ => Status::ServiceUnavailable,
                };
                HttpErrorJson::new(status, "Remote sync is unavailable under the current signed policy.".into())
            })
    }).await
        .map_err(|_| HttpErrorJson::new(Status::ServiceUnavailable, "Remote sync request stopped.".into()))?
}

use rocket::data::{Data, ToByteUnit};

const POLICY_SMALL_BODY: u64 = 1024;
const POLICY_CHOICE_BODY: u64 = 4 * aw_models::SYNC_MAX_CHUNK_BYTES as u64;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PolicyListRequest {
    schema_version: u16,
    after: Option<String>,
    limit: usize,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PolicyPreviewRequest {
    schema_version: u16,
    candidate_id: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PolicyChoiceRequest {
    choice: aw_models::SyncPolicyChoiceRequestV1,
    firewall: Option<super::egress::SyncPolicyFirewallReviewV1>,
}
#[derive(Serialize)]
pub(crate) struct PolicyPreviewResponse {
    policy: aw_models::SyncPolicyPreviewV1,
    firewall: Option<super::egress::SyncPolicyFirewallReviewV1>,
    accept_remote_available: bool,
    reason: Option<&'static str>,
}
fn policy_error(status: Status) -> HttpErrorJson {
    HttpErrorJson::new(
        status,
        "The local policy review could not be completed. Refresh and review it again.".into(),
    )
}
fn policy_gate(config: &crate::config::AWConfig, state: &ServerState) -> Result<(), HttpErrorJson> {
    if config.auth.sessions.is_none() {
        return Err(policy_error(Status::Forbidden));
    }
    if !state.datastore.is_encrypted() {
        return Err(policy_error(Status::ServiceUnavailable));
    }
    if state.datastore.is_locked() {
        return Err(policy_error(Status::Locked));
    }
    Ok(())
}
fn policy_store_error(datastore: &Datastore) -> HttpErrorJson {
    policy_error(if datastore.is_locked() {
        Status::Locked
    } else {
        Status::Conflict
    })
}
// Typed decoding rejects duplicate/unknown fields; this second pass rejects positional struct arrays.
fn policy_record_shapes(source: &Value, typed: &Value) -> bool {
    match typed {
        Value::Object(expected) => source.as_object().is_some_and(|record| {
            record.iter().all(|(key, value)| {
                expected
                    .get(key)
                    .is_some_and(|expected| policy_record_shapes(value, expected))
            })
        }),
        Value::Array(expected) => source.as_array().is_some_and(|items| {
            items.len() == expected.len()
                && items
                    .iter()
                    .zip(expected)
                    .all(|(item, expected)| policy_record_shapes(item, expected))
        }),
        _ => true,
    }
}
async fn policy_body<T: serde::de::DeserializeOwned + Serialize>(
    data: Data<'_>,
    max: u64,
) -> Result<T, HttpErrorJson> {
    let bytes = data
        .open((max + 1).bytes())
        .into_bytes()
        .await
        .map_err(|_| policy_error(Status::BadRequest))?;
    if !bytes.is_complete() || bytes.len() > max as usize {
        return Err(policy_error(Status::PayloadTooLarge));
    }
    if bytes.iter().find(|b| !b.is_ascii_whitespace()) != Some(&b'{') {
        return Err(policy_error(Status::BadRequest));
    }
    let typed: T = serde_json::from_slice(&bytes).map_err(|_| policy_error(Status::BadRequest))?;
    let source: Value =
        serde_json::from_slice(&bytes).map_err(|_| policy_error(Status::BadRequest))?;
    let encoded = serde_json::to_value(&typed).map_err(|_| policy_error(Status::BadRequest))?;
    if !policy_record_shapes(&source, &encoded) {
        return Err(policy_error(Status::BadRequest));
    }
    Ok(typed)
}
async fn policy_work<T: Serialize + Send + 'static>(
    action: impl FnOnce() -> Result<T, HttpErrorJson> + Send + 'static,
) -> Result<Json<T>, HttpErrorJson> {
    let value = rocket::tokio::task::spawn_blocking(action)
        .await
        .map_err(|_| policy_error(Status::ServiceUnavailable))??;
    aw_models::serialized_size(&value, POLICY_CHOICE_BODY as usize)
        .map_err(|_| policy_error(Status::PayloadTooLarge))?;
    Ok(Json(value))
}

#[post("/policies/list", data = "<data>", format = "application/json")]
pub(crate) async fn list_policies(
    config: &State<crate::config::AWConfig>,
    state: &State<ServerState>,
    data: Data<'_>,
) -> Result<Json<aw_models::SyncPolicyCandidatePageV1>, HttpErrorJson> {
    policy_gate(config, state)?;
    let request = policy_body::<PolicyListRequest>(data, POLICY_SMALL_BODY).await?;
    if request.schema_version != 1
        || !(1..=256).contains(&request.limit)
        || request
            .after
            .as_ref()
            .is_some_and(|id| !aw_models::valid_lower_hex(id, 64))
    {
        return Err(policy_error(Status::BadRequest));
    }
    let datastore = state.datastore.clone();
    policy_work(move || {
        datastore
            .list_sync_policy_candidates(request.after.as_deref(), request.limit)
            .map_err(|_| policy_store_error(&datastore))
    })
    .await
}

#[post("/policies/preview", data = "<data>", format = "application/json")]
pub(crate) async fn preview_policy(
    config: &State<crate::config::AWConfig>,
    state: &State<ServerState>,
    trust: &State<EgressPolicyTrust>,
    proxy: &State<EgressProxy>,
    data: Data<'_>,
) -> Result<Json<PolicyPreviewResponse>, HttpErrorJson> {
    policy_gate(config, state)?;
    let request = policy_body::<PolicyPreviewRequest>(data, POLICY_SMALL_BODY).await?;
    if request.schema_version != 1 || !aw_models::valid_lower_hex(&request.candidate_id, 64) {
        return Err(policy_error(Status::BadRequest));
    }
    let datastore = state.datastore.clone();
    let trust = trust.inner().clone();
    let proxy = proxy.inner().clone();
    policy_work(move || {
        let policy = datastore
            .preview_sync_policy_candidate(&request.candidate_id)
            .map_err(|_| policy_store_error(&datastore))?;
        let (firewall, available, reason) = if policy.candidate.field.starts_with("egress.") {
            match super::egress::preview_sync_policy(
                &datastore,
                &trust,
                &proxy,
                &request.candidate_id,
            ) {
                Ok(review) => (review.firewall, true, None),
                Err(_) => (None, false, Some("firewall-review-unavailable")),
            }
        } else {
            (None, true, None)
        };
        let fresh = datastore
            .preview_sync_policy_candidate(&request.candidate_id)
            .map_err(|_| policy_store_error(&datastore))?;
        if fresh.expected_review_sha256 != policy.expected_review_sha256 {
            return Err(policy_error(Status::Conflict));
        }
        Ok(PolicyPreviewResponse {
            policy,
            firewall,
            accept_remote_available: available,
            reason,
        })
    })
    .await
}

#[post("/policies/choice", data = "<data>", format = "application/json")]
pub(crate) async fn choose_policy(
    config: &State<crate::config::AWConfig>,
    state: &State<ServerState>,
    trust: &State<EgressPolicyTrust>,
    proxy: &State<EgressProxy>,
    data: Data<'_>,
) -> Result<Json<aw_models::SyncPolicyChoiceResultV1>, HttpErrorJson> {
    policy_gate(config, state)?;
    let request = policy_body::<PolicyChoiceRequest>(data, POLICY_CHOICE_BODY).await?;
    request
        .choice
        .validate()
        .map_err(|_| policy_error(Status::BadRequest))?;
    let datastore = state.datastore.clone();
    let trust = trust.inner().clone();
    let proxy = proxy.inner().clone();
    policy_work(move || {
        super::egress::choose_sync_policy(
            &datastore,
            &trust,
            &proxy,
            request.choice,
            request.firewall,
        )
        .map_err(|_| policy_store_error(&datastore))
    })
    .await
}

#[get("/policies/context")]
pub(crate) async fn policy_context(
    config: &State<crate::config::AWConfig>,
    state: &State<ServerState>,
) -> Result<Json<aw_models::SyncPolicyContextV1>, HttpErrorJson> {
    policy_gate(config, state)?;
    let datastore = state.datastore.clone();
    policy_work(move || datastore.get_sync_policy_context().map_err(|_| policy_store_error(&datastore))).await
}
