use aw_datastore::{DatastoreError, SyncBaselineProgressV1, SyncTombstoneIdentityV1};
use aw_egress::{EgressProxy, EgressSyncRelayTransportV1};
use aw_models::{SyncEnvelopeV1, SYNC_EGRESS_PURPOSE_V1};
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
    enabled: bool,
    destination_id: Option<String>,
    purpose_id: Option<String>,
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

#[get("/enabled")]
pub async fn sync_enabled(state: &State<ServerState>) -> Result<Json<SyncEgressControlResponse>, HttpErrorJson> {
    let datastore = state.datastore.clone();
    rocket::tokio::task::spawn_blocking(move || {
        let consent = datastore.sync_egress_consent().map_err(HttpErrorJson::from)?;
        let baseline = datastore.sync_baseline_progress().map_err(HttpErrorJson::from)?;
        Ok(Json(SyncEgressControlResponse {
            enabled: consent.is_some(),
            destination_id: consent.as_ref().map(|value| value.destination_id.clone()),
            purpose_id: consent.map(|value| value.purpose_id),
            preparing: baseline.as_ref().is_some_and(|progress| !progress.complete),
            baseline,
        }))
    }).await
        .map_err(|_| HttpErrorJson::new(Status::ServiceUnavailable, "Sync state is unavailable.".into()))?
}

#[post("/run")]
pub async fn run_sync(
    state: &State<ServerState>,
    trust: &State<EgressPolicyTrust>,
    proxy: &State<EgressProxy>,
) -> Result<Json<Value>, HttpErrorJson> {
    let datastore = state.datastore.clone();
    let trust = trust.inner().clone();
    let proxy = proxy.inner().clone();
    rocket::tokio::task::spawn_blocking(move || {
        let sync_enabled = proxy.sync_enabled().map_err(|_| {
            HttpErrorJson::new(Status::Forbidden, "Network sync is not enabled by local consent.".into())
        })?;
        if !sync_enabled {
            return Err(HttpErrorJson::new(Status::Forbidden, "Network sync is not enabled by local consent.".into()));
        }
        let consent = datastore.sync_egress_consent()
            .map_err(HttpErrorJson::from)?
            .ok_or_else(|| HttpErrorJson::new(Status::Forbidden, "No signed sync destination is selected.".into()))?;
        let policy = super::egress::active_policy(&datastore, &trust)
            .map_err(|_| HttpErrorJson::new(Status::Forbidden, "The signed sync policy is unavailable or untrusted.".into()))?;
        if !policy.policy().purposes.iter().any(|purpose| {
            purpose.id == consent.purpose_id
                && purpose.destination_id == consent.destination_id
                && purpose.id == SYNC_EGRESS_PURPOSE_V1
        }) {
            return Err(HttpErrorJson::new(Status::Forbidden, "Sync is not permitted by the active signed policy.".into()));
        }
        let transport = EgressSyncRelayTransportV1::new(proxy, policy);
        let remote = SyncHttpObjectStoreV1::new(consent.destination_id, consent.purpose_id, transport)
            .map_err(|_| HttpErrorJson::new(Status::Forbidden, "The signed sync destination is invalid.".into()))?;
        SyncControl::new()
            .sync_operations(&datastore, &remote)
            .map(Json)
            .map_err(|error| HttpErrorJson::new(
                if error.retryable { Status::ServiceUnavailable } else { Status::Conflict },
                "Encrypted sync did not complete; local operation data remains in the encrypted vault.".into(),
            ))
    }).await
        .map_err(|_| HttpErrorJson::new(Status::ServiceUnavailable, "Sync task stopped.".into()))?
}

#[post("/enabled", data = "<request>", format = "application/json")]
pub async fn set_sync_enabled(
    request: Json<SyncEgressControlRequest>,
    state: &State<ServerState>,
    trust: &State<EgressPolicyTrust>,
    proxy: &State<EgressProxy>,
) -> Result<Json<SyncEgressControlResponse>, HttpErrorJson> {
    let request = request.into_inner();
    let datastore = state.datastore.clone();
    let proxy = proxy.inner().clone();
    let trust = trust.inner().clone();
    rocket::tokio::task::spawn_blocking(move || {
        if request.enabled {
            let destination_id = request.destination_id.as_deref().ok_or_else(|| {
                HttpErrorJson::new(Status::BadRequest, "Select a signed sync destination.".into())
            })?;
            let purpose_id = request.purpose_id.as_deref().ok_or_else(|| {
                HttpErrorJson::new(Status::BadRequest, "Select a signed sync purpose.".into())
            })?;
            if purpose_id != SYNC_EGRESS_PURPOSE_V1 {
                return Err(HttpErrorJson::new(Status::Forbidden, "Only the signed sync purpose can enable synchronization.".into()));
            }
            let policy = super::egress::active_policy(&datastore, &trust)?;
            if !policy.policy().purposes.iter().any(|purpose| {
                purpose.id == purpose_id && purpose.destination_id == destination_id
            }) {
                return Err(HttpErrorJson::new(Status::Forbidden, "The sync purpose is not in the signed destination policy.".into()));
            }
            if proxy.kill_switch_enabled().unwrap_or(true) {
                return Err(HttpErrorJson::new(Status::Forbidden, "Sync is paused by the egress kill switch.".into()));
            }
            let progress = SyncControl::new().prepare_sync_baseline(&datastore, 128)
                .map_err(|_| HttpErrorJson::new(Status::Forbidden, "Sync baseline preparation requires recovery and a trusted current-epoch device.".into()))?;
            if !progress.complete {
                proxy.set_sync_enabled(false, None, None)
                    .map_err(|_| HttpErrorJson::new(Status::Forbidden, "Sync consent could not be paused during baseline preparation.".into()))?;
                return Ok(Json(SyncEgressControlResponse {
                    enabled: false,
                    destination_id: None,
                    purpose_id: None,
                    preparing: true,
                    baseline: Some(progress),
                }));
            }
            let refreshed_policy = super::egress::active_policy(&datastore, &trust)?;
            if !refreshed_policy.policy().purposes.iter().any(|purpose| {
                purpose.id == purpose_id && purpose.destination_id == destination_id
            }) || proxy.kill_switch_enabled().unwrap_or(true) {
                return Err(HttpErrorJson::new(Status::Forbidden, "Sync is no longer permitted by current privacy controls.".into()));
            }
            proxy.set_sync_enabled(true, Some(destination_id.into()), Some(purpose_id.into()))
                .map_err(|_| HttpErrorJson::new(Status::Forbidden, "Sync remains unavailable under the current privacy controls.".into()))?;
            return Ok(Json(SyncEgressControlResponse {
                enabled: true,
                destination_id: Some(destination_id.into()),
                purpose_id: Some(purpose_id.into()),
                preparing: false,
                baseline: Some(progress),
            }));
        }
        proxy.set_sync_enabled(false, None, None)
            .map_err(|_| HttpErrorJson::new(Status::Forbidden, "Sync remains unavailable under the current privacy controls.".into()))?;
        let baseline = datastore.sync_baseline_progress().map_err(HttpErrorJson::from)?;
        Ok(Json(SyncEgressControlResponse {
            enabled: false,
            destination_id: None,
            purpose_id: None,
            preparing: baseline.as_ref().is_some_and(|progress| !progress.complete),
            baseline,
        }))
    }).await
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
    let datastore = state.datastore.clone();
    let trust = trust.inner().clone();
    let proxy = proxy.inner().clone();
    rocket::tokio::task::spawn_blocking(move || {
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
