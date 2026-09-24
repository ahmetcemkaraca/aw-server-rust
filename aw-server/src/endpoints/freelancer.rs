use aw_datastore::{Datastore, DatastoreError};
use aw_models::{
    freelancer_report_signature_message_v1, ApprovedTimesheetV1, FreelancerWorkspaceV1,
    SignedClientReportV1, FREELANCER_MAX_WORKSPACE_BYTES_V1,
};
use ring::digest::{digest, SHA256};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{Ed25519KeyPair, KeyPair};
use rocket::data::{Data, ToByteUnit};
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::{get, put, State};
use serde::Deserialize;

use crate::endpoints::{HttpErrorJson, ServerState};

const WORKSPACE_KEY: &str = "freelancer.workspace.v1";
const REPORT_SIGNING_KEY: &str = "freelancer.report-signing-key.v1";
const MAX_WORKSPACE_REQUEST_BYTES: u64 = FREELANCER_MAX_WORKSPACE_BYTES_V1 as u64 + 4096;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateWorkspaceRequestV1 {
    expected_revision: u64,
    workspace: FreelancerWorkspaceV1,
}

#[derive(serde::Serialize)]
pub(crate) struct TimesheetPreviewResponseV1 {
    schema_version: u16,
    timesheet: ApprovedTimesheetV1,
    artifact_sha256: String,
    artifact_json: String,
}

fn default_workspace() -> FreelancerWorkspaceV1 {
    FreelancerWorkspaceV1 {
        schema_version: 1,
        revision: 0,
        projects: Vec::new(),
        category_rules: Vec::new(),
    }
}

fn require_encrypted_vault(datastore: &Datastore) -> Result<(), HttpErrorJson> {
    if datastore.is_locked() {
        return Err(HttpErrorJson::new(Status::Locked, "Unlock the local vault before using Freelancer projects".into()));
    }
    if !datastore.is_encrypted() {
        return Err(HttpErrorJson::new(Status::ServiceUnavailable, "Freelancer projects require an encrypted local vault".into()));
    }
    Ok(())
}

fn load_workspace(
    datastore: &Datastore,
) -> Result<(Option<String>, FreelancerWorkspaceV1), HttpErrorJson> {
    match datastore.get_key_value(WORKSPACE_KEY) {
        Ok(serialized) => {
            let workspace: FreelancerWorkspaceV1 = serde_json::from_str(&serialized)
                .map_err(|_| HttpErrorJson::new(Status::InternalServerError, "The local Freelancer workspace is invalid".into()))?;
            workspace.validate()
                .map_err(|_| HttpErrorJson::new(Status::InternalServerError, "The local Freelancer workspace is invalid".into()))?;
            Ok((Some(serialized), workspace))
        }
        Err(DatastoreError::NoSuchKey(_)) => Ok((None, default_workspace())),
        Err(error) => Err(error.into()),
    }
}

fn report_signing_key(datastore: &Datastore) -> Result<Ed25519KeyPair, HttpErrorJson> {
    loop {
        match datastore.get_key_value(REPORT_SIGNING_KEY) {
            Ok(encoded) => {
                let mut stored = encoded.into_bytes();
                let decoded = std::str::from_utf8(&stored).ok().and_then(decode_hex);
                stored.fill(0);
                let mut seed = decoded.filter(|seed| seed.len() == 32)
                    .ok_or_else(|| HttpErrorJson::new(Status::ServiceUnavailable, "The local report signing key is unavailable".into()))?;
                let keypair = Ed25519KeyPair::from_seed_unchecked(&seed);
                seed.fill(0);
                return keypair
                    .map_err(|_| HttpErrorJson::new(Status::ServiceUnavailable, "The local report signing key is unavailable".into()));
            }
            Err(DatastoreError::NoSuchKey(_)) => {
                let mut seed = [0_u8; 32];
                SystemRandom::new().fill(&mut seed)
                    .map_err(|_| HttpErrorJson::new(Status::ServiceUnavailable, "The local report signing key is unavailable".into()))?;
                let encoded = encode_hex(&seed);
                let updated = datastore.compare_and_set_key_value(REPORT_SIGNING_KEY, None, Some(&encoded));
                let mut encoded_bytes = encoded.into_bytes();
                encoded_bytes.fill(0);
                match updated {
                    Ok(true) => {
                        let keypair = Ed25519KeyPair::from_seed_unchecked(&seed);
                        seed.fill(0);
                        return keypair.map_err(|_| HttpErrorJson::new(Status::ServiceUnavailable, "The local report signing key is unavailable".into()));
                    }
                    Ok(false) => {
                        seed.fill(0);
                        continue;
                    }
                    Err(error) => {
                        seed.fill(0);
                        return Err(error.into());
                    }
                }
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 { return None; }
    (0..value.len()).step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).ok())
        .collect()
}

fn sign_report(
    datastore: &Datastore,
    timesheet: ApprovedTimesheetV1,
) -> Result<SignedClientReportV1, HttpErrorJson> {
    let artifact = timesheet.artifact_bytes()
        .map_err(|_| HttpErrorJson::new(Status::UnprocessableEntity, "The Approved Timesheet is invalid".into()))?;
    let artifact_sha256 = encode_hex(digest(&SHA256, &artifact).as_ref());
    let signing_key = report_signing_key(datastore)?;
    let message = freelancer_report_signature_message_v1(&timesheet)
        .map_err(|_| HttpErrorJson::new(Status::UnprocessableEntity, "The Approved Timesheet is invalid".into()))?;
    let report = SignedClientReportV1 {
        schema_version: 1,
        timesheet,
        artifact_sha256,
        signer_public_key_ed25519: encode_hex(signing_key.public_key().as_ref()),
        signature_ed25519: encode_hex(signing_key.sign(&message).as_ref()),
    };
    report.validate()
        .map_err(|_| HttpErrorJson::new(Status::InternalServerError, "The signed client report could not be created".into()))?;
    Ok(report)
}

#[get("/workspace")]
pub fn get_workspace(
    state: &State<ServerState>,
) -> Result<Json<FreelancerWorkspaceV1>, HttpErrorJson> {
    require_encrypted_vault(&state.datastore)?;
    load_workspace(&state.datastore).map(|(_, workspace)| Json(workspace))
}

#[put("/workspace", data = "<data>", format = "application/json")]
pub async fn update_workspace(
    data: Data<'_>,
    state: &State<ServerState>,
) -> Result<Json<FreelancerWorkspaceV1>, HttpErrorJson> {
    require_encrypted_vault(&state.datastore)?;
    let body = data.open(MAX_WORKSPACE_REQUEST_BYTES.bytes()).into_string().await
        .map_err(|_| HttpErrorJson::new(Status::BadRequest, "The local Freelancer workspace request is invalid".into()))?;
    if !body.is_complete() {
        return Err(HttpErrorJson::new(Status::PayloadTooLarge, "The local Freelancer workspace is too large".into()));
    }
    let mut request: UpdateWorkspaceRequestV1 = serde_json::from_str(&body.value)
        .map_err(|_| HttpErrorJson::new(Status::UnprocessableEntity, "The local Freelancer workspace request is invalid".into()))?;
    request.workspace.validate()
        .map_err(|_| HttpErrorJson::new(Status::UnprocessableEntity, "The local Freelancer workspace is invalid".into()))?;
    if request.workspace.revision != request.expected_revision {
        return Err(HttpErrorJson::new(Status::UnprocessableEntity, "The local Freelancer workspace revision is invalid".into()));
    }

    let (previous, current) = load_workspace(&state.datastore)?;
    if current.revision != request.expected_revision {
        return Err(HttpErrorJson::new(Status::Conflict, "The local Freelancer workspace changed; reload before saving".into()));
    }
    request.workspace.revision = request.expected_revision.checked_add(1)
        .ok_or_else(|| HttpErrorJson::new(Status::Conflict, "The local Freelancer workspace revision is exhausted".into()))?;
    let serialized = serde_json::to_string(&request.workspace)
        .map_err(|_| HttpErrorJson::new(Status::UnprocessableEntity, "The local Freelancer workspace could not be encoded".into()))?;
    let updated = state.datastore.compare_and_set_key_value(
        WORKSPACE_KEY,
        previous.as_deref(),
        Some(&serialized),
    ).map_err(HttpErrorJson::from)?;
    if !updated {
        return Err(HttpErrorJson::new(Status::Conflict, "The local Freelancer workspace changed; reload before saving".into()));
    }
    Ok(Json(request.workspace))
}

#[post("/timesheet/preview", data = "<data>", format = "application/json")]
pub async fn timesheet_preview(
    data: Data<'_>,
    state: &State<ServerState>,
) -> Result<Json<TimesheetPreviewResponseV1>, HttpErrorJson> {
    require_encrypted_vault(&state.datastore)?;
    let body = data.open(MAX_WORKSPACE_REQUEST_BYTES.bytes()).into_string().await
        .map_err(|_| HttpErrorJson::new(Status::BadRequest, "The Approved Timesheet request is invalid".into()))?;
    if !body.is_complete() {
        return Err(HttpErrorJson::new(Status::PayloadTooLarge, "The Approved Timesheet is too large".into()));
    }
    let timesheet: ApprovedTimesheetV1 = serde_json::from_str(&body.value)
        .map_err(|_| HttpErrorJson::new(Status::UnprocessableEntity, "The Approved Timesheet is invalid".into()))?;
    timesheet.validate()
        .map_err(|_| HttpErrorJson::new(Status::UnprocessableEntity, "The Approved Timesheet is invalid".into()))?;
    let bytes = timesheet.artifact_bytes()
        .map_err(|_| HttpErrorJson::new(Status::UnprocessableEntity, "The Approved Timesheet is invalid".into()))?;
    let artifact_sha256 = digest(&SHA256, &bytes).as_ref().iter()
        .map(|byte| format!("{byte:02x}")).collect();
    let artifact_json = String::from_utf8(bytes)
        .map_err(|_| HttpErrorJson::new(Status::UnprocessableEntity, "The Approved Timesheet is invalid".into()))?;
    Ok(Json(TimesheetPreviewResponseV1 {
        schema_version: 1,
        timesheet,
        artifact_sha256,
        artifact_json,
    }))
}

#[post("/timesheet/sign", data = "<data>", format = "application/json")]
pub async fn sign_timesheet(
    data: Data<'_>,
    state: &State<ServerState>,
) -> Result<Json<SignedClientReportV1>, HttpErrorJson> {
    require_encrypted_vault(&state.datastore)?;
    let body = data.open(8.kilobytes()).into_string().await
        .map_err(|_| HttpErrorJson::new(Status::BadRequest, "The Approved Timesheet request is invalid".into()))?;
    if !body.is_complete() {
        return Err(HttpErrorJson::new(Status::PayloadTooLarge, "The Approved Timesheet is too large".into()));
    }
    let timesheet: ApprovedTimesheetV1 = serde_json::from_str(&body.value)
        .map_err(|_| HttpErrorJson::new(Status::UnprocessableEntity, "The Approved Timesheet is invalid".into()))?;
    timesheet.validate()
        .map_err(|_| HttpErrorJson::new(Status::UnprocessableEntity, "The Approved Timesheet is invalid".into()))?;
    let datastore = state.datastore.clone();
    rocket::tokio::task::spawn_blocking(move || sign_report(&datastore, timesheet).map(Json))
        .await
        .map_err(|_| HttpErrorJson::new(Status::ServiceUnavailable, "The signed report is unavailable".into()))?
}
