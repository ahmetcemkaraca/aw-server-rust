use aw_models::CapturePolicy;
use rocket::{State, http::Status, serde::json::Json};
use serde::Serialize;
use super::{HttpErrorJson, ServerState};

#[derive(Serialize)]
pub struct CaptureStatus {
    policy: CapturePolicy,
    recording: bool,
}

fn status(policy: CapturePolicy) -> Json<CaptureStatus> {
    Json(CaptureStatus { recording: policy.active(chrono::Utc::now()), policy })
}

#[get("/")]
pub fn get(state: &State<ServerState>) -> Result<Json<CaptureStatus>, HttpErrorJson> {
    state.datastore.capture_policy().map(status)
        .map_err(|_| HttpErrorJson::new(Status::ServiceUnavailable, "Capture controls are unavailable".into()))
}

#[post("/", format = "json", data = "<policy>")]
pub fn set(policy: Json<CapturePolicy>, state: &State<ServerState>) -> Result<Json<CaptureStatus>, HttpErrorJson> {
    let mut policy = policy.into_inner();
    policy.validate().map_err(|message| HttpErrorJson::new(Status::BadRequest, message.into()))?;
    state.datastore.set_capture_policy(policy).map(status)
        .map_err(|error| match error {
            aw_datastore::DatastoreError::InternalError(ref message) if message == "capture-policy-conflict" =>
                HttpErrorJson::new(Status::Conflict, "Privacy controls changed. Reload the saved controls before applying your edits.".into()),
            _ => HttpErrorJson::new(Status::ServiceUnavailable, "Capture policy could not be saved; verify recording status".into()),
        })
}
