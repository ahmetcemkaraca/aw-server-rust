use crate::{
    backup::BackupWorkflowV1,
    config::AWConfig,
    endpoints::{EgressPolicyTrust, HttpErrorJson, ServerState},
};
use aw_egress::EgressProxy;
use rocket::{data::ToByteUnit, http::Status, serde::json::Json, Data, State};
use serde_json::Value;
use zeroize::Zeroizing;

fn error(status: Status) -> HttpErrorJson {
    HttpErrorJson::new(
        status,
        "The provider backup operation could not be completed. Refresh and review again.".into(),
    )
}
fn gate(config: &AWConfig, state: &ServerState) -> Result<(), HttpErrorJson> {
    if config.auth.sessions.is_none() {
        return Err(error(Status::Forbidden));
    }
    if !state.datastore.is_encrypted() {
        return Err(error(Status::ServiceUnavailable));
    }
    if state.datastore.is_locked() {
        return Err(error(Status::Locked));
    }
    Ok(())
}
async fn execute(
    kind: &'static str,
    config: &AWConfig,
    state: &ServerState,
    trust: &EgressPolicyTrust,
    proxy: &EgressProxy,
    workflow: &State<BackupWorkflowV1>,
    data: Data<'_>,
) -> Result<Json<Value>, HttpErrorJson> {
    gate(config, state)?;
    let bytes = data
        .open((128 * 1024 + 1).bytes())
        .into_string()
        .await
        .map_err(|_| error(Status::BadRequest))?;
    if !bytes.is_complete() || bytes.len() > 128 * 1024 {
        return Err(error(Status::PayloadTooLarge));
    }
    let raw = Zeroizing::new(bytes.into_inner());
    BackupWorkflowV1::validate_request(kind, &raw).map_err(|_| error(Status::BadRequest))?;
    let store = state.datastore.clone();
    let trust = trust.clone();
    let proxy = proxy.clone();
    let workflow = workflow.inner().clone();
    rocket::tokio::task::spawn_blocking(move || {
        let policy = super::egress::active_policy(&store, &trust)?;
        let result = match kind {
            "preview" => workflow.preview(&store, &proxy, &policy, raw.to_string()),
            "approve" => workflow.approve(&store, &proxy, &policy, raw.to_string()),
            "run" => workflow.run(&store, &proxy, &policy, raw.to_string()),
            _ => unreachable!(),
        };
        result.map(Json).map_err(|_| {
            error(if store.is_locked() {
                Status::Locked
            } else {
                Status::Conflict
            })
        })
    })
    .await
    .map_err(|_| error(Status::ServiceUnavailable))?
}

#[post("/preview", data = "<data>", format = "application/json")]
pub(crate) async fn preview(
    config: &State<AWConfig>,
    state: &State<ServerState>,
    trust: &State<EgressPolicyTrust>,
    proxy: &State<EgressProxy>,
    workflow: &State<BackupWorkflowV1>,
    data: Data<'_>,
) -> Result<Json<Value>, HttpErrorJson> {
    execute("preview", config, state, trust, proxy, workflow, data).await
}
#[post("/approve", data = "<data>", format = "application/json")]
pub(crate) async fn approve(
    config: &State<AWConfig>,
    state: &State<ServerState>,
    trust: &State<EgressPolicyTrust>,
    proxy: &State<EgressProxy>,
    workflow: &State<BackupWorkflowV1>,
    data: Data<'_>,
) -> Result<Json<Value>, HttpErrorJson> {
    execute("approve", config, state, trust, proxy, workflow, data).await
}
#[post("/run", data = "<data>", format = "application/json")]
pub(crate) async fn run(
    config: &State<AWConfig>,
    state: &State<ServerState>,
    trust: &State<EgressPolicyTrust>,
    proxy: &State<EgressProxy>,
    workflow: &State<BackupWorkflowV1>,
    data: Data<'_>,
) -> Result<Json<Value>, HttpErrorJson> {
    execute("run", config, state, trust, proxy, workflow, data).await
}
