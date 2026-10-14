use crate::{config::AWConfig, endpoints::ServerState, reports::ReportCoordinatorV1};
use aw_models::*;
use rocket::{
    data::{Data, ToByteUnit},
    http::{ContentType, Header, Status},
    request::{FromRequest, Outcome},
    response::{Responder, Response},
    Request, State,
};
use std::{io::Cursor, sync::Arc};
use ReportExecutionErrorV1 as Error;
pub(crate) struct Body {
    status: Status,
    bytes: Arc<[u8]>,
}
impl<'r> Responder<'r, 'static> for Body {
    fn respond_to(self, _: &'r Request<'_>) -> rocket::response::Result<'static> {
        Response::build()
            .status(self.status)
            .header(ContentType::JSON)
            .header(Header::new("Cache-Control", "no-store"))
            .sized_body(self.bytes.len(), Cursor::new(self.bytes))
            .ok()
    }
}
fn failure(reason: Error, status: Option<Status>) -> Body {
    let status = status.unwrap_or(match reason {
        Error::EntitlementUnavailable => Status::Forbidden,
        Error::StaleConfiguration => Status::Conflict,
        Error::SourceUnavailable => Status::ServiceUnavailable,
        Error::RowLimit
        | Error::ByteLimit
        | Error::ValueLimit
        | Error::FuelLimit
        | Error::Deadline => Status::PayloadTooLarge,
        Error::DataIntegrity => Status::UnprocessableEntity,
        _ => Status::ServiceUnavailable,
    });
    let bytes = serde_json::to_vec(&serde_json::json!({"schema_version":1,"reason":reason}))
        .unwrap_or_else(|_| b"{\"schema_version\":1,\"reason\":\"internal-error\"}".to_vec());
    Body {
        status,
        bytes: Arc::from(bytes),
    }
}
fn respond<T: serde::Serialize>(result: Result<T, Error>) -> Body {
    match result {
        Ok(value) => match serde_json::to_vec(&value) {
            Ok(bytes) => Body {
                status: Status::Ok,
                bytes: Arc::from(bytes),
            },
            Err(_) => failure(Error::DataIntegrity, None),
        },
        Err(reason) => failure(reason, None),
    }
}
fn gate(config: &AWConfig, state: &ServerState) -> Result<(), Body> {
    if config.auth.sessions.is_none() {
        return Err(failure(Error::SourceUnavailable, Some(Status::Forbidden)));
    }
    if !state.datastore.is_encrypted() {
        return Err(failure(Error::SourceUnavailable, None));
    }
    if state.datastore.is_locked() {
        return Err(failure(Error::SourceUnavailable, Some(Status::Locked)));
    }
    Ok(())
}
async fn body<T: serde::de::DeserializeOwned>(data: Data<'_>, max: u64) -> Result<T, Error> {
    let bytes = data
        .open((max + 1).bytes())
        .into_bytes()
        .await
        .map_err(|_| Error::DataIntegrity)?;
    if !bytes.is_complete() || bytes.len() > max as usize {
        return Err(Error::ByteLimit);
    }
    serde_json::from_slice(&bytes).map_err(|_| Error::DataIntegrity)
}
async fn blocking<T: Send + 'static>(
    action: impl FnOnce() -> Result<T, Error> + Send + 'static,
) -> Result<T, Error> {
    rocket::tokio::task::spawn_blocking(action)
        .await
        .map_err(|_| Error::InternalError)?
}
pub(crate) struct Capability(Result<ReportCapabilityV1, Error>);
#[rocket::async_trait]
impl<'r> FromRequest<'r> for Capability {
    type Error = std::convert::Infallible;
    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let result = if request
            .headers()
            .get("X-PeakActivity-Report-Capability")
            .count()
            != 1
        {
            Err(Error::SourceUnavailable)
        } else {
            request
                .headers()
                .get_one("X-PeakActivity-Report-Capability")
                .ok_or(Error::SourceUnavailable)
                .and_then(|s| ReportCapabilityV1::from_hex(s).map_err(|_| Error::SourceUnavailable))
        };
        Outcome::Success(Self(result))
    }
}
#[get("/library")]
pub(crate) async fn library(
    config: &State<AWConfig>,
    state: &State<ServerState>,
    reports: &State<Arc<ReportCoordinatorV1>>,
) -> Body {
    if let Err(error) = gate(config, state) {
        return error;
    }
    let reports = reports.inner().clone();
    respond(blocking(move || reports.library()).await)
}
#[put("/library", data = "<data>")]
pub(crate) async fn update(
    config: &State<AWConfig>,
    state: &State<ServerState>,
    reports: &State<Arc<ReportCoordinatorV1>>,
    data: Data<'_>,
) -> Body {
    if let Err(error) = gate(config, state) {
        return error;
    }
    let request =
        match body::<UpdateReportLibraryRequestV1>(data, REPORT_LIBRARY_MAX_BYTES_V1 as u64 + 4096)
            .await
        {
            Ok(v) => v,
            Err(e) => return failure(e, None),
        };
    let reports = reports.inner().clone();
    respond(blocking(move || reports.update_library(request)).await)
}
#[post("/library/export", data = "<data>")]
pub(crate) async fn export(
    config: &State<AWConfig>,
    state: &State<ServerState>,
    reports: &State<Arc<ReportCoordinatorV1>>,
    data: Data<'_>,
) -> Body {
    if let Err(error) = gate(config, state) {
        return error;
    }
    let request = match body::<ReportPortableExportRequestV1>(data, 1024).await {
        Ok(v) => v,
        Err(e) => return failure(e, None),
    };
    let reports = reports.inner().clone();
    respond(blocking(move || reports.export_library(request)).await)
}
#[post("/import/preview", data = "<data>")]
pub(crate) async fn preview(
    config: &State<AWConfig>,
    state: &State<ServerState>,
    reports: &State<Arc<ReportCoordinatorV1>>,
    data: Data<'_>,
) -> Body {
    if let Err(error) = gate(config, state) {
        return error;
    }
    let request =
        match body::<PortableReportPackV1>(data, REPORT_PORTABLE_MAX_BYTES_V1 as u64).await {
            Ok(v) => v,
            Err(e) => return failure(e, None),
        };
    let reports = reports.inner().clone();
    respond(blocking(move || reports.preview_import(request)).await)
}
#[post("/import/commit", data = "<data>")]
pub(crate) async fn commit(
    config: &State<AWConfig>,
    state: &State<ServerState>,
    reports: &State<Arc<ReportCoordinatorV1>>,
    data: Data<'_>,
) -> Body {
    if let Err(error) = gate(config, state) {
        return error;
    }
    let request = match body::<ReportImportCommitRequestV1>(data, 4096).await {
        Ok(v) => v,
        Err(e) => return failure(e, None),
    };
    let reports = reports.inner().clone();
    respond(blocking(move || reports.commit_import(request)).await)
}
#[post("/run/start", data = "<data>")]
pub(crate) async fn start(
    config: &State<AWConfig>,
    state: &State<ServerState>,
    reports: &State<Arc<ReportCoordinatorV1>>,
    data: Data<'_>,
) -> Body {
    if let Err(error) = gate(config, state) {
        return error;
    }
    let request = match body::<AdvancedReportRunRequestV1>(data, 65536).await {
        Ok(v) => v,
        Err(e) => return failure(e, None),
    };
    respond(reports.start(request))
}
#[post("/run/read", data = "<data>")]
pub(crate) async fn read(
    config: &State<AWConfig>,
    state: &State<ServerState>,
    reports: &State<Arc<ReportCoordinatorV1>>,
    cap: Capability,
    data: Data<'_>,
) -> Body {
    if let Err(error) = gate(config, state) {
        return error;
    }
    let cap = match cap.0 {
        Ok(c) => c,
        Err(e) => return failure(e, None),
    };
    let request = match body::<ReportRunReadRequestV1>(data, 1024).await {
        Ok(v) => v,
        Err(e) => return failure(e, None),
    };
    match reports.read(request, &cap) {
        Ok(bytes) => Body {
            status: Status::Ok,
            bytes,
        },
        Err(e) => failure(e, None),
    }
}
#[post("/run/cancel", data = "<data>")]
pub(crate) async fn cancel(
    config: &State<AWConfig>,
    state: &State<ServerState>,
    reports: &State<Arc<ReportCoordinatorV1>>,
    cap: Capability,
    data: Data<'_>,
) -> Body {
    if let Err(error) = gate(config, state) {
        return error;
    }
    let cap = match cap.0 {
        Ok(c) => c,
        Err(e) => return failure(e, None),
    };
    let request = match body::<ReportRunOwnerRequestV1>(data, 1024).await {
        Ok(v) => v,
        Err(e) => return failure(e, None),
    };
    respond(reports.cancel(request, &cap))
}
#[post("/run/release", data = "<data>")]
pub(crate) async fn release(
    config: &State<AWConfig>,
    state: &State<ServerState>,
    reports: &State<Arc<ReportCoordinatorV1>>,
    cap: Capability,
    data: Data<'_>,
) -> Body {
    if let Err(error) = gate(config, state) {
        return error;
    }
    let cap = match cap.0 {
        Ok(c) => c,
        Err(e) => return failure(e, None),
    };
    let request = match body::<ReportRunOwnerRequestV1>(data, 1024).await {
        Ok(v) => v,
        Err(e) => return failure(e, None),
    };
    respond(reports.release(request, &cap))
}

struct ReportRequest(bool);
pub(crate) struct NoStore;
#[rocket::async_trait]
impl rocket::fairing::Fairing for NoStore {
    fn info(&self) -> rocket::fairing::Info {
        rocket::fairing::Info {
            name: "Private local API replies",
            kind: rocket::fairing::Kind::Request | rocket::fairing::Kind::Response,
        }
    }
    async fn on_request(&self, request: &mut Request<'_>, _: &mut Data<'_>) {
        let report = rocket::http::RawStr::new(request.uri().path().as_str())
            .percent_decode()
            .is_ok_and(|path| path.starts_with("/api/0/reports/") || path.starts_with("/api/0/sync/policies/") || path.starts_with("/api/0/sync/backups/"));
        request.local_cache(|| ReportRequest(report));
    }
    async fn on_response<'r>(&self, request: &'r Request<'_>, response: &mut Response<'r>) {
        if request.local_cache(|| ReportRequest(false)).0 {
            response.set_header(Header::new("Cache-Control", "no-store"));
        }
    }
}
