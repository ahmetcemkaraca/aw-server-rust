use rocket::form::Form;
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::State;

use aw_models::BucketsExport;
use aw_datastore::{Datastore, DatastoreError, ImportSummary};

use crate::endpoints::{HttpErrorJson, ServerState};

fn import_error(error: DatastoreError) -> HttpErrorJson {
    match error {
        DatastoreError::Locked => HttpErrorJson::new(Status::Locked, "The local vault is locked".into()),
        DatastoreError::InvalidImport(message) => HttpErrorJson::new(Status::BadRequest, message),
        _ => HttpErrorJson::new(Status::InternalServerError, "Import could not be completed safely".into()),
    }
}

fn preview(datastore: &Datastore, source: BucketsExport) -> Result<Json<ImportSummary>, HttpErrorJson> {
    datastore.preview_import_buckets(source).map(Json).map_err(import_error)
}

fn import(datastore: &Datastore, source: BucketsExport) -> Result<Json<ImportSummary>, HttpErrorJson> {
    datastore.import_buckets(source).map(Json).map_err(import_error)
}

#[post("/preview", data = "<json_data>", format = "application/json")]
pub fn bucket_import_preview_json(
    state: &State<ServerState>,
    json_data: Json<BucketsExport>,
) -> Result<Json<ImportSummary>, HttpErrorJson> {
    preview(&state.datastore, json_data.into_inner())
}

#[post("/preview", data = "<form>", format = "multipart/form-data")]
pub fn bucket_import_preview_form(
    state: &State<ServerState>,
    form: Form<ImportForm>,
) -> Result<Json<ImportSummary>, HttpErrorJson> {
    preview(&state.datastore, form.into_inner().import.into_inner())
}

#[post("/", data = "<json_data>", format = "application/json")]
pub fn bucket_import_json(
    state: &State<ServerState>,
    json_data: Json<BucketsExport>,
) -> Result<Json<ImportSummary>, HttpErrorJson> {
    import(&state.datastore, json_data.into_inner())
}

#[derive(FromForm)]
pub struct ImportForm {
    #[field(name = "buckets")]
    import: Json<BucketsExport>,
}

#[post("/", data = "<form>", format = "multipart/form-data")]
pub fn bucket_import_form(
    state: &State<ServerState>,
    form: Form<ImportForm>,
) -> Result<Json<ImportSummary>, HttpErrorJson> {
    import(&state.datastore, form.into_inner().import.into_inner())
}
