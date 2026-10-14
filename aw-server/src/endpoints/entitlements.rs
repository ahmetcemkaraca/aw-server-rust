use crate::{config::AWConfig, endpoints::HttpErrorJson};
use rocket::{http::Status, serde::json::Json, State};
use serde_json::{json, Value};

async fn invoke(
    config: &State<AWConfig>,
    command: &'static str,
    arguments: Value,
) -> Result<Json<Value>, HttpErrorJson> {
    let access = config.feature_access.clone();
    rocket::tokio::task::spawn_blocking(move || {
        crate::feature_access::invoke(&access, command, arguments)
            .expect("fixed entitlement command")
            .map(Json)
            .map_err(|message| HttpErrorJson::new(Status::Forbidden, message))
    })
    .await
    .map_err(|_| {
        HttpErrorJson::new(
            Status::ServiceUnavailable,
            "The separate entitlement store is unavailable".into(),
        )
    })?
}

#[get("/")]
pub async fn status(config: &State<AWConfig>) -> Result<Json<Value>, HttpErrorJson> {
    invoke(config, "entitlement_status", json!({})).await
}

#[post("/import", data = "<request>", format = "application/json")]
pub async fn import(
    request: Json<Value>,
    config: &State<AWConfig>,
) -> Result<Json<Value>, HttpErrorJson> {
    invoke(config, "import_entitlement", request.into_inner()).await
}
