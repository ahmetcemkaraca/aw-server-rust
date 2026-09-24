use rust_embed::RustEmbed;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use gethostname::gethostname;
use rocket::fs::FileServer;
use rocket::http::ContentType;
use rocket::serde::json::Json;
use rocket::State;

use crate::config::AWConfig;

use aw_datastore::Datastore;
use aw_models::Info;

#[derive(RustEmbed)]
#[folder = "$AW_WEBUI_DIR"]
struct EmbeddedAssets;

pub struct AssetResolver {
    asset_path: Option<PathBuf>,
}

impl AssetResolver {
    pub fn new(asset_path: Option<PathBuf>) -> Self {
        Self { asset_path }
    }

    fn resolve(&self, file_path: &str) -> Option<Vec<u8>> {
        if let Some(asset_path) = &self.asset_path {
            let content = std::fs::read(asset_path.join(file_path));
            if let Ok(data) = content {
                return Some(data);
            }
        }
        Some(EmbeddedAssets::get(file_path)?.data.to_vec())
    }
}

// The Datastore is just a cheap handle to the DB worker thread (a crossbeam
// channel sender), which serializes all DB access internally. No mutex is
// needed here — wrapping it in one would serialize all HTTP requests, letting
// a slow query block every heartbeat.
pub struct ServerState {
    pub datastore: Datastore,
    pub asset_resolver: AssetResolver,
    pub device_id: String,
}

#[macro_use]
mod util;
mod apikey;
mod ai;
mod plugins;
mod bucket;
mod capture;
mod cors;
mod export;
mod freelancer;
mod egress;
mod hostcheck;
mod import;
mod query;
mod settings;
#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
mod sync;

pub use util::HttpErrorJson;
pub use egress::EgressPolicyTrust;

#[get("/")]
fn root_index(state: &State<ServerState>) -> Option<(ContentType, Vec<u8>)> {
    get_file("index.html".into(), state)
}

#[get("/css/<file..>")]
fn root_css(file: PathBuf, state: &State<ServerState>) -> Option<(ContentType, Vec<u8>)> {
    get_file(Path::new("css").join(file), state)
}

#[get("/fonts/<file..>")]
fn root_fonts(file: PathBuf, state: &State<ServerState>) -> Option<(ContentType, Vec<u8>)> {
    get_file(Path::new("fonts").join(file), state)
}

#[get("/js/<file..>")]
fn root_js(file: PathBuf, state: &State<ServerState>) -> Option<(ContentType, Vec<u8>)> {
    get_file(Path::new("js").join(file), state)
}

#[get("/static/<file..>")]
fn root_static(file: PathBuf, state: &State<ServerState>) -> Option<(ContentType, Vec<u8>)> {
    get_file(Path::new("static").join(file), state)
}

#[get("/favicon.ico")]
fn root_favicon(state: &State<ServerState>) -> Option<(ContentType, Vec<u8>)> {
    get_file("favicon.ico".into(), state)
}

#[get("/dark.css")]
fn root_dark(state: &State<ServerState>) -> Option<(ContentType, Vec<u8>)> {
    get_file("dark.css".into(), state)
}

#[get("/peakactivity.svg")]
fn root_peak_logo(state: &State<ServerState>) -> Option<(ContentType, Vec<u8>)> {
    get_file("peakactivity.svg".into(), state)
}

#[get("/LICENSE.txt")]
fn root_license(state: &State<ServerState>) -> Option<(ContentType, Vec<u8>)> {
    get_file("LICENSE.txt".into(), state)
}

#[get("/logo.png")]
fn root_logo(state: &State<ServerState>) -> Option<(ContentType, Vec<u8>)> {
    get_file("logo.png".into(), state)
}

#[get("/manifest.json")]
fn root_manifest(state: &State<ServerState>) -> Option<(ContentType, Vec<u8>)> {
    get_file("manifest.json".into(), state)
}

#[get("/")]
fn server_info(config: &State<AWConfig>, state: &State<ServerState>) -> Json<Info> {
    #[allow(clippy::or_fun_call)]
    let hostname = gethostname().into_string().unwrap_or("unknown".to_string());
    const VERSION: Option<&'static str> = option_env!("CARGO_PKG_VERSION");

    Json(Info {
        hostname,
        version: format!("v{} (rust)", VERSION.unwrap_or("(unknown)")),
        testing: config.testing,
        device_id: state.device_id.clone(),
    })
}

fn get_file(file: PathBuf, state: &State<ServerState>) -> Option<(ContentType, Vec<u8>)> {
    let asset = state.asset_resolver.resolve(&file.display().to_string())?;

    let content_type = file
        .extension()
        .and_then(OsStr::to_str)
        .and_then(ContentType::from_extension)
        .unwrap_or(ContentType::Bytes);

    Some((content_type, asset))
}

pub fn build_rocket(server_state: ServerState, config: AWConfig) -> rocket::Rocket<rocket::Build> {
    build_rocket_with_policy_trust(server_state, config, EgressPolicyTrust::default())
}

pub fn build_rocket_with_policy_trust(
    server_state: ServerState,
    config: AWConfig,
    egress_policy_trust: EgressPolicyTrust,
) -> rocket::Rocket<rocket::Build> {
    info!(
        "Starting aw-server-rust at {}:{}",
        config.address, config.port
    );
    if config.auth.sessions.is_some() {
        assert_eq!(config.address, "127.0.0.1", "Scoped local sessions require loopback binding");
    }
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    let sync_routes_enabled = config.auth.sessions.is_some() && server_state.datastore.is_encrypted();
    let cors = cors::cors(&config);
    let hostcheck = hostcheck::HostCheck::new(&config);
    let apikey = apikey::ApiKeyCheck::new(&config);
    let custom_static = config.custom_static.clone();
    let egress_proxy = aw_egress::EgressProxy::new(server_state.datastore.clone());

    let mut rocket = rocket::custom(config.to_rocket_config())
        .attach(cors.clone())
        .attach(hostcheck)
        .attach(apikey)
        .manage(cors)
        .manage(server_state)
        .manage(egress_proxy)
        .manage(egress_policy_trust)
        .manage(config)
        .mount("/api/0/session", routes![apikey::refresh])
        .mount("/api/0/capture", routes![capture::get, capture::set])
        .mount(
            "/",
            routes![
                root_index,
                root_favicon,
                root_fonts,
                root_css,
                root_js,
                root_static,
                // custom static files
                root_dark,
                root_logo,
                root_peak_logo,
                root_license,
                root_manifest
            ],
        )
        .mount("/api/0/info", routes![server_info])
        .mount(
            "/api/0/buckets",
            routes![
                bucket::bucket_new,
                bucket::bucket_delete,
                bucket::buckets_get,
                bucket::bucket_get,
                bucket::bucket_events_get,
                bucket::bucket_events_create,
                bucket::bucket_events_heartbeat,
                bucket::bucket_event_count,
                bucket::bucket_events_get_single,
                bucket::bucket_event_corrections,
                bucket::bucket_event_correct,
                bucket::bucket_event_split,
                bucket::bucket_events_merge,
                bucket::bucket_events_delete_by_id,
                bucket::bucket_events_delete_range,
                bucket::bucket_export
            ],
        )
        .mount("/api/0/query", routes![query::query])
        .mount(
            "/api/0/import",
            routes![
                import::bucket_import_preview_json,
                import::bucket_import_preview_form,
                import::bucket_import_json,
                import::bucket_import_form
            ],
        )
        .mount("/api/0/export", routes![export::buckets_export])
        .mount("/api/0/freelancer", routes![
            freelancer::get_workspace,
            freelancer::update_workspace,
            freelancer::timesheet_preview,
            freelancer::sign_timesheet,
        ])
        .mount("/api/0/ai", routes![
            ai::status,
            ai::settings_get,
            ai::settings_update,
            ai::connection_test,
            ai::preview,
            ai::approve,
            ai::native_preview,
            ai::send,
            ai::history_get,
            ai::history_save,
            ai::history_delete,
        ])
        .mount("/api/0/plugins", routes![plugins::status])
        .mount("/api/0/egress", routes![
            egress::status,
            egress::receipts,
            egress::approvals,
            egress::user_policy,
            egress::preview_user_policy,
            egress::accept_user_policy,
            egress::policy,
            egress::policy_diff_preview,
            egress::accept_policy,
            egress::revoke_approvals,
            egress::approve,
            egress::set_kill_switch,
            egress::preview,
            egress::send,
        ])
        .mount(
            "/api/0/settings",
            routes![
                settings::setting_get,
                settings::setting_set,
                settings::setting_delete,
                settings::settings_get,
            ],
        )
        .mount("/", rocket_cors::catch_all_options_routes());

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    if sync_routes_enabled {
        rocket = rocket.mount("/api/0/sync", routes![
            sync::sync_enabled,
            sync::set_sync_enabled,
            sync::run_sync,
            sync::relay_request,
            sync::put_object,
            sync::get_object,
            sync::list_objects,
            sync::delete_object,
            sync::history,
        ]);
    }

    // for each custom static directory, mount it at the given name
    for (name, dir) in custom_static {
        info!(
            "Serving /pages/{} custom static directory from {}",
            name, dir
        );
        rocket = rocket.mount(&format!("/pages/{name}"), FileServer::from(dir));
    }
    rocket
}

/// Do not load a privileged WebView until this server owns its loopback socket.
pub async fn launch_with_readiness(
    server_state: ServerState,
    config: AWConfig,
    ready: std::sync::mpsc::SyncSender<Result<(), String>>,
) -> Result<rocket::Rocket<rocket::Ignite>, rocket::Error> {
    let notification = ready.clone();
    let server = build_rocket(server_state, config).attach(rocket::fairing::AdHoc::on_liftoff(
        "Local server ready", move |_| Box::pin(async move { let _ = notification.try_send(Ok(())); }),
    ));
    let result = server.launch().await;
    if result.is_err() { let _ = ready.try_send(Err("The local server could not bind its selected port".into())); }
    result
}

mod tests {
    #[test]
    fn test_filesystem_resolver() {
        let resolver = super::AssetResolver::new(Some(".".into()));

        let content = resolver.resolve("Cargo.toml").unwrap();

        assert!(String::from_utf8(content).unwrap().contains("aw-server"));
    }

    #[test]
    fn test_resolver_without_asset() {
        let resolver = super::AssetResolver::new(Some(".".into()));

        let content = resolver.resolve("Cargo.json");

        assert!(content.is_none());
    }
}
