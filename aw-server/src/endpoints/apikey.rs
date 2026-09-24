//! API key authentication via Bearer token.
//!
//! When `api_key` is set under `[auth]` in the config, all API endpoints except
//! `/api/0/info` require an `Authorization: Bearer <key>` header. Requests
//! missing or presenting an invalid key receive a 401 Unauthorized response.
//!
//! By default `api_key` is `None`, meaning authentication is disabled.
//! To enable, add to `config.toml`:
//!
//! ```toml
//! [auth]
//! api_key = "your-secret-key-here"
//! ```
//!
//! Exempt paths (always public):
//! - `GET /api/0/info` — health/version endpoint used by clients and the webui
//!
//! CORS preflight requests (OPTIONS) are also passed through unconditionally so
//! the browser can obtain allowed headers before sending the actual request.

use subtle::ConstantTimeEq;
use std::sync::Mutex;
use crate::sessions::{Sessions, TOKEN_HEADER};

use rocket::fairing::Fairing;
use rocket::http::uri::Origin;
use rocket::http::{Header, Method, RawStr, Status};
use rocket::route::Outcome;
use rocket::{Data, Request, Response, Rocket, Route};

use crate::config::AWConfig;
use crate::endpoints::HttpErrorJson;

static FAIRING_ROUTE_BASE: &str = "/apikey_fairing";

/// Paths that are always accessible without authentication.
const PUBLIC_PATHS: &[&str] = &["/api/0/info"];

#[derive(Default)]
struct Decision {
    status: Option<Status>,
    rotated: Option<String>,
    ingest_only: bool,
    ai_send_only: bool,
    credential: Option<String>,
}

pub struct IngestOnly(pub bool);

#[rocket::async_trait]
impl<'r> rocket::request::FromRequest<'r> for IngestOnly {
    type Error = std::convert::Infallible;
    async fn from_request(request: &'r Request<'_>) -> rocket::request::Outcome<Self, Self::Error> {
        let ingest = request.local_cache(|| Mutex::new(Decision::default())).lock().unwrap().ingest_only;
        rocket::request::Outcome::Success(IngestOnly(ingest))
    }
}

pub struct AiSendOnly(pub bool);

#[rocket::async_trait]
impl<'r> rocket::request::FromRequest<'r> for AiSendOnly {
    type Error = std::convert::Infallible;
    async fn from_request(request: &'r Request<'_>) -> rocket::request::Outcome<Self, Self::Error> {
        let allowed = request.local_cache(|| Mutex::new(Decision::default())).lock().unwrap().ai_send_only;
        rocket::request::Outcome::Success(AiSendOnly(allowed))
    }
}

pub struct ApiKeyCheck {
    api_key: Option<String>,
    sessions: Option<Sessions>,
}

impl ApiKeyCheck {
    pub fn new(config: &AWConfig) -> ApiKeyCheck {
        let api_key = match &config.auth.api_key {
            Some(k) if k.is_empty() => {
                warn!("api_key is set to an empty string — authentication is disabled. Set a non-empty key to enable auth.");
                None
            }
            other => other.clone(),
        };
        ApiKeyCheck { api_key, sessions: config.auth.sessions.clone() }
    }
}

/// Route handler that returns 401 Unauthorized for failed auth checks.
#[derive(Clone)]
struct FairingErrorRoute {}

#[rocket::async_trait]
impl rocket::route::Handler for FairingErrorRoute {
    async fn handle<'r>(
        &self,
        request: &'r Request<'_>,
        _: rocket::Data<'r>,
    ) -> rocket::route::Outcome<'r> {
        let err = HttpErrorJson::new(
            request.local_cache(|| Mutex::new(Decision::default())).lock().unwrap().status.unwrap_or(Status::Unauthorized),
            "Local request was denied. Set 'Authorization: Bearer <key>' header.".to_string(),
        );
        Outcome::from(request, err)
    }
}

fn fairing_route() -> Route {
    Route::ranked(1, Method::Get, "/", FairingErrorRoute {})
}

fn redirect_unauthorized(request: &mut Request) {
    let uri = FAIRING_ROUTE_BASE.to_string();
    let origin = Origin::parse_owned(uri).unwrap();
    request.set_method(Method::Get);
    request.set_uri(origin);
}

#[rocket::async_trait]
impl Fairing for ApiKeyCheck {
    fn info(&self) -> rocket::fairing::Info {
        rocket::fairing::Info {
            name: "ApiKeyCheck",
            kind: rocket::fairing::Kind::Ignite | rocket::fairing::Kind::Request | rocket::fairing::Kind::Response,
        }
    }

    async fn on_ignite(&self, rocket: Rocket<rocket::Build>) -> rocket::fairing::Result {
        match (&self.api_key, &self.sessions) {
            (Some(_), _) | (_, Some(_)) => Ok(rocket.mount(FAIRING_ROUTE_BASE, vec![fairing_route()])),
            (None, None) => {
                debug!("API key authentication is disabled");
                Ok(rocket)
            }
        }
    }

    async fn on_request(&self, request: &mut Request<'_>, _: &mut Data<'_>) {
        if let Some(sessions) = &self.sessions {
            let path = match RawStr::new(request.uri().path().as_str()).percent_decode() {
                Ok(path) => path.into_owned(),
                Err(_) => { redirect_unauthorized(request); return; }
            };
            if !path.trim_start_matches('/').starts_with("api/") { return; }
            let origin = request.headers().get_one("Origin");
            let query_credentials = request.uri().query().is_some_and(|query| query.as_str().split('&').any(|field| {
                let key = RawStr::new(field.split('=').next().unwrap_or("")).url_decode_lossy();
                matches!(key.as_ref(), "token" | "api_key" | "access_token")
            }));
            let result = if query_credentials { Err(Status::BadRequest) }
            else if !sessions.origin_allowed(origin) { Err(Status::Forbidden) }
            else if request.method() == Method::Options { return; }
            else if path == "/api/0/session/refresh" && request.method() == Method::Post { return; }
            else if request.headers().get("Authorization").count() != 1 { Err(Status::Unauthorized) }
            else {
                match request.headers().get_one("Authorization").and_then(|value| value.strip_prefix("Bearer ")) {
                    Some(token) => sessions.authorize(token, request.method(), &path, origin),
                    None => Err(Status::Unauthorized),
                }
            };
            match result {
                Ok(access) => {
                    let mut decision = request.local_cache(|| Mutex::new(Decision::default())).lock().unwrap();
                    decision.rotated = access.rotated;
                    decision.ingest_only = access.ingest_only;
                    decision.ai_send_only = access.ai_send_only;
                    decision.credential = request.headers().get_one("Authorization")
                        .and_then(|value| value.strip_prefix("Bearer ")).map(str::to_string);
                }
                Err(status) => {
                    request.local_cache(|| Mutex::new(Decision::default())).lock().unwrap().status = Some(status);
                    redirect_unauthorized(request);
                }
            }
            return;
        }
        let api_key = match &self.api_key {
            None => return, // auth disabled
            Some(k) => k,
        };

        // Always allow OPTIONS (CORS preflight)
        if request.method() == Method::Options {
            return;
        }

        let decoded_path = match RawStr::new(request.uri().path().as_str()).percent_decode() {
            Ok(path) => path,
            Err(_) => { redirect_unauthorized(request); return; }
        };
        let path = decoded_path.as_ref();

        // Normalize leading slashes to prevent bypass via `//api/...`
        let normalized_path = format!("/{}", path.trim_start_matches('/'));

        // Only gate API endpoints — static web UI assets are not under /api/
        if !normalized_path.starts_with("/api/") {
            return;
        }

        // Always allow public API paths (e.g. /api/0/info for health checks)
        if PUBLIC_PATHS.contains(&normalized_path.as_str()) {
            return;
        }

        // Validate Authorization: Bearer <key>
        // Use constant-time comparison to prevent timing attacks.
        let auth_header = request.headers().get_one("Authorization");
        let valid = match auth_header {
            Some(value) => {
                if let Some(token) = value.strip_prefix("Bearer ") {
                    token.as_bytes().ct_eq(api_key.as_bytes()).into()
                } else {
                    false
                }
            }
            None => false,
        };

        if !valid {
            debug!("API key check failed");
            redirect_unauthorized(request);
        }
    }
    async fn on_response<'r>(&self, request: &'r Request<'_>, response: &mut Response<'r>) {
        if let Some(sessions) = &self.sessions {
            response.set_header(Header::new("Cache-Control", "no-store"));
            let decision = request.local_cache(|| Mutex::new(Decision::default())).lock().unwrap();
            if decision.credential.as_ref().is_some_and(|token| !sessions.token_alive(token)) {
                response.set_status(Status::Unauthorized);
                response.set_header(rocket::http::ContentType::JSON);
                response.set_sized_body(None, std::io::Cursor::new(b"{\"message\":\"The local session ended\"}"));
                return;
            }
            if let Some(token) = &decision.rotated {
                response.set_header(Header::new(TOKEN_HEADER, token.clone()));
            }
        }
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefreshRequest { refresh_token: String }

#[post("/refresh", data = "<request>", format = "json")]
pub fn refresh(request: rocket::serde::json::Json<RefreshRequest>, config: &rocket::State<AWConfig>)
    -> Result<rocket::serde::json::Json<serde_json::Value>, Status> {
    let sessions = config.auth.sessions.as_ref().ok_or(Status::NotFound)?;
    let access = sessions.renew(&request.refresh_token)?;
    Ok(rocket::serde::json::Json(serde_json::json!({"access_token": access})))
}

#[cfg(test)]
mod tests {

    use rocket::http::{ContentType, Header, Status};
    use rocket::Rocket;

    use crate::config::AWConfig;
    use crate::endpoints;

    fn setup_testserver(api_key: Option<String>) -> Rocket<rocket::Build> {
        let state = endpoints::ServerState {
            datastore: aw_datastore::Datastore::new_in_memory(false),
            asset_resolver: endpoints::AssetResolver::new(None),
            device_id: "test_id".to_string(),
        };
        let mut aw_config = AWConfig::default();
        aw_config.auth.api_key = api_key;
        endpoints::build_rocket(state, aw_config)
    }

    #[test]
    fn test_no_api_key_configured() {
        // When no api_key is set, all endpoints are accessible without auth.
        let server = setup_testserver(None);
        let client = rocket::local::blocking::Client::tracked(server).expect("valid instance");

        let res = client
            .get("/api/0/info")
            .header(ContentType::JSON)
            .header(Header::new("Host", "localhost:5600"))
            .dispatch();
        assert_eq!(res.status(), Status::Ok);

        let res = client
            .get("/api/0/buckets/")
            .header(ContentType::JSON)
            .header(Header::new("Host", "localhost:5600"))
            .dispatch();
        assert_eq!(res.status(), Status::Ok);
    }

    #[test]
    fn test_api_key_required() {
        // With api_key set, requests without a key should be rejected.
        let server = setup_testserver(Some("secret123".to_string()));
        let client = rocket::local::blocking::Client::tracked(server).expect("valid instance");

        // /api/0/info is always public
        let res = client
            .get("/api/0/info")
            .header(ContentType::JSON)
            .header(Header::new("Host", "localhost:5600"))
            .dispatch();
        assert_eq!(res.status(), Status::Ok);

        // Other endpoints require auth
        let res = client
            .get("/api/0/buckets/")
            .header(ContentType::JSON)
            .header(Header::new("Host", "localhost:5600"))
            .dispatch();
        assert_eq!(res.status(), Status::Unauthorized);

        // Double slash should also require auth
        let res = client
            .get("//api/0/buckets/")
            .header(ContentType::JSON)
            .header(Header::new("Host", "localhost:5600"))
            .dispatch();
        assert_eq!(res.status(), Status::Unauthorized);
    }

    #[test]
    fn test_api_key_valid() {
        let server = setup_testserver(Some("secret123".to_string()));
        let client = rocket::local::blocking::Client::tracked(server).expect("valid instance");

        let res = client
            .get("/api/0/buckets/")
            .header(ContentType::JSON)
            .header(Header::new("Host", "localhost:5600"))
            .header(Header::new("Authorization", "Bearer secret123"))
            .dispatch();
        assert_eq!(res.status(), Status::Ok);
    }

    #[test]
    fn test_api_key_invalid() {
        let server = setup_testserver(Some("secret123".to_string()));
        let client = rocket::local::blocking::Client::tracked(server).expect("valid instance");

        let res = client
            .get("/api/0/buckets/")
            .header(ContentType::JSON)
            .header(Header::new("Host", "localhost:5600"))
            .header(Header::new("Authorization", "Bearer wrongkey"))
            .dispatch();
        assert_eq!(res.status(), Status::Unauthorized);
    }

    #[test]
    fn test_api_key_wrong_scheme() {
        // Must be Bearer, not Basic or bare key
        let server = setup_testserver(Some("secret123".to_string()));
        let client = rocket::local::blocking::Client::tracked(server).expect("valid instance");

        let res = client
            .get("/api/0/buckets/")
            .header(ContentType::JSON)
            .header(Header::new("Host", "localhost:5600"))
            .header(Header::new("Authorization", "Basic secret123"))
            .dispatch();
        assert_eq!(res.status(), Status::Unauthorized);
    }

    #[test]
    fn test_empty_api_key_disables_auth() {
        // An empty string key should be treated as disabled (no auth required).
        let server = setup_testserver(Some("".to_string()));
        let client = rocket::local::blocking::Client::tracked(server).expect("valid instance");

        let res = client
            .get("/api/0/buckets/")
            .header(ContentType::JSON)
            .header(Header::new("Host", "localhost:5600"))
            .dispatch();
        assert_eq!(res.status(), Status::Ok);
    }
}
