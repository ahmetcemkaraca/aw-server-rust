#![cfg(any(feature = "encryption", feature = "encryption-vendored"))]
use aw_datastore::Datastore;
use aw_models::*;
use aw_server::{
    config::AWConfig,
    endpoints::{self, AssetResolver, ServerState},
    sessions::{Scope, Sessions},
};
use rocket::{
    http::{ContentType, Header, Status},
    local::blocking::Client,
};
use serde_json::{json, Value};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
mod entitlement_fixture {
    include!("support/entitlement.rs");
}
fn setup(
    store: Datastore,
    access: Arc<aw_entitlements::RuntimeFeatureAccessV1>,
    scoped: bool,
) -> (Client, Vec<String>) {
    let sessions = Sessions::new(5600, false);
    let tokens = [
        Scope::Admin,
        Scope::Read,
        Scope::Query,
        Scope::Ingest(vec!["aw-".into()]),
        Scope::AiSend,
    ]
    .into_iter()
    .map(|scope| sessions.mint(scope).unwrap())
    .collect();
    let mut config = AWConfig::default();
    config.port = 5600;
    config.feature_access = access;
    if scoped {
        config.auth.sessions = Some(sessions);
    }
    (
        Client::tracked(endpoints::build_rocket(
            ServerState {
                datastore: store,
                asset_resolver: AssetResolver::new(None),
                device_id: "synthetic".into(),
            },
            config,
        ))
        .unwrap(),
        tokens,
    )
}
fn post(
    client: &Client,
    token: &str,
    path: &str,
    body: Value,
    cap: Option<&str>,
) -> (Status, Value) {
    let mut req = client
        .post(format!("/api/0/reports/{path}"))
        .header(Header::new("Host", "localhost:5600"))
        .header(Header::new("Authorization", format!("Bearer {token}")))
        .header(ContentType::JSON)
        .body(body.to_string());
    if let Some(cap) = cap {
        req = req.header(Header::new(
            "X-PeakActivity-Report-Capability",
            cap.to_owned(),
        ));
    }
    let reply = req.dispatch();
    let status = reply.status();
    assert_eq!(reply.headers().get_one("Cache-Control"), Some("no-store"));
    (
        status,
        serde_json::from_str(&reply.into_string().unwrap()).unwrap(),
    )
}
fn library() -> Value {
    json!({"schema_version":1,"expected_revision":0,"library":{"schema_version":1,"revision":0,"templates":[{"id":"work","name":"Work","content_version":1,"method_id":"work-time-report","method_version":1,"sections":["daily","app-summary"],"category_paths":[],"break_time_seconds":0,"rule_pack":null}],"rule_packs":[]}})
}
fn request() -> Value {
    json!({"schema_version":1,"template_id":"work","expected_library_revision":1,"ordered_host_ids":["Host"],"current_periods":[{"local_date":"2026-01-01","interval":"2026-01-01T00:00:00Z/2026-01-02T00:00:00Z"}],"previous_periods":null,"timezone":"Europe/Berlin","timezone_resolution":"client-local-calendar-v1","day_start":"00:00"})
}
fn sources(store: &Datastore) {
    for (id, kind, data) in [
        (
            "aw-watcher-window_Host",
            "currentwindow",
            json!({"app":"Editor","private_marker":"frozen"}),
        ),
        (
            "aw-watcher-afk_Host",
            "afkstatus",
            json!({"status":"not-afk"}),
        ),
    ] {
        store
            .create_bucket(&Bucket {
                bid: None,
                id: id.into(),
                _type: kind.into(),
                client: "report-test".into(),
                hostname: "Host".into(),
                created: None,
                data: Default::default(),
                metadata: Default::default(),
                events: None,
                last_updated: None,
            })
            .unwrap();
        store
            .insert_events(
                id,
                &[Event::new(
                    "2026-01-01T12:00:00Z".parse().unwrap(),
                    chrono::Duration::seconds(60),
                    data.as_object().unwrap().clone(),
                )],
            )
            .unwrap();
    }
    store.set_key_value("settings.classes", "[]").unwrap();
}
fn save(client: &Client, token: &str) -> Value {
    let reply = client
        .put("/api/0/reports/library")
        .header(Header::new("Host", "localhost:5600"))
        .header(Header::new("Authorization", format!("Bearer {token}")))
        .header(ContentType::JSON)
        .body(library().to_string())
        .dispatch();
    assert_eq!(reply.status(), Status::Ok);
    serde_json::from_str(&reply.into_string().unwrap()).unwrap()
}
fn terminal(client: &Client, token: &str, start: &Value, raw: bool) -> Value {
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        let (status, value) = post(
            client,
            token,
            "run/read",
            json!({"schema_version":1,"run_id":start["run_id"],"include_raw_events":raw}),
            start["capability"].as_str(),
        );
        assert_eq!(status, Status::Ok);
        if !matches!(value["state"].as_str(), Some("queued" | "running")) {
            return value;
        }
        assert!(Instant::now() < until, "native report did not terminate");
        std::thread::sleep(Duration::from_millis(5));
    }
}
#[test]
fn report_routes_enforce_real_signed_access_and_frozen_owned_results() {
    for local_pro in [true, false] {
        let now = entitlement_fixture::aw_server_time();
        let access = entitlement_fixture::configured_access(
            entitlement_fixture::report_proof(now, 1, false, local_pro),
            now,
        )
        .0;
        let store = Datastore::new_encrypted(":memory:".into(), "9a".repeat(32), false);
        sources(&store);
        let (client, tokens) = setup(store.clone(), access, true);
        let admin = &tokens[0];
        save(&client, admin);
        let (status, start) = post(&client, admin, "run/start", request(), None);
        assert_eq!(status, Status::Ok);
        assert_eq!(start["run_id"].as_str().unwrap().len(), 32);
        assert_eq!(start["capability"].as_str().unwrap().len(), 64);
        let result = terminal(&client, admin, &start, false);
        assert_eq!(result["state"], "complete");
        assert_eq!(result["result"]["summary"]["totalDuration"], 60);
        assert!(result["result"].get("rawEvents").is_none());
        store
            .set_key_value(
                "settings.classes",
                "[{\"name\":[\"Changed\"],\"rule\":{\"type\":\"none\"}}]",
            )
            .unwrap();
        let raw = terminal(&client, admin, &start, true);
        assert_eq!(
            raw["result"]["rawEvents"][0]["buckets"][0]["events"][0]["data"]["private_marker"],
            "frozen"
        );
        assert_eq!(raw["result"]["summary"], result["result"]["summary"]);
        let body = json!({"schema_version":1,"run_id":start["run_id"],"include_raw_events":false});
        assert_ne!(
            post(&client, admin, "run/read", body.clone(), None).0,
            Status::Ok
        );
        assert_ne!(
            post(&client, admin, "run/read", body, Some(&"f".repeat(64))).0,
            Status::Ok
        );
        let owner = json!({"schema_version":1,"run_id":start["run_id"]});
        assert_eq!(
            post(
                &client,
                admin,
                "run/release",
                owner,
                start["capability"].as_str()
            )
            .0,
            Status::Ok
        );
        assert_ne!(
            post(
                &client,
                admin,
                "run/read",
                json!({"schema_version":1,"run_id":start["run_id"],"include_raw_events":true}),
                start["capability"].as_str()
            )
            .0,
            Status::Ok
        );
    }
}
#[test]
fn report_routes_require_admin_scoped_session_and_encrypted_unlocked_vault() {
    for scoped in [false, true] {
        let (client, tokens) = setup(Datastore::new_in_memory(false), Arc::default(), scoped);
        for token in &tokens {
            let response = client
                .get("/api/0/reports/library")
                .header(Header::new("Host", "localhost:5600"))
                .header(Header::new("Authorization", format!("Bearer {token}")))
                .dispatch();
            assert_ne!(response.status(), Status::Ok);
            assert_eq!(
                response.headers().get_one("Cache-Control"),
                Some("no-store")
            );
        }
    }
}
#[test]
fn report_routes_missing_entitlement_preserves_free_library_and_denies_paid_mutation() {
    let store = Datastore::new_encrypted(":memory:".into(), "9a".repeat(32), false);
    let (client, tokens) = setup(store.clone(), Arc::default(), true);
    let admin = &tokens[0];
    let reply = client
        .get("/api/0/reports/library")
        .header(Header::new("Host", "localhost:5600"))
        .header(Header::new("Authorization", format!("Bearer {admin}")))
        .dispatch();
    assert_eq!(reply.status(), Status::Ok);
    let reply = client
        .put("/api/0/reports/library")
        .header(Header::new("Host", "localhost:5600"))
        .header(Header::new("Authorization", format!("Bearer {admin}")))
        .header(ContentType::JSON)
        .body(library().to_string())
        .dispatch();
    assert_eq!(reply.status(), Status::Forbidden);
    assert!(!store
        .get_key_values("%")
        .unwrap()
        .contains_key("reports.library.v1"));
    assert_eq!(
        post(
            &client,
            admin,
            "library/export",
            json!({"schema_version":1,"include_category_sets":true}),
            None
        )
        .0,
        Status::Ok
    );
}

#[test]
fn report_routes_scoped_browser_preflight_allows_owned_header_and_library_put() {
    let (client, _) = setup(
        Datastore::new_encrypted(":memory:".into(), "9a".repeat(32), false),
        Arc::default(),
        true,
    );
    for (path, method) in [("run/read", "POST"), ("library", "PUT")] {
        let reply = client
            .options(format!("/api/0/reports/{path}"))
            .header(Header::new("Host", "localhost:5600"))
            .header(Header::new("Origin", "http://localhost:5600"))
            .header(Header::new("Access-Control-Request-Method", method))
            .header(Header::new(
                "Access-Control-Request-Headers",
                "authorization,content-type,x-peakactivity-report-capability",
            ))
            .dispatch();
        assert!(
            reply.status().code < 400,
            "scoped browser preflight was denied"
        );
    }
}

#[test]
fn report_routes_signed_denials_have_no_partial_result_and_keep_free_actions() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    for case in [
        "wrong-feature",
        "forged",
        "expired",
        "revoked",
        "missing-revocations",
    ] {
        let now = entitlement_fixture::aw_server_time();
        let valid = entitlement_fixture::report_proof(now, 1, false, false);
        let (access, source) = entitlement_fixture::configured_access(valid.clone(), now);
        let store = Datastore::new_encrypted(":memory:".into(), "9a".repeat(32), false);
        sources(&store);
        let (client, tokens) = setup(store, access, true);
        let admin = &tokens[0];
        let saved = save(&client, admin);
        let mut invalid = valid;
        match case {
            "wrong-feature" => {
                invalid.entitlement.payload.claims.feature_ids = vec!["e2ee-sync".into()];
            }
            "forged" => {
                invalid.entitlement.signature = URL_SAFE_NO_PAD.encode([0u8; 64]);
            }
            "expired" => {
                let claims = &mut invalid.entitlement.payload.claims;
                claims.issued_at = now - 7200;
                claims.expires_at = now - 3600;
                claims.grace_until = now - 1;
            }
            "revoked" => {
                invalid = entitlement_fixture::report_proof(now, 2, true, false);
            }
            "missing-revocations" => invalid.revocations = None,
            _ => unreachable!(),
        }
        if case == "wrong-feature" || case == "expired" {
            invalid.entitlement.signature = URL_SAFE_NO_PAD.encode(
                entitlement_fixture::key()
                    .sign(&invalid.entitlement.payload.signing_bytes().unwrap())
                    .as_ref(),
            );
        }
        *source.proof.lock().unwrap() = Some(invalid);
        let (status, start) = post(&client, admin, "run/start", request(), None);
        assert_eq!(status, Status::Ok);
        let result = terminal(&client, admin, &start, false);
        assert_eq!(result["state"], "failed");
        assert_eq!(result["reason"], "entitlement-unavailable");
        assert_eq!(result["result"], Value::Null);
        assert_eq!(
            post(
                &client,
                admin,
                "library/export",
                json!({"schema_version":1,"include_category_sets":true}),
                None
            )
            .0,
            Status::Ok
        );
        assert_eq!(
            post(
                &client,
                admin,
                "run/cancel",
                json!({"schema_version":1,"run_id":start["run_id"]}),
                start["capability"].as_str()
            )
            .0,
            Status::Ok
        );
        let update = json!({"schema_version":1,"expected_revision":1,"library":saved});
        let reply = client
            .put("/api/0/reports/library")
            .header(Header::new("Host", "localhost:5600"))
            .header(Header::new("Authorization", format!("Bearer {admin}")))
            .body(update.to_string())
            .dispatch();
        assert_eq!(reply.status(), Status::Ok);
        let mut remove = saved;
        remove["templates"] = json!([]);
        let reply = client
            .put("/api/0/reports/library")
            .header(Header::new("Host", "localhost:5600"))
            .header(Header::new("Authorization", format!("Bearer {admin}")))
            .body(json!({"schema_version":1,"expected_revision":1,"library":remove}).to_string())
            .dispatch();
        assert_eq!(reply.status(), Status::Ok);
    }
}
#[test]
fn report_routes_reject_unscoped_readers_duplicate_headers_and_ambiguous_bodies() {
    let now = entitlement_fixture::aw_server_time();
    let access = entitlement_fixture::configured_access(
        entitlement_fixture::report_proof(now, 1, false, true),
        now,
    )
    .0;
    let store = Datastore::new_encrypted(":memory:".into(), "9a".repeat(32), false);
    sources(&store);
    let (client, tokens) = setup(store, access, true);
    let admin = &tokens[0];
    save(&client, admin);
    for token in &tokens[1..] {
        let reply = client
            .get("/api/0/reports/library")
            .header(Header::new("Host", "localhost:5600"))
            .header(Header::new("Authorization", format!("Bearer {token}")))
            .dispatch();
        assert_eq!(reply.status(), Status::Forbidden);
    }
    let (_, start) = post(&client, admin, "run/start", request(), None);
    terminal(&client, admin, &start, false);
    let reply = client
        .post("/api/0/reports/run/read")
        .header(Header::new("Host", "localhost:5600"))
        .header(Header::new("Authorization", format!("Bearer {admin}")))
        .header(Header::new(
            "X-PeakActivity-Report-Capability",
            start["capability"].as_str().unwrap().to_owned(),
        ))
        .header(Header::new(
            "X-PeakActivity-Report-Capability",
            start["capability"].as_str().unwrap().to_owned(),
        ))
        .body(
            json!({"schema_version":1,"run_id":start["run_id"],"include_raw_events":false})
                .to_string(),
        )
        .dispatch();
    assert_ne!(reply.status(), Status::Ok);
    for text in [
        "[]",
        r#"{"schema_version":1,"schema_version":1,"include_category_sets":true}"#,
        r#"{"schema_version":1,"include_category_sets":true,"extra":0}"#,
    ] {
        let reply = client
            .post("/api/0/reports/library/export")
            .header(Header::new("Host", "localhost:5600"))
            .header(Header::new("Authorization", format!("Bearer {admin}")))
            .body(text)
            .dispatch();
        assert_eq!(reply.status(), Status::UnprocessableEntity);
        assert_eq!(reply.headers().get_one("Cache-Control"), Some("no-store"));
    }
    for (path, limit) in [
        ("library/export", 1024),
        ("run/start", 65536),
        ("import/commit", 4096),
        ("import/preview", 4 * 1024 * 1024),
    ] {
        let reply = client
            .post(format!("/api/0/reports/{path}"))
            .header(Header::new("Host", "localhost:5600"))
            .header(Header::new("Authorization", format!("Bearer {admin}")))
            .body(" ".repeat(limit + 1))
            .dispatch();
        assert_eq!(reply.status(), Status::PayloadTooLarge);
    }
}

#[test]
fn report_routes_import_requires_reviewed_opaque_preview_and_returns_durable_ack() {
    let now = entitlement_fixture::aw_server_time();
    let access = entitlement_fixture::configured_access(
        entitlement_fixture::report_proof(now, 1, false, true),
        now,
    )
    .0;
    let store = Datastore::new_encrypted(":memory:".into(), "9a".repeat(32), false);
    sources(&store);
    let (client, tokens) = setup(store.clone(), access, true);
    let admin = &tokens[0];
    let before = save(&client, admin);
    let package = json!({"schema_version":1,"templates":library()["library"]["templates"],"rule_packs":[],"category_sets":[]});
    let (status, preview) = post(&client, admin, "import/preview", package, None);
    assert_eq!(status, Status::Ok);
    assert_eq!(preview["mappings"][0]["to_id"], "work-import-1");
    assert_eq!(
        serde_json::to_value(store.report_library().unwrap()).unwrap(),
        before
    );
    let extra =
        json!({"schema_version":1,"preview_id":preview["preview_id"],"accept":true,"payload":{}});
    assert_eq!(
        post(&client, admin, "import/commit", extra, None).0,
        Status::UnprocessableEntity
    );
    let commit = json!({"schema_version":1,"preview_id":preview["preview_id"],"accept":true});
    let (status, committed) = post(&client, admin, "import/commit", commit.clone(), None);
    assert_eq!(status, Status::Ok);
    assert_eq!(committed["revision"], 2);
    assert_eq!(
        serde_json::to_value(store.report_library().unwrap()).unwrap(),
        committed
    );
    assert_eq!(
        post(&client, admin, "import/commit", commit, None).0,
        Status::Conflict
    );
}
#[test]
fn report_routes_rotated_admin_session_preserves_separate_run_capability() {
    let now = entitlement_fixture::aw_server_time();
    let access = entitlement_fixture::configured_access(
        entitlement_fixture::report_proof(now, 1, false, true),
        now,
    )
    .0;
    let store = Datastore::new_encrypted(":memory:".into(), "9a".repeat(32), false);
    sources(&store);
    let (client, tokens) = setup(store, access, true);
    save(&client, &tokens[0]);
    let sessions = client
        .rocket()
        .state::<AWConfig>()
        .unwrap()
        .auth
        .sessions
        .as_ref()
        .unwrap();
    let (admin, refresh) = sessions.mint_collector(Scope::Admin).unwrap();
    let (status, start) = post(&client, &admin, "run/start", request(), None);
    assert_eq!(status, Status::Ok);
    terminal(&client, &admin, &start, false);
    let rotated = sessions.renew(&refresh).unwrap();
    assert!(rotated != admin);
    let result = terminal(&client, &rotated, &start, true);
    assert_eq!(result["state"], "complete");
    assert_eq!(result["result"]["summary"]["totalDuration"], 60);
    assert!(!serde_json::to_string(&result["result"])
        .unwrap()
        .contains(start["capability"].as_str().unwrap()));
}
#[test]
fn report_routes_valid_static_key_locked_vault_and_library_cap_are_explicit() {
    let store = Datastore::new_encrypted(":memory:".into(), "9a".repeat(32), false);
    let mut config = AWConfig::default();
    config.port = 5600;
    config.auth.api_key = Some("synthetic-static".into());
    let client = Client::tracked(endpoints::build_rocket(
        ServerState {
            datastore: store,
            asset_resolver: AssetResolver::new(None),
            device_id: "synthetic".into(),
        },
        config,
    ))
    .unwrap();
    for (path, status) in [
        ("/api/0/reports/library", Status::Forbidden),
        ("/api/0/buckets", Status::Ok),
    ] {
        let reply = client
            .get(path)
            .header(Header::new("Host", "localhost:5600"))
            .header(Header::new("Authorization", "Bearer synthetic-static"))
            .dispatch();
        assert_eq!(reply.status(), status);
        if path.contains("reports") {
            assert_eq!(reply.headers().get_one("Cache-Control"), Some("no-store"));
        }
    }
    let store = Datastore::new_encrypted(":memory:".into(), "9a".repeat(32), false);
    let (client, tokens) = setup(store.clone(), Arc::default(), true);
    let admin = &tokens[0];
    let (status, start) = post(&client, admin, "run/start", request(), None);
    assert_eq!(status, Status::Ok);
    let denied = terminal(&client, admin, &start, false);
    assert_eq!(denied["reason"], "entitlement-unavailable");
    assert_eq!(denied["result"], Value::Null);
    let reply = client
        .put("/api/0/reports/library")
        .header(Header::new("Host", "localhost:5600"))
        .header(Header::new("Authorization", format!("Bearer {admin}")))
        .body(" ".repeat(1024 * 1024 + 4097))
        .dispatch();
    assert_eq!(reply.status(), Status::PayloadTooLarge);
    store.lock().unwrap();
    let reply = client
        .get("/api/0/reports/library")
        .header(Header::new("Host", "localhost:5600"))
        .header(Header::new("Authorization", format!("Bearer {admin}")))
        .dispatch();
    assert_eq!(reply.status(), Status::Locked);
    assert_eq!(reply.headers().get_one("Cache-Control"), Some("no-store"));
}
