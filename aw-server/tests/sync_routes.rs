use aw_datastore::{Datastore, SyncKeyMaterial};
use aw_models::SyncEnvelopeV1;
use aw_server::{
    config::AWConfig,
    endpoints::{self, AssetResolver, ServerState},
    sessions::{Scope, Sessions},
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rocket::http::{ContentType, Header, Status};
use serde_json::{json, Value};
use std::path::PathBuf;
use zeroize::Zeroizing;

fn encrypted_store(name: &str) -> (Datastore, PathBuf) {
    let path = std::env::temp_dir().join(format!("peakactivity-sync-routes-{name}-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let store = Datastore::open_encrypted(path.to_string_lossy().into_owned(), "e".repeat(64)).unwrap();
    (store, path)
}

fn envelope(vault: [u8; 16], object: [u8; 16], ciphertext: [u8; 32]) -> SyncEnvelopeV1 {
    SyncEnvelopeV1 {
        schema_version: 1,
        object_id: URL_SAFE_NO_PAD.encode(object),
        vault_id: URL_SAFE_NO_PAD.encode(vault),
        key_epoch: 1,
        nonce: URL_SAFE_NO_PAD.encode([0x44; 24]),
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
    }
}

#[test]
fn sync_object_routes_are_admin_only_opaque_idempotent_and_ack_gated() {
    let sessions = Sessions::new(5600, false);
    let admin = sessions.mint(Scope::Admin).unwrap();
    let read = sessions.mint(Scope::Read).unwrap();
    let (datastore, path) = encrypted_store("objects");
    let vault_id = [0x11; 16];
    let device_id = [0x22; 16];
    datastore.record_sync_pairing(
        Some(SyncKeyMaterial::new(Zeroizing::new([0x33; 32]), vault_id, 1, [0x55; 24], [0x66; 48])),
        [0x77; 16], device_id, [0x88; 32], [0x89; 32], "2026-09-23T12:00:00Z".into(),
    ).unwrap();
    let state = ServerState {
        datastore: datastore.clone(),
        asset_resolver: AssetResolver::new(None),
        device_id: "synthetic".into(),
    };
    let mut config = AWConfig::default();
    config.port = 5600;
    config.auth.sessions = Some(sessions);
    let client = rocket::local::blocking::Client::tracked(endpoints::build_rocket(state, config)).unwrap();
    let host = Header::new("Host", "localhost:5600");
    let auth = |token: &str| Header::new("Authorization", format!("Bearer {token}"));
    let object = envelope(vault_id, [0x99; 16], [0xAA; 32]);
    let body = json!({"envelope": object.clone()});

    for method in ["GET", "POST", "DELETE"] {
        let response = match method {
            "GET" => client.get(format!("/api/0/sync/objects?vault_id={}", URL_SAFE_NO_PAD.encode(vault_id)))
                .header(host.clone()).header(auth(&read)).dispatch(),
            "POST" => client.post("/api/0/sync/objects")
                .header(host.clone()).header(auth(&read)).header(ContentType::JSON)
                .body(body.to_string()).dispatch(),
            _ => client.delete(format!("/api/0/sync/objects/{}", URL_SAFE_NO_PAD.encode([0x99; 16])))
                .header(host.clone()).header(auth(&read)).header(ContentType::JSON)
                .body(r#"{"tombstones":[]}"#).dispatch(),
        };
        assert_eq!(response.status(), Status::Forbidden);
    }
    assert_eq!(client.get("/api/0/sync/enabled").header(host.clone()).header(auth(&read)).dispatch().status(), Status::Forbidden);
    assert_eq!(client.post("/api/0/sync/enabled").header(host.clone()).header(auth(&read))
        .header(ContentType::JSON).body(r#"{"enabled":false,"destination_id":null,"purpose_id":null}"#).dispatch().status(), Status::Forbidden);
    assert_eq!(client.post("/api/0/sync/relay").header(host.clone()).header(auth(&read))
        .header(ContentType::JSON).body("{}").dispatch().status(), Status::Forbidden);
    assert_eq!(client.post("/api/0/sync/objects").header(host.clone()).header(ContentType::JSON)
        .body(body.to_string()).dispatch().status(), Status::Unauthorized);

    let inserted = client.post("/api/0/sync/objects").header(host.clone()).header(auth(&admin))
        .header(ContentType::JSON).body(body.to_string()).dispatch();
    assert_eq!(inserted.status(), Status::Created);
    assert!(serde_json::from_str::<Value>(&inserted.into_string().unwrap()).unwrap()["inserted"] == true);
    let duplicate = client.post("/api/0/sync/objects").header(host.clone()).header(auth(&admin))
        .header(ContentType::JSON).body(body.to_string()).dispatch();
    assert_eq!(duplicate.status(), Status::Ok);
    assert_eq!(serde_json::from_str::<Value>(&duplicate.into_string().unwrap()).unwrap()["inserted"], false);

    let id = URL_SAFE_NO_PAD.encode([0x99; 16]);
    let listed = client.get(format!("/api/0/sync/objects?vault_id={}&limit=1", URL_SAFE_NO_PAD.encode(vault_id)))
        .header(host.clone()).header(auth(&admin)).dispatch();
    assert_eq!(listed.status(), Status::Ok);
    let page: Value = serde_json::from_str(&listed.into_string().unwrap()).unwrap();
    assert_eq!(page["objects"].as_array().unwrap().len(), 1);
    assert_eq!(page["next_cursor"], Value::Null);
    let fetched = client.get(format!("/api/0/sync/objects/{id}")).header(host.clone()).header(auth(&admin)).dispatch();
    assert_eq!(fetched.status(), Status::Ok);
    assert_eq!(serde_json::from_str::<SyncEnvelopeV1>(&fetched.into_string().unwrap()).unwrap(), object);
    let history = client.get("/api/0/sync/history").header(host.clone()).header(auth(&admin)).dispatch();
    assert_eq!(history.status(), Status::Ok);
    let history: Value = serde_json::from_str(&history.into_string().unwrap()).unwrap();
    let history = serde_json::to_string(&history).unwrap();
    assert!(!history.contains("private-window-title"));
    assert!(!history.contains("/Users/alice"));

    let delete = || client.delete(format!("/api/0/sync/objects/{id}")).header(host.clone()).header(auth(&admin))
        .header(ContentType::JSON)
        .body(json!({"tombstones":[{
            "origin_device_id":URL_SAFE_NO_PAD.encode([0xBB; 16]),
            "local_event_id":7,
            "tombstone_counter":3
        }]}).to_string()).dispatch();
    assert_eq!(delete().status(), Status::Conflict);
    datastore.acknowledge_sync_tombstone([0xBB; 16], 7, 3, device_id, "2026-09-23T12:01:00Z".into()).unwrap();
    assert_eq!(delete().status(), Status::Ok);
    assert!(datastore.get_sync_object(id).unwrap().is_none());
    datastore.lock().unwrap();
    std::fs::remove_file(path).unwrap();
}

#[test]
fn sync_object_routes_are_absent_without_encrypted_scoped_local_sessions() {
    let state = ServerState {
        datastore: Datastore::new_in_memory(false),
        asset_resolver: AssetResolver::new(None),
        device_id: "synthetic".into(),
    };
    let mut config = AWConfig::default();
    config.port = 5600;
    let client = rocket::local::blocking::Client::tracked(endpoints::build_rocket(state, config)).unwrap();
    assert_eq!(client.get("/api/0/sync/objects?vault_id=AQEBAQEBAQEBAQEBAQEBAQ")
        .header(Header::new("Host", "localhost:5600")).dispatch().status(), Status::NotFound);

    let sessions = Sessions::new(5601, false);
    let admin = sessions.mint(Scope::Admin).unwrap();
    let mut config = AWConfig::default();
    config.port = 5601;
    config.auth.sessions = Some(sessions);
    let state = ServerState {
        datastore: Datastore::new_in_memory(false),
        asset_resolver: AssetResolver::new(None),
        device_id: "synthetic".into(),
    };
    let client = rocket::local::blocking::Client::tracked(endpoints::build_rocket(state, config)).unwrap();
    assert_eq!(client.get("/api/0/sync/objects?vault_id=AQEBAQEBAQEBAQEBAQEBAQ")
        .header(Header::new("Host", "localhost:5601"))
        .header(Header::new("Authorization", format!("Bearer {admin}")))
        .dispatch().status(), Status::NotFound);
}

#[test]
fn missing_signed_sync_destination_keeps_remote_requests_unavailable() {
    let sessions = Sessions::new(5600, false);
    let admin = sessions.mint(Scope::Admin).unwrap();
    let (datastore, path) = encrypted_store("missing-trust");
    let state = ServerState {
        datastore: datastore.clone(),
        asset_resolver: AssetResolver::new(None),
        device_id: "synthetic".into(),
    };
    let mut config = AWConfig::default();
    config.port = 5600;
    config.auth.sessions = Some(sessions);
    let client = rocket::local::blocking::Client::tracked(endpoints::build_rocket(state, config)).unwrap();
    let host = Header::new("Host", "localhost:5600");
    let auth = Header::new("Authorization", format!("Bearer {admin}"));

    let status = client.get("/api/0/sync/enabled").header(host.clone()).header(auth.clone()).dispatch();
    assert_eq!(status.status(), Status::Ok);
    assert_eq!(serde_json::from_str::<Value>(&status.into_string().unwrap()).unwrap()["enabled"], false);
    let enable = client.post("/api/0/sync/enabled").header(host.clone()).header(auth.clone())
        .header(ContentType::JSON).body(r#"{"enabled":true,"destination_id":"sync-relay","purpose_id":"sync-object-v1"}"#).dispatch();
    assert_eq!(enable.status(), Status::ServiceUnavailable);
    assert!(!datastore.sync_enabled().unwrap());

    let envelope = envelope([0x31; 16], [0x32; 16], [0x33; 32]);
    let request = json!({
        "destination_id":"sync-relay",
        "purpose_id":"sync-object-v1",
        "request":{
            "schema_version":1,
            "operation":"put_if_absent",
            "object_id":envelope.object_id.clone(),
            "vault_id":envelope.vault_id.clone(),
            "envelope":envelope.clone()
        }
    });
    let relay = client.post("/api/0/sync/relay").header(host.clone()).header(auth.clone())
        .header(ContentType::JSON).body(request.to_string()).dispatch();
    assert_eq!(relay.status(), Status::ServiceUnavailable);
    let local_put = client.post("/api/0/sync/objects").header(host).header(auth)
        .header(ContentType::JSON).body(json!({"envelope":envelope}).to_string()).dispatch();
    assert_eq!(local_put.status(), Status::Created);
    assert!(datastore.get_egress_receipts(10).unwrap().is_empty());
    datastore.lock().unwrap();
    std::fs::remove_file(path).unwrap();
}
