#![cfg(any(feature = "encryption", feature = "encryption-vendored"))]
use aw_datastore::Datastore;
use aw_server::{
    config::AWConfig,
    endpoints::{self, AssetResolver, ServerState},
    sessions::{Scope, Sessions},
};
use rocket::{
    http::{ContentType, Header, Status},
    local::blocking::Client,
};
use serde_json::json;
#[path = "support/entitlement.rs"]
mod entitlement;
#[path = "support/backup_provider.rs"]
mod fixture;

fn client(store: &Datastore) -> (Client, String, Vec<String>) {
    let sessions = Sessions::new(5600, false);
    let admin = sessions.mint(Scope::Admin).unwrap();
    let denied = [
        Scope::Read,
        Scope::Query,
        Scope::Ingest(vec!["fixture".into()]),
        Scope::AiSend,
    ]
    .into_iter()
    .map(|scope| sessions.mint(scope).unwrap())
    .collect();
    let mut config = AWConfig::default();
    config.auth.sessions = Some(sessions);
    let client = Client::tracked(endpoints::build_rocket(
        ServerState {
            datastore: store.clone(),
            asset_resolver: AssetResolver::new(None),
            device_id: "fixture".into(),
        },
        config,
    ))
    .unwrap();
    (client, admin, denied)
}
fn send(client: &Client, token: &str, path: &str, body: &str) -> (Status, Option<String>) {
    let mut request = client
        .post(format!("/api/0/sync/backups/{path}"))
        .header(Header::new("Host", "localhost:5600"))
        .header(ContentType::JSON)
        .body(body);
    if !token.is_empty() {
        request = request.header(Header::new("Authorization", format!("Bearer {token}")));
    }
    let response = request.dispatch();
    (
        response.status(),
        response
            .headers()
            .get_one("Cache-Control")
            .map(str::to_owned),
    )
}
#[test]
fn provider_routes_require_admin_and_all_errors_disable_caching() {
    let store = Datastore::open_encrypted(":memory:".into(), "a".repeat(64)).unwrap();
    let (client, admin, denied) = client(&store);
    let context = store.get_sync_policy_context().unwrap().context_id;
    let body=json!({"schema_version":1,"context_id":context,"operation":"list","destination_id":"sync-relay","source_json":json!({"schema_version":1,"context_id":context,"source_id":"local"}).to_string(),"selection":null}).to_string();
    for path in ["preview", "approve", "run"] {
        assert_eq!(
            send(&client, "", path, "{}"),
            (Status::Unauthorized, Some("no-store".into()))
        );
        for token in &denied {
            assert_eq!(
                send(&client, token, path, "{}"),
                (Status::Forbidden, Some("no-store".into()))
            );
        }
    }
    assert_eq!(
        send(&client, &admin, "preview", &body),
        (Status::ServiceUnavailable, Some("no-store".into()))
    );
    store.close();
    assert_eq!(
        send(&client, &admin, "preview", &body),
        (Status::Locked, Some("no-store".into()))
    );
}
#[test]
fn provider_routes_reject_duplicate_array_unknown_and_oversize_bodies_before_work() {
    let store = Datastore::open_encrypted(":memory:".into(), "a".repeat(64)).unwrap();
    let (client, admin, _) = client(&store);
    for body in [
        "[]",
        "{\"schema_version\":1,\"schema_version\":1}",
        "{\"extra\":true}",
    ] {
        assert_eq!(
            send(&client, &admin, "preview", body),
            (Status::BadRequest, Some("no-store".into()))
        );
    }
    assert_eq!(
        send(&client, &admin, "preview", &" ".repeat(128 * 1024 + 1)),
        (Status::PayloadTooLarge, Some("no-store".into()))
    );
    store.close();
}

fn provider_client(store: &Datastore, relay: fixture::Relay) -> (Client, String) {
    provider_client_access(store, relay, true)
}
fn provider_client_access(
    store: &Datastore,
    relay: fixture::Relay,
    paid: bool,
) -> (Client, String) {
    let sessions = Sessions::new(5600, false);
    let admin = sessions.mint(Scope::Admin).unwrap();
    let mut config = AWConfig::default();
    config.auth.sessions = Some(sessions);
    if paid {
        config.feature_access = entitlement::access();
    }
    let signer = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[0x91; 32]).unwrap();
    use ring::signature::KeyPair;
    let trust =
        endpoints::EgressPolicyTrust::from_release_keys(std::collections::HashMap::from([(
            "fixture".into(),
            signer.public_key().as_ref().to_vec(),
        )]));
    let client = Client::tracked(endpoints::build_rocket_with_egress_transport(
        ServerState {
            datastore: store.clone(),
            asset_resolver: AssetResolver::new(None),
            device_id: "fixture".into(),
        },
        config,
        trust,
        relay,
    ))
    .unwrap();
    (client, admin)
}
fn post_value(client: &Client, token: &str, path: &str, body: String) -> serde_json::Value {
    let response = client
        .post(format!("/api/0/sync/backups/{path}"))
        .header(Header::new("Host", "localhost:5600"))
        .header(Header::new("Authorization", format!("Bearer {token}")))
        .header(ContentType::JSON)
        .body(body)
        .dispatch();
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(
        response.headers().get_one("Cache-Control"),
        Some("no-store")
    );
    serde_json::from_str(&response.into_string().unwrap()).unwrap()
}
fn http_operation(
    client: &Client,
    token: &str,
    operation: &str,
    key: &serde_json::Value,
    selection: Option<serde_json::Value>,
) -> serde_json::Value {
    let preview = post_value(
        client,
        token,
        "preview",
        fixture::request(operation, key, selection),
    );
    let approval=post_value(client,token,"approve",json!({"schema_version":1,"context_id":key["context_id"],"preview_id":preview["preview_id"],"user_accepted":true,"source_json":key.to_string()}).to_string());
    post_value(client,token,"run",json!({"schema_version":1,"context_id":key["context_id"],"job_id":approval["job_id"],"source_json":key.to_string()}).to_string())
}
#[test]
fn provider_http_actual_signed_roundtrip_uses_managed_paid_proxy_and_atomic_sink() {
    let (source, kit, selected) = fixture::source();
    let _ = fixture::policy(&source);
    let relay = fixture::Relay::default();
    let (source_client, source_admin) = provider_client(&source, relay.clone());
    let uploaded = http_operation(&source_client, &source_admin, "upload", &selected, None);
    assert_eq!(uploaded["status"], "complete");
    let target = Datastore::open_encrypted(":memory:".into(), "b".repeat(64)).unwrap();
    let _ = fixture::policy(&target);
    let (client, admin) = provider_client(&target, relay.clone());
    let key = json!({"schema_version":1,"source_id":"local","context_id":target.get_sync_policy_context().unwrap().context_id,"recovery":{"kit":kit["kit"],"phrase":kit["recovery_phrase"]}});
    let catalogue = http_operation(&client, &admin, "list", &key, None);
    let downloaded = http_operation(
        &client,
        &admin,
        "download",
        &key,
        Some(catalogue["versions"][0]["selection"].clone()),
    );
    assert_eq!(downloaded["status"], "complete");
    assert_eq!(downloaded["local_selection"]["source_id"], "local");
    assert!(target.load_sync_key_material().unwrap().is_none());
    assert!(target.load_sync_snapshot().unwrap().is_none());
    assert!(!target.sync_enabled().unwrap());
    assert_eq!(relay.requests.lock().unwrap().len(), 3);
    source.close();
    target.close();
}

#[test]
fn provider_http_signed_cleanup_discovery_and_delete_work_without_paid_access() {
    let (store, _, selected) = fixture::source();
    let old = store.load_sync_snapshot().unwrap().unwrap();
    aw_server::sync_control::SyncControl::new()
        .invoke(&store, "create_current_sync_snapshot", json!({}))
        .unwrap();
    let _ = fixture::policy(&store);
    let relay = fixture::Relay::default();
    for o in &old.envelopes {
        relay
            .objects
            .lock()
            .unwrap()
            .insert(o.object_id.clone(), o.clone());
    }
    let (client, admin) = provider_client_access(&store, relay.clone(), false);
    let key = json!({"schema_version":1,"source_id":"local","context_id":selected["context_id"]});
    let catalogue = http_operation(&client, &admin, "cleanup_list", &key, None);
    assert_eq!(catalogue["cleanup_only"], true);
    let result = http_operation(
        &client,
        &admin,
        "delete",
        &key,
        Some(catalogue["versions"][0]["deletion_selection"].clone()),
    );
    assert_eq!(result["deleted"], 1);
    assert_eq!(result["unknown"], 0);
    assert!(relay.objects.lock().unwrap().is_empty());
    assert!(store.get_buckets().unwrap().is_empty());
    drop(client);
    store.close();
}
