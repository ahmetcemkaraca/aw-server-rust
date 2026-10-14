#![cfg(any(feature = "encryption", feature = "encryption-vendored"))]
use aw_datastore::{
    Datastore, SyncApplyBatchV1, SyncDeviceIdentity, SyncHeadCommitV1, SyncKeyMaterial,
};
use aw_models::{EgressPolicyBundleV1, EgressPolicyV1, SignedEgressPolicyBundleV1};
use aw_server::{
    config::AWConfig,
    endpoints::{self, AssetResolver, ServerState},
    sessions::{Scope, Sessions},
};
use aw_sync_e2ee::{create_policy_change, DeviceIdentityV1, SyncManifestV1};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rocket::{
    http::{ContentType, Header, Status},
    local::blocking::Client,
};
use serde_json::{json, Value};
use std::{collections::BTreeMap, path::PathBuf};
use zeroize::Zeroizing;
const LOCAL: [u8; 16] = [0x71; 16];
const PEER: [u8; 16] = [0x81; 16];
const VAULT: [u8; 16] = [0x75; 16];
struct Fixture {
    store: Datastore,
    path: PathBuf,
    key: String,
    peer: DeviceIdentityV1,
}
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "peak-policy-review-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let key = "c".repeat(64);
        let store =
            Datastore::open_encrypted(path.to_string_lossy().into_owned(), key.clone()).unwrap();
        store
            .create_sync_device_identity(&SyncDeviceIdentity::new(
                LOCAL,
                Zeroizing::new([0x72; 32]),
                Zeroizing::new([0x73; 32]),
            ))
            .unwrap();
        store
            .install_sync_key_material(&SyncKeyMaterial::new(
                Zeroizing::new([0x74; 32]),
                VAULT,
                1,
                [0x76; 24],
                [0x77; 48],
            ))
            .unwrap();
        let peer = DeviceIdentityV1::from_bytes(
            PEER,
            Zeroizing::new([0x82; 32]),
            Zeroizing::new([0x83; 32]),
        );
        let public = peer.public_identity();
        store
            .record_sync_pairing(
                None,
                [0x84; 16],
                PEER,
                URL_SAFE_NO_PAD
                    .decode(public.x25519_public_key)
                    .unwrap()
                    .try_into()
                    .unwrap(),
                URL_SAFE_NO_PAD
                    .decode(public.ed25519_public_key)
                    .unwrap()
                    .try_into()
                    .unwrap(),
                "2026-10-14T00:00:00Z".into(),
            )
            .unwrap();
        Self {
            store,
            path,
            key,
            peer,
        }
    }
    fn manifest(
        &self,
        field: &str,
        value: Value,
        revision: u64,
        counter: u64,
        parent: [u8; 32],
    ) -> SyncManifestV1 {
        let op = create_policy_change(
            PEER,
            counter,
            counter,
            BTreeMap::from([(field.to_owned(), value)]),
        )
        .unwrap();
        SyncManifestV1::new_signed(&self.peer, VAULT, 1, revision, parent, vec![op]).unwrap()
    }
    fn apply(
        &self,
        manifest: SyncManifestV1,
    ) -> Result<SyncHeadCommitV1, aw_datastore::DatastoreError> {
        self.store
            .apply_sync_operations(SyncApplyBatchV1 { manifest })
    }
    fn reopen(&mut self) {
        self.store.close();
        self.store =
            Datastore::open_encrypted(self.path.to_string_lossy().into_owned(), self.key.clone())
                .unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.store.close();
        let _ = std::fs::remove_file(&self.path);
        let _ = std::fs::remove_file(format!("{}-wal", self.path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", self.path.display()));
    }
}
fn portable(value: Value) -> Value {
    json!({"schema_version":1,"present":true,"value":value})
}

fn setup(store: &Datastore, scoped: bool) -> (Client, String, Vec<String>) {
    let sessions = Sessions::new(5600, false);
    let admin = sessions.mint(Scope::Admin).unwrap();
    let denied = vec![
        sessions.mint(Scope::Read).unwrap(),
        sessions.mint(Scope::Query).unwrap(),
        sessions
            .mint(Scope::Ingest(vec!["aw-watcher-window_".into()]))
            .unwrap(),
        sessions.mint(Scope::AiSend).unwrap(),
    ];
    let mut config = AWConfig::default();
    config.port = 5600;
    if scoped {
        config.auth.sessions = Some(sessions);
    }
    let client = Client::tracked(endpoints::build_rocket(
        ServerState {
            datastore: store.clone(),
            asset_resolver: AssetResolver::new(None),
            device_id: "synthetic".into(),
        },
        config,
    ))
    .unwrap();
    (client, admin, denied)
}
fn send(client: &Client, token: &str, path: &str, body: String) -> (Status, Value, Option<String>) {
    let mut request = client
        .post(format!("/api/0/sync/policies/{path}"))
        .header(Header::new("Host", "localhost:5600"))
        .header(ContentType::JSON)
        .body(body);
    if !token.is_empty() {
        request = request.header(Header::new("Authorization", format!("Bearer {token}")));
    }
    let response = request.dispatch();
    let status = response.status();
    let cache = response
        .headers()
        .get_one("Cache-Control")
        .map(str::to_owned);
    let raw = response.into_string().unwrap_or_default();
    let value = serde_json::from_str(&raw).unwrap_or(Value::Null);
    (status, value, cache)
}
fn import(f: &Fixture, field: &str, value: Value) -> String {
    f.apply(f.manifest(field, portable(value), 1, 1, [0; 32]))
        .unwrap();
    f.store
        .list_sync_policy_candidates(None, 256)
        .unwrap()
        .candidates[0]
        .candidate_id
        .clone()
}
fn preview(client: &Client, admin: &str, id: &str) -> Value {
    let (status, data, cache) = send(
        client,
        admin,
        "preview",
        json!({"schema_version":1,"candidate_id":id}).to_string(),
    );
    assert_eq!(status, Status::Ok);
    assert_eq!(cache.as_deref(), Some("no-store"));
    data
}
fn choice(preview: &Value, decision: &str) -> Value {
    json!({"choice":{"schema_version":1,"candidate_id":preview["policy"]["candidate"]["candidate_id"],"expected_review_sha256":preview["policy"]["expected_review_sha256"],"decision":decision},"firewall":preview["firewall"]})
}
#[test]
fn policy_routes_require_admin_and_no_store_including_denied_requests() {
    let f = Fixture::new();
    let (client, admin, denied) = setup(&f.store, true);
    for path in ["list", "preview", "choice"] {
        let (status, _, cache) = send(&client, "", path, "{}".into());
        assert_eq!(status, Status::Unauthorized);
        assert_eq!(cache.as_deref(), Some("no-store"));
        for token in &denied {
            let (status, _, cache) = send(&client, token, path, "{}".into());
            assert_eq!(status, Status::Forbidden);
            assert_eq!(cache.as_deref(), Some("no-store"));
        }
    }
    let (status, data, cache) = send(
        &client,
        &admin,
        "list",
        json!({"schema_version":1,"after":null,"limit":32}).to_string(),
    );
    assert_eq!(status, Status::Ok);
    assert_eq!(data["candidates"], json!([]));
    assert_eq!(cache.as_deref(), Some("no-store"));
}
#[test]
fn policy_routes_are_absent_without_scoped_encryption_and_fail_closed_when_locked() {
    let plain = Datastore::new_in_memory(false);
    for scoped in [true, false] {
        let (client, admin, _) = setup(&plain, scoped);
        let (status, _, cache) = send(&client, &admin, "list", "{}".into());
        assert_eq!(status, Status::NotFound);
        assert_eq!(cache.as_deref(), Some("no-store"));
    }
    let f = Fixture::new();
    let (client, admin, _) = setup(&f.store, true);
    f.store.lock().unwrap();
    for path in ["list", "preview", "choice"] {
        let (status, _, cache) = send(&client, &admin, path, "{}".into());
        assert_eq!(status, Status::Locked);
        assert_eq!(cache.as_deref(), Some("no-store"));
    }
}
#[test]
fn policy_request_records_reject_arrays_duplicates_unknown_fields_and_body_limits() {
    let f = Fixture::new();
    let (client, admin, _) = setup(&f.store, true);
    for (path,bodies) in [
        ("list",vec!["[1,null,32]".into(),"{\"schema_version\":1,\"schema_version\":1,\"limit\":32}".into(),json!({"schema_version":1,"limit":32,"trusted":true}).to_string(),json!({"schema_version":2,"limit":32}).to_string(),json!({"schema_version":1,"limit":0}).to_string(),json!({"schema_version":1,"limit":257}).to_string(),json!({"schema_version":1,"after":"bad","limit":32}).to_string()]),
        ("preview",vec![json!([1,"a".repeat(64)]).to_string(),json!({"schema_version":1,"candidate_id":"bad"}).to_string(),format!("{{\"schema_version\":1,\"candidate_id\":\"{}\",\"candidate_id\":\"{}\"}}","a".repeat(64),"b".repeat(64))]),
        ("choice",vec!["[]".into(),json!({"choice":[1,"a".repeat(64),"b".repeat(64),"keep-local"],"firewall":null}).to_string(),json!({"choice":{"schema_version":1,"candidate_id":"a".repeat(64),"expected_review_sha256":"b".repeat(64),"decision":"keep-local"},"firewall":null,"accept_remote_available":true}).to_string()])
    ] {for body in bodies {let (status,_,cache)=send(&client,&admin,path,body);assert_eq!(status,Status::BadRequest,"{path}");assert_eq!(cache.as_deref(),Some("no-store"));}}
    for (path, max) in [
        ("list", 1024),
        ("preview", 1024),
        ("choice", 4 * 1024 * 1024),
    ] {
        let (status, _, cache) = send(&client, &admin, path, format!("{{}}{}", " ".repeat(max)));
        assert_eq!(status, Status::PayloadTooLarge);
        assert_eq!(cache.as_deref(), Some("no-store"));
    }
}
#[test]
fn ordinary_policy_review_is_metadata_only_until_preview_and_choice_is_explicit_free_and_atomic() {
    let mut f = Fixture::new();
    f.store.set_key_value("settings.theme", "\"dark\"").unwrap();
    f.store.begin_sync_baseline().unwrap();
    let id = import(&f, "settings.theme", json!("light"));
    let before = f
        .store
        .list_sync_operations(LOCAL, 1, 0, 256)
        .unwrap()
        .len();
    let (client, admin, _) = setup(&f.store, true);
    let (status, page, _) = send(
        &client,
        &admin,
        "list",
        json!({"schema_version":1,"limit":32}).to_string(),
    );
    assert_eq!(status, Status::Ok);
    assert!(!page.to_string().contains("dark"));
    assert!(!page.to_string().contains("light"));
    assert!(page["candidates"][0]["counter"].is_string());
    let review = preview(&client, &admin, &id);
    assert_eq!(review["policy"]["current"]["value"], "dark");
    assert_eq!(review["policy"]["proposed"]["value"], "light");
    assert_eq!(review["accept_remote_available"], true);
    assert_eq!(f.store.get_key_value("settings.theme").unwrap(), "\"dark\"");
    let (status, accepted, cache) = send(
        &client,
        &admin,
        "choice",
        choice(&review, "accept-remote").to_string(),
    );
    assert_eq!(status, Status::Ok);
    assert_eq!(accepted["applied"], true);
    assert_eq!(cache.as_deref(), Some("no-store"));
    assert_eq!(
        f.store.get_key_value("settings.theme").unwrap(),
        "\"light\""
    );
    assert_eq!(
        f.store
            .list_sync_operations(LOCAL, 1, 0, 256)
            .unwrap()
            .len(),
        before + 1
    );
    let (status, _, _) = send(
        &client,
        &admin,
        "choice",
        choice(&review, "accept-remote").to_string(),
    );
    assert_eq!(status, Status::Conflict);
    drop(client);
    f.reopen();
    assert_eq!(
        f.store.get_key_value("settings.theme").unwrap(),
        "\"light\""
    );
    assert!(f
        .store
        .list_sync_policy_candidates(None, 256)
        .unwrap()
        .candidates
        .is_empty());
}
#[test]
fn untrusted_firewall_is_visible_keepable_and_cannot_activate_from_ui_flags() {
    let f = Fixture::new();
    let vector: Value =
        serde_json::from_str(include_str!("../../test-vectors/privacy-firewall-v1.json")).unwrap();
    let policy: EgressPolicyV1 = serde_json::from_value(vector["policy"].clone()).unwrap();
    let bundle = SignedEgressPolicyBundleV1 {
        schema_version: 1,
        signer_key_id: "untrusted-test".into(),
        bundle: EgressPolicyBundleV1 {
            schema_version: 1,
            version: policy.version,
            hard_deny_version: policy.hard_deny_version,
            destinations: policy.destinations,
            purposes: policy.purposes,
            organization_rules: policy.organization_rules,
        },
        signature: vec![0; 64],
    };
    let id = import(&f, "egress.signed_bundle", json!(bundle));
    let (client, admin, _) = setup(&f.store, true);
    let review = preview(&client, &admin, &id);
    assert_eq!(review["accept_remote_available"], false);
    assert_eq!(review["reason"], "firewall-review-unavailable");
    assert!(review["firewall"].is_null());
    assert_eq!(
        review["policy"]["candidate"]["field"],
        "egress.signed_bundle"
    );
    let (status, _, _) = send(
        &client,
        &admin,
        "choice",
        choice(&review, "accept-remote").to_string(),
    );
    assert_eq!(status, Status::Conflict);
    assert!(f.store.get_egress_policy_state().unwrap().is_none());
    assert_eq!(
        f.store
            .list_sync_policy_candidates(None, 256)
            .unwrap()
            .candidates
            .len(),
        1
    );
    let (status, kept, _) = send(
        &client,
        &admin,
        "choice",
        choice(&review, "keep-local").to_string(),
    );
    assert_eq!(status, Status::Ok);
    assert_eq!(kept["applied"], false);
    assert!(f
        .store
        .list_sync_policy_candidates(None, 256)
        .unwrap()
        .candidates
        .is_empty());
    assert!(f.store.get_egress_policy_state().unwrap().is_none());
}
#[test]
fn free_user_policy_uses_reviewed_firewall_and_rejects_nested_record_arrays() {
    let f = Fixture::new();
    let user = json!({"schema_version":1,"user_rules":[{"pattern":{"kind":"keyword","value":"banking"},"action":"deny"}],"safe_zone_patterns":[],"after_hours":null});
    let id = import(&f, "egress.user_policy", user.clone());
    let (client, admin, _) = setup(&f.store, true);
    let review = preview(&client, &admin, &id);
    assert_eq!(review["accept_remote_available"], true);
    let mut ambiguous = choice(&review, "accept-remote");
    let names = [
        "schema_version",
        "from_version",
        "to_version",
        "hard_deny_version_before",
        "hard_deny_version_after",
        "added_destinations",
        "removed_destinations",
        "changed_destinations",
        "added_purposes",
        "removed_purposes",
        "changed_purposes",
        "added_organization_rules",
        "removed_organization_rules",
        "added_user_rules",
        "removed_user_rules",
        "added_safe_zone_patterns",
        "removed_safe_zone_patterns",
        "after_hours_before",
        "after_hours_after",
    ];
    ambiguous["firewall"]["diff"] = Value::Array(
        names
            .iter()
            .map(|name| review["firewall"]["diff"][name].clone())
            .collect(),
    );
    let (status, _, _) = send(&client, &admin, "choice", ambiguous.to_string());
    assert_eq!(status, Status::BadRequest);
    assert!(f
        .store
        .get_egress_user_policy()
        .unwrap()
        .user_rules
        .is_empty());
    let (status, result, _) = send(
        &client,
        &admin,
        "choice",
        choice(&review, "accept-remote").to_string(),
    );
    assert_eq!(status, Status::Ok);
    assert_eq!(result["applied"], true);
    assert_eq!(
        serde_json::to_value(f.store.get_egress_user_policy().unwrap()).unwrap(),
        user
    );
    assert!(f.store.get_egress_policy_state().unwrap().is_none());
}
#[test]
fn local_edit_after_preview_rejects_choice_without_resolving_candidate() {
    let f = Fixture::new();
    let id = import(&f, "settings.theme", json!("light"));
    let (client, admin, _) = setup(&f.store, true);
    let review = preview(&client, &admin, &id);
    f.store.set_key_value("settings.theme", "\"dark\"").unwrap();
    let (status, _, cache) = send(
        &client,
        &admin,
        "choice",
        choice(&review, "accept-remote").to_string(),
    );
    assert_eq!(status, Status::Conflict);
    assert_eq!(cache.as_deref(), Some("no-store"));
    assert_eq!(f.store.get_key_value("settings.theme").unwrap(), "\"dark\"");
    assert_eq!(
        f.store
            .list_sync_policy_candidates(None, 256)
            .unwrap()
            .candidates
            .len(),
        1
    );
}

#[test]
fn shared_policy_context_route_is_admin_only_private_and_tracks_actual_worker_reopening() {
    let f = Fixture::new();
    let (client, admin, denied) = setup(&f.store, true);
    let request = |token: &str| {
        let mut request = client
            .get("/api/0/sync/policies/context")
            .header(Header::new("Host", "localhost:5600"));
        if !token.is_empty() {
            request = request.header(Header::new("Authorization", format!("Bearer {token}")));
        }
        request.dispatch()
    };
    for (token, status) in std::iter::once(("", Status::Unauthorized))
        .chain(denied.iter().map(|t| (t.as_str(), Status::Forbidden)))
    {
        let response = request(token);
        assert_eq!(response.status(), status);
        assert_eq!(
            response.headers().get_one("Cache-Control"),
            Some("no-store")
        );
    }
    let response = request(&admin);
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(
        response.headers().get_one("Cache-Control"),
        Some("no-store")
    );
    let first: Value = serde_json::from_str(&response.into_string().unwrap()).unwrap();
    assert_eq!(first["schema_version"], 1);
    assert_eq!(first.as_object().unwrap().len(), 2);
    assert!(aw_models::valid_lower_hex(
        first["context_id"].as_str().unwrap(),
        64
    ));
    assert_eq!(
        first,
        serde_json::to_value(f.store.get_sync_policy_context().unwrap()).unwrap()
    );
    f.store.lock().unwrap();
    let response = request(&admin);
    assert_eq!(response.status(), Status::Locked);
    assert_eq!(
        response.headers().get_one("Cache-Control"),
        Some("no-store")
    );
    f.store
        .unlock_encrypted(f.path.to_string_lossy().into_owned(), f.key.clone())
        .unwrap();
    let response = request(&admin);
    assert_eq!(response.status(), Status::Ok);
    let second: Value = serde_json::from_str(&response.into_string().unwrap()).unwrap();
    assert_ne!(second["context_id"], first["context_id"]);
}
