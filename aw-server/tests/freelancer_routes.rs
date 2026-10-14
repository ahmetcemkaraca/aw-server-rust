use aw_datastore::Datastore;
use aw_models::{
    freelancer_report_signature_message_v1, ApprovedTimesheetV1, FreelancerWorkspaceV1,
};
use aw_server::{
    config::AWConfig,
    endpoints::{self, AssetResolver, ServerState},
    sessions::{Scope, Sessions},
};
use ring::signature::{UnparsedPublicKey, ED25519};
use rocket::http::{ContentType, Header, Status};
use rocket::local::blocking::Client;
use std::sync::Arc;
mod entitlement_fixture {
    include!("support/entitlement.rs");
}

fn setup(datastore: Datastore) -> (Client, String, String) {
    let now = entitlement_fixture::aw_server_time();
    setup_with_access(
        datastore,
        entitlement_fixture::configured_access(
            entitlement_fixture::freelancer_proof(now, 1, false),
            now,
        )
        .0,
    )
}

fn setup_with_access(
    datastore: Datastore,
    access: Arc<aw_entitlements::RuntimeFeatureAccessV1>,
) -> (Client, String, String) {
    let sessions = Sessions::new(5600, false);
    let admin = sessions.mint(Scope::Admin).unwrap();
    let read = sessions.mint(Scope::Read).unwrap();
    let state = ServerState {
        datastore,
        asset_resolver: AssetResolver::new(None),
        device_id: "synthetic".into(),
    };
    let mut config = AWConfig::default();
    config.port = 5600;
    config.auth.sessions = Some(sessions);
    config.feature_access = access;
    (
        Client::tracked(endpoints::build_rocket(state, config)).unwrap(),
        admin,
        read,
    )
}

fn workspace_update(label: &str, revision: u64) -> serde_json::Value {
    serde_json::json!({"expected_revision":revision,"workspace":{"schema_version":1,"revision":revision,
        "projects":[{"project_alias":"project-9af31c","label":label,"billable_default":true,
            "rounding_increment_seconds":900,"rounding_mode":"nearest","currency_code":"EUR","hourly_rate_minor":7500}],
        "category_rules":[{"category_path":["Work","Client work"],"project_alias":"project-9af31c"}]}})
}

#[test]
fn freelancer_paid_work_is_denied_without_a_plan_and_does_not_modify_vault_metadata() {
    let store = Datastore::new_encrypted(":memory:".into(), "9a".repeat(32), false);
    let before = store.get_key_values("%").unwrap();
    let (client, admin, _) = setup_with_access(store.clone(), Arc::default());
    let host = Header::new("Host", "localhost:5600");
    let auth = Header::new("Authorization", format!("Bearer {admin}"));
    assert_eq!(
        client
            .get("/api/0/freelancer/workspace")
            .header(host.clone())
            .header(auth.clone())
            .dispatch()
            .status(),
        Status::Ok
    );
    assert_eq!(
        client
            .put("/api/0/freelancer/workspace")
            .header(host.clone())
            .header(auth.clone())
            .header(ContentType::JSON)
            .body(workspace_update("Private project", 0).to_string())
            .dispatch()
            .status(),
        Status::Forbidden
    );
    let timesheet = r#"{"schema_version":1,"project_alias":"project-9af31c","date":"2026-10-13","approved_duration_seconds":600,"user_note":null}"#;
    for path in ["preview", "sign"] {
        assert_eq!(
            client
                .post(format!("/api/0/freelancer/timesheet/{path}"))
                .header(host.clone())
                .header(auth.clone())
                .header(ContentType::JSON)
                .body(timesheet)
                .dispatch()
                .status(),
            Status::Forbidden
        );
    }
    assert_eq!(store.get_key_values("%").unwrap(), before);
}

#[test]
fn freelancer_revocation_preserves_read_and_removal_only_access_without_allowing_corrections() {
    let store = Datastore::new_encrypted(":memory:".into(), "9a".repeat(32), false);
    let now = entitlement_fixture::aw_server_time();
    let (access, _) = entitlement_fixture::configured_access(
        entitlement_fixture::freelancer_proof(now, 1, false),
        now,
    );
    let (client, admin, _) = setup_with_access(store.clone(), access.clone());
    let host = Header::new("Host", "localhost:5600");
    let auth = Header::new("Authorization", format!("Bearer {admin}"));
    let updated = client
        .put("/api/0/freelancer/workspace")
        .header(host.clone())
        .header(auth.clone())
        .header(ContentType::JSON)
        .body(workspace_update("Private project", 0).to_string())
        .dispatch();
    assert_eq!(updated.status(), Status::Ok);
    let original: serde_json::Value =
        serde_json::from_str(&updated.into_string().unwrap()).unwrap();
    assert!(access
        .install(entitlement_fixture::freelancer_proof(now, 2, true), now)
        .is_err());
    let before = store.get_key_values("%").unwrap();
    assert_eq!(
        client
            .put("/api/0/freelancer/workspace")
            .header(host.clone())
            .header(auth.clone())
            .header(ContentType::JSON)
            .body(workspace_update("Unlicensed correction", 1).to_string())
            .dispatch()
            .status(),
        Status::Forbidden
    );
    let timesheet = r#"{"schema_version":1,"project_alias":"project-9af31c","date":"2026-10-13","approved_duration_seconds":600,"user_note":null}"#;
    for path in ["preview", "sign"] {
        assert_eq!(
            client
                .post(format!("/api/0/freelancer/timesheet/{path}"))
                .header(host.clone())
                .header(auth.clone())
                .header(ContentType::JSON)
                .body(timesheet)
                .dispatch()
                .status(),
            Status::Forbidden
        );
    }
    assert_eq!(store.get_key_values("%").unwrap(), before);
    let read = client
        .get("/api/0/freelancer/workspace")
        .header(host.clone())
        .header(auth.clone())
        .dispatch();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&read.into_string().unwrap()).unwrap(),
        original
    );
    let mut removal = original;
    removal["category_rules"] = serde_json::json!([]);
    let deleted = client
        .put("/api/0/freelancer/workspace")
        .header(host.clone())
        .header(auth.clone())
        .header(ContentType::JSON)
        .body(serde_json::json!({"expected_revision":1,"workspace":removal}).to_string())
        .dispatch();
    assert_eq!(deleted.status(), Status::Ok);
    removal["revision"] = serde_json::json!(2);
    removal["projects"] = serde_json::json!([]);
    let cleared = client
        .put("/api/0/freelancer/workspace")
        .header(host)
        .header(auth)
        .header(ContentType::JSON)
        .body(serde_json::json!({"expected_revision":2,"workspace":removal}).to_string())
        .dispatch();
    assert_eq!(cleared.status(), Status::Ok);
    let final_workspace: FreelancerWorkspaceV1 =
        serde_json::from_str(&cleared.into_string().unwrap()).unwrap();
    assert!(final_workspace.projects.is_empty());
    assert!(final_workspace.category_rules.is_empty());
}

fn decode_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn unlicensed_workspace_removal_preserves_order_and_noops_do_not_increment_revision() {
    let store = Datastore::new_encrypted(":memory:".into(), "9a".repeat(32), false);
    let mut workspace = workspace_update("Private project", 3)["workspace"].clone();
    let base = workspace["projects"][0].clone();
    let projects = ["project-a", "project-b", "project-c"].map(|alias| {
        let mut project = base.clone(); project["project_alias"] = serde_json::json!(alias); project
    });
    workspace["projects"] = serde_json::json!(projects);
    workspace["category_rules"] = serde_json::json!([]);
    store.set_key_value("freelancer.workspace.v1", &workspace.to_string()).unwrap();
    let (client, admin, _) = setup_with_access(store.clone(), Arc::default());
    let host = Header::new("Host", "localhost:5600");
    let auth = Header::new("Authorization", format!("Bearer {admin}"));
    let put = |workspace: &serde_json::Value| client.put("/api/0/freelancer/workspace")
        .header(host.clone()).header(auth.clone()).header(ContentType::JSON)
        .body(serde_json::json!({"expected_revision":workspace["revision"],"workspace":workspace}).to_string()).dispatch();
    let original = store.get_key_values("%").unwrap();
    let mut changed = workspace.clone();
    changed["projects"] = serde_json::json!([projects[2], projects[0]]);
    assert_eq!(put(&changed).status(), Status::Forbidden);
    changed["projects"] = serde_json::json!([projects[0], projects[2]]);
    changed["projects"][0]["label"] = serde_json::json!("Unlicensed correction");
    assert_eq!(put(&changed).status(), Status::Forbidden);
    assert_eq!(store.get_key_values("%").unwrap(), original);
    changed["projects"][0] = projects[0].clone();
    let removed = put(&changed);
    assert_eq!(removed.status(), Status::Ok);
    let retained: serde_json::Value = serde_json::from_str(&removed.into_string().unwrap()).unwrap();
    assert_eq!(retained["revision"], 4);
    let before_noop = store.get_key_values("%").unwrap();
    let noop = put(&retained);
    assert_eq!(noop.status(), Status::Ok);
    assert_eq!(serde_json::from_str::<serde_json::Value>(&noop.into_string().unwrap()).unwrap(), retained);
    assert_eq!(store.get_key_values("%").unwrap(), before_noop);
}

#[test]
fn local_freelancer_workspace_is_strict_revisioned_and_admin_scoped() {
    let store = Datastore::new_encrypted(":memory:".into(), "9a".repeat(32), false);
    let (client, admin, read) = setup(store);
    let host = Header::new("Host", "localhost:5600");
    let auth = |token: &str| Header::new("Authorization", format!("Bearer {token}"));

    assert_eq!(client.get("/api/0/freelancer/workspace").header(host.clone()).dispatch().status(), Status::Unauthorized);
    assert_eq!(client.get("/api/0/freelancer/workspace").header(host.clone()).header(auth(&read)).dispatch().status(), Status::Forbidden);

    let initial = client.get("/api/0/freelancer/workspace")
        .header(host.clone()).header(auth(&admin)).dispatch();
    assert_eq!(initial.status(), Status::Ok);
    let initial: FreelancerWorkspaceV1 = serde_json::from_str(&initial.into_string().unwrap()).unwrap();
    assert_eq!(initial.revision, 0);

    let update = client.put("/api/0/freelancer/workspace")
        .header(host.clone()).header(auth(&admin)).header(ContentType::JSON)
        .body(r#"{"expected_revision":0,"workspace":{"schema_version":1,"revision":0,"projects":[{"project_alias":"project-9af31c","label":"Private internal label","billable_default":true,"rounding_increment_seconds":900,"rounding_mode":"nearest","currency_code":"EUR","hourly_rate_minor":7500}],"category_rules":[{"category_path":["Work","Client work"],"project_alias":"project-9af31c"}]}}"#)
        .dispatch();
    assert_eq!(update.status(), Status::Ok);
    let updated: FreelancerWorkspaceV1 = serde_json::from_str(&update.into_string().unwrap()).unwrap();
    assert_eq!(updated.revision, 1);
    assert_eq!(updated.projects[0].project_alias, "project-9af31c");

    let stale = client.put("/api/0/freelancer/workspace")
        .header(host.clone()).header(auth(&admin)).header(ContentType::JSON)
        .body(r#"{"expected_revision":0,"workspace":{"schema_version":1,"revision":0,"projects":[],"category_rules":[]}}"#)
        .dispatch();
    assert_eq!(stale.status(), Status::Conflict);

    let cleared = client.put("/api/0/freelancer/workspace")
        .header(host.clone()).header(auth(&admin)).header(ContentType::JSON)
        .body(r#"{"expected_revision":1,"workspace":{"schema_version":1,"revision":1,"projects":[],"category_rules":[]}}"#)
        .dispatch();
    assert_eq!(cleared.status(), Status::Ok);
    let cleared: FreelancerWorkspaceV1 = serde_json::from_str(&cleared.into_string().unwrap()).unwrap();
    assert_eq!(cleared.revision, 2);
    assert!(cleared.projects.is_empty());
    assert!(cleared.category_rules.is_empty());

    let tainted = client.put("/api/0/freelancer/workspace")
        .header(host.clone()).header(auth(&admin)).header(ContentType::JSON)
        .body(r#"{"expected_revision":2,"workspace":{"schema_version":1,"revision":2,"projects":[],"category_rules":[],"client_name":"private"}}"#)
        .dispatch();
    assert_eq!(tainted.status(), Status::UnprocessableEntity);
}

#[test]
fn project_workspace_fails_closed_without_an_unlocked_encrypted_vault() {
    let (plaintext, admin, _) = setup(Datastore::new_in_memory(false));
    let host = Header::new("Host", "localhost:5600");
    let auth = Header::new("Authorization", format!("Bearer {admin}"));
    assert_eq!(plaintext.get("/api/0/freelancer/workspace").header(host.clone()).header(auth).dispatch().status(), Status::ServiceUnavailable);
    let auth = Header::new("Authorization", format!("Bearer {admin}"));
    assert_eq!(plaintext.post("/api/0/freelancer/timesheet/sign").header(host.clone()).header(auth).header(ContentType::JSON).body("{}").dispatch().status(), Status::ServiceUnavailable);

    let (locked, admin, _) = setup(Datastore::new_locked());
    let auth = Header::new("Authorization", format!("Bearer {admin}"));
    assert_eq!(locked.get("/api/0/freelancer/workspace").header(host.clone()).header(auth.clone()).dispatch().status(), Status::Locked);
    assert_eq!(locked.post("/api/0/freelancer/timesheet/sign").header(host).header(auth).header(ContentType::JSON).body("{}").dispatch().status(), Status::Locked);
}

#[test]
fn signed_client_report_is_verifiable_and_uses_a_persistent_vault_key() {
    let store = Datastore::new_encrypted(":memory:".into(), "9a".repeat(32), false);
    let (client, admin, _) = setup(store);
    let host = Header::new("Host", "localhost:5600");
    let auth = Header::new("Authorization", format!("Bearer {admin}"));
    let request = r#"{"schema_version":1,"project_alias":"project-9af31c","date":"2026-09-23","approved_duration_seconds":18000,"user_note":"Approved sprint work"}"#;
    let sign = || client.post("/api/0/freelancer/timesheet/sign")
        .header(host.clone()).header(auth.clone()).header(ContentType::JSON).body(request).dispatch();
    let first = sign();
    assert_eq!(first.status(), Status::Ok);
    let first: serde_json::Value = serde_json::from_str(&first.into_string().unwrap()).unwrap();
    assert!(first.get("private_key").is_none());
    let timesheet: ApprovedTimesheetV1 = serde_json::from_value(first["timesheet"].clone()).unwrap();
    let artifact = timesheet.artifact_bytes().unwrap();
    let message = freelancer_report_signature_message_v1(&timesheet).unwrap();
    let hash = ring::digest::digest(&ring::digest::SHA256, &artifact);
    assert_eq!(first["artifact_sha256"], hash.as_ref().iter().map(|byte| format!("{byte:02x}")).collect::<String>());
    let public_key = decode_hex(first["signer_public_key_ed25519"].as_str().unwrap());
    let signature = decode_hex(first["signature_ed25519"].as_str().unwrap());
    UnparsedPublicKey::new(&ED25519, public_key).verify(&message, &signature).unwrap();

    let second = sign();
    assert_eq!(second.status(), Status::Ok);
    let second: serde_json::Value = serde_json::from_str(&second.into_string().unwrap()).unwrap();
    assert_eq!(first["signer_public_key_ed25519"], second["signer_public_key_ed25519"]);
    assert_eq!(first["signature_ed25519"], second["signature_ed25519"]);

    let tainted = r#"{"schema_version":1,"project_alias":"project-9af31c","date":"2026-09-23","approved_duration_seconds":18000,"user_note":null,"client_alias":"private-client"}"#;
    assert_eq!(client.post("/api/0/freelancer/timesheet/sign")
        .header(host).header(auth).header(ContentType::JSON).body(tainted).dispatch().status(), Status::UnprocessableEntity);
}

#[test]
fn timesheet_preview_returns_exact_client_safe_bytes_and_rejects_raw_fields() {
    let store = Datastore::new_encrypted(":memory:".into(), "9a".repeat(32), false);
    let (client, admin, _) = setup(store);
    let host = Header::new("Host", "localhost:5600");
    let auth = Header::new("Authorization", format!("Bearer {admin}"));
    let request = r#"{"schema_version":1,"project_alias":"project-9af31c","date":"2026-09-23","approved_duration_seconds":18000,"user_note":"Approved sprint work"}"#;
    let response = client.post("/api/0/freelancer/timesheet/preview")
        .header(host.clone()).header(auth.clone()).header(ContentType::JSON).body(request).dispatch();
    assert_eq!(response.status(), Status::Ok);
    let response: serde_json::Value = serde_json::from_str(&response.into_string().unwrap()).unwrap();
    let bytes = response["artifact_json"].as_str().unwrap().as_bytes();
    let actual_hash = ring::digest::digest(&ring::digest::SHA256, bytes);
    assert_eq!(response["artifact_sha256"], actual_hash.as_ref().iter().map(|byte| format!("{byte:02x}")).collect::<String>());
    assert_eq!(response["timesheet"]["approved_duration_seconds"], 18_000);
    assert!(response["artifact_json"].as_str().unwrap().find("window_title").is_none());

    let outbound = client.post("/api/0/egress/preview")
        .header(host.clone()).header(auth.clone()).header(ContentType::JSON)
        .body(serde_json::json!({
            "schema_version": 1,
            "destination_id": "client-api",
            "purpose_id": "freelancer-timesheet-v1",
            "retention_id": "client-session",
            "payload": response["timesheet"].clone(),
        }).to_string())
        .dispatch();
    assert_eq!(outbound.status(), Status::ServiceUnavailable);

    let tainted = r#"{"schema_version":1,"project_alias":"project-9af31c","date":"2026-09-23","approved_duration_seconds":18000,"user_note":null,"window_title":"private marker"}"#;
    let rejected = client.post("/api/0/freelancer/timesheet/preview")
        .header(host).header(auth).header(ContentType::JSON).body(tainted).dispatch();
    assert_eq!(rejected.status(), Status::UnprocessableEntity);
}
