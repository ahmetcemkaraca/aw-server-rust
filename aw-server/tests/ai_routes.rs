use aw_datastore::Datastore;
use aw_models::{AIAccessModeV1, AIAuthenticationV1, AIEndpointProfileV1, AIEndpointProtocolV1, AISettingsV1, AIDestinationTypeV1};
use aw_server::{
    config::AWConfig,
    endpoints::{self, AssetResolver, ServerState},
    sessions::{Scope, Sessions},
};
use rocket::http::{ContentType, Header, Status};
use rocket::local::blocking::Client;
use serde_json::{json, Value};

fn setup() -> (Client, String, String, String) {
    setup_with(Datastore::new_encrypted(":memory:".into(), "9a".repeat(32), false))
}

fn setup_with(store: Datastore) -> (Client, String, String, String) {
    let sessions = Sessions::new(5600, false);
    let admin = sessions.mint(Scope::Admin).unwrap();
    let read = sessions.mint(Scope::Read).unwrap();
    let ai_send = sessions.mint(Scope::AiSend).unwrap();
    let state = ServerState {
        datastore: store,
        asset_resolver: AssetResolver::new(None),
        device_id: "synthetic".into(),
    };
    let mut config = AWConfig::default();
    config.port = 5600;
    config.auth.sessions = Some(sessions);
    (Client::tracked(endpoints::build_rocket(state, config)).unwrap(), admin, read, ai_send)
}

fn auth(token: &str) -> Header<'static> {
    Header::new("Authorization", format!("Bearer {token}"))
}

fn profile() -> AIEndpointProfileV1 {
    AIEndpointProfileV1 {
        profile_id: "profile_01".into(),
        display_name: "Synthetic endpoint".into(),
        origin: "https://ai.example.invalid".into(),
        endpoint_path: "/v1/chat/completions".into(),
        protocol: AIEndpointProtocolV1::OpenAiChatCompletionsV1,
        authentication: AIAuthenticationV1::Bearer,
        model_id: "synthetic-model".into(),
        destination_type: AIDestinationTypeV1::Remote,
        region_note: "Not verified".into(),
        retention_note: "Not verified".into(),
        training_note: "Not verified".into(),
        cost_note: None,
        credential_ref: Some("credential_01".into()),
        resolved_addresses: Vec::new(),
    }
}

fn settings_json(settings: &AISettingsV1) -> Value {
    serde_json::to_value(settings).unwrap()
}

#[test]
fn ai_settings_start_off_are_revisioned_and_admin_scoped() {
    let (client, admin, read, _) = setup();
    let host = Header::new("Host", "localhost:5600");
    assert_eq!(client.get("/api/0/ai/settings").header(host.clone()).dispatch().status(), Status::Unauthorized);
    assert_eq!(client.get("/api/0/ai/settings").header(host.clone()).header(auth(&read)).dispatch().status(), Status::Forbidden);

    let response = client.get("/api/0/ai/settings").header(host.clone()).header(auth(&admin)).dispatch();
    assert_eq!(response.status(), Status::Ok);
    let initial: AISettingsV1 = serde_json::from_str(&response.into_string().unwrap()).unwrap();
    assert_eq!(initial.mode, AIAccessModeV1::Off);
    assert_eq!(initial.revision, 0);

    let mut saved = AISettingsV1::default();
    saved.profiles.push(profile());
    let update = json!({"expected_revision":0,"settings":settings_json(&saved)});
    let response = client.put("/api/0/ai/settings")
        .header(host.clone()).header(auth(&admin)).header(ContentType::JSON)
        .body(serde_json::to_string(&update).unwrap()).dispatch();
    assert_eq!(response.status(), Status::Ok);
    let saved: AISettingsV1 = serde_json::from_str(&response.into_string().unwrap()).unwrap();
    assert_eq!(saved.revision, 1);
    assert_eq!(saved.mode, AIAccessModeV1::Off);
    assert_eq!(saved.profiles[0].credential_ref.as_deref(), Some("credential_01"));

    let stale = json!({"expected_revision":0,"settings":settings_json(&AISettingsV1::default())});
    assert_eq!(client.put("/api/0/ai/settings")
        .header(host).header(auth(&admin)).header(ContentType::JSON)
        .body(serde_json::to_string(&stale).unwrap()).dispatch().status(), Status::Conflict);
}

#[test]
fn off_mode_and_admin_sessions_cannot_send_custom_endpoint_requests() {
    let (client, admin, _, ai_send) = setup();
    let host = Header::new("Host", "localhost:5600");
    let request = json!({
        "profile_id":"profile_01",
        "credential_ref":"credential_01",
        "preview_id":"missing-preview",
        "approval_id":"missing-approval"
    });
    assert_eq!(client.post("/api/0/ai/send")
        .header(host.clone()).header(auth(&admin)).header(ContentType::JSON)
        .header(Header::new("X-PeakActivity-AI-Credential", "synthetic-bearer-secret"))
        .body(serde_json::to_string(&request).unwrap()).dispatch().status(), Status::Forbidden);
    assert_ne!(client.post("/api/0/ai/send")
        .header(host).header(auth(&ai_send)).header(ContentType::JSON)
        .header(Header::new("X-PeakActivity-AI-Credential", "synthetic-bearer-secret"))
        .body(serde_json::to_string(&request).unwrap()).dispatch().status(), Status::Ok);
}

#[test]
fn result_history_is_saved_only_by_explicit_local_action_and_can_be_deleted() {
    let (client, admin, _, _) = setup();
    let host = Header::new("Host", "localhost:5600");
    let save = json!({
        "feature": "report_explanation",
        "result": {
            "schema_version": 1,
            "source_mode": "custom_endpoint",
            "profile_label": "Synthetic endpoint",
            "model_id": "synthetic-model",
            "text": "Synthetic result"
        }
    });
    let saved = client.post("/api/0/ai/history")
        .header(host.clone()).header(auth(&admin)).header(ContentType::JSON)
        .body(serde_json::to_string(&save).unwrap()).dispatch();
    let saved_status = saved.status();
    let saved_body = saved.into_string().unwrap_or_default();
    assert_eq!(saved_status, Status::Ok, "{saved_body}");
    let saved: Value = serde_json::from_str(&saved_body).unwrap();
    let insight = &saved["insights"][0];
    let insight_id = insight["insight_id"].as_str().unwrap();
    assert_eq!(insight["text"], "Synthetic result");
    assert!(insight.get("question").is_none());
    assert!(insight.get("aggregate").is_none());
    assert!(insight.get("credential").is_none());

    let deleted = client.delete(format!("/api/0/ai/history/{insight_id}"))
        .header(host.clone()).header(auth(&admin)).dispatch();
    assert_eq!(deleted.status(), Status::Ok);
    let history = client.get("/api/0/ai/history").header(host).header(auth(&admin)).dispatch();
    assert_eq!(history.status(), Status::Ok);
    let history: Value = serde_json::from_str(&history.into_string().unwrap()).unwrap();
    assert!(history["insights"].as_array().unwrap().is_empty());
}

#[test]
fn ai_settings_fail_closed_when_the_vault_is_locked_or_plaintext() {
    let host = Header::new("Host", "localhost:5600");
    let (locked, admin, _, _) = setup_with(Datastore::new_locked());
    assert_eq!(locked.get("/api/0/ai/settings")
        .header(host.clone()).header(auth(&admin)).dispatch().status(), Status::Locked);

    let (plaintext, admin, _, _) = setup_with(Datastore::new_in_memory(false));
    assert_eq!(plaintext.get("/api/0/ai/settings")
        .header(host).header(auth(&admin)).dispatch().status(), Status::ServiceUnavailable);
}
