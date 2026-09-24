use aw_datastore::Datastore;
use aw_models::{
    AIAccessModeV1, AIAuthenticationV1, AIEndpointProfileV1, AIEndpointProtocolV1,
    AIInsightV1, AIRequestFeatureV1, AISettingsV1, AIDestinationTypeV1,
};

fn profile() -> AIEndpointProfileV1 {
    AIEndpointProfileV1 {
        profile_id: "profile_01".into(),
        display_name: "Synthetic endpoint".into(),
        origin: "https://ai.example.invalid".into(),
        endpoint_path: "/v1/chat/completions".into(),
        protocol: AIEndpointProtocolV1::OpenAiChatCompletionsV1,
        authentication: AIAuthenticationV1::Bearer,
        model_id: "synthetic-model-v1".into(),
        destination_type: AIDestinationTypeV1::Remote,
        region_note: "Not verified".into(),
        retention_note: "Not verified".into(),
        training_note: "Not verified".into(),
        cost_note: None,
        credential_ref: Some("credential_01".into()),
        resolved_addresses: vec!["8.8.8.8".into()],
    }
}

fn encrypted_store() -> Datastore {
    Datastore::open_encrypted(
        ":memory:".into(),
        "epic11-ai-profile-test-key-".repeat(3),
    ).unwrap()
}

#[test]
fn ai_profile_settings_default_off_and_use_revision_cas() {
    let store = encrypted_store();
    let current = store.get_ai_settings().unwrap();
    assert_eq!(current, AISettingsV1::default());
    let mut next = current.clone();
    next.mode = aw_models::AIAccessModeV1::CustomEndpoint;
    next.active_connection_id = Some("profile_01".into());
    next.profiles.push(profile());
    let saved = store.compare_and_set_ai_settings(0, next.clone()).unwrap().unwrap();
    assert_eq!(saved.revision, 1);
    assert!(store.compare_and_set_ai_settings(0, current).unwrap().is_none());
    assert_eq!(store.get_ai_settings().unwrap(), saved);
}

#[test]
fn generic_settings_cannot_read_or_write_ai_profile_state() {
    let store = Datastore::new_in_memory(true);
    assert!(store.get_key_value("settings.ai.v1").is_err());
    assert!(!store.get_key_values("settings.%").unwrap().contains_key("settings.ai.v1"));
    assert!(store.set_key_value("settings.ai.v1", "{}").is_err());
    assert!(store.delete_key_value("settings.ai.v1").is_err());
}

#[test]
fn ai_settings_require_an_encrypted_datastore_and_valid_profile() {
    let plaintext = Datastore::new_in_memory(false);
    assert!(plaintext.get_ai_settings().is_err());

    let encrypted = encrypted_store();
    let mut invalid = AISettingsV1::default();
    invalid.profiles.push(profile());
    invalid.profiles[0].origin = "http://ai.example.invalid".into();
    assert!(encrypted.compare_and_set_ai_settings(0, invalid).is_err());
}

#[test]
fn insight_history_is_opt_in_encrypted_and_individually_deletable() {
    let store = encrypted_store();
    let insight = AIInsightV1 {
        insight_id: "insight_01".into(),
        created_at: "2026-09-24T12:00:00Z".into(),
        source_mode: AIAccessModeV1::CustomEndpoint,
        profile_label: "My endpoint".into(),
        model_id: "model-v1".into(),
        feature: AIRequestFeatureV1::ReportExplanation,
        text: "Synthetic explanation".into(),
    };
    let saved = store.save_ai_insight(insight).unwrap();
    assert_eq!(saved.insights.len(), 1);
    assert!(store.get_key_value("settings.ai.history.v1").is_err());
    assert!(!store.get_key_values("settings.%").unwrap().contains_key("settings.ai.history.v1"));
    let deleted = store.delete_ai_insight("insight_01").unwrap().unwrap();
    assert!(deleted.insights.is_empty());
}
