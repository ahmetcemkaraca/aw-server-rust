use aw_models::{
    AIAccessModeV1, AIAuthenticationV1, AIEndpointProfileV1, AIEndpointProtocolV1, AIProviderV1,
    AIInsightHistoryV1, AIInsightV1, AIRequestFeatureV1, AIResultV1, AISettingsV1, AIUserRequestV1, AIDestinationTypeV1,
    SignedAIProviderRegistryV1,
};
use serde_json::json;

fn report_aggregate() -> serde_json::Value {
    json!({
        "method_id":"local-work-report", "method_version":1, "break_time_seconds":300,
        "date_range":{"start_date":"2026-09-01","end_date":"2026-09-07"},
        "daily":[{"date":"2026-09-01","duration_seconds":3600,"session_count":2,"average_session_seconds":1800.0}],
        "coverage":{"requested_periods":7,"periods_with_data":1,"limitation":"complete"},
        "weekly":[], "monthly":[], "comparison":null
    })
}

fn profile() -> AIEndpointProfileV1 {
    AIEndpointProfileV1 {
        profile_id: "profile_01".into(),
        display_name: "My endpoint".into(),
        origin: "https://ai.example.net".into(),
        endpoint_path: "/v1/chat/completions".into(),
        protocol: AIEndpointProtocolV1::OpenAiChatCompletionsV1,
        authentication: AIAuthenticationV1::Bearer,
        model_id: "model-v1".into(),
        destination_type: AIDestinationTypeV1::Remote,
        region_note: "EU (user supplied)".into(),
        retention_note: "Unknown".into(),
        training_note: "Unknown".into(),
        cost_note: None,
        credential_ref: Some("credential_01".into()),
        resolved_addresses: vec!["8.8.8.8".into()],
    }
}

#[test]
fn clean_ai_settings_default_to_off() {
    let settings = AISettingsV1::default();
    assert_eq!(settings.mode, AIAccessModeV1::Off);
    assert_eq!(settings.revision, 0);
    assert!(settings.active_connection_id.is_none());
    assert!(settings.profiles.is_empty());
}

#[test]
fn endpoint_profile_rejects_credentials_in_url_and_non_https_origins() {
    let mut value = profile();
    assert!(value.validate().is_ok());
    value.origin = "https://user:pass@ai.example.net".into();
    assert!(value.validate().is_err());
    value.origin = "http://ai.example.net".into();
    assert!(value.validate().is_err());
    value.origin = "https://ai.example.net/path?token=x".into();
    assert!(value.validate().is_err());
}

#[test]
fn endpoint_auth_method_requires_an_opaque_secret_reference_for_bearer_only() {
    let mut value = profile();
    value.authentication = AIAuthenticationV1::None;
    assert!(value.validate().is_err());
    value.authentication = AIAuthenticationV1::Bearer;
    value.credential_ref = None;
    assert!(value.validate().is_err());
}

#[test]
fn profile_serialization_keeps_only_an_opaque_credential_reference() {
    let value = profile();
    let serialized = serde_json::to_string(&value).unwrap();
    assert!(serialized.contains("credential_01"));
    assert!(!serialized.contains("api_key"));
    assert!(!serialized.contains("credential_value"));
    assert!(!serialized.contains("secret"));
}

#[test]
fn user_request_accepts_aggregates_but_rejects_raw_events_and_secrets() {
    let base = AIUserRequestV1 {
        schema_version: 1,
        profile_id: "profile_01".into(),
        feature: AIRequestFeatureV1::ReportExplanation,
        question: "Explain this summary".into(),
        aggregate: report_aggregate(),
    };
    assert!(base.validate().is_ok());
    let mut multiline = base.clone();
    multiline.question = "Explain this summary\nUse one short paragraph".into();
    assert!(multiline.validate().is_ok());
    let mut raw_events = base.clone();
    raw_events.aggregate.as_object_mut().unwrap().insert("events".into(), json!([{"timestamp":"secret"}]));
    assert!(raw_events.validate().is_err());
    let mut credential = base;
    credential.aggregate.as_object_mut().unwrap().insert("notes".into(), json!({"label":"private-value"}));
    assert!(credential.validate().is_err());
}

#[test]
fn user_request_rejects_health_emotion_and_worker_scoring_purposes() {
    let mut request = AIUserRequestV1 {
        schema_version: 1,
        profile_id: "profile_01".into(),
        feature: AIRequestFeatureV1::QuestionAnswer,
        question: "Summarize my work week".into(),
        aggregate: report_aggregate(),
    };
    assert!(request.validate().is_ok());
    for question in [
        "infer my mental health from these hours",
        "score this employee's productivity",
        "rank workers by performance",
        "guess my mood from the report",
    ] {
        request.question = question.into();
        assert!(request.validate().is_err(), "{question}");
    }
}

#[test]
fn ai_aggregates_have_feature_specific_closed_shapes() {
    let mut category_request = AIUserRequestV1 {
        schema_version: 1,
        profile_id: "profile_01".into(),
        feature: AIRequestFeatureV1::CategorySuggestion,
        question: "Suggest category mappings".into(),
        aggregate: json!({
            "categories":["Design"],
            "projects":[{"project_alias":"p-01","display_label":"Client work"}],
            "existing_mappings":[]
        }),
    };
    assert!(category_request.validate().is_ok());
    category_request.aggregate.as_object_mut().unwrap().insert("notes".into(), json!(["unreviewed"]));
    assert!(category_request.validate().is_err());

    let timesheet_request = AIUserRequestV1 {
        schema_version: 1,
        profile_id: "profile_01".into(),
        feature: AIRequestFeatureV1::FreelancerDraft,
        question: "Draft neutral wording".into(),
        aggregate: json!({"project_alias":"p-01","date":"2026-09-01","approved_duration_seconds":3600}),
    };
    assert!(timesheet_request.validate().is_ok());
    let mut invalid_timesheet = timesheet_request;
    invalid_timesheet.aggregate["approved_duration_seconds"] = json!(86_401);
    assert!(invalid_timesheet.validate().is_err());

    let mut invalid_report = AIUserRequestV1 {
        schema_version: 1,
        profile_id: "profile_01".into(),
        feature: AIRequestFeatureV1::ReportExplanation,
        question: "Explain this report".into(),
        aggregate: report_aggregate(),
    };
    invalid_report.aggregate["coverage"]["private_note"] = json!("must not pass");
    assert!(invalid_report.validate().is_err());
}

#[test]
fn unknown_profile_fields_are_rejected() {
    let mut value = serde_json::to_value(profile()).unwrap();
    value.as_object_mut().unwrap().insert("api_key".into(), json!("must-not-parse"));
    assert!(serde_json::from_value::<AIEndpointProfileV1>(value).is_err());
}

#[test]
fn shared_ai_request_vector_matches_the_rust_contract() {
    let vector: serde_json::Value = serde_json::from_str(include_str!("../../test-vectors/ai-request-v1.json")).unwrap();
    let profile: AIEndpointProfileV1 = serde_json::from_value(vector["valid_profile"].clone()).unwrap();
    profile.validate().unwrap();
    let request: AIUserRequestV1 = serde_json::from_value(vector["valid_request"].clone()).unwrap();
    request.validate().unwrap();
    for invalid in vector["invalid_requests"].as_array().unwrap() {
        let request: AIUserRequestV1 = serde_json::from_value(invalid.clone()).unwrap();
        assert!(request.validate().is_err());
    }
}

#[test]
fn signed_provider_registry_requires_a_cap_and_unique_provider_ids() {
    let provider = AIProviderV1 {
        provider_id: "synthetic-provider".into(),
        display_name: "Synthetic provider".into(),
        egress_destination_id: "peak-ai-provider".into(),
        egress_purpose_id: "ai.peak".into(),
        model_id: "model-v1".into(),
        model_version: "2026-09".into(),
        region: "region-test".into(),
        retention_id: "retention-test".into(),
        retention_disclosure: "Synthetic test disclosure".into(),
        training_disclosure: "Synthetic test disclosure".into(),
        subprocessors: vec!["Synthetic subprocessor".into()],
        currency_code: "USD".into(),
        input_price_micros_per_1k: 100,
        output_price_micros_per_1k: 200,
        monthly_cap_micros: 10_000,
    };
    let registry = SignedAIProviderRegistryV1 {
        schema_version: 1,
        version: 1,
        signer_key_id: "test-key".into(),
        providers: vec![provider.clone()],
        signature: vec![0; 64],
    };
    registry.validate().unwrap();
    let mut duplicate = registry.clone();
    duplicate.providers.push(provider.clone());
    assert!(duplicate.validate().is_err());
    let mut uncapped = registry;
    uncapped.providers[0].monthly_cap_micros = 0;
    assert!(uncapped.validate().is_err());
}

#[test]
fn ai_result_requires_a_non_off_source_label_and_bounded_text() {
    let mut result = AIResultV1 {
        schema_version: 1,
        source_mode: AIAccessModeV1::CustomEndpoint,
        profile_label: "My endpoint".into(),
        model_id: "model-v1".into(),
        text: "Synthetic response".into(),
    };
    assert!(result.validate().is_ok());
    result.source_mode = AIAccessModeV1::Off;
    assert!(result.validate().is_err());
    result.source_mode = AIAccessModeV1::PeakAi;
    result.text = "x".repeat(aw_models::AI_MAX_RESULT_BYTES_V1 + 1);
    assert!(result.validate().is_err());
}

#[test]
fn insight_history_is_opt_in_metadata_and_contains_no_prompt_or_aggregate() {
    let history = AIInsightHistoryV1 {
        schema_version: 1,
        revision: 2,
        insights: vec![AIInsightV1 {
            insight_id: "insight_01".into(),
            created_at: "2026-09-24T12:00:00Z".into(),
            source_mode: AIAccessModeV1::CustomEndpoint,
            profile_label: "My endpoint".into(),
            model_id: "model-v1".into(),
            feature: AIRequestFeatureV1::ReportExplanation,
            text: "Synthetic answer".into(),
        }],
    };
    history.validate().unwrap();
    let serialized = serde_json::to_value(history).unwrap();
    let insight = &serialized["insights"][0];
    assert!(insight.get("question").is_none());
    assert!(insight.get("aggregate").is_none());
    assert!(insight.get("payload").is_none());
}
