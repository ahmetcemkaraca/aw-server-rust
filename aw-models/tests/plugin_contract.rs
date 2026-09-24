use aw_models::{
    PluginCapabilitiesV1, PluginDataClassV1, PluginManifestV1, PluginNetworkCapabilityV1,
    PluginReadCapabilityV1, PluginWriteCapabilityV1, PluginPayloadClassV1, PluginUISurfaceV1,
    SignedPluginPackageV1, PluginDestructiveCapabilityV1, PluginDestructiveActionV1,
    PluginStorageCapabilityV1, PluginBackgroundCapabilityV1, PluginCapabilityDiffV1,
    PluginInvocationInputV1, PluginInputRecordV1, PluginInvocationOutputV1,
    PluginNetworkIntentV1, PluginAIIntentV1, AIRequestFeatureV1,
    validate_plugin_input_v1, validate_plugin_output_v1, plugin_capability_diff_v1,
};

fn manifest() -> PluginManifestV1 {
    PluginManifestV1 {
        schema_version: 1,
        plugin_id: "sample-plugin".into(),
        version: "1.0.0".into(),
        publisher_key_id: "publisher-01".into(),
        display_name: "Sample plugin".into(),
        description: "Synthetic contract fixture".into(),
        capabilities: PluginCapabilitiesV1::default(),
    }
}

#[test]
fn plugin_defaults_to_no_capabilities_and_rejects_unknown_fields() {
    let value = manifest();
    assert!(value.validate().is_ok());
    assert_eq!(value.capabilities, PluginCapabilitiesV1::default());
    let mut json = serde_json::to_value(value).unwrap();
    json["capabilities"]["raw_vault"] = serde_json::json!(true);
    assert!(serde_json::from_value::<PluginManifestV1>(json).is_err());
}

#[test]
fn plugin_capabilities_reject_wildcards_and_unconfirmed_destructive_actions() {
    let mut value = manifest();
    value.capabilities.read.push(PluginReadCapabilityV1 {
        data_class: PluginDataClassV1::Raw,
        bucket_type: "app".into(),
        event_type: "activity".into(),
        time_window_days: 7,
        fields: vec!["/*".into()],
    });
    assert!(value.validate().is_err());

    value.capabilities.read.clear();
    value.capabilities.destructive.push(PluginDestructiveCapabilityV1 {
        action: PluginDestructiveActionV1::Export,
        confirmation_required: false,
    });
    assert!(value.validate().is_err());
}

#[test]
fn plugin_network_is_exact_and_storage_must_be_encrypted() {
    let mut value = manifest();
    value.capabilities.network.push(PluginNetworkCapabilityV1 {
        domain: "*.example.net".into(),
        destination_id: "vendor-api".into(),
        purpose_id: "plugin.export".into(),
        payload_class: PluginPayloadClassV1::Aggregate,
    });
    assert!(value.validate().is_err());

    value.capabilities.network[0].domain = "api.example.net".into();
    value.capabilities.network[0].purpose_id = "ai.custom_endpoint".into();
    assert!(value.validate().is_err());
    value.capabilities.network[0].purpose_id = "plugin.export".into();
    value.capabilities.storage = Some(PluginStorageCapabilityV1 { quota_bytes: 1024, encrypted: false });
    assert!(value.validate().is_err());
    value.capabilities.storage.as_mut().unwrap().encrypted = true;
    value.capabilities.ui.push(PluginUISurfaceV1::WorkReport);
    value.capabilities.write.push(PluginWriteCapabilityV1 {
        event_type: "plugin.annotation".into(), schema_id: "annotation-v1".into(),
    });
    value.capabilities.background = Some(PluginBackgroundCapabilityV1 {
        minimum_interval_seconds: 900, maximum_runtime_ms: 1000, maximum_memory_bytes: 1_048_576,
    });
    value.capabilities.destructive.push(PluginDestructiveCapabilityV1 {
        action: PluginDestructiveActionV1::Send, confirmation_required: true,
    });
    assert!(value.validate().is_ok());
}

#[test]
fn capability_expansion_is_reported_as_new_consent() {
    let before = PluginCapabilitiesV1::default();
    let mut after = before.clone();
    after.network.push(PluginNetworkCapabilityV1 {
        domain: "api.example.net".into(), destination_id: "vendor-api".into(),
        purpose_id: "plugin.export".into(), payload_class: PluginPayloadClassV1::Aggregate,
    });
    let diff: PluginCapabilityDiffV1 = plugin_capability_diff_v1(&before, &after).unwrap();
    assert!(diff.requires_reconsent);
    assert_eq!(diff.added.len(), 1);
    assert!(diff.removed.is_empty());
}

#[test]
fn signed_package_shape_requires_sha256_and_a_full_signature() {
    let package = SignedPluginPackageV1 {
        schema_version: 1,
        manifest: manifest(),
        module_sha256: "a".repeat(64),
        signature: vec![0; 64],
    };
    assert!(package.validate().is_ok());
    let mut invalid = package;
    invalid.module_sha256 = "not-a-digest".into();
    assert!(invalid.validate().is_err());
}

#[test]
fn plugin_output_is_rechecked_against_capabilities_and_the_active_ai_profile() {
    let mut value = manifest();
    let network_output = PluginInvocationOutputV1 {
        schema_version: 1,
        network: vec![PluginNetworkIntentV1 {
            domain: "api.example.net".into(), destination_id: "vendor-api".into(),
            purpose_id: "plugin.export".into(), payload_class: PluginPayloadClassV1::Aggregate,
            payload: serde_json::json!({"aggregate":{}}),
        }],
        ..PluginInvocationOutputV1::default()
    };
    assert!(validate_plugin_output_v1(&value, network_output, None).is_err());

    value.capabilities.ai_features.push(AIRequestFeatureV1::FreelancerDraft);
    let ai_output = PluginInvocationOutputV1 {
        schema_version: 1,
        ai: vec![PluginAIIntentV1 {
            feature: AIRequestFeatureV1::FreelancerDraft,
            question: "Draft neutral wording".into(),
            aggregate: serde_json::json!({"project_alias":"p-01","date":"2026-09-01","approved_duration_seconds":3600}),
        }],
        ..PluginInvocationOutputV1::default()
    };
    assert!(validate_plugin_output_v1(&value, ai_output.clone(), None).is_err());
    assert!(validate_plugin_output_v1(&value, ai_output, Some("profile_01")).is_ok());
}

#[test]
fn plugin_write_intents_require_a_registered_closed_schema() {
    let mut value = manifest();
    value.capabilities.write.push(PluginWriteCapabilityV1 {
        event_type: "plugin.annotation".into(), schema_id: "annotation-v1".into(),
    });
    let valid = PluginInvocationOutputV1 {
        schema_version: 1,
        writes: vec![aw_models::PluginWriteIntentV1 {
            event_type: "plugin.annotation".into(), schema_id: "annotation-v1".into(),
            payload: serde_json::json!({"title":"Review","body":"Check totals"}),
        }],
        ..PluginInvocationOutputV1::default()
    };
    assert!(validate_plugin_output_v1(&value, valid, None).is_ok());
    let extra_field = PluginInvocationOutputV1 {
        schema_version: 1,
        writes: vec![aw_models::PluginWriteIntentV1 {
            event_type: "plugin.annotation".into(), schema_id: "annotation-v1".into(),
            payload: serde_json::json!({"title":"Review","body":"Check totals","path":"/private/file"}),
        }],
        ..PluginInvocationOutputV1::default()
    };
    assert!(validate_plugin_output_v1(&value, extra_field, None).is_err());

    value.capabilities.write[0].schema_id = "unknown-schema".into();
    let unsupported = PluginInvocationOutputV1 {
        schema_version: 1,
        writes: vec![aw_models::PluginWriteIntentV1 {
            event_type: "plugin.annotation".into(), schema_id: "unknown-schema".into(),
            payload: serde_json::json!({"title":"Review","body":"Check totals"}),
        }],
        ..PluginInvocationOutputV1::default()
    };
    assert!(validate_plugin_output_v1(&value, unsupported, None).is_err());
}

#[test]
fn validated_plugin_output_is_bound_to_its_manifest() {
    let value = manifest();
    let output = validate_plugin_output_v1(&value, PluginInvocationOutputV1 {
        schema_version: 1,
        ..PluginInvocationOutputV1::default()
    }, None).unwrap();
    assert!(output.is_for_manifest(&value));
    let other = PluginManifestV1 { plugin_id: "other-plugin".into(), ..value };
    assert!(!output.is_for_manifest(&other));
    let value = manifest();
    let other_publisher = PluginManifestV1 { publisher_key_id: "publisher-02".into(), ..value.clone() };
    let other_version = PluginManifestV1 { version: "1.0.1".into(), ..value.clone() };
    let output = validate_plugin_output_v1(&value, PluginInvocationOutputV1 {
        schema_version: 1,
        ..PluginInvocationOutputV1::default()
    }, None).unwrap();
    assert!(!output.is_for_manifest(&other_publisher));
    assert!(!output.is_for_manifest(&other_version));
}

#[test]
fn plugin_storage_deletes_do_not_consume_the_persistent_storage_quota() {
    let mut value = manifest();
    value.capabilities.storage = Some(PluginStorageCapabilityV1 { quota_bytes: 1, encrypted: true });
    let output = PluginInvocationOutputV1 {
        schema_version: 1,
        storage: vec![
            aw_models::PluginStorageIntentV1 { key: "old-preference".into(), value: None },
            aw_models::PluginStorageIntentV1 { key: "old-cache".into(), value: None },
        ],
        ..PluginInvocationOutputV1::default()
    };
    assert!(validate_plugin_output_v1(&value, output, None).is_ok());
}

#[test]
fn plugin_storage_quota_is_bounded_by_the_invocation_budget() {
    let mut value = manifest();
    value.capabilities.storage = Some(PluginStorageCapabilityV1 { quota_bytes: 1_048_577, encrypted: true });
    assert!(value.validate().is_err());
}

#[test]
fn aggregate_reads_are_limited_to_host_defined_metrics() {
    let mut value = manifest();
    value.capabilities.read.push(PluginReadCapabilityV1 {
        data_class: PluginDataClassV1::Aggregate,
        bucket_type: "app".into(),
        event_type: "activity".into(),
        time_window_days: 7,
        fields: vec!["/event_count".into(), "/total_duration_seconds".into()],
    });
    assert!(value.validate().is_ok());
    value.capabilities.read[0].fields = vec!["/title".into()];
    assert!(value.validate().is_err());
}

#[test]
fn aggregate_invocation_records_disclose_the_granted_window() {
    let mut value = manifest();
    value.capabilities.read = vec![1, 7].into_iter().map(|days| PluginReadCapabilityV1 {
        data_class: PluginDataClassV1::Aggregate,
        bucket_type: "app".into(),
        event_type: "activity".into(),
        time_window_days: days,
        fields: vec!["/event_count".into()],
    }).collect();
    let now = "2026-09-24T12:00:00Z";
    let input: PluginInvocationInputV1 = serde_json::from_value(serde_json::json!({
        "schema_version": 1,
        "records": [
            {"data_class":"aggregate","bucket_type":"app","event_type":"activity","captured_at":now,"time_window_days":1,"payload":{"event_count":2}},
            {"data_class":"aggregate","bucket_type":"app","event_type":"activity","captured_at":now,"time_window_days":7,"payload":{"event_count":9}}
        ],
        "storage": {}
    })).unwrap();
    let validated = validate_plugin_input_v1(&value, input, chrono::DateTime::parse_from_rfc3339(now).unwrap().with_timezone(&chrono::Utc)).unwrap();
    let exposed: serde_json::Value = serde_json::from_slice(validated.serialized()).unwrap();
    assert_eq!(exposed["records"][0]["time_window_days"], 1);
    assert_eq!(exposed["records"][1]["time_window_days"], 7);
}

#[test]
fn plugin_input_filters_fields_and_time_before_exposing_records() {
    let mut value = manifest();
    value.capabilities.read.push(PluginReadCapabilityV1 {
        data_class: PluginDataClassV1::Raw,
        bucket_type: "app".into(),
        event_type: "activity".into(),
        time_window_days: 7,
        fields: vec!["/app".into()],
    });
    let now = chrono::DateTime::parse_from_rfc3339("2026-09-24T12:00:00Z").unwrap().with_timezone(&chrono::Utc);
    let input = PluginInvocationInputV1 {
        schema_version: 1,
        records: vec![
            PluginInputRecordV1 {
                data_class: PluginDataClassV1::Raw,
                bucket_type: "app".into(), event_type: "activity".into(),
                captured_at: "2026-09-24T11:00:00Z".into(),
                time_window_days: None,
                payload: serde_json::json!({"app":"editor","title":"private window title"}),
            },
            PluginInputRecordV1 {
                data_class: PluginDataClassV1::Raw,
                bucket_type: "window".into(), event_type: "activity".into(),
                captured_at: "2026-09-24T11:00:00Z".into(),
                time_window_days: None,
                payload: serde_json::json!({"app":"other"}),
            },
        ],
        storage: Default::default(),
    };
    let validated = validate_plugin_input_v1(&value, input, now).unwrap();
    let exposed: serde_json::Value = serde_json::from_slice(validated.serialized()).unwrap();
    assert_eq!(exposed.pointer("/records/0/payload/app").and_then(serde_json::Value::as_str), Some("editor"));
    assert!(exposed.pointer("/records/0/payload/title").is_none());
    assert!(exposed.pointer("/records/0/captured_at").is_none());
    assert_eq!(exposed["records"].as_array().unwrap().len(), 1);
}

#[test]
fn plugin_input_exposes_only_its_own_encrypted_storage_values() {
    let mut value = manifest();
    value.capabilities.storage = Some(PluginStorageCapabilityV1 { quota_bytes: 1024, encrypted: true });
    let now = chrono::DateTime::parse_from_rfc3339("2026-09-24T12:00:00Z").unwrap().with_timezone(&chrono::Utc);
    let input: PluginInvocationInputV1 = serde_json::from_value(serde_json::json!({
        "schema_version": 1,
        "records": [],
        "storage": {"theme": "dark"}
    })).unwrap();

    let validated = validate_plugin_input_v1(&value, input.clone(), now).unwrap();
    let exposed: serde_json::Value = serde_json::from_slice(validated.serialized()).unwrap();
    assert_eq!(exposed["storage"]["theme"], "dark");
    value.capabilities.storage = None;
    assert!(validate_plugin_input_v1(&value, input, now).is_err());
}
