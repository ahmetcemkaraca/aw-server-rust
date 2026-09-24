use aw_datastore::Datastore;
use aw_models::{
    Bucket, BucketMetadata, EgressDestinationStatusV1, EgressDestinationV1,
    EgressPolicyBundleV1, EgressPurposeV1, EgressUserPolicyV1, Event, PluginAIIntentV1,
    PluginCapabilitiesV1, PluginDataClassV1, PluginDestructiveActionV1,
    PluginDestructiveCapabilityV1, PluginDestructiveIntentV1, PluginInvocationOutputV1,
    PluginManifestV1, PluginNetworkCapabilityV1, PluginNetworkIntentV1,
    PluginPayloadClassV1, PluginReadCapabilityV1, PluginStorageCapabilityV1,
    PluginStorageIntentV1, PluginUISurfaceV1, PluginUIOutputV1, SignedEgressPolicyBundleV1,
    PluginWriteCapabilityV1, PluginWriteIntentV1, TryVec, AIRequestFeatureV1,
    validate_plugin_output_v1,
};
use aw_egress::{policy_bundle_signing_bytes, verify_and_activate, EgressProxy, EgressTransport};
use aw_server::plugin_host::{apply_plugin_output, prepare_plugin_actions, prepare_plugin_input};
use chrono::{Duration, Utc};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::json;
use std::collections::HashMap;
use std::sync::{atomic::{AtomicUsize, Ordering}, Arc};

#[derive(Clone)]
struct CountingEgress(Arc<AtomicUsize>);

impl EgressTransport for CountingEgress {
    fn send(
        &self,
        _: &EgressDestinationV1,
        _: &EgressPurposeV1,
        _: &[u8],
    ) -> Result<(), aw_models::EgressReasonCodeV1> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

fn manifest() -> PluginManifestV1 {
    PluginManifestV1 {
        schema_version: 1,
        plugin_id: "sample-plugin".into(),
        version: "1.0.0".into(),
        publisher_key_id: "publisher-01".into(),
        display_name: "Sample".into(),
        description: String::new(),
        capabilities: PluginCapabilitiesV1 {
            read: vec![PluginReadCapabilityV1 {
                data_class: PluginDataClassV1::Raw,
                bucket_type: "app".into(),
                event_type: "activity".into(),
                time_window_days: 7,
                fields: vec!["/app".into()],
            }],
            storage: Some(PluginStorageCapabilityV1 { quota_bytes: 1024, encrypted: true }),
            ..PluginCapabilitiesV1::default()
        },
    }
}

fn signed_policy() -> aw_egress::VerifiedPolicyV1 {
    let mut signed = SignedEgressPolicyBundleV1 {
        schema_version: 1,
        signer_key_id: "plugin-host-policy-key".into(),
        bundle: EgressPolicyBundleV1 {
            schema_version: 1,
            version: 1,
            hard_deny_version: 1,
            destinations: vec![EgressDestinationV1 {
                id: "vendor-api".into(),
                status: EgressDestinationStatusV1::Available,
                https_origin: Some("https://api.example.net".into()),
                allowed_purposes: vec!["plugin.export".into()],
            }],
            purposes: vec![EgressPurposeV1 {
                id: "plugin.export".into(), destination_id: "vendor-api".into(),
                endpoint_path: "/v1/export".into(), retention_id: "bounded".into(),
                retention_disclosure: "Approved aggregate only".into(),
                allowed_fields: vec!["/aggregate".into()],
            }],
            organization_rules: Vec::new(),
        },
        signature: Vec::new(),
    };
    let keypair = Ed25519KeyPair::from_seed_unchecked(&[0x91; 32]).unwrap();
    signed.signature = keypair.sign(&policy_bundle_signing_bytes(&signed).unwrap()).as_ref().to_vec();
    verify_and_activate(
        &signed,
        &EgressUserPolicyV1 { schema_version: 1, user_rules: vec![], safe_zone_patterns: vec![], after_hours: None },
        &HashMap::from([("plugin-host-policy-key".into(), keypair.public_key().as_ref().to_vec())]),
        None,
    ).unwrap()
}

#[test]
fn plugin_host_filters_input_and_applies_only_manifest_bound_storage_intents() {
    let store = Datastore::open_encrypted(":memory:".into(), "plugin-host-test-key-".repeat(3)).unwrap();
    let manifest = manifest();
    let output = validate_plugin_output_v1(&manifest, PluginInvocationOutputV1 {
        schema_version: 1,
        storage: vec![PluginStorageIntentV1 { key: "theme".into(), value: Some(json!("dark")) }],
        ..PluginInvocationOutputV1::default()
    }, None).unwrap();
    apply_plugin_output(&store, &manifest, output.clone()).unwrap();
    store.create_bucket(&Bucket {
        bid: None,
        id: "plugin-host-bucket".into(),
        _type: "app".into(),
        client: "test".into(),
        hostname: "host".into(),
        created: None,
        data: Default::default(),
        metadata: BucketMetadata::default(),
        events: Some(TryVec::new(vec![Event::new(
            Utc::now() - Duration::hours(1), Duration::seconds(1),
            json!({"app":"editor","title":"private"}).as_object().unwrap().clone(),
        )])),
        last_updated: None,
    }).unwrap();

    let input = prepare_plugin_input(&store, &manifest, Utc::now()).unwrap();
    let exposed: serde_json::Value = serde_json::from_slice(input.serialized()).unwrap();
    assert_eq!(exposed["storage"]["theme"], "dark");
    assert_eq!(exposed["records"][0]["payload"], json!({"app":"editor"}));
    assert!(exposed["records"][0].get("captured_at").is_none());

    let other = PluginManifestV1 { plugin_id: "other-plugin".into(), ..manifest.clone() };
    assert!(apply_plugin_output(&store, &other, output).is_err());
}

#[test]
fn plugin_host_rejects_plaintext_vaults() {
    let store = Datastore::new_in_memory(false);
    assert!(prepare_plugin_input(&store, &manifest(), Utc::now()).is_err());
}

#[test]
fn aggregate_plugin_input_contains_only_bounded_host_metrics() {
    let store = Datastore::open_encrypted(":memory:".into(), "plugin-host-aggregate-test-".repeat(3)).unwrap();
    let mut grant = manifest();
    grant.capabilities.read = vec![PluginReadCapabilityV1 {
        data_class: PluginDataClassV1::Aggregate,
        bucket_type: "app".into(),
        event_type: "activity".into(),
        time_window_days: 1,
        fields: vec!["/event_count".into(), "/total_duration_seconds".into()],
    }];
    let now = Utc::now();
    store.create_bucket(&Bucket {
        bid: None,
        id: "aggregate-source".into(),
        _type: "app".into(),
        client: "test".into(),
        hostname: "private-host".into(),
        created: None,
        data: Default::default(),
        metadata: BucketMetadata::default(),
        events: Some(TryVec::new(vec![
            Event::new(now - Duration::days(2), Duration::seconds(20), json!({"app":"old"}).as_object().unwrap().clone()),
            Event::new(now - Duration::hours(1), Duration::seconds(5), json!({"app":"recent","title":"private"}).as_object().unwrap().clone()),
        ])),
        last_updated: None,
    }).unwrap();

    let input = prepare_plugin_input(&store, &grant, now).unwrap();
    let exposed: serde_json::Value = serde_json::from_slice(input.serialized()).unwrap();
    assert_eq!(exposed["records"].as_array().unwrap().len(), 1);
    assert_eq!(exposed["records"][0]["data_class"], "aggregate");
    assert_eq!(exposed["records"][0]["time_window_days"], 1);
    assert_eq!(exposed["records"][0]["payload"], json!({"event_count":1,"total_duration_seconds":5}));
    assert!(exposed.to_string().find("private-host").is_none());
    assert!(exposed.to_string().find("private").is_none());
}

#[test]
fn plugin_network_and_ai_intents_return_existing_approval_inputs_without_sending() {
    let store = Datastore::open_encrypted(":memory:".into(), "plugin-host-policy-key-".repeat(3)).unwrap();
    store.set_egress_kill_switch(false).unwrap();
    let mut value = manifest();
    value.capabilities.network.push(PluginNetworkCapabilityV1 {
        domain: "api.example.net".into(), destination_id: "vendor-api".into(),
        purpose_id: "plugin.export".into(), payload_class: PluginPayloadClassV1::Aggregate,
    });
    value.capabilities.ai_features.push(AIRequestFeatureV1::FreelancerDraft);
    value.capabilities.ui.push(PluginUISurfaceV1::SettingsPanel);
    value.capabilities.destructive.push(PluginDestructiveCapabilityV1 {
        action: PluginDestructiveActionV1::Export, confirmation_required: true,
    });
    let output = validate_plugin_output_v1(&value, PluginInvocationOutputV1 {
        schema_version: 1,
        ui: vec![PluginUIOutputV1 { surface: PluginUISurfaceV1::SettingsPanel, title: "Summary".into(), text: "Ready".into() }],
        network: vec![PluginNetworkIntentV1 {
            domain: "api.example.net".into(), destination_id: "vendor-api".into(),
            purpose_id: "plugin.export".into(), payload_class: PluginPayloadClassV1::Aggregate,
            payload: json!({"aggregate":{"hours":1}}),
        }],
        ai: vec![PluginAIIntentV1 {
            feature: AIRequestFeatureV1::FreelancerDraft,
            question: "Draft neutral wording".into(),
            aggregate: json!({"project_alias":"p-01","date":"2026-09-01","approved_duration_seconds":3600}),
        }],
        destructive: vec![PluginDestructiveIntentV1 {
            action: PluginDestructiveActionV1::Export, resource_id: "report-01".into(),
        }],
        ..PluginInvocationOutputV1::default()
    }, Some("profile_01")).unwrap();
    let requests = Arc::new(AtomicUsize::new(0));

    let actions = prepare_plugin_actions(
        &store, &EgressProxy::with_transport(store.clone(), CountingEgress(requests.clone())), &signed_policy(), &value, output,
        Some("profile_01"), Utc::now(), 0,
    ).unwrap();

    assert_eq!(actions.ui.len(), 1);
    assert_eq!(actions.network_previews.len(), 1);
    assert_eq!(actions.ai_requests.len(), 1);
    assert_eq!(actions.destructive_confirmations.len(), 1);
    assert_eq!(actions.ai_requests[0].profile_id, "profile_01");
    assert!(actions.network_previews[0].sanitized_payload.is_some());
    assert_eq!(actions.destructive_confirmations[0].action, PluginDestructiveActionV1::Export);
    assert_eq!(requests.load(Ordering::Relaxed), 0);
}

#[test]
fn plugin_host_prepares_registered_writes_without_persisting_them() {
    let store = Datastore::open_encrypted(":memory:".into(), "plugin-host-write-test-key-".repeat(3)).unwrap();
    let mut manifest = manifest();
    manifest.capabilities.write.push(PluginWriteCapabilityV1 {
        event_type: "plugin.annotation".into(), schema_id: "annotation-v1".into(),
    });
    let output = validate_plugin_output_v1(&manifest, PluginInvocationOutputV1 {
        schema_version: 1,
        writes: vec![PluginWriteIntentV1 {
            event_type: "plugin.annotation".into(), schema_id: "annotation-v1".into(),
            payload: json!({"title":"Review","body":"Check totals"}),
        }],
        ..PluginInvocationOutputV1::default()
    }, None).unwrap();
    let actions = prepare_plugin_actions(
        &store, &EgressProxy::new(store.clone()), &signed_policy(), &manifest, output,
        None, Utc::now(), 0,
    ).unwrap();
    assert_eq!(actions.writes.len(), 1);
    assert_eq!(actions.writes[0].payload, json!({"title":"Review","body":"Check totals"}));
    assert!(store.get_plugin_events(&manifest).unwrap().is_empty());
    assert!(store.get_buckets().unwrap().is_empty());
}
