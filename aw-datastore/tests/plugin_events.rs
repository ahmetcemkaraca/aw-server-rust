use aw_datastore::Datastore;
use aw_models::{PluginCapabilitiesV1, PluginManifestV1, PluginWriteCapabilityV1, PluginWriteIntentV1};
use serde_json::json;

fn manifest() -> PluginManifestV1 {
    PluginManifestV1 {
        schema_version: 1,
        plugin_id: "sample-plugin".into(),
        version: "1.0.0".into(),
        publisher_key_id: "publisher-01".into(),
        display_name: "Sample".into(),
        description: String::new(),
        capabilities: PluginCapabilitiesV1 {
            write: vec![PluginWriteCapabilityV1 {
                event_type: "plugin.annotation".into(), schema_id: "annotation-v1".into(),
            }],
            ..PluginCapabilitiesV1::default()
        },
    }
}

#[test]
fn plugin_annotation_writes_are_schema_checked_encrypted_and_isolated_from_activity() {
    let store = Datastore::open_encrypted(":memory:".into(), "plugin-events-test-key-".repeat(3)).unwrap();
    let manifest = manifest();
    let write = PluginWriteIntentV1 {
        event_type: "plugin.annotation".into(),
        schema_id: "annotation-v1".into(),
        payload: json!({"title":"Review","body":"Check totals"}),
    };

    store.apply_plugin_write_intents(&manifest, &[write.clone()]).unwrap();

    let rows = store.get_plugin_events(&manifest).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].payload, write.payload);
    assert!(store.get_buckets().unwrap().is_empty());

    let unknown = PluginManifestV1 {
        capabilities: PluginCapabilitiesV1 {
            write: vec![PluginWriteCapabilityV1 {
                event_type: "plugin.annotation".into(), schema_id: "unknown-v1".into(),
            }],
            ..PluginCapabilitiesV1::default()
        },
        ..manifest.clone()
    };
    let invalid = PluginWriteIntentV1 { schema_id: "unknown-v1".into(), ..write };
    assert!(store.apply_plugin_write_intents(&unknown, &[invalid]).is_err());
    assert_eq!(store.get_plugin_events(&manifest).unwrap().len(), 1);
    store.delete_plugin_data(&manifest).unwrap();
    assert!(store.get_plugin_events(&manifest).unwrap().is_empty());
}

#[test]
fn plugin_annotation_storage_rejects_plaintext_datastores() {
    let store = Datastore::new_in_memory(false);
    assert!(store.apply_plugin_write_intents(&manifest(), &[]).is_err());
    assert!(store.get_plugin_events(&manifest()).is_err());
}
