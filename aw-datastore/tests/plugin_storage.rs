use aw_datastore::Datastore;
use aw_models::{
    PluginCapabilitiesV1, PluginManifestV1, PluginStorageCapabilityV1,
    PluginStorageIntentV1,
};
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

fn manifest(quota_bytes: u64) -> PluginManifestV1 {
    PluginManifestV1 {
        schema_version: 1,
        plugin_id: "sample-plugin".into(),
        version: "1.0.0".into(),
        publisher_key_id: "publisher-01".into(),
        display_name: "Sample".into(),
        description: String::new(),
        capabilities: PluginCapabilitiesV1 {
            storage: Some(PluginStorageCapabilityV1 { quota_bytes, encrypted: true }),
            ..PluginCapabilitiesV1::default()
        },
    }
}

#[test]
fn plugin_storage_is_encrypted_namespaced_and_quota_updates_are_atomic() {
    let path = std::env::temp_dir().join(format!(
        "peak-plugin-storage-{}-{}.db",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos(),
    ));
    let store = Datastore::open_encrypted(path.to_string_lossy().into_owned(), "plugin-storage-test-key-".repeat(3)).unwrap();
    let grant = manifest(16);

    store.apply_plugin_storage_intents(&grant, &[PluginStorageIntentV1 {
        key: "theme".into(), value: Some(json!("dark")),
    }]).unwrap();
    assert_eq!(store.get_plugin_storage(&grant).unwrap()["theme"], json!("dark"));
    let other_publisher = PluginManifestV1 { publisher_key_id: "publisher-02".into(), ..grant.clone() };
    assert!(store.get_plugin_storage(&other_publisher).unwrap().is_empty());
    let too_large = [
        PluginStorageIntentV1 { key: "theme".into(), value: Some(json!("light")) },
        PluginStorageIntentV1 { key: "lang".into(), value: Some(json!("en")) },
    ];
    assert!(store.apply_plugin_storage_intents(&grant, &too_large).is_err());
    assert_eq!(store.get_plugin_storage(&grant).unwrap(), std::collections::BTreeMap::from([
        ("theme".to_owned(), json!("dark")),
    ]));
    store.apply_plugin_storage_intents(&grant, &[PluginStorageIntentV1 {
        key: "theme".into(), value: None,
    }]).unwrap();
    assert!(store.get_plugin_storage(&grant).unwrap().is_empty());
    store.apply_plugin_storage_intents(&grant, &[PluginStorageIntentV1 {
        key: "theme".into(), value: Some(json!("dark")),
    }]).unwrap();
    store.delete_plugin_storage(&grant).unwrap();
    assert!(store.get_plugin_storage(&grant).unwrap().is_empty());

    store.lock().unwrap();
    std::fs::remove_file(path).unwrap();
}

#[test]
fn plugin_storage_rejects_plaintext_vaults_and_missing_storage_grants() {
    let store = Datastore::new_in_memory(false);
    let grant = manifest(128);
    assert!(store.get_plugin_storage(&grant).is_err());
    assert!(store.apply_plugin_storage_intents(&grant, &[PluginStorageIntentV1 {
        key: "theme".into(), value: Some(json!("dark")),
    }]).is_err());

    let no_storage = PluginManifestV1 { capabilities: PluginCapabilitiesV1::default(), ..grant };
    let encrypted = Datastore::open_encrypted(":memory:".into(), "plugin-storage-memory-key-".repeat(3)).unwrap();
    assert!(encrypted.get_plugin_storage(&no_storage).is_err());
    assert!(encrypted.apply_plugin_storage_intents(&no_storage, &[]).is_err());
}
