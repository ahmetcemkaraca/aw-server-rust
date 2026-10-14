#![cfg(any(feature = "encryption", feature = "encryption-vendored"))]
#[path = "support/backup_provider.rs"]
mod fixture;
use aw_datastore::Datastore;
use aw_server::sync_control::SyncControl;
use aw_sync_e2ee::{FolderSyncObjectStoreV1, SyncObjectStoreV1};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};
fn context(store: &Datastore) -> String {
    store.get_sync_policy_context().unwrap().context_id
}
fn call(
    store: &Datastore,
    command: &str,
    request: &Value,
    accepted: Option<bool>,
) -> Result<Value, String> {
    let mut args = json!({"requestJson":serde_json::to_string(request).unwrap()});
    if let Some(accepted) = accepted {
        args["userAccepted"] = json!(accepted);
    }
    SyncControl::new().invoke(store, command, args)
}
fn request(store: &Datastore) -> Value {
    json!({"schema_version":1,"source_id":"local","context_id":context(store)})
}
#[test]
fn backup_delete_local_preview_is_readonly_acceptance_is_explicit_and_current_is_protected() {
    let (store, _, original) = fixture::source();
    let control = SyncControl::new();
    control
        .invoke(&store, "create_current_sync_snapshot", json!({}))
        .unwrap();
    let mut raw = request(&store);
    let catalogue = call(&store, "list_sync_backups", &raw, None).unwrap();
    raw["selection"] = original["selection"].clone();
    assert!(catalogue["versions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v["selection"] == raw["selection"]));
    let current = store.load_sync_snapshot().unwrap();
    let preview = call(&store, "preview_sync_backup_delete", &raw, None).unwrap();
    assert_eq!(preview["object_count"], raw["selection"]["object_count"]);
    assert!(store
        .export_sync_backup_deletions(context(&store))
        .unwrap()
        .is_empty());
    assert!(call(&store, "delete_selected_sync_backup", &raw, None).is_err());
    assert!(call(&store, "delete_selected_sync_backup", &raw, Some(false)).is_err());
    let result = call(&store, "delete_selected_sync_backup", &raw, Some(true)).unwrap();
    assert_eq!(result["deleted"], raw["selection"]["object_count"]);
    assert_eq!(result["context_id"], context(&store));
    assert_eq!(store.load_sync_snapshot().unwrap(), current);
    let known = call(&store, "list_sync_backups", &request(&store), None).unwrap();
    assert!(known["versions"]
        .as_array()
        .unwrap()
        .iter()
        .all(|v| v["selection"]["snapshot_id"] != raw["selection"]["snapshot_id"]));
    assert!(call(&store, "export_selected_sync_backup", &raw, None).is_err());
    let id = URL_SAFE_NO_PAD.encode(current.as_ref().unwrap().snapshot_id);
    let fresh = known["versions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["snapshot_id"] == id)
        .unwrap();
    raw["selection"] = fresh["selection"].clone();
    assert!(call(&store, "preview_sync_backup_delete", &raw, None).is_err());
    store.close();
}
#[test]
fn backup_delete_folder_acceptance_keeps_local_copy_and_sealed_absence_retry() {
    let (store, kit, _) = fixture::source();
    let saved = store.load_sync_snapshot().unwrap().unwrap();
    SyncControl::new()
        .invoke(&store, "create_current_sync_snapshot", json!({}))
        .unwrap();
    let root = std::env::temp_dir().join(format!(
        "peak-delete-control-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let folder = FolderSyncObjectStoreV1::open(&root).unwrap();
    for object in &saved.envelopes {
        folder.put_if_absent(object).unwrap();
    }
    let raw = json!({"schema_version":1,"source_id":"folder","context_id":context(&store),"folder_path":root,"recovery":{"kit":kit["kit"],"phrase":kit["recovery_phrase"]}});
    let catalogue = call(&store, "list_sync_backups", &raw, None).unwrap();
    let mut raw = raw;
    raw["selection"] = catalogue["versions"][0]["selection"].clone();
    call(&store, "preview_sync_backup_delete", &raw, None).unwrap();
    let result = call(&store, "delete_selected_sync_backup", &raw, Some(true)).unwrap();
    assert_eq!(result["deleted"], saved.envelopes.len());
    for object in &saved.envelopes {
        assert_eq!(
            store.get_sync_object(object.object_id.clone()).unwrap(),
            Some(object.clone())
        );
        assert!(folder.get(&object.object_id).unwrap().is_none());
    }
    let mut discovery = raw.clone();
    discovery.as_object_mut().unwrap().remove("selection");
    let retained = call(&store, "list_sync_backups", &discovery, None).unwrap();
    let row = retained["versions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["snapshot_id"] == raw["selection"]["snapshot_id"])
        .unwrap();
    assert_eq!(row["status"], "forgotten");
    assert!(row["selection"].is_null());
    assert_eq!(row["deletion_selection"], raw["selection"]);
    let retry = call(&store, "delete_selected_sync_backup", &raw, Some(true)).unwrap();
    assert_eq!(retry["deleted"], 0);
    assert_eq!(retry["absent"], saved.envelopes.len());
    assert!(retry["durable"].as_bool().unwrap());
    for object in &saved.envelopes {
        assert!(folder.put_if_absent(object).is_err());
        std::fs::write(
            root.join(format!("{}.json", object.object_id)),
            serde_json::to_vec(object).unwrap(),
        )
        .unwrap();
    }
    assert!(call(&store, "export_selected_sync_backup", &raw, None).is_err());
    drop(folder);
    std::fs::remove_dir_all(root).unwrap();
    store.close();
}
#[test]
fn backup_delete_controls_refuse_changed_context_shapes_and_unaccepted_requests_without_new_state()
{
    let (store, _, _) = fixture::source();
    let mut raw = request(&store);
    raw["context_id"] = json!("0".repeat(64));
    assert!(call(&store, "preview_sync_backup_delete", &raw, None).is_err());
    assert!(call(&store, "delete_selected_sync_backup", &raw, Some(true)).is_err());
    let mut raw = request(&store);
    raw["unknown"] = json!(true);
    assert!(call(&store, "preview_sync_backup_delete", &raw, None).is_err());
    let raw = request(&store);
    assert!(SyncControl::new()
        .invoke(
            &store,
            "preview_sync_backup_delete",
            json!({"requestJson":serde_json::to_string(&raw).unwrap(),"userAccepted":true})
        )
        .is_err());
    assert!(SyncControl::new()
        .invoke(
            &store,
            "delete_selected_sync_backup",
            json!({"requestJson":"[]","userAccepted":true})
        )
        .is_err());
    assert!(store
        .export_sync_backup_deletions(context(&store))
        .unwrap()
        .is_empty());
    store.close();
    let plain = Datastore::new_in_memory(false);
    assert!(call(&plain, "preview_sync_backup_delete", &raw, None).is_err());
    plain.close();
}

#[cfg(unix)]
#[test]
fn backup_delete_folder_refresh_counts_marked_active_and_quarantined_remaining_copies() {
    let (store, kit, selected) = fixture::multipart_source();
    let saved = store.load_sync_snapshot().unwrap().unwrap();
    SyncControl::new()
        .invoke(&store, "create_current_sync_snapshot", json!({}))
        .unwrap();
    let opened = aw_sync_e2ee::open_recovery_kit(
        &serde_json::from_value(kit["kit"].clone()).unwrap(),
        kit["recovery_phrase"].as_str().unwrap(),
    )
    .unwrap();
    let key =
        aw_sync_e2ee::unwrap_vault_data_key(&opened.account_root_key, &opened.wrapped_vault_key)
            .unwrap();
    let encrypted = aw_sync_e2ee::EncryptedSyncSnapshotV1 {
        schema_version: 1,
        snapshot_id: selected["selection"]["snapshot_id"]
            .as_str()
            .unwrap()
            .into(),
        envelopes: saved.envelopes.clone(),
    };
    let proof = aw_sync_e2ee::SnapshotDeletionProofV1::authenticate(&key, &encrypted).unwrap();
    let fact = proof.fact().clone();
    let root = std::env::temp_dir().join(format!(
        "peak-folder-observation-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let folder = FolderSyncObjectStoreV1::open(&root).unwrap();
    for o in &saved.envelopes {
        folder.put_if_absent(o).unwrap();
    }
    store
        .record_sync_backup_deletion_intent(context(&store), proof, chrono::Utc::now().to_rfc3339())
        .unwrap();
    let io = aw_server::backup::FolderBackupDeletionV1::open_existing(&root).unwrap();
    io.persist_intent(
        &key,
        &aw_sync_e2ee::SnapshotDeletionProofV1::authenticate(&key, &encrypted).unwrap(),
    )
    .unwrap();
    let raw = json!({"schema_version":1,"source_id":"folder","context_id":context(&store),"folder_path":root,"recovery":{"kit":kit["kit"],"phrase":kit["recovery_phrase"]}});
    let page = call(&store, "list_sync_backups", &raw, None).unwrap();
    assert_eq!(page["versions"][0]["observed_object_count"], 2);
    let quarantine = root.join(format!(".peakactivity-delete-{}", fact.bundle_sha256));
    std::fs::create_dir(&quarantine).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&quarantine, std::fs::Permissions::from_mode(0o700)).unwrap();
    let leaf = format!("{}.json", saved.envelopes[1].object_id);
    std::fs::rename(root.join(&leaf), quarantine.join(&leaf)).unwrap();
    std::fs::remove_file(root.join(format!("{}.json", saved.envelopes[0].object_id))).unwrap();
    let page = call(&store, "list_sync_backups", &raw, None).unwrap();
    assert_eq!(page["versions"][0]["observed_object_count"], 1);
    std::fs::write(
        root.join(&leaf),
        serde_json::to_vec(&saved.envelopes[1]).unwrap(),
    )
    .unwrap();
    assert!(call(&store, "list_sync_backups", &raw, None).is_err());
    drop(io);
    drop(folder);
    store.close();
    std::fs::remove_dir_all(root).unwrap();
}
