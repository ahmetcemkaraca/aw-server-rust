use aw_datastore::{Datastore, SyncKeyMaterial};
use aw_server::sync_control::SyncControl;
use aw_sync_e2ee::{create_vault_data_key, generate_account_root_key, EncryptedSyncSnapshotV1};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};

fn source() -> (Datastore, SyncControl) {
    let store = Datastore::open_encrypted(":memory:".into(), "a".repeat(64)).unwrap();
    let control = SyncControl::new();
    control
        .invoke(&store, "create_local_sync_identity", json!({}))
        .unwrap();
    let root = generate_account_root_key().unwrap();
    let (_, wrapped) =
        create_vault_data_key(&root, &URL_SAFE_NO_PAD.encode([0x71; 16]), 1).unwrap();
    store
        .install_sync_key_material(&SyncKeyMaterial::new(
            root.secret_for_storage(),
            [0x71; 16],
            1,
            URL_SAFE_NO_PAD
                .decode(wrapped.nonce)
                .unwrap()
                .try_into()
                .unwrap(),
            URL_SAFE_NO_PAD
                .decode(wrapped.ciphertext)
                .unwrap()
                .try_into()
                .unwrap(),
        ))
        .unwrap();
    store
        .confirm_sync_recovery_saved("2026-10-14T12:00:00Z".into())
        .unwrap();
    store.set_key_value("settings.theme", "\"dark\"").unwrap();
    store
        .create_bucket(&aw_models::Bucket {
            bid: None,
            id: "backup-source".into(),
            _type: "app".into(),
            client: "fixture-client".into(),
            hostname: "fixture-host".into(),
            created: None,
            data: Default::default(),
            metadata: Default::default(),
            last_updated: None,
            events: Some(aw_models::TryVec::new(vec![aw_models::Event::new(
                chrono::DateTime::parse_from_rfc3339("2026-10-14T12:00:00Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
                chrono::Duration::seconds(2),
                json!({"app":"fixture-app"}).as_object().unwrap().clone(),
            )])),
        })
        .unwrap();
    control
        .invoke(&store, "create_current_sync_snapshot", json!({}))
        .unwrap();
    (store, control)
}

fn request(store: &Datastore) -> Value {
    json!({"schema_version":1,"source_id":"local","context_id":store.get_sync_policy_context().unwrap().context_id})
}

fn invoke(
    control: &SyncControl,
    store: &Datastore,
    name: &str,
    request: Value,
) -> Result<Value, String> {
    control.invoke(
        store,
        name,
        json!({"requestJson":serde_json::to_string(&request).unwrap()}),
    )
}

#[test]
fn backup_folder_selection_binds_private_source_and_rechecks_ciphertext_without_writes() {
    use aw_sync_e2ee::SyncObjectStoreV1;
    let (store, control) = source();
    let snapshot = store.load_sync_snapshot().unwrap().unwrap();
    let path = std::env::temp_dir().join(format!(
        "peak-backup-folder-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let objects = aw_sync_e2ee::FolderSyncObjectStoreV1::open(&path).unwrap();
    for object in &snapshot.envelopes {
        objects.put_if_absent(object).unwrap();
    }
    let before =
        std::fs::read(path.join(format!("{}.json", snapshot.envelopes[0].object_id))).unwrap();
    let mut args = request(&store);
    args["source_id"] = json!("folder");
    args["folder_path"] = json!(path.to_str().unwrap());
    let result = invoke(&control, &store, "list_sync_backups", args.clone()).unwrap();
    assert_eq!(result["versions"][0]["status"], "authenticated");
    assert!(result["source_id"].as_str().unwrap().starts_with("folder-"));
    assert!(!serde_json::to_string(&result)
        .unwrap()
        .contains(path.to_str().unwrap()));
    args["selection"] = result["versions"][0]["selection"].clone();
    let text = invoke(
        &control,
        &store,
        "export_selected_sync_backup",
        args.clone(),
    )
    .unwrap();
    let exported: EncryptedSyncSnapshotV1 = serde_json::from_str(text.as_str().unwrap()).unwrap();
    assert_eq!(
        exported.snapshot_id,
        URL_SAFE_NO_PAD.encode(snapshot.snapshot_id)
    );
    assert_eq!(
        std::fs::read_dir(&path).unwrap().count(),
        snapshot.envelopes.len()
    );
    assert_eq!(
        std::fs::read(path.join(format!("{}.json", snapshot.envelopes[0].object_id))).unwrap(),
        before
    );
    let other = path.with_extension("other");
    let other_objects = aw_sync_e2ee::FolderSyncObjectStoreV1::open(&other).unwrap();
    for object in &snapshot.envelopes {
        other_objects.put_if_absent(object).unwrap();
    }
    args["folder_path"] = json!(other.to_str().unwrap());
    assert!(invoke(
        &control,
        &store,
        "export_selected_sync_backup",
        args.clone()
    )
    .is_err());
    args["folder_path"] = json!(path.to_str().unwrap());
    std::fs::remove_file(path.join(format!("{}.json", snapshot.envelopes[0].object_id))).unwrap();
    assert!(invoke(&control, &store, "export_selected_sync_backup", args).is_err());
    store.close();
    std::fs::remove_dir_all(path).unwrap();
    std::fs::remove_dir_all(other).unwrap();
}

#[test]
fn backup_common_context_requires_empty_arguments_and_real_unlocked_encrypted_worker() {
    let (store, control) = source();
    let context = control
        .invoke(&store, "get_sync_backup_context", json!({}))
        .unwrap();
    assert_eq!(context["context_id"], request(&store)["context_id"]);
    assert!(control
        .invoke(
            &store,
            "get_sync_backup_context",
            json!({"unexpected":true})
        )
        .is_err());
    store.close();
    assert!(control
        .invoke(&store, "get_sync_backup_context", json!({}))
        .is_err());
    let plain = Datastore::new_in_memory(false);
    assert!(control
        .invoke(&plain, "get_sync_backup_context", json!({}))
        .is_err());
    plain.close();
}

#[test]
fn backup_closed_records_reject_positional_arrays_instead_of_accepting_serde_struct_sequences() {
    let (store, control) = source();
    let context = request(&store)["context_id"].clone();
    let positional = json!([1, "local", context, null, null, null]);
    assert!(invoke(&control, &store, "list_sync_backups", positional).is_err());
    let listed = invoke(&control, &store, "list_sync_backups", request(&store)).unwrap();
    let selection = &listed["versions"][0]["selection"];
    let mut args = request(&store);
    args["selection"] = json!([
        selection["schema_version"],
        selection["source_id"],
        selection["vault_id"],
        selection["key_epoch"],
        selection["snapshot_id"],
        selection["object_count"],
        selection["bundle_sha256"]
    ]);
    assert!(invoke(&control, &store, "export_selected_sync_backup", args).is_err());
    let mut args = request(&store);
    args["recovery"] = json!([{}, "phrase"]);
    assert!(invoke(&control, &store, "list_sync_backups", args).is_err());
    store.close();
}

#[test]
fn backup_selected_folder_restore_uses_native_raw_input_and_existing_clean_target_acceptance() {
    use aw_sync_e2ee::SyncObjectStoreV1;
    let (source, control) = source();
    let mut later = source
        .get_events("backup-source", None, None, None)
        .unwrap()[0]
        .clone();
    later.id = None;
    later.timestamp += chrono::Duration::hours(1);
    source.insert_events("backup-source", &[later]).unwrap();
    source
        .delete_events_by_id("backup-source".into(), vec![1])
        .unwrap();
    control
        .invoke(&source, "create_current_sync_snapshot", json!({}))
        .unwrap();
    assert_eq!(
        source
            .get_events("backup-source", None, None, None)
            .unwrap()[0]
            .id,
        Some(2)
    );

    let material = source.load_sync_key_material().unwrap().unwrap();
    let root = aw_sync_e2ee::AccountRootKeyV1::from_bytes(zeroize::Zeroizing::new(
        *material.account_root_key(),
    ));
    let (_, wrapped) =
        aw_sync_e2ee::create_vault_data_key(&root, &URL_SAFE_NO_PAD.encode([0x71; 16]), 1).unwrap();
    let wrapped = aw_sync_e2ee::WrappedVaultDataKeyV1 {
        nonce: URL_SAFE_NO_PAD.encode(material.wrapped_nonce()),
        ciphertext: URL_SAFE_NO_PAD.encode(material.wrapped_ciphertext()),
        ..wrapped
    };
    let (phrase, kit) = aw_sync_e2ee::create_recovery_kit(&root, &wrapped).unwrap();
    let snapshot = source.load_sync_snapshot().unwrap().unwrap();
    let path = std::env::temp_dir().join(format!(
        "peak-selected-restore-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let folder = aw_sync_e2ee::FolderSyncObjectStoreV1::open(&path).unwrap();
    for object in &snapshot.envelopes {
        folder.put_if_absent(object).unwrap();
    }
    let target = Datastore::open_encrypted(":memory:".into(), "b".repeat(64)).unwrap();
    target.enable_capture_policy().unwrap();
    target.pause_capture().unwrap();
    let mut args = request(&target);
    args["source_id"] = json!("folder");
    args["folder_path"] = json!(path.to_str().unwrap());
    args["recovery"] = json!({"kit":kit,"phrase":phrase});
    let catalogue = invoke(&control, &target, "list_sync_backups", args.clone()).unwrap();
    args["selection"] = catalogue["versions"][0]["selection"].clone();
    let preview = invoke(
        &control,
        &target,
        "preview_selected_sync_backup_restore",
        args.clone(),
    )
    .unwrap();
    let preview: Value = serde_json::from_str(preview.as_str().unwrap()).unwrap();
    assert_eq!(
        preview["snapshot_id"],
        URL_SAFE_NO_PAD.encode(snapshot.snapshot_id)
    );
    assert!(target.get_buckets().unwrap().is_empty());
    assert!(target.load_sync_key_material().unwrap().is_none());
    let key = aw_sync_e2ee::unwrap_vault_data_key(&root, &wrapped).unwrap();
    let encrypted = EncryptedSyncSnapshotV1 {
        schema_version: 1,
        snapshot_id: URL_SAFE_NO_PAD.encode(snapshot.snapshot_id),
        envelopes: snapshot.envelopes.clone(),
    };
    let payload = aw_server::sync_control::decrypt_recovery_snapshot(&key, &encrypted).unwrap();
    let identity = aw_sync_e2ee::generate_device_identity().unwrap();
    assert!(target
        .restore_sync_recovery_data_with_context(
            payload.activity,
            material.clone(),
            snapshot.clone(),
            payload.sync,
            aw_datastore::SyncDeviceIdentity::new(
                *identity.device_id_bytes(),
                identity.secret_for_storage(),
                identity.signing_seed_for_storage()
            ),
            None,
            Some(source.get_sync_policy_context().unwrap().context_id)
        )
        .is_err());
    assert!(target.get_buckets().unwrap().is_empty());
    assert!(target.load_sync_key_material().unwrap().is_none());
    assert!(control
        .invoke(
            &target,
            "restore_selected_sync_backup",
            json!({"requestJson":args.to_string(),"userAccepted":false})
        )
        .is_err());
    let restored = control
        .invoke(
            &target,
            "restore_selected_sync_backup",
            json!({"requestJson":args.to_string(),"userAccepted":true}),
        )
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(restored.as_str().unwrap()).unwrap()["snapshot_id"],
        preview["snapshot_id"]
    );
    assert_eq!(
        target
            .get_events("backup-source", None, None, None)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        target
            .get_events("backup-source", None, None, None)
            .unwrap()[0]
            .id,
        Some(2)
    );
    assert!(!target.capture_policy().unwrap().recording);
    assert!(!target.sync_enabled().unwrap());
    assert!(control
        .invoke(
            &target,
            "restore_selected_sync_backup",
            json!({"requestJson":args.to_string(),"userAccepted":true})
        )
        .is_err());
    source.close();
    target.close();
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn backup_catalogue_retains_versions_and_selected_export_never_creates_or_changes_current() {
    let (store, control) = source();
    let first = control
        .invoke(&store, "export_sync_snapshot", json!({}))
        .unwrap();
    store.set_key_value("settings.theme", "\"light\"").unwrap();
    control
        .invoke(&store, "create_current_sync_snapshot", json!({}))
        .unwrap();
    let current = store.load_sync_snapshot().unwrap().unwrap();
    let history = store.list_sync_object_history(1000).unwrap();
    let result = invoke(&control, &store, "list_sync_backups", request(&store)).unwrap();
    assert_eq!(result["versions"].as_array().unwrap().len(), 2);
    let old = result["versions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["snapshot_id"] == first["snapshot_id"])
        .unwrap();
    assert_eq!(old["status"], "authenticated");
    assert_eq!(old["key_epoch"], "1");
    assert_eq!(old["query_start"], "2026-10-14T12:00:00+00:00");
    assert_eq!(old["event_count"], 1);
    let mut selected = request(&store);
    selected["selection"] = old["selection"].clone();
    let text = invoke(&control, &store, "export_selected_sync_backup", selected).unwrap();
    let exported: Value = serde_json::from_str(text.as_str().unwrap()).unwrap();
    assert_eq!(exported, first);
    assert_eq!(store.load_sync_snapshot().unwrap().unwrap(), current);
    assert_eq!(store.list_sync_object_history(1000).unwrap(), history);
    assert_eq!(store.get_key_value("settings.theme").unwrap(), "\"light\"");
    assert!(!store.sync_enabled().unwrap());
    store.close();
}

#[test]
fn backup_context_changes_after_lock_reopen_and_old_selection_cannot_reach_new_worker() {
    let (store, control) = source();
    let mut old_request = request(&store);
    let result = invoke(&control, &store, "list_sync_backups", old_request.clone()).unwrap();
    old_request["selection"] = result["versions"][0]["selection"].clone();
    store.close();
    assert!(invoke(
        &control,
        &store,
        "export_selected_sync_backup",
        old_request.clone()
    )
    .is_err());
    store
        .unlock_encrypted(":memory:".into(), "a".repeat(64))
        .unwrap();
    assert_ne!(request(&store)["context_id"], old_request["context_id"]);
    assert!(invoke(&control, &store, "export_selected_sync_backup", old_request).is_err());
    assert!(store.load_sync_key_material().unwrap().is_none());
    store.close();
}

#[test]
fn backup_read_lease_uses_captured_worker_channel_while_vault_lock_writer_is_waiting() {
    let (store, _) = source();
    let lease = store.egress_lease().unwrap();
    let source = lease.sync_backup_source().unwrap();
    let other = store.clone();
    let (started, ready) = std::sync::mpsc::channel();
    let (finished, done) = std::sync::mpsc::channel();
    let writer = std::thread::spawn(move || {
        started.send(()).unwrap();
        other.close();
        finished.send(()).unwrap();
    });
    ready
        .recv_timeout(std::time::Duration::from_secs(1))
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(10));
    assert!(done.try_recv().is_err());
    assert_eq!(
        lease.sync_backup_source().unwrap().context_id,
        source.context_id
    );
    let page = lease
        .sync_backup_objects(
            URL_SAFE_NO_PAD.encode(source.material.as_ref().unwrap().vault_id()),
            None,
            64,
        )
        .unwrap();
    assert!(!page.objects.is_empty());
    assert_eq!(
        lease
            .sync_backup_object(page.objects[0].object_id.clone())
            .unwrap(),
        Some(page.objects[0].clone())
    );
    drop(lease);
    done.recv_timeout(std::time::Duration::from_secs(1))
        .unwrap();
    writer.join().unwrap();
    assert!(store.is_locked());
}

#[test]
fn backup_catalogue_rejects_plaintext_workers_and_conflicting_current_retained_objects() {
    let plain = Datastore::new_in_memory(false);
    let control = SyncControl::new();
    assert!(control.invoke(&plain,"list_sync_backups",json!({"requestJson":format!(r#"{{"schema_version":1,"source_id":"local","context_id":"{}"}}"#,"0".repeat(64))})).is_err());
    plain.close();
    let (store, control) = source();
    let mut snapshot = store.load_sync_snapshot().unwrap().unwrap();
    let mut ciphertext = URL_SAFE_NO_PAD
        .decode(&snapshot.envelopes[0].ciphertext)
        .unwrap();
    *ciphertext.last_mut().unwrap() ^= 1;
    snapshot.envelopes[0].ciphertext = URL_SAFE_NO_PAD.encode(ciphertext);
    store
        .save_sync_snapshot(store.load_sync_key_material().unwrap().unwrap(), snapshot)
        .unwrap();
    assert!(invoke(&control, &store, "list_sync_backups", request(&store)).is_err());
    store.close();
}

#[test]
fn backup_catalogue_without_keys_does_not_generate_or_install_any() {
    let store = Datastore::open_encrypted(":memory:".into(), "b".repeat(64)).unwrap();
    let control = SyncControl::new();
    let result = invoke(&control, &store, "list_sync_backups", request(&store)).unwrap();
    assert_eq!(result["requires_recovery_kit"], true);
    assert_eq!(result["versions"], json!([]));
    assert!(store.load_sync_key_material().unwrap().is_none());
    assert!(store.load_sync_device_identity().unwrap().is_none());
    assert!(store.load_sync_snapshot().unwrap().is_none());
    store.close();
}

#[test]
fn backup_selection_and_closed_raw_requests_reject_forged_or_rounded_metadata() {
    let (store, control) = source();
    let result = invoke(&control, &store, "list_sync_backups", request(&store)).unwrap();
    let reference = result["versions"][0]["selection"].clone();
    for (field, value) in [
        ("bundle_sha256", json!("0".repeat(64))),
        ("source_id", json!("relay")),
        ("key_epoch", json!("01")),
        ("key_epoch", json!(1)),
        ("object_count", json!(2)),
        ("unknown", json!(true)),
    ] {
        let mut selected = request(&store);
        selected["selection"] = reference.clone();
        selected["selection"][field] = value;
        assert!(
            invoke(&control, &store, "export_selected_sync_backup", selected).is_err(),
            "{field}"
        );
    }
    let context = store.get_sync_policy_context().unwrap().context_id;
    for raw in [
        format!(
            r#"{{"schema_version":1,"schema_version":1,"source_id":"local","context_id":"{context}"}}"#
        ),
        format!(
            r#"{{"schema_version":1,"source_id":"local","context_id":"{context}","extra":null}}"#
        ),
    ] {
        assert!(control
            .invoke(&store, "list_sync_backups", json!({"requestJson":raw}))
            .is_err());
    }
    let mut stale = request(&store);
    stale["context_id"] = json!("0".repeat(64));
    assert!(invoke(&control, &store, "list_sync_backups", stale).is_err());
    store.close();
}

#[test]
fn backup_catalogue_authenticates_whole_recovery_payload_before_offering_selection() {
    let (store, control) = source();
    let material = store.load_sync_key_material().unwrap().unwrap();
    let root = aw_sync_e2ee::AccountRootKeyV1::from_bytes(zeroize::Zeroizing::new(
        *material.account_root_key(),
    ));
    let key = aw_sync_e2ee::unwrap_vault_data_key(
        &root,
        &aw_sync_e2ee::WrappedVaultDataKeyV1 {
            schema_version: 1,
            vault_id: URL_SAFE_NO_PAD.encode(material.vault_id()),
            key_epoch: material.key_epoch(),
            nonce: URL_SAFE_NO_PAD.encode(material.wrapped_nonce()),
            ciphertext: URL_SAFE_NO_PAD.encode(material.wrapped_ciphertext()),
        },
    )
    .unwrap();
    let invalid =
        aw_sync_e2ee::encrypt_snapshot(&key, b"authenticated-but-not-a-recovery-record").unwrap();
    for envelope in &invalid.envelopes {
        store
            .put_sync_object(envelope.clone(), "2026-10-14T12:00:00Z".into())
            .unwrap();
    }
    let complete = aw_sync_e2ee::encrypt_snapshot(&key, &vec![7; 1_100_000]).unwrap();
    store
        .put_sync_object(complete.envelopes[0].clone(), "2026-10-14T12:00:00Z".into())
        .unwrap();
    let result = invoke(&control, &store, "list_sync_backups", request(&store)).unwrap();
    let rows = result["versions"].as_array().unwrap();
    let row = |id: &str| rows.iter().find(|row| row["snapshot_id"] == id).unwrap();
    assert_eq!(row(&invalid.snapshot_id)["status"], "invalid_recovery");
    assert!(row(&invalid.snapshot_id)["selection"].is_null());
    assert_eq!(row(&complete.snapshot_id)["status"], "incomplete");
    assert!(row(&complete.snapshot_id)["selection"].is_null());
    store.close();
}

#[test]
fn backup_historical_kit_authenticates_populated_source_without_replacing_current_keys() {
    let (store, control) = source();
    let material = store.load_sync_key_material().unwrap().unwrap();
    let root = aw_sync_e2ee::AccountRootKeyV1::from_bytes(zeroize::Zeroizing::new(
        *material.account_root_key(),
    ));
    let (phrase, kit) = aw_sync_e2ee::create_recovery_kit(
        &root,
        &aw_sync_e2ee::WrappedVaultDataKeyV1 {
            schema_version: 1,
            vault_id: URL_SAFE_NO_PAD.encode(material.vault_id()),
            key_epoch: material.key_epoch(),
            nonce: URL_SAFE_NO_PAD.encode(material.wrapped_nonce()),
            ciphertext: URL_SAFE_NO_PAD.encode(material.wrapped_ciphertext()),
        },
    )
    .unwrap();
    let old: EncryptedSyncSnapshotV1 = serde_json::from_value(
        control
            .invoke(&store, "export_sync_snapshot", json!({}))
            .unwrap(),
    )
    .unwrap();
    control
        .invoke(&store, "rotate_sync_keys", json!({}))
        .unwrap();
    let current = store.load_sync_key_material().unwrap().unwrap();
    let mut historical = request(&store);
    historical["recovery"] = json!({"kit":kit,"phrase":phrase});
    let listed = invoke(&control, &store, "list_sync_backups", historical.clone()).unwrap();
    let old_row = listed["versions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["snapshot_id"] == old.snapshot_id)
        .unwrap();
    assert_eq!(old_row["status"], "authenticated");
    historical["selection"] = old_row["selection"].clone();
    let exported = invoke(
        &control,
        &store,
        "export_selected_sync_backup",
        historical.clone(),
    )
    .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(exported.as_str().unwrap()).unwrap(),
        serde_json::to_value(old).unwrap()
    );
    let after = store.load_sync_key_material().unwrap().unwrap();
    assert_eq!(after.key_epoch(), current.key_epoch());
    assert_eq!(after.account_root_key(), current.account_root_key());
    assert!(!store.sync_enabled().unwrap());
    historical.as_object_mut().unwrap().remove("selection");
    historical["recovery"]["phrase"] = json!("incorrect phrase");
    assert!(invoke(&control, &store, "list_sync_backups", historical).is_err());
    store.close();
}
#[test]
fn backup_semantically_invalid_continuity_is_not_selectable_even_with_genuine_ciphertext() {
    let (store, control) = source();
    let material = store.load_sync_key_material().unwrap().unwrap();
    let root = aw_sync_e2ee::AccountRootKeyV1::from_bytes(zeroize::Zeroizing::new(
        *material.account_root_key(),
    ));
    let key = aw_sync_e2ee::unwrap_vault_data_key(
        &root,
        &aw_sync_e2ee::WrappedVaultDataKeyV1 {
            schema_version: 1,
            vault_id: URL_SAFE_NO_PAD.encode(material.vault_id()),
            key_epoch: material.key_epoch(),
            nonce: URL_SAFE_NO_PAD.encode(material.wrapped_nonce()),
            ciphertext: URL_SAFE_NO_PAD.encode(material.wrapped_ciphertext()),
        },
    )
    .unwrap();
    let snapshot = store.load_sync_snapshot().unwrap().unwrap();
    let current = EncryptedSyncSnapshotV1 {
        schema_version: 1,
        snapshot_id: URL_SAFE_NO_PAD.encode(snapshot.snapshot_id),
        envelopes: snapshot.envelopes,
    };
    let original: Value =
        serde_json::from_slice(&aw_sync_e2ee::decrypt_snapshot(&key, &current).unwrap()).unwrap();
    let mut invalids = Vec::new();
    for mutation in 0..6 {
        let mut payload = original.clone();
        match mutation {
            0 => payload["sync"]["counters"] = json!([{ "device_id":vec![4;16],"last_counter":0}]),
            1 => {
                let first = payload["sync"]["trusted_devices"][0].clone();
                payload["sync"]["trusted_devices"]
                    .as_array_mut()
                    .unwrap()
                    .push(first);
            }
            2 => {
                payload["sync"]["bucket_mappings"][0]["descriptor"]["client"] =
                    json!("wrong-client")
            }
            3 => payload["sync"]["event_mappings"][0]["origin_event_id"] = json!(0),
            4 => {
                payload["sync"]["stream_heads"] =
                    json!([{ "device_id":vec![4;16],"revision":0,"head_hash":vec![0;32]}])
            }
            _ => {
                let peer = payload["sync"]["trusted_devices"][0]["device_id"].clone();
                payload["sync"]["counters"] = json!([{ "device_id":peer,"last_counter":1}]);
                payload["sync"]["operations"] = json!([{ "device_id":peer,"counter":1,"key_epoch":1,"operation_json":"{}","content_hash":vec![0;32]}]);
            }
        }
        let invalid =
            aw_sync_e2ee::encrypt_snapshot(&key, &serde_json::to_vec(&payload).unwrap()).unwrap();
        for object in &invalid.envelopes {
            store
                .put_sync_object(object.clone(), "2026-10-14T12:00:00Z".into())
                .unwrap();
        }
        invalids.push(invalid.snapshot_id);
    }
    let listed = invoke(&control, &store, "list_sync_backups", request(&store)).unwrap();
    for invalid in invalids {
        let row = listed["versions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["snapshot_id"] == invalid)
            .unwrap();
        assert_eq!(row["status"], "invalid_recovery");
        assert!(row["selection"].is_null());
    }
    store.close();
}
