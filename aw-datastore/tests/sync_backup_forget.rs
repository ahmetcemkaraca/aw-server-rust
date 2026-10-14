#![cfg(any(feature = "encryption", feature = "encryption-vendored"))]
use aw_datastore::{
    Datastore, SyncApplyBatchV1, SyncDeviceIdentity, SyncHeadCommitV1, SyncKeyMaterial,
    SyncSnapshotV1,
};
use aw_models::SyncOperationKindV1;
use aw_sync_e2ee::{
    assemble_backup_forget_operations, create_backup_forget_operations, create_vault_data_key,
    encrypt_snapshot, generate_account_root_key, generate_device_identity, SnapshotDeletionProofV1,
    SyncManifestV1,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
const AT: &str = "2026-10-14T12:00:00Z";
fn material() -> (SyncKeyMaterial, aw_sync_e2ee::VaultDataKeyV1) {
    let root = generate_account_root_key().unwrap();
    let (key, wrapped) = create_vault_data_key(&root, &URL_SAFE_NO_PAD.encode([1; 16]), 1).unwrap();
    let material = SyncKeyMaterial::new(
        root.secret_for_storage(),
        key.vault_id(),
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
    );
    (material, key)
}
fn identity(store: &Datastore) -> aw_sync_e2ee::DeviceIdentityV1 {
    let identity = generate_device_identity().unwrap();
    store
        .create_sync_device_identity(&SyncDeviceIdentity::new(
            *identity.device_id_bytes(),
            identity.secret_for_storage(),
            identity.signing_seed_for_storage(),
        ))
        .unwrap();
    identity
}
fn trust(store: &Datastore, signer: &aw_sync_e2ee::DeviceIdentityV1) {
    let public = signer.public_identity();
    store
        .record_sync_pairing(
            None,
            [7; 16],
            *signer.device_id_bytes(),
            URL_SAFE_NO_PAD
                .decode(public.x25519_public_key)
                .unwrap()
                .try_into()
                .unwrap(),
            URL_SAFE_NO_PAD
                .decode(public.ed25519_public_key)
                .unwrap()
                .try_into()
                .unwrap(),
            AT.into(),
        )
        .unwrap();
}
#[test]
fn backup_forget_queued_local_deletion_publishes_once_on_future_baseline_without_policy_effect() {
    let store = Datastore::open_encrypted(":memory:".into(), "a".repeat(64)).unwrap();
    let (material, key) = material();
    store.install_sync_key_material(&material).unwrap();
    let old = encrypt_snapshot(&key, b"known historical artifact").unwrap();
    for object in &old.envelopes {
        store.put_sync_object(object.clone(), AT.into()).unwrap();
    }
    let current = encrypt_snapshot(&key, b"current preserved artifact").unwrap();
    store
        .save_sync_snapshot(
            material,
            SyncSnapshotV1::new(
                URL_SAFE_NO_PAD
                    .decode(current.snapshot_id)
                    .unwrap()
                    .try_into()
                    .unwrap(),
                current.envelopes,
            ),
        )
        .unwrap();
    let proof = SnapshotDeletionProofV1::authenticate(&key, &old).unwrap();
    let fact = proof.fact().clone();
    store
        .delete_sync_backup(
            store.get_sync_policy_context().unwrap().context_id,
            proof,
            AT.into(),
        )
        .unwrap();
    assert!(store.load_sync_device_identity().unwrap().is_none());
    let signer = identity(&store);
    store.set_key_value("settings.theme", "\"dark\"").unwrap();
    store.begin_sync_baseline().unwrap();
    let first = store
        .list_sync_operations(*signer.device_id_bytes(), 1, 0, 256)
        .unwrap();
    let operations = first
        .iter()
        .map(|record| serde_json::from_str(&record.operation_json).unwrap())
        .collect::<Vec<aw_sync_e2ee::SyncOperationV1>>();
    assert_eq!(
        assemble_backup_forget_operations(&operations).unwrap(),
        vec![fact]
    );
    assert_eq!(
        operations
            .iter()
            .filter(|op| op.kind == SyncOperationKindV1::BackupForget)
            .count(),
        1
    );
    store.begin_sync_baseline().unwrap();
    assert_eq!(
        store
            .list_sync_operations(*signer.device_id_bytes(), 1, 0, 256)
            .unwrap(),
        first
    );
    assert_eq!(store.get_key_value("settings.theme").unwrap(), "\"dark\"");
    assert!(!store.sync_enabled().unwrap());
    store.close();
}
#[test]
fn backup_forget_signed_receive_waits_for_complete_fact_and_replay_is_idempotent() {
    let path = std::env::temp_dir().join(format!(
        "peak-forget-signed-{}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let secret = "a".repeat(64);
    let store =
        Datastore::open_encrypted(path.to_string_lossy().into_owned(), secret.clone()).unwrap();
    let (material, key) = material();
    store.install_sync_key_material(&material).unwrap();
    identity(&store);
    let signer = generate_device_identity().unwrap();
    trust(&store, &signer);
    let artifact = encrypt_snapshot(&key, b"known artifact").unwrap();
    let mut fact = SnapshotDeletionProofV1::authenticate(&key, &artifact)
        .unwrap()
        .fact()
        .clone();
    let original = fact.objects[0].clone();
    fact.objects = (0..4001u128)
        .map(|n| aw_models::SnapshotDeletionObjectV1 {
            object_id: URL_SAFE_NO_PAD.encode((n + 1).to_be_bytes()),
            envelope_sha256: original.envelope_sha256.clone(),
        })
        .collect();
    let operations = create_backup_forget_operations(*signer.device_id_bytes(), 1, &fact).unwrap();
    let mut parent = [0; 32];
    store.set_key_value("settings.theme", "\"dark\"").unwrap();
    for (index, operation) in operations.into_iter().enumerate() {
        let manifest = SyncManifestV1::new_signed(
            &signer,
            key.vault_id(),
            1,
            index as u64 + 1,
            parent,
            vec![operation],
        )
        .unwrap();
        parent = URL_SAFE_NO_PAD
            .decode(&manifest.head_hash)
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(
            store
                .apply_sync_operations(SyncApplyBatchV1 {
                    manifest: manifest.clone()
                })
                .unwrap(),
            SyncHeadCommitV1::Advanced
        );
        assert_eq!(
            store
                .apply_sync_operations(SyncApplyBatchV1 { manifest })
                .unwrap(),
            SyncHeadCommitV1::Duplicate
        );
        if index == 0 {
            store.lock().unwrap();
            store
                .unlock_encrypted(path.to_string_lossy().into_owned(), secret.clone())
                .unwrap();
            assert_eq!(
                store
                    .list_sync_operations(*signer.device_id_bytes(), 1, 0, 16)
                    .unwrap()
                    .len(),
                1
            );
        }
        let all = store
            .export_sync_backup_deletions(store.get_sync_policy_context().unwrap().context_id)
            .unwrap();
        let continuity = store.export_sync_recovery_state(1).unwrap();
        aw_datastore::validate_sync_recovery_state_v1(
            &continuity,
            &aw_models::BucketsExport {
                buckets: Default::default(),
            },
            1,
        )
        .unwrap();
        if index == 2 {
            let mut missing = continuity.clone();
            missing.backup_deletions.clear();
            assert!(aw_datastore::validate_sync_recovery_state_v1(
                &missing,
                &aw_models::BucketsExport {
                    buckets: Default::default()
                },
                1
            )
            .is_err());
        }
        if index < 2 {
            assert!(all.is_empty());
        } else {
            assert!(all == vec![fact.clone()]);
        }
    }
    assert!(store.get_buckets().unwrap().is_empty());
    assert_eq!(store.get_key_value("settings.theme").unwrap(), "\"dark\"");
    assert!(!store.sync_enabled().unwrap());
    store.close();
    let reopened = Datastore::open_encrypted(path.to_string_lossy().into_owned(), secret).unwrap();
    assert!(
        reopened
            .export_sync_backup_deletions(reopened.get_sync_policy_context().unwrap().context_id)
            .unwrap()
            == vec![fact]
    );
    reopened.close();
    std::fs::remove_file(path).unwrap();
}

#[test]
fn backup_forget_conflicting_signed_fragment_rolls_back_counter_head_and_partial_state() {
    let store = Datastore::open_encrypted(":memory:".into(), "a".repeat(64)).unwrap();
    let (material, key) = material();
    store.install_sync_key_material(&material).unwrap();
    identity(&store);
    let signer = generate_device_identity().unwrap();
    trust(&store, &signer);
    let artifact = encrypt_snapshot(&key, b"known version").unwrap();
    let mut fact = SnapshotDeletionProofV1::authenticate(&key, &artifact)
        .unwrap()
        .fact()
        .clone();
    fact.objects = (0..4001u128)
        .map(|n| aw_models::SnapshotDeletionObjectV1 {
            object_id: URL_SAFE_NO_PAD.encode((n + 1).to_be_bytes()),
            envelope_sha256: "b".repeat(64),
        })
        .collect();
    let ops = create_backup_forget_operations(*signer.device_id_bytes(), 1, &fact).unwrap();
    let first =
        SyncManifestV1::new_signed(&signer, key.vault_id(), 1, 1, [0; 32], vec![ops[0].clone()])
            .unwrap();
    let parent: [u8; 32] = URL_SAFE_NO_PAD
        .decode(first.head_hash.clone())
        .unwrap()
        .try_into()
        .unwrap();
    store
        .apply_sync_operations(SyncApplyBatchV1 { manifest: first })
        .unwrap();
    let mut conflict = ops[0].clone();
    conflict.counter = 4;
    conflict.backup_forget_fragment.as_mut().unwrap().objects[0].envelope_sha256 = "c".repeat(64);
    let bad =
        SyncManifestV1::new_signed(&signer, key.vault_id(), 1, 2, parent, vec![conflict]).unwrap();
    assert!(store
        .apply_sync_operations(SyncApplyBatchV1 { manifest: bad })
        .is_err());
    assert_eq!(
        store
            .load_sync_manifest_head(key.vault_id(), 1, *signer.device_id_bytes())
            .unwrap()
            .unwrap()
            .revision,
        1
    );
    assert_eq!(
        store
            .list_sync_operations(*signer.device_id_bytes(), 1, 0, 16)
            .unwrap()
            .len(),
        1
    );
    assert!(store
        .export_sync_backup_deletions(store.get_sync_policy_context().unwrap().context_id)
        .unwrap()
        .is_empty());
    assert_eq!(
        store
            .next_sync_operation_counter(*signer.device_id_bytes())
            .unwrap(),
        2
    );
    store.close();
}
#[test]
fn backup_forget_authenticated_receipt_preserves_current_copy_and_refuses_unsigned_or_stale_epoch()
{
    let store = Datastore::open_encrypted(":memory:".into(), "a".repeat(64)).unwrap();
    let (material, key) = material();
    store.install_sync_key_material(&material).unwrap();
    identity(&store);
    let signer = generate_device_identity().unwrap();
    trust(&store, &signer);
    let artifact = encrypt_snapshot(&key, b"current version must remain local").unwrap();
    let fact = SnapshotDeletionProofV1::authenticate(&key, &artifact)
        .unwrap()
        .fact()
        .clone();
    for object in &artifact.envelopes {
        store.put_sync_object(object.clone(), AT.into()).unwrap();
    }
    let snapshot = SyncSnapshotV1::new(
        URL_SAFE_NO_PAD
            .decode(&artifact.snapshot_id)
            .unwrap()
            .try_into()
            .unwrap(),
        artifact.envelopes.clone(),
    );
    store
        .save_sync_snapshot(material, snapshot.clone())
        .unwrap();
    let ops = create_backup_forget_operations(*signer.device_id_bytes(), 1, &fact).unwrap();
    let manifest =
        SyncManifestV1::new_signed(&signer, key.vault_id(), 1, 1, [0; 32], ops.clone()).unwrap();
    let mut unsigned = manifest.clone();
    unsigned.signature = URL_SAFE_NO_PAD.encode([0; 64]);
    assert!(store
        .apply_sync_operations(SyncApplyBatchV1 { manifest: unsigned })
        .is_err());
    let stale = SyncManifestV1::new_signed(&signer, key.vault_id(), 2, 1, [0; 32], ops).unwrap();
    assert!(store
        .apply_sync_operations(SyncApplyBatchV1 { manifest: stale })
        .is_err());
    assert!(store
        .export_sync_backup_deletions(store.get_sync_policy_context().unwrap().context_id)
        .unwrap()
        .is_empty());
    store
        .apply_sync_operations(SyncApplyBatchV1 { manifest })
        .unwrap();
    assert_eq!(store.load_sync_snapshot().unwrap(), Some(snapshot));
    assert_eq!(
        store
            .get_sync_object(artifact.envelopes[0].object_id.clone())
            .unwrap(),
        Some(artifact.envelopes[0].clone())
    );
    assert!(store
        .put_sync_object(artifact.envelopes[0].clone(), AT.into())
        .is_err());
    assert_eq!(
        store
            .export_sync_backup_deletions(store.get_sync_policy_context().unwrap().context_id)
            .unwrap(),
        vec![fact]
    );
    store.close();
}

#[test]
fn backup_forget_recovery_history_checks_stored_operation_bytes_before_loading_json() {
    let path = std::env::temp_dir().join(format!(
        "peak-forget-history-bound-{}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let secret = "a".repeat(64);
    let store =
        Datastore::open_encrypted(path.to_string_lossy().into_owned(), secret.clone()).unwrap();
    let (material, key) = material();
    store.install_sync_key_material(&material).unwrap();
    let signer = identity(&store);
    let artifact = encrypt_snapshot(&key, b"known artifact").unwrap();
    let fact = SnapshotDeletionProofV1::authenticate(&key, &artifact)
        .unwrap()
        .fact()
        .clone();
    store
        .merge_sync_backup_deletions(
            store.get_sync_policy_context().unwrap().context_id,
            vec![fact],
            AT.into(),
        )
        .unwrap();
    store.begin_sync_baseline().unwrap();
    store.close();
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection.pragma_update(None, "key", &secret).unwrap();
    connection.execute("UPDATE sync_operations SET operation_json=?1 WHERE device_id=?2 AND counter=(SELECT MIN(counter) FROM sync_operations)",rusqlite::params!["x".repeat(1024*1024+1),signer.device_id_bytes().as_slice()]).unwrap();
    drop(connection);
    let reopened = Datastore::open_encrypted(path.to_string_lossy().into_owned(), secret).unwrap();
    assert!(reopened.export_sync_recovery_state(1).is_err());
    assert!(reopened.begin_sync_baseline().is_err());
    reopened.close();
    std::fs::remove_file(path).unwrap();
}
