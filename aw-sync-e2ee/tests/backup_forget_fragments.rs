use aw_models::{SnapshotDeletionFactV1, SnapshotDeletionObjectV1, SyncOperationKindV1};
use aw_sync_e2ee::{
    assemble_backup_forget_operations, create_backup_forget_operations, generate_device_identity,
    merge_operations, SyncManifestV1,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
fn fact(objects: usize) -> SnapshotDeletionFactV1 {
    SnapshotDeletionFactV1 {
        schema_version: 1,
        vault_id: URL_SAFE_NO_PAD.encode([1; 16]),
        key_epoch: u64::MAX.to_string(),
        snapshot_id: URL_SAFE_NO_PAD.encode([2; 16]),
        bundle_sha256: "a".repeat(64),
        objects: (0..objects)
            .map(|n| SnapshotDeletionObjectV1 {
                object_id: URL_SAFE_NO_PAD.encode((n as u128 + 1).to_be_bytes()),
                envelope_sha256: "b".repeat(64),
            })
            .collect(),
    }
}
#[test]
fn backup_forget_large_fact_fragments_fit_signed_encrypted_manifest_bounds() {
    let fact = fact(12000);
    assert!(serde_json::to_vec(&fact).unwrap().len() > 1024 * 1024);
    let signer = generate_device_identity().unwrap();
    let operations = create_backup_forget_operations(*signer.device_id_bytes(), 1, &fact).unwrap();
    assert!(operations.len() > 1);
    let key = aw_sync_e2ee::create_vault_data_key(
        &aw_sync_e2ee::generate_account_root_key().unwrap(),
        &URL_SAFE_NO_PAD.encode([1; 16]),
        1,
    )
    .unwrap()
    .0;
    let mut parent = [0; 32];
    for (index, op) in operations.iter().enumerate() {
        assert_eq!(op.kind, SyncOperationKindV1::BackupForget);
        assert!(serde_json::to_vec(op).unwrap().len() <= 512 * 1024);
        let manifest = SyncManifestV1::new_signed(
            &signer,
            [1; 16],
            1,
            index as u64 + 1,
            parent,
            vec![op.clone()],
        )
        .unwrap();
        manifest
            .verify_signature(&signer.public_identity(), &[1; 16])
            .unwrap();
        assert!(serde_json::to_vec(&manifest).unwrap().len() <= 1024 * 1024);
        let envelope = aw_sync_e2ee::encrypt_manifest(
            &key,
            &aw_models::SyncChunkHeaderV1 {
                schema_version: 1,
                object_id: URL_SAFE_NO_PAD.encode((index as u128 + 100).to_be_bytes()),
                vault_id: URL_SAFE_NO_PAD.encode([1; 16]),
                key_epoch: 1,
            },
            &manifest,
        )
        .unwrap();
        assert_eq!(
            aw_sync_e2ee::decrypt_manifest(&key, &envelope)
                .unwrap()
                .head_hash,
            manifest.head_hash
        );
        parent = URL_SAFE_NO_PAD
            .decode(&manifest.head_hash)
            .unwrap()
            .try_into()
            .unwrap();
    }
    assert_eq!(
        assemble_backup_forget_operations(&operations).unwrap(),
        vec![fact]
    );
    let merged = merge_operations(&[], &operations).unwrap();
    assert!(merged.events.is_empty());
    assert!(merged.pending_policy_conflict.is_none());
}
#[test]
fn backup_forget_missing_fragments_have_no_effect_and_duplicates_converge() {
    let fact = fact(4001);
    let ops = create_backup_forget_operations([4; 16], 1, &fact).unwrap();
    assert!(assemble_backup_forget_operations(&ops[..ops.len() - 1])
        .unwrap()
        .is_empty());
    let mut duplicate = ops.clone();
    let mut first = ops[0].clone();
    first.counter = 100;
    duplicate.push(first);
    assert_eq!(
        assemble_backup_forget_operations(&duplicate).unwrap(),
        vec![fact]
    );
}
#[test]
fn backup_forget_conflicting_hash_headers_and_fragments_refuse_complete_admission() {
    let ops = create_backup_forget_operations([4; 16], 1, &fact(4001)).unwrap();
    for alteration in 0..3 {
        let mut changed = ops.clone();
        let f = changed[0].backup_forget_fragment.as_mut().unwrap();
        match alteration {
            0 => f.objects[0].envelope_sha256 = "c".repeat(64),
            1 => f.bundle_sha256 = "c".repeat(64),
            _ => f.fact_sha256 = "c".repeat(64),
        }
        assert!(
            assemble_backup_forget_operations(&changed).is_err()
                || assemble_backup_forget_operations(&changed)
                    .unwrap()
                    .is_empty()
        );
    }
    let mut changed = ops.clone();
    let mut conflict = ops[0].clone();
    conflict.counter = 100;
    conflict.backup_forget_fragment.as_mut().unwrap().objects[0].envelope_sha256 = "c".repeat(64);
    changed.push(conflict);
    assert!(assemble_backup_forget_operations(&changed).is_err());
}
#[test]
fn backup_forget_closed_fragments_reject_count_allocation_and_event_or_policy_fields() {
    let operation = create_backup_forget_operations([4; 16], 1, &fact(1))
        .unwrap()
        .remove(0);
    for name in ["local_event_id", "policy_version"] {
        let mut value = serde_json::to_value(&operation).unwrap();
        value[name] = serde_json::json!(1);
        assert!(
            serde_json::from_value::<aw_sync_e2ee::SyncOperationV1>(value)
                .unwrap()
                .validate()
                .is_err()
        );
    }
    let fragment =
        serde_json::to_value(operation.backup_forget_fragment.as_ref().unwrap()).unwrap();
    for (name, value) in [
        ("fragment_count", serde_json::json!(u32::MAX)),
        ("total_objects", serde_json::json!(u32::MAX)),
        ("unknown", serde_json::json!(true)),
    ] {
        let mut malformed = fragment.clone();
        malformed[name] = value;
        assert!(serde_json::from_value::<aw_models::BackupForgetFragmentV1>(malformed).is_err());
    }
    let raw = serde_json::to_string(&fragment).unwrap();
    let duplicate = raw.replacen("{", "{\"schema_version\":1,", 1);
    assert!(serde_json::from_str::<aw_models::BackupForgetFragmentV1>(&duplicate).is_err());
    assert!(create_backup_forget_operations([4; 16], i64::MAX as u64, &fact(4001)).is_err());
}

#[test]
fn backup_forget_full_bound_converges_when_two_writers_publish_identical_facts() {
    let fact = fact(100000);
    let mut first = create_backup_forget_operations([4; 16], 1, &fact).unwrap();
    let second = create_backup_forget_operations([5; 16], 1, &fact).unwrap();
    first.extend(second);
    let assembled = assemble_backup_forget_operations(&first).unwrap();
    assert!(assembled == vec![fact]);
}
