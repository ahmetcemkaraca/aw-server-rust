use crate::{
    create_vault_data_key, encrypt_snapshot, generate_account_root_key, EncryptedSyncSnapshotV1,
    SnapshotDeletionFactV1, SnapshotDeletionProofV1,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
fn key(epoch: u64) -> crate::VaultDataKeyV1 {
    create_vault_data_key(
        &generate_account_root_key().unwrap(),
        &URL_SAFE_NO_PAD.encode([0x71; 16]),
        epoch,
    )
    .unwrap()
    .0
}
#[test]
fn backup_deletion_proof_binds_whole_version_and_exact_immutable_hashes_with_full_epoch() {
    let key = key(u64::MAX);
    let snapshot = encrypt_snapshot(&key, &vec![7; 1_100_000]).unwrap();
    let proof = SnapshotDeletionProofV1::authenticate(&key, &snapshot).unwrap();
    let fact = proof.fact();
    assert_eq!(fact.key_epoch, u64::MAX.to_string());
    assert_eq!(fact.snapshot_id, snapshot.snapshot_id);
    assert_eq!(fact.vault_id, URL_SAFE_NO_PAD.encode(key.vault_id()));
    assert_eq!(fact.objects.len(), 2);
    for (entry, object) in fact.objects.iter().zip(&snapshot.envelopes) {
        assert_eq!(entry.object_id, object.object_id);
        let hash =
            ring::digest::digest(&ring::digest::SHA256, &serde_json::to_vec(object).unwrap());
        assert_eq!(
            entry.envelope_sha256,
            hash.as_ref()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
    }
    let encoded = serde_json::to_string(fact).unwrap();
    assert!(!encoded.contains("ciphertext"));
    assert!(!encoded.contains("nonce"));
    assert!(!encoded.contains("phrase"));
    assert_eq!(
        serde_json::from_str::<SnapshotDeletionFactV1>(&encoded).unwrap(),
        *fact
    );
    let other = encrypt_snapshot(&key, &vec![7; 1_100_000]).unwrap();
    assert_ne!(
        SnapshotDeletionProofV1::authenticate(&key, &other)
            .unwrap()
            .fact()
            .bundle_sha256,
        fact.bundle_sha256
    );
}
#[test]
fn backup_deletion_proof_rejects_partial_duplicate_changed_order_and_tampered_versions() {
    let key = key(1);
    let snapshot = encrypt_snapshot(&key, &vec![7; 1_100_000]).unwrap();
    let mut candidates = Vec::new();
    let mut missing = snapshot.clone();
    missing.envelopes.pop();
    candidates.push(missing);
    let mut repeated = snapshot.clone();
    repeated.envelopes.push(repeated.envelopes[0].clone());
    candidates.push(repeated);
    let mut reversed = snapshot.clone();
    reversed.envelopes.reverse();
    candidates.push(reversed);
    let mut changed = snapshot.clone();
    changed.snapshot_id = URL_SAFE_NO_PAD.encode([9; 16]);
    candidates.push(changed);
    let mut tamper = snapshot.clone();
    tamper.envelopes[0].nonce = URL_SAFE_NO_PAD.encode([9; 24]);
    candidates.push(tamper);
    for candidate in candidates {
        assert!(SnapshotDeletionProofV1::authenticate(&key, &candidate).is_err());
    }
    assert!(SnapshotDeletionProofV1::authenticate(&self::key(1), &snapshot).is_err());
}
#[test]
fn backup_deletion_proof_never_authorizes_authenticated_operation_objects() {
    let key = key(1);
    let identity = crate::generate_device_identity().unwrap();
    let manifest =
        crate::SyncManifestV1::new_signed(&identity, key.vault_id(), 1, 1, [0; 32], vec![])
            .unwrap();
    let envelope = crate::encrypt_manifest(
        &key,
        &aw_models::SyncChunkHeaderV1 {
            schema_version: 1,
            object_id: URL_SAFE_NO_PAD.encode([1; 16]),
            vault_id: URL_SAFE_NO_PAD.encode(key.vault_id()),
            key_epoch: 1,
        },
        &manifest,
    )
    .unwrap();
    let snapshot = EncryptedSyncSnapshotV1 {
        schema_version: 1,
        snapshot_id: URL_SAFE_NO_PAD.encode([1; 16]),
        envelopes: vec![envelope],
    };
    assert!(SnapshotDeletionProofV1::authenticate(&key, &snapshot).is_err());
}
#[test]
fn backup_deletion_fact_is_closed_bounded_metadata_and_does_not_mint_authority() {
    let key = key(1);
    let snapshot = encrypt_snapshot(&key, b"private payload").unwrap();
    let proof = SnapshotDeletionProofV1::authenticate(&key, &snapshot).unwrap();
    let raw = serde_json::to_value(proof.fact()).unwrap();
    for changed in [
        serde_json::json!([]),
        {
            let mut v = raw.clone();
            v["key_epoch"] = serde_json::json!(1);
            v
        },
        {
            let mut v = raw.clone();
            let first = v["objects"][0].clone();
            v["objects"].as_array_mut().unwrap().push(first);
            v
        },
        {
            let mut v = raw.clone();
            v["root_key"] = serde_json::json!("untrusted");
            v
        },
        {
            let mut v = raw.clone();
            v["objects"][0]["envelope_sha256"] = serde_json::json!("a");
            v
        },
    ] {
        assert!(serde_json::from_value::<SnapshotDeletionFactV1>(changed).is_err());
    }
    let raw = serde_json::to_string(proof.fact()).unwrap().replace(
        "\"schema_version\":1",
        "\"schema_version\":1,\"schema_version\":1",
    );
    assert!(serde_json::from_str::<SnapshotDeletionFactV1>(&raw).is_err());
}

#[test]
fn backup_deletion_proof_checks_bounds_before_issuing_any_authority() {
    let key = key(1);
    let snapshot = encrypt_snapshot(&key, &vec![7; 1_100_000]).unwrap();
    let bytes: usize = snapshot
        .envelopes
        .iter()
        .map(|e| serde_json::to_vec(e).unwrap().len())
        .sum();
    assert!(
        crate::deletion::SnapshotDeletionProofV1::authenticate_with_limits(
            &key,
            &snapshot,
            1,
            usize::MAX
        )
        .is_err()
    );
    assert!(
        crate::deletion::SnapshotDeletionProofV1::authenticate_with_limits(
            &key,
            &snapshot,
            2,
            bytes - 1
        )
        .is_err()
    );
    assert!(
        crate::deletion::SnapshotDeletionProofV1::authenticate_with_limits(
            &key, &snapshot, 2, bytes
        )
        .is_ok()
    );
}
#[test]
fn backup_deletion_sealed_intent_can_resume_without_caching_keys_or_original_ciphertext() {
    let key = key(1);
    let snapshot = encrypt_snapshot(&key, b"original private activity").unwrap();
    let proof = SnapshotDeletionProofV1::authenticate(&key, &snapshot).unwrap();
    let record = proof.seal(&key).unwrap();
    assert_ne!(record.snapshot_id, proof.fact().snapshot_id);
    let raw = serde_json::to_string(&record).unwrap();
    assert!(!raw.contains(&proof.fact().bundle_sha256));
    assert!(!raw.contains("original private activity"));
    let resumed = SnapshotDeletionProofV1::open_record(&key, &record).unwrap();
    assert_eq!(&resumed, proof.fact());
    assert!(SnapshotDeletionProofV1::open_record(&key, &snapshot).is_err());
    assert!(proof.seal(&self::key(1)).is_err());
    let mut tampered = record.clone();
    tampered.envelopes[0].nonce = URL_SAFE_NO_PAD.encode([9; 24]);
    assert!(SnapshotDeletionProofV1::open_record(&key, &tampered).is_err());
    assert!(SnapshotDeletionProofV1::open_record(&self::key(1), &record).is_err());
}
#[test]
fn backup_deletion_resume_requires_remaining_headers_and_never_promotes_a_plain_fact() {
    let key = key(1);
    let snapshot = encrypt_snapshot(&key, &vec![7; 1_100_000]).unwrap();
    let full = SnapshotDeletionProofV1::authenticate(&key, &snapshot).unwrap();
    let record = full.seal(&key).unwrap();
    let partial = SnapshotDeletionProofV1::resume(&key, &record, &snapshot.envelopes[1..]).unwrap();
    assert_eq!(partial.fact(), full.fact());
    assert!(!partial.allows_object(&snapshot.envelopes[0]));
    assert!(partial.allows_object(&snapshot.envelopes[1]));
    assert!(SnapshotDeletionProofV1::resume(&key, &record, &[]).is_err());
    let identity = crate::generate_device_identity().unwrap();
    let manifest =
        crate::SyncManifestV1::new_signed(&identity, key.vault_id(), 1, 1, [0; 32], vec![])
            .unwrap();
    let operation = crate::encrypt_manifest(
        &key,
        &aw_models::SyncChunkHeaderV1 {
            schema_version: 1,
            object_id: URL_SAFE_NO_PAD.encode([1; 16]),
            vault_id: URL_SAFE_NO_PAD.encode(key.vault_id()),
            key_epoch: 1,
        },
        &manifest,
    )
    .unwrap();
    let mut forged = full.fact().clone();
    forged.objects = vec![crate::SnapshotDeletionObjectV1 {
        object_id: operation.object_id.clone(),
        envelope_sha256: ring::digest::digest(
            &ring::digest::SHA256,
            &serde_json::to_vec(&operation).unwrap(),
        )
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect(),
    }];
    let mut bytes = b"PeakActivity-Backup-Deletion-Record-v1\0".to_vec();
    bytes.extend(serde_json::to_vec(&forged).unwrap());
    let forged_record = encrypt_snapshot(&key, &bytes).unwrap();
    assert!(SnapshotDeletionProofV1::resume(&key, &forged_record, &[operation]).is_err());
}
