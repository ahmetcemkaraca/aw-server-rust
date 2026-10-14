use crate::{
    create_vault_data_key, decrypt_snapshot, encrypt_snapshot, generate_account_root_key,
    inspect_snapshot_chunk, reencrypt_snapshot_chunks, rotate_account_and_vault_key,
    EncryptedSyncSnapshotV1,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use crate::snapshot::SnapshotIndexBuilderV1;
use crate::{encrypt_chunk, SyncErrorV1, VaultDataKeyV1};
use aw_models::{SyncChunkHeaderV1, SyncEnvelopeV1};

fn catalogue_key() -> VaultDataKeyV1 {
    let root = generate_account_root_key().unwrap();
    create_vault_data_key(&root, &URL_SAFE_NO_PAD.encode([0x71; 16]), 1)
        .unwrap()
        .0
}

fn altered_snapshot_chunk(
    key: &VaultDataKeyV1,
    original: &SyncEnvelopeV1,
    object_id: u8,
    index: u32,
    count: u32,
) -> SyncEnvelopeV1 {
    let mut plaintext = crate::decrypt_chunk(key, original).unwrap();
    let header = b"PeakActivity-Sync-Snapshot-v1\0".len() + 16;
    plaintext[header..header + 4].copy_from_slice(&index.to_be_bytes());
    plaintext[header + 4..header + 8].copy_from_slice(&count.to_be_bytes());
    encrypt_chunk(
        key,
        &SyncChunkHeaderV1 {
            schema_version: 1,
            object_id: URL_SAFE_NO_PAD.encode([object_id; 16]),
            vault_id: original.vault_id.clone(),
            key_epoch: original.key_epoch,
        },
        &plaintext,
    )
    .unwrap()
}

#[test]
fn backup_index_orders_versions_by_authenticated_indices_and_deduplicates_exact_objects() {
    let key = catalogue_key();
    let first = encrypt_snapshot(&key, &vec![7; 1_100_000]).unwrap();
    let second = encrypt_snapshot(&key, b"second-private-marker").unwrap();
    let mut builder = SnapshotIndexBuilderV1::new(&key);
    for envelope in [
        &first.envelopes[1],
        &second.envelopes[0],
        &first.envelopes[0],
        &first.envelopes[1],
    ] {
        builder.push(envelope).unwrap();
    }
    let index = builder.finish().unwrap();
    assert_eq!(index.groups.len(), 2);
    let group = index
        .groups
        .iter()
        .find(|group| group.snapshot_id == first.snapshot_id)
        .unwrap();
    assert!(group.complete);
    assert_eq!(
        group.object_ids,
        first
            .envelopes
            .iter()
            .map(|e| e.object_id.clone())
            .collect::<Vec<_>>()
    );
    assert_eq!(group.bundle_sha256.as_ref().unwrap().len(), 64);
    assert!(index.invalid_objects.is_empty());
    assert!(!format!("{index:?}").contains("second-private-marker"));
    let mut ordered = SnapshotIndexBuilderV1::new(&key);
    for envelope in &first.envelopes {
        ordered.push(envelope).unwrap();
    }
    assert_eq!(
        ordered.finish().unwrap().groups[0].bundle_sha256,
        group.bundle_sha256
    );
}

#[test]
fn backup_index_disables_missing_duplicate_and_conflicting_chunk_indices() {
    let key = catalogue_key();
    let snapshot = encrypt_snapshot(&key, &vec![7; 1_100_000]).unwrap();
    for bad in [
        None,
        Some(altered_snapshot_chunk(
            &key,
            &snapshot.envelopes[0],
            9,
            0,
            2,
        )),
        Some(altered_snapshot_chunk(
            &key,
            &snapshot.envelopes[1],
            10,
            1,
            3,
        )),
    ] {
        let mut builder = SnapshotIndexBuilderV1::new(&key);
        builder.push(&snapshot.envelopes[0]).unwrap();
        if let Some(bad) = bad {
            builder.push(&bad).unwrap();
        }
        let index = builder.finish().unwrap();
        assert_eq!(index.groups.len(), 1);
        assert!(!index.groups[0].complete);
        assert!(index.groups[0].bundle_sha256.is_none());
    }
    let huge_count = altered_snapshot_chunk(&key, &snapshot.envelopes[0], 11, 0, u32::MAX);
    let mut builder = SnapshotIndexBuilderV1::new(&key);
    builder.push(&huge_count).unwrap();
    let group = builder.finish().unwrap().groups.remove(0);
    assert_eq!(group.object_ids.len(), 1);
    assert!(!group.complete);
}

#[test]
fn backup_index_reports_tamper_without_exposing_or_guessing_snapshot_identity() {
    let key = catalogue_key();
    let snapshot = encrypt_snapshot(&key, b"private-payload").unwrap();
    let mut tampered = snapshot.envelopes[0].clone();
    let mut ciphertext = URL_SAFE_NO_PAD.decode(&tampered.ciphertext).unwrap();
    *ciphertext.last_mut().unwrap() ^= 1;
    tampered.ciphertext = URL_SAFE_NO_PAD.encode(ciphertext);
    let mut builder = SnapshotIndexBuilderV1::new(&key);
    builder.push(&tampered).unwrap();
    let index = builder.finish().unwrap();
    assert!(index.groups.is_empty());
    assert_eq!(index.invalid_objects, vec![tampered.object_id]);
}

#[test]
fn backup_index_rejects_conflicting_immutable_ids_and_latches_scan_errors() {
    let key = catalogue_key();
    let snapshot = encrypt_snapshot(&key, b"payload").unwrap();
    let mut changed = snapshot.envelopes[0].clone();
    let mut ciphertext = URL_SAFE_NO_PAD.decode(&changed.ciphertext).unwrap();
    *ciphertext.last_mut().unwrap() ^= 1;
    changed.ciphertext = URL_SAFE_NO_PAD.encode(ciphertext);
    let mut builder = SnapshotIndexBuilderV1::new(&key);
    builder.push(&snapshot.envelopes[0]).unwrap();
    assert_eq!(builder.push(&changed), Err(SyncErrorV1::InvalidEnvelope));
    assert_eq!(builder.finish().unwrap_err(), SyncErrorV1::InvalidEnvelope);
}

#[test]
fn backup_index_records_other_epochs_without_claiming_authenticated_versions() {
    let key = catalogue_key();
    let root = generate_account_root_key().unwrap();
    let (old, _) =
        create_vault_data_key(&root, &URL_SAFE_NO_PAD.encode(key.vault_id()), u64::MAX).unwrap();
    let snapshot = encrypt_snapshot(&old, b"historical-payload").unwrap();
    let mut builder = SnapshotIndexBuilderV1::new(&key);
    builder.push(&snapshot.envelopes[0]).unwrap();
    let index = builder.finish().unwrap();
    assert!(index.groups.is_empty());
    assert_eq!(index.unavailable_epochs.get(&u64::MAX), Some(&1));
    let (foreign, _) =
        create_vault_data_key(&root, &URL_SAFE_NO_PAD.encode([0x72; 16]), 1).unwrap();
    let foreign = encrypt_snapshot(&foreign, b"foreign").unwrap();
    let mut builder = SnapshotIndexBuilderV1::new(&key);
    assert_eq!(
        builder.push(&foreign.envelopes[0]),
        Err(SyncErrorV1::InvalidKeyScope)
    );
    assert_eq!(builder.finish().unwrap_err(), SyncErrorV1::InvalidKeyScope);
}

#[test]
fn backup_index_bounds_admission_before_partial_results_can_be_returned() {
    let key = catalogue_key();
    let first = encrypt_snapshot(&key, b"first").unwrap();
    let second = encrypt_snapshot(&key, b"second").unwrap();
    let mut builder = SnapshotIndexBuilderV1::with_limits(&key, 1, usize::MAX);
    builder.push(&first.envelopes[0]).unwrap();
    builder.push(&first.envelopes[0]).unwrap();
    assert_eq!(
        builder.push(&second.envelopes[0]),
        Err(SyncErrorV1::PayloadTooLarge)
    );
    assert_eq!(builder.finish().unwrap_err(), SyncErrorV1::PayloadTooLarge);
    let exact = serde_json::to_vec(&first.envelopes[0]).unwrap().len();
    let mut builder = SnapshotIndexBuilderV1::with_limits(&key, 2, exact - 1);
    assert_eq!(
        builder.push(&first.envelopes[0]),
        Err(SyncErrorV1::PayloadTooLarge)
    );
    assert_eq!(builder.finish().unwrap_err(), SyncErrorV1::PayloadTooLarge);
    let mut builder = SnapshotIndexBuilderV1::with_limits(&key, 1, exact);
    builder.push(&first.envelopes[0]).unwrap();
    assert!(builder.finish().unwrap().groups[0].complete);
}

#[test]
fn backup_index_keeps_authenticated_manifests_separate_from_snapshots() {
    let key = catalogue_key();
    let identity = crate::generate_device_identity().unwrap();
    let manifest =
        crate::SyncManifestV1::new_signed(&identity, key.vault_id(), 1, 1, [0; 32], vec![])
            .unwrap();
    let envelope = crate::encrypt_manifest(
        &key,
        &SyncChunkHeaderV1 {
            schema_version: 1,
            object_id: URL_SAFE_NO_PAD.encode([1; 16]),
            vault_id: URL_SAFE_NO_PAD.encode(key.vault_id()),
            key_epoch: 1,
        },
        &manifest,
    )
    .unwrap();
    let mut builder = SnapshotIndexBuilderV1::new(&key);
    builder.push(&envelope).unwrap();
    let index = builder.finish().unwrap();
    assert!(index.groups.is_empty());
    assert!(index.invalid_objects.is_empty());
    assert_eq!(index.operation_objects, 1);
}

#[test]
fn encrypted_snapshot_chunks_are_complete_ordered_and_rekeyable() {
    let root = generate_account_root_key().unwrap();
    let vault_id = URL_SAFE_NO_PAD.encode([0x71; 16]);
    let (old_key, old_wrapped) = create_vault_data_key(&root, &vault_id, 1).unwrap();
    let mut plaintext = vec![0xA5; 1_100_000];
    plaintext.extend_from_slice(b"private-activity-marker");
    let old_snapshot = encrypt_snapshot(&old_key, &plaintext).unwrap();
    assert!(!serde_json::to_string(&old_snapshot)
        .unwrap()
        .contains("private-activity-marker"));
    assert_eq!(old_snapshot.envelopes.len(), 2);
    for (index, envelope) in old_snapshot.envelopes.iter().enumerate() {
        let header = inspect_snapshot_chunk(&old_key, envelope).unwrap();
        assert_eq!(header.snapshot_id, old_snapshot.snapshot_id);
        assert_eq!(header.index, index as u32);
        assert_eq!(header.count, old_snapshot.envelopes.len() as u32);
    }
    assert_eq!(
        decrypt_snapshot(&old_key, &old_snapshot)
            .unwrap()
            .as_slice(),
        plaintext.as_slice()
    );

    let (new_root, new_key, _) = rotate_account_and_vault_key(&root, &old_wrapped).unwrap();
    let new_envelopes =
        reencrypt_snapshot_chunks(&old_key, &new_key, &old_snapshot.envelopes).unwrap();
    let new_snapshot = EncryptedSyncSnapshotV1 {
        schema_version: old_snapshot.schema_version,
        snapshot_id: old_snapshot.snapshot_id.clone(),
        envelopes: new_envelopes,
    };
    assert_eq!(
        decrypt_snapshot(&new_key, &new_snapshot)
            .unwrap()
            .as_slice(),
        plaintext.as_slice()
    );
    assert!(decrypt_snapshot(&old_key, &new_snapshot).is_err());

    let mut old_index = SnapshotIndexBuilderV1::new(&old_key);
    for envelope in &old_snapshot.envelopes {
        old_index.push(envelope).unwrap();
    }
    let old_group = old_index.finish().unwrap().groups.remove(0);
    let mut new_index = SnapshotIndexBuilderV1::new(&new_key);
    for envelope in &new_snapshot.envelopes {
        new_index.push(envelope).unwrap();
    }
    let new_group = new_index.finish().unwrap().groups.remove(0);
    assert_eq!(old_group.snapshot_id, new_group.snapshot_id);
    assert!(old_group.complete && new_group.complete);
    assert_ne!(old_group.bundle_sha256, new_group.bundle_sha256);

    let mut reordered = new_snapshot;
    reordered.envelopes.swap(0, 1);
    assert!(decrypt_snapshot(&new_key, &reordered).is_err());

    let mut tampered = old_snapshot.clone();
    let mut ciphertext = URL_SAFE_NO_PAD
        .decode(&tampered.envelopes[0].ciphertext)
        .unwrap();
    *ciphertext.last_mut().unwrap() ^= 1;
    tampered.envelopes[0].ciphertext = URL_SAFE_NO_PAD.encode(ciphertext);
    assert!(decrypt_snapshot(&old_key, &tampered).is_err());
    let mut incomplete = old_snapshot;
    incomplete.envelopes.pop();
    assert!(decrypt_snapshot(&old_key, &incomplete).is_err());
    assert_ne!(new_root.as_bytes(), root.as_bytes());
}
