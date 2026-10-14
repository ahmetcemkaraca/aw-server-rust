#![cfg(any(feature = "encryption", feature = "encryption-vendored"))]
use aw_server::backup::FolderBackupDeletionV1;
use aw_sync_e2ee::{
    create_vault_data_key, encrypt_snapshot, generate_account_root_key, FolderSyncObjectStoreV1,
    SnapshotDeletionProofV1, SyncObjectStoreV1,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use std::{fs, path::PathBuf};
fn root() -> PathBuf {
    std::env::temp_dir().join(format!(
        "peak-folder-delete-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}
fn fixture() -> (
    PathBuf,
    aw_sync_e2ee::VaultDataKeyV1,
    aw_sync_e2ee::EncryptedSyncSnapshotV1,
) {
    let root = root();
    let store = FolderSyncObjectStoreV1::open(&root).unwrap();
    let key = create_vault_data_key(
        &generate_account_root_key().unwrap(),
        &URL_SAFE_NO_PAD.encode([1; 16]),
        1,
    )
    .unwrap()
    .0;
    let snapshot = encrypt_snapshot(&key, &vec![7; 1_100_000]).unwrap();
    for object in &snapshot.envelopes {
        store.put_if_absent(object).unwrap();
    }
    (root, key, snapshot)
}
#[test]
fn folder_delete_requires_existing_root_and_does_not_change_permissions() {
    let missing = root();
    assert!(FolderBackupDeletionV1::open_existing(&missing).is_err());
    assert!(!missing.exists());
    fs::create_dir(&missing).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&missing, fs::Permissions::from_mode(0o750)).unwrap();
        FolderBackupDeletionV1::open_existing(&missing).unwrap();
        assert_eq!(
            fs::metadata(&missing).unwrap().permissions().mode() & 0o777,
            0o750
        );
    }
    fs::remove_dir_all(missing).unwrap();
}
#[test]
fn folder_delete_persists_sealed_intent_before_removal_and_keeps_it_for_absence_retry() {
    let (root, key, snapshot) = fixture();
    let io = FolderBackupDeletionV1::open_existing(&root).unwrap();
    let proof = SnapshotDeletionProofV1::authenticate(&key, &snapshot).unwrap();
    let hash = proof.fact().bundle_sha256.clone();
    assert!(io.delete_recorded(&key, Some(&proof), &hash).is_err());
    assert!(snapshot
        .envelopes
        .iter()
        .all(|e| root.join(format!("{}.json", e.object_id)).exists()));
    io.persist_intent(&key, &proof).unwrap();
    let record = io.load_intent(&key, &hash).unwrap().unwrap();
    assert_eq!(
        SnapshotDeletionProofV1::open_record(&key, &record).unwrap(),
        *proof.fact()
    );
    let result = io.delete_recorded(&key, Some(&proof), &hash).unwrap();
    assert_eq!(result.deleted, 2);
    assert_eq!(result.conflict + result.failed, 0);
    assert!(result.durable);
    let again = io.delete_recorded(&key, None, &hash).unwrap();
    assert_eq!(again.absent, 2);
    assert!(again.durable);
    assert!(io.load_intent(&key, &hash).unwrap().is_some());
    FolderSyncObjectStoreV1::open_readonly(&root)
        .unwrap()
        .visit_backup_objects(|_| Ok(()))
        .unwrap();
    drop(io);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn folder_delete_changed_second_copy_is_retained_and_partial_retry_reauthenticates_remaining() {
    let (root, key, snapshot) = fixture();
    let io = FolderBackupDeletionV1::open_existing(&root).unwrap();
    let proof = SnapshotDeletionProofV1::authenticate(&key, &snapshot).unwrap();
    let hash = proof.fact().bundle_sha256.clone();
    io.persist_intent(&key, &proof).unwrap();
    let mut changed = snapshot.envelopes[1].clone();
    changed.nonce = URL_SAFE_NO_PAD.encode([9; 24]);
    let second = root.join(format!("{}.json", changed.object_id));
    fs::write(&second, serde_json::to_vec(&changed).unwrap()).unwrap();
    let result = io.delete_recorded(&key, Some(&proof), &hash).unwrap();
    assert_eq!(result.deleted, 1);
    assert_eq!(result.conflict, 1);
    assert!(second.exists());
    assert_eq!(
        serde_json::from_slice::<aw_models::SyncEnvelopeV1>(&fs::read(&second).unwrap()).unwrap(),
        changed
    );
    fs::write(&second, serde_json::to_vec(&snapshot.envelopes[1]).unwrap()).unwrap();
    let record = io.load_intent(&key, &hash).unwrap().unwrap();
    let fact = SnapshotDeletionProofV1::open_record(&key, &record).unwrap();
    let remaining = io.remaining(&fact).unwrap();
    assert_eq!(remaining.len(), 1);
    let partial = SnapshotDeletionProofV1::resume(&key, &record, &remaining).unwrap();
    assert!(!partial.is_complete());
    let result = io.delete_recorded(&key, Some(&partial), &hash).unwrap();
    assert_eq!(result.deleted, 1);
    assert_eq!(result.absent, 1);
    assert_eq!(result.conflict + result.failed, 0);
    drop(io);
    fs::remove_dir_all(root).unwrap();
}
#[cfg(unix)]
#[test]
fn folder_delete_rejects_ancestor_root_and_object_links_and_preserves_external_bytes() {
    use std::os::unix::fs::symlink;
    let (root, key, snapshot) = fixture();
    let link = root.with_extension("link");
    symlink(&root, &link).unwrap();
    assert!(FolderBackupDeletionV1::open_existing(&link).is_err());
    assert!(FolderBackupDeletionV1::open_existing(link.join(".")).is_err());
    let outside = root.with_extension("outside");
    fs::write(&outside, b"external private bytes").unwrap();
    let io = FolderBackupDeletionV1::open_existing(&root).unwrap();
    let proof = SnapshotDeletionProofV1::authenticate(&key, &snapshot).unwrap();
    let hash = proof.fact().bundle_sha256.clone();
    io.persist_intent(&key, &proof).unwrap();
    let path = root.join(format!("{}.json", snapshot.envelopes[1].object_id));
    fs::remove_file(&path).unwrap();
    symlink(&outside, &path).unwrap();
    let result = io.delete_recorded(&key, Some(&proof), &hash).unwrap();
    assert_eq!(result.conflict, 1);
    assert_eq!(fs::read(&outside).unwrap(), b"external private bytes");
    assert!(path.is_symlink());
    drop(io);
    fs::remove_file(link).unwrap();
    fs::remove_file(outside).unwrap();
    fs::remove_dir_all(root).unwrap();
}
#[cfg(unix)]
#[test]
fn folder_delete_pins_the_root_when_the_named_path_is_replaced() {
    let (root, key, snapshot) = fixture();
    let io = FolderBackupDeletionV1::open_existing(&root).unwrap();
    let proof = SnapshotDeletionProofV1::authenticate(&key, &snapshot).unwrap();
    let hash = proof.fact().bundle_sha256.clone();
    io.persist_intent(&key, &proof).unwrap();
    let moved = root.with_extension("moved");
    fs::rename(&root, &moved).unwrap();
    fs::create_dir(&root).unwrap();
    for object in &snapshot.envelopes {
        fs::write(
            root.join(format!("{}.json", object.object_id)),
            b"replacement root must remain unchanged",
        )
        .unwrap();
    }
    let result = io.delete_recorded(&key, Some(&proof), &hash).unwrap();
    assert_eq!(result.deleted, 2);
    for object in &snapshot.envelopes {
        assert_eq!(
            fs::read(root.join(format!("{}.json", object.object_id))).unwrap(),
            b"replacement root must remain unchanged"
        );
    }
    drop(io);
    fs::remove_dir_all(root).unwrap();
    fs::remove_dir_all(moved).unwrap();
}

#[cfg(unix)]
#[test]
fn folder_delete_resumes_an_exact_file_left_in_private_quarantine_after_interruption() {
    use std::os::unix::fs::PermissionsExt;
    let (root, key, snapshot) = fixture();
    let io = FolderBackupDeletionV1::open_existing(&root).unwrap();
    let proof = SnapshotDeletionProofV1::authenticate(&key, &snapshot).unwrap();
    let hash = proof.fact().bundle_sha256.clone();
    let record = io.persist_intent(&key, &proof).unwrap();
    let quarantine = root.join(format!(".peakactivity-delete-{hash}"));
    fs::create_dir(&quarantine).unwrap();
    fs::set_permissions(&quarantine, fs::Permissions::from_mode(0o700)).unwrap();
    let name = format!("{}.json", snapshot.envelopes[0].object_id);
    fs::rename(root.join(&name), quarantine.join(&name)).unwrap();
    let fact = SnapshotDeletionProofV1::open_record(&key, &record).unwrap();
    let remaining = io.remaining(&fact).unwrap();
    assert_eq!(remaining.len(), 2);
    let resumed = SnapshotDeletionProofV1::resume(&key, &record, &remaining).unwrap();
    let result = io.delete_recorded(&key, Some(&resumed), &hash).unwrap();
    assert_eq!(result.deleted, 2);
    assert_eq!(result.failed + result.conflict, 0);
    assert!(result.durable);
    drop(io);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn folder_delete_never_uses_plain_metadata_or_missing_proof_to_remove_present_bytes() {
    let (root, key, snapshot) = fixture();
    let io = FolderBackupDeletionV1::open_existing(&root).unwrap();
    let proof = SnapshotDeletionProofV1::authenticate(&key, &snapshot).unwrap();
    let hash = proof.fact().bundle_sha256.clone();
    io.persist_intent(&key, &proof).unwrap();
    let result = io.delete_recorded(&key, None, &hash).unwrap();
    assert_eq!(result.deleted, 0);
    assert_eq!(result.conflict, 2);
    for object in &snapshot.envelopes {
        assert!(root.join(format!("{}.json", object.object_id)).exists());
    }
    let wrong = create_vault_data_key(
        &generate_account_root_key().unwrap(),
        &URL_SAFE_NO_PAD.encode([1; 16]),
        1,
    )
    .unwrap()
    .0;
    assert!(io.delete_recorded(&wrong, Some(&proof), &hash).is_err());
    drop(io);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn folder_delete_admission_markers_block_copied_back_objects_but_allow_fresh_snapshots() {
    let (root, key, snapshot) = fixture();
    let io = FolderBackupDeletionV1::open_existing(&root).unwrap();
    let proof = SnapshotDeletionProofV1::authenticate(&key, &snapshot).unwrap();
    let hash = proof.fact().bundle_sha256.clone();
    io.persist_intent(&key, &proof).unwrap();
    io.delete_recorded(&key, Some(&proof), &hash).unwrap();
    for object in &snapshot.envelopes {
        fs::write(
            root.join(format!("{}.json", object.object_id)),
            serde_json::to_vec(object).unwrap(),
        )
        .unwrap();
    }
    let folder = FolderSyncObjectStoreV1::open_readonly(&root).unwrap();
    assert!(folder
        .get(&snapshot.envelopes[0].object_id)
        .unwrap()
        .is_none());
    let writable = FolderSyncObjectStoreV1::open(&root).unwrap();
    assert!(writable.put_if_absent(&snapshot.envelopes[0]).is_err());
    let fresh = encrypt_snapshot(&key, b"fresh immutable backup").unwrap();
    assert!(writable.put_if_absent(&fresh.envelopes[0]).unwrap());
    let mut observed = Vec::new();
    folder
        .visit_backup_objects(|object| {
            observed.push(object.object_id.clone());
            Ok(())
        })
        .unwrap();
    assert_eq!(observed, vec![fresh.envelopes[0].object_id.clone()]);
    drop(io);
    fs::remove_dir_all(root).unwrap();
}
