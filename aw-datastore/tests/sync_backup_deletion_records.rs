#![cfg(any(feature = "encryption", feature = "encryption-vendored"))]
use aw_datastore::Datastore;
use aw_models::SnapshotDeletionFactV1;
use aw_sync_e2ee::{
    create_vault_data_key, encrypt_snapshot, generate_account_root_key, SnapshotDeletionProofV1,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
const AT: &str = "2026-10-14T12:00:00Z";
fn fact(epoch: u64) -> SnapshotDeletionFactV1 {
    let key = create_vault_data_key(
        &generate_account_root_key().unwrap(),
        &URL_SAFE_NO_PAD.encode([0x71; 16]),
        epoch,
    )
    .unwrap()
    .0;
    let snapshot = encrypt_snapshot(&key, b"private source").unwrap();
    SnapshotDeletionProofV1::authenticate(&key, &snapshot)
        .unwrap()
        .fact()
        .clone()
}
fn store() -> Datastore {
    Datastore::open_encrypted(":memory:".into(), "a".repeat(64)).unwrap()
}
#[test]
fn deletion_fact_pages_bind_worker_and_frozen_prefix_without_rounding_epochs() {
    let store = store();
    let ctx = store.get_sync_policy_context().unwrap().context_id;
    let a = fact(u64::MAX);
    let b = fact(1);
    let c = fact(2);
    assert_eq!(
        store
            .merge_sync_backup_deletions(ctx.clone(), vec![a.clone(), b.clone()], AT.into())
            .unwrap(),
        2
    );
    let page = store
        .list_sync_backup_deletions(ctx.clone(), None, 1)
        .unwrap();
    assert_eq!(page.facts, vec![a.clone()]);
    let cursor = page.next_cursor.clone().unwrap();
    assert_eq!(
        store
            .merge_sync_backup_deletions(ctx.clone(), vec![c.clone()], AT.into())
            .unwrap(),
        1
    );
    let last = store
        .list_sync_backup_deletions(ctx.clone(), Some(cursor.clone()), 1)
        .unwrap();
    assert_eq!(last.facts, vec![b.clone()]);
    assert!(last.next_cursor.is_none());
    let all = store.export_sync_backup_deletions(ctx.clone()).unwrap();
    assert_eq!(all, vec![a, b, c]);
    assert!(store
        .list_sync_backup_deletions("0".repeat(64), Some(cursor), 1)
        .is_err());
    assert!(store
        .list_sync_backup_deletions(ctx.clone(), None, 0)
        .is_err());
    assert!(store.list_sync_backup_deletions(ctx, None, 65).is_err());
    store.close();
}
#[test]
fn deletion_fact_merge_is_idempotent_and_conflicts_roll_back_the_whole_batch() {
    let store = store();
    let ctx = store.get_sync_policy_context().unwrap().context_id;
    let a = fact(1);
    let b = fact(1);
    let mut conflict = b.clone();
    conflict.objects[0].object_id = a.objects[0].object_id.clone();
    assert!(store
        .merge_sync_backup_deletions(ctx.clone(), vec![a.clone(), conflict], AT.into())
        .is_err());
    assert!(store
        .get_sync_backup_deletion(a.objects[0].object_id.clone())
        .unwrap()
        .is_none());
    assert_eq!(
        store
            .merge_sync_backup_deletions(ctx.clone(), vec![a.clone(), a.clone()], AT.into())
            .unwrap(),
        1
    );
    assert_eq!(
        store
            .merge_sync_backup_deletions(ctx.clone(), vec![a.clone()], AT.into())
            .unwrap(),
        0
    );
    let mut changed = a.clone();
    changed.bundle_sha256 = "f".repeat(64);
    assert!(store
        .merge_sync_backup_deletions(ctx.clone(), vec![b.clone(), changed], AT.into())
        .is_err());
    assert!(store
        .get_sync_backup_deletion(b.objects[0].object_id.clone())
        .unwrap()
        .is_none());
    assert_eq!(store.export_sync_backup_deletions(ctx).unwrap(), vec![a]);
    store.close();
}
#[test]
fn deletion_fact_merge_preserves_active_current_ciphertext_and_controls() {
    let store = store();
    let root = generate_account_root_key().unwrap();
    let (key, wrapped) =
        create_vault_data_key(&root, &URL_SAFE_NO_PAD.encode([0x71; 16]), 1).unwrap();
    let snapshot = encrypt_snapshot(&key, b"retained current private").unwrap();
    let material = aw_datastore::SyncKeyMaterial::new(
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
    store.install_sync_key_material(&material).unwrap();
    let current = aw_datastore::SyncSnapshotV1::new(
        URL_SAFE_NO_PAD
            .decode(&snapshot.snapshot_id)
            .unwrap()
            .try_into()
            .unwrap(),
        snapshot.envelopes.clone(),
    );
    store
        .save_sync_snapshot(material.clone(), current.clone())
        .unwrap();
    let proof = SnapshotDeletionProofV1::authenticate(&key, &snapshot).unwrap();
    let fact = proof.fact().clone();
    store
        .put_sync_object(snapshot.envelopes[0].clone(), AT.into())
        .unwrap();
    store.set_key_value("settings.theme", "\"dark\"").unwrap();
    let ctx = store.get_sync_policy_context().unwrap().context_id;
    store
        .merge_sync_backup_deletions(ctx, vec![fact.clone()], AT.into())
        .unwrap();
    assert_eq!(
        store
            .get_sync_object(snapshot.envelopes[0].object_id.clone())
            .unwrap(),
        Some(snapshot.envelopes[0].clone())
    );
    assert_eq!(store.get_key_value("settings.theme").unwrap(), "\"dark\"");
    assert_eq!(
        store
            .load_sync_key_material()
            .unwrap()
            .unwrap()
            .account_root_key(),
        material.account_root_key()
    );
    assert_eq!(store.load_sync_snapshot().unwrap(), Some(current));
    assert!(!store.sync_enabled().unwrap());
    assert_eq!(
        store
            .get_sync_backup_deletion(snapshot.envelopes[0].object_id.clone())
            .unwrap(),
        Some(fact)
    );
    store.close();
}
#[test]
fn deletion_fact_corrupt_parent_or_missing_child_cannot_export_a_complete_ledger() {
    for corruption in 0..4 {
        let path = std::env::temp_dir().join(format!(
            "peak-facts-corrupt-{}-{}-{corruption}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let store =
            Datastore::open_encrypted(path.to_string_lossy().into_owned(), "a".repeat(64)).unwrap();
        let a = fact(1);
        let ctx = store.get_sync_policy_context().unwrap().context_id;
        store
            .merge_sync_backup_deletions(ctx, vec![a.clone()], AT.into())
            .unwrap();
        store.close();
        let db = rusqlite::Connection::open(&path).unwrap();
        db.pragma_update(None, "key", "a".repeat(64)).unwrap();
        db.execute_batch(match corruption {
            0=>"UPDATE sync_backup_deletions SET fact_json='[]';",
            1=>"DELETE FROM sync_backup_deleted_objects;",
            2=>"PRAGMA foreign_keys=OFF; DELETE FROM sync_backup_deletions;",
            _=>"UPDATE sync_backup_deleted_objects SET envelope_sha256='ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';",
        })
        .unwrap();
        drop(db);
        let store =
            Datastore::open_encrypted(path.to_string_lossy().into_owned(), "a".repeat(64)).unwrap();
        let ctx = store.get_sync_policy_context().unwrap().context_id;
        assert!(store.export_sync_backup_deletions(ctx.clone()).is_err());
        assert!(store.list_sync_backup_deletions(ctx, None, 1).is_err());
        store.close();
        std::fs::remove_file(path).unwrap();
    }
}

#[test]
fn deletion_fact_merge_real_commit_failure_never_acknowledges_or_leaves_records() {
    let path = std::env::temp_dir().join(format!(
        "peak-facts-commit-{}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let store =
        Datastore::open_encrypted(path.to_string_lossy().into_owned(), "a".repeat(64)).unwrap();
    store.close();
    let db = rusqlite::Connection::open(&path).unwrap();
    db.pragma_update(None, "key", "a".repeat(64)).unwrap();
    db.execute_batch("CREATE TABLE facts_parent(id INTEGER PRIMARY KEY);CREATE TABLE facts_child(id INTEGER REFERENCES facts_parent(id) DEFERRABLE INITIALLY DEFERRED);CREATE TRIGGER fail_facts_commit AFTER INSERT ON sync_backup_deleted_objects BEGIN INSERT INTO facts_child(id) VALUES(1); END;").unwrap();
    drop(db);
    let store =
        Datastore::open_encrypted(path.to_string_lossy().into_owned(), "a".repeat(64)).unwrap();
    let ctx = store.get_sync_policy_context().unwrap().context_id;
    let a = fact(1);
    let error = store
        .merge_sync_backup_deletions(ctx, vec![a.clone()], AT.into())
        .unwrap_err();
    assert!(format!("{error:?}").to_lowercase().contains("commit"));
    store.close();
    let store =
        Datastore::open_encrypted(path.to_string_lossy().into_owned(), "a".repeat(64)).unwrap();
    let ctx = store.get_sync_policy_context().unwrap().context_id;
    assert!(store.export_sync_backup_deletions(ctx).unwrap().is_empty());
    assert!(store
        .get_sync_backup_deletion(a.objects[0].object_id.clone())
        .unwrap()
        .is_none());
    store.close();
    std::fs::remove_file(path).unwrap();
}
#[test]
fn deletion_fact_captured_lease_reads_while_close_writer_waits() {
    let store = store();
    let ctx = store.get_sync_policy_context().unwrap().context_id;
    let a = fact(1);
    store
        .merge_sync_backup_deletions(ctx.clone(), vec![a.clone()], AT.into())
        .unwrap();
    let lease = store.egress_lease().unwrap();
    let closing = store.clone();
    let (ready, observed) = std::sync::mpsc::channel();
    let writer = std::thread::spawn(move || {
        ready.send(()).unwrap();
        closing.close();
    });
    observed
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap();
    assert_eq!(
        lease
            .list_sync_backup_deletions(ctx.clone(), None, 1)
            .unwrap()
            .facts,
        vec![a.clone()]
    );
    assert_eq!(
        lease.export_sync_backup_deletions(ctx).unwrap(),
        vec![a.clone()]
    );
    assert_eq!(
        lease
            .sync_backup_deletion(a.objects[0].object_id.clone())
            .unwrap(),
        Some(a)
    );
    drop(lease);
    writer.join().unwrap();
}

#[test]
fn deletion_fact_row_byte_bound_fails_before_returning_any_complete_page() {
    let path = std::env::temp_dir().join(format!(
        "peak-facts-size-{}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let store =
        Datastore::open_encrypted(path.to_string_lossy().into_owned(), "a".repeat(64)).unwrap();
    let a = fact(1);
    let ctx = store.get_sync_policy_context().unwrap().context_id;
    store
        .merge_sync_backup_deletions(ctx, vec![a], AT.into())
        .unwrap();
    store.close();
    let db = rusqlite::Connection::open(&path).unwrap();
    db.pragma_update(None, "key", "a".repeat(64)).unwrap();
    db.execute(
        "UPDATE sync_backup_deletions SET fact_json=CAST(zeroblob(16777217) AS TEXT)",
        [],
    )
    .unwrap();
    drop(db);
    let store =
        Datastore::open_encrypted(path.to_string_lossy().into_owned(), "a".repeat(64)).unwrap();
    let ctx = store.get_sync_policy_context().unwrap().context_id;
    assert!(store
        .list_sync_backup_deletions(ctx.clone(), None, 1)
        .is_err());
    assert!(store.export_sync_backup_deletions(ctx).is_err());
    store.close();
    std::fs::remove_file(path).unwrap();
}
#[test]
fn deletion_fact_full_export_never_truncates_a_ledger_over_100000_entries() {
    fn many(epoch: u64, count: u64) -> SnapshotDeletionFactV1 {
        let mut f = fact(epoch);
        f.objects = (0..count)
            .map(|n| {
                let mut id = [0; 16];
                id[..8].copy_from_slice(&epoch.to_be_bytes());
                id[8..].copy_from_slice(&n.to_be_bytes());
                aw_models::SnapshotDeletionObjectV1 {
                    object_id: URL_SAFE_NO_PAD.encode(id),
                    envelope_sha256: "a".repeat(64),
                }
            })
            .collect();
        f
    }
    let store = store();
    let ctx = store.get_sync_policy_context().unwrap().context_id;
    let a = many(1, 50001);
    let b = many(2, 50000);
    store
        .merge_sync_backup_deletions(ctx.clone(), vec![a], AT.into())
        .unwrap();
    store
        .merge_sync_backup_deletions(ctx.clone(), vec![b], AT.into())
        .unwrap();
    let page = store
        .list_sync_backup_deletions(ctx.clone(), None, 64)
        .unwrap();
    assert_eq!(page.facts.len(), 1);
    assert_eq!(page.facts[0].objects.len(), 50001);
    let next = store
        .list_sync_backup_deletions(ctx.clone(), page.next_cursor, 64)
        .unwrap();
    assert_eq!(next.facts[0].objects.len(), 50000);
    assert!(next.next_cursor.is_none());
    assert!(store.export_sync_backup_deletions(ctx).is_err());
    store.close();
}

#[test]
fn deletion_fact_old_cursor_and_merge_context_never_reach_a_reopened_worker() {
    let path = std::env::temp_dir().join(format!(
        "peak-facts-context-{}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let store =
        Datastore::open_encrypted(path.to_string_lossy().into_owned(), "a".repeat(64)).unwrap();
    let a = fact(1);
    let b = fact(2);
    let ctx = store.get_sync_policy_context().unwrap().context_id;
    store
        .merge_sync_backup_deletions(ctx.clone(), vec![a.clone(), b.clone()], AT.into())
        .unwrap();
    let cursor = store
        .list_sync_backup_deletions(ctx.clone(), None, 1)
        .unwrap()
        .next_cursor
        .unwrap();
    store.close();
    let store =
        Datastore::open_encrypted(path.to_string_lossy().into_owned(), "a".repeat(64)).unwrap();
    let fresh = store.get_sync_policy_context().unwrap().context_id;
    assert_ne!(fresh, ctx);
    assert!(store
        .list_sync_backup_deletions(fresh.clone(), Some(cursor), 1)
        .is_err());
    assert!(store
        .merge_sync_backup_deletions(ctx, vec![fact(3)], AT.into())
        .is_err());
    assert_eq!(
        store.export_sync_backup_deletions(fresh).unwrap(),
        vec![a, b]
    );
    store.close();
    std::fs::remove_file(path).unwrap();
}
