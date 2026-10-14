#![cfg(any(feature = "encryption", feature = "encryption-vendored"))]

use aw_datastore::{
    Datastore, DatastoreError, SyncDeviceIdentity, SyncKeyMaterial, SyncStoredOperationV1,
};
use aw_models::{Bucket, Event};
use aw_sync_e2ee::SyncOperationV1;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{Duration, Utc};
use rusqlite::{params, Connection};
use serde_json::json;
use std::path::PathBuf;
use zeroize::Zeroizing;

const BUCKET: &str = "corrupt-delete";
const OTHER_BUCKET: &str = "untouched-empty-bucket";
const DEVICE: [u8; 16] = [0x61; 16];
const CORRUPT_DATA: &str = "{synthetic-corrupt-payload";

fn bucket(id: &str) -> Bucket {
    Bucket {
        bid: None,
        id: id.into(),
        _type: "test".into(),
        client: "corrupt-delete-test".into(),
        hostname: "synthetic".into(),
        created: None,
        data: Default::default(),
        metadata: Default::default(),
        events: None,
        last_updated: None,
    }
}

struct Fixture {
    store: Datastore,
    path: PathBuf,
    key: String,
    active: bool,
    events: Vec<Event>,
    old_operations: Vec<SyncStoredOperationV1>,
}

impl Fixture {
    fn new(name: &str, active: bool) -> Self {
        let path = std::env::temp_dir().join(format!(
            "peakactivity-{name}-{active}-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        let key = "synthetic-corrupt-deletion-key-".repeat(3);
        let store =
            Datastore::open_encrypted(path.to_string_lossy().into_owned(), key.clone()).unwrap();
        store.create_bucket(&bucket(BUCKET)).unwrap();
        store.create_bucket(&bucket(OTHER_BUCKET)).unwrap();
        let start = "2026-01-01T00:00:00Z"
            .parse::<chrono::DateTime<Utc>>()
            .unwrap();
        let events = store
            .insert_events(
                BUCKET,
                &[
                    Event::new(
                        start,
                        Duration::seconds(1),
                        json!({"app":"synthetic-first"})
                            .as_object()
                            .unwrap()
                            .clone(),
                    ),
                    Event::new(
                        start + Duration::hours(1),
                        Duration::seconds(1),
                        json!({"app":"synthetic-healthy"})
                            .as_object()
                            .unwrap()
                            .clone(),
                    ),
                ],
            )
            .unwrap();
        store
            .create_sync_device_identity(&SyncDeviceIdentity::new(
                DEVICE,
                Zeroizing::new([0x62; 32]),
                Zeroizing::new([0x63; 32]),
            ))
            .unwrap();
        store
            .install_sync_key_material(&SyncKeyMaterial::new(
                Zeroizing::new([0x64; 32]),
                [0x65; 16],
                1,
                [0x66; 24],
                [0x67; 48],
            ))
            .unwrap();
        if active {
            store.begin_sync_baseline().unwrap();
            assert!(store.process_sync_baseline_batch(8).unwrap().complete);
        }
        let old_operations = store.list_sync_operations(DEVICE, 1, 0, 16).unwrap();
        assert_eq!(old_operations.len(), if active { 2 } else { 0 });
        let mut fixture = Self {
            store,
            path,
            key,
            active,
            events,
            old_operations,
        };
        let corrupt_id = fixture.events[0].id.unwrap();
        fixture.edit_database(|conn| {
            assert_eq!(
                conn.execute(
                    "UPDATE events SET data = ?1 WHERE id = ?2",
                    params![CORRUPT_DATA, corrupt_id]
                )
                .unwrap(),
                1
            );
        });
        fixture
    }

    fn edit_database(&mut self, action: impl FnOnce(&Connection)) {
        self.store.lock().unwrap();
        let conn = Connection::open(&self.path).unwrap();
        conn.pragma_update(None, "key", self.key.as_str()).unwrap();
        action(&conn);
        drop(conn);
        self.store =
            Datastore::open_encrypted(self.path.to_string_lossy().into_owned(), self.key.clone())
                .unwrap();
    }

    fn assert_deletion(&mut self, deleted: &[i64]) {
        let operations = self.store.list_sync_operations(DEVICE, 1, 0, 16).unwrap();
        let acknowledgements = self
            .store
            .list_local_sync_tombstone_acknowledgements()
            .unwrap();
        let before = self.old_operations.len();
        assert_eq!(
            operations.len(),
            before + if self.active { deleted.len() } else { 0 }
        );
        assert_eq!(&operations[..before], self.old_operations.as_slice());
        assert_eq!(
            acknowledgements.len(),
            if self.active { deleted.len() } else { 0 }
        );
        let mut tombstoned_ids = Vec::new();
        for (index, stored) in operations.iter().enumerate().skip(before) {
            let operation: SyncOperationV1 = serde_json::from_str(&stored.operation_json).unwrap();
            operation.validate().unwrap();
            assert_eq!(stored.counter, (index + 1) as u64);
            assert_eq!(serde_json::to_value(&operation.kind).unwrap(), "tombstone");
            assert!(operation.fields.is_empty());
            assert!(operation.bucket_descriptor.is_none());
            assert_eq!(operation.origin_device_id, URL_SAFE_NO_PAD.encode(DEVICE));
            let id = operation.local_event_id.unwrap();
            tombstoned_ids.push(id as i64);
            let origin: SyncOperationV1 = self
                .old_operations
                .iter()
                .map(|old| serde_json::from_str::<SyncOperationV1>(&old.operation_json).unwrap())
                .find(|old| old.local_event_id == Some(id))
                .unwrap();
            assert_eq!(operation.sync_bucket_id, origin.sync_bucket_id);
            assert!(acknowledgements
                .iter()
                .any(|ack| ack.origin_device_id == operation.origin_device_id
                    && ack.local_event_id == id
                    && ack.tombstone_counter == stored.counter));
            let state = self
                .store
                .sync_tombstone_ack_state(DEVICE, id, stored.counter)
                .unwrap();
            assert_eq!(state.active_device_ids, vec![DEVICE]);
            assert_eq!(state.acknowledged_device_ids, vec![DEVICE]);
        }
        assert!(!operations
            .iter()
            .any(|op| op.operation_json.contains("synthetic-corrupt-payload")));
        if self.active {
            tombstoned_ids.sort_unstable();
            let mut expected = deleted.to_vec();
            expected.sort_unstable();
            assert_eq!(tombstoned_ids, expected);
        }
        let active = self.active;
        let event_ids: Vec<_> = self.events.iter().map(|event| event.id.unwrap()).collect();
        self.edit_database(|conn| {
            for id in &event_ids {
                let rows: i64 = conn.query_row("SELECT COUNT(*) FROM events WHERE id = ?1", [id], |row| row.get(0)).unwrap();
                assert_eq!(rows, if deleted.contains(id) { 0 } else { 1 });
                if active {
                    let mapped_deleted: bool = conn.query_row(
                        "SELECT deleted FROM sync_event_mappings WHERE origin_device_id = ?1 AND origin_event_id = ?2",
                        params![&DEVICE[..], id], |row| row.get(0),
                    ).unwrap();
                    assert_eq!(mapped_deleted, deleted.contains(id));
                }
            }
            let counter: i64 = conn.query_row("SELECT COALESCE(MAX(last_counter),0) FROM sync_device_counters", [], |row| row.get(0)).unwrap();
            assert_eq!(counter, if active { 2 + deleted.len() as i64 } else { 0 });
        });
        self.store
            .set_key_value("corrupt-deletion-worker-health", "usable")
            .unwrap();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.store.lock();
        let _ = std::fs::remove_file(&self.path);
    }
}

#[test]
fn delete_corrupt_event_by_id_preserves_healthy_event_and_journals_origin_tombstone() {
    for active in [true, false] {
        let mut f = Fixture::new("corrupt-by-id", active);
        let id = f.events[0].id.unwrap();
        f.store.delete_events_by_id(BUCKET, vec![id]).unwrap();
        assert_eq!(
            f.store.get_events(BUCKET, None, None, None).unwrap(),
            vec![f.events[1].clone()]
        );
        f.assert_deletion(&[id]);
        assert_eq!(
            f.store.get_events(BUCKET, None, None, None).unwrap(),
            vec![f.events[1].clone()]
        );
        assert!(f.store.get_bucket(OTHER_BUCKET).is_ok());
    }
}

#[test]
fn delete_corrupt_event_in_range_preserves_healthy_event_and_journals_origin_tombstone() {
    for active in [true, false] {
        let mut f = Fixture::new("corrupt-range", active);
        let corrupt = &f.events[0];
        assert_eq!(
            f.store
                .delete_events_in_range(
                    BUCKET,
                    corrupt.timestamp - Duration::seconds(1),
                    corrupt.timestamp + Duration::seconds(2),
                )
                .unwrap(),
            1
        );
        let id = corrupt.id.unwrap();
        assert_eq!(
            f.store.get_events(BUCKET, None, None, None).unwrap(),
            vec![f.events[1].clone()]
        );
        f.assert_deletion(&[id]);
        assert_eq!(
            f.store.get_events(BUCKET, None, None, None).unwrap(),
            vec![f.events[1].clone()]
        );
        assert!(f.store.get_bucket(OTHER_BUCKET).is_ok());
    }
}

#[test]
fn delete_bucket_containing_corrupt_event_preserves_other_bucket_and_journals_both_origins() {
    for active in [true, false] {
        let mut f = Fixture::new("corrupt-bucket", active);
        let other_before = serde_json::to_value(f.store.get_bucket(OTHER_BUCKET).unwrap()).unwrap();
        let deleted: Vec<_> = f.events.iter().map(|event| event.id.unwrap()).collect();
        f.store.delete_bucket(BUCKET).unwrap();
        assert!(matches!(
            f.store.get_bucket(BUCKET),
            Err(DatastoreError::NoSuchBucket(_))
        ));
        assert_eq!(
            serde_json::to_value(f.store.get_bucket(OTHER_BUCKET).unwrap()).unwrap(),
            other_before
        );
        f.assert_deletion(&deleted);
        assert!(matches!(
            f.store.get_bucket(BUCKET),
            Err(DatastoreError::NoSuchBucket(_))
        ));
        assert_eq!(
            serde_json::to_value(f.store.get_bucket(OTHER_BUCKET).unwrap()).unwrap(),
            other_before
        );
    }
}

#[test]
fn failed_tombstone_storage_preserves_rows_journal_and_counters_then_retry_succeeds() {
    let mut f = Fixture::new("corrupt-delete-rollback", true);
    let healthy_id = f.events[1].id.unwrap();
    f.edit_database(|conn| {
        conn.execute_batch("CREATE TRIGGER reject_tombstone BEFORE INSERT ON sync_operations
            WHEN NEW.counter = 3 BEGIN SELECT RAISE(ABORT, 'injected tombstone storage failure'); END;").unwrap();
    });
    let error = f
        .store
        .delete_events_by_id(BUCKET, vec![healthy_id])
        .unwrap_err();
    assert!(
        matches!(error, DatastoreError::InternalError(ref message) if message == "Could not store sync operation")
    );
    assert_eq!(f.store.get_event(BUCKET, healthy_id).unwrap(), f.events[1]);
    assert_eq!(
        f.store.list_sync_operations(DEVICE, 1, 0, 16).unwrap(),
        f.old_operations
    );
    assert!(f
        .store
        .list_local_sync_tombstone_acknowledgements()
        .unwrap()
        .is_empty());
    let corrupt_id = f.events[0].id.unwrap();
    f.edit_database(|conn| {
        assert_eq!(
            conn.query_row::<i64, _, _>("SELECT COUNT(*) FROM events", [], |row| row.get(0))
                .unwrap(),
            2
        );
        assert_eq!(
            conn.query_row::<i64, _, _>(
                "SELECT last_counter FROM sync_device_counters",
                [],
                |row| row.get(0)
            )
            .unwrap(),
            2
        );
        assert_eq!(
            conn.query_row::<i64, _, _>(
                "SELECT COUNT(*) FROM sync_event_mappings WHERE deleted = 1",
                [],
                |row| row.get(0)
            )
            .unwrap(),
            0
        );
        assert_eq!(
            conn.query_row::<String, _, _>(
                "SELECT data FROM events WHERE id = ?1",
                [corrupt_id],
                |row| row.get(0)
            )
            .unwrap(),
            CORRUPT_DATA
        );
        conn.execute_batch("DROP TRIGGER reject_tombstone").unwrap();
    });
    f.store
        .delete_events_by_id(BUCKET, vec![healthy_id])
        .unwrap();
    f.assert_deletion(&[healthy_id]);
    f.edit_database(|conn| {
        assert_eq!(
            conn.query_row::<String, _, _>(
                "SELECT data FROM events WHERE id = ?1",
                [corrupt_id],
                |row| row.get(0)
            )
            .unwrap(),
            CORRUPT_DATA
        );
    });
}
