use aw_datastore::{DatastoreError, DatastoreInstance};
use aw_models::{Bucket, Event, TryVec};
use chrono::{Duration, Utc};
use rusqlite::Connection;
use serde_json::json;

fn bucket(id: &str, offsets: &[i64]) -> Bucket {
    let start = "2026-01-01T00:00:00Z"
        .parse::<chrono::DateTime<Utc>>()
        .unwrap();
    Bucket {
        bid: None,
        id: id.into(),
        _type: "test".into(),
        client: "atomic-test".into(),
        hostname: "synthetic".into(),
        created: None,
        data: Default::default(),
        metadata: Default::default(),
        events: Some(TryVec::new(
            offsets
                .iter()
                .map(|offset| {
                    Event::new(
                        start + Duration::seconds(*offset),
                        Duration::seconds(1),
                        json!({"app": "synthetic"}).as_object().unwrap().clone(),
                    )
                })
                .collect(),
        )),
        last_updated: None,
    }
}

fn count(conn: &Connection, sql: &str) -> i64 {
    conn.query_row(sql, [], |row| row.get(0)).unwrap()
}

fn reject_second_event(conn: &Connection) {
    conn.execute_batch(
        "CREATE TRIGGER reject_second_event BEFORE INSERT ON events
         WHEN (SELECT name FROM buckets WHERE id = NEW.bucketrow) = 'new-bucket'
           AND (SELECT COUNT(*) FROM events WHERE bucketrow = NEW.bucketrow) = 1
         BEGIN SELECT RAISE(ABORT, 'injected second event failure'); END;",
    )
    .unwrap();
}

#[test]
fn failed_attached_event_insert_leaves_no_bucket_and_same_id_can_be_retried() {
    let conn = Connection::open_in_memory().unwrap();
    let mut ds = DatastoreInstance::new(&conn, true, false).unwrap();
    ds.create_bucket(&conn, bucket("old-bucket", &[0])).unwrap();
    let before = serde_json::to_value(ds.get_buckets()).unwrap();
    let old_events = ds
        .get_events(&conn, "old-bucket", None, None, None)
        .unwrap();
    reject_second_event(&conn);

    assert!(matches!(
        ds.create_bucket(&conn, bucket("new-bucket", &[10, 20])),
        Err(DatastoreError::InternalError(_))
    ));
    assert_eq!(
        count(
            &conn,
            "SELECT COUNT(*) FROM buckets WHERE name = 'new-bucket'"
        ),
        0
    );
    assert!(matches!(
        ds.get_bucket("new-bucket"),
        Err(DatastoreError::NoSuchBucket(_))
    ));
    assert_eq!(serde_json::to_value(ds.get_buckets()).unwrap(), before);
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM events"), 1);
    assert_eq!(
        ds.get_events(&conn, "old-bucket", None, None, None)
            .unwrap(),
        old_events
    );

    conn.execute_batch("DROP TRIGGER reject_second_event")
        .unwrap();
    ds.create_bucket(&conn, bucket("new-bucket", &[10, 20]))
        .unwrap();
    assert_eq!(
        ds.get_events(&conn, "new-bucket", None, None, None)
            .unwrap()
            .len(),
        2
    );
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM buckets"), 2);
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM events"), 3);
    assert_eq!(
        ds.get_events(&conn, "old-bucket", None, None, None)
            .unwrap(),
        old_events
    );
}

#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
#[test]
fn failed_attached_event_journal_preserves_old_sync_state_and_retry_counters() {
    use aw_datastore::{SyncDeviceIdentity, SyncKeyMaterial};
    use zeroize::Zeroizing;

    let conn = Connection::open_in_memory().unwrap();
    let mut ds = DatastoreInstance::new(&conn, true, false).unwrap();
    ds.create_bucket(&conn, bucket("old-bucket", &[0])).unwrap();
    let device = [0x41; 16];
    ds.create_sync_device_identity(
        &conn,
        &SyncDeviceIdentity::new(
            device,
            Zeroizing::new([0x42; 32]),
            Zeroizing::new([0x43; 32]),
        ),
    )
    .unwrap();
    ds.install_sync_key_material(
        &conn,
        &SyncKeyMaterial::new(
            Zeroizing::new([0x44; 32]),
            [0x45; 16],
            1,
            [0x46; 24],
            [0x47; 48],
        ),
    )
    .unwrap();
    ds.begin_sync_baseline(&conn).unwrap();
    assert!(ds.process_sync_baseline_batch(&conn, 1).unwrap().complete);
    let before = serde_json::to_value(ds.get_buckets()).unwrap();
    let old_events = ds
        .get_events(&conn, "old-bucket", None, None, None)
        .unwrap();
    let old_operations = ds.list_sync_operations(&conn, &device, 1, 0, 16).unwrap();
    assert_eq!(old_operations.len(), 1);
    conn.execute_batch(
        "CREATE TRIGGER reject_second_journal BEFORE INSERT ON sync_operations
         WHEN (SELECT COUNT(*) FROM sync_operations) = 2
         BEGIN SELECT RAISE(ABORT, 'injected second journal failure'); END;",
    )
    .unwrap();

    assert!(matches!(
        ds.create_bucket(&conn, bucket("new-bucket", &[10, 20])),
        Err(DatastoreError::InternalError(_))
    ));
    assert_eq!(
        count(
            &conn,
            "SELECT COUNT(*) FROM buckets WHERE name = 'new-bucket'"
        ),
        0
    );
    assert!(matches!(
        ds.get_bucket("new-bucket"),
        Err(DatastoreError::NoSuchBucket(_))
    ));
    assert_eq!(serde_json::to_value(ds.get_buckets()).unwrap(), before);
    assert_eq!(
        ds.get_events(&conn, "old-bucket", None, None, None)
            .unwrap(),
        old_events
    );
    assert_eq!(
        ds.list_sync_operations(&conn, &device, 1, 0, 16).unwrap(),
        old_operations
    );
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM events"), 1);
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM sync_bucket_mappings"), 1);
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM sync_event_mappings"), 1);
    assert_eq!(
        count(&conn, "SELECT last_counter FROM sync_device_counters"),
        1
    );

    conn.execute_batch("DROP TRIGGER reject_second_journal")
        .unwrap();
    ds.create_bucket(&conn, bucket("new-bucket", &[10, 20]))
        .unwrap();
    assert_eq!(
        ds.get_events(&conn, "new-bucket", None, None, None)
            .unwrap()
            .len(),
        2
    );
    let operations = ds.list_sync_operations(&conn, &device, 1, 0, 16).unwrap();
    assert_eq!(
        operations
            .iter()
            .map(|operation| operation.counter)
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert_eq!(operations[0], old_operations[0]);
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM sync_bucket_mappings"), 2);
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM sync_event_mappings"), 3);
    assert_eq!(
        count(&conn, "SELECT last_counter FROM sync_device_counters"),
        3
    );
}

#[test]
fn failed_bucket_creation_preserves_its_callers_outer_savepoint() {
    let conn = Connection::open_in_memory().unwrap();
    let mut ds = DatastoreInstance::new(&conn, true, false).unwrap();
    reject_second_event(&conn);
    conn.execute_batch("SAVEPOINT enclosing_import").unwrap();
    ds.insert_key_value(&conn, "outer-work", "retained")
        .unwrap();

    assert!(matches!(
        ds.create_bucket(&conn, bucket("new-bucket", &[10, 20])),
        Err(DatastoreError::InternalError(_))
    ));
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM buckets"), 0);
    assert!(ds.get_buckets().is_empty());
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM events"), 0);
    assert_eq!(ds.get_key_value(&conn, "outer-work").unwrap(), "retained");
    conn.execute_batch(
        "ROLLBACK TO SAVEPOINT enclosing_import; RELEASE SAVEPOINT enclosing_import",
    )
    .unwrap();
    ds.reload_buckets(&conn).unwrap();
    assert!(matches!(
        ds.get_key_value(&conn, "outer-work"),
        Err(DatastoreError::NoSuchKey(_))
    ));
    conn.execute_batch("DROP TRIGGER reject_second_event")
        .unwrap();
    ds.create_bucket(&conn, bucket("new-bucket", &[10, 20]))
        .unwrap();
    assert_eq!(
        ds.get_events(&conn, "new-bucket", None, None, None)
            .unwrap()
            .len(),
        2
    );
}
