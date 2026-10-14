#![cfg(any(feature = "encryption", feature = "encryption-vendored"))]

use aw_datastore::{Datastore, DatastoreError};
use aw_models::{Bucket, Event};
use chrono::{DateTime, Duration};
use rusqlite::Connection;
use serde_json::json;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const MARKER: &str = "SYNTHETIC_STORED_PRIVATE_VALUE";

struct Fixture {
    store: Datastore,
    root: PathBuf,
    good_id: i64,
    bad_id: i64,
}

impl Fixture {
    fn new(corrupt: impl FnOnce(&Connection, i64)) -> Self {
        let root = std::env::temp_dir().join(format!(
            "peak-stored-event-integrity-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("vault.db").to_string_lossy().into_owned();
        let key = "a".repeat(64);
        let store = Datastore::open_encrypted(path.clone(), key.clone()).unwrap();
        store
            .create_bucket(&Bucket {
                bid: None,
                id: "synthetic".into(),
                _type: "test".into(),
                client: "integrity-test".into(),
                hostname: "synthetic".into(),
                created: None,
                data: Default::default(),
                metadata: Default::default(),
                events: None,
                last_updated: None,
            })
            .unwrap();
        let start = "2026-01-01T00:00:00Z".parse().unwrap();
        let inserted = store
            .insert_events(
                "synthetic",
                &[
                Event::new(
                    start + Duration::seconds(2),
                        Duration::seconds(1),
                        json!({"app":"healthy"}).as_object().unwrap().clone(),
                    ),
                Event::new(
                    start,
                        Duration::seconds(1),
                        json!({"app":"synthetic"}).as_object().unwrap().clone(),
                    ),
                ],
            )
            .unwrap();
        let good_id = inserted[0].id.unwrap();
        let bad_id = inserted[1].id.unwrap();
        store.lock().unwrap();
        {
            let conn = Connection::open(&path).unwrap();
            conn.pragma_update(None, "key", &key).unwrap();
            corrupt(&conn, bad_id);
        }
        let store = Datastore::open_encrypted(path, key).unwrap();
        Self {
            store,
            root,
            good_id,
            bad_id,
        }
    }

    fn rejected<T: std::fmt::Debug>(&self, result: Result<T, DatastoreError>) {
        let error = result.expect_err("a corrupt selected row must not become a successful result");
        assert!(!format!("{error:?}").contains(MARKER));
        assert_eq!(
            self.store
                .get_event("synthetic", self.good_id)
                .unwrap()
                .data["app"],
            "healthy"
        );
        self.store
            .set_key_value("integrity-worker-health", "usable")
            .unwrap();
        assert_eq!(
            self.store.get_key_value("integrity-worker-health").unwrap(),
            "usable"
        );
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.store.lock();
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn stored_event_wrong_json_type_single_read_keeps_worker_and_error_private() {
    let fixture = Fixture::new(|conn, id| {
        conn.execute(
            "UPDATE events SET data = ?1 WHERE id = ?2",
            (serde_json::to_string(MARKER).unwrap(), id),
        )
        .unwrap();
    });
    fixture.rejected(fixture.store.get_event("synthetic", fixture.bad_id));
}

#[test]
fn stored_event_malformed_json_bulk_reads_fail_without_partial_results() {
    let fixture = Fixture::new(|conn, id| {
        conn.execute(
            "UPDATE events SET data = ?1 WHERE id = ?2",
            (format!("{{{MARKER}"), id),
        )
        .unwrap();
    });
    fixture.rejected(fixture.store.get_events("synthetic", None, None, None));
    fixture.rejected(
        fixture
            .store
            .get_events_unclipped("synthetic", None, None, None),
    );
}

#[test]
fn stored_event_non_text_payload_is_not_silently_skipped() {
    let fixture = Fixture::new(|conn, id| {
        conn.execute("UPDATE events SET data = x'ff' WHERE id = ?1", [id])
            .unwrap();
    });
    fixture.rejected(fixture.store.get_events("synthetic", None, None, None));
    fixture.rejected(
        fixture
            .store
            .get_events_unclipped("synthetic", None, None, None),
    );
}

#[test]
fn stored_event_negative_duration_is_rejected_on_single_and_bulk_reads() {
    let fixture = Fixture::new(|conn, id| {
        conn.execute(
            "UPDATE events SET endtime = starttime - 1 WHERE id = ?1",
            [id],
        )
        .unwrap();
    });
    fixture.rejected(fixture.store.get_event("synthetic", fixture.bad_id));
    fixture.rejected(fixture.store.get_events("synthetic", None, None, None));
    fixture.rejected(
        fixture
            .store
            .get_events_unclipped("synthetic", None, None, None),
    );
}

#[test]
fn stored_event_overflow_is_rejected_before_clipping_can_hide_it() {
    let fixture = Fixture::new(|conn, id| {
        conn.execute(
            "UPDATE events SET starttime = ?1, endtime = ?2 WHERE id = ?3",
            (i64::MIN, i64::MAX, id),
        )
        .unwrap();
    });
    fixture.rejected(fixture.store.get_events(
        "synthetic",
        Some(DateTime::from_timestamp_nanos(0)),
        Some(DateTime::from_timestamp_nanos(2)),
        None,
    ));
    fixture.rejected(fixture.store.get_event("synthetic", fixture.bad_id));
    fixture.rejected(
        fixture
            .store
            .get_events_unclipped("synthetic", None, None, None),
    );
}
