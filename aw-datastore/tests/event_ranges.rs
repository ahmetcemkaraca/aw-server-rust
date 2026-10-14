use aw_datastore::{Datastore, DatastoreError, DatastoreInstance};
use aw_models::{Bucket, Event};
use chrono::{DateTime, Duration, Utc};
use serde_json::json;

fn bucket() -> Bucket {
    Bucket {
        bid: None,
        id: "synthetic-event-ranges".into(),
        _type: "test".into(),
        client: "range-test".into(),
        hostname: "synthetic".into(),
        created: None,
        data: Default::default(),
        metadata: Default::default(),
        events: None,
        last_updated: None,
    }
}

fn event(timestamp: DateTime<Utc>, duration: Duration) -> Event {
    Event::new(
        timestamp,
        duration,
        json!({"app": "synthetic"}).as_object().unwrap().clone(),
    )
}

fn valid_event() -> Event {
    event(
        "2026-01-01T00:00:00Z".parse().unwrap(),
        Duration::seconds(1),
    )
}

fn invalid_events() -> Vec<Event> {
    vec![
        event("1500-01-01T00:00:00Z".parse().unwrap(), Duration::zero()),
        event(
            DateTime::from_timestamp_nanos(i64::MAX),
            Duration::nanoseconds(1),
        ),
        event(valid_event().timestamp, Duration::nanoseconds(-1)),
        event(
            valid_event().timestamp,
            Duration::seconds(i64::MAX / 1_000_000_000 + 1),
        ),
    ]
}

#[test]
fn event_ranges_invalid_insert_rolls_back_batch_and_preserves_worker() {
    let ds = Datastore::new_in_memory(false);
    let bucket = bucket();
    ds.create_bucket(&bucket).unwrap();
    ds.insert_events(&bucket.id, &[valid_event()]).unwrap();
    let before = ds.get_events(&bucket.id, None, None, None).unwrap();
    let metadata = ds.get_bucket(&bucket.id).unwrap().metadata;
    for invalid in invalid_events() {
        let candidate = event(
            valid_event().timestamp + Duration::seconds(10),
            Duration::seconds(1),
        );
        assert!(matches!(
            ds.insert_events(&bucket.id, &[candidate, invalid]),
            Err(DatastoreError::InvalidTimeRange)
        ));
        assert_eq!(ds.get_events(&bucket.id, None, None, None).unwrap(), before);
        let after = ds.get_bucket(&bucket.id).unwrap().metadata;
        assert_eq!(after.start, metadata.start);
        assert_eq!(after.end, metadata.end);
        ds.set_key_value("range-worker-health", "usable").unwrap();
    }
    ds.lock().unwrap();
}

#[test]
fn event_ranges_invalid_replacement_preserves_original_and_metadata() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    let mut ds = DatastoreInstance::new(&conn, true, false).unwrap();
    let bucket = bucket();
    ds.create_bucket(&conn, bucket.clone()).unwrap();
    let inserted = ds
        .insert_events(&conn, &bucket.id, vec![valid_event()])
        .unwrap();
    let original = &inserted[0];
    let metadata = ds.get_bucket(&bucket.id).unwrap().metadata;
    for invalid in invalid_events() {
        assert!(matches!(
            ds.replace_last_event(&conn, &bucket.id, original.id.unwrap(), &invalid),
            Err(DatastoreError::InvalidTimeRange)
        ));
        assert_eq!(
            ds.get_event(&conn, &bucket.id, original.id.unwrap())
                .unwrap(),
            *original
        );
        let after = ds.get_bucket(&bucket.id).unwrap().metadata;
        assert_eq!(after.start, metadata.start);
        assert_eq!(after.end, metadata.end);
    }
}

#[test]
fn event_ranges_invalid_bucket_creation_leaves_no_bucket_or_worker_failure() {
    let ds = Datastore::new_in_memory(false);
    let mut bucket = bucket();
    bucket.events = Some(aw_models::TryVec::new(vec![
        valid_event(),
        event(
            DateTime::from_timestamp_nanos(i64::MAX),
            Duration::nanoseconds(1),
        ),
    ]));
    assert!(matches!(
        ds.create_bucket(&bucket),
        Err(DatastoreError::InvalidTimeRange)
    ));
    assert!(ds.get_buckets().unwrap().is_empty());
    assert!(matches!(
        ds.get_bucket(&bucket.id),
        Err(DatastoreError::NoSuchBucket(_))
    ));
    ds.set_key_value("create-range-worker-health", "usable")
        .unwrap();
    ds.lock().unwrap();
}

#[test]
fn event_ranges_invalid_heartbeat_preserves_worker_and_cached_event() {
    let ds = Datastore::new_in_memory(false);
    let bucket = bucket();
    ds.create_bucket(&bucket).unwrap();
    let first = ds.heartbeat(&bucket.id, valid_event(), 10.0).unwrap();
    let original = ds
        .heartbeat(
            &bucket.id,
            event(first.timestamp + Duration::seconds(1), Duration::zero()),
            10.0,
        )
        .unwrap();
    assert_eq!(original.id, first.id);
    for invalid in invalid_events() {
        assert!(matches!(
            ds.heartbeat(&bucket.id, invalid, 10.0),
            Err(DatastoreError::InvalidTimeRange)
        ));
        assert_eq!(
            ds.get_events(&bucket.id, None, None, None).unwrap(),
            vec![original.clone()]
        );
    }
    let next = event(original.timestamp + Duration::seconds(2), Duration::zero());
    let merged = ds.heartbeat(&bucket.id, next, 10.0).unwrap();
    assert_eq!(merged.id, original.id);
    assert_eq!(merged.duration, Duration::seconds(2));
    assert_eq!(ds.get_event_count(&bucket.id, None, None).unwrap(), 1);
    ds.lock().unwrap();
}

#[test]
fn event_ranges_valid_heartbeats_with_unrepresentable_merge_remain_separate() {
    let ds = Datastore::new_in_memory(false);
    let bucket = bucket();
    ds.create_bucket(&bucket).unwrap();
    let first = event(
        DateTime::from_timestamp_nanos(-i64::MAX),
        Duration::nanoseconds(i64::MAX),
    );
    let second = event(DateTime::from_timestamp_nanos(0), Duration::nanoseconds(1));
    let first = ds.heartbeat(&bucket.id, first, 0.0).unwrap();
    let second = ds.heartbeat(&bucket.id, second, 0.0).unwrap();
    assert_ne!(first.id, second.id);
    assert_eq!(
        ds.get_events(&bucket.id, None, None, None).unwrap(),
        vec![second, first]
    );
    assert_eq!(ds.get_event_count(&bucket.id, None, None).unwrap(), 2);
    ds.lock().unwrap();
}
