use std::collections::HashMap;

use aw_datastore::Datastore;
use aw_models::{Bucket, BucketsExport, Event, TryVec};
use chrono::{Duration, Utc};
use serde_json::{json, Map};

fn bucket(id: &str, events: Vec<Event>) -> Bucket {
    Bucket {
        bid: None,
        id: id.into(),
        _type: "test".into(),
        client: "import-test".into(),
        hostname: "test-host".into(),
        created: None,
        data: Map::new(),
        metadata: Default::default(),
        events: Some(TryVec::new(events)),
        last_updated: None,
    }
}

fn export(buckets: Vec<Bucket>) -> BucketsExport {
    BucketsExport {
        buckets: buckets.into_iter().map(|bucket| (bucket.id.clone(), bucket)).collect::<HashMap<_, _>>(),
    }
}

fn event(duration: Duration) -> Event {
    Event::new(Utc::now(), duration, json!({"app":"Editor", "title":"private title"}).as_object().unwrap().clone())
}

#[test]
fn preview_counts_duplicate_events_without_writing_and_imports_once() {
    let store = Datastore::new_in_memory(false);
    store.enable_capture_policy().unwrap();
    let duplicate = event(Duration::seconds(1));
    let source = export(vec![bucket("aw-watcher-window_import", vec![duplicate.clone(), duplicate])]);

    let preview = store.preview_import_buckets(source.clone()).unwrap();
    assert_eq!(preview.buckets_created, 1);
    assert_eq!(preview.events_imported, 1);
    assert_eq!(preview.events_skipped, 1);
    assert_eq!(preview.events_changed, 1);
    assert!(store.get_buckets().unwrap().is_empty());

    let result = store.import_buckets(source.clone()).unwrap();
    assert_eq!(result, preview);
    assert_eq!(store.get_event_count("aw-watcher-window_import", None, None).unwrap(), 1);
    assert!(!store.get_events("aw-watcher-window_import", None, None, None).unwrap()[0].data.contains_key("title"));

    let repeated = store.preview_import_buckets(source).unwrap();
    assert_eq!(repeated.buckets_merged, 1);
    assert_eq!(repeated.events_imported, 0);
    assert_eq!(repeated.events_skipped, 2);
}

#[test]
fn invalid_bucket_leaves_all_source_buckets_unwritten() {
    let store = Datastore::new_in_memory(false);
    let unrepresentable = Duration::seconds(i64::MAX / 1_000_000_000 + 1);
    let source = export(vec![
        bucket("valid.bucket", vec![event(Duration::seconds(1))]),
        bucket("invalid.bucket", vec![event(unrepresentable)]),
    ]);

    assert!(store.import_buckets(source).is_err());
    assert!(store.get_buckets().unwrap().is_empty());
}
