use aw_datastore::Datastore;
use aw_models::{Bucket, Event, TryVec};
use chrono::{Duration, Utc};
use serde_json::json;

#[test]
fn raw_retention_removes_only_events_before_the_cutoff() {
    let store = Datastore::new_in_memory(false);
    store.enable_capture_policy().unwrap();
    let now = Utc::now();
    let events = vec![
        Event::new(now - Duration::days(31), Duration::seconds(10), json!({"app":"Editor"}).as_object().unwrap().clone()),
        Event::new(now - Duration::days(1), Duration::seconds(10), json!({"app":"Editor"}).as_object().unwrap().clone()),
    ];
    let bucket = Bucket {
        bid: None,
        id: "aw-watcher-window_retention".into(),
        _type: "currentwindow".into(),
        client: "test".into(),
        hostname: "test".into(),
        created: None,
        data: Default::default(),
        metadata: Default::default(),
        events: Some(TryVec::new(events)),
        last_updated: None,
    };
    store.create_bucket(&bucket).unwrap();

    assert_eq!(store.apply_raw_retention(30, now).unwrap(), 1);
    assert_eq!(store.get_event_count(&bucket.id, None, None).unwrap(), 1);
    assert_eq!(store.apply_raw_retention(0, now).unwrap(), 0);
    assert!(store.apply_raw_retention(3651, now).is_err());
    assert_eq!(store.get_event_count(&bucket.id, None, None).unwrap(), 1);
}
