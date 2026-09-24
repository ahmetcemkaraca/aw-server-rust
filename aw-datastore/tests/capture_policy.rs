use aw_datastore::Datastore;
use aw_models::{Bucket, BucketMetadata, Event, TryVec};
use chrono::{Duration, Utc};
use serde_json::json;

fn bucket() -> Bucket {
    Bucket { bid: None, id: "aw-watcher-window_synthetic".into(), _type: "currentwindow".into(),
             client: "test".into(), hostname: "test".into(), created: None,
             data: Default::default(), metadata: BucketMetadata::default(), events: None, last_updated: None }
}

fn event() -> Event {
    Event::new(Utc::now(), Duration::zero(), json!({"app":"Editor","title":"private title","path":"/private/file"}).as_object().unwrap().clone())
}

#[test]
fn consent_pause_and_replay_are_enforced_for_every_capture_write() {
    let store = Datastore::new_in_memory(false);
    let mut policy = store.enable_capture_policy().unwrap();
    let bucket = bucket();
    store.create_bucket(&bucket).unwrap();
    assert!(store.insert_events(&bucket.id, &[event()]).unwrap().is_empty());
    policy.recording = true;
    policy = store.set_capture_policy(policy).unwrap();
    let old = event();
    let written = store.insert_events(&bucket.id, &[old.clone()]).unwrap();
    assert_eq!(written[0].data, json!({"app":"Editor"}).as_object().unwrap().clone());
    policy.recording = false;
    policy = store.set_capture_policy(policy).unwrap();
    assert!(store.heartbeat(&bucket.id, event(), 2.0).unwrap().data.is_empty());
    assert!(store.insert_events(&bucket.id, &[event()]).unwrap().is_empty());
    policy.recording = true;
    store.set_capture_policy(policy).unwrap();
    assert!(store.insert_events(&bucket.id, &[old]).unwrap().is_empty());
    store.heartbeat(&bucket.id, event(), 100.0).unwrap();
    assert_eq!(store.get_events(&bucket.id, None, None, None).unwrap().len(), 2,
               "Even a large pulse interval must not merge across a pause");
    let mut resumed = event();
    resumed.data.insert("capture_break".into(), true.into());
    store.heartbeat(&bucket.id, resumed, 100.0).unwrap();
    let events = store.get_events(&bucket.id, None, None, None).unwrap();
    assert_eq!(events.len(), 3, "Collector-side exclusion must break the merge chain too");
    assert!(events.iter().all(|event| !event.data.contains_key("capture_break")));
    let mut stale_resume = store.capture_policy().unwrap();
    let paused = store.pause_capture().unwrap();
    stale_resume.recording = true;
    assert!(store.set_capture_policy(stale_resume).is_err(), "An in-flight older save cannot undo panic pause");
    assert!(!store.capture_policy().unwrap().recording);
    assert_eq!(store.capture_policy().unwrap().revision, paused.revision);
    store.close();
}

#[test]
fn explicit_import_works_while_paused_but_cannot_bypass_minimization() {
    let store = Datastore::new_in_memory(false);
    store.enable_capture_policy().unwrap();
    let mut bucket = bucket();
    let mut old = event();
    old.timestamp = Utc::now() - Duration::days(1);
    bucket.events = Some(TryVec::new(vec![old.clone()]));
    store.create_bucket(&bucket).unwrap();
    let imported = store.get_events(&bucket.id, None, None, None).unwrap();
    assert_eq!(imported.len(), 1);
    assert!(!imported[0].data.contains_key("title"));
    assert!(!store.import_events(&bucket.id, &[old]).unwrap()[0].data.contains_key("path"));
    assert!(store.set_key_value("peakactivity.capture_policy", "{}").is_err());
    store.close();
}

#[test]
fn explicit_stopwatch_remains_available_while_automatic_capture_is_off() {
    let store = Datastore::new_in_memory(false);
    let policy = store.enable_capture_policy().unwrap();
    assert!(!policy.recording);
    let mut bucket = bucket();
    bucket.id = "aw-stopwatch".into();
    bucket._type = "general.stopwatch".into();
    store.create_bucket(&bucket).unwrap();
    let event = Event::new(Utc::now(), Duration::zero(), json!({"label":"Planning", "running":true}).as_object().unwrap().clone());

    let stored = store.heartbeat(&bucket.id, event, 1.0).unwrap();
    assert_eq!(stored.data, json!({"label":"Planning", "running":true}).as_object().unwrap().clone());
    assert!(!store.capture_policy().unwrap().recording);
    store.close();
}
