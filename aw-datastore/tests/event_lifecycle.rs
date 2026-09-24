use aw_datastore::Datastore;
use aw_models::{Bucket, Event, TryVec};
use chrono::{Duration, Utc};
use serde_json::json;

fn make_bucket(id: &str, events: Vec<Event>) -> Bucket {
    Bucket {
        bid: None,
        id: id.into(),
        _type: "currentwindow".into(),
        client: "test".into(),
        hostname: "test".into(),
        created: None,
        data: Default::default(),
        metadata: Default::default(),
        events: Some(TryVec::new(events)),
        last_updated: None,
    }
}

#[test]
fn correction_records_changed_fields_and_range_delete_removes_both() {
    let store = Datastore::new_in_memory(false);
    let mut policy = store.enable_capture_policy().unwrap();
    policy.titles = true;
    store.set_capture_policy(policy).unwrap();

    let timestamp = Utc::now() - Duration::days(1);
    let initial = Event::new(timestamp, Duration::seconds(30), json!({
        "app": "Editor",
        "title": "original title"
    }).as_object().unwrap().clone());
    let bucket = Bucket {
        bid: None,
        id: "aw-watcher-window_edit".into(),
        _type: "currentwindow".into(),
        client: "test".into(),
        hostname: "test".into(),
        created: None,
        data: Default::default(),
        metadata: Default::default(),
        events: Some(TryVec::new(vec![initial])),
        last_updated: None,
    };
    store.create_bucket(&bucket).unwrap();
    let saved = store.get_events(&bucket.id, None, None, None).unwrap().remove(0);
    let event_id = saved.id.unwrap();
    let mut corrected = saved.clone();
    corrected.data.insert("title".into(), "corrected title".into());

    let updated = store.correct_event(&bucket.id, corrected.clone()).unwrap();
    assert_eq!(updated.data.get("title").unwrap(), "corrected title");
    let history = store.get_event_corrections(&bucket.id, event_id).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].fields, vec!["title"]);
    assert_eq!(history[0].source, "local-ui");
    let audit = serde_json::to_string(&history).unwrap();
    assert!(!audit.contains("original title") && !audit.contains("corrected title"));
    assert_eq!(store.correct_event(&bucket.id, corrected).unwrap(), updated);
    assert_eq!(store.get_event_corrections(&bucket.id, event_id).unwrap().len(), 1);

    let start = timestamp - Duration::seconds(1);
    let end = timestamp + Duration::seconds(31);
    assert!(store.delete_events_in_range(&bucket.id, end, start).is_err());
    assert_eq!(store.get_event_count(&bucket.id, None, None).unwrap(), 1);
    let removed = store.delete_events_in_range(
        &bucket.id,
        start,
        end,
    ).unwrap();
    assert_eq!(removed, 1);
    assert_eq!(store.get_event_count(&bucket.id, None, None).unwrap(), 0);
    assert!(store.get_event_corrections(&bucket.id, event_id).unwrap().is_empty());
}

#[test]
fn splitting_replaces_one_event_atomically_and_keeps_metadata_only_provenance() {
    let store = Datastore::new_in_memory(false);
    store.enable_capture_policy().unwrap();
    let timestamp = Utc::now() - Duration::days(1);
    let bucket = make_bucket("aw-watcher-window_split", vec![Event::new(
        timestamp,
        Duration::seconds(30),
        json!({"app":"Editor", "title":"private-window-title"}).as_object().unwrap().clone(),
    )]);
    store.create_bucket(&bucket).unwrap();
    let original = store.get_events(&bucket.id, None, None, None).unwrap().remove(0);
    let parts = store.split_event(&bucket.id, original.id.unwrap(), timestamp + Duration::seconds(10)).unwrap();

    assert_eq!(parts.len(), 2);
    assert_ne!(parts[0].id, original.id);
    assert_ne!(parts[1].id, original.id);
    assert_eq!(parts[0].timestamp, timestamp);
    assert_eq!(parts[0].duration, Duration::seconds(10));
    assert_eq!(parts[1].timestamp, timestamp + Duration::seconds(10));
    assert_eq!(parts[1].duration, Duration::seconds(20));
    assert!(parts.iter().all(|part| !part.data.contains_key("title")));
    assert_eq!(store.get_event_count(&bucket.id, None, None).unwrap(), 2);
    for part in &parts {
        let history = store.get_event_corrections(&bucket.id, part.id.unwrap()).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].source, "local-ui-split");
        assert!(history[0].fields.contains(&"duration".to_string()));
    }
    assert!(store.get_event_corrections(&bucket.id, original.id.unwrap()).unwrap().is_empty());
    store.close();
}

#[test]
fn split_rejects_a_boundary_without_changing_the_original() {
    let store = Datastore::new_in_memory(false);
    store.enable_capture_policy().unwrap();
    let timestamp = Utc::now() - Duration::days(1);
    let bucket = make_bucket("aw-watcher-window_split_boundary", vec![Event::new(
        timestamp, Duration::seconds(10), json!({"app":"Editor"}).as_object().unwrap().clone(),
    )]);
    store.create_bucket(&bucket).unwrap();
    let original = store.get_events(&bucket.id, None, None, None).unwrap().remove(0);

    assert!(store.split_event(&bucket.id, original.id.unwrap(), timestamp).is_err());
    assert_eq!(store.get_event_count(&bucket.id, None, None).unwrap(), 1);
    assert_eq!(store.get_event(&bucket.id, original.id.unwrap()).unwrap(), original);
    store.close();
}

#[test]
fn merging_adjacent_matching_events_replaces_both_atomically() {
    let store = Datastore::new_in_memory(false);
    store.enable_capture_policy().unwrap();
    let timestamp = Utc::now() - Duration::days(1);
    let data = json!({"app":"Editor"}).as_object().unwrap().clone();
    let bucket = make_bucket("aw-watcher-window_merge", vec![
        Event::new(timestamp, Duration::seconds(10), data.clone()),
        Event::new(timestamp + Duration::seconds(10), Duration::seconds(20), data),
    ]);
    store.create_bucket(&bucket).unwrap();
    let originals = store.get_events(&bucket.id, None, None, None).unwrap();
    let merged = store.merge_events(&bucket.id, originals[0].id.unwrap(), originals[1].id.unwrap()).unwrap();

    assert_ne!(merged.id, originals[0].id);
    assert_ne!(merged.id, originals[1].id);
    assert_eq!(merged.timestamp, timestamp);
    assert_eq!(merged.duration, Duration::seconds(30));
    assert_eq!(store.get_event_count(&bucket.id, None, None).unwrap(), 1);
    let history = store.get_event_corrections(&bucket.id, merged.id.unwrap()).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].source, "local-ui-merge");
    assert_eq!(store.get_event_corrections(&bucket.id, originals[0].id.unwrap()).unwrap().len(), 0);
    store.close();
}

#[test]
fn merge_rejects_mismatched_events_without_removing_them() {
    let store = Datastore::new_in_memory(false);
    store.enable_capture_policy().unwrap();
    let timestamp = Utc::now() - Duration::days(1);
    let bucket = make_bucket("aw-watcher-window_merge_mismatch", vec![
        Event::new(timestamp, Duration::seconds(10), json!({"app":"Editor"}).as_object().unwrap().clone()),
        Event::new(timestamp + Duration::seconds(10), Duration::seconds(20), json!({"app":"Browser"}).as_object().unwrap().clone()),
    ]);
    store.create_bucket(&bucket).unwrap();
    let originals = store.get_events(&bucket.id, None, None, None).unwrap();

    assert!(store.merge_events(&bucket.id, originals[0].id.unwrap(), originals[1].id.unwrap()).is_err());
    assert_eq!(store.get_event_count(&bucket.id, None, None).unwrap(), 2);
    store.close();
}
