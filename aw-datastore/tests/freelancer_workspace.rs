use aw_datastore::Datastore;

#[test]
fn local_workspace_updates_use_compare_and_set_to_avoid_lost_edits() {
    let store = Datastore::new_in_memory(false);
    let key = "freelancer.workspace.v1";
    assert!(store.compare_and_set_key_value(key, None, Some("revision-1")).unwrap());
    assert!(!store.compare_and_set_key_value(key, None, Some("lost-create")).unwrap());
    assert!(!store.compare_and_set_key_value(key, Some("stale"), Some("lost-edit")).unwrap());
    assert!(store.compare_and_set_key_value(key, Some("revision-1"), Some("revision-2")).unwrap());
    assert_eq!(store.get_key_value(key).unwrap(), "revision-2");
    assert!(store.compare_and_set_key_value(key, Some("revision-2"), None).unwrap());
    assert!(store.get_key_value(key).is_err());
}

#[test]
fn compare_and_set_cannot_modify_capture_or_egress_policy_keys() {
    let store = Datastore::new_in_memory(false);
    assert!(store.compare_and_set_key_value("peakactivity.capture_policy", None, Some("{}")).is_err());
    assert!(store.compare_and_set_key_value("egress.policy_state", None, Some("{}")).is_err());
}
