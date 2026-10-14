#![cfg(any(feature = "encryption", feature = "encryption-vendored"))]
#[path = "support/entitlement.rs"]
mod entitlement;
use aw_datastore::Datastore;
use aw_egress::{EgressProxy, VerifiedPolicyV1};
use aw_server::{backup::BackupWorkflowV1, sync_control::SyncControl};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{json, Value};
use std::collections::HashMap;

#[path = "support/backup_provider.rs"]
mod fixture;
use fixture::{policy, request, source, Relay};

fn approve(
    workflow: &BackupWorkflowV1,
    store: &Datastore,
    proxy: &EgressProxy,
    policy: &VerifiedPolicyV1,
    preview: &Value,
    source: &Value,
) -> Value {
    workflow.approve(store,proxy,policy,json!({"schema_version":1,"context_id":source["context_id"],"preview_id":preview["preview_id"],"user_accepted":true,"source_json":source.to_string()}).to_string()).unwrap()
}
fn run(
    workflow: &BackupWorkflowV1,
    store: &Datastore,
    proxy: &EgressProxy,
    policy: &VerifiedPolicyV1,
    job: &Value,
    source: &Value,
) -> Value {
    workflow.run(store,proxy,policy,json!({"schema_version":1,"context_id":source["context_id"],"job_id":job["job_id"],"source_json":source.to_string()}).to_string()).unwrap()
}

#[test]
fn provider_backup_full_review_upload_discover_download_stages_without_installing_or_changing_pointer(
) {
    let (source, kit, selected) = source();
    let relay = Relay::default();
    let source_policy = policy(&source);
    let source_proxy = EgressProxy::with_transport(source.clone(), relay.clone())
        .with_sync_access(entitlement::access());
    let workflow = BackupWorkflowV1::new();
    let before = source.load_sync_snapshot().unwrap().unwrap();
    let preview = workflow
        .preview(
            &source,
            &source_proxy,
            &source_policy,
            request("upload", &selected, None),
        )
        .unwrap();
    assert!(relay.requests.lock().unwrap().is_empty());
    let job = approve(
        &workflow,
        &source,
        &source_proxy,
        &source_policy,
        &preview,
        &selected,
    );
    let result = run(
        &workflow,
        &source,
        &source_proxy,
        &source_policy,
        &job,
        &selected,
    );
    assert_eq!(result["status"], "complete");
    assert_eq!(source.load_sync_snapshot().unwrap().unwrap(), before);
    assert!(!source.sync_enabled().unwrap());
    let target = Datastore::open_encrypted(":memory:".into(), "b".repeat(64)).unwrap();
    let target_policy = policy(&target);
    let proxy = EgressProxy::with_transport(target.clone(), relay.clone())
        .with_sync_access(entitlement::access());
    let key_input = json!({"schema_version":1,"source_id":"local","context_id":target.get_sync_policy_context().unwrap().context_id,"recovery":{"kit":kit["kit"],"phrase":kit["recovery_phrase"]}});
    let preview = workflow
        .preview(
            &target,
            &proxy,
            &target_policy,
            request("list", &key_input, None),
        )
        .unwrap();
    let job = approve(
        &workflow,
        &target,
        &proxy,
        &target_policy,
        &preview,
        &key_input,
    );
    let catalogue = run(&workflow, &target, &proxy, &target_policy, &job, &key_input);
    assert_eq!(catalogue["versions"][0]["status"], "authenticated");
    assert!(target.load_sync_key_material().unwrap().is_none());
    let reference = catalogue["versions"][0]["selection"].clone();
    let preview = workflow
        .preview(
            &target,
            &proxy,
            &target_policy,
            request("download", &key_input, Some(reference)),
        )
        .unwrap();
    let job = approve(
        &workflow,
        &target,
        &proxy,
        &target_policy,
        &preview,
        &key_input,
    );
    let downloaded = run(&workflow, &target, &proxy, &target_policy, &job, &key_input);
    assert_eq!(downloaded["status"], "complete");
    assert_eq!(downloaded["local_selection"]["source_id"], "local");
    assert!(target.load_sync_key_material().unwrap().is_none());
    assert!(target.load_sync_snapshot().unwrap().is_none());
    assert!(target.get_buckets().unwrap().is_empty());
    assert!(!target.sync_enabled().unwrap());
    let mut local = key_input;
    local["selection"] = downloaded["local_selection"].clone();
    let raw = SyncControl::new()
        .invoke(
            &target,
            "export_selected_sync_backup",
            json!({"requestJson":local.to_string()}),
        )
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(raw.as_str().unwrap()).unwrap()["snapshot_id"],
        selected["selection"]["snapshot_id"]
    );
    source.close();
    target.close();
}

#[test]
fn provider_backup_explicit_decline_or_changed_source_rejects_without_transport() {
    let (store, _, selected) = source();
    let relay = Relay::default();
    let policy = policy(&store);
    let proxy = EgressProxy::with_transport(store.clone(), relay.clone())
        .with_sync_access(entitlement::access());
    let workflow = BackupWorkflowV1::new();
    let preview = workflow
        .preview(&store, &proxy, &policy, request("upload", &selected, None))
        .unwrap();
    let decline = json!({"schema_version":1,"context_id":selected["context_id"],"preview_id":preview["preview_id"],"user_accepted":false,"source_json":selected.to_string()});
    assert!(workflow
        .approve(&store, &proxy, &policy, decline.to_string())
        .is_err());
    let mut forged = selected.clone();
    forged["selection"]["bundle_sha256"] = json!("0".repeat(64));
    assert!(workflow
        .preview(&store, &proxy, &policy, request("upload", &forged, None))
        .is_err());
    assert!(relay.requests.lock().unwrap().is_empty());
    store.close();
}

#[test]
fn provider_selected_upload_does_not_require_discovery_permission() {
    let (store, _, selected) = source();
    let _ = policy(&store);
    let (bundle, mut user) = store.get_egress_policy_state().unwrap().unwrap();
    user.user_rules.push(aw_models::EgressRuleV1 {
        pattern: aw_models::EgressPatternV1 {
            kind: aw_models::EgressMatchKindV1::Keyword,
            value: "list_opaque_heads".into(),
        },
        action: aw_models::EgressRuleActionV1::Deny,
    });
    store.store_egress_user_policy(&user).unwrap();
    let key = Ed25519KeyPair::from_seed_unchecked(&[0x91; 32]).unwrap();
    let policy = aw_egress::verify_and_activate(
        &bundle,
        &user,
        &HashMap::from([("fixture".into(), key.public_key().as_ref().to_vec())]),
        None,
    )
    .unwrap();
    let relay = Relay::default();
    let proxy = EgressProxy::with_transport(store.clone(), relay.clone())
        .with_sync_access(entitlement::access());
    assert!(BackupWorkflowV1::new()
        .preview(&store, &proxy, &policy, request("upload", &selected, None))
        .is_ok());
    assert!(relay.requests.lock().unwrap().is_empty());
    store.close();
}

#[test]
fn provider_partial_upload_reports_exact_count_and_job_cannot_replay() {
    let (store, _, selected) = fixture::multipart_source();
    let policy = policy(&store);
    let relay = Relay {
        fail_after: Some(1),
        ..Default::default()
    };
    let proxy = EgressProxy::with_transport(store.clone(), relay.clone())
        .with_sync_access(entitlement::access());
    let workflow = BackupWorkflowV1::new();
    let before = store.load_sync_snapshot().unwrap().unwrap();
    let preview = workflow
        .preview(&store, &proxy, &policy, request("upload", &selected, None))
        .unwrap();
    let job = approve(&workflow, &store, &proxy, &policy, &preview, &selected);
    let result = run(&workflow, &store, &proxy, &policy, &job, &selected);
    assert_eq!(result["status"], "partial");
    assert_eq!(result["completed_objects"], 1);
    assert_eq!(result["object_count"], 2);
    assert!(result["local_selection"].is_null());
    assert_eq!(relay.objects.lock().unwrap().len(), 1);
    assert_eq!(store.load_sync_snapshot().unwrap().unwrap(), before);
    assert!(!store.sync_enabled().unwrap());
    let repeat = json!({"schema_version":1,"context_id":selected["context_id"],"job_id":job["job_id"],"source_json":selected.to_string()});
    assert!(workflow
        .run(&store, &proxy, &policy, repeat.to_string())
        .is_err());
    assert_eq!(relay.requests.lock().unwrap().len(), 1);
    store.close();
}

#[test]
fn provider_partial_download_never_stages_the_first_successful_chunk() {
    let (source, kit, _) = fixture::multipart_source();
    let snapshot = source.load_sync_snapshot().unwrap().unwrap();
    let relay = Relay::default();
    for object in &snapshot.envelopes {
        relay
            .objects
            .lock()
            .unwrap()
            .insert(object.object_id.clone(), object.clone());
    }
    let target = Datastore::open_encrypted(":memory:".into(), "b".repeat(64)).unwrap();
    let policy = policy(&target);
    let proxy = EgressProxy::with_transport(target.clone(), relay.clone())
        .with_sync_access(entitlement::access());
    let workflow = BackupWorkflowV1::new();
    let key = json!({"schema_version":1,"source_id":"local","context_id":target.get_sync_policy_context().unwrap().context_id,"recovery":{"kit":kit["kit"],"phrase":kit["recovery_phrase"]}});
    let preview = workflow
        .preview(&target, &proxy, &policy, request("list", &key, None))
        .unwrap();
    let job = approve(&workflow, &target, &proxy, &policy, &preview, &key);
    let catalogue = run(&workflow, &target, &proxy, &policy, &job, &key);
    let reference = catalogue["versions"][0]["selection"].clone();
    let failing = Relay {
        fail_after: Some(relay.requests.lock().unwrap().len() + 1),
        ..relay.clone()
    };
    let proxy = EgressProxy::with_transport(target.clone(), failing)
        .with_sync_access(entitlement::access());
    let preview = workflow
        .preview(
            &target,
            &proxy,
            &policy,
            request("download", &key, Some(reference)),
        )
        .unwrap();
    let job = approve(&workflow, &target, &proxy, &policy, &preview, &key);
    let result = run(&workflow, &target, &proxy, &policy, &job, &key);
    assert_eq!(result["status"], "partial");
    assert_eq!(result["completed_objects"], 1);
    assert_eq!(result["object_count"], 2);
    assert!(result["local_selection"].is_null());

    relay
        .objects
        .lock()
        .unwrap()
        .remove(&snapshot.envelopes[1].object_id);
    let fresh_proxy = EgressProxy::with_transport(target.clone(), relay.clone())
        .with_sync_access(entitlement::access());
    let preview = workflow
        .preview(
            &target,
            &fresh_proxy,
            &policy,
            request(
                "download",
                &key,
                Some(catalogue["versions"][0]["selection"].clone()),
            ),
        )
        .unwrap();
    let job = approve(&workflow, &target, &fresh_proxy, &policy, &preview, &key);
    let missing = run(&workflow, &target, &fresh_proxy, &policy, &job, &key);
    assert_eq!(missing["status"], "partial");
    assert_eq!(missing["completed_objects"], 1);
    assert_eq!(missing["object_count"], 2);
    assert!(missing["local_selection"].is_null());
    for object in snapshot.envelopes {
        assert!(target.get_sync_object(object.object_id).unwrap().is_none());
    }
    assert!(target.list_sync_object_history(1000).unwrap().is_empty());
    assert!(target.load_sync_key_material().unwrap().is_none());
    assert!(target.load_sync_snapshot().unwrap().is_none());
    source.close();
    target.close();
}

#[test]
fn provider_pending_quota_counts_approved_jobs_and_reclaims_consumed_slots() {
    let (store, _, selected) = source();
    let policy = policy(&store);
    let relay = Relay::default();
    let proxy = EgressProxy::with_transport(store.clone(), relay.clone())
        .with_sync_access(entitlement::access());
    let workflow = BackupWorkflowV1::new();
    let mut jobs = Vec::new();
    for i in 0..32 {
        let preview = workflow
            .preview(&store, &proxy, &policy, request("upload", &selected, None))
            .unwrap();
        if i < 3 {
            jobs.push(approve(
                &workflow, &store, &proxy, &policy, &preview, &selected,
            ));
        }
    }
    assert!(workflow
        .preview(&store, &proxy, &policy, request("upload", &selected, None))
        .is_err());
    assert!(relay.requests.lock().unwrap().is_empty());
    assert_eq!(
        run(&workflow, &store, &proxy, &policy, &jobs[0], &selected)["status"],
        "complete"
    );
    assert!(workflow
        .preview(&store, &proxy, &policy, request("upload", &selected, None))
        .is_ok());
    assert_eq!(relay.requests.lock().unwrap().len(), 1);
    store.close();
}

#[test]
fn provider_paged_discovery_disables_corrupt_payloads_and_missing_get_never_stages() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let (store, _, selected) = source();
    let material = store.load_sync_key_material().unwrap().unwrap();
    let root = aw_sync_e2ee::AccountRootKeyV1::from_bytes(zeroize::Zeroizing::new(
        *material.account_root_key(),
    ));
    let wrapped = aw_sync_e2ee::WrappedVaultDataKeyV1 {
        schema_version: 1,
        vault_id: URL_SAFE_NO_PAD.encode(material.vault_id()),
        key_epoch: material.key_epoch(),
        nonce: URL_SAFE_NO_PAD.encode(material.wrapped_nonce()),
        ciphertext: URL_SAFE_NO_PAD.encode(material.wrapped_ciphertext()),
    };
    let key = aw_sync_e2ee::unwrap_vault_data_key(&root, &wrapped).unwrap();
    let relay = Relay::default();
    let snapshot = store.load_sync_snapshot().unwrap().unwrap();
    for object in &snapshot.envelopes {
        relay
            .objects
            .lock()
            .unwrap()
            .insert(object.object_id.clone(), object.clone());
    }
    for _ in 0..17 {
        let invalid =
            aw_sync_e2ee::encrypt_snapshot(&key, b"authenticated header, invalid recovery payload")
                .unwrap();
        let object = invalid.envelopes[0].clone();
        relay
            .objects
            .lock()
            .unwrap()
            .insert(object.object_id.clone(), object);
    }
    let policy = policy(&store);
    let proxy = EgressProxy::with_transport(store.clone(), relay.clone())
        .with_sync_access(entitlement::access());
    let workflow = BackupWorkflowV1::new();
    let mut local = selected.clone();
    local.as_object_mut().unwrap().remove("selection");
    let preview = workflow
        .preview(&store, &proxy, &policy, request("list", &local, None))
        .unwrap();
    let job = approve(&workflow, &store, &proxy, &policy, &preview, &local);
    let catalogue = run(&workflow, &store, &proxy, &policy, &job, &local);
    let versions = catalogue["versions"].as_array().unwrap();
    assert_eq!(versions.len(), 18);
    assert_eq!(
        versions
            .iter()
            .filter(|v| v["status"] == "invalid_recovery" && v["selection"].is_null())
            .count(),
        17
    );
    assert_eq!(relay.requests.lock().unwrap().len(), 2);
    let valid = versions
        .iter()
        .find(|v| v["status"] == "authenticated")
        .unwrap();
    let preview = workflow
        .preview(
            &store,
            &proxy,
            &policy,
            request("download", &local, Some(valid["selection"].clone())),
        )
        .unwrap();
    let job = approve(&workflow, &store, &proxy, &policy, &preview, &local);
    relay
        .objects
        .lock()
        .unwrap()
        .remove(&snapshot.envelopes[0].object_id);
    let history_before = store.list_sync_object_history(100).unwrap();
    let raw = json!({"schema_version":1,"context_id":local["context_id"],"job_id":job["job_id"],"source_json":local.to_string()});
    let missing = workflow
        .run(&store, &proxy, &policy, raw.to_string())
        .unwrap();
    assert_eq!(missing["status"], "partial");
    assert_eq!(missing["completed_objects"], 0);
    assert_eq!(missing["object_count"], 1);
    assert!(missing["local_selection"].is_null());
    assert_eq!(store.load_sync_snapshot().unwrap().unwrap(), snapshot);
    assert_eq!(store.list_sync_object_history(100).unwrap(), history_before);
    store.close();
}

#[test]
fn provider_stale_jobs_do_not_revive_after_real_worker_close_and_reopen() {
    let path = std::env::temp_dir().join(format!(
        "peak-provider-context-{}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let (source, _, _) = source();
    let store =
        Datastore::open_encrypted(path.to_string_lossy().into_owned(), "b".repeat(64)).unwrap();
    store
        .install_sync_key_material(&source.load_sync_key_material().unwrap().unwrap())
        .unwrap();
    let policy = policy(&store);
    let relay = Relay::default();
    let proxy = EgressProxy::with_transport(store.clone(), relay.clone())
        .with_sync_access(entitlement::access());
    let workflow = BackupWorkflowV1::new();
    let old = json!({"schema_version":1,"source_id":"local","context_id":store.get_sync_policy_context().unwrap().context_id});
    let preview = workflow
        .preview(&store, &proxy, &policy, request("list", &old, None))
        .unwrap();
    let job = approve(&workflow, &store, &proxy, &policy, &preview, &old);
    store.close();
    let reopened =
        Datastore::open_encrypted(path.to_string_lossy().into_owned(), "b".repeat(64)).unwrap();
    assert_ne!(
        reopened.get_sync_policy_context().unwrap().context_id,
        old["context_id"]
    );
    let fresh_policy = fixture::policy(&reopened);
    let fresh_proxy = EgressProxy::with_transport(reopened.clone(), relay.clone())
        .with_sync_access(entitlement::access());
    let raw = json!({"schema_version":1,"context_id":old["context_id"],"job_id":job["job_id"],"source_json":old.to_string()});
    assert!(workflow
        .run(&reopened, &fresh_proxy, &policy, raw.to_string())
        .is_err());
    assert!(relay.requests.lock().unwrap().is_empty());
    let fresh = json!({"schema_version":1,"source_id":"local","context_id":reopened.get_sync_policy_context().unwrap().context_id});
    assert!(workflow
        .preview(
            &reopened,
            &fresh_proxy,
            &fresh_policy,
            request("list", &fresh, None)
        )
        .is_ok());
    assert!(workflow.approve(&reopened,&fresh_proxy,&fresh_policy,json!({"schema_version":1,"context_id":fresh["context_id"],"preview_id":preview["preview_id"],"user_accepted":true,"source_json":fresh.to_string()}).to_string()).is_err());
    reopened.close();
    source.close();
    std::fs::remove_file(path).unwrap();
}
#[test]
fn provider_shared_workflow_rejects_overlapping_expensive_work_without_waiting_or_transport() {
    use aw_egress::EgressTransport;
    use aw_models::{EgressDestinationV1, EgressPurposeV1, EgressReasonCodeV1};
    use std::sync::{Arc, Barrier};
    #[derive(Clone)]
    struct BlockingRelay {
        inner: Relay,
        entered: Arc<Barrier>,
        release: Arc<Barrier>,
    }
    impl EgressTransport for BlockingRelay {
        fn send(
            &self,
            _: &EgressDestinationV1,
            _: &EgressPurposeV1,
            _: &[u8],
        ) -> Result<(), EgressReasonCodeV1> {
            unreachable!()
        }
        fn request(
            &self,
            d: &EgressDestinationV1,
            p: &EgressPurposeV1,
            bytes: &[u8],
        ) -> Result<Vec<u8>, EgressReasonCodeV1> {
            self.entered.wait();
            self.release.wait();
            self.inner.request(d, p, bytes)
        }
    }
    let (store, _, mut local) = source();
    local.as_object_mut().unwrap().remove("selection");
    let policy = policy(&store);
    let relay = Relay::default();
    let blocked = BlockingRelay {
        inner: relay.clone(),
        entered: Arc::new(Barrier::new(2)),
        release: Arc::new(Barrier::new(2)),
    };
    let proxy = EgressProxy::with_transport(store.clone(), blocked.clone())
        .with_sync_access(entitlement::access());
    let workflow = BackupWorkflowV1::new();
    let preview = workflow
        .preview(&store, &proxy, &policy, request("list", &local, None))
        .unwrap();
    let job = approve(&workflow, &store, &proxy, &policy, &preview, &local);
    let owner = workflow.clone();
    let worker = store.clone();
    let sender = proxy.clone();
    let current_policy = policy.clone();
    let input = local.clone();
    let running =
        std::thread::spawn(move || run(&owner, &worker, &sender, &current_policy, &job, &input));
    blocked.entered.wait();
    let denied = workflow
        .preview(&store, &proxy, &policy, request("list", &local, None))
        .is_err();
    blocked.release.wait();
    let result = running.join().unwrap();
    assert_eq!(result["versions"].as_array().unwrap().len(), 0);
    assert!(
        denied,
        "expensive work on the same workflow must fail busy immediately"
    );
    assert_eq!(relay.requests.lock().unwrap().len(), 1);
    store.close();
}

#[test]
fn provider_cleanup_is_free_delete_only_and_commits_intent_before_exact_deletion() {
    let (store, _, selected) = source();
    let historical = store.load_sync_snapshot().unwrap().unwrap();
    SyncControl::new()
        .invoke(&store, "create_current_sync_snapshot", json!({}))
        .unwrap();
    let current = store.load_sync_snapshot().unwrap().unwrap();
    let relay = Relay::default();
    for object in &historical.envelopes {
        relay
            .objects
            .lock()
            .unwrap()
            .insert(object.object_id.clone(), object.clone());
    }
    let policy = policy(&store);
    let free = EgressProxy::with_transport(store.clone(), relay.clone());
    let workflow = BackupWorkflowV1::new();
    let key = json!({"schema_version":1,"source_id":"local","context_id":selected["context_id"]});
    let preview = workflow
        .preview(&store, &free, &policy, request("cleanup_list", &key, None))
        .unwrap();
    let job = approve(&workflow, &store, &free, &policy, &preview, &key);
    let catalogue = run(&workflow, &store, &free, &policy, &job, &key);
    assert_eq!(catalogue["cleanup_only"], true);
    assert!(catalogue["versions"][0]["selection"].is_null());
    let reference = catalogue["versions"][0]["deletion_selection"].clone();
    assert!(reference.is_object());
    let paid = EgressProxy::with_transport(store.clone(), relay.clone())
        .with_sync_access(entitlement::access());
    assert!(workflow
        .preview(
            &store,
            &paid,
            &policy,
            request("download", &key, Some(reference.clone()))
        )
        .is_err());
    let preview = workflow
        .preview(
            &store,
            &free,
            &policy,
            request("delete", &key, Some(reference)),
        )
        .unwrap();
    let decline = json!({"schema_version":1,"context_id":key["context_id"],"preview_id":preview["preview_id"],"user_accepted":false,"source_json":key.to_string()});
    assert!(workflow
        .approve(&store, &free, &policy, decline.to_string())
        .is_err());
    assert_eq!(relay.requests.lock().unwrap().len(), 1);
    let job = approve(&workflow, &store, &free, &policy, &preview, &key);
    let result = run(&workflow, &store, &free, &policy, &job, &key);
    assert_eq!(result["deleted"], historical.envelopes.len());
    assert_eq!(result["unknown"], 0);
    assert!(relay.objects.lock().unwrap().is_empty());
    assert_eq!(
        store
            .export_sync_backup_deletions(key["context_id"].as_str().unwrap().into())
            .unwrap()
            .len(),
        1
    );
    assert_eq!(store.load_sync_snapshot().unwrap().unwrap(), current);
    assert!(workflow.run(&store,&free,&policy,json!({"schema_version":1,"context_id":key["context_id"],"job_id":job["job_id"],"source_json":key.to_string()}).to_string()).is_err());
    store.close();
}

#[test]
fn provider_cleanup_current_snapshot_cannot_be_reviewed_for_deletion() {
    let (store, _, selected) = source();
    let relay = Relay::default();
    for object in store.load_sync_snapshot().unwrap().unwrap().envelopes {
        relay
            .objects
            .lock()
            .unwrap()
            .insert(object.object_id.clone(), object);
    }
    let policy = policy(&store);
    let proxy = EgressProxy::with_transport(store.clone(), relay.clone());
    let workflow = BackupWorkflowV1::new();
    let key = json!({"schema_version":1,"source_id":"local","context_id":selected["context_id"]});
    let preview = workflow
        .preview(&store, &proxy, &policy, request("cleanup_list", &key, None))
        .unwrap();
    let job = approve(&workflow, &store, &proxy, &policy, &preview, &key);
    let catalogue = run(&workflow, &store, &proxy, &policy, &job, &key);
    assert_eq!(catalogue["versions"][0]["current"], true);
    assert!(catalogue["versions"][0]["deletion_selection"].is_null());
    let mut reference = selected["selection"].clone();
    reference["source_id"] = catalogue["source_id"].clone();
    assert!(workflow
        .preview(
            &store,
            &proxy,
            &policy,
            request("delete", &key, Some(reference))
        )
        .is_err());
    assert_eq!(relay.requests.lock().unwrap().len(), 1);
    store.close();
}

#[test]
fn provider_cleanup_partial_retry_uses_durable_intent_in_a_fresh_workflow() {
    let (store, _, selected) = fixture::multipart_source();
    let old = store.load_sync_snapshot().unwrap().unwrap();
    SyncControl::new()
        .invoke(&store, "create_current_sync_snapshot", json!({}))
        .unwrap();
    let relay = Relay::default();
    for object in &old.envelopes {
        relay
            .objects
            .lock()
            .unwrap()
            .insert(object.object_id.clone(), object.clone());
    }
    let policy = policy(&store);
    let key = json!({"schema_version":1,"source_id":"local","context_id":selected["context_id"]});
    let workflow = BackupWorkflowV1::new();
    let normal = EgressProxy::with_transport(store.clone(), relay.clone());
    let preview = workflow
        .preview(
            &store,
            &normal,
            &policy,
            request("cleanup_list", &key, None),
        )
        .unwrap();
    let job = approve(&workflow, &store, &normal, &policy, &preview, &key);
    let catalogue = run(&workflow, &store, &normal, &policy, &job, &key);
    let reference = catalogue["versions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["snapshot_id"] == selected["selection"]["snapshot_id"])
        .unwrap()["deletion_selection"]
        .clone();
    let partial = EgressProxy::with_transport(
        store.clone(),
        Relay {
            fail_after: Some(2),
            ..relay.clone()
        },
    );
    let preview = workflow
        .preview(
            &store,
            &partial,
            &policy,
            request("delete", &key, Some(reference)),
        )
        .unwrap();
    let job = approve(&workflow, &store, &partial, &policy, &preview, &key);
    let result = run(&workflow, &store, &partial, &policy, &job, &key);
    assert_eq!(result["deleted"], 1);
    assert_eq!(result["unknown"], 1);
    let workflow = BackupWorkflowV1::new();
    let preview = workflow
        .preview(
            &store,
            &normal,
            &policy,
            request("cleanup_list", &key, None),
        )
        .unwrap();
    let job = approve(&workflow, &store, &normal, &policy, &preview, &key);
    let catalogue = run(&workflow, &store, &normal, &policy, &job, &key);
    let row = &catalogue["versions"][0];
    assert_eq!(row["status"], "forgotten");
    assert!(row["selection"].is_null());
    let preview = workflow
        .preview(
            &store,
            &normal,
            &policy,
            request("delete", &key, Some(row["deletion_selection"].clone())),
        )
        .unwrap();
    let job = approve(&workflow, &store, &normal, &policy, &preview, &key);
    let result = run(&workflow, &store, &normal, &policy, &job, &key);
    assert_eq!(result["deleted"], 1);
    assert_eq!(result["absent"], 1);
    assert_eq!(result["unknown"], 0);
    assert!(relay.objects.lock().unwrap().is_empty());
    store.close();
}

#[test]
fn provider_cleanup_preserves_changed_copy_and_reports_unknown_or_observed_absence() {
    for changed in [false, true] {
        let (store, _, selected) = source();
        let old = store.load_sync_snapshot().unwrap().unwrap();
        SyncControl::new()
            .invoke(&store, "create_current_sync_snapshot", json!({}))
            .unwrap();
        let relay = Relay::default();
        for o in &old.envelopes {
            relay
                .objects
                .lock()
                .unwrap()
                .insert(o.object_id.clone(), o.clone());
        }
        let policy = policy(&store);
        let proxy = EgressProxy::with_transport(store.clone(), relay.clone());
        let workflow = BackupWorkflowV1::new();
        let key =
            json!({"schema_version":1,"source_id":"local","context_id":selected["context_id"]});
        let preview = workflow
            .preview(&store, &proxy, &policy, request("cleanup_list", &key, None))
            .unwrap();
        let job = approve(&workflow, &store, &proxy, &policy, &preview, &key);
        let catalogue = run(&workflow, &store, &proxy, &policy, &job, &key);
        let preview = workflow
            .preview(
                &store,
                &proxy,
                &policy,
                request(
                    "delete",
                    &key,
                    Some(catalogue["versions"][0]["deletion_selection"].clone()),
                ),
            )
            .unwrap();
        let job = approve(&workflow, &store, &proxy, &policy, &preview, &key);
        if changed {
            relay
                .objects
                .lock()
                .unwrap()
                .get_mut(&old.envelopes[0].object_id)
                .unwrap()
                .ciphertext = "changed".into();
        } else {
            relay.objects.lock().unwrap().clear();
        }
        let result = run(&workflow, &store, &proxy, &policy, &job, &key);
        assert_eq!(result["deleted"], 0);
        assert_eq!(result["unknown"], if changed { 1 } else { 0 });
        assert_eq!(result["absent"], if changed { 0 } else { 1 });
        assert_eq!(
            relay.objects.lock().unwrap().len(),
            if changed { 1 } else { 0 }
        );
        store.close();
    }
}

#[test]
fn provider_cleanup_finished_fact_is_visible_without_minting_another_delete_job() {
    let (store, _, selected) = source();
    let old = store.load_sync_snapshot().unwrap().unwrap();
    SyncControl::new()
        .invoke(&store, "create_current_sync_snapshot", json!({}))
        .unwrap();
    let relay = Relay::default();
    for o in old.envelopes {
        relay.objects.lock().unwrap().insert(o.object_id.clone(), o);
    }
    let policy = policy(&store);
    let proxy = EgressProxy::with_transport(store.clone(), relay.clone());
    let workflow = BackupWorkflowV1::new();
    let key = json!({"schema_version":1,"source_id":"local","context_id":selected["context_id"]});
    let review = workflow
        .preview(&store, &proxy, &policy, request("cleanup_list", &key, None))
        .unwrap();
    let job = approve(&workflow, &store, &proxy, &policy, &review, &key);
    let page = run(&workflow, &store, &proxy, &policy, &job, &key);
    let review = workflow
        .preview(
            &store,
            &proxy,
            &policy,
            request(
                "delete",
                &key,
                Some(page["versions"][0]["deletion_selection"].clone()),
            ),
        )
        .unwrap();
    let job = approve(&workflow, &store, &proxy, &policy, &review, &key);
    run(&workflow, &store, &proxy, &policy, &job, &key);
    let fresh = BackupWorkflowV1::new();
    let review = fresh
        .preview(&store, &proxy, &policy, request("cleanup_list", &key, None))
        .unwrap();
    let job = approve(&fresh, &store, &proxy, &policy, &review, &key);
    let page = run(&fresh, &store, &proxy, &policy, &job, &key);
    let row = page["versions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["snapshot_id"] == selected["selection"]["snapshot_id"])
        .expect("protected fact remains visible");
    assert_eq!(row["status"], "forgotten");
    assert_eq!(row["observed_object_count"], 0);
    assert!(row["selection"].is_null());
    assert!(row["deletion_selection"].is_null());
    store.close();
}

#[test]
fn provider_cleanup_known_fact_rejects_paid_download_from_preexisting_discovery() {
    let (store, _, selected) = source();
    let old = store.load_sync_snapshot().unwrap().unwrap();
    SyncControl::new()
        .invoke(&store, "create_current_sync_snapshot", json!({}))
        .unwrap();
    let relay = Relay::default();
    for o in old.envelopes {
        relay.objects.lock().unwrap().insert(o.object_id.clone(), o);
    }
    let policy = policy(&store);
    let paid = EgressProxy::with_transport(store.clone(), relay.clone())
        .with_sync_access(entitlement::access());
    let workflow = BackupWorkflowV1::new();
    let key = json!({"schema_version":1,"source_id":"local","context_id":selected["context_id"]});
    let review = workflow
        .preview(&store, &paid, &policy, request("list", &key, None))
        .unwrap();
    let job = approve(&workflow, &store, &paid, &policy, &review, &key);
    let page = run(&workflow, &store, &paid, &policy, &job, &key);
    let reference = page["versions"][0]["selection"].clone();
    let free = EgressProxy::with_transport(store.clone(), relay.clone());
    let review = workflow
        .preview(
            &store,
            &free,
            &policy,
            request("delete", &key, Some(reference.clone())),
        )
        .unwrap();
    let job = approve(&workflow, &store, &free, &policy, &review, &key);
    run(&workflow, &store, &free, &policy, &job, &key);
    assert!(workflow
        .preview(
            &store,
            &paid,
            &policy,
            request("download", &key, Some(reference))
        )
        .is_err());
    store.close();
}

#[test]
fn provider_cleanup_durable_intent_precedes_transport_and_changed_pointer_cannot_publish() {
    let (store,_,selected)=source();let old=store.load_sync_snapshot().unwrap().unwrap();
    SyncControl::new().invoke(&store,"create_current_sync_snapshot",json!({})).unwrap();
    let relay=Relay::default();for o in old.envelopes{relay.objects.lock().unwrap().insert(o.object_id.clone(),o);}
    let policy=policy(&store);let context=store.get_sync_policy_context().unwrap().context_id;
    let observed=std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));let flag=observed.clone();let callback_store=store.clone();
    let hooked=Relay{before_delete:Some(std::sync::Arc::new(move||{
        assert_eq!(callback_store.export_sync_backup_deletions(context.clone()).unwrap().len(),1);
        flag.store(true,std::sync::atomic::Ordering::SeqCst);
        SyncControl::new().invoke(&callback_store,"create_current_sync_snapshot",json!({})).unwrap();
    })),..relay.clone()};
    let proxy=EgressProxy::with_transport(store.clone(),hooked);let workflow=BackupWorkflowV1::new();let key=json!({"schema_version":1,"source_id":"local","context_id":selected["context_id"]});
    let review=workflow.preview(&store,&proxy,&policy,request("cleanup_list",&key,None)).unwrap();let job=approve(&workflow,&store,&proxy,&policy,&review,&key);let page=run(&workflow,&store,&proxy,&policy,&job,&key);
    let review=workflow.preview(&store,&proxy,&policy,request("delete",&key,Some(page["versions"][0]["deletion_selection"].clone()))).unwrap();let job=approve(&workflow,&store,&proxy,&policy,&review,&key);
    assert!(workflow.run(&store,&proxy,&policy,json!({"schema_version":1,"context_id":key["context_id"],"job_id":job["job_id"],"source_json":key.to_string()}).to_string()).is_err());
    assert!(observed.load(std::sync::atomic::Ordering::SeqCst));assert!(relay.objects.lock().unwrap().is_empty());store.close();
}
