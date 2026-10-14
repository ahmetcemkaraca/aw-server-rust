#[test]
fn native_enable_refuses_unavailable_signed_destinations_before_snapshot_changes() {
    let (store, controller, relay) = configured(false);
    let before = store.load_sync_snapshot().unwrap().unwrap().snapshot_id;
    let (mut bundle, _) = signed_policy();
    bundle.bundle.version = 2;
    bundle.bundle.destinations[0].status = EgressDestinationStatusV1::Planned;
    bundle.bundle.destinations[0].https_origin = None;
    let signer = Ed25519KeyPair::from_seed_unchecked(&[0xC1; 32]).unwrap();
    bundle.signature = signer.sign(&aw_egress::policy_bundle_signing_bytes(&bundle).unwrap()).as_ref().to_vec();
    let diff = call(&controller, "preview_sync_policy", json!({"bundle":bundle})).unwrap();
    call(&controller, "accept_sync_policy", json!({"bundle":bundle,"expected_diff":diff,"userConfirmed":true})).unwrap();
    assert!(call(&controller, "set_sync_enabled", json!({"enabled":true,"userConfirmed":true,
        "destination_id":"synthetic-sync","purpose_id":"sync-object-v1"})).is_err());
    assert!(!store.sync_enabled().unwrap());
    assert_eq!(store.load_sync_snapshot().unwrap().unwrap().snapshot_id, before);
    assert!(relay.requests.lock().unwrap().is_empty());
    store.lock().unwrap();
}

#[test]
fn native_baseline_continuation_reuses_the_initial_encrypted_snapshot() {
    let (store, controller, relay) = configured(false);
    let events = (0..129).map(|_| Event::new(Utc::now() - Duration::hours(1), Duration::minutes(1),
        json!({"label":"synthetic baseline entry","running":false}).as_object().unwrap().clone())).collect::<Vec<_>>();
    store.insert_events("aw-stopwatch", &events).unwrap();
    let request = json!({"enabled":true,"userConfirmed":true,
        "destination_id":"synthetic-sync","purpose_id":"sync-object-v1"});
    let first = call(&controller, "set_sync_enabled", request.clone()).unwrap();
    assert_eq!(first["enabled"], false);
    assert_eq!(first["preparing"], true);
    let initial_snapshot = store.load_sync_snapshot().unwrap().unwrap().snapshot_id;
    let completed = call(&controller, "set_sync_enabled", request).unwrap();
    assert_eq!(completed["enabled"], true);
    assert_eq!(completed["preparing"], false);
    assert_eq!(store.load_sync_snapshot().unwrap().unwrap().snapshot_id, initial_snapshot);
    assert!(relay.requests.lock().unwrap().is_empty());
    store.lock().unwrap();
}

#[test]
fn embedded_release_resource_establishes_only_the_selected_signed_policy_trust() {
    let store = store();
    let (bundle, keys) = signed_policy();
    let resource = serde_json::to_vec(&json!({"schema_version":1,"keys":[{
        "id":"synthetic-release","ed25519_public_key":keys["synthetic-release"],
    }]})).unwrap();
    let controller = CompanionNetwork::from_release_resource(store.clone(),&resource).unwrap();
    let preview = call(&controller,"preview_sync_policy",json!({"bundle":bundle})).unwrap();
    assert_eq!(preview["to_version"],1);
    let status = call(&controller,"sync_network_status",json!({})).unwrap();
    assert_eq!(status["egress"]["trusted_policy_keys"],1);
    assert_eq!(status["sync"]["enabled"],false);
    assert!(store.get_egress_policy_state().unwrap().is_none());
    assert!(controller.invoke("set_release_trust",json!({"keys":keys})).is_none());
    assert!(call(&controller,"accept_sync_policy",json!({"bundle":bundle,"expected_diff":preview,
        "userConfirmed":true,"release_keys":keys})).is_err());
    store.lock().unwrap();
}

#[test]
fn concurrent_native_pause_waits_for_the_active_request_and_blocks_later_sends() {
    use std::sync::mpsc;
    use std::time::Duration as Wait;

    struct BlockingRelay {
        relay: Relay,
        entered: mpsc::Sender<()>,
        release: Mutex<mpsc::Receiver<()>>,
        blocked: AtomicBool,
    }
    impl aw_egress::EgressTransport for BlockingRelay {
        fn send(&self, _: &EgressDestinationV1, _: &EgressPurposeV1, _: &[u8]) -> Result<(), aw_models::EgressReasonCodeV1> {
            panic!("Sync must use the shared request transport")
        }
        fn request(&self, destination: &EgressDestinationV1, purpose: &EgressPurposeV1, payload: &[u8]) -> Result<Vec<u8>, aw_models::EgressReasonCodeV1> {
            if !self.blocked.swap(true, Ordering::AcqRel) {
                self.entered.send(()).unwrap();
                self.release.lock().unwrap().recv_timeout(Wait::from_secs(5))
                    .map_err(|_| aw_models::EgressReasonCodeV1::NetworkUnavailable)?;
            }
            aw_egress::EgressTransport::request(&self.relay, destination, purpose, payload)
        }
    }

    let (store, _, relay) = configured(false);
    let (_, keys) = signed_policy();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let proxy = EgressProxy::with_transport(store.clone(), BlockingRelay {
        relay: relay.clone(), entered: entered_tx, release: Mutex::new(release_rx), blocked: AtomicBool::new(false),
    }).with_sync_access(entitlement_fixture::access());
    let controller = Arc::new(CompanionNetwork::from_parts(store.clone(), EgressPolicyTrust::from_release_keys(keys), proxy));
    call(&controller,"set_sync_enabled",json!({"enabled":true,"userConfirmed":true,
        "destination_id":"synthetic-sync","purpose_id":"sync-object-v1"})).unwrap();
    let (finished_tx, finished_rx) = mpsc::channel();
    let runner = controller.clone();
    let run_thread = std::thread::spawn(move || finished_tx.send(call(&runner,"run_sync_once",json!({}))).unwrap());
    entered_rx.recv_timeout(Wait::from_secs(5)).unwrap();
    assert!(controller.running.load(Ordering::Acquire));
    assert!(call(&controller,"run_sync_once",json!({})).is_err());
    let (attempted_tx, attempted_rx) = mpsc::channel();
    let (paused_tx, paused_rx) = mpsc::channel();
    let pausing = controller.clone();
    let pause_thread = std::thread::spawn(move || {
        attempted_tx.send(()).unwrap();
        paused_tx.send(pausing.pause()).unwrap();
    });
    attempted_rx.recv_timeout(Wait::from_secs(5)).unwrap();
    assert!(matches!(paused_rx.try_recv(),Err(mpsc::TryRecvError::Empty)));
    release_tx.send(()).unwrap();
    paused_rx.recv_timeout(Wait::from_secs(5)).unwrap().unwrap();
    let requests_after_pause = relay.requests.lock().unwrap().len();
    finished_rx.recv_timeout(Wait::from_secs(5)).unwrap().unwrap();
    pause_thread.join().unwrap();
    run_thread.join().unwrap();
    assert!(!controller.running.load(Ordering::Acquire));
    assert!(!store.sync_enabled().unwrap());
    let later_run = call(&controller,"run_sync_once",json!({})).unwrap();
    assert_eq!(later_run["success"],false);
    assert_eq!(later_run["retryable"],false);
    assert_eq!(relay.requests.lock().unwrap().len(),requests_after_pause);
    assert!(requests_after_pause >= 1);
    assert_eq!(store.get_events("aw-stopwatch",None,None,None).unwrap().len(),1);
    assert!(store.load_sync_key_material().unwrap().is_some());
    store.lock().unwrap();
}
