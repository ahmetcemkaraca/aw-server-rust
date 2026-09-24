use super::EgressSyncRelayTransportV1;
use crate::{
    policy_bundle_signing_bytes, verify_and_activate, EgressProxy, EgressTransport,
};
use aw_datastore::{Datastore, SyncDeviceIdentity, SyncKeyMaterial, SyncSnapshotV1};
use aw_models::{
    Bucket, BucketMetadata, Event, EgressDestinationStatusV1, EgressDestinationV1, EgressPolicyBundleV1,
    EgressOutcomeV1, EgressPurposeV1, EgressRequestV1, EgressUserPolicyV1,
    SignedEgressPolicyBundleV1, SyncEnvelopeV1, TryVec,
};
use aw_sync_e2ee::{
    SyncHttpObjectStoreV1, SyncObjectStoreErrorV1, SyncObjectStoreV1,
    SyncRelayRequestV1, SyncRelayResponseV1, SyncRelayTransportV1, generate_device_identity,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
struct CaptureTransport {
    requests: Arc<Mutex<Vec<(String, String, Vec<u8>)>>>,
    response: Vec<u8>,
}

impl EgressTransport for CaptureTransport {
    fn send(
        &self,
        _: &EgressDestinationV1,
        _: &EgressPurposeV1,
        _: &[u8],
    ) -> Result<(), aw_models::EgressReasonCodeV1> {
        Ok(())
    }

    fn request(
        &self,
        destination: &EgressDestinationV1,
        purpose: &EgressPurposeV1,
        payload: &[u8],
    ) -> Result<Vec<u8>, aw_models::EgressReasonCodeV1> {
        self.requests.lock().unwrap().push((destination.id.clone(), purpose.id.clone(), payload.to_vec()));
        Ok(self.response.clone())
    }
}

fn signed_sync_policy() -> crate::VerifiedPolicyV1 {
    let mut signed = SignedEgressPolicyBundleV1 {
        schema_version: 1,
        signer_key_id: "release-sync-key".into(),
        bundle: EgressPolicyBundleV1 {
            schema_version: 1,
            version: 1,
            hard_deny_version: 1,
            destinations: vec![EgressDestinationV1 {
                id: "sync-relay".into(),
                status: EgressDestinationStatusV1::Available,
                https_origin: Some(["https", "://sync.example"].concat()),
                allowed_purposes: vec!["sync-object-v1".into()],
            }],
            purposes: vec![EgressPurposeV1 {
                id: "sync-object-v1".into(),
                destination_id: "sync-relay".into(),
                endpoint_path: "/v1/objects".into(),
                retention_id: "ciphertext-only".into(),
                retention_disclosure: "Encrypted envelopes only".into(),
                allowed_fields: vec![
                    "/schema_version".into(),
                    "/operation".into(),
                    "/object_id".into(),
                    "/vault_id".into(),
                    "/cursor".into(),
                    "/limit".into(),
                    "/envelope/*".into(),
                ],
            }],
            organization_rules: Vec::new(),
        },
        signature: Vec::new(),
    };
    let keypair = Ed25519KeyPair::from_seed_unchecked(&[0x91; 32]).unwrap();
    signed.signature = keypair.sign(&policy_bundle_signing_bytes(&signed).unwrap()).as_ref().to_vec();
    verify_and_activate(
        &signed,
        &EgressUserPolicyV1 { schema_version: 1, user_rules: Vec::new(), safe_zone_patterns: Vec::new(), after_hours: None },
        &HashMap::from([("release-sync-key".into(), keypair.public_key().as_ref().to_vec())]),
        None,
    ).unwrap()
}

fn configured_store(with_baseline_event: bool) -> (Datastore, SyncEnvelopeV1, aw_sync_e2ee::VaultDataKeyV1) {
    let store = Datastore::open_encrypted(":memory:".into(), "sync-test-key-".repeat(4)).unwrap();
    let identity = generate_device_identity().unwrap();
    store.create_sync_device_identity(&SyncDeviceIdentity::new(
        *identity.device_id_bytes(), identity.secret_for_storage(), identity.signing_seed_for_storage(),
    )).unwrap();
    let root = aw_sync_e2ee::generate_account_root_key().unwrap();
    let vault_id = [0x21; 16];
    let vault_id_text = URL_SAFE_NO_PAD.encode(vault_id);
    let (data_key, wrapped) = aw_sync_e2ee::create_vault_data_key(&root, &vault_id_text, 1).unwrap();
    let plaintext = serde_json::to_vec(&serde_json::json!({
        "app":"synthetic-editor", "title":"private-window-title", "path":"/private/project"
    })).unwrap();
    let encrypted = aw_sync_e2ee::encrypt_snapshot(&data_key, &plaintext).unwrap();
    let envelope = encrypted.envelopes[0].clone();
    store.install_sync_recovery(
        SyncKeyMaterial::new(
            root.secret_for_storage(),
            vault_id,
            1,
            URL_SAFE_NO_PAD.decode(wrapped.nonce).unwrap().try_into().unwrap(),
            URL_SAFE_NO_PAD.decode(wrapped.ciphertext).unwrap().try_into().unwrap(),
        ),
        SyncSnapshotV1::new(
            URL_SAFE_NO_PAD.decode(encrypted.snapshot_id).unwrap().try_into().unwrap(),
            encrypted.envelopes,
        ),
    ).unwrap();
    store.record_sync_pairing(None, [0x29; 16], [0x2A; 16], [0x2B; 32], [0x2C; 32], "2026-09-23T13:00:00Z".into()).unwrap();
    store.confirm_sync_recovery_saved("2026-09-23T13:00:00Z".into()).unwrap();
    if with_baseline_event {
        store.create_bucket(&Bucket {
            bid: None,
            id: "sync-baseline-test".into(),
            _type: "app".into(),
            client: "test".into(),
            hostname: "host".into(),
            created: None,
            data: Default::default(),
            metadata: BucketMetadata::default(),
            events: Some(TryVec::new(vec![Event::new(
                Utc::now(), chrono::Duration::seconds(1),
                serde_json::json!({"app":"synthetic","title":"baseline-marker"}).as_object().unwrap().clone(),
            )])),
            last_updated: None,
        }).unwrap();
    }
    store.begin_sync_baseline().unwrap();
    store.set_egress_kill_switch(false).unwrap();
    (store, envelope, data_key)
}

#[test]
fn signed_sync_transport_checks_user_consent_and_sends_the_exact_opaque_envelope() {
    let response = serde_json::to_vec(&SyncRelayResponseV1 {
        schema_version: 1,
        inserted: Some(true),
        ..Default::default()
    }).unwrap();
    let request_log = Arc::new(Mutex::new(Vec::new()));
    let policy = signed_sync_policy();
    let (datastore, envelope, data_key) = configured_store(false);
    let proxy = EgressProxy::with_transport(datastore, CaptureTransport {
        requests: request_log.clone(),
        response,
    });
    proxy.set_sync_enabled(true, Some("sync-relay".into()), Some("sync-object-v1".into())).unwrap();
    let relay_request = SyncRelayRequestV1 {
        schema_version: 1,
        operation: aw_sync_e2ee::SyncRelayOperationV1::PutIfAbsent,
        object_id: Some(envelope.object_id.clone()),
        vault_id: Some(envelope.vault_id.clone()),
        envelope: Some(envelope.clone()),
        cursor: None,
        limit: None,
    };
    let decision = proxy.preview(&policy, EgressRequestV1 {
        schema_version: 1,
        destination_id: "sync-relay".into(),
        purpose_id: "sync-object-v1".into(),
        retention_id: "ciphertext-only".into(),
        payload: serde_json::to_value(&relay_request).unwrap(),
    }, Utc::now(), 0);
    assert_eq!(decision.outcome, EgressOutcomeV1::Allow, "{:?}", decision.reason_codes);
    assert!(decision.removed_fields.is_empty(), "{:?}", decision.removed_fields);
    let preview: SyncRelayRequestV1 = serde_json::from_value(decision.sanitized_payload.clone().unwrap()).unwrap();
    assert_eq!(preview.envelope, Some(envelope.clone()));
    let relay = EgressSyncRelayTransportV1::new(proxy.clone(), policy.clone());
    let store = SyncHttpObjectStoreV1::new("sync-relay".into(), "sync-object-v1".into(), relay).unwrap();
    assert!(store.put_if_absent(&envelope).unwrap());
    let captured = request_log.lock().unwrap();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].0, "sync-relay");
    assert_eq!(captured[0].1, "sync-object-v1");
    let sent: SyncRelayRequestV1 = serde_json::from_slice(&captured[0].2).unwrap();
    assert_eq!(sent, preview);
    assert_eq!(sent.envelope, Some(envelope.clone()));
    assert!(!String::from_utf8_lossy(&captured[0].2).contains("private-window-title"));
    drop(captured);

    let second_snapshot = aw_sync_e2ee::encrypt_snapshot(&data_key, b"second immutable snapshot").unwrap();
    let second_envelope = second_snapshot.envelopes[0].clone();
    assert_ne!(second_envelope, envelope);
    proxy.validate_sync_envelope(&second_envelope).unwrap();

    let wrong_purpose = EgressSyncRelayTransportV1::new(proxy.clone(), policy);
    assert!(wrong_purpose.request("sync-relay", "custom-endpoint", &relay_request).is_err());
    assert!(wrong_purpose.request("sync-relay", "ai-analysis", &relay_request).is_err());
    assert_eq!(request_log.lock().unwrap().len(), 1);

    let (disabled_datastore, disabled_envelope, _) = configured_store(false);
    let disabled_requests = Arc::new(Mutex::new(Vec::new()));
    let disabled = EgressProxy::with_transport(disabled_datastore, CaptureTransport {
        requests: disabled_requests.clone(),
        response: serde_json::to_vec(&SyncRelayResponseV1 { schema_version: 1, inserted: Some(true), ..Default::default() }).unwrap(),
    });
    let transport = EgressSyncRelayTransportV1::new(disabled, signed_sync_policy());
    assert!(matches!(
        transport.request("sync-relay", "sync-object-v1", &SyncRelayRequestV1 {
            schema_version: 1,
            operation: aw_sync_e2ee::SyncRelayOperationV1::PutIfAbsent,
            object_id: Some(disabled_envelope.object_id.clone()),
            vault_id: Some(disabled_envelope.vault_id.clone()),
            envelope: Some(disabled_envelope),
            cursor: None,
            limit: None,
        }),
        Err(SyncObjectStoreErrorV1::PolicyDenied)
    ));
    assert!(disabled_requests.lock().unwrap().is_empty());
}

#[test]
fn sync_egress_is_blocked_until_the_local_baseline_is_complete() {
    let (datastore, envelope, _) = configured_store(true);
    datastore.set_sync_enabled(true, Some("sync-relay".into()), Some("sync-object-v1".into())).unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let proxy = EgressProxy::with_transport(datastore.clone(), CaptureTransport {
        requests: requests.clone(),
        response: serde_json::to_vec(&SyncRelayResponseV1 { schema_version: 1, inserted: Some(true), ..Default::default() }).unwrap(),
    });
    let relay = EgressSyncRelayTransportV1::new(proxy, signed_sync_policy());
    assert!(SyncHttpObjectStoreV1::new("sync-relay".into(), "sync-object-v1".into(), relay)
        .unwrap().put_if_absent(&envelope).is_err());
    assert!(requests.lock().unwrap().is_empty());
    assert_eq!(datastore.get_events("sync-baseline-test", None, None, None).unwrap().len(), 1);
    datastore.lock().unwrap();
}
