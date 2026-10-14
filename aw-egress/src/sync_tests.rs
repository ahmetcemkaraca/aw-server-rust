use super::EgressSyncRelayTransportV1;
use crate::{policy_bundle_signing_bytes, verify_and_activate, EgressProxy, EgressTransport};
use aw_datastore::{Datastore, SyncDeviceIdentity, SyncKeyMaterial, SyncSnapshotV1};
use aw_entitlements::{
    EntitlementAccessV1, EntitlementSourceV1, EntitlementVerificationErrorV1,
    RuntimeFeatureAccessErrorV1, RuntimeFeatureAccessV1, StoredEntitlementV1,
    ENTITLEMENT_REVOCATION_SCOPE_V1,
};
use aw_models::{
    Bucket, BucketMetadata, EgressDestinationStatusV1, EgressDestinationV1, EgressOutcomeV1,
    EgressPolicyBundleV1, EgressPurposeV1, EgressRequestV1, EgressUserPolicyV1,
    EntitlementClaimsV1, EntitlementRevocationSnapshotV1, EntitlementSigningPayloadV1, Event,
    SignedEgressPolicyBundleV1, SignedEntitlementV1, SyncChunkHeaderV1, SyncEnvelopeV1, TryVec,
};
use aw_sync_e2ee::{
    generate_device_identity, SyncHttpObjectStoreV1, SyncObjectStoreErrorV1, SyncObjectStoreV1,
    SyncRelayRequestV1, SyncRelayResponseV1, SyncRelayTransportV1,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use crate::{BackupScopeV1, BackupTransferDirectionV1};

fn historical_backup() -> (
    aw_sync_e2ee::VaultDataKeyV1,
    aw_sync_e2ee::EncryptedSyncSnapshotV1,
) {
    let root = aw_sync_e2ee::generate_account_root_key().unwrap();
    let (key, _) =
        aw_sync_e2ee::create_vault_data_key(&root, &URL_SAFE_NO_PAD.encode([0x51; 16]), u64::MAX)
            .unwrap();
    let snapshot =
        aw_sync_e2ee::encrypt_snapshot(&key, b"authenticated-private-backup-marker").unwrap();
    (key, snapshot)
}

#[test]
fn backup_egress_scope_rejects_wrong_key_tamper_and_incomplete_snapshot() {
    let (key, snapshot) = historical_backup();
    let mut invalid = snapshot.clone();
    invalid.snapshot_id = URL_SAFE_NO_PAD.encode([8; 16]);
    assert!(
        BackupScopeV1::selected(&key, &invalid, "local", BackupTransferDirectionV1::Upload)
            .is_err()
    );
    let root = aw_sync_e2ee::generate_account_root_key().unwrap();
    let (other, _) = aw_sync_e2ee::create_vault_data_key(
        &root,
        &URL_SAFE_NO_PAD.encode(key.vault_id()),
        key.key_epoch(),
    )
    .unwrap();
    assert!(BackupScopeV1::selected(
        &other,
        &snapshot,
        "local",
        BackupTransferDirectionV1::Upload
    )
    .is_err());
    let mut incomplete = aw_sync_e2ee::encrypt_snapshot(&key, &vec![7; 1_100_000]).unwrap();
    incomplete.envelopes.pop();
    assert!(BackupScopeV1::selected(
        &key,
        &incomplete,
        "local",
        BackupTransferDirectionV1::Upload
    )
    .is_err());
    assert!(BackupScopeV1::discovery(&key, "").is_err());
}

fn clean_backup_store(bundle: &SignedEgressPolicyBundleV1, user: &EgressUserPolicyV1) -> Datastore {
    let store =
        Datastore::open_encrypted(":memory:".into(), "backup-egress-fixture-".repeat(3)).unwrap();
    store.store_egress_policy_state(bundle, user).unwrap();
    store.set_egress_kill_switch(false).unwrap();
    store
}

fn backup_egress_request(request: SyncRelayRequestV1) -> EgressRequestV1 {
    EgressRequestV1 {
        schema_version: 1,
        destination_id: "sync-relay".into(),
        purpose_id: "sync-object-v1".into(),
        retention_id: "ciphertext-only".into(),
        payload: serde_json::to_value(request).unwrap(),
    }
}

fn put_backup(snapshot: &aw_sync_e2ee::EncryptedSyncSnapshotV1) -> EgressRequestV1 {
    let envelope = snapshot.envelopes[0].clone();
    backup_egress_request(SyncRelayRequestV1 {
        schema_version: 1,
        operation: aw_models::SyncRelayOperationV1::PutIfAbsent,
        object_id: Some(envelope.object_id.clone()),
        vault_id: Some(envelope.vault_id.clone()),
        envelope: Some(envelope),
        cursor: None,
        limit: None,
    })
}

#[test]
fn backup_egress_requires_explicit_review_and_sends_historical_ciphertext_from_clean_vault() {
    let now = Utc::now();
    let (bundle, user, policy) = signed_sync_policy(1);
    let store = clean_backup_store(&bundle, &user);
    let (key, snapshot) = historical_backup();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let proxy = EgressProxy::with_transport(
        store.clone(),
        CaptureTransport {
            requests: requests.clone(),
            response: serde_json::to_vec(&SyncRelayResponseV1 {
                schema_version: 1,
                inserted: Some(true),
                ..Default::default()
            })
            .unwrap(),
        },
    )
    .with_sync_access(signed_sync_access());
    let scope =
        BackupScopeV1::selected(&key, &snapshot, "local", BackupTransferDirectionV1::Upload)
            .unwrap();
    let preview = proxy
        .preview_backup(&policy, scope, "sync-relay", now, 0)
        .unwrap();
    assert!(proxy
        .approve_backup(&policy, &preview, false, now, 0)
        .is_err());
    assert!(requests.lock().unwrap().is_empty());
    let permit = proxy
        .approve_backup(&policy, &preview, true, now, 0)
        .unwrap();
    let request = put_backup(&snapshot);
    assert!(proxy
        .send_sync_request(&policy, request.clone(), now, 0)
        .is_err());
    proxy
        .send_backup_request(&policy, &permit, request.clone(), now, 0)
        .unwrap();
    assert_eq!(requests.lock().unwrap().len(), 1);
    assert_eq!(
        requests.lock().unwrap()[0].2,
        serde_json::to_vec(&request.payload).unwrap()
    );
    assert!(!String::from_utf8(requests.lock().unwrap()[0].2.clone())
        .unwrap()
        .contains("private-backup-marker"));
    assert!(store.load_sync_key_material().unwrap().is_none());
    assert!(store.load_sync_device_identity().unwrap().is_none());
    assert!(!store.sync_enabled().unwrap());
    assert_eq!(store.get_egress_receipts(10).unwrap().len(), 1);
    store.close();
}

#[test]
fn backup_egress_selected_permit_rejects_unselected_operations_objects_and_bytes() {
    let now = Utc::now();
    let (bundle, user, policy) = signed_sync_policy(1);
    let store = clean_backup_store(&bundle, &user);
    let (key, snapshot) = historical_backup();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let proxy = EgressProxy::with_transport(
        store.clone(),
        CaptureTransport {
            requests: requests.clone(),
            response: Vec::new(),
        },
    )
    .with_sync_access(signed_sync_access());
    let scope =
        BackupScopeV1::selected(&key, &snapshot, "local", BackupTransferDirectionV1::Upload)
            .unwrap();
    let preview = proxy
        .preview_backup(&policy, scope, "sync-relay", now, 0)
        .unwrap();
    let permit = proxy
        .approve_backup(&policy, &preview, true, now, 0)
        .unwrap();
    for changed in [
        "operation",
        "object",
        "ciphertext",
        "destination",
        "purpose",
    ] {
        let mut request = put_backup(&snapshot);
        match changed {
            "operation" => {
                request.payload = serde_json::to_value(SyncRelayRequestV1 {
                    schema_version: 1,
                    operation: aw_models::SyncRelayOperationV1::Get,
                    object_id: Some(snapshot.envelopes[0].object_id.clone()),
                    vault_id: None,
                    envelope: None,
                    cursor: None,
                    limit: None,
                })
                .unwrap();
            }
            "object" => {
                let id = URL_SAFE_NO_PAD.encode([9; 16]);
                request.payload["object_id"] = serde_json::json!(id);
                request.payload["envelope"]["object_id"] = request.payload["object_id"].clone();
            }
            "ciphertext" => {
                request.payload["envelope"]["ciphertext"] =
                    serde_json::json!(URL_SAFE_NO_PAD.encode([0; 64]));
            }
            "destination" => request.destination_id = "other".into(),
            "purpose" => request.purpose_id = "ai.custom_endpoint".into(),
            _ => unreachable!(),
        }
        assert!(
            proxy
                .send_backup_request(&policy, &permit, request, now, 0)
                .is_err(),
            "{changed}"
        );
    }
    assert!(requests.lock().unwrap().is_empty());
    store.close();
}

#[test]
fn backup_egress_discovery_is_list_only_and_checks_the_reviewed_vault() {
    let now = Utc::now();
    let (bundle, user, policy) = signed_sync_policy(1);
    let store = clean_backup_store(&bundle, &user);
    let (key, snapshot) = historical_backup();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let proxy = EgressProxy::with_transport(
        store.clone(),
        CaptureTransport {
            requests: requests.clone(),
            response: serde_json::to_vec(&SyncRelayResponseV1 {
                schema_version: 1,
                ..Default::default()
            })
            .unwrap(),
        },
    )
    .with_sync_access(signed_sync_access());
    let preview = proxy
        .preview_backup(
            &policy,
            BackupScopeV1::discovery(&key, "local").unwrap(),
            "sync-relay",
            now,
            0,
        )
        .unwrap();
    let permit = proxy
        .approve_backup(&policy, &preview, true, now, 0)
        .unwrap();
    assert!(proxy
        .send_backup_request(&policy, &permit, put_backup(&snapshot), now, 0)
        .is_err());
    let mut request = backup_egress_request(SyncRelayRequestV1 {
        schema_version: 1,
        operation: aw_models::SyncRelayOperationV1::ListOpaqueHeads,
        object_id: None,
        vault_id: Some(URL_SAFE_NO_PAD.encode(key.vault_id())),
        envelope: None,
        cursor: None,
        limit: Some(16),
    });
    proxy
        .send_backup_request(&policy, &permit, request.clone(), now, 0)
        .unwrap();
    request.payload["vault_id"] = serde_json::json!(URL_SAFE_NO_PAD.encode([8; 16]));
    assert!(proxy
        .send_backup_request(&policy, &permit, request, now, 0)
        .is_err());
    assert_eq!(requests.lock().unwrap().len(), 1);
    store.close();
}

#[test]
fn backup_egress_approval_expires_and_cannot_revive_after_kill_or_clear() {
    let now = Utc::now();
    let (bundle, user, policy) = signed_sync_policy(1);
    let (key, snapshot) = historical_backup();
    for revoked in ["expiry", "kill", "clear", "policy"] {
        let store = clean_backup_store(&bundle, &user);
        let requests = Arc::new(Mutex::new(Vec::new()));
        let proxy = EgressProxy::with_transport(
            store.clone(),
            CaptureTransport {
                requests: requests.clone(),
                response: Vec::new(),
            },
        )
        .with_sync_access(signed_sync_access());
        let scope =
            BackupScopeV1::selected(&key, &snapshot, "local", BackupTransferDirectionV1::Upload)
                .unwrap();
        let preview = proxy
            .preview_backup(&policy, scope, "sync-relay", now, 0)
            .unwrap();
        let permit = proxy
            .approve_backup(&policy, &preview, true, now, 0)
            .unwrap();
        let at = match revoked {
            "expiry" => now + chrono::Duration::minutes(5),
            "kill" => {
                proxy.set_kill_switch(true).unwrap();
                proxy.set_kill_switch(false).unwrap();
                now
            }
            "clear" => {
                proxy
                    .with_policy_update(|| store.clear_egress_approvals().unwrap())
                    .unwrap();
                now
            }
            "policy" => {
                store.store_egress_policy_state(&bundle, &user).unwrap();
                now
            }
            _ => unreachable!(),
        };
        assert!(
            proxy
                .send_backup_request(&policy, &permit, put_backup(&snapshot), at, 0)
                .is_err(),
            "{revoked}"
        );
        assert!(requests.lock().unwrap().is_empty());
        store.close();
    }
}

#[test]
fn backup_egress_download_checks_exact_response_and_metadata_receipts_at_transport() {
    let now = Utc::now();
    let (bundle, user, policy) = signed_sync_policy(1);
    let (key, snapshot) = historical_backup();
    for tampered in [false, true] {
        let store = clean_backup_store(&bundle, &user);
        let requests = Arc::new(Mutex::new(Vec::new()));
        let mut envelope = snapshot.envelopes[0].clone();
        if tampered {
            envelope.ciphertext = URL_SAFE_NO_PAD.encode([7; 64]);
        }
        let proxy = EgressProxy::with_transport(
            store.clone(),
            CaptureTransport {
                requests: requests.clone(),
                response: serde_json::to_vec(&SyncRelayResponseV1 {
                    schema_version: 1,
                    envelope: Some(envelope),
                    ..Default::default()
                })
                .unwrap(),
            },
        )
        .with_sync_access(signed_sync_access());
        let preview = proxy
            .preview_backup(
                &policy,
                BackupScopeV1::selected(
                    &key,
                    &snapshot,
                    "local",
                    BackupTransferDirectionV1::Download,
                )
                .unwrap(),
                "sync-relay",
                now,
                0,
            )
            .unwrap();
        let metadata = preview.metadata();
        assert_eq!(metadata["key_epoch"], u64::MAX.to_string());
        assert!(metadata.get("ciphertext").is_none());
        assert!(!metadata
            .to_string()
            .contains(&snapshot.envelopes[0].ciphertext));
        let permit = proxy
            .approve_backup(&policy, &preview, true, now, 0)
            .unwrap();
        let remote = SyncHttpObjectStoreV1::new(
            "sync-relay".into(),
            "sync-object-v1".into(),
            crate::EgressBackupRelayTransportV1::new(proxy, policy.clone(), permit),
        )
        .unwrap();
        let response = remote.get(&snapshot.envelopes[0].object_id);
        if tampered {
            assert!(response.is_err());
        } else {
            assert_eq!(response.unwrap(), Some(snapshot.envelopes[0].clone()));
        }
        assert_eq!(requests.lock().unwrap().len(), 1);
        let receipts = store.get_egress_receipts(10).unwrap();
        assert_eq!(receipts.len(), 1);
        let serialized = serde_json::to_string(&receipts).unwrap();
        assert!(!serialized.contains("private-backup-marker"));
        assert!(!serialized.contains(&snapshot.envelopes[0].object_id));
        store.close();
    }
}

#[test]
fn backup_egress_rechecks_paid_access_after_approval_on_every_request() {
    let now = Utc::now();
    let epoch = now.timestamp() as u64;
    let mut proof = signed_sync_proof(epoch);
    proof.entitlement.payload.claims.expires_at = epoch + 5;
    proof.entitlement.payload.claims.grace_until = epoch + 10;
    sign_sync_proof(&mut proof);
    let (access, _) = sync_access_with_proof(proof, epoch);
    let (bundle, user, policy) = signed_sync_policy(1);
    let store = clean_backup_store(&bundle, &user);
    let (key, snapshot) = historical_backup();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let proxy = EgressProxy::with_transport(
        store.clone(),
        CaptureTransport {
            requests: requests.clone(),
            response: serde_json::to_vec(&SyncRelayResponseV1 {
                schema_version: 1,
                inserted: Some(true),
                ..Default::default()
            })
            .unwrap(),
        },
    )
    .with_sync_access(access);
    let preview = proxy
        .preview_backup(
            &policy,
            BackupScopeV1::selected(&key, &snapshot, "local", BackupTransferDirectionV1::Upload)
                .unwrap(),
            "sync-relay",
            now,
            0,
        )
        .unwrap();
    let permit = proxy
        .approve_backup(&policy, &preview, true, now, 0)
        .unwrap();
    proxy
        .send_backup_request(&policy, &permit, put_backup(&snapshot), now, 0)
        .unwrap();
    assert!(proxy
        .send_backup_request(
            &policy,
            &permit,
            put_backup(&snapshot),
            now + chrono::Duration::seconds(11),
            0
        )
        .is_err());
    assert_eq!(requests.lock().unwrap().len(), 1);
    assert_eq!(store.get_egress_receipts(10).unwrap().len(), 1);
    store.close();
}

#[test]
fn backup_egress_missing_access_or_registered_policy_sends_nothing() {
    let now = Utc::now();
    let (bundle, user, policy) = signed_sync_policy(1);
    let (key, snapshot) = historical_backup();
    let store = clean_backup_store(&bundle, &user);
    let requests = Arc::new(Mutex::new(Vec::new()));
    let proxy = EgressProxy::with_transport(
        store.clone(),
        CaptureTransport {
            requests: requests.clone(),
            response: Vec::new(),
        },
    );
    let preview = proxy
        .preview_backup(
            &policy,
            BackupScopeV1::selected(&key, &snapshot, "local", BackupTransferDirectionV1::Upload)
                .unwrap(),
            "sync-relay",
            now,
            0,
        )
        .unwrap();
    let permit = proxy
        .approve_backup(&policy, &preview, true, now, 0)
        .unwrap();
    assert!(proxy
        .send_backup_request(&policy, &permit, put_backup(&snapshot), now, 0)
        .is_err());
    assert!(requests.lock().unwrap().is_empty());
    assert!(store.get_egress_receipts(10).unwrap().is_empty());
    store.close();
    let empty = Datastore::open_encrypted(":memory:".into(), "b".repeat(64)).unwrap();
    empty.set_egress_kill_switch(false).unwrap();
    let proxy = EgressProxy::with_transport(
        empty.clone(),
        CaptureTransport {
            requests: requests.clone(),
            response: Vec::new(),
        },
    )
    .with_sync_access(signed_sync_access());
    assert!(proxy
        .preview_backup(
            &policy,
            BackupScopeV1::discovery(&key, "local").unwrap(),
            "sync-relay",
            now,
            0
        )
        .is_err());
    assert!(requests.lock().unwrap().is_empty());
    empty.close();
}

#[test]
fn backup_egress_signed_revocation_blocks_an_existing_permit_and_replay_cannot_restore_access() {
    let now = Utc::now();
    let epoch = now.timestamp() as u64;
    let proof = signed_sync_proof(epoch);
    let (access, _) = sync_access_with_proof(proof.clone(), epoch);
    let (bundle, user, policy) = signed_sync_policy(1);
    let store = clean_backup_store(&bundle, &user);
    let (key, snapshot) = historical_backup();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let proxy = EgressProxy::with_transport(
        store.clone(),
        CaptureTransport {
            requests: requests.clone(),
            response: serde_json::to_vec(&SyncRelayResponseV1 {
                schema_version: 1,
                inserted: Some(true),
                ..Default::default()
            })
            .unwrap(),
        },
    )
    .with_sync_access(access.clone());
    let preview = proxy
        .preview_backup(
            &policy,
            BackupScopeV1::selected(&key, &snapshot, "local", BackupTransferDirectionV1::Upload)
                .unwrap(),
            "sync-relay",
            now,
            0,
        )
        .unwrap();
    let permit = proxy
        .approve_backup(&policy, &preview, true, now, 0)
        .unwrap();
    proxy
        .send_backup_request(&policy, &permit, put_backup(&snapshot), now, 0)
        .unwrap();
    let mut revoked = proof.clone();
    let revocations = revoked.revocations.as_mut().unwrap();
    revocations.sequence = 2;
    revocations
        .revoked_entitlement_ids
        .push(proof.entitlement.payload.claims.entitlement_id.clone());
    sign_sync_proof(&mut revoked);
    assert!(access.install(revoked, epoch).is_err());
    assert!(proxy
        .send_backup_request(&policy, &permit, put_backup(&snapshot), now, 0)
        .is_err());
    assert!(access.install(proof, epoch).is_err());
    assert!(proxy
        .send_backup_request(&policy, &permit, put_backup(&snapshot), now, 0)
        .is_err());
    assert_eq!(requests.lock().unwrap().len(), 1);
    store.close();
}

#[test]
fn backup_egress_same_version_user_rules_and_reopened_worker_invalidate_review_and_permit() {
    let now = Utc::now();
    let (bundle, mut user, policy) = signed_sync_policy(1);
    let store = clean_backup_store(&bundle, &user);
    let (key, snapshot) = historical_backup();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let proxy = EgressProxy::with_transport(
        store.clone(),
        CaptureTransport {
            requests: requests.clone(),
            response: Vec::new(),
        },
    )
    .with_sync_access(signed_sync_access());
    let preview = proxy
        .preview_backup(
            &policy,
            BackupScopeV1::discovery(&key, "local").unwrap(),
            "sync-relay",
            now,
            0,
        )
        .unwrap();
    let permit = proxy
        .approve_backup(&policy, &preview, true, now, 0)
        .unwrap();
    let allowed = backup_egress_request(SyncRelayRequestV1 {
        schema_version: 1,
        operation: aw_models::SyncRelayOperationV1::ListOpaqueHeads,
        object_id: None,
        vault_id: Some(URL_SAFE_NO_PAD.encode(key.vault_id())),
        envelope: None,
        cursor: None,
        limit: Some(16),
    });
    user.user_rules.push(aw_models::EgressRuleV1 {
        pattern: aw_models::EgressPatternV1 {
            kind: aw_models::EgressMatchKindV1::Field,
            value: "/envelope/ciphertext".into(),
        },
        action: aw_models::EgressRuleActionV1::Deny,
    });
    proxy
        .with_policy_update(|| store.store_egress_user_policy(&user))
        .unwrap()
        .unwrap();
    assert!(proxy
        .approve_backup(&policy, &preview, true, now, 0)
        .is_err());
    assert!(proxy
        .send_backup_request(&policy, &permit, allowed.clone(), now, 0)
        .is_err());
    store.close();
    store
        .unlock_encrypted(":memory:".into(), "new-backup-vault-key".repeat(4))
        .unwrap();
    store
        .store_egress_policy_state(
            &bundle,
            &EgressUserPolicyV1 {
                schema_version: 1,
                user_rules: Vec::new(),
                safe_zone_patterns: Vec::new(),
                after_hours: None,
            },
        )
        .unwrap();
    store.set_egress_kill_switch(false).unwrap();
    assert!(proxy
        .approve_backup(&policy, &preview, true, now, 0)
        .is_err());
    assert!(proxy
        .send_backup_request(&policy, &permit, allowed, now, 0)
        .is_err());
    assert!(requests.lock().unwrap().is_empty());
    store.close();
}

#[derive(Default)]
struct MemoryEntitlementSource {
    proof: Mutex<Option<StoredEntitlementV1>>,
    revocation_floor: Mutex<u64>,
}

impl EntitlementSourceV1 for MemoryEntitlementSource {
    fn load(&self) -> Result<Option<StoredEntitlementV1>, &'static str> {
        Ok(self.proof.lock().unwrap().clone())
    }

    fn save(&self, proof: &StoredEntitlementV1) -> Result<(), &'static str> {
        *self.proof.lock().unwrap() = Some(proof.clone());
        Ok(())
    }

    fn revocation_floor(&self, scope: &str) -> Result<u64, &'static str> {
        assert_eq!(scope, ENTITLEMENT_REVOCATION_SCOPE_V1);
        Ok(*self.revocation_floor.lock().unwrap())
    }

    fn advance_revocation_floor(&self, scope: &str, sequence: u64) -> Result<(), &'static str> {
        assert_eq!(scope, ENTITLEMENT_REVOCATION_SCOPE_V1);
        let mut floor = self.revocation_floor.lock().unwrap();
        *floor = (*floor).max(sequence);
        Ok(())
    }
}

fn sign_sync_proof(proof: &mut StoredEntitlementV1) {
    let signer = Ed25519KeyPair::from_seed_unchecked(&[0x94; 32]).unwrap();
    proof.entitlement.signature = URL_SAFE_NO_PAD.encode(
        signer
            .sign(&proof.entitlement.payload.signing_bytes().unwrap())
            .as_ref(),
    );
    if let Some(snapshot) = &mut proof.revocations {
        snapshot.signature =
            URL_SAFE_NO_PAD.encode(signer.sign(&snapshot.signing_bytes().unwrap()).as_ref());
    }
}

fn signed_sync_proof(now: u64) -> StoredEntitlementV1 {
    let mut proof = StoredEntitlementV1 {
        entitlement: SignedEntitlementV1 {
            payload: EntitlementSigningPayloadV1 {
                key_id: "synthetic-billing-key".into(),
                claims: EntitlementClaimsV1 {
                    schema_version: 1,
                    entitlement_id: URL_SAFE_NO_PAD.encode([0x41; 16]),
                    account_id: URL_SAFE_NO_PAD.encode([0x42; 16]),
                    plan_id: "paid-sync".into(),
                    feature_ids: vec!["e2ee-sync".into()],
                    issued_at: now - 60,
                    expires_at: now + 600,
                    grace_until: now + 3600,
                    device_limit: 2,
                },
            },
            signature: String::new(),
        },
        revocations: Some(EntitlementRevocationSnapshotV1 {
            schema_version: 1,
            key_id: "synthetic-billing-key".into(),
            sequence: 1,
            issued_at: now - 60,
            expires_at: now + 7200,
            revoked_entitlement_ids: Vec::new(),
            signature: String::new(),
        }),
    };
    sign_sync_proof(&mut proof);
    proof
}

fn sync_access_with_proof(
    proof: StoredEntitlementV1,
    now: u64,
) -> (Arc<RuntimeFeatureAccessV1>, Arc<MemoryEntitlementSource>) {
    let signer = Ed25519KeyPair::from_seed_unchecked(&[0x94; 32]).unwrap();
    let source = Arc::new(MemoryEntitlementSource::default());
    let runtime = Arc::new(RuntimeFeatureAccessV1::new(
        BTreeMap::from([(
            "synthetic-billing-key".into(),
            signer.public_key().as_ref().try_into().unwrap(),
        )]),
        0,
        source.clone(),
    ));
    runtime.install(proof, now).unwrap();
    (runtime, source)
}

fn signed_sync_access() -> Arc<RuntimeFeatureAccessV1> {
    let now = Utc::now().timestamp() as u64;
    sync_access_with_proof(signed_sync_proof(now), now).0
}

#[derive(Clone)]
struct CaptureTransport {
    requests: Arc<Mutex<Vec<(String, String, Vec<u8>)>>>,
    response: Vec<u8>,
}

impl EgressTransport for CaptureTransport {
    fn send(
        &self,
        destination: &EgressDestinationV1,
        purpose: &EgressPurposeV1,
        payload: &[u8],
    ) -> Result<(), aw_models::EgressReasonCodeV1> {
        self.requests.lock().unwrap().push((
            destination.id.clone(),
            purpose.id.clone(),
            payload.to_vec(),
        ));
        Ok(())
    }

    fn request(
        &self,
        destination: &EgressDestinationV1,
        purpose: &EgressPurposeV1,
        payload: &[u8],
    ) -> Result<Vec<u8>, aw_models::EgressReasonCodeV1> {
        self.requests.lock().unwrap().push((
            destination.id.clone(),
            purpose.id.clone(),
            payload.to_vec(),
        ));
        Ok(self.response.clone())
    }
}

fn signed_sync_policy(
    version: u64,
) -> (
    SignedEgressPolicyBundleV1,
    EgressUserPolicyV1,
    crate::VerifiedPolicyV1,
) {
    let mut signed = SignedEgressPolicyBundleV1 {
        schema_version: 1,
        signer_key_id: "release-sync-key".into(),
        bundle: EgressPolicyBundleV1 {
            schema_version: 1,
            version,
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
    signed.signature = keypair
        .sign(&policy_bundle_signing_bytes(&signed).unwrap())
        .as_ref()
        .to_vec();
    let user = EgressUserPolicyV1 {
        schema_version: 1,
        user_rules: Vec::new(),
        safe_zone_patterns: Vec::new(),
        after_hours: None,
    };
    let verified = verify_and_activate(
        &signed,
        &user,
        &HashMap::from([(
            "release-sync-key".into(),
            keypair.public_key().as_ref().to_vec(),
        )]),
        None,
    )
    .unwrap();
    (signed, user, verified)
}

fn configured_store(
    with_baseline_event: bool,
) -> (Datastore, SyncEnvelopeV1, aw_sync_e2ee::VaultDataKeyV1) {
    let store = Datastore::open_encrypted(":memory:".into(), "sync-test-key-".repeat(4)).unwrap();
    let identity = generate_device_identity().unwrap();
    store
        .create_sync_device_identity(&SyncDeviceIdentity::new(
            *identity.device_id_bytes(),
            identity.secret_for_storage(),
            identity.signing_seed_for_storage(),
        ))
        .unwrap();
    let root = aw_sync_e2ee::generate_account_root_key().unwrap();
    let vault_id = [0x21; 16];
    let vault_id_text = URL_SAFE_NO_PAD.encode(vault_id);
    let (data_key, wrapped) =
        aw_sync_e2ee::create_vault_data_key(&root, &vault_id_text, 1).unwrap();
    let plaintext = serde_json::to_vec(&serde_json::json!({
        "app":"synthetic-editor", "title":"private-window-title", "path":"/private/project"
    }))
    .unwrap();
    let encrypted = aw_sync_e2ee::encrypt_snapshot(&data_key, &plaintext).unwrap();
    let envelope = encrypted.envelopes[0].clone();
    store
        .install_sync_recovery(
            SyncKeyMaterial::new(
                root.secret_for_storage(),
                vault_id,
                1,
                URL_SAFE_NO_PAD
                    .decode(wrapped.nonce)
                    .unwrap()
                    .try_into()
                    .unwrap(),
                URL_SAFE_NO_PAD
                    .decode(wrapped.ciphertext)
                    .unwrap()
                    .try_into()
                    .unwrap(),
            ),
            SyncSnapshotV1::new(
                URL_SAFE_NO_PAD
                    .decode(encrypted.snapshot_id)
                    .unwrap()
                    .try_into()
                    .unwrap(),
                encrypted.envelopes,
            ),
        )
        .unwrap();
    store
        .record_sync_pairing(
            None,
            [0x29; 16],
            [0x2A; 16],
            [0x2B; 32],
            [0x2C; 32],
            "2026-09-23T13:00:00Z".into(),
        )
        .unwrap();
    store
        .confirm_sync_recovery_saved("2026-09-23T13:00:00Z".into())
        .unwrap();
    if with_baseline_event {
        store
            .create_bucket(&Bucket {
                bid: None,
                id: "sync-baseline-test".into(),
                _type: "app".into(),
                client: "test".into(),
                hostname: "host".into(),
                created: None,
                data: Default::default(),
                metadata: BucketMetadata::default(),
                events: Some(TryVec::new(vec![Event::new(
                    Utc::now(),
                    chrono::Duration::seconds(1),
                    serde_json::json!({"app":"synthetic","title":"baseline-marker"})
                        .as_object()
                        .unwrap()
                        .clone(),
                )])),
                last_updated: None,
            })
            .unwrap();
    }
    store.begin_sync_baseline().unwrap();
    store.set_egress_kill_switch(false).unwrap();
    (store, envelope, data_key)
}

fn signed_operation_envelope(
    datastore: &Datastore,
    data_key: &aw_sync_e2ee::VaultDataKeyV1,
    object_id: String,
) -> SyncEnvelopeV1 {
    let stored = datastore.load_sync_device_identity().unwrap().unwrap();
    let writer = aw_sync_e2ee::DeviceIdentityV1::from_bytes(
        *stored.device_id(),
        zeroize::Zeroizing::new(*stored.private_key()),
        zeroize::Zeroizing::new(*stored.signing_seed()),
    );
    let keys = datastore.load_sync_key_material().unwrap().unwrap();
    let operation = aw_sync_e2ee::create_event_correction(
        *writer.device_id_bytes(),
        1,
        *writer.device_id_bytes(),
        1,
        [0x43; 16],
        BTreeMap::from([(
            "data:title".into(),
            serde_json::json!("private-operation-title"),
        )]),
    )
    .unwrap();
    let manifest = aw_sync_e2ee::SyncManifestV1::new_signed(
        &writer,
        *keys.vault_id(),
        keys.key_epoch(),
        1,
        [0; 32],
        vec![operation],
    )
    .unwrap();
    manifest
        .verify_signature(&writer.public_identity(), keys.vault_id())
        .unwrap();
    aw_sync_e2ee::encrypt_manifest(
        data_key,
        &SyncChunkHeaderV1 {
            schema_version: 1,
            object_id,
            vault_id: URL_SAFE_NO_PAD.encode(keys.vault_id()),
            key_epoch: keys.key_epoch(),
        },
        &manifest,
    )
    .unwrap()
}

#[test]
fn sync_transport_accepts_authenticated_manifest_with_secret_like_opaque_metadata() {
    let (bundle, user, policy) = signed_sync_policy(1);
    let (datastore, _, data_key) = configured_store(false);
    datastore.store_egress_policy_state(&bundle, &user).unwrap();
    let envelope =
        signed_operation_envelope(&datastore, &data_key, "ghpAAAAAAAAAAAAAAAAAAA".into());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let proxy = EgressProxy::with_transport(
        datastore,
        CaptureTransport {
            requests: requests.clone(),
            response: serde_json::to_vec(&SyncRelayResponseV1 {
                schema_version: 1,
                inserted: Some(true),
                ..Default::default()
            })
            .unwrap(),
        },
    )
    .with_sync_access(signed_sync_access());
    proxy.validate_sync_envelope(&envelope).unwrap();
    proxy
        .set_sync_enabled(
            true,
            Some("sync-relay".into()),
            Some("sync-object-v1".into()),
        )
        .unwrap();
    let remote = SyncHttpObjectStoreV1::new(
        "sync-relay".into(),
        "sync-object-v1".into(),
        EgressSyncRelayTransportV1::new(proxy, policy),
    )
    .unwrap();
    assert!(remote.put_if_absent(&envelope).unwrap());
    let captured = requests.lock().unwrap();
    assert_eq!(captured.len(), 1);
    let sent: SyncRelayRequestV1 = serde_json::from_slice(&captured[0].2).unwrap();
    assert_eq!(sent.envelope, Some(envelope.clone()));
    assert!(crate::has_secret(&serde_json::to_value(&sent).unwrap()).unwrap());
    assert!(!String::from_utf8_lossy(&captured[0].2).contains("private-operation-title"));
    drop(captured);
    let mut unauthenticated = envelope;
    unauthenticated.ciphertext = URL_SAFE_NO_PAD.encode([0; 80]);
    assert!(matches!(
        remote.put_if_absent(&unauthenticated),
        Err(SyncObjectStoreErrorV1::InvalidEnvelope)
    ));
    assert_eq!(requests.lock().unwrap().len(), 1);
}

#[test]
fn sync_transport_opaque_metadata_does_not_exempt_plaintext_or_other_purposes() {
    use aw_models::EgressReasonCodeV1::{InvalidPayload, SecretDetected};
    let (bundle, user, policy) = signed_sync_policy(1);
    let (datastore, _, data_key) = configured_store(false);
    datastore.store_egress_policy_state(&bundle, &user).unwrap();
    let envelope =
        signed_operation_envelope(&datastore, &data_key, "ghpAAAAAAAAAAAAAAAAAAA".into());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let proxy = EgressProxy::with_transport(
        datastore,
        CaptureTransport {
            requests: requests.clone(),
            response: Vec::new(),
        },
    )
    .with_sync_access(signed_sync_access());
    let relay_request = SyncRelayRequestV1 {
        schema_version: 1,
        operation: aw_sync_e2ee::SyncRelayOperationV1::PutIfAbsent,
        object_id: Some(envelope.object_id.clone()),
        vault_id: Some(envelope.vault_id.clone()),
        envelope: Some(envelope),
        cursor: None,
        limit: None,
    };
    let payload = serde_json::to_value(relay_request).unwrap();
    let mut plaintext = payload.clone();
    plaintext["raw"] = serde_json::json!("ghp_SYNTHETIC_SECRET_12345678");
    let mut malformed = payload.clone();
    malformed["envelope"]["ciphertext"] = serde_json::json!("ghp_SYNTHETIC_SECRET_12345678!");
    let mut array_envelope = payload.clone();
    let envelope = &payload["envelope"];
    array_envelope["envelope"] = serde_json::json!([
        envelope["schema_version"],
        envelope["object_id"],
        envelope["vault_id"],
        envelope["key_epoch"],
        envelope["nonce"],
        envelope["ciphertext"],
    ]);
    let array_request = serde_json::json!([
        payload["schema_version"],
        payload["operation"],
        payload["object_id"],
        payload["vault_id"],
        payload["envelope"],
        payload["cursor"],
        payload["limit"],
    ]);
    for (purpose, payload, reason) in [
        ("sync-object-v1", plaintext, SecretDetected),
        ("sync-object-v1", malformed, SecretDetected),
        ("sync-object-v1", array_envelope, SecretDetected),
        ("sync-object-v1", array_request, InvalidPayload),
        (
            "other-purpose",
            serde_json::json!({"text":"ghp_SYNTHETIC_SECRET_12345678"}),
            SecretDetected,
        ),
    ] {
        let decision = proxy.preview(
            &policy,
            EgressRequestV1 {
                schema_version: 1,
                destination_id: "sync-relay".into(),
                purpose_id: purpose.into(),
                retention_id: "ciphertext-only".into(),
                payload,
            },
            Utc::now(),
            0,
        );
        assert_eq!(decision.outcome, EgressOutcomeV1::Deny);
        assert_eq!(decision.reason_codes, vec![reason]);
    }
    proxy
        .set_sync_enabled(
            true,
            Some("sync-relay".into()),
            Some("sync-object-v1".into()),
        )
        .unwrap();
    let mut forged = payload;
    forged["envelope"]["ciphertext"] = serde_json::json!(URL_SAFE_NO_PAD.encode([0; 80]));
    let request = EgressRequestV1 {
        schema_version: 1,
        destination_id: "sync-relay".into(),
        purpose_id: "sync-object-v1".into(),
        retention_id: "ciphertext-only".into(),
        payload: forged,
    };
    let now = Utc::now();
    let decision = proxy.preview(&policy, request.clone(), now, 0);
    assert_eq!(decision.outcome, EgressOutcomeV1::Allow);
    let approved = proxy
        .approve(
            &policy,
            &decision.preview_id,
            aw_models::EgressApprovalScopeV1::Once,
            Some(now + chrono::Duration::minutes(5)),
            now,
            0,
        )
        .unwrap();
    assert_eq!(
        proxy
            .send_approval(
                &policy,
                &decision.preview_id,
                approved.approval_id(),
                now,
                0
            )
            .unwrap_err(),
        aw_models::EgressReasonCodeV1::InvalidPayload
    );
    assert_eq!(
        proxy
            .begin_send()
            .unwrap()
            .send_approval(
                &policy,
                &decision.preview_id,
                approved.approval_id(),
                now,
                0
            )
            .unwrap_err(),
        aw_models::EgressReasonCodeV1::InvalidPayload
    );
    assert_eq!(
        proxy.send(&policy, approved, now, 0).unwrap_err(),
        aw_models::EgressReasonCodeV1::InvalidPayload
    );
    let approved = proxy
        .approve(
            &policy,
            &decision.preview_id,
            aw_models::EgressApprovalScopeV1::Once,
            Some(now + chrono::Duration::minutes(5)),
            now,
            0,
        )
        .unwrap();
    assert_eq!(
        proxy
            .begin_send()
            .unwrap()
            .send(&policy, approved, now, 0)
            .unwrap_err(),
        aw_models::EgressReasonCodeV1::InvalidPayload
    );
    assert_eq!(
        proxy
            .send_sync_request(&policy, request, now, 0)
            .unwrap_err(),
        aw_models::EgressReasonCodeV1::InvalidPayload
    );
    assert!(requests.lock().unwrap().is_empty());
}

#[test]
fn sync_transport_opaque_exemption_keeps_generic_sync_disabled_until_consent() {
    let (bundle, user, policy) = signed_sync_policy(1);
    let (datastore, _, data_key) = configured_store(false);
    datastore.store_egress_policy_state(&bundle, &user).unwrap();
    let envelope =
        signed_operation_envelope(&datastore, &data_key, "ghpAAAAAAAAAAAAAAAAAAA".into());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let proxy = EgressProxy::with_transport(
        datastore,
        CaptureTransport {
            requests: requests.clone(),
            response: Vec::new(),
        },
    )
    .with_sync_access(signed_sync_access());
    let relay_request = SyncRelayRequestV1 {
        schema_version: 1,
        operation: aw_sync_e2ee::SyncRelayOperationV1::PutIfAbsent,
        object_id: Some(envelope.object_id.clone()),
        vault_id: Some(envelope.vault_id.clone()),
        envelope: Some(envelope),
        cursor: None,
        limit: None,
    };
    let now = Utc::now();
    let decision = proxy.preview(
        &policy,
        EgressRequestV1 {
            schema_version: 1,
            destination_id: "sync-relay".into(),
            purpose_id: "sync-object-v1".into(),
            retention_id: "ciphertext-only".into(),
            payload: serde_json::to_value(relay_request).unwrap(),
        },
        now,
        0,
    );
    assert_eq!(decision.outcome, EgressOutcomeV1::Allow);
    let approved = proxy
        .approve(
            &policy,
            &decision.preview_id,
            aw_models::EgressApprovalScopeV1::Once,
            Some(now + chrono::Duration::minutes(5)),
            now,
            0,
        )
        .unwrap();
    assert_eq!(
        proxy
            .send_approval(
                &policy,
                &decision.preview_id,
                approved.approval_id(),
                now,
                0
            )
            .unwrap_err(),
        aw_models::EgressReasonCodeV1::ApprovalRequired
    );
    assert_eq!(
        proxy.send(&policy, approved, now, 0).unwrap_err(),
        aw_models::EgressReasonCodeV1::ApprovalRequired
    );
    assert!(requests.lock().unwrap().is_empty());
    proxy
        .set_sync_enabled(
            true,
            Some("sync-relay".into()),
            Some("sync-object-v1".into()),
        )
        .unwrap();
    let approved = proxy
        .approve(
            &policy,
            &decision.preview_id,
            aw_models::EgressApprovalScopeV1::Once,
            Some(now + chrono::Duration::minutes(5)),
            now,
            0,
        )
        .unwrap();
    proxy.send(&policy, approved, now, 0).unwrap();
    assert_eq!(requests.lock().unwrap().len(), 1);
}

#[test]
fn sync_transport_generic_approval_cannot_replace_a_sealed_tombstone_ack_permit() {
    let (bundle, user, policy) = signed_sync_policy(1);
    let (datastore, envelope, _) = configured_store(false);
    datastore.store_egress_policy_state(&bundle, &user).unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let proxy = EgressProxy::with_transport(
        datastore,
        CaptureTransport {
            requests: requests.clone(),
            response: Vec::new(),
        },
    )
    .with_sync_access(signed_sync_access());
    proxy
        .set_sync_enabled(
            true,
            Some("sync-relay".into()),
            Some("sync-object-v1".into()),
        )
        .unwrap();
    let request = SyncRelayRequestV1 {
        schema_version: 1,
        operation: aw_sync_e2ee::SyncRelayOperationV1::DeleteAfterTombstone,
        object_id: Some(envelope.object_id),
        vault_id: None,
        envelope: None,
        cursor: None,
        limit: None,
    };
    request.validate().unwrap();
    let now = Utc::now();
    let decision = proxy.preview(
        &policy,
        EgressRequestV1 {
            schema_version: 1,
            destination_id: "sync-relay".into(),
            purpose_id: "sync-object-v1".into(),
            retention_id: "ciphertext-only".into(),
            payload: serde_json::to_value(request).unwrap(),
        },
        now,
        0,
    );
    assert_eq!(decision.outcome, EgressOutcomeV1::Allow);
    let approved = proxy
        .approve(
            &policy,
            &decision.preview_id,
            aw_models::EgressApprovalScopeV1::Once,
            Some(now + chrono::Duration::minutes(5)),
            now,
            0,
        )
        .unwrap();
    assert_eq!(
        proxy
            .send_approval(
                &policy,
                &decision.preview_id,
                approved.approval_id(),
                now,
                0
            )
            .unwrap_err(),
        aw_models::EgressReasonCodeV1::ApprovalRequired
    );
    assert_eq!(
        proxy.send(&policy, approved, now, 0).unwrap_err(),
        aw_models::EgressReasonCodeV1::ApprovalRequired
    );
    assert!(requests.lock().unwrap().is_empty());
}

#[test]
fn paid_sync_denies_unconfigured_access_at_the_actual_relay_transport() {
    let (bundle, user, policy) = signed_sync_policy(1);
    let (datastore, envelope, _) = configured_store(false);
    datastore.store_egress_policy_state(&bundle, &user).unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let proxy = EgressProxy::with_transport(
        datastore,
        CaptureTransport {
            requests: requests.clone(),
            response: serde_json::to_vec(&SyncRelayResponseV1 {
                schema_version: 1,
                inserted: Some(true),
                ..Default::default()
            })
            .unwrap(),
        },
    );
    proxy
        .set_sync_enabled(
            true,
            Some("sync-relay".into()),
            Some("sync-object-v1".into()),
        )
        .unwrap();
    let remote = SyncHttpObjectStoreV1::new(
        "sync-relay".into(),
        "sync-object-v1".into(),
        EgressSyncRelayTransportV1::new(proxy, policy),
    )
    .unwrap();
    assert!(matches!(
        remote.put_if_absent(&envelope),
        Err(SyncObjectStoreErrorV1::PolicyDenied)
    ));
    assert!(requests.lock().unwrap().is_empty());
}

#[test]
fn paid_sync_denies_generic_approved_send_without_a_license() {
    let (bundle, user, policy) = signed_sync_policy(1);
    let (datastore, envelope, _) = configured_store(false);
    datastore.store_egress_policy_state(&bundle, &user).unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let proxy = EgressProxy::with_transport(
        datastore,
        CaptureTransport {
            requests: requests.clone(),
            response: Vec::new(),
        },
    );
    proxy
        .set_sync_enabled(
            true,
            Some("sync-relay".into()),
            Some("sync-object-v1".into()),
        )
        .unwrap();
    let request = SyncRelayRequestV1 {
        schema_version: 1,
        operation: aw_sync_e2ee::SyncRelayOperationV1::PutIfAbsent,
        object_id: Some(envelope.object_id.clone()),
        vault_id: Some(envelope.vault_id.clone()),
        envelope: Some(envelope),
        cursor: None,
        limit: None,
    };
    let now = Utc::now();
    let decision = proxy.preview(
        &policy,
        EgressRequestV1 {
            schema_version: 1,
            destination_id: "sync-relay".into(),
            purpose_id: "sync-object-v1".into(),
            retention_id: "ciphertext-only".into(),
            payload: serde_json::to_value(request).unwrap(),
        },
        now,
        0,
    );
    let approved = proxy
        .approve(
            &policy,
            &decision.preview_id,
            aw_models::EgressApprovalScopeV1::Once,
            Some(now + chrono::Duration::minutes(5)),
            now,
            0,
        )
        .unwrap();
    assert_eq!(
        proxy
            .send_approval(
                &policy,
                &decision.preview_id,
                approved.approval_id(),
                now,
                0
            )
            .unwrap_err(),
        aw_models::EgressReasonCodeV1::ApprovalRequired
    );
    assert_eq!(
        proxy
            .begin_send()
            .unwrap()
            .send_approval(
                &policy,
                &decision.preview_id,
                approved.approval_id(),
                now,
                0
            )
            .unwrap_err(),
        aw_models::EgressReasonCodeV1::ApprovalRequired
    );
    assert_eq!(
        proxy.send(&policy, approved, now, 0).unwrap_err(),
        aw_models::EgressReasonCodeV1::ApprovalRequired
    );
    let approved = proxy
        .approve(
            &policy,
            &decision.preview_id,
            aw_models::EgressApprovalScopeV1::Once,
            Some(now + chrono::Duration::minutes(5)),
            now,
            0,
        )
        .unwrap();
    assert_eq!(
        proxy
            .begin_send()
            .unwrap()
            .send(&policy, approved, now, 0)
            .unwrap_err(),
        aw_models::EgressReasonCodeV1::ApprovalRequired
    );
    assert!(requests.lock().unwrap().is_empty());
}

#[test]
fn paid_sync_allows_signed_grace_at_the_actual_relay_transport() {
    let now = Utc::now().timestamp() as u64;
    let mut proof = signed_sync_proof(now);
    proof.entitlement.payload.claims.expires_at = now - 10;
    sign_sync_proof(&mut proof);
    let (access, _) = sync_access_with_proof(proof, now);
    assert_eq!(
        access.require_sync_access(now).unwrap().access,
        EntitlementAccessV1::Grace
    );
    let (bundle, user, policy) = signed_sync_policy(1);
    let (datastore, envelope, _) = configured_store(false);
    datastore.store_egress_policy_state(&bundle, &user).unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let proxy = EgressProxy::with_transport(
        datastore,
        CaptureTransport {
            requests: requests.clone(),
            response: serde_json::to_vec(&SyncRelayResponseV1 {
                schema_version: 1,
                inserted: Some(true),
                ..Default::default()
            })
            .unwrap(),
        },
    )
    .with_sync_access(access);
    proxy
        .set_sync_enabled(
            true,
            Some("sync-relay".into()),
            Some("sync-object-v1".into()),
        )
        .unwrap();
    let remote = SyncHttpObjectStoreV1::new(
        "sync-relay".into(),
        "sync-object-v1".into(),
        EgressSyncRelayTransportV1::new(proxy, policy),
    )
    .unwrap();
    assert!(remote.put_if_absent(&envelope).unwrap());
    assert_eq!(requests.lock().unwrap().len(), 1);
}

#[test]
fn paid_sync_denies_expired_wrong_feature_and_stale_proofs_at_the_actual_relay_transport() {
    let now = Utc::now().timestamp() as u64;
    for case in [
        "expired",
        "wrong-feature",
        "expired-revocations",
        "missing-revocations",
    ] {
        let mut proof = signed_sync_proof(now);
        let (install_at, expected) = match case {
            "expired" => {
                proof.entitlement.payload.claims.expires_at = now - 20;
                proof.entitlement.payload.claims.grace_until = now - 10;
                (
                    now - 30,
                    RuntimeFeatureAccessErrorV1::Verification(
                        EntitlementVerificationErrorV1::Expired,
                    ),
                )
            }
            "wrong-feature" => {
                proof.entitlement.payload.claims.feature_ids = vec!["local-pro".into()];
                (now, RuntimeFeatureAccessErrorV1::MissingFeature)
            }
            "expired-revocations" => {
                proof.revocations.as_mut().unwrap().expires_at = now - 10;
                (
                    now - 30,
                    RuntimeFeatureAccessErrorV1::Verification(
                        EntitlementVerificationErrorV1::RevocationSnapshotExpired,
                    ),
                )
            }
            "missing-revocations" => {
                proof.revocations = None;
                (
                    now,
                    RuntimeFeatureAccessErrorV1::Verification(
                        EntitlementVerificationErrorV1::MissingRevocations,
                    ),
                )
            }
            _ => unreachable!(),
        };
        sign_sync_proof(&mut proof);
        let (access, _) = sync_access_with_proof(proof, install_at);
        assert_eq!(
            access.require_sync_access(now).unwrap_err(),
            expected,
            "{case}"
        );
        let (bundle, user, policy) = signed_sync_policy(1);
        let (datastore, envelope, _) = configured_store(false);
        datastore.store_egress_policy_state(&bundle, &user).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let proxy = EgressProxy::with_transport(
            datastore,
            CaptureTransport {
                requests: requests.clone(),
                response: serde_json::to_vec(&SyncRelayResponseV1 {
                    schema_version: 1,
                    inserted: Some(true),
                    ..Default::default()
                })
                .unwrap(),
            },
        )
        .with_sync_access(access);
        proxy
            .set_sync_enabled(
                true,
                Some("sync-relay".into()),
                Some("sync-object-v1".into()),
            )
            .unwrap();
        let remote = SyncHttpObjectStoreV1::new(
            "sync-relay".into(),
            "sync-object-v1".into(),
            EgressSyncRelayTransportV1::new(proxy, policy),
        )
        .unwrap();
        assert!(
            matches!(
                remote.put_if_absent(&envelope),
                Err(SyncObjectStoreErrorV1::PolicyDenied)
            ),
            "{case}"
        );
        assert!(requests.lock().unwrap().is_empty(), "{case}");
    }
}

#[test]
fn paid_sync_rechecks_signed_revocation_and_rejects_replay_between_actual_relay_requests() {
    let now = Utc::now().timestamp() as u64;
    let proof = signed_sync_proof(now);
    let (access, source) = sync_access_with_proof(proof.clone(), now);
    let (bundle, user, policy) = signed_sync_policy(1);
    let (datastore, envelope, _) = configured_store(false);
    datastore.store_egress_policy_state(&bundle, &user).unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let proxy = EgressProxy::with_transport(
        datastore,
        CaptureTransport {
            requests: requests.clone(),
            response: serde_json::to_vec(&SyncRelayResponseV1 {
                schema_version: 1,
                inserted: Some(true),
                ..Default::default()
            })
            .unwrap(),
        },
    )
    .with_sync_access(access.clone());
    proxy
        .set_sync_enabled(
            true,
            Some("sync-relay".into()),
            Some("sync-object-v1".into()),
        )
        .unwrap();
    let remote = SyncHttpObjectStoreV1::new(
        "sync-relay".into(),
        "sync-object-v1".into(),
        EgressSyncRelayTransportV1::new(proxy, policy),
    )
    .unwrap();
    assert!(remote.put_if_absent(&envelope).unwrap());
    let mut revoked = proof.clone();
    let snapshot = revoked.revocations.as_mut().unwrap();
    snapshot.sequence = 2;
    snapshot.revoked_entitlement_ids =
        vec![revoked.entitlement.payload.claims.entitlement_id.clone()];
    sign_sync_proof(&mut revoked);
    assert_eq!(
        access.install(revoked, now).unwrap_err(),
        RuntimeFeatureAccessErrorV1::Verification(EntitlementVerificationErrorV1::Revoked)
    );
    assert!(matches!(
        remote.put_if_absent(&envelope),
        Err(SyncObjectStoreErrorV1::PolicyDenied)
    ));
    assert_eq!(
        source
            .revocation_floor(ENTITLEMENT_REVOCATION_SCOPE_V1)
            .unwrap(),
        2
    );
    assert_eq!(
        access.install(proof, now).unwrap_err(),
        RuntimeFeatureAccessErrorV1::Verification(EntitlementVerificationErrorV1::StaleRevocations)
    );
    assert!(matches!(
        remote.put_if_absent(&envelope),
        Err(SyncObjectStoreErrorV1::PolicyDenied)
    ));
    assert_eq!(requests.lock().unwrap().len(), 1);
}

#[test]
fn paid_sync_rechecks_expiry_after_generic_approval_including_send_guards() {
    let now = Utc::now();
    let mut proof = signed_sync_proof(now.timestamp() as u64);
    proof.entitlement.payload.claims.expires_at = now.timestamp() as u64 + 5;
    proof.entitlement.payload.claims.grace_until = now.timestamp() as u64 + 10;
    sign_sync_proof(&mut proof);
    let (access, _) = sync_access_with_proof(proof, now.timestamp() as u64);
    let (bundle, user, policy) = signed_sync_policy(1);
    let (datastore, envelope, _) = configured_store(false);
    datastore.store_egress_policy_state(&bundle, &user).unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let proxy = EgressProxy::with_transport(
        datastore,
        CaptureTransport {
            requests: requests.clone(),
            response: Vec::new(),
        },
    )
    .with_sync_access(access);
    proxy
        .set_sync_enabled(
            true,
            Some("sync-relay".into()),
            Some("sync-object-v1".into()),
        )
        .unwrap();
    let relay_request = SyncRelayRequestV1 {
        schema_version: 1,
        operation: aw_sync_e2ee::SyncRelayOperationV1::PutIfAbsent,
        object_id: Some(envelope.object_id.clone()),
        vault_id: Some(envelope.vault_id.clone()),
        envelope: Some(envelope),
        cursor: None,
        limit: None,
    };
    let request = EgressRequestV1 {
        schema_version: 1,
        destination_id: "sync-relay".into(),
        purpose_id: "sync-object-v1".into(),
        retention_id: "ciphertext-only".into(),
        payload: serde_json::to_value(relay_request).unwrap(),
    };
    let decision = proxy.preview(&policy, request.clone(), now, 0);
    let approved = proxy
        .approve(
            &policy,
            &decision.preview_id,
            aw_models::EgressApprovalScopeV1::Once,
            Some(now + chrono::Duration::minutes(5)),
            now,
            0,
        )
        .unwrap();
    proxy.send(&policy, approved, now, 0).unwrap();
    assert_eq!(requests.lock().unwrap().len(), 1);

    let decision = proxy.preview(&policy, request, now, 0);
    let approved = proxy
        .approve(
            &policy,
            &decision.preview_id,
            aw_models::EgressApprovalScopeV1::Once,
            Some(now + chrono::Duration::minutes(5)),
            now,
            0,
        )
        .unwrap();
    let expired = now + chrono::Duration::seconds(11);
    assert_eq!(
        proxy
            .send_approval(
                &policy,
                &decision.preview_id,
                approved.approval_id(),
                expired,
                0
            )
            .unwrap_err(),
        aw_models::EgressReasonCodeV1::ApprovalRequired
    );
    assert_eq!(
        proxy
            .begin_send()
            .unwrap()
            .send_approval(
                &policy,
                &decision.preview_id,
                approved.approval_id(),
                expired,
                0
            )
            .unwrap_err(),
        aw_models::EgressReasonCodeV1::ApprovalRequired
    );
    assert_eq!(
        proxy.send(&policy, approved, expired, 0).unwrap_err(),
        aw_models::EgressReasonCodeV1::ApprovalRequired
    );
    let approved = proxy
        .approve(
            &policy,
            &decision.preview_id,
            aw_models::EgressApprovalScopeV1::Once,
            Some(now + chrono::Duration::minutes(5)),
            now,
            0,
        )
        .unwrap();
    assert_eq!(
        proxy
            .begin_send()
            .unwrap()
            .send(&policy, approved, expired, 0)
            .unwrap_err(),
        aw_models::EgressReasonCodeV1::ApprovalRequired
    );
    assert_eq!(requests.lock().unwrap().len(), 1);
}

#[test]
fn signed_sync_transport_checks_user_consent_and_sends_the_exact_opaque_envelope() {
    let response = serde_json::to_vec(&SyncRelayResponseV1 {
        schema_version: 1,
        inserted: Some(true),
        ..Default::default()
    })
    .unwrap();
    let request_log = Arc::new(Mutex::new(Vec::new()));
    let (bundle, user, policy) = signed_sync_policy(1);
    let (datastore, envelope, data_key) = configured_store(false);
    datastore.store_egress_policy_state(&bundle, &user).unwrap();
    let proxy = EgressProxy::with_transport(
        datastore,
        CaptureTransport {
            requests: request_log.clone(),
            response,
        },
    )
    .with_sync_access(signed_sync_access());
    proxy
        .set_sync_enabled(
            true,
            Some("sync-relay".into()),
            Some("sync-object-v1".into()),
        )
        .unwrap();
    let relay_request = SyncRelayRequestV1 {
        schema_version: 1,
        operation: aw_sync_e2ee::SyncRelayOperationV1::PutIfAbsent,
        object_id: Some(envelope.object_id.clone()),
        vault_id: Some(envelope.vault_id.clone()),
        envelope: Some(envelope.clone()),
        cursor: None,
        limit: None,
    };
    let decision = proxy.preview(
        &policy,
        EgressRequestV1 {
            schema_version: 1,
            destination_id: "sync-relay".into(),
            purpose_id: "sync-object-v1".into(),
            retention_id: "ciphertext-only".into(),
            payload: serde_json::to_value(&relay_request).unwrap(),
        },
        Utc::now(),
        0,
    );
    assert_eq!(
        decision.outcome,
        EgressOutcomeV1::Allow,
        "{:?}",
        decision.reason_codes
    );
    assert!(
        decision.removed_fields.is_empty(),
        "{:?}",
        decision.removed_fields
    );
    let preview: SyncRelayRequestV1 =
        serde_json::from_value(decision.sanitized_payload.clone().unwrap()).unwrap();
    assert_eq!(preview.envelope, Some(envelope.clone()));
    let relay = EgressSyncRelayTransportV1::new(proxy.clone(), policy.clone());
    let store =
        SyncHttpObjectStoreV1::new("sync-relay".into(), "sync-object-v1".into(), relay).unwrap();
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

    let second_snapshot =
        aw_sync_e2ee::encrypt_snapshot(&data_key, b"second immutable snapshot").unwrap();
    let second_envelope = second_snapshot.envelopes[0].clone();
    assert_ne!(second_envelope, envelope);
    proxy.validate_sync_envelope(&second_envelope).unwrap();

    let wrong_purpose = EgressSyncRelayTransportV1::new(proxy.clone(), policy);
    assert!(wrong_purpose
        .request("sync-relay", "custom-endpoint", &relay_request)
        .is_err());
    assert!(wrong_purpose
        .request("sync-relay", "ai-analysis", &relay_request)
        .is_err());
    assert_eq!(request_log.lock().unwrap().len(), 1);

    let (disabled_datastore, disabled_envelope, _) = configured_store(false);
    let disabled_requests = Arc::new(Mutex::new(Vec::new()));
    let disabled = EgressProxy::with_transport(
        disabled_datastore,
        CaptureTransport {
            requests: disabled_requests.clone(),
            response: serde_json::to_vec(&SyncRelayResponseV1 {
                schema_version: 1,
                inserted: Some(true),
                ..Default::default()
            })
            .unwrap(),
        },
    )
    .with_sync_access(signed_sync_access());
    let transport = EgressSyncRelayTransportV1::new(disabled, signed_sync_policy(1).2);
    assert!(matches!(
        transport.request(
            "sync-relay",
            "sync-object-v1",
            &SyncRelayRequestV1 {
                schema_version: 1,
                operation: aw_sync_e2ee::SyncRelayOperationV1::PutIfAbsent,
                object_id: Some(disabled_envelope.object_id.clone()),
                vault_id: Some(disabled_envelope.vault_id.clone()),
                envelope: Some(disabled_envelope),
                cursor: None,
                limit: None,
            }
        ),
        Err(SyncObjectStoreErrorV1::PolicyDenied)
    ));
    assert!(disabled_requests.lock().unwrap().is_empty());
}

#[test]
fn sync_egress_is_blocked_until_the_local_baseline_is_complete() {
    let (datastore, envelope, _) = configured_store(true);
    let (bundle, user, policy) = signed_sync_policy(1);
    datastore.store_egress_policy_state(&bundle, &user).unwrap();
    datastore
        .set_sync_enabled(
            true,
            Some("sync-relay".into()),
            Some("sync-object-v1".into()),
        )
        .unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let proxy = EgressProxy::with_transport(
        datastore.clone(),
        CaptureTransport {
            requests: requests.clone(),
            response: serde_json::to_vec(&SyncRelayResponseV1 {
                schema_version: 1,
                inserted: Some(true),
                ..Default::default()
            })
            .unwrap(),
        },
    )
    .with_sync_access(signed_sync_access());
    let relay = EgressSyncRelayTransportV1::new(proxy, policy);
    assert!(
        SyncHttpObjectStoreV1::new("sync-relay".into(), "sync-object-v1".into(), relay)
            .unwrap()
            .put_if_absent(&envelope)
            .is_err()
    );
    assert!(requests.lock().unwrap().is_empty());
    assert_eq!(
        datastore
            .get_events("sync-baseline-test", None, None, None)
            .unwrap()
            .len(),
        1
    );
    datastore.lock().unwrap();
}

#[test]
fn sync_transport_rejects_a_new_signed_bundle_between_requests() {
    let (datastore, envelope, _) = configured_store(false);
    let (bundle, user, policy) = signed_sync_policy(1);
    datastore.store_egress_policy_state(&bundle, &user).unwrap();
    datastore
        .set_sync_enabled(
            true,
            Some("sync-relay".into()),
            Some("sync-object-v1".into()),
        )
        .unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let proxy = EgressProxy::with_transport(
        datastore.clone(),
        CaptureTransport {
            requests: requests.clone(),
            response: serde_json::to_vec(&SyncRelayResponseV1 {
                schema_version: 1,
                inserted: Some(true),
                ..Default::default()
            })
            .unwrap(),
        },
    )
    .with_sync_access(signed_sync_access());
    let stale = SyncHttpObjectStoreV1::new(
        "sync-relay".into(),
        "sync-object-v1".into(),
        EgressSyncRelayTransportV1::new(proxy.clone(), policy),
    )
    .unwrap();
    assert!(stale.put_if_absent(&envelope).unwrap());
    let (next, next_user, next_policy) = signed_sync_policy(2);
    proxy
        .with_policy_update(|| datastore.store_egress_policy_state(&next, &next_user))
        .unwrap()
        .unwrap();
    assert!(matches!(
        stale.put_if_absent(&envelope),
        Err(SyncObjectStoreErrorV1::PolicyDenied)
    ));
    assert_eq!(requests.lock().unwrap().len(), 1);
    let current = SyncHttpObjectStoreV1::new(
        "sync-relay".into(),
        "sync-object-v1".into(),
        EgressSyncRelayTransportV1::new(proxy, next_policy),
    )
    .unwrap();
    assert!(current.put_if_absent(&envelope).unwrap());
    assert_eq!(requests.lock().unwrap().len(), 2);
    datastore.lock().unwrap();
}

#[test]
fn sync_transport_rejects_same_version_local_rule_changes_between_requests() {
    let (datastore, envelope, _) = configured_store(false);
    let (bundle, mut user, policy) = signed_sync_policy(1);
    datastore.store_egress_policy_state(&bundle, &user).unwrap();
    datastore
        .set_sync_enabled(
            true,
            Some("sync-relay".into()),
            Some("sync-object-v1".into()),
        )
        .unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let proxy = EgressProxy::with_transport(
        datastore.clone(),
        CaptureTransport {
            requests: requests.clone(),
            response: serde_json::to_vec(&SyncRelayResponseV1 {
                schema_version: 1,
                inserted: Some(true),
                ..Default::default()
            })
            .unwrap(),
        },
    )
    .with_sync_access(signed_sync_access());
    let stale = SyncHttpObjectStoreV1::new(
        "sync-relay".into(),
        "sync-object-v1".into(),
        EgressSyncRelayTransportV1::new(proxy.clone(), policy.clone()),
    )
    .unwrap();
    assert!(stale.put_if_absent(&envelope).unwrap());
    user.user_rules.push(aw_models::EgressRuleV1 {
        pattern: aw_models::EgressPatternV1 {
            kind: aw_models::EgressMatchKindV1::Field,
            value: "/envelope/ciphertext".into(),
        },
        action: aw_models::EgressRuleActionV1::Deny,
    });
    proxy
        .with_policy_update(|| datastore.store_egress_user_policy(&user))
        .unwrap()
        .unwrap();
    assert_eq!(
        datastore
            .get_egress_policy_state()
            .unwrap()
            .unwrap()
            .0
            .bundle
            .version,
        policy.policy().version
    );
    assert!(matches!(
        stale.put_if_absent(&envelope),
        Err(SyncObjectStoreErrorV1::PolicyDenied)
    ));
    assert_eq!(requests.lock().unwrap().len(), 1);
    datastore.lock().unwrap();
}

#[test]
fn sync_transport_rejects_verified_policy_that_is_not_registered_in_the_vault() {
    let (datastore, envelope, _) = configured_store(false);
    datastore
        .set_sync_enabled(
            true,
            Some("sync-relay".into()),
            Some("sync-object-v1".into()),
        )
        .unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let proxy = EgressProxy::with_transport(
        datastore.clone(),
        CaptureTransport {
            requests: requests.clone(),
            response: serde_json::to_vec(&SyncRelayResponseV1 {
                schema_version: 1,
                inserted: Some(true),
                ..Default::default()
            })
            .unwrap(),
        },
    )
    .with_sync_access(signed_sync_access());
    let relay = SyncHttpObjectStoreV1::new(
        "sync-relay".into(),
        "sync-object-v1".into(),
        EgressSyncRelayTransportV1::new(proxy, signed_sync_policy(1).2),
    )
    .unwrap();
    assert!(matches!(
        relay.put_if_absent(&envelope),
        Err(SyncObjectStoreErrorV1::PolicyDenied)
    ));
    assert!(requests.lock().unwrap().is_empty());
    datastore.lock().unwrap();
}

fn delete_backup_request(snapshot: &aw_sync_e2ee::EncryptedSyncSnapshotV1) -> EgressRequestV1 {
    let envelope = snapshot.envelopes[0].clone();
    backup_egress_request(SyncRelayRequestV1 {
        schema_version: 1,
        operation: aw_models::SyncRelayOperationV1::DeleteSelectedBackup,
        object_id: Some(envelope.object_id.clone()),
        vault_id: Some(envelope.vault_id.clone()),
        envelope: Some(envelope),
        cursor: None,
        limit: None,
    })
}
#[test]
fn backup_cleanup_selected_delete_is_free_only_after_private_review_and_never_transfers() {
    let now = Utc::now();
    let (bundle, user, policy) = signed_sync_policy(1);
    let store = clean_backup_store(&bundle, &user);
    let (key, snapshot) = historical_backup();
    let proof = aw_sync_e2ee::SnapshotDeletionProofV1::authenticate(&key, &snapshot).unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let proxy = EgressProxy::with_transport(
        store.clone(),
        CaptureTransport {
            requests: requests.clone(),
            response: serde_json::to_vec(&SyncRelayResponseV1 {
                schema_version: 1,
                deleted: Some(true),
                ..Default::default()
            })
            .unwrap(),
        },
    );
    let scope = BackupScopeV1::selected_deletion(&proof, &snapshot.envelopes, "local").unwrap();
    let preview = proxy
        .preview_backup(&policy, scope, "sync-relay", now, 0)
        .unwrap();
    assert_eq!(preview.metadata()["operation"], "delete");
    assert!(proxy
        .approve_backup(&policy, &preview, false, now, 0)
        .is_err());
    let permit = proxy
        .approve_backup(&policy, &preview, true, now, 0)
        .unwrap();
    assert!(proxy
        .send_backup_request(&policy, &permit, put_backup(&snapshot), now, 0)
        .is_err());
    let mut get = delete_backup_request(&snapshot);
    get.payload = serde_json::to_value(SyncRelayRequestV1 {
        schema_version: 1,
        operation: aw_models::SyncRelayOperationV1::Get,
        object_id: Some(snapshot.envelopes[0].object_id.clone()),
        vault_id: None,
        envelope: None,
        cursor: None,
        limit: None,
    })
    .unwrap();
    assert!(proxy
        .send_backup_request(&policy, &permit, get, now, 0)
        .is_err());
    assert!(proxy
        .send_sync_request(&policy, delete_backup_request(&snapshot), now, 0)
        .is_err());
    assert!(requests.lock().unwrap().is_empty());
    let (receipt, _) = proxy
        .send_backup_request(&policy, &permit, delete_backup_request(&snapshot), now, 0)
        .unwrap();
    assert_eq!(receipt.scope, aw_models::EgressApprovalScopeV1::TimeLimited);
    assert_eq!(requests.lock().unwrap().len(), 1);
    assert!(store.load_sync_key_material().unwrap().is_none());
    assert!(!store.sync_enabled().unwrap());
    store.close();
}
#[test]
fn backup_cleanup_discovery_is_free_list_only_and_normal_discovery_stays_paid() {
    let now = Utc::now();
    let (bundle, user, policy) = signed_sync_policy(1);
    let store = clean_backup_store(&bundle, &user);
    let (key, snapshot) = historical_backup();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let proxy = EgressProxy::with_transport(
        store.clone(),
        CaptureTransport {
            requests: requests.clone(),
            response: serde_json::to_vec(&SyncRelayResponseV1 {
                schema_version: 1,
                ..Default::default()
            })
            .unwrap(),
        },
    );
    let list = backup_egress_request(SyncRelayRequestV1 {
        schema_version: 1,
        operation: aw_models::SyncRelayOperationV1::ListOpaqueHeads,
        object_id: None,
        vault_id: Some(URL_SAFE_NO_PAD.encode(key.vault_id())),
        envelope: None,
        cursor: None,
        limit: Some(16),
    });
    let normal = proxy
        .preview_backup(
            &policy,
            BackupScopeV1::discovery(&key, "local").unwrap(),
            "sync-relay",
            now,
            0,
        )
        .unwrap();
    let paid = proxy
        .approve_backup(&policy, &normal, true, now, 0)
        .unwrap();
    assert!(proxy
        .send_backup_request(&policy, &paid, list.clone(), now, 0)
        .is_err());
    let preview = proxy
        .preview_backup(
            &policy,
            BackupScopeV1::cleanup_discovery(&key, "local").unwrap(),
            "sync-relay",
            now,
            0,
        )
        .unwrap();
    assert_eq!(preview.metadata()["operation"], "cleanup_list");
    let permit = proxy
        .approve_backup(&policy, &preview, true, now, 0)
        .unwrap();
    assert!(proxy
        .send_backup_request(&policy, &permit, put_backup(&snapshot), now, 0)
        .is_err());
    assert!(proxy
        .send_backup_request(&policy, &permit, delete_backup_request(&snapshot), now, 0)
        .is_err());
    assert!(requests.lock().unwrap().is_empty());
    proxy
        .send_backup_request(&policy, &permit, list, now, 0)
        .unwrap();
    assert_eq!(requests.lock().unwrap().len(), 1);
    store.close();
}
#[test]
fn backup_cleanup_delete_rejects_changed_object_hash_vault_and_event_opcode_before_transport() {
    let now = Utc::now();
    let (bundle, user, policy) = signed_sync_policy(1);
    let store = clean_backup_store(&bundle, &user);
    let (key, snapshot) = historical_backup();
    let proof = aw_sync_e2ee::SnapshotDeletionProofV1::authenticate(&key, &snapshot).unwrap();
    let mut changed = snapshot.envelopes.clone();
    changed[0].nonce = URL_SAFE_NO_PAD.encode([9; 24]);
    assert!(BackupScopeV1::selected_deletion(&proof, &changed, "local").is_err());
    assert!(BackupScopeV1::selected_deletion(&proof, &[], "local").is_err());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let proxy = EgressProxy::with_transport(
        store.clone(),
        CaptureTransport {
            requests: requests.clone(),
            response: Vec::new(),
        },
    );
    let preview = proxy
        .preview_backup(
            &policy,
            BackupScopeV1::selected_deletion(&proof, &snapshot.envelopes, "local").unwrap(),
            "sync-relay",
            now,
            0,
        )
        .unwrap();
    let permit = proxy
        .approve_backup(&policy, &preview, true, now, 0)
        .unwrap();
    let valid = delete_backup_request(&snapshot);
    for field in ["object_id", "vault_id", "nonce", "operation"] {
        let mut bad = valid.clone();
        match field {
            "object_id" => {
                let id = URL_SAFE_NO_PAD.encode([9; 16]);
                bad.payload["object_id"] = serde_json::json!(id);
                bad.payload["envelope"]["object_id"] = bad.payload["object_id"].clone();
            }
            "vault_id" => {
                bad.payload["vault_id"] = serde_json::json!(URL_SAFE_NO_PAD.encode([9; 16]));
                bad.payload["envelope"]["vault_id"] = bad.payload["vault_id"].clone();
            }
            "nonce" => {
                bad.payload["envelope"]["nonce"] =
                    serde_json::json!(URL_SAFE_NO_PAD.encode([9; 24]))
            }
            _ => {
                bad.payload = serde_json::to_value(SyncRelayRequestV1 {
                    schema_version: 1,
                    operation: aw_models::SyncRelayOperationV1::DeleteAfterTombstone,
                    object_id: Some(snapshot.envelopes[0].object_id.clone()),
                    vault_id: None,
                    envelope: None,
                    cursor: None,
                    limit: None,
                })
                .unwrap();
            }
        }
        assert!(
            proxy
                .send_backup_request(&policy, &permit, bad, now, 0)
                .is_err(),
            "{field}"
        );
    }
    assert!(requests.lock().unwrap().is_empty());
    store.close();
}
#[test]
fn backup_cleanup_delete_keeps_expiry_kill_revocation_policy_and_context_guards_without_license() {
    let now = Utc::now();
    let (bundle, user, policy) = signed_sync_policy(1);
    let (key, snapshot) = historical_backup();
    let proof = aw_sync_e2ee::SnapshotDeletionProofV1::authenticate(&key, &snapshot).unwrap();
    for reason in ["expiry", "kill", "clear", "policy", "context"] {
        let store = clean_backup_store(&bundle, &user);
        let requests = Arc::new(Mutex::new(Vec::new()));
        let proxy = EgressProxy::with_transport(
            store.clone(),
            CaptureTransport {
                requests: requests.clone(),
                response: Vec::new(),
            },
        );
        let preview = proxy
            .preview_backup(
                &policy,
                BackupScopeV1::selected_deletion(&proof, &snapshot.envelopes, "local").unwrap(),
                "sync-relay",
                now,
                0,
            )
            .unwrap();
        let permit = proxy
            .approve_backup(&policy, &preview, true, now, 0)
            .unwrap();
        let at = match reason {
            "expiry" => now + chrono::Duration::minutes(5),
            "kill" => {
                proxy.set_kill_switch(true).unwrap();
                proxy.set_kill_switch(false).unwrap();
                now
            }
            "clear" => {
                proxy.revoke_approvals().unwrap();
                now
            }
            "policy" => {
                store.store_egress_policy_state(&bundle, &user).unwrap();
                now
            }
            _ => {
                store.lock().unwrap();
                store
                    .unlock_encrypted(":memory:".into(), "backup-egress-fixture-".repeat(3))
                    .unwrap();
                store.store_egress_policy_state(&bundle, &user).unwrap();
                store.set_egress_kill_switch(false).unwrap();
                now
            }
        };
        assert!(
            proxy
                .send_backup_request(&policy, &permit, delete_backup_request(&snapshot), at, 0)
                .is_err(),
            "{reason}"
        );
        assert!(requests.lock().unwrap().is_empty());
        store.close();
    }
}

#[test]
fn backup_cleanup_expired_license_does_not_disable_delete_but_still_blocks_paid_transfer() {
    let now = Utc::now();
    let epoch = now.timestamp() as u64;
    let mut paid = signed_sync_proof(epoch - 100);
    paid.entitlement.payload.claims.expires_at = epoch - 20;
    paid.entitlement.payload.claims.grace_until = epoch - 10;
    sign_sync_proof(&mut paid);
    let (access, _) = sync_access_with_proof(paid, epoch - 60);
    let (bundle, user, policy) = signed_sync_policy(1);
    let store = clean_backup_store(&bundle, &user);
    let (key, snapshot) = historical_backup();
    let proof = aw_sync_e2ee::SnapshotDeletionProofV1::authenticate(&key, &snapshot).unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let proxy = EgressProxy::with_transport(
        store.clone(),
        CaptureTransport {
            requests: requests.clone(),
            response: serde_json::to_vec(&SyncRelayResponseV1 {
                schema_version: 1,
                deleted: Some(false),
                ..Default::default()
            })
            .unwrap(),
        },
    )
    .with_sync_access(access);
    assert!(proxy.require_sync_access(now).is_err());
    let upload = proxy
        .preview_backup(
            &policy,
            BackupScopeV1::selected(&key, &snapshot, "local", BackupTransferDirectionV1::Upload)
                .unwrap(),
            "sync-relay",
            now,
            0,
        )
        .unwrap();
    let upload = proxy
        .approve_backup(&policy, &upload, true, now, 0)
        .unwrap();
    assert!(proxy
        .send_backup_request(&policy, &upload, put_backup(&snapshot), now, 0)
        .is_err());
    let preview = proxy
        .preview_backup(
            &policy,
            BackupScopeV1::selected_deletion(&proof, &snapshot.envelopes, "local").unwrap(),
            "sync-relay",
            now,
            0,
        )
        .unwrap();
    let permit = proxy
        .approve_backup(&policy, &preview, true, now, 0)
        .unwrap();
    let (_, bytes) = proxy
        .send_backup_request(&policy, &permit, delete_backup_request(&snapshot), now, 0)
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<SyncRelayResponseV1>(&bytes)
            .unwrap()
            .deleted,
        Some(false)
    );
    assert_eq!(requests.lock().unwrap().len(), 1);
    store.close();
}
#[test]
fn backup_cleanup_opcode_is_unavailable_to_valid_paid_live_and_generic_approval_senders() {
    let now = Utc::now();
    let (bundle, user, policy) = signed_sync_policy(1);
    let (store, envelope, _) = configured_store(false);
    store.store_egress_policy_state(&bundle, &user).unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let proxy = EgressProxy::with_transport(
        store.clone(),
        CaptureTransport {
            requests: requests.clone(),
            response: Vec::new(),
        },
    )
    .with_sync_access(signed_sync_access());
    proxy
        .set_sync_enabled(
            true,
            Some("sync-relay".into()),
            Some("sync-object-v1".into()),
        )
        .unwrap();
    let request = backup_egress_request(SyncRelayRequestV1 {
        schema_version: 1,
        operation: aw_models::SyncRelayOperationV1::DeleteSelectedBackup,
        object_id: Some(envelope.object_id.clone()),
        vault_id: Some(envelope.vault_id.clone()),
        envelope: Some(envelope),
        cursor: None,
        limit: None,
    });
    assert!(proxy.require_sync_access(now).is_ok());
    assert!(proxy
        .send_sync_request(&policy, request.clone(), now, 0)
        .is_err());
    let decision = proxy.preview(&policy, request, now, 0);
    assert_eq!(decision.outcome, EgressOutcomeV1::Allow);
    let approved = proxy
        .approve(
            &policy,
            &decision.preview_id,
            aw_models::EgressApprovalScopeV1::Once,
            Some(now + chrono::Duration::minutes(5)),
            now,
            0,
        )
        .unwrap();
    assert!(proxy.send(&policy, approved, now, 0).is_err());
    assert!(requests.lock().unwrap().is_empty());
    store.close();
}

#[test]
fn backup_cleanup_response_failure_keeps_one_request_receipt_and_never_reports_erasure() {
    let now = Utc::now();
    let (bundle, user, policy) = signed_sync_policy(1);
    let (key, snapshot) = historical_backup();
    let proof = aw_sync_e2ee::SnapshotDeletionProofV1::authenticate(&key, &snapshot).unwrap();
    for response in [
        b"unsupported-operation".to_vec(),
        serde_json::to_vec(&SyncRelayResponseV1 {
            schema_version: 1,
            ..Default::default()
        })
        .unwrap(),
        serde_json::to_vec(&SyncRelayResponseV1 {
            schema_version: 1,
            deleted: Some(true),
            inserted: Some(true),
            ..Default::default()
        })
        .unwrap(),
    ] {
        let store = clean_backup_store(&bundle, &user);
        let requests = Arc::new(Mutex::new(Vec::new()));
        let proxy = EgressProxy::with_transport(
            store.clone(),
            CaptureTransport {
                requests: requests.clone(),
                response,
            },
        );
        let preview = proxy
            .preview_backup(
                &policy,
                BackupScopeV1::selected_deletion(&proof, &snapshot.envelopes, "local").unwrap(),
                "sync-relay",
                now,
                0,
            )
            .unwrap();
        let permit = proxy
            .approve_backup(&policy, &preview, true, now, 0)
            .unwrap();
        assert!(proxy
            .send_backup_request(&policy, &permit, delete_backup_request(&snapshot), now, 0)
            .is_err());
        assert_eq!(requests.lock().unwrap().len(), 1);
        let receipts = store.get_egress_receipts(10).unwrap();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].decision, EgressOutcomeV1::Allow);
        assert!(!serde_json::to_string(&receipts)
            .unwrap()
            .contains("authenticated-private-backup-marker"));
        store.close();
    }
}

#[test]
fn backup_cleanup_multipart_accepted_permit_survives_license_expiry_between_deletes() {
    let now=Utc::now();let epoch=now.timestamp() as u64;
    let mut entitlement=signed_sync_proof(epoch);
    entitlement.entitlement.payload.claims.expires_at=epoch+5;
    entitlement.entitlement.payload.claims.grace_until=epoch+10;
    sign_sync_proof(&mut entitlement);
    let (access,_)=sync_access_with_proof(entitlement,epoch);
    let (bundle,user,policy)=signed_sync_policy(1);let store=clean_backup_store(&bundle,&user);
    let (key,_)=historical_backup();
    let snapshot=aw_sync_e2ee::encrypt_snapshot(&key,&vec![7;1_100_000]).unwrap();
    assert_eq!(snapshot.envelopes.len(),2);
    let proof=aw_sync_e2ee::SnapshotDeletionProofV1::authenticate(&key,&snapshot).unwrap();
    let requests=Arc::new(Mutex::new(Vec::new()));
    let proxy=EgressProxy::with_transport(store.clone(),CaptureTransport{requests:requests.clone(),response:serde_json::to_vec(&SyncRelayResponseV1{schema_version:1,deleted:Some(true),..Default::default()}).unwrap()}).with_sync_access(access);
    assert!(proxy.require_sync_access(now).is_ok());
    let review=proxy.preview_backup(&policy,BackupScopeV1::selected_deletion(&proof,&snapshot.envelopes,"local").unwrap(),"sync-relay",now,0).unwrap();
    let permit=proxy.approve_backup(&policy,&review,true,now,0).unwrap();
    let upload=proxy.preview_backup(&policy,BackupScopeV1::selected(&key,&snapshot,"local",BackupTransferDirectionV1::Upload).unwrap(),"sync-relay",now,0).unwrap();
    let upload=proxy.approve_backup(&policy,&upload,true,now,0).unwrap();
    for (index,envelope) in snapshot.envelopes.iter().enumerate(){
        let at=now+chrono::Duration::seconds(if index==0{0}else{11});
        let request=backup_egress_request(SyncRelayRequestV1{schema_version:1,operation:aw_models::SyncRelayOperationV1::DeleteSelectedBackup,object_id:Some(envelope.object_id.clone()),vault_id:Some(envelope.vault_id.clone()),envelope:Some(envelope.clone()),cursor:None,limit:None});
        proxy.send_backup_request(&policy,&permit,request,at,0).unwrap();
    }
    let expired=now+chrono::Duration::seconds(11);
    assert!(proxy.require_sync_access(expired).is_err());
    assert!(proxy.send_backup_request(&policy,&upload,put_backup(&snapshot),expired,0).is_err());
    assert_eq!(requests.lock().unwrap().len(),2);store.close();
}
