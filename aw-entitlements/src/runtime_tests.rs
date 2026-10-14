use super::{
    EntitlementSourceV1, RuntimeFeatureAccessErrorV1 as Error, RuntimeFeatureAccessV1,
    StoredEntitlementV1,
};
use crate::tests::{signed_entitlement, signed_revocations, NOW};
use crate::{
    verify_entitlement, EntitlementAccessV1, EntitlementVerificationErrorV1 as Verification,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::signature::Ed25519KeyPair;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const SEED: [u8; 32] = [0x94; 32];

#[derive(Default)]
struct MemorySource {
    proof: Mutex<Option<StoredEntitlementV1>>,
    floors: Mutex<BTreeMap<String, u64>>,
    fail_save: AtomicBool,
    replace_on_save: AtomicBool,
    fail_floor: AtomicBool,
    fail_floor_read: AtomicBool,
}

impl EntitlementSourceV1 for MemorySource {
    fn load(&self) -> Result<Option<StoredEntitlementV1>, &'static str> {
        Ok(self.proof.lock().unwrap().clone())
    }

    fn save(&self, proof: &StoredEntitlementV1) -> Result<(), &'static str> {
        if self.fail_save.load(Ordering::SeqCst) {
            return Err("proof save failed");
        }
        let mut persisted = proof.clone();
        if self.replace_on_save.load(Ordering::SeqCst) {
            persisted.entitlement.signature = URL_SAFE_NO_PAD.encode([0; 64]);
        }
        *self.proof.lock().unwrap() = Some(persisted);
        Ok(())
    }

    fn revocation_floor(&self, account: &str) -> Result<u64, &'static str> {
        if self.fail_floor_read.load(Ordering::SeqCst) {
            return Err("cloud revocation checkpoint unavailable");
        }
        Ok(*self.floors.lock().unwrap().get(account).unwrap_or(&0))
    }

    fn advance_revocation_floor(&self, account: &str, sequence: u64) -> Result<(), &'static str> {
        if self.fail_floor.load(Ordering::SeqCst) {
            return Err("floor save failed");
        }
        let mut floors = self.floors.lock().unwrap();
        let floor = floors.entry(account.into()).or_default();
        *floor = (*floor).max(sequence);
        Ok(())
    }
}

fn proof(sequence: Option<u64>) -> (StoredEntitlementV1, BTreeMap<String, [u8; 32]>) {
    let (entitlement, public_key) = signed_entitlement(SEED);
    (
        StoredEntitlementV1 {
            entitlement,
            revocations: sequence.map(|seq| signed_revocations(SEED, seq, vec![])),
        },
        BTreeMap::from([("billing-key-1".into(), public_key)]),
    )
}

fn local_pro_proof() -> (StoredEntitlementV1, BTreeMap<String, [u8; 32]>) {
    let (mut stored, keys) = proof(None);
    stored.entitlement.payload.claims.plan_id = "local-pro".into();
    stored.entitlement.payload.claims.feature_ids = vec!["advanced-reports".into()];
    let signer = Ed25519KeyPair::from_seed_unchecked(&SEED).unwrap();
    stored.entitlement.signature = URL_SAFE_NO_PAD.encode(
        signer.sign(&stored.entitlement.payload.signing_bytes().unwrap()).as_ref());
    (stored, keys)
}

fn freelancer_proof(sequence: Option<u64>) -> (StoredEntitlementV1, BTreeMap<String, [u8; 32]>) {
    let (mut stored, keys) = proof(sequence);
    stored.entitlement.payload.claims.plan_id = "freelancer".into();
    stored.entitlement.payload.claims.feature_ids = [
        "advanced-reports", "android", "e2ee-sync", "freelancer-workspace", "integrations", "ios",
    ].into_iter().map(str::to_owned).collect();
    let signer = Ed25519KeyPair::from_seed_unchecked(&SEED).unwrap();
    stored.entitlement.signature = URL_SAFE_NO_PAD.encode(
        signer.sign(&stored.entitlement.payload.signing_bytes().unwrap()).as_ref());
    (stored, keys)
}

#[test]
fn signed_freelancer_feature_actions_allow_current_and_grace_access() {
    let (stored, keys) = freelancer_proof(Some(8));
    let source = Arc::new(MemorySource::default());
    let runtime = RuntimeFeatureAccessV1::new(keys, 0, source);
    runtime.install(stored, NOW).unwrap();
    let mut calls = 0;
    for (now, expected) in [(NOW, EntitlementAccessV1::Current), (NOW + 101, EntitlementAccessV1::Grace)] {
        assert_eq!(runtime.require_feature_access("freelancer-workspace", now).unwrap().access, expected);
        assert_eq!(runtime.with_feature_access("freelancer-workspace", now, || {
            calls += 1;
            "approved local work"
        }).unwrap(), "approved local work");
    }
    assert_eq!(calls, 2);
    assert!(runtime.require_sync_access(NOW).is_ok());
    assert_eq!(runtime.with_sync_access(NOW, || 7).unwrap(), 7);
}

#[test]
fn freelancer_actions_recheck_replaced_proofs_and_never_run_when_denied() {
    let (stored, keys) = freelancer_proof(Some(8));
    let (wrong_feature, _) = proof(Some(8));
    let mut missing_revocations = stored.clone();
    missing_revocations.revocations = None;
    let mut forged = stored.clone();
    forged.entitlement.signature = URL_SAFE_NO_PAD.encode([0; 64]);
    let mut expired = stored.clone();
    let snapshot = expired.revocations.as_mut().unwrap();
    snapshot.expires_at = NOW + 7_200;
    let signer = Ed25519KeyPair::from_seed_unchecked(&SEED).unwrap();
    snapshot.signature = URL_SAFE_NO_PAD.encode(signer.sign(&snapshot.signing_bytes().unwrap()).as_ref());
    let mut revoked = stored.clone();
    revoked.revocations = Some(signed_revocations(SEED, 9,
        vec![stored.entitlement.payload.claims.entitlement_id.clone()]));
    let mut stale = stored.clone();
    stale.revocations = Some(signed_revocations(SEED, 7, vec![]));
    for (name, replacement, now, expected) in [
        ("missing", None, NOW, Error::MissingEntitlement),
        ("wrong feature", Some(wrong_feature), NOW, Error::MissingFeature),
        ("missing revocations", Some(missing_revocations), NOW, Error::Verification(Verification::MissingRevocations)),
        ("forged", Some(forged), NOW, Error::Verification(Verification::InvalidSignature)),
        ("expired entitlement", Some(expired), NOW + 3_601, Error::Verification(Verification::Expired)),
        ("expired snapshot", Some(stored.clone()), NOW + 1_001, Error::Verification(Verification::RevocationSnapshotExpired)),
        ("revoked", Some(revoked), NOW, Error::Verification(Verification::Revoked)),
        ("stale", Some(stale), NOW, Error::Verification(Verification::StaleRevocations)),
    ] {
        let source = Arc::new(MemorySource::default());
        let runtime = RuntimeFeatureAccessV1::new(keys.clone(), 0, source.clone());
        runtime.install(stored.clone(), NOW).unwrap();
        assert!(runtime.require_feature_access("freelancer-workspace", NOW).is_ok());
        *source.proof.lock().unwrap() = replacement;
        let mut called = false;
        assert_eq!(runtime.with_feature_access("freelancer-workspace", now, || {
            called = true;
        }).unwrap_err(), expected, "{name}");
        assert!(!called, "{name} must prevent the action");
    }
}

#[test]
fn purchased_features_require_signed_revocations_even_at_zero_floor() {
    for (plan, feature, features) in [
        ("freelancer", "freelancer-workspace", vec!["freelancer-workspace"]),
        ("plus", "e2ee-sync", vec!["e2ee-sync"]),
        ("peak-ai", "peak-ai", vec!["peak-ai"]),
        ("pro", "advanced-reports", vec!["advanced-reports"]),
        ("local-pro", "advanced-reports", vec!["advanced-reports", "future-feature"]),
    ] {
        let (mut stored, keys) = proof(None);
        stored.entitlement.payload.claims.plan_id = plan.into();
        stored.entitlement.payload.claims.feature_ids = features.into_iter().map(str::to_owned).collect();
        let signer = Ed25519KeyPair::from_seed_unchecked(&SEED).unwrap();
        stored.entitlement.signature = URL_SAFE_NO_PAD.encode(
            signer.sign(&stored.entitlement.payload.signing_bytes().unwrap()).as_ref());
        let source = Arc::new(MemorySource::default());
        *source.proof.lock().unwrap() = Some(stored);
        let runtime = RuntimeFeatureAccessV1::new(keys, 0, source);
        let mut called = false;
        assert_eq!(runtime.with_feature_access(feature, NOW, || {
            called = true;
        }).unwrap_err(), Error::Verification(Verification::MissingRevocations), "{plan}/{feature}");
        assert!(!called, "snapshot-free {plan}/{feature} must prevent the action");
    }
}

#[test]
fn local_pro_without_snapshot_retains_offline_access_after_cloud_revocation_floor() {
    let (stored, keys) = local_pro_proof();
    let source = Arc::new(MemorySource::default());
    source.floors.lock().unwrap().insert(super::ENTITLEMENT_REVOCATION_SCOPE_V1.into(), 9);
    let runtime = RuntimeFeatureAccessV1::new(keys, 8, source.clone());
    assert_eq!(runtime.install(stored.clone(), NOW).unwrap().claims.feature_ids, ["advanced-reports"]);
    assert_eq!(runtime.status(NOW).unwrap().unwrap().access, EntitlementAccessV1::Current);
    assert_eq!(source.floors.lock().unwrap().get(super::ENTITLEMENT_REVOCATION_SCOPE_V1), Some(&9));
    source.fail_floor_read.store(true, Ordering::SeqCst);
    assert_eq!(runtime.status(NOW + 101).unwrap().unwrap().access, EntitlementAccessV1::Grace);
    assert_eq!(runtime.require_feature_access("advanced-reports", NOW).unwrap().access, EntitlementAccessV1::Current);
    assert_eq!(runtime.with_feature_access("advanced-reports", NOW + 101, || "offline report").unwrap(), "offline report");
    assert_eq!(runtime.require_sync_access(NOW).unwrap_err(), Error::Verification(Verification::MissingRevocations));
    assert_eq!(runtime.status(NOW - 61).unwrap_err(), Error::Verification(Verification::NotYetValid));
    assert_eq!(runtime.status(NOW + 3_601).unwrap_err(), Error::Verification(Verification::Expired));
    let mut forged = stored;
    forged.entitlement.signature = URL_SAFE_NO_PAD.encode([0; 64]);
    assert_eq!(runtime.install(forged, NOW).unwrap_err(), Error::Verification(Verification::InvalidSignature));
    assert_eq!(source.floors.lock().unwrap().get(super::ENTITLEMENT_REVOCATION_SCOPE_V1), Some(&9));
}

#[test]
fn local_pro_offline_exception_does_not_cover_cloud_or_non_catalog_features() {
    let (stored, keys) = local_pro_proof();
    for (plan, features) in [
        ("plus", vec!["e2ee-sync"]), ("pro", vec!["e2ee-sync"]), ("freelancer", vec!["e2ee-sync"]),
        ("local-pro", vec!["e2ee-sync"]), ("local-pro", vec!["advanced-reports", "e2ee-sync"]),
        ("local-pro", vec!["advanced-reports", "future-feature"]),
    ] {
        let source = Arc::new(MemorySource::default());
        source.floors.lock().unwrap().insert(super::ENTITLEMENT_REVOCATION_SCOPE_V1.into(), 9);
        let runtime = RuntimeFeatureAccessV1::new(keys.clone(), 8, source);
        let mut candidate = stored.clone();
        candidate.entitlement.payload.claims.plan_id = plan.into();
        candidate.entitlement.payload.claims.feature_ids = features.into_iter().map(str::to_owned).collect();
        let signer = Ed25519KeyPair::from_seed_unchecked(&SEED).unwrap();
        candidate.entitlement.signature = URL_SAFE_NO_PAD.encode(
            signer.sign(&candidate.entitlement.payload.signing_bytes().unwrap()).as_ref());
        assert_eq!(runtime.install(candidate, NOW).unwrap_err(), Error::Verification(Verification::MissingRevocations), "snapshot-free {plan} must remain denied");
        assert!(runtime.require_sync_access(NOW).is_err());
    }
}

#[test]
fn local_pro_with_explicit_snapshot_honors_revocation_expiry_and_floor() {
    let (stored, keys) = local_pro_proof();
    for (snapshot, expected) in [
        (signed_revocations(SEED, 8, vec![]), Verification::StaleRevocations),
        (signed_revocations(SEED, 9, vec![stored.entitlement.payload.claims.entitlement_id.clone()]), Verification::Revoked),
        ({ let mut expired = signed_revocations(SEED, 9, vec![]); expired.expires_at = NOW - 1;
           let signer = Ed25519KeyPair::from_seed_unchecked(&SEED).unwrap();
           expired.signature = URL_SAFE_NO_PAD.encode(signer.sign(&expired.signing_bytes().unwrap()).as_ref()); expired }, Verification::RevocationSnapshotExpired),
    ] {
        let source = Arc::new(MemorySource::default());
        source.floors.lock().unwrap().insert(super::ENTITLEMENT_REVOCATION_SCOPE_V1.into(), 9);
        let runtime = RuntimeFeatureAccessV1::new(keys.clone(), 8, source);
        let mut candidate = stored.clone();
        candidate.revocations = Some(snapshot);
        assert_eq!(runtime.install(candidate, NOW).unwrap_err(), Error::Verification(expected));
    }
}

#[test]
fn stored_signed_vector_rejects_tuple_forms_at_every_contract_object() {
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../test-vectors/entitlement-v1.json"
    )).unwrap();
    let (mut stored, mut keys) = proof(Some(8));
    stored.entitlement = serde_json::from_value(vector["entitlement"].clone()).unwrap();
    let public_key = URL_SAFE_NO_PAD.decode(vector["public_key"].as_str().unwrap())
        .unwrap().try_into().unwrap();
    keys.insert(stored.entitlement.payload.key_id.clone(), public_key);
    let verified = verify_entitlement(&stored.entitlement, &keys, NOW, stored.revocations.as_ref(), 0).unwrap();
    let canonical = serde_json::to_value(&stored).unwrap();
    assert_eq!(serde_json::from_value::<StoredEntitlementV1>(canonical.clone()).unwrap(), stored);

    let cases: &[(&str, &[&str])] = &[
        ("/entitlement/payload/claims", &["schema_version", "entitlement_id", "account_id", "plan_id", "feature_ids", "issued_at", "expires_at", "grace_until", "device_limit"]),
        ("/entitlement/payload", &["key_id", "claims"]),
        ("/entitlement", &["payload", "signature"]),
        ("/revocations", &["schema_version", "key_id", "sequence", "issued_at", "expires_at", "revoked_entitlement_ids", "signature"]),
        ("", &["entitlement", "revocations"]),
    ];
    for (path, fields) in cases {
        let mut tuple = canonical.clone();
        let values = fields.iter().map(|field| tuple.pointer(path).unwrap()[*field].clone()).collect();
        *tuple.pointer_mut(path).unwrap() = serde_json::Value::Array(values);
        let parsed = serde_json::from_value::<StoredEntitlementV1>(tuple.clone());
        if let Ok(parsed) = &parsed {
            assert_eq!(verify_entitlement(&parsed.entitlement, &keys, NOW, parsed.revocations.as_ref(), 0).unwrap(), verified);
        }
        assert!(parsed.is_err(), "signed tuple-form object was accepted at {path}");
        assert!(serde_json::from_slice::<StoredEntitlementV1>(&serde_json::to_vec(&tuple).unwrap()).is_err(), "tuple-form bytes were accepted at {path}");
    }
}

#[test]
fn stored_object_parser_preserves_duplicate_unknown_and_optional_field_rules() {
    let (stored, _) = proof(Some(8));
    let canonical = serde_json::to_value(&stored).unwrap();
    let encoded = serde_json::to_string(&canonical).unwrap();
    for (path, field) in [("", "entitlement"), ("/entitlement", "payload"),
        ("/entitlement/payload", "claims"), ("/entitlement/payload/claims", "plan_id"),
        ("", "revocations"), ("/revocations", "sequence")] {
        let value = serde_json::to_string(&canonical.pointer(path).unwrap()[field]).unwrap();
        let field = format!("\"{field}\":{value}");
        let duplicate = encoded.replacen(&field, &format!("{field},{field}"), 1);
        assert!(serde_json::from_str::<StoredEntitlementV1>(&duplicate).is_err(), "duplicate field was accepted at {path}");
    }
    for path in ["", "/entitlement", "/entitlement/payload", "/entitlement/payload/claims", "/revocations"] {
        let mut unexpected = canonical.clone();
        unexpected.pointer_mut(path).unwrap()["activity"] = serde_json::json!({"title":"private-activity-marker"});
        assert!(serde_json::from_value::<StoredEntitlementV1>(unexpected.clone()).is_err(), "unknown field was accepted at {path}");
        assert!(serde_json::from_slice::<StoredEntitlementV1>(&serde_json::to_vec(&unexpected).unwrap()).is_err());
    }
    let mut optional = canonical;
    optional["revocations"] = serde_json::Value::Null;
    assert!(serde_json::from_value::<StoredEntitlementV1>(optional.clone()).unwrap().revocations.is_none());
    optional.as_object_mut().unwrap().remove("revocations");
    assert!(serde_json::from_value::<StoredEntitlementV1>(optional).unwrap().revocations.is_none());
}

#[test]
fn closed_defaults_and_empty_release_trust_deny_sync() {
    let default = RuntimeFeatureAccessV1::default();
    assert_eq!(default.status(NOW).unwrap(), None);
    assert_eq!(
        default.require_sync_access(NOW).unwrap_err(),
        Error::MissingEntitlement
    );
    let (stored, _) = proof(Some(8));
    let mut unexpected = serde_json::to_value(&stored).unwrap();
    unexpected["ui_enabled"] = serde_json::json!(true);
    assert!(serde_json::from_value::<StoredEntitlementV1>(unexpected).is_err());
    let source = Arc::new(MemorySource::default());
    *source.proof.lock().unwrap() = Some(stored);
    let runtime = RuntimeFeatureAccessV1::new(BTreeMap::new(), 0, source);
    assert_eq!(
        runtime.require_sync_access(NOW).unwrap_err(),
        Error::Verification(Verification::UnknownKey)
    );
}

#[test]
fn sync_rechecks_signed_state_and_clock_at_actual_work() {
    let (stored, keys) = proof(Some(8));
    let source = Arc::new(MemorySource::default());
    let runtime = RuntimeFeatureAccessV1::new(keys, 0, source.clone());
    runtime.install(stored.clone(), NOW).unwrap();
    assert_eq!(
        runtime.require_sync_access(NOW).unwrap().access,
        EntitlementAccessV1::Current
    );
    assert_eq!(
        runtime.require_sync_access(NOW + 101).unwrap().access,
        EntitlementAccessV1::Grace
    );
    assert_eq!(
        runtime.require_sync_access(NOW + 1_001).unwrap_err(),
        Error::Verification(Verification::RevocationSnapshotExpired)
    );
    assert_eq!(
        runtime.require_sync_access(NOW + 3_601).unwrap_err(),
        Error::Verification(Verification::RevocationSnapshotExpired)
    );
    source
        .proof
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .entitlement
        .signature = URL_SAFE_NO_PAD.encode([0; 64]);
    assert_eq!(
        runtime.require_sync_access(NOW).unwrap_err(),
        Error::Verification(Verification::InvalidSignature)
    );
}

#[test]
fn forged_expired_and_wrong_feature_proofs_never_enable_sync() {
    let (mut stored, keys) = proof(Some(8));
    let source = Arc::new(MemorySource::default());
    let runtime = RuntimeFeatureAccessV1::new(keys, 0, source);
    let authentic = stored.clone();
    stored.entitlement.signature = URL_SAFE_NO_PAD.encode([0; 64]);
    assert_eq!(
        runtime.install(stored, NOW).unwrap_err(),
        Error::Verification(Verification::InvalidSignature)
    );
    let mut expired = authentic.clone();
    let snapshot = expired.revocations.as_mut().unwrap();
    snapshot.expires_at = NOW + 7_200;
    let signer = Ed25519KeyPair::from_seed_unchecked(&SEED).unwrap();
    snapshot.signature =
        URL_SAFE_NO_PAD.encode(signer.sign(&snapshot.signing_bytes().unwrap()).as_ref());
    assert_eq!(
        runtime.install(expired, NOW + 3_601).unwrap_err(),
        Error::Verification(Verification::Expired)
    );
    assert_eq!(
        runtime.status(NOW + 3_601).unwrap_err(),
        Error::Verification(Verification::Expired)
    );
    let mut wrong_feature = authentic;
    wrong_feature.entitlement.payload.claims.feature_ids = vec!["local-pro".into()];
    let signer = Ed25519KeyPair::from_seed_unchecked(&SEED).unwrap();
    wrong_feature.entitlement.signature = URL_SAFE_NO_PAD.encode(
        signer
            .sign(&wrong_feature.entitlement.payload.signing_bytes().unwrap())
            .as_ref(),
    );
    runtime.install(wrong_feature, NOW).unwrap();
    assert_eq!(
        runtime.require_sync_access(NOW).unwrap_err(),
        Error::MissingFeature
    );
}

#[test]
fn revoked_import_advances_floor_and_prevents_old_snapshot_replay() {
    let (stored, keys) = proof(Some(8));
    let source = Arc::new(MemorySource::default());
    let runtime = RuntimeFeatureAccessV1::new(keys, 0, source.clone());
    runtime.install(stored.clone(), NOW).unwrap();
    let mut revoked = stored.clone();
    revoked.revocations = Some(signed_revocations(
        SEED,
        9,
        vec![stored.entitlement.payload.claims.entitlement_id.clone()],
    ));
    assert_eq!(
        runtime.install(revoked, NOW).unwrap_err(),
        Error::Verification(Verification::Revoked)
    );
    assert_eq!(
        runtime.status(NOW).unwrap_err(),
        Error::Verification(Verification::Revoked)
    );
    let mut other_account = stored;
    other_account.entitlement.payload.claims.account_id = URL_SAFE_NO_PAD.encode([0x44; 16]);
    let signer = Ed25519KeyPair::from_seed_unchecked(&SEED).unwrap();
    other_account.entitlement.signature = URL_SAFE_NO_PAD.encode(
        signer
            .sign(&other_account.entitlement.payload.signing_bytes().unwrap())
            .as_ref(),
    );
    *source.proof.lock().unwrap() = Some(other_account);
    assert_eq!(
        runtime.require_sync_access(NOW).unwrap_err(),
        Error::Verification(Verification::StaleRevocations)
    );
}

#[test]
fn status_learns_a_floor_and_missing_snapshots_deny_sync_without_changing_pure_verifier() {
    let (stored, keys) = proof(Some(8));
    let source = Arc::new(MemorySource::default());
    *source.proof.lock().unwrap() = Some(stored.clone());
    let runtime = RuntimeFeatureAccessV1::new(keys.clone(), 0, source.clone());
    runtime.status(NOW).unwrap().unwrap();
    let mut old = stored.clone();
    old.revocations = Some(signed_revocations(SEED, 7, vec![]));
    *source.proof.lock().unwrap() = Some(old);
    assert_eq!(
        runtime.status(NOW).unwrap_err(),
        Error::Verification(Verification::StaleRevocations)
    );
    let mut offline = stored;
    offline.revocations = None;
    assert!(verify_entitlement(&offline.entitlement, &keys, NOW, None, 0).is_ok());
    *source.proof.lock().unwrap() = Some(offline.clone());
    assert_eq!(
        runtime.require_sync_access(NOW).unwrap_err(),
        Error::Verification(Verification::MissingRevocations)
    );
    let fresh = Arc::new(MemorySource::default());
    *fresh.proof.lock().unwrap() = Some(offline);
    let offline_runtime = RuntimeFeatureAccessV1::new(keys, 0, fresh);
    assert!(offline_runtime.status(NOW).unwrap().is_some());
    assert_eq!(
        offline_runtime.require_sync_access(NOW).unwrap_err(),
        Error::Verification(Verification::MissingRevocations)
    );
}

#[test]
fn release_floor_and_forged_revocations_cannot_be_lowered_or_learned() {
    let (mut stored, keys) = proof(Some(8));
    let source = Arc::new(MemorySource::default());
    let runtime = RuntimeFeatureAccessV1::new(keys, 9, source.clone());
    assert_eq!(
        runtime.install(stored.clone(), NOW).unwrap_err(),
        Error::Verification(Verification::StaleRevocations)
    );
    stored.revocations = Some(signed_revocations(SEED, 99, vec![]));
    stored.revocations.as_mut().unwrap().signature = URL_SAFE_NO_PAD.encode([0; 64]);
    assert_eq!(
        runtime.install(stored.clone(), NOW).unwrap_err(),
        Error::Verification(Verification::InvalidSignature)
    );
    let signer = Ed25519KeyPair::from_seed_unchecked(&SEED).unwrap();
    let mut future = signed_revocations(SEED, 100, vec![]);
    future.issued_at = NOW + 1;
    future.signature =
        URL_SAFE_NO_PAD.encode(signer.sign(&future.signing_bytes().unwrap()).as_ref());
    stored.revocations = Some(future);
    assert_eq!(
        runtime.install(stored.clone(), NOW).unwrap_err(),
        Error::Verification(Verification::NotYetValid)
    );
    let mut expired = signed_revocations(SEED, 100, vec![]);
    expired.expires_at = NOW - 1;
    expired.signature =
        URL_SAFE_NO_PAD.encode(signer.sign(&expired.signing_bytes().unwrap()).as_ref());
    stored.revocations = Some(expired);
    assert_eq!(
        runtime.install(stored.clone(), NOW).unwrap_err(),
        Error::Verification(Verification::RevocationSnapshotExpired)
    );
    stored.revocations = Some(signed_revocations(SEED, 9, vec![]));
    assert!(runtime.install(stored, NOW).is_ok());
}

#[test]
fn save_failure_and_invalid_readback_keep_runtime_closed_until_successful_install() {
    let (stored, keys) = proof(Some(8));
    let source = Arc::new(MemorySource::default());
    let runtime = RuntimeFeatureAccessV1::new(keys, 0, source.clone());
    runtime.install(stored.clone(), NOW).unwrap();
    source.fail_save.store(true, Ordering::SeqCst);
    assert_eq!(
        runtime.install(stored.clone(), NOW).unwrap_err(),
        Error::Source("proof save failed")
    );
    assert!(runtime.require_sync_access(NOW).is_err());
    source.fail_save.store(false, Ordering::SeqCst);
    source.replace_on_save.store(true, Ordering::SeqCst);
    assert!(runtime.install(stored.clone(), NOW).is_err());
    assert!(runtime.require_sync_access(NOW).is_err());
    source.replace_on_save.store(false, Ordering::SeqCst);
    runtime.install(stored.clone(), NOW).unwrap();
    assert!(runtime.require_sync_access(NOW).is_ok());
    let mut newer = stored;
    newer.revocations = Some(signed_revocations(SEED, 9, vec![]));
    source.fail_floor.store(true, Ordering::SeqCst);
    assert_eq!(
        runtime.install(newer.clone(), NOW).unwrap_err(),
        Error::Source("floor save failed")
    );
    assert!(runtime.require_sync_access(NOW).is_err());
    source.fail_floor.store(false, Ordering::SeqCst);
    runtime.install(newer, NOW).unwrap();
    assert!(runtime.require_sync_access(NOW).is_ok());
}

#[test]
fn concurrent_installs_cannot_roll_back_a_newer_signed_snapshot() {
    let (stored, keys) = freelancer_proof(Some(8));
    let source = Arc::new(MemorySource::default());
    let runtime = Arc::new(RuntimeFeatureAccessV1::new(keys.clone(), 0, source));
    runtime.install(stored.clone(), NOW).unwrap();
    let mut newer = stored.clone();
    newer.revocations = Some(signed_revocations(SEED, 9, vec![]));
    std::thread::scope(|scope| {
        let new_runtime = runtime.clone();
        scope.spawn(move || new_runtime.install(newer, NOW).unwrap());
        let old_runtime = runtime.clone();
        let old = stored.clone();
        scope.spawn(move || {
            let _ = old_runtime.install(old, NOW);
        });
    });
    assert!(runtime.require_sync_access(NOW).is_ok());
    assert_eq!(
        runtime.install(stored.clone(), NOW).unwrap_err(),
        Error::Verification(Verification::StaleRevocations)
    );
    for feature_id in ["e2ee-sync", "freelancer-workspace"] {
        let source = Arc::new(MemorySource::default());
        let runtime = Arc::new(RuntimeFeatureAccessV1::new(keys.clone(), 0, source));
        runtime.install(stored.clone(), NOW).unwrap();
        let mut revoked = stored.clone();
        revoked.revocations = Some(signed_revocations(
            SEED,
            10,
            vec![revoked.entitlement.payload.claims.entitlement_id.clone()],
        ));
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (attempt_tx, attempt_rx) = std::sync::mpsc::channel();
        let (installed_tx, installed_rx) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            let sender_runtime = runtime.clone();
            scope.spawn(move || {
                sender_runtime
                    .with_feature_access(feature_id, NOW, || {
                        started_tx.send(()).unwrap();
                        release_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                    })
                    .unwrap()
            });
            started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            let importer_runtime = runtime.clone();
            scope.spawn(move || {
                attempt_tx.send(()).unwrap();
                installed_tx
                    .send(importer_runtime.install(revoked, NOW))
                    .unwrap();
            });
            attempt_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            assert!(
                installed_rx
                    .recv_timeout(Duration::from_millis(40))
                    .is_err(),
                "import must wait for the active send"
            );
            release_tx.send(()).unwrap();
            assert_eq!(
                installed_rx
                    .recv_timeout(Duration::from_secs(2))
                    .unwrap()
                    .unwrap_err(),
                Error::Verification(Verification::Revoked)
            );
        });
        let mut called = false;
        assert_eq!(
            runtime
                .with_feature_access(feature_id, NOW, || {
                    called = true;
                })
                .unwrap_err(),
            Error::Verification(Verification::Revoked)
        );
        assert!(!called);
    }
}
