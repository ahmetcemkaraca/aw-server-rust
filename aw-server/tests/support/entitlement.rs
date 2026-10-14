use aw_entitlements::{
    EntitlementSourceV1, RuntimeFeatureAccessV1, StoredEntitlementV1,
    ENTITLEMENT_REVOCATION_SCOPE_V1,
};
use aw_models::{
    EntitlementClaimsV1, EntitlementRevocationSnapshotV1, EntitlementSigningPayloadV1,
    SignedEntitlementV1,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

pub const KEY_ID: &str = "synthetic-entitlement";

#[derive(Default)]
pub struct MemorySource {
    pub proof: Mutex<Option<StoredEntitlementV1>>,
    pub floor: Mutex<u64>,
}

impl EntitlementSourceV1 for MemorySource {
    fn load(&self) -> Result<Option<StoredEntitlementV1>, &'static str> {
        Ok(self.proof.lock().unwrap().clone())
    }
    fn save(&self, proof: &StoredEntitlementV1) -> Result<(), &'static str> {
        *self.proof.lock().unwrap() = Some(proof.clone());
        Ok(())
    }
    fn revocation_floor(&self, scope: &str) -> Result<u64, &'static str> {
        assert_eq!(scope, ENTITLEMENT_REVOCATION_SCOPE_V1);
        Ok(*self.floor.lock().unwrap())
    }
    fn advance_revocation_floor(&self, scope: &str, sequence: u64) -> Result<(), &'static str> {
        assert_eq!(scope, ENTITLEMENT_REVOCATION_SCOPE_V1);
        let mut floor = self.floor.lock().unwrap();
        if sequence < *floor {
            return Err("rollback");
        }
        *floor = sequence;
        Ok(())
    }
}

pub fn key() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[0xE1; 32]).unwrap()
}

pub fn proof(now: u64, sequence: u64, revoked: bool) -> StoredEntitlementV1 {
    let key = key();
    let payload = EntitlementSigningPayloadV1 {
        key_id: KEY_ID.into(),
        claims: EntitlementClaimsV1 {
            schema_version: 1,
            entitlement_id: URL_SAFE_NO_PAD.encode([0xE2; 16]),
            account_id: URL_SAFE_NO_PAD.encode([0xE3; 16]),
            plan_id: "plus".into(),
            feature_ids: vec!["e2ee-sync".into()],
            issued_at: now - 60,
            expires_at: now + 3600,
            grace_until: now + 7200,
            device_limit: 3,
        },
    };
    let signature = URL_SAFE_NO_PAD.encode(key.sign(&payload.signing_bytes().unwrap()).as_ref());
    let mut revocations = EntitlementRevocationSnapshotV1 {
        schema_version: 1,
        key_id: KEY_ID.into(),
        sequence,
        issued_at: now - 30,
        expires_at: now + 10_000,
        revoked_entitlement_ids: if revoked {
            vec![payload.claims.entitlement_id.clone()]
        } else {
            vec![]
        },
        signature: String::new(),
    };
    revocations.signature =
        URL_SAFE_NO_PAD.encode(key.sign(&revocations.signing_bytes().unwrap()).as_ref());
    StoredEntitlementV1 {
        entitlement: SignedEntitlementV1 { payload, signature },
        revocations: Some(revocations),
    }
}

pub fn access() -> Arc<RuntimeFeatureAccessV1> {
    let now = aw_server_time();
    configured_access(proof(now, 1, false), now).0
}

pub fn freelancer_proof(now: u64, sequence: u64, revoked: bool) -> StoredEntitlementV1 {
    let mut proof = proof(now, sequence, revoked);
    proof.entitlement.payload.claims.plan_id = "freelancer".into();
    proof.entitlement.payload.claims.feature_ids = vec!["freelancer-workspace".into()];
    proof.entitlement.signature = URL_SAFE_NO_PAD.encode(
        key()
            .sign(&proof.entitlement.payload.signing_bytes().unwrap())
            .as_ref(),
    );
    proof
}

pub fn configured_access(
    proof: StoredEntitlementV1,
    now: u64,
) -> (Arc<RuntimeFeatureAccessV1>, Arc<MemorySource>) {
    let source = Arc::new(MemorySource::default());
    let runtime = Arc::new(RuntimeFeatureAccessV1::new(
        BTreeMap::from([(
            KEY_ID.into(),
            key().public_key().as_ref().try_into().unwrap(),
        )]),
        1,
        source.clone(),
    ));
    runtime.install(proof, now).unwrap();
    (runtime, source)
}

pub fn aw_server_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub fn report_proof(now:u64,sequence:u64,revoked:bool,local_pro:bool)->StoredEntitlementV1 {
    let mut proof=proof(now,sequence,revoked);
    proof.entitlement.payload.claims.plan_id=if local_pro {"local-pro"}else{"pro"}.into();
    proof.entitlement.payload.claims.feature_ids=vec!["advanced-reports".into()];
    proof.entitlement.signature=URL_SAFE_NO_PAD.encode(key().sign(&proof.entitlement.payload.signing_bytes().unwrap()).as_ref());
    if local_pro {proof.revocations=None;}
    proof
}
