use crate::{
    verify_entitlement, verify_signature, EntitlementVerificationErrorV1, VerifiedEntitlementV1,
};
use aw_models::{EntitlementClaimsV1, EntitlementRevocationSnapshotV1, EntitlementSigningPayloadV1, SignedEntitlementV1};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, RwLock};

pub const ENTITLEMENT_REVOCATION_SCOPE_V1: &str = "entitlement-revocations-v1";
pub const MAX_STORED_ENTITLEMENT_BYTES_V1: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StoredEntitlementV1 {
    pub entitlement: SignedEntitlementV1,
    pub revocations: Option<EntitlementRevocationSnapshotV1>,
}

// Serde accepts arrays for structs by default; signed contract objects must stay objects.
struct Object<T>(T);

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Object<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ObjectVisitor<T>(std::marker::PhantomData<T>);
        impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for ObjectVisitor<T> {
            type Value = T;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an entitlement contract object")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, map: A) -> Result<T, A::Error> {
                T::deserialize(serde::de::value::MapAccessDeserializer::new(map))
            }
        }
        deserializer.deserialize_map(ObjectVisitor(std::marker::PhantomData)).map(Self)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredProof {
    entitlement: Object<SignedProof>,
    revocations: Option<Object<EntitlementRevocationSnapshotV1>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedProof {
    payload: Object<SigningPayload>,
    signature: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SigningPayload {
    key_id: String,
    claims: Object<EntitlementClaimsV1>,
}

impl<'de> Deserialize<'de> for StoredEntitlementV1 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let proof = Object::<StoredProof>::deserialize(deserializer)?.0;
        let signed = proof.entitlement.0;
        let payload = signed.payload.0;
        Ok(Self {
            entitlement: SignedEntitlementV1 {
                payload: EntitlementSigningPayloadV1 { key_id: payload.key_id, claims: payload.claims.0 },
                signature: signed.signature,
            },
            revocations: proof.revocations.map(|revocations| revocations.0),
        })
    }
}

/// Billing metadata lives outside activity storage; saves are atomic and floors never decrease.
pub trait EntitlementSourceV1: Send + Sync {
    fn load(&self) -> Result<Option<StoredEntitlementV1>, &'static str>;
    fn save(&self, proof: &StoredEntitlementV1) -> Result<(), &'static str>;
    fn revocation_floor(&self, scope: &str) -> Result<u64, &'static str>;
    fn advance_revocation_floor(&self, scope: &str, sequence: u64) -> Result<(), &'static str>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeFeatureAccessErrorV1 {
    MissingEntitlement,
    MissingFeature,
    Verification(EntitlementVerificationErrorV1),
    Source(&'static str),
}

#[derive(Default)]
pub struct RuntimeFeatureAccessV1 {
    public_keys: BTreeMap<String, [u8; 32]>,
    minimum_revocation_sequence: u64,
    source: Option<Arc<dyn EntitlementSourceV1>>,
    work: RwLock<()>,
    persistence_failed: Mutex<bool>,
}

impl std::fmt::Debug for RuntimeFeatureAccessV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeFeatureAccessV1")
            .field("public_key_count", &self.public_keys.len())
            .field(
                "minimum_revocation_sequence",
                &self.minimum_revocation_sequence,
            )
            .field("source_available", &self.source.is_some())
            .finish()
    }
}

impl RuntimeFeatureAccessV1 {
    pub fn new(
        public_keys: BTreeMap<String, [u8; 32]>,
        minimum_revocation_sequence: u64,
        source: Arc<dyn EntitlementSourceV1>,
    ) -> Self {
        Self {
            public_keys,
            minimum_revocation_sequence,
            source: Some(source),
            ..Self::default()
        }
    }

    pub fn status(
        &self,
        now: u64,
    ) -> Result<Option<VerifiedEntitlementV1>, RuntimeFeatureAccessErrorV1> {
        let _work = self
            .work
            .read()
            .map_err(|_| RuntimeFeatureAccessErrorV1::Source("entitlement work lock failed"))?;
        Ok(self.current(now)?.map(|(_, access)| access))
    }

    pub fn install(
        &self,
        proof: StoredEntitlementV1,
        now: u64,
    ) -> Result<VerifiedEntitlementV1, RuntimeFeatureAccessErrorV1> {
        let _work = self
            .work
            .write()
            .map_err(|_| RuntimeFeatureAccessErrorV1::Source("entitlement work lock failed"))?;
        let source = self
            .source
            .as_ref()
            .ok_or(RuntimeFeatureAccessErrorV1::Source(
                "entitlement source unavailable",
            ))?;
        let mut failed = self
            .persistence_failed
            .lock()
            .map_err(|_| RuntimeFeatureAccessErrorV1::Source("entitlement source lock failed"))?;
        self.authenticate(&proof, source.as_ref(), now, &mut failed)?;
        // A failed replacement must close the previous proof until a successful import.
        *failed = true;
        source
            .save(&proof)
            .map_err(RuntimeFeatureAccessErrorV1::Source)?;
        let persisted = source
            .load()
            .map_err(RuntimeFeatureAccessErrorV1::Source)?
            .ok_or(RuntimeFeatureAccessErrorV1::MissingEntitlement)?;
        if persisted != proof {
            return Err(RuntimeFeatureAccessErrorV1::Source(
                "entitlement proof readback differs",
            ));
        }
        let floor = self.authenticate(&persisted, source.as_ref(), now, &mut failed)?;
        *failed = false;
        self.verify(&persisted, now, floor)
    }

    pub fn require_feature_access(
        &self,
        feature_id: &str,
        now: u64,
    ) -> Result<VerifiedEntitlementV1, RuntimeFeatureAccessErrorV1> {
        let _work = self
            .work
            .read()
            .map_err(|_| RuntimeFeatureAccessErrorV1::Source("entitlement work lock failed"))?;
        self.feature_access(feature_id, now)
    }

    pub fn with_feature_access<T>(
        &self,
        feature_id: &str,
        now: u64,
        action: impl FnOnce() -> T,
    ) -> Result<T, RuntimeFeatureAccessErrorV1> {
        let _work = self
            .work
            .read()
            .map_err(|_| RuntimeFeatureAccessErrorV1::Source("entitlement work lock failed"))?;
        self.feature_access(feature_id, now)?;
        Ok(action())
    }

    pub fn require_sync_access(
        &self,
        now: u64,
    ) -> Result<VerifiedEntitlementV1, RuntimeFeatureAccessErrorV1> {
        self.require_feature_access("e2ee-sync", now)
    }

    pub fn with_sync_access<T>(
        &self,
        now: u64,
        action: impl FnOnce() -> T,
    ) -> Result<T, RuntimeFeatureAccessErrorV1> {
        self.with_feature_access("e2ee-sync", now, action)
    }

    fn feature_access(
        &self,
        feature_id: &str,
        now: u64,
    ) -> Result<VerifiedEntitlementV1, RuntimeFeatureAccessErrorV1> {
        let (proof, access) = self
            .current(now)?
            .ok_or(RuntimeFeatureAccessErrorV1::MissingEntitlement)?;
        if proof.revocations.is_none()
            && !(feature_id == "advanced-reports"
                && access.claims.plan_id == "local-pro"
                && access.claims.feature_ids == ["advanced-reports"])
        {
            return Err(RuntimeFeatureAccessErrorV1::Verification(
                EntitlementVerificationErrorV1::MissingRevocations,
            ));
        }
        if !access
            .claims
            .feature_ids
            .iter()
            .any(|feature| feature == feature_id)
        {
            return Err(RuntimeFeatureAccessErrorV1::MissingFeature);
        }
        Ok(access)
    }

    fn current(
        &self,
        now: u64,
    ) -> Result<Option<(StoredEntitlementV1, VerifiedEntitlementV1)>, RuntimeFeatureAccessErrorV1>
    {
        let mut failed = self
            .persistence_failed
            .lock()
            .map_err(|_| RuntimeFeatureAccessErrorV1::Source("entitlement source lock failed"))?;
        if *failed {
            return Err(RuntimeFeatureAccessErrorV1::Source(
                "entitlement persistence failed",
            ));
        }
        let Some(source) = &self.source else {
            return Ok(None);
        };
        let Some(proof) = source.load().map_err(RuntimeFeatureAccessErrorV1::Source)? else {
            return Ok(None);
        };
        let floor = self.authenticate(&proof, source.as_ref(), now, &mut failed)?;
        let access = self.verify(&proof, now, floor)?;
        Ok(Some((proof, access)))
    }

    fn verify(
        &self,
        proof: &StoredEntitlementV1,
        now: u64,
        floor: u64,
    ) -> Result<VerifiedEntitlementV1, RuntimeFeatureAccessErrorV1> {
        verify_entitlement(
            &proof.entitlement,
            &self.public_keys,
            now,
            proof.revocations.as_ref(),
            floor,
        )
        .map_err(RuntimeFeatureAccessErrorV1::Verification)
    }

    fn authenticate(
        &self,
        proof: &StoredEntitlementV1,
        source: &dyn EntitlementSourceV1,
        now: u64,
        failed: &mut bool,
    ) -> Result<u64, RuntimeFeatureAccessErrorV1> {
        use EntitlementVerificationErrorV1 as Verification;
        let invalid = || RuntimeFeatureAccessErrorV1::Verification(Verification::InvalidContract);
        proof.entitlement.validate().map_err(|_| invalid())?;
        if let Some(snapshot) = &proof.revocations {
            snapshot.validate().map_err(|_| invalid())?;
        }
        let bytes = serde_json::to_vec(proof).map_err(|_| invalid())?;
        if bytes.len() > MAX_STORED_ENTITLEMENT_BYTES_V1 {
            return Err(invalid());
        }
        verify_signature(
            &proof.entitlement.payload.key_id,
            &proof
                .entitlement
                .payload
                .signing_bytes()
                .map_err(|_| invalid())?,
            &proof.entitlement.signature,
            &self.public_keys,
        )
        .map_err(RuntimeFeatureAccessErrorV1::Verification)?;
        let claims = &proof.entitlement.payload.claims;
        // shortcut: offline Local Pro includes only advanced-reports; update after a reviewed catalog change.
        if proof.revocations.is_none()
            && claims.plan_id == "local-pro"
            && claims.feature_ids == ["advanced-reports"]
        {
            return Ok(0);
        }
        let secure_floor = source
            .revocation_floor(ENTITLEMENT_REVOCATION_SCOPE_V1)
            .map_err(RuntimeFeatureAccessErrorV1::Source)?;
        let floor = secure_floor.max(self.minimum_revocation_sequence);
        if let Some(snapshot) = &proof.revocations {
            if now < snapshot.issued_at {
                return Err(RuntimeFeatureAccessErrorV1::Verification(
                    Verification::NotYetValid,
                ));
            }
            if now > snapshot.expires_at {
                return Err(RuntimeFeatureAccessErrorV1::Verification(
                    Verification::RevocationSnapshotExpired,
                ));
            }
            if snapshot.sequence < floor {
                return Err(RuntimeFeatureAccessErrorV1::Verification(
                    Verification::StaleRevocations,
                ));
            }
            verify_signature(
                &snapshot.key_id,
                &snapshot.signing_bytes().map_err(|_| invalid())?,
                &snapshot.signature,
                &self.public_keys,
            )
            .map_err(RuntimeFeatureAccessErrorV1::Verification)?;
            if snapshot.sequence > secure_floor {
                let previous_failure = *failed;
                *failed = true;
                source
                    .advance_revocation_floor(ENTITLEMENT_REVOCATION_SCOPE_V1, snapshot.sequence)
                    .map_err(RuntimeFeatureAccessErrorV1::Source)?;
                if source
                    .revocation_floor(ENTITLEMENT_REVOCATION_SCOPE_V1)
                    .map_err(RuntimeFeatureAccessErrorV1::Source)?
                    < snapshot.sequence
                {
                    return Err(RuntimeFeatureAccessErrorV1::Source(
                        "entitlement revocation floor did not advance",
                    ));
                }
                *failed = previous_failure;
            }
        } else if floor > 0 {
            return Err(RuntimeFeatureAccessErrorV1::Verification(
                Verification::MissingRevocations,
            ));
        }
        Ok(floor)
    }
}

#[cfg(test)]
#[path = "runtime_tests.rs"]
mod tests;
