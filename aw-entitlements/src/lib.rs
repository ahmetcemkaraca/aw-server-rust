use aw_models::{
    EntitlementClaimsV1, EntitlementRevocationSnapshotV1, SignedEntitlementV1,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::signature::{UnparsedPublicKey, ED25519};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntitlementAccessV1 {
    Current,
    Grace,
}

#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedEntitlementV1 {
    pub claims: EntitlementClaimsV1,
    pub access: EntitlementAccessV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntitlementVerificationErrorV1 {
    InvalidContract,
    UnknownKey,
    InvalidSignature,
    NotYetValid,
    Expired,
    Revoked,
    StaleRevocations,
    MissingRevocations,
    RevocationSnapshotExpired,
}

pub fn verify_entitlement(
    token: &SignedEntitlementV1,
    public_keys: &BTreeMap<String, [u8; 32]>,
    now: u64,
    revocations: Option<&EntitlementRevocationSnapshotV1>,
    minimum_revocation_sequence: u64,
) -> Result<VerifiedEntitlementV1, EntitlementVerificationErrorV1> {
    token.validate().map_err(|_| EntitlementVerificationErrorV1::InvalidContract)?;
    verify_signature(
        &token.payload.key_id,
        &token.payload.signing_bytes().map_err(|_| EntitlementVerificationErrorV1::InvalidContract)?,
        &token.signature,
        public_keys,
    )?;

    let claims = &token.payload.claims;
    if now < claims.issued_at {
        return Err(EntitlementVerificationErrorV1::NotYetValid);
    }
    if now > claims.grace_until {
        return Err(EntitlementVerificationErrorV1::Expired);
    }
    if let Some(snapshot) = revocations {
        snapshot.validate().map_err(|_| EntitlementVerificationErrorV1::InvalidContract)?;
        if now < snapshot.issued_at {
            return Err(EntitlementVerificationErrorV1::NotYetValid);
        }
        if now > snapshot.expires_at {
            return Err(EntitlementVerificationErrorV1::RevocationSnapshotExpired);
        }
        if snapshot.sequence < minimum_revocation_sequence {
            return Err(EntitlementVerificationErrorV1::StaleRevocations);
        }
        verify_signature(
            &snapshot.key_id,
            &snapshot.signing_bytes().map_err(|_| EntitlementVerificationErrorV1::InvalidContract)?,
            &snapshot.signature,
            public_keys,
        )?;
        if snapshot.revoked_entitlement_ids.binary_search(&claims.entitlement_id).is_ok() {
            return Err(EntitlementVerificationErrorV1::Revoked);
        }
    } else if minimum_revocation_sequence > 0 {
        return Err(EntitlementVerificationErrorV1::MissingRevocations);
    }
    Ok(VerifiedEntitlementV1 {
        claims: claims.clone(),
        access: if now > claims.expires_at {
            EntitlementAccessV1::Grace
        } else {
            EntitlementAccessV1::Current
        },
    })
}

fn verify_signature(
    key_id: &str,
    signing_bytes: &[u8],
    signature: &str,
    public_keys: &BTreeMap<String, [u8; 32]>,
) -> Result<(), EntitlementVerificationErrorV1> {
    let public_key = public_keys.get(key_id).ok_or(EntitlementVerificationErrorV1::UnknownKey)?;
    let signature = URL_SAFE_NO_PAD.decode(signature)
        .map_err(|_| EntitlementVerificationErrorV1::InvalidSignature)?;
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(signing_bytes, &signature)
        .map_err(|_| EntitlementVerificationErrorV1::InvalidSignature)
}

#[cfg(test)]
mod tests;
