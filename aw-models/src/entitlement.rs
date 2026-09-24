use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

pub const ENTITLEMENT_SCHEMA_VERSION_V1: u32 = 1;
// ponytail: cap token features at 128 and device_limit at 64; raise only after package/activation tests need it.
pub const ENTITLEMENT_MAX_FEATURES_V1: usize = 128;
pub const ENTITLEMENT_MAX_DEVICES_V1: u16 = 64;
// ponytail: keep one signed revocation snapshot under 4 MiB; paginate if accounts exceed 100k revocations.
pub const ENTITLEMENT_MAX_REVOCATIONS_V1: usize = 100_000;
pub const PACKAGE_CATALOG_SCHEMA_VERSION_V1: u32 = 1;

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommercialPackageV1 {
    pub id: String,
    pub label: String,
    pub status: String,
    pub purchase_model: String,
    pub feature_ids: Vec<String>,
    pub device_limit: Option<u16>,
    pub grace_period_seconds: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageCatalogV1 {
    pub schema_version: u32,
    pub prices_published: bool,
    pub always_available_feature_ids: Vec<String>,
    pub packages: Vec<CommercialPackageV1>,
}

impl PackageCatalogV1 {
    pub fn validate(&self) -> Result<(), EntitlementContractErrorV1> {
        if self.schema_version != PACKAGE_CATALOG_SCHEMA_VERSION_V1 || self.prices_published
            || self.packages.is_empty() || self.packages.len() > 32
        {
            return Err(EntitlementContractErrorV1::InvalidPackageCatalog);
        }
        validate_feature_ids(&self.always_available_feature_ids)?;
        let always_available: BTreeSet<_> = self.always_available_feature_ids.iter().map(String::as_str).collect();
        let mut package_ids = BTreeSet::new();
        for package in &self.packages {
            validate_identifier(&package.id)?;
            validate_identifier(&package.status.to_ascii_lowercase().replace(' ', "-"))?;
            validate_identifier(&package.purchase_model)?;
            if !package_ids.insert(package.id.as_str())
                || package.label.trim().is_empty()
                || package.label.len() > 80
                || package.label.chars().any(char::is_control)
            {
                return Err(EntitlementContractErrorV1::InvalidPackageCatalog);
            }
            if !matches!(package.status.as_str(), "Available" | "Planned" | "Decision required")
                || !matches!(package.purchase_model.as_str(), "free" | "subscription" | "one-time-license" | "usage-credits" | "decision-required")
            {
                return Err(EntitlementContractErrorV1::InvalidPackageCatalog);
            }
            let paid = !matches!(package.purchase_model.as_str(), "free" | "decision-required");
            if paid && package.feature_ids.is_empty() {
                return Err(EntitlementContractErrorV1::InvalidPackageCatalog);
            }
            if package.status == "Available" && paid {
                if !package.device_limit.is_some_and(|limit| (1..=ENTITLEMENT_MAX_DEVICES_V1).contains(&limit))
                    || package.grace_period_seconds.is_none()
                {
                    return Err(EntitlementContractErrorV1::InvalidPackageCatalog);
                }
            } else if package.device_limit.is_some() || package.grace_period_seconds.is_some() {
                return Err(EntitlementContractErrorV1::InvalidPackageCatalog);
            }
            validate_feature_ids(&package.feature_ids)?;
            if package.feature_ids.iter().any(|feature| always_available.contains(feature.as_str())) {
                return Err(EntitlementContractErrorV1::InvalidPackageCatalog);
            }
            if package.status == "Decision required"
                && (package.purchase_model != "decision-required" || !package.feature_ids.is_empty())
            {
                return Err(EntitlementContractErrorV1::InvalidPackageCatalog);
            }
            if package.id == "community"
                && (package.status != "Available" || package.purchase_model != "free" || !package.feature_ids.is_empty())
            {
                return Err(EntitlementContractErrorV1::InvalidPackageCatalog);
            }
        }
        if !package_ids.contains("community") {
            return Err(EntitlementContractErrorV1::InvalidPackageCatalog);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EntitlementClaimsV1 {
    pub schema_version: u32,
    pub entitlement_id: String,
    pub account_id: String,
    pub plan_id: String,
    pub feature_ids: Vec<String>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub grace_until: u64,
    pub device_limit: u16,
}

impl EntitlementClaimsV1 {
    pub fn validate(&self) -> Result<(), EntitlementContractErrorV1> {
        if self.schema_version != ENTITLEMENT_SCHEMA_VERSION_V1 {
            return Err(EntitlementContractErrorV1::UnknownVersion);
        }
        validate_id(&self.entitlement_id)?;
        validate_id(&self.account_id)?;
        validate_identifier(&self.plan_id)?;
        if self.feature_ids.is_empty()
            || self.feature_ids.len() > ENTITLEMENT_MAX_FEATURES_V1
            || self.feature_ids.windows(2).any(|pair| pair[0] >= pair[1])
            || self.feature_ids.iter().any(|feature| validate_identifier(feature).is_err())
        {
            return Err(EntitlementContractErrorV1::InvalidFeatures);
        }
        if self.issued_at == 0
            || self.expires_at <= self.issued_at
            || self.grace_until < self.expires_at
            || !(1..=ENTITLEMENT_MAX_DEVICES_V1).contains(&self.device_limit)
        {
            return Err(EntitlementContractErrorV1::InvalidTimeOrLimit);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EntitlementSigningPayloadV1 {
    pub key_id: String,
    pub claims: EntitlementClaimsV1,
}

impl EntitlementSigningPayloadV1 {
    pub fn validate(&self) -> Result<(), EntitlementContractErrorV1> {
        validate_identifier(&self.key_id)?;
        self.claims.validate()
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, EntitlementContractErrorV1> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| EntitlementContractErrorV1::InvalidPayload)
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedEntitlementV1 {
    pub payload: EntitlementSigningPayloadV1,
    pub signature: String,
}

impl SignedEntitlementV1 {
    pub fn validate(&self) -> Result<(), EntitlementContractErrorV1> {
        self.payload.validate()?;
        validate_signature(&self.signature)
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EntitlementRevocationSnapshotV1 {
    pub schema_version: u32,
    pub key_id: String,
    pub sequence: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub revoked_entitlement_ids: Vec<String>,
    pub signature: String,
}

#[derive(Serialize)]
struct EntitlementRevocationSigningPayloadV1<'a> {
    schema_version: u32,
    key_id: &'a str,
    sequence: u64,
    issued_at: u64,
    expires_at: u64,
    revoked_entitlement_ids: &'a [String],
}

impl EntitlementRevocationSnapshotV1 {
    pub fn validate(&self) -> Result<(), EntitlementContractErrorV1> {
        if self.schema_version != ENTITLEMENT_SCHEMA_VERSION_V1 {
            return Err(EntitlementContractErrorV1::UnknownVersion);
        }
        validate_identifier(&self.key_id)?;
        if self.sequence == 0
            || self.issued_at == 0
            || self.expires_at <= self.issued_at
            || self.revoked_entitlement_ids.len() > ENTITLEMENT_MAX_REVOCATIONS_V1
            || self.revoked_entitlement_ids.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(EntitlementContractErrorV1::InvalidRevocationSnapshot);
        }
        for entitlement_id in &self.revoked_entitlement_ids {
            validate_id(entitlement_id)?;
        }
        validate_signature(&self.signature)
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, EntitlementContractErrorV1> {
        if self.schema_version != ENTITLEMENT_SCHEMA_VERSION_V1 {
            return Err(EntitlementContractErrorV1::UnknownVersion);
        }
        validate_identifier(&self.key_id)?;
        if self.sequence == 0
            || self.issued_at == 0
            || self.expires_at <= self.issued_at
            || self.revoked_entitlement_ids.len() > ENTITLEMENT_MAX_REVOCATIONS_V1
            || self.revoked_entitlement_ids.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(EntitlementContractErrorV1::InvalidRevocationSnapshot);
        }
        for entitlement_id in &self.revoked_entitlement_ids {
            validate_id(entitlement_id)?;
        }
        serde_json::to_vec(&EntitlementRevocationSigningPayloadV1 {
            schema_version: self.schema_version,
            key_id: &self.key_id,
            sequence: self.sequence,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            revoked_entitlement_ids: &self.revoked_entitlement_ids,
        }).map_err(|_| EntitlementContractErrorV1::InvalidPayload)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntitlementContractErrorV1 {
    UnknownVersion,
    InvalidId,
    InvalidIdentifier,
    InvalidFeatures,
    InvalidTimeOrLimit,
    InvalidSignature,
    InvalidRevocationSnapshot,
    InvalidPackageCatalog,
    InvalidPayload,
}

impl fmt::Display for EntitlementContractErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnknownVersion => "unsupported entitlement contract version",
            Self::InvalidId => "invalid opaque entitlement ID",
            Self::InvalidIdentifier => "invalid entitlement identifier",
            Self::InvalidFeatures => "invalid entitlement feature list",
            Self::InvalidTimeOrLimit => "invalid entitlement time or device limit",
            Self::InvalidSignature => "invalid entitlement signature encoding",
            Self::InvalidRevocationSnapshot => "invalid entitlement revocation snapshot",
            Self::InvalidPackageCatalog => "invalid commercial package catalog",
            Self::InvalidPayload => "entitlement payload could not be encoded",
        })
    }
}

impl std::error::Error for EntitlementContractErrorV1 {}

fn validate_id(value: &str) -> Result<(), EntitlementContractErrorV1> {
    let decoded = URL_SAFE_NO_PAD.decode(value)
        .map_err(|_| EntitlementContractErrorV1::InvalidId)?;
    if decoded.len() == 16 && URL_SAFE_NO_PAD.encode(decoded) == value {
        Ok(())
    } else {
        Err(EntitlementContractErrorV1::InvalidId)
    }
}

fn validate_identifier(value: &str) -> Result<(), EntitlementContractErrorV1> {
    if !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        Ok(())
    } else {
        Err(EntitlementContractErrorV1::InvalidIdentifier)
    }
}

fn validate_signature(value: &str) -> Result<(), EntitlementContractErrorV1> {
    let decoded = URL_SAFE_NO_PAD.decode(value)
        .map_err(|_| EntitlementContractErrorV1::InvalidSignature)?;
    if decoded.len() == 64 && URL_SAFE_NO_PAD.encode(decoded) == value {
        Ok(())
    } else {
        Err(EntitlementContractErrorV1::InvalidSignature)
    }
}

fn validate_feature_ids(values: &[String]) -> Result<(), EntitlementContractErrorV1> {
    if values.len() > ENTITLEMENT_MAX_FEATURES_V1
        || values.windows(2).any(|pair| pair[0] >= pair[1])
        || values.iter().any(|feature| validate_identifier(feature).is_err())
    {
        Err(EntitlementContractErrorV1::InvalidPackageCatalog)
    } else {
        Ok(())
    }
}
