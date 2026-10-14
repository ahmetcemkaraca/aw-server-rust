use crate::reports::record;
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::fmt;

// Reserve the existing signed manifest/operation overhead, then check actual encoding at journaling.
pub const SYNC_POLICY_MAX_FIELD_BYTES_V1: usize = crate::SYNC_MAX_CHUNK_BYTES - 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncPolicyContractErrorV1 {
    Invalid,
    ByteLimit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SyncPolicyDecisionV1 {
    KeepLocal,
    AcceptRemote,
}

record!(SyncPolicyChoiceRequestV1 {
    schema_version: u16,
    #[serde(deserialize_with = "crate::reports::limited_string::<_, 64>")]
    candidate_id: String,
    #[serde(deserialize_with = "crate::reports::limited_string::<_, 64>")]
    expected_review_sha256: String,
    decision: SyncPolicyDecisionV1,
});

record!(SyncPolicyValueV1 {
    schema_version: u16,
    present: bool,
    value: Value,
});

record!(SyncRecoveryPolicyFieldV1 {
    #[serde(deserialize_with = "crate::reports::limited_string::<_, 64>")]
    field: String,
    value: SyncPolicyValueV1,
});
record!(SyncRecoveryPolicyDecisionV1 {
    #[serde(deserialize_with = "crate::reports::limited_string::<_, 64>")]
    field: String,
    #[serde(deserialize_with = "crate::reports::limited_strings::<_, 100000, 64>")]
    candidate_ids: Vec<String>,
    #[serde(deserialize_with = "crate::reports::limited_string::<_, 64>")]
    active_binding_sha256: String,
});
record!(SyncRecoveryPolicyV1 {
    schema_version: u16,
    #[serde(deserialize_with = "crate::reports::limited_vec::<_, _, 21>")]
    active_values: Vec<SyncRecoveryPolicyFieldV1>,
    #[serde(deserialize_with = "crate::reports::limited_vec::<_, _, 21>")]
    decisions: Vec<SyncRecoveryPolicyDecisionV1>,
    #[serde(default, skip_serializing_if = "Vec::is_empty", deserialize_with = "crate::reports::limited_vec::<_, _, 100000>")]
    pending_recovery: Vec<SyncRecoveryPolicyCandidateV1>,
});

record!(SyncPolicyRecoverySourceV1 {
    schema_version: u16,
    #[serde(deserialize_with = "crate::reports::limited_string::<_, 22>")]
    vault_id: String,
    #[serde(deserialize_with = "crate::reports::limited_string::<_, 20>")]
    key_epoch: String,
    #[serde(deserialize_with = "crate::reports::limited_string::<_, 22>")]
    snapshot_id: String,
});
record!(SyncRecoveryPolicyCandidateV1 {
    schema_version: u16,
    source: SyncPolicyRecoverySourceV1,
    #[serde(deserialize_with = "crate::reports::limited_string::<_, 64>")]
    field: String,
    value: SyncPolicyValueV1,
});
record!(SyncRecoveryPolicySummaryV1 {
    schema_version: u16,
    continuity_present: bool,
    conflict_count: usize,
    target_binding_sha256: String,
});

record!(SyncPolicyContextV1 {
    schema_version: u16,
    #[serde(deserialize_with = "crate::reports::limited_string::<_, 64>")]
    context_id: String,
});

record!(SyncPolicyCandidateV1 {
    candidate_id: String,
    field: String,
    device_id: String,
    counter: String,
    policy_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recovery_source: Option<SyncPolicyRecoverySourceV1>,
});
record!(SyncPolicyCandidatePageV1 {
    schema_version: u16,
    candidates: Vec<SyncPolicyCandidateV1>,
    next_cursor: Option<String>,
});
record!(SyncPolicyPreviewV1 {
    schema_version: u16,
    candidate: SyncPolicyCandidateV1,
    current: SyncPolicyValueV1,
    proposed: SyncPolicyValueV1,
    expected_review_sha256: String,
});
record!(SyncPolicyChoiceResultV1 {
    schema_version: u16,
    field: String,
    decision: SyncPolicyDecisionV1,
    applied: bool,
});

record!(SyncCapturePreferencesV1 {
    window: bool,
    idle: bool,
    browser: bool,
    titles: bool,
    urls: bool,
    paths: bool,
    excluded_apps: Vec<String>,
    excluded_domains: Vec<String>,
});

impl SyncCapturePreferencesV1 {
    pub fn from_policy(policy: &crate::CapturePolicy) -> Self {
        Self {
            window: policy.window,
            idle: policy.idle,
            browser: policy.browser,
            titles: policy.titles,
            urls: policy.urls,
            paths: policy.paths,
            excluded_apps: policy.excluded_apps.clone(),
            excluded_domains: policy.excluded_domains.clone(),
        }
    }

    pub fn apply_to(
        &self,
        current: &crate::CapturePolicy,
    ) -> Result<crate::CapturePolicy, SyncPolicyContractErrorV1> {
        let mut policy = current.clone();
        policy.window = self.window;
        policy.idle = self.idle;
        policy.browser = self.browser;
        policy.titles = self.titles;
        policy.urls = self.urls;
        policy.paths = self.paths;
        policy.excluded_apps = self.excluded_apps.clone();
        policy.excluded_domains = self.excluded_domains.clone();
        policy
            .validate()
            .map_err(|_| SyncPolicyContractErrorV1::Invalid)?;
        Ok(policy)
    }
}

impl SyncPolicyChoiceRequestV1 {
    pub fn validate(&self) -> Result<(), SyncPolicyContractErrorV1> {
        if self.schema_version != 1
            || !crate::valid_lower_hex(&self.candidate_id, 64)
            || !crate::valid_lower_hex(&self.expected_review_sha256, 64)
        {
            return Err(SyncPolicyContractErrorV1::Invalid);
        }
        Ok(())
    }
}

impl SyncPolicyValueV1 {
    pub fn validate(&self) -> Result<(), SyncPolicyContractErrorV1> {
        if self.schema_version != 1 || (!self.present && !self.value.is_null()) {
            return Err(SyncPolicyContractErrorV1::Invalid);
        }
        crate::serialized_size(self, SYNC_POLICY_MAX_FIELD_BYTES_V1)
            .map_err(|_| SyncPolicyContractErrorV1::ByteLimit)
    }
}
