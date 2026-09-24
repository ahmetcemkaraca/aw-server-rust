use super::{evaluate, EvaluationContext, VerifiedPolicyV1};
use aw_datastore::Datastore;
#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
use aw_models::SyncEnvelopeV1;
use aw_models::{
    AIAuthenticationV1, AIEndpointProfileV1, AIRequestFeatureV1, AIUserRequestV1, EgressApprovalScopeV1, EgressDecisionV1, EgressDestinationV1, EgressOutcomeV1,
    EgressPolicyDiffV1, EgressPolicyV1, EgressPurposeV1, EgressReasonCodeV1,
    EgressReceiptV1, EgressRequestV1, EgressUserPolicyV1,
};
#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
use aw_models::SYNC_EGRESS_PURPOSE_V1;
#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
use aw_sync_e2ee::{decrypt_chunk, unwrap_vault_data_key, AccountRootKeyV1, WrappedVaultDataKeyV1};
#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use reqwest::blocking::Client;
use reqwest::header::{HeaderValue, ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use reqwest::redirect::Policy;
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::Value;
use std::collections::HashMap;
use std::fmt;
use std::io::Read;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex, RwLock, RwLockReadGuard};
use std::time::Duration as StdDuration;
use zeroize::Zeroizing;
use url::Url;

const PREVIEW_LIFETIME: Duration = Duration::minutes(5);
const MAX_PREVIEWS: usize = 128;
const MAX_PAYLOAD_BYTES: usize = 1024 * 1024;
const MAX_SYNC_PAYLOAD_BYTES: usize = 2 * 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 32 * 1024 * 1024;
const MAX_AI_RESPONSE_BYTES: usize = 128 * 1024;

pub trait EgressTransport: Send + Sync {
    fn send(
        &self,
        destination: &EgressDestinationV1,
        purpose: &EgressPurposeV1,
        payload: &[u8],
    ) -> Result<(), EgressReasonCodeV1>;

    fn request(
        &self,
        destination: &EgressDestinationV1,
        purpose: &EgressPurposeV1,
        payload: &[u8],
    ) -> Result<Vec<u8>, EgressReasonCodeV1> {
        self.send(destination, purpose, payload)?;
        Ok(Vec::new())
    }

    fn test_connection(
        &self,
        _profile: &AIEndpointProfileV1,
    ) -> Result<(u16, Vec<String>), EgressReasonCodeV1> {
        Err(EgressReasonCodeV1::DestinationRejected)
    }

    fn request_custom_ai(
        &self,
        _profile: &AIEndpointProfileV1,
        _purpose: &EgressPurposeV1,
        _payload: &[u8],
        _bearer_credential: Option<&str>,
    ) -> Result<Vec<u8>, EgressReasonCodeV1> {
        Err(EgressReasonCodeV1::DestinationRejected)
    }
}

struct ReqwestTransport;

#[derive(Clone)]
struct Preview {
    preview_id: String,
    destination_id: String,
    purpose_id: String,
    retention_id: String,
    policy_version: u64,
    policy_snapshot: EgressPolicyV1,
    allowed_fields: Vec<String>,
    payload: Vec<u8>,
    policy_payload: Option<Vec<u8>>,
    ai_feature: Option<AIRequestFeatureV1>,
    custom_endpoint: Option<AIEndpointProfileV1>,
    created_at: DateTime<Utc>,
}

struct UserPolicyPreview {
    current: EgressPolicyV1,
    expected: EgressUserPolicyV1,
    draft: EgressUserPolicyV1,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct EgressUserPolicyPreview {
    pub preview_id: String,
    pub diff: EgressPolicyDiffV1,
}

pub struct ApprovedEgress {
    approval_id: String,
    preview_id: String,
    destination_id: String,
    purpose_id: String,
    retention_id: String,
    policy_version: u64,
    scope: EgressApprovalScopeV1,
    allowed_fields: Vec<String>,
    payload: Vec<u8>,
    custom_endpoint: Option<AIEndpointProfileV1>,
}

impl fmt::Debug for ApprovedEgress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApprovedEgress")
            .field("approval_id", &"<redacted>")
            .field("preview_id", &self.preview_id)
            .field("destination_id", &self.destination_id)
            .field("purpose_id", &self.purpose_id)
            .field("policy_version", &self.policy_version)
            .field("payload", &"<redacted>")
            .finish()
    }
}

impl ApprovedEgress {
    pub fn approval_id(&self) -> &str { &self.approval_id }
}

#[derive(Clone)]
pub struct EgressProxy {
    datastore: Datastore,
    transport: Arc<dyn EgressTransport>,
    previews: Arc<Mutex<HashMap<String, Preview>>>,
    user_policy_previews: Arc<Mutex<HashMap<String, UserPolicyPreview>>>,
    // ponytail: one process-wide gate keeps kill-switch changes ordered with sends; use per-destination gates only if concurrent outbound traffic is added.
    send_gate: Arc<RwLock<()>>,
}

pub struct EgressSendGuard<'a> {
    proxy: &'a EgressProxy,
    _gate: RwLockReadGuard<'a, ()>,
}

impl EgressProxy {
    pub fn new(datastore: Datastore) -> Self {
        Self::with_transport(datastore, ReqwestTransport)
    }

    pub fn with_transport<T: EgressTransport + 'static>(datastore: Datastore, transport: T) -> Self {
        Self {
            datastore,
            transport: Arc::new(transport),
            previews: Arc::new(Mutex::new(HashMap::new())),
            user_policy_previews: Arc::new(Mutex::new(HashMap::new())),
            send_gate: Arc::new(RwLock::new(())),
        }
    }

    pub fn begin_send(&self) -> Result<EgressSendGuard<'_>, EgressReasonCodeV1> {
        let gate = self.send_gate.read().map_err(|_| EgressReasonCodeV1::KillSwitch)?;
        Ok(EgressSendGuard { proxy: self, _gate: gate })
    }

    pub fn with_policy_update<T>(
        &self,
        update: impl FnOnce() -> T,
    ) -> Result<T, EgressReasonCodeV1> {
        let _gate = self.send_gate.write().map_err(|_| EgressReasonCodeV1::KillSwitch)?;
        Ok(update())
    }

    pub fn kill_switch_enabled(&self) -> Result<bool, EgressReasonCodeV1> {
        self.datastore.egress_kill_switch().map_err(|_| EgressReasonCodeV1::KillSwitch)
    }

    /// Explicit connection test: only a user-selected profile and the signed
    /// generic AI purpose may issue a bodyless HEAD. The kill-switch gate covers
    /// DNS, TLS and receipt persistence as one operation.
    pub fn test_custom_endpoint(
        &self,
        policy: &VerifiedPolicyV1,
        profile: &AIEndpointProfileV1,
        now_utc: DateTime<Utc>,
    ) -> Result<(u16, Vec<String>), EgressReasonCodeV1> {
        let _gate = self.send_gate.read().map_err(|_| EgressReasonCodeV1::KillSwitch)?;
        let policy = policy.for_custom_endpoint_probe(profile)?;
        let destination = policy.policy().destinations.iter()
            .find(|destination| destination.id == "custom-endpoint")
            .ok_or(EgressReasonCodeV1::UnknownDestination)?;
        let purpose = policy.policy().purposes.iter()
            .find(|purpose| purpose.id == "ai.custom_endpoint")
            .ok_or(EgressReasonCodeV1::UnknownPurpose)?;
        let lease = self.datastore.egress_lease().map_err(|_| EgressReasonCodeV1::KillSwitch)?;
        if lease.egress_kill_switch().unwrap_or(true) {
            return Err(EgressReasonCodeV1::KillSwitch);
        }
        let result = self.transport.test_connection(profile);
        let receipt = EgressReceiptV1 {
            schema_version: 1,
            destination_id: destination.id.clone(),
            purpose_id: purpose.id.clone(),
            retention_id: purpose.retention_id.clone(),
            allowed_fields: Vec::new(),
            policy_version: policy.policy().version,
            scope: EgressApprovalScopeV1::Once,
            decision: if result.is_ok() { EgressOutcomeV1::Allow } else { EgressOutcomeV1::Deny },
            created_at: now_utc,
        };
        lease.record_egress_receipt(&receipt).map_err(|_| EgressReasonCodeV1::NetworkUnavailable)?;
        result
    }

    pub fn send_custom_ai_approval(
        &self,
        policy: &VerifiedPolicyV1,
        profile: &AIEndpointProfileV1,
        preview_id: &str,
        approval_id: &str,
        bearer_credential: Option<&str>,
        now_utc: DateTime<Utc>,
        local_offset_seconds: i32,
    ) -> Result<(EgressReceiptV1, Vec<u8>), EgressReasonCodeV1> {
        let _gate = self.send_gate.read().map_err(|_| EgressReasonCodeV1::KillSwitch)?;
        if self.datastore.egress_kill_switch().unwrap_or(true) {
            return Err(EgressReasonCodeV1::KillSwitch);
        }
        if policy.custom_endpoint_profile() != Some(profile)
            || (profile.authentication == AIAuthenticationV1::Bearer
                && bearer_credential.is_none_or(str::is_empty))
            || (profile.authentication == AIAuthenticationV1::None && bearer_credential.is_some())
            || bearer_credential.is_some_and(|value| {
                value.is_empty() || value.len() > 8192 || value.bytes().any(|byte| !(0x21..=0x7e).contains(&byte))
            })
        {
            return Err(EgressReasonCodeV1::InvalidPayload);
        }
        if policy.policy().version == 0 {
            return Err(EgressReasonCodeV1::InvalidPolicy);
        }
        let approval = self.datastore.get_egress_approval(approval_id, now_utc)
            .map_err(|_| EgressReasonCodeV1::ApprovalExpired)?
            .ok_or(EgressReasonCodeV1::ApprovalExpired)?;
        let preview = self.previews.lock().map_err(|_| EgressReasonCodeV1::InvalidPolicy)?
            .get(preview_id).cloned().ok_or(EgressReasonCodeV1::ApprovalExpired)?;
        if now_utc >= preview.created_at + PREVIEW_LIFETIME
            || preview.policy_version != policy.policy().version
            || &preview.policy_snapshot != policy.policy()
            || approval.policy_version != policy.policy().version
            || preview.custom_endpoint.as_ref() != Some(profile)
            || preview.ai_feature.is_none()
            || preview.destination_id != approval.destination_id
            || preview.purpose_id != approval.purpose_id
            || preview.retention_id != approval.retention_id
        {
            return Err(EgressReasonCodeV1::PolicyChanged);
        }
        let destination = policy.policy().destinations.iter()
            .find(|item| item.id == preview.destination_id)
            .ok_or(EgressReasonCodeV1::UnknownDestination)?;
        let purpose = policy.policy().purposes.iter()
            .find(|item| item.id == preview.purpose_id && item.destination_id == preview.destination_id)
            .ok_or(EgressReasonCodeV1::UnknownPurpose)?;
        if purpose.id != "ai.custom_endpoint" || purpose.retention_id != preview.retention_id
            || preview.destination_id != super::ai::custom_destination_id(profile)
        {
            return Err(EgressReasonCodeV1::PolicyChanged);
        }
        let secrets = self.datastore.get_or_create_egress_secrets()
            .map_err(|_| EgressReasonCodeV1::InvalidPolicy)?;
        let context = EvaluationContext {
            now_utc,
            local_offset_seconds,
            alias_secret: secrets.alias_secret(),
            preview_id,
        };
        let decision = evaluate_preview_payload(&preview, policy.policy(), &context)?;
        let approved_bytes = decision.sanitized_payload.as_ref()
            .and_then(|value| serde_json::to_vec(value).ok())
            .ok_or(EgressReasonCodeV1::PolicyChanged)?;
        if decision.outcome != EgressOutcomeV1::Allow || approved_bytes != preview.payload {
            return Err(EgressReasonCodeV1::PolicyChanged);
        }
        let tag = payload_tag(secrets.approval_secret(), &approved_bytes);
        let lease = self.datastore.egress_lease().map_err(|_| EgressReasonCodeV1::KillSwitch)?;
        if lease.egress_kill_switch().unwrap_or(true) { return Err(EgressReasonCodeV1::KillSwitch); }
        let stored_scope = lease.consume_egress_approval(
            approval_id,
            &preview.destination_id,
            &preview.purpose_id,
            &preview.retention_id,
            preview.policy_version,
            tag,
            now_utc,
        ).map_err(|_| EgressReasonCodeV1::ApprovalExpired)?;
        if stored_scope != approval.scope { return Err(EgressReasonCodeV1::PolicyChanged); }
        if lease.egress_kill_switch().unwrap_or(true) { return Err(EgressReasonCodeV1::KillSwitch); }
        if stored_scope == EgressApprovalScopeV1::Once {
            self.previews.lock().map_err(|_| EgressReasonCodeV1::InvalidPolicy)?.remove(preview_id);
        }
        let response = self.transport.request_custom_ai(profile, purpose, &approved_bytes, bearer_credential)?;
        if response.len() > MAX_AI_RESPONSE_BYTES { return Err(EgressReasonCodeV1::InvalidPayload); }
        let receipt = EgressReceiptV1 {
            schema_version: 1,
            destination_id: destination.id.clone(),
            purpose_id: purpose.id.clone(),
            retention_id: purpose.retention_id.clone(),
            allowed_fields: purpose.allowed_fields.clone(),
            policy_version: policy.policy().version,
            scope: stored_scope,
            decision: EgressOutcomeV1::Allow,
            created_at: now_utc,
        };
        lease.record_egress_receipt(&receipt).map_err(|_| EgressReasonCodeV1::NetworkUnavailable)?;
        Ok((receipt, response))
    }

    pub fn set_kill_switch(&self, enabled: bool) -> Result<(), EgressReasonCodeV1> {
        let _gate = self.send_gate.write().map_err(|_| EgressReasonCodeV1::KillSwitch)?;
        self.datastore.set_egress_kill_switch(enabled).map_err(|_| EgressReasonCodeV1::KillSwitch)?;
        self.previews.lock().map_err(|_| EgressReasonCodeV1::InvalidPolicy)?.clear();
        Ok(())
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn sync_enabled(&self) -> Result<bool, EgressReasonCodeV1> {
        self.datastore.sync_enabled().map_err(|_| EgressReasonCodeV1::ApprovalRequired)
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn set_sync_enabled(
        &self,
        enabled: bool,
        destination_id: Option<String>,
        purpose_id: Option<String>,
    ) -> Result<(), EgressReasonCodeV1> {
        let _gate = self.send_gate.write().map_err(|_| EgressReasonCodeV1::KillSwitch)?;
        self.datastore.set_sync_enabled(enabled, destination_id, purpose_id)
            .map_err(|_| EgressReasonCodeV1::ApprovalRequired)
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn validate_sync_envelope(&self, envelope: &SyncEnvelopeV1) -> Result<(), EgressReasonCodeV1> {
        envelope.validate().map_err(|_| EgressReasonCodeV1::InvalidPayload)?;
        let keys = self.datastore.load_sync_key_material()
            .map_err(|_| EgressReasonCodeV1::InvalidPolicy)?
            .ok_or(EgressReasonCodeV1::InvalidPolicy)?;
        let root = AccountRootKeyV1::from_bytes(Zeroizing::new(*keys.account_root_key()));
        let wrapped = WrappedVaultDataKeyV1 {
            schema_version: envelope.schema_version,
            vault_id: URL_SAFE_NO_PAD.encode(keys.vault_id()),
            key_epoch: keys.key_epoch(),
            nonce: URL_SAFE_NO_PAD.encode(keys.wrapped_nonce()),
            ciphertext: URL_SAFE_NO_PAD.encode(keys.wrapped_ciphertext()),
        };
        let key = unwrap_vault_data_key(&root, &wrapped).map_err(|_| EgressReasonCodeV1::InvalidPolicy)?;
        // All sync payload classes are authenticated ciphertext chunks. Validate the
        // envelope with the current epoch key without assuming the relay object is a
        // manifest or the exact latest snapshot already stored on this device.
        decrypt_chunk(&key, envelope).map_err(|_| EgressReasonCodeV1::InvalidPayload)?;
        Ok(())
    }

    pub fn preview(
        &self,
        policy: &VerifiedPolicyV1,
        request: EgressRequestV1,
        now_utc: DateTime<Utc>,
        local_offset_seconds: i32,
    ) -> EgressDecisionV1 {
        if policy.custom_endpoint_profile().is_some() {
            return denied(policy.policy().version, "", EgressReasonCodeV1::InvalidPayload);
        }
        self.preview_inner(policy, request, None, now_utc, local_offset_seconds)
    }

    pub fn preview_custom_ai(
        &self,
        policy: &VerifiedPolicyV1,
        request: EgressRequestV1,
        feature: AIRequestFeatureV1,
        now_utc: DateTime<Utc>,
        local_offset_seconds: i32,
    ) -> EgressDecisionV1 {
        let Some(profile) = policy.custom_endpoint_profile() else {
            return denied(policy.policy().version, "", EgressReasonCodeV1::InvalidPayload);
        };
        if request.purpose_id != "ai.custom_endpoint"
            || policy.custom_endpoint_destination_id().as_deref() != Some(request.destination_id.as_str())
            || validate_custom_ai_source(profile, feature, &request.payload).is_err()
        {
            return denied(policy.policy().version, "", EgressReasonCodeV1::InvalidPayload);
        }
        self.preview_inner(policy, request, Some(feature), now_utc, local_offset_seconds)
    }

    fn preview_inner(
        &self,
        policy: &VerifiedPolicyV1,
        request: EgressRequestV1,
        ai_feature: Option<AIRequestFeatureV1>,
        now_utc: DateTime<Utc>,
        local_offset_seconds: i32,
    ) -> EgressDecisionV1 {
        let preview_id = match random_id() {
            Ok(id) => id,
            Err(_) => return denied(policy.policy().version, "", EgressReasonCodeV1::InvalidPolicy),
        };
        if self.datastore.egress_kill_switch().unwrap_or(true) {
            return denied(policy.policy().version, &preview_id, EgressReasonCodeV1::KillSwitch);
        }
        if serde_json::to_vec(&request.payload).map_or(true, |bytes| bytes.len() > MAX_PAYLOAD_BYTES) {
            return denied(policy.policy().version, &preview_id, EgressReasonCodeV1::InvalidPayload);
        }
        let secrets = match self.datastore.get_or_create_egress_secrets() {
            Ok(value) => value,
            Err(_) => return denied(policy.policy().version, &preview_id, EgressReasonCodeV1::InvalidPolicy),
        };
        let context = EvaluationContext {
            now_utc,
            local_offset_seconds,
            alias_secret: secrets.alias_secret(),
            preview_id: &preview_id,
        };
        let policy_payload = ai_feature.and_then(|_| serde_json::to_vec(&request.payload).ok());
        let mut decision = evaluate(&request, policy.policy(), &context);
        if decision.outcome != EgressOutcomeV1::Allow { return decision; }
        let Some(sanitized_payload) = decision.sanitized_payload.as_ref() else {
            return denied(policy.policy().version, &preview_id, EgressReasonCodeV1::InvalidPayload);
        };
        let payload = if let (Some(feature), Some(profile)) = (ai_feature, policy.custom_endpoint_profile()) {
            match render_custom_ai_payload(profile, feature, sanitized_payload) {
                Ok(payload) => payload,
                Err(error) => return denied(policy.policy().version, &preview_id, error),
            }
        } else {
            sanitized_payload.clone()
        };
        let Some(payload_slot) = decision.sanitized_payload.as_mut() else {
            return denied(policy.policy().version, &preview_id, EgressReasonCodeV1::InvalidPayload);
        };
        *payload_slot = payload.clone();
        let Ok(payload) = serde_json::to_vec(&payload) else {
            return denied(policy.policy().version, &preview_id, EgressReasonCodeV1::InvalidPayload);
        };
        let Some(purpose) = policy.policy().purposes.iter().find(|item| item.id == request.purpose_id) else {
            return denied(policy.policy().version, &preview_id, EgressReasonCodeV1::UnknownPurpose);
        };
        let preview = Preview {
            preview_id: preview_id.clone(),
            destination_id: request.destination_id,
            purpose_id: purpose.id.clone(),
            retention_id: purpose.retention_id.clone(),
            policy_version: policy.policy().version,
            policy_snapshot: policy.policy().clone(),
            allowed_fields: purpose.allowed_fields.clone(),
            payload,
            policy_payload,
            ai_feature,
            custom_endpoint: policy.custom_endpoint_profile().cloned(),
            created_at: now_utc,
        };
        let Ok(mut previews) = self.previews.lock() else {
            return denied(policy.policy().version, &preview_id, EgressReasonCodeV1::InvalidPolicy);
        };
        previews.retain(|_, item| now_utc < item.created_at + PREVIEW_LIFETIME);
        if previews.len() >= MAX_PREVIEWS {
            if let Some(oldest) = previews.values().min_by_key(|item| item.created_at).map(|item| item.preview_id.clone()) {
                previews.remove(&oldest);
            }
        }
        previews.insert(preview_id, preview);
        decision
    }

    /// Rebuilds the cached Custom Endpoint preview for a native confirmation UI.
    /// It never reads new request data or makes a network call.
    pub fn read_custom_ai_preview(
        &self,
        policy: &VerifiedPolicyV1,
        profile: &AIEndpointProfileV1,
        preview_id: &str,
        now_utc: DateTime<Utc>,
        local_offset_seconds: i32,
    ) -> Result<EgressDecisionV1, EgressReasonCodeV1> {
        if self.datastore.egress_kill_switch().unwrap_or(true) {
            return Err(EgressReasonCodeV1::KillSwitch);
        }
        if policy.custom_endpoint_profile() != Some(profile) {
            return Err(EgressReasonCodeV1::PolicyChanged);
        }
        let preview = self.previews.lock().map_err(|_| EgressReasonCodeV1::InvalidPolicy)?
            .get(preview_id).cloned().ok_or(EgressReasonCodeV1::ApprovalExpired)?;
        if now_utc >= preview.created_at + PREVIEW_LIFETIME
            || preview.policy_version != policy.policy().version
            || &preview.policy_snapshot != policy.policy()
            || preview.custom_endpoint.as_ref() != Some(profile)
            || preview.destination_id != super::ai::custom_destination_id(profile)
            || preview.ai_feature.is_none()
        {
            return Err(EgressReasonCodeV1::PolicyChanged);
        }
        let secrets = self.datastore.get_or_create_egress_secrets()
            .map_err(|_| EgressReasonCodeV1::InvalidPolicy)?;
        let context = EvaluationContext {
            now_utc,
            local_offset_seconds,
            alias_secret: secrets.alias_secret(),
            preview_id,
        };
        let decision = evaluate_preview_payload(&preview, policy.policy(), &context)?;
        let current_bytes = decision.sanitized_payload.as_ref()
            .and_then(|value| serde_json::to_vec(value).ok())
            .ok_or(EgressReasonCodeV1::PolicyChanged)?;
        if decision.outcome != EgressOutcomeV1::Allow || current_bytes != preview.payload {
            return Err(EgressReasonCodeV1::PolicyChanged);
        }
        Ok(decision)
    }

    pub fn preview_user_policy(
        &self,
        current: &EgressPolicyV1,
        current_user: &EgressUserPolicyV1,
        draft: &EgressUserPolicyV1,
        now_utc: DateTime<Utc>,
    ) -> Result<EgressUserPolicyPreview, EgressReasonCodeV1> {
        current_user.validate().map_err(|_| EgressReasonCodeV1::InvalidPolicy)?;
        draft.validate().map_err(|_| EgressReasonCodeV1::InvalidPolicy)?;
        if current.user_rules != current_user.user_rules
            || current.safe_zone_patterns != current_user.safe_zone_patterns
            || current.after_hours != current_user.after_hours
        {
            return Err(EgressReasonCodeV1::PolicyChanged);
        }
        let mut next = current.clone();
        next.user_rules = draft.user_rules.clone();
        next.safe_zone_patterns = draft.safe_zone_patterns.clone();
        next.after_hours = draft.after_hours.clone();
        let preview_id = random_id().map_err(|_| EgressReasonCodeV1::InvalidPolicy)?;
        let diff = super::policy_diff(current, &next);
        let preview = UserPolicyPreview {
            current: current.clone(),
            expected: current_user.clone(),
            draft: draft.clone(),
            created_at: now_utc,
        };
        let mut previews = self.user_policy_previews.lock().map_err(|_| EgressReasonCodeV1::InvalidPolicy)?;
        previews.retain(|_, item| now_utc < item.created_at + PREVIEW_LIFETIME);
        if previews.len() >= MAX_PREVIEWS {
            if let Some(oldest) = previews.iter().min_by_key(|(_, item)| item.created_at).map(|(id, _)| id.clone()) {
                previews.remove(&oldest);
            }
        }
        previews.insert(preview_id.clone(), preview);
        Ok(EgressUserPolicyPreview { preview_id, diff })
    }

    pub fn accept_user_policy(
        &self,
        preview_id: &str,
        current: &EgressPolicyV1,
        now_utc: DateTime<Utc>,
    ) -> Result<(EgressUserPolicyV1, EgressUserPolicyV1), EgressReasonCodeV1> {
        let preview = self.user_policy_previews.lock().map_err(|_| EgressReasonCodeV1::InvalidPolicy)?
            .remove(preview_id).ok_or(EgressReasonCodeV1::ApprovalExpired)?;
        if now_utc >= preview.created_at + PREVIEW_LIFETIME {
            return Err(EgressReasonCodeV1::ApprovalExpired);
        }
        if &preview.current != current {
            return Err(EgressReasonCodeV1::PolicyChanged);
        }
        Ok((preview.expected, preview.draft))
    }

    pub fn approve(
        &self,
        policy: &VerifiedPolicyV1,
        preview_id: &str,
        scope: EgressApprovalScopeV1,
        expires_at: Option<DateTime<Utc>>,
        now_utc: DateTime<Utc>,
        local_offset_seconds: i32,
    ) -> Result<ApprovedEgress, EgressReasonCodeV1> {
        let _gate = self.send_gate.read().map_err(|_| EgressReasonCodeV1::KillSwitch)?;
        self.approve_locked(policy, preview_id, scope, expires_at, now_utc, local_offset_seconds)
    }

    fn approve_locked(
        &self,
        policy: &VerifiedPolicyV1,
        preview_id: &str,
        scope: EgressApprovalScopeV1,
        expires_at: Option<DateTime<Utc>>,
        now_utc: DateTime<Utc>,
        local_offset_seconds: i32,
    ) -> Result<ApprovedEgress, EgressReasonCodeV1> {
        if self.datastore.egress_kill_switch().unwrap_or(true) { return Err(EgressReasonCodeV1::KillSwitch); }
        let preview = self.previews.lock().map_err(|_| EgressReasonCodeV1::InvalidPolicy)?
            .get(preview_id).cloned().ok_or(EgressReasonCodeV1::ApprovalExpired)?;
        if now_utc >= preview.created_at + PREVIEW_LIFETIME { return Err(EgressReasonCodeV1::ApprovalExpired); }
        if preview.policy_version != policy.policy().version
            || &preview.policy_snapshot != policy.policy()
            || preview.custom_endpoint.as_ref() != policy.custom_endpoint_profile()
            || (preview.custom_endpoint.is_some() && preview.ai_feature.is_none())
        {
            return Err(EgressReasonCodeV1::PolicyChanged);
        }

        let secrets = self.datastore.get_or_create_egress_secrets().map_err(|_| EgressReasonCodeV1::InvalidPolicy)?;
        let context = EvaluationContext {
            now_utc,
            local_offset_seconds,
            alias_secret: secrets.alias_secret(),
            preview_id,
        };
        let current = evaluate_preview_payload(&preview, policy.policy(), &context)?;
        let current_bytes = current.sanitized_payload.as_ref()
            .and_then(|payload| serde_json::to_vec(payload).ok())
            .ok_or(EgressReasonCodeV1::PolicyChanged)?;
        if current.outcome != EgressOutcomeV1::Allow || current_bytes != preview.payload {
            return Err(EgressReasonCodeV1::PolicyChanged);
        }
        let payload_tag = payload_tag(secrets.approval_secret(), &preview.payload);
        let approval_id = self.datastore.create_egress_approval(
            &preview.destination_id,
            &preview.purpose_id,
            &preview.retention_id,
            preview.policy_version,
            scope,
            payload_tag,
            expires_at,
            now_utc,
        ).map_err(|_| EgressReasonCodeV1::InvalidPolicy)?;
        Ok(ApprovedEgress {
            approval_id,
            preview_id: preview.preview_id,
            destination_id: preview.destination_id,
            purpose_id: preview.purpose_id,
            retention_id: preview.retention_id,
            policy_version: preview.policy_version,
            scope,
            allowed_fields: preview.allowed_fields,
            payload: preview.payload,
            custom_endpoint: preview.custom_endpoint,
        })
    }

    pub fn send(
        &self,
        policy: &VerifiedPolicyV1,
        approved: ApprovedEgress,
        now_utc: DateTime<Utc>,
        local_offset_seconds: i32,
    ) -> Result<EgressReceiptV1, EgressReasonCodeV1> {
        let _gate = self.send_gate.read().map_err(|_| EgressReasonCodeV1::KillSwitch)?;
        self.send_locked(policy, approved, now_utc, local_offset_seconds)
    }

    pub fn send_approval(
        &self,
        policy: &VerifiedPolicyV1,
        preview_id: &str,
        approval_id: &str,
        now_utc: DateTime<Utc>,
        local_offset_seconds: i32,
    ) -> Result<EgressReceiptV1, EgressReasonCodeV1> {
        let _gate = self.send_gate.read().map_err(|_| EgressReasonCodeV1::KillSwitch)?;
        self.send_approval_locked(policy, preview_id, approval_id, now_utc, local_offset_seconds)
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn send_sync_request(
        &self,
        policy: &VerifiedPolicyV1,
        request: EgressRequestV1,
        now_utc: DateTime<Utc>,
        local_offset_seconds: i32,
    ) -> Result<(EgressReceiptV1, Vec<u8>), EgressReasonCodeV1> {
        let _gate = self.send_gate.read().map_err(|_| EgressReasonCodeV1::KillSwitch)?;
        if self.datastore.egress_kill_switch().unwrap_or(true) {
            return Err(EgressReasonCodeV1::KillSwitch);
        }
        if request.purpose_id != SYNC_EGRESS_PURPOSE_V1 {
            return Err(EgressReasonCodeV1::UnknownPurpose);
        }
        let consent = self.datastore.sync_egress_consent()
            .ok().flatten().ok_or(EgressReasonCodeV1::ApprovalRequired)?;
        if consent.destination_id != request.destination_id || consent.purpose_id != request.purpose_id {
            return Err(EgressReasonCodeV1::ApprovalRequired);
        }
        let baseline = self.datastore.begin_sync_baseline()
            .map_err(|_| EgressReasonCodeV1::ApprovalRequired)?;
        if !baseline.complete { return Err(EgressReasonCodeV1::ApprovalRequired); }
        let original_payload = serde_json::to_vec(&request.payload).map_err(|_| EgressReasonCodeV1::InvalidPayload)?;
        if original_payload.len() > MAX_SYNC_PAYLOAD_BYTES {
            return Err(EgressReasonCodeV1::InvalidPayload);
        }
        let secrets = self.datastore.get_or_create_egress_secrets().map_err(|_| EgressReasonCodeV1::InvalidPolicy)?;
        let preview_id = random_id().map_err(|_| EgressReasonCodeV1::InvalidPolicy)?;
        let context = EvaluationContext {
            now_utc,
            local_offset_seconds,
            alias_secret: secrets.alias_secret(),
            preview_id: &preview_id,
        };
        let decision = evaluate(&request, policy.policy(), &context);
        if decision.outcome != EgressOutcomeV1::Allow {
            return Err(decision.reason_codes.first().copied().unwrap_or(EgressReasonCodeV1::ApprovalRequired));
        }
        let payload = decision.sanitized_payload.as_ref()
            .and_then(|payload| serde_json::to_vec(payload).ok())
            .ok_or(EgressReasonCodeV1::InvalidPayload)?;
        if payload != original_payload {
            return Err(EgressReasonCodeV1::PolicyChanged);
        }
        let destination = policy.policy().destinations.iter()
            .find(|item| item.id == request.destination_id)
            .ok_or(EgressReasonCodeV1::UnknownDestination)?;
        let purpose = policy.policy().purposes.iter()
            .find(|item| item.id == request.purpose_id && item.destination_id == request.destination_id)
            .ok_or(EgressReasonCodeV1::UnknownPurpose)?;
        let lease = self.datastore.egress_lease().map_err(|_| EgressReasonCodeV1::KillSwitch)?;
        if lease.egress_kill_switch().unwrap_or(true) {
            return Err(EgressReasonCodeV1::KillSwitch);
        }
        let response = self.transport.request(destination, purpose, &payload)?;
        if response.len() > MAX_RESPONSE_BYTES {
            return Err(EgressReasonCodeV1::InvalidPayload);
        }
        let receipt = EgressReceiptV1 {
            schema_version: 1,
            destination_id: destination.id.clone(),
            purpose_id: purpose.id.clone(),
            retention_id: purpose.retention_id.clone(),
            allowed_fields: purpose.allowed_fields.clone(),
            policy_version: policy.policy().version,
            scope: EgressApprovalScopeV1::DestinationSpecific,
            decision: EgressOutcomeV1::Allow,
            created_at: now_utc,
        };
        lease.record_egress_receipt(&receipt).map_err(|_| EgressReasonCodeV1::NetworkUnavailable)?;
        Ok((receipt, response))
    }

    fn send_locked(
        &self,
        policy: &VerifiedPolicyV1,
        approved: ApprovedEgress,
        now_utc: DateTime<Utc>,
        local_offset_seconds: i32,
    ) -> Result<EgressReceiptV1, EgressReasonCodeV1> {
        if approved.custom_endpoint.is_some() {
            return Err(EgressReasonCodeV1::ApprovalRequired);
        }
        if self.datastore.egress_kill_switch().unwrap_or(true) { return Err(EgressReasonCodeV1::KillSwitch); }
        if policy.policy().version != approved.policy_version { return Err(EgressReasonCodeV1::PolicyChanged); }
        let destination = policy.policy().destinations.iter().find(|item| item.id == approved.destination_id)
            .ok_or(EgressReasonCodeV1::UnknownDestination)?;
        let purpose = policy.policy().purposes.iter().find(|item| item.id == approved.purpose_id)
            .ok_or(EgressReasonCodeV1::UnknownPurpose)?;
        if purpose.retention_id != approved.retention_id { return Err(EgressReasonCodeV1::UnknownRetention); }
        let payload: Value = serde_json::from_slice(&approved.payload).map_err(|_| EgressReasonCodeV1::InvalidPayload)?;
        let secrets = self.datastore.get_or_create_egress_secrets().map_err(|_| EgressReasonCodeV1::InvalidPolicy)?;
        let context = EvaluationContext {
            now_utc,
            local_offset_seconds,
            alias_secret: secrets.alias_secret(),
            preview_id: &approved.preview_id,
        };
        let request = EgressRequestV1 {
            schema_version: 1,
            destination_id: approved.destination_id.clone(),
            purpose_id: approved.purpose_id.clone(),
            retention_id: approved.retention_id.clone(),
            payload,
        };
        let current = evaluate(&request, policy.policy(), &context);
        let current_bytes = current.sanitized_payload.as_ref()
            .and_then(|payload| serde_json::to_vec(payload).ok())
            .ok_or(EgressReasonCodeV1::PolicyChanged)?;
        if current.outcome != EgressOutcomeV1::Allow || current_bytes != approved.payload {
            return Err(EgressReasonCodeV1::PolicyChanged);
        }
        let payload_tag = payload_tag(secrets.approval_secret(), &approved.payload);
        let lease = self.datastore.egress_lease().map_err(|_| EgressReasonCodeV1::KillSwitch)?;
        if lease.egress_kill_switch().unwrap_or(true) { return Err(EgressReasonCodeV1::KillSwitch); }
        let stored_scope = lease.consume_egress_approval(
            &approved.approval_id,
            &approved.destination_id,
            &approved.purpose_id,
            &approved.retention_id,
            approved.policy_version,
            payload_tag,
            now_utc,
        ).map_err(|_| EgressReasonCodeV1::ApprovalExpired)?;
        if stored_scope != approved.scope { return Err(EgressReasonCodeV1::PolicyChanged); }
        if lease.egress_kill_switch().unwrap_or(true) { return Err(EgressReasonCodeV1::KillSwitch); }
        if stored_scope == EgressApprovalScopeV1::Once {
            self.previews.lock().map_err(|_| EgressReasonCodeV1::InvalidPolicy)?.remove(&approved.preview_id);
        }

        let decision = match self.transport.send(destination, purpose, &approved.payload) {
            Ok(()) => EgressOutcomeV1::Allow,
            Err(reason) => return Err(reason),
        };
        let receipt = EgressReceiptV1 {
            schema_version: 1,
            destination_id: approved.destination_id,
            purpose_id: approved.purpose_id,
            retention_id: approved.retention_id,
            allowed_fields: approved.allowed_fields,
            policy_version: approved.policy_version,
            scope: approved.scope,
            decision,
            created_at: now_utc,
        };
        lease.record_egress_receipt(&receipt).map_err(|_| EgressReasonCodeV1::NetworkUnavailable)?;
        Ok(receipt)
    }

    fn send_approval_locked(
        &self,
        policy: &VerifiedPolicyV1,
        preview_id: &str,
        approval_id: &str,
        now_utc: DateTime<Utc>,
        local_offset_seconds: i32,
    ) -> Result<EgressReceiptV1, EgressReasonCodeV1> {
        let approval = self.datastore.get_egress_approval(approval_id, now_utc)
            .map_err(|_| EgressReasonCodeV1::ApprovalExpired)?
            .ok_or(EgressReasonCodeV1::ApprovalExpired)?;
        let preview = self.previews.lock().map_err(|_| EgressReasonCodeV1::InvalidPolicy)?
            .get(preview_id).cloned().ok_or(EgressReasonCodeV1::ApprovalExpired)?;
        if now_utc >= preview.created_at + PREVIEW_LIFETIME
            || preview.policy_version != policy.policy().version
            || &preview.policy_snapshot != policy.policy()
            || approval.policy_version != policy.policy().version
            || preview.destination_id != approval.destination_id
            || preview.purpose_id != approval.purpose_id
            || preview.retention_id != approval.retention_id
            || (preview.custom_endpoint.is_some() && preview.ai_feature.is_none())
        {
            return Err(EgressReasonCodeV1::PolicyChanged);
        }
        self.send_locked(policy, ApprovedEgress {
            approval_id: approval.approval_id,
            preview_id: preview.preview_id,
            destination_id: preview.destination_id,
            purpose_id: preview.purpose_id,
            retention_id: preview.retention_id,
            policy_version: preview.policy_version,
            scope: approval.scope,
            allowed_fields: preview.allowed_fields,
            payload: preview.payload,
            custom_endpoint: preview.custom_endpoint,
        }, now_utc, local_offset_seconds)
    }
}

impl EgressSendGuard<'_> {
    pub fn approve(
        &self,
        policy: &VerifiedPolicyV1,
        preview_id: &str,
        scope: EgressApprovalScopeV1,
        expires_at: Option<DateTime<Utc>>,
        now_utc: DateTime<Utc>,
        local_offset_seconds: i32,
    ) -> Result<ApprovedEgress, EgressReasonCodeV1> {
        self.proxy.approve_locked(policy, preview_id, scope, expires_at, now_utc, local_offset_seconds)
    }

    pub fn send(
        &self,
        policy: &VerifiedPolicyV1,
        approved: ApprovedEgress,
        now_utc: DateTime<Utc>,
        local_offset_seconds: i32,
    ) -> Result<EgressReceiptV1, EgressReasonCodeV1> {
        self.proxy.send_locked(policy, approved, now_utc, local_offset_seconds)
    }

    pub fn send_approval(
        &self,
        policy: &VerifiedPolicyV1,
        preview_id: &str,
        approval_id: &str,
        now_utc: DateTime<Utc>,
        local_offset_seconds: i32,
    ) -> Result<EgressReceiptV1, EgressReasonCodeV1> {
        self.proxy.send_approval_locked(policy, preview_id, approval_id, now_utc, local_offset_seconds)
    }
}

fn denied(policy_version: u64, preview_id: &str, reason: EgressReasonCodeV1) -> EgressDecisionV1 {
    EgressDecisionV1 {
        schema_version: 1,
        outcome: EgressOutcomeV1::Deny,
        sanitized_payload: None,
        removed_fields: Vec::new(),
        reason_codes: vec![reason],
        policy_version,
        preview_id: preview_id.to_string(),
    }
}

fn random_id() -> Result<String, ()> {
    let mut bytes = [0_u8; 32];
    SystemRandom::new().fill(&mut bytes).map_err(|_| ())?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn payload_tag(secret: &[u8], payload: &[u8]) -> [u8; 32] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let tag = hmac::sign(&key, payload);
    let mut output = [0_u8; 32];
    output.copy_from_slice(tag.as_ref());
    output
}

impl EgressTransport for ReqwestTransport {
    fn send(
        &self,
        destination: &EgressDestinationV1,
        purpose: &EgressPurposeV1,
        payload: &[u8],
    ) -> Result<(), EgressReasonCodeV1> {
        self.post(destination, purpose, payload, false).map(|_| ())
    }

    fn request(
        &self,
        destination: &EgressDestinationV1,
        purpose: &EgressPurposeV1,
        payload: &[u8],
    ) -> Result<Vec<u8>, EgressReasonCodeV1> {
        self.post(destination, purpose, payload, true).map(Option::unwrap_or_default)
    }

    fn test_connection(
        &self,
        profile: &AIEndpointProfileV1,
    ) -> Result<(u16, Vec<String>), EgressReasonCodeV1> {
        let (host, port, resolved) = super::ai::resolve_addresses(profile)?;
        let pins = resolved.iter().map(ToString::to_string).collect::<Vec<_>>();
        let address_set = resolved.iter().map(|ip| SocketAddr::new(*ip, port)).collect::<Vec<_>>();
        let base = Url::parse(&profile.origin).map_err(|_| EgressReasonCodeV1::DestinationRejected)?;
        let target = base.join(&profile.endpoint_path).map_err(|_| EgressReasonCodeV1::DestinationRejected)?;
        if target.origin() != base.origin() || target.path() != profile.endpoint_path {
            return Err(EgressReasonCodeV1::DestinationRejected);
        }
        let client = Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(Policy::none())
            .connect_timeout(StdDuration::from_secs(5))
            .timeout(StdDuration::from_secs(5))
            .resolve_to_addrs(&host, &address_set)
            .build()
            .map_err(|_| EgressReasonCodeV1::NetworkUnavailable)?;
        let response = client.head(target).send().map_err(|_| EgressReasonCodeV1::NetworkUnavailable)?;
        if response.status().is_redirection() { return Err(EgressReasonCodeV1::RedirectRejected); }
        Ok((response.status().as_u16(), pins))
    }

    fn request_custom_ai(
        &self,
        profile: &AIEndpointProfileV1,
        purpose: &EgressPurposeV1,
        payload: &[u8],
        bearer_credential: Option<&str>,
    ) -> Result<Vec<u8>, EgressReasonCodeV1> {
        if payload.len() > MAX_PAYLOAD_BYTES || purpose.id != "ai.custom_endpoint"
            || purpose.endpoint_path != profile.endpoint_path
        {
            return Err(EgressReasonCodeV1::InvalidPayload);
        }
        let base = Url::parse(&profile.origin).map_err(|_| EgressReasonCodeV1::DestinationRejected)?;
        let target = base.join(&profile.endpoint_path).map_err(|_| EgressReasonCodeV1::DestinationRejected)?;
        if target.origin() != base.origin() || target.path() != profile.endpoint_path {
            return Err(EgressReasonCodeV1::DestinationRejected);
        }
        let host = base.host_str().ok_or(EgressReasonCodeV1::DestinationRejected)?;
        let addresses = super::ai::resolve_pinned_addresses(profile)?;
        let client = Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(Policy::none())
            .connect_timeout(StdDuration::from_secs(5))
            .timeout(StdDuration::from_secs(30))
            .resolve_to_addrs(host, &addresses)
            .build()
            .map_err(|_| EgressReasonCodeV1::NetworkUnavailable)?;
        let mut request = client.post(target)
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, "application/json");
        if let Some(secret) = bearer_credential {
            let bearer = Zeroizing::new(format!("Bearer {secret}"));
            let mut authorization = HeaderValue::from_bytes(bearer.as_bytes())
                .map_err(|_| EgressReasonCodeV1::InvalidPayload)?;
            authorization.set_sensitive(true);
            request = request.header(AUTHORIZATION, authorization);
        }
        let response = request.body(payload.to_vec()).send()
            .map_err(|_| EgressReasonCodeV1::NetworkUnavailable)?;
        if response.status().is_redirection() { return Err(EgressReasonCodeV1::RedirectRejected); }
        if !response.status().is_success() { return Err(EgressReasonCodeV1::DestinationRejected); }
        if response.content_length().is_some_and(|length| length > MAX_AI_RESPONSE_BYTES as u64) {
            return Err(EgressReasonCodeV1::InvalidPayload);
        }
        let mut body = Vec::new();
        response.take((MAX_AI_RESPONSE_BYTES + 1) as u64).read_to_end(&mut body)
            .map_err(|_| EgressReasonCodeV1::NetworkUnavailable)?;
        if body.len() > MAX_AI_RESPONSE_BYTES { return Err(EgressReasonCodeV1::InvalidPayload); }
        Ok(body)
    }
}

impl ReqwestTransport {
    fn post(
        &self,
        destination: &EgressDestinationV1,
        purpose: &EgressPurposeV1,
        payload: &[u8],
        capture_response: bool,
    ) -> Result<Option<Vec<u8>>, EgressReasonCodeV1> {
        let max_payload_bytes = if capture_response { MAX_SYNC_PAYLOAD_BYTES } else { MAX_PAYLOAD_BYTES };
        if payload.len() > max_payload_bytes { return Err(EgressReasonCodeV1::InvalidPayload); }
        let origin = destination.https_origin.as_deref().ok_or(EgressReasonCodeV1::DestinationRejected)?;
        let base = Url::parse(origin).map_err(|_| EgressReasonCodeV1::DestinationRejected)?;
        let target = base.join(&purpose.endpoint_path).map_err(|_| EgressReasonCodeV1::DestinationRejected)?;
        if target.origin() != base.origin() || target.path() != purpose.endpoint_path {
            return Err(EgressReasonCodeV1::DestinationRejected);
        }
        let host = base.host_str().ok_or(EgressReasonCodeV1::DestinationRejected)?;
        let port = base.port_or_known_default().ok_or(EgressReasonCodeV1::DestinationRejected)?;
        let addresses = resolve_public_addresses(host, port)?;
        let client = Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(Policy::none())
            .connect_timeout(StdDuration::from_secs(5))
            .timeout(StdDuration::from_secs(15))
            .resolve_to_addrs(host, &addresses)
            .build()
            .map_err(|_| EgressReasonCodeV1::NetworkUnavailable)?;
        let response = client.post(target)
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, "application/json")
            .body(payload.to_vec())
            .send()
            .map_err(|_| EgressReasonCodeV1::NetworkUnavailable)?;
        if response.status().is_redirection() { return Err(EgressReasonCodeV1::RedirectRejected); }
        if !response.status().is_success() { return Err(EgressReasonCodeV1::DestinationRejected); }
        if !capture_response { return Ok(None); }
        if response.content_length().is_some_and(|length| length > MAX_RESPONSE_BYTES as u64) {
            return Err(EgressReasonCodeV1::InvalidPayload);
        }
        let mut body = Vec::new();
        response.take((MAX_RESPONSE_BYTES + 1) as u64).read_to_end(&mut body)
            .map_err(|_| EgressReasonCodeV1::NetworkUnavailable)?;
        if body.len() > MAX_RESPONSE_BYTES { return Err(EgressReasonCodeV1::InvalidPayload); }
        Ok(Some(body))
    }
}

fn evaluate_preview_payload(
    preview: &Preview,
    policy: &EgressPolicyV1,
    context: &EvaluationContext<'_>,
) -> Result<EgressDecisionV1, EgressReasonCodeV1> {
    let payload = match &preview.policy_payload {
        Some(bytes) if preview.ai_feature.is_some() => serde_json::from_slice(bytes)
            .map_err(|_| EgressReasonCodeV1::InvalidPayload)?,
        Some(_) => return Err(EgressReasonCodeV1::InvalidPayload),
        None if preview.ai_feature.is_none() => serde_json::from_slice(&preview.payload)
            .map_err(|_| EgressReasonCodeV1::InvalidPayload)?,
        None => return Err(EgressReasonCodeV1::InvalidPayload),
    };
    let request = EgressRequestV1 {
        schema_version: 1,
        destination_id: preview.destination_id.clone(),
        purpose_id: preview.purpose_id.clone(),
        retention_id: preview.retention_id.clone(),
        payload,
    };
    let mut decision = evaluate(&request, policy, context);
    if decision.outcome != EgressOutcomeV1::Allow { return Ok(decision); }
    if let Some(feature) = preview.ai_feature {
        let profile = preview.custom_endpoint.as_ref().ok_or(EgressReasonCodeV1::PolicyChanged)?;
        let sanitized = decision.sanitized_payload.as_ref().ok_or(EgressReasonCodeV1::PolicyChanged)?;
        decision.sanitized_payload = Some(render_custom_ai_payload(profile, feature, sanitized)?);
    }
    Ok(decision)
}

fn render_custom_ai_payload(
    profile: &AIEndpointProfileV1,
    feature: AIRequestFeatureV1,
    source: &Value,
) -> Result<Value, EgressReasonCodeV1> {
    let question = source.get("question").and_then(Value::as_str)
        .ok_or(EgressReasonCodeV1::InvalidPayload)?;
    let aggregate = source.get("aggregate").filter(|value| value.is_object())
        .ok_or(EgressReasonCodeV1::InvalidPayload)?;
    let feature_label = match feature {
        AIRequestFeatureV1::QuestionAnswer => "Question and answer",
        AIRequestFeatureV1::ReportExplanation => "Report explanation",
        AIRequestFeatureV1::CategorySuggestion => "Category suggestion",
        AIRequestFeatureV1::FreelancerDraft => "Freelancer draft wording",
        AIRequestFeatureV1::PatternComparison => "Pattern comparison",
    };
    let aggregate = serde_json::to_string(aggregate).map_err(|_| EgressReasonCodeV1::InvalidPayload)?;
    Ok(serde_json::json!({
        "model": profile.model_id,
        "messages": [{
            "role": "user",
            "content": format!("Feature: {feature_label}\nQuestion: {question}\n\nApproved aggregate JSON:\n{aggregate}"),
        }],
        "stream": false,
        "max_tokens": 1024,
    }))
}

fn validate_custom_ai_source(
    profile: &AIEndpointProfileV1,
    feature: AIRequestFeatureV1,
    source: &Value,
) -> Result<(), EgressReasonCodeV1> {
    let object = source.as_object().ok_or(EgressReasonCodeV1::InvalidPayload)?;
    if object.len() != 2 { return Err(EgressReasonCodeV1::InvalidPayload); }
    let question = source.get("question").and_then(Value::as_str)
        .ok_or(EgressReasonCodeV1::InvalidPayload)?;
    let aggregate = source.get("aggregate").ok_or(EgressReasonCodeV1::InvalidPayload)?;
    AIUserRequestV1 {
        schema_version: 1,
        profile_id: profile.profile_id.clone(),
        feature,
        question: question.to_string(),
        aggregate: aggregate.clone(),
    }.validate().map_err(|_| EgressReasonCodeV1::InvalidPayload)
}

pub(super) fn resolve_public_addresses(host: &str, port: u16) -> Result<Vec<SocketAddr>, EgressReasonCodeV1> {
    let lowered = host.to_ascii_lowercase();
    if !lowered.contains('.') || lowered == "localhost" || lowered.ends_with(".localhost")
        || lowered.ends_with(".local") || lowered.ends_with(".internal")
        || lowered.ends_with(".test") || lowered.ends_with(".example") || lowered.ends_with(".invalid")
    {
        return Err(EgressReasonCodeV1::DestinationRejected);
    }
    let addresses: Vec<SocketAddr> = (host, port).to_socket_addrs()
        .map_err(|_| EgressReasonCodeV1::NetworkUnavailable)?.collect();
    if addresses.is_empty() || addresses.iter().any(|address| !is_public_ip(address.ip())) {
        return Err(EgressReasonCodeV1::DestinationRejected);
    }
    Ok(addresses)
}

pub(super) fn is_public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(ip.is_private() || ip.is_loopback() || ip.is_link_local() || ip.is_broadcast() || ip.is_unspecified()
                || a == 0 || a >= 224
                || (a == 100 && (64..=127).contains(&b))
                || (a == 192 && b == 0)
                || (a == 192 && b == 88 && c == 99)
                || (a == 198 && (b == 18 || b == 19))
                || (a == 198 && b == 51 && c == 100)
                || (a == 203 && b == 0 && c == 113))
        }
        IpAddr::V6(ip) => {
            let octets = ip.octets();
            let second_hextet = u16::from_be_bytes([octets[2], octets[3]]);
            (octets[0] & 0xe0) == 0x20
                && !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast()
                && !ip.is_unique_local() && !ip.is_unicast_link_local()
                && !(octets[0] == 0x20 && octets[1] == 0x01 && second_hextet <= 0x01ff)
                && !(octets[0] == 0x20 && octets[1] == 0x01 && octets[2] == 0x0d && octets[3] == 0xb8)
                && !(octets[0] == 0x3f && octets[1] == 0xff && second_hextet <= 0x0fff)
                && ip.to_ipv4().is_none_or(|ipv4| is_public_ip(IpAddr::V4(ipv4)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aw_models::{AIAuthenticationV1, AIEndpointProtocolV1, AIDestinationTypeV1, EgressDestinationStatusV1};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct ProbeTransport(Arc<AtomicUsize>);

    impl EgressTransport for ProbeTransport {
        fn send(
            &self,
            _: &EgressDestinationV1,
            _: &EgressPurposeV1,
            _: &[u8],
        ) -> Result<(), EgressReasonCodeV1> {
            Ok(())
        }

        fn test_connection(
            &self,
            _: &AIEndpointProfileV1,
        ) -> Result<(u16, Vec<String>), EgressReasonCodeV1> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok((204, vec!["8.8.8.8".into()]))
        }
    }

    struct AITransport {
        body: Arc<Mutex<Vec<u8>>>,
        auth: Arc<Mutex<Option<String>>>,
    }

    impl EgressTransport for AITransport {
        fn send(
            &self,
            _: &EgressDestinationV1,
            _: &EgressPurposeV1,
            _: &[u8],
        ) -> Result<(), EgressReasonCodeV1> {
            Err(EgressReasonCodeV1::DestinationRejected)
        }

        fn request_custom_ai(
            &self,
            _: &AIEndpointProfileV1,
            _: &EgressPurposeV1,
            payload: &[u8],
            bearer: Option<&str>,
        ) -> Result<Vec<u8>, EgressReasonCodeV1> {
            *self.body.lock().unwrap() = payload.to_vec();
            *self.auth.lock().unwrap() = bearer.map(str::to_string);
            Ok(br#"{"choices":[{"message":{"content":"Synthetic result"}}]}"#.to_vec())
        }
    }

    fn custom_endpoint_policy() -> VerifiedPolicyV1 {
        VerifiedPolicyV1 {
            policy: EgressPolicyV1 {
                schema_version: 1,
                version: 3,
                hard_deny_version: 1,
                destinations: vec![EgressDestinationV1 {
                    id: "custom-endpoint".into(),
                    status: EgressDestinationStatusV1::Planned,
                    https_origin: None,
                    allowed_purposes: vec!["ai.custom_endpoint".into()],
                }],
                purposes: vec![EgressPurposeV1 {
                    id: "ai.custom_endpoint".into(),
                    destination_id: "custom-endpoint".into(),
                    endpoint_path: "/v1/chat/completions".into(),
                    retention_id: "user-defined".into(),
                    retention_disclosure: "User disclosure is not verified".into(),
                    allowed_fields: vec![
                        "/question".into(), "/aggregate".into(),
                        "/model".into(), "/messages/*/role".into(),
                        "/messages/*/content".into(), "/stream".into(),
                    ],
                }],
                organization_rules: Vec::new(),
                user_rules: Vec::new(),
                safe_zone_patterns: Vec::new(),
                after_hours: None,
            },
            custom_endpoint: None,
        }
    }

    fn custom_endpoint_profile() -> AIEndpointProfileV1 {
        AIEndpointProfileV1 {
            profile_id: "profile_01".into(),
            display_name: "Synthetic endpoint".into(),
            origin: "https://ai.example.invalid".into(),
            endpoint_path: "/v1/chat/completions".into(),
            protocol: AIEndpointProtocolV1::OpenAiChatCompletionsV1,
            authentication: AIAuthenticationV1::Bearer,
            model_id: "synthetic-model".into(),
            destination_type: AIDestinationTypeV1::Remote,
            region_note: "Not verified".into(),
            retention_note: "Not verified".into(),
            training_note: "Not verified".into(),
            cost_note: None,
            credential_ref: Some("credential_01".into()),
            resolved_addresses: vec!["8.8.8.8".into()],
        }
    }

    #[test]
    fn egress_destination_ip_filter_rejects_local_and_reserved_ranges() {
        for address in ["127.0.0.1", "10.0.0.1", "192.168.1.2", "169.254.10.20", "100.64.0.1", "198.51.100.5", "::1", "fc00::1", "fe80::1", "2001:db8::1", "2001:2::1", "2001:10::1", "3fff::1"] {
            assert!(!is_public_ip(address.parse().unwrap()), "{address}");
        }
        for address in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"] {
            assert!(is_public_ip(address.parse().unwrap()), "{address}");
        }
    }

    #[test]
    fn destination_resolution_rejects_local_and_test_names_before_connecting() {
        assert_eq!(resolve_public_addresses("localhost", 443), Err(EgressReasonCodeV1::DestinationRejected));
        assert_eq!(resolve_public_addresses("relay.example.test", 443), Err(EgressReasonCodeV1::DestinationRejected));
    }

    #[test]
    fn policy_update_waits_for_a_send_guard() {
        let proxy = EgressProxy::new(Datastore::new_in_memory(false));
        let send_guard = proxy.begin_send().unwrap();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();
        let updater = proxy.clone();
        let thread = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            updater.with_policy_update(|| ()).unwrap();
            finished_tx.send(()).unwrap();
        });

        started_rx.recv_timeout(StdDuration::from_secs(1)).unwrap();
        assert!(finished_rx.recv_timeout(StdDuration::from_millis(25)).is_err());
        drop(send_guard);
        finished_rx.recv_timeout(StdDuration::from_secs(1)).unwrap();
        thread.join().unwrap();
    }

    #[test]
    fn explicit_custom_endpoint_probe_obeys_the_kill_switch_and_records_no_payload() {
        let store = Datastore::new_in_memory(true);
        let probes = Arc::new(AtomicUsize::new(0));
        let proxy = EgressProxy::with_transport(store, ProbeTransport(probes.clone()));
        let policy = custom_endpoint_policy();
        let profile = custom_endpoint_profile();

        assert_eq!(
            proxy.test_custom_endpoint(&policy, &profile, Utc::now()),
            Err(EgressReasonCodeV1::KillSwitch),
        );
        assert_eq!(probes.load(Ordering::SeqCst), 0);

        proxy.set_kill_switch(false).unwrap();
        assert_eq!(proxy.test_custom_endpoint(&policy, &profile, Utc::now()).unwrap().0, 204);
        assert_eq!(probes.load(Ordering::SeqCst), 1);
        let receipts = proxy.datastore.get_egress_receipts(10).unwrap();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].decision, EgressOutcomeV1::Allow);
        assert!(receipts[0].allowed_fields.is_empty());
    }

    #[test]
    fn approved_custom_ai_sends_exact_preview_bytes_and_keeps_secret_out_of_receipt() {
        let store = Datastore::new_in_memory(true);
        let request_body = Arc::new(Mutex::new(Vec::new()));
        let sent_auth = Arc::new(Mutex::new(None));
        let proxy = EgressProxy::with_transport(store, AITransport {
            body: request_body.clone(),
            auth: sent_auth.clone(),
        });
        proxy.set_kill_switch(false).unwrap();
        let profile = custom_endpoint_profile();
        let policy = custom_endpoint_policy().for_custom_endpoint(&profile).unwrap();
        let destination = policy.policy().destinations.iter()
            .find(|item| item.status == EgressDestinationStatusV1::Experimental).unwrap();
        let request = EgressRequestV1 {
            schema_version: 1,
            destination_id: destination.id.clone(),
            purpose_id: "ai.custom_endpoint".into(),
            retention_id: "user-defined".into(),
            payload: serde_json::json!({
                "question": "Explain the Work aggregate",
                "aggregate": {
                    "method_id":"local-work-report", "method_version":1, "break_time_seconds":300,
                    "date_range":{"start_date":"2026-09-01","end_date":"2026-09-01"},
                    "daily":[],
                    "coverage":{"requested_periods":1,"periods_with_data":1,"limitation":"complete"},
                    "weekly":[], "monthly":[], "comparison":null
                }
            }),
        };
        let now = Utc::now();
        let preview = proxy.preview_custom_ai(&policy, request, AIRequestFeatureV1::ReportExplanation, now, 0);
        assert_eq!(preview.outcome, EgressOutcomeV1::Allow);
        let approved = proxy.approve(&policy, &preview.preview_id, EgressApprovalScopeV1::Once, Some(now + Duration::minutes(5)), now, 0).unwrap();
        assert_eq!(
            proxy.send_custom_ai_approval(&policy, &profile, &preview.preview_id, approved.approval_id(), None, now, 0),
            Err(EgressReasonCodeV1::InvalidPayload),
        );
        assert!(request_body.lock().unwrap().is_empty());
        assert!(sent_auth.lock().unwrap().is_none());
        let (receipt, response) = proxy.send_custom_ai_approval(
            &policy, &profile, &preview.preview_id, approved.approval_id(),
            Some("synthetic-bearer-secret"), now, 0,
        ).unwrap();
        let expected_body = serde_json::to_vec(&preview.sanitized_payload.unwrap()).unwrap();
        assert_eq!(request_body.lock().unwrap().as_slice(), expected_body.as_slice());
        assert_eq!(sent_auth.lock().unwrap().as_deref(), Some("synthetic-bearer-secret"));
        assert!(String::from_utf8(response).unwrap().contains("Synthetic result"));
        let receipt = serde_json::to_string(&receipt).unwrap();
        assert!(!receipt.contains("synthetic-bearer-secret"));
        assert!(!receipt.contains("ai.example.invalid"));
    }

    #[test]
    fn custom_ai_filters_nested_source_fields_before_prompt_serialization() {
        let store = Datastore::new_in_memory(true);
        let request_body = Arc::new(Mutex::new(Vec::new()));
        let sent_auth = Arc::new(Mutex::new(None));
        let proxy = EgressProxy::with_transport(store, AITransport {
            body: request_body.clone(),
            auth: sent_auth,
        });
        proxy.set_kill_switch(false).unwrap();
        let profile = custom_endpoint_profile();
        let mut template = custom_endpoint_policy();
        template.policy.user_rules.push(aw_models::EgressRuleV1 {
            pattern: aw_models::EgressPatternV1 {
                kind: aw_models::EgressMatchKindV1::Field,
                value: "/aggregate/coverage/limitation".into(),
            },
            action: aw_models::EgressRuleActionV1::DropField,
        });
        let policy = template.for_custom_endpoint(&profile).unwrap();
        let destination_id = policy.custom_endpoint_destination_id().unwrap();
        let request = EgressRequestV1 {
            schema_version: 1,
            destination_id,
            purpose_id: "ai.custom_endpoint".into(),
            retention_id: "user-defined".into(),
            payload: serde_json::json!({
                "question": "Summarize this report",
                "aggregate": {
                    "method_id":"local-work-report", "method_version":1, "break_time_seconds":300,
                    "date_range":{"start_date":"2026-09-01","end_date":"2026-09-07"},
                    "daily":[],
                    "coverage":{"requested_periods":7,"periods_with_data":2,"limitation":"private note"},
                    "weekly":[], "monthly":[], "comparison":null
                }
            }),
        };
        let now = Utc::now();
        let preview = proxy.preview_custom_ai(&policy, request, AIRequestFeatureV1::ReportExplanation, now, 0);
        assert_eq!(preview.outcome, EgressOutcomeV1::Allow);
        assert!(preview.removed_fields.contains(&"/aggregate/coverage/limitation".to_string()));
        let payload = serde_json::to_string(preview.sanitized_payload.as_ref().unwrap()).unwrap();
        assert!(!payload.contains("private note"));
        let approved = proxy.approve(&policy, &preview.preview_id, EgressApprovalScopeV1::Once, Some(now + Duration::minutes(5)), now, 0).unwrap();
        proxy.send_custom_ai_approval(
            &policy, &profile, &preview.preview_id, approved.approval_id(),
            Some("synthetic-bearer-secret"), now, 0,
        ).unwrap();
        assert_eq!(request_body.lock().unwrap().as_slice(), serde_json::to_vec(preview.sanitized_payload.as_ref().unwrap()).unwrap());
    }

    #[test]
    fn custom_ai_approval_rejects_a_same_version_policy_change_even_when_payload_is_unchanged() {
        let store = Datastore::new_in_memory(true);
        let proxy = EgressProxy::with_transport(store, AITransport {
            body: Arc::new(Mutex::new(Vec::new())),
            auth: Arc::new(Mutex::new(None)),
        });
        proxy.set_kill_switch(false).unwrap();
        let profile = custom_endpoint_profile();
        let policy = custom_endpoint_policy().for_custom_endpoint(&profile).unwrap();
        let request = EgressRequestV1 {
            schema_version: 1,
            destination_id: policy.custom_endpoint_destination_id().unwrap(),
            purpose_id: "ai.custom_endpoint".into(),
            retention_id: "user-defined".into(),
            payload: serde_json::json!({
                "question":"Explain this report",
                "aggregate":{
                    "method_id":"local-work-report", "method_version":1, "break_time_seconds":300,
                    "date_range":{"start_date":"2026-09-01","end_date":"2026-09-01"},
                    "daily":[], "coverage":{"requested_periods":1,"periods_with_data":1,"limitation":"complete"},
                    "weekly":[], "monthly":[], "comparison":null
                }
            }),
        };
        let now = Utc::now();
        let preview = proxy.preview_custom_ai(&policy, request, AIRequestFeatureV1::ReportExplanation, now, 0);
        assert_eq!(preview.outcome, EgressOutcomeV1::Allow);
        let mut changed_policy = policy.clone();
        changed_policy.policy.user_rules.push(aw_models::EgressRuleV1 {
            pattern: aw_models::EgressPatternV1 {
                kind: aw_models::EgressMatchKindV1::Field,
                value: "/aggregate/daily/0/private".into(),
            },
            action: aw_models::EgressRuleActionV1::DropField,
        });
        assert!(matches!(
            proxy.approve(&changed_policy, &preview.preview_id, EgressApprovalScopeV1::Once, None, now, 0),
            Err(EgressReasonCodeV1::PolicyChanged),
        ));
    }
}
