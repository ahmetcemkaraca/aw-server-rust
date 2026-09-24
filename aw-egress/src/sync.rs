use aw_models::{EgressReasonCodeV1, EgressRequestV1};
use aw_models::SYNC_EGRESS_PURPOSE_V1;
use aw_sync_e2ee::{
    SyncObjectStoreErrorV1, SyncRelayRequestV1, SyncRelayResponseV1,
    SyncRelayOperationV1, SyncRelayTransportV1,
};
use chrono::Utc;
use serde_json::Value;

use crate::{EgressProxy, VerifiedPolicyV1};

/// Sync relay transport that resolves every request through a verified signed
/// destination and purpose. It has no URL or general HTTP client input.
#[derive(Clone)]
pub struct EgressSyncRelayTransportV1 {
    proxy: EgressProxy,
    policy: VerifiedPolicyV1,
}

impl EgressSyncRelayTransportV1 {
    pub fn new(proxy: EgressProxy, policy: VerifiedPolicyV1) -> Self {
        Self { proxy, policy }
    }
}

impl SyncRelayTransportV1 for EgressSyncRelayTransportV1 {
    fn request(
        &self,
        destination_id: &str,
        purpose_id: &str,
        request: &SyncRelayRequestV1,
    ) -> Result<SyncRelayResponseV1, SyncObjectStoreErrorV1> {
        request.validate().map_err(|_| SyncObjectStoreErrorV1::InvalidEnvelope)?;
        if purpose_id != SYNC_EGRESS_PURPOSE_V1 {
            return Err(SyncObjectStoreErrorV1::PolicyDenied);
        }
        if request.operation == SyncRelayOperationV1::PutIfAbsent {
            self.proxy.validate_sync_envelope(request.envelope.as_ref().ok_or(SyncObjectStoreErrorV1::InvalidEnvelope)?)
                .map_err(|_| SyncObjectStoreErrorV1::InvalidEnvelope)?;
        }
        let purpose = self.policy.policy().purposes.iter()
            .find(|purpose| purpose.id == purpose_id && purpose.destination_id == destination_id)
            .ok_or(SyncObjectStoreErrorV1::PolicyDenied)?;
        let payload: Value = serde_json::to_value(request)
            .map_err(|_| SyncObjectStoreErrorV1::InvalidEnvelope)?;
        let egress_request = EgressRequestV1 {
            schema_version: 1,
            destination_id: destination_id.into(),
            purpose_id: purpose_id.into(),
            retention_id: purpose.retention_id.clone(),
            payload,
        };
        let (_, response) = self.proxy.send_sync_request(
            &self.policy,
            egress_request,
            Utc::now(),
            chrono::Local::now().offset().local_minus_utc(),
        ).map_err(|reason| match reason {
            EgressReasonCodeV1::NetworkUnavailable => SyncObjectStoreErrorV1::TransportUnavailable,
            _ => SyncObjectStoreErrorV1::PolicyDenied,
        })?;
        serde_json::from_slice(&response).map_err(|_| SyncObjectStoreErrorV1::CorruptObject)
    }
}
