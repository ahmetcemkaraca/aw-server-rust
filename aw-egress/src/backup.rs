use aw_models::{
    EgressPolicyV1, EgressReasonCodeV1, SyncEnvelopeV1, SyncRelayOperationV1, SyncRelayRequestV1,
    SyncRelayResponseV1,
};
use aw_sync_e2ee::{
    decrypt_snapshot, EncryptedSyncSnapshotV1, SnapshotIndexBuilderV1, VaultDataKeyV1,
    MAX_BACKUP_BUNDLE_BYTES, MAX_BACKUP_SCAN_OBJECTS,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::{collections::BTreeMap, sync::Arc};

#[derive(Clone, Copy, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum BackupTransferDirectionV1 {
    Upload,
    Download,
}

#[derive(Clone, Serialize)]
pub struct BackupScopeV1 {
    source_id: String,
    vault_id: String,
    key_epoch: u64,
    kind: BackupScopeKind,
}

#[derive(Clone, Serialize)]
enum BackupScopeKind {
    Discovery,
    CleanupDiscovery,
    SelectedDeletion {
        snapshot_id: String,
        bundle_sha256: String,
        objects: BTreeMap<String, [u8; 32]>,
        #[serde(skip)]
        sample: SyncEnvelopeV1,
    },
    Selected {
        snapshot_id: String,
        bundle_sha256: String,
        direction: BackupTransferDirectionV1,
        objects: BTreeMap<String, [u8; 32]>,
        #[serde(skip)]
        sample: SyncEnvelopeV1,
    },
}

#[derive(Clone)]
pub struct BackupEgressPreviewV1 {
    pub(crate) scope: Arc<BackupScopeV1>,
    pub(crate) policy: EgressPolicyV1,
    pub(crate) context_id: String,
    pub(crate) destination_id: String,
    pub(crate) retention_id: String,
    pub(crate) retention_disclosure: String,
    pub(crate) preview_id: String,
    pub(crate) created_at: DateTime<Utc>,
    pub(crate) expires_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct ReviewedBackupPermitV1 {
    pub(crate) preview: BackupEgressPreviewV1,
    pub(crate) approval_id: String,
}

impl BackupEgressPreviewV1 {
    pub fn matches_scope(&self, scope: &BackupScopeV1) -> bool {
        serde_json::to_value(self.scope.as_ref()).ok() == serde_json::to_value(scope).ok()
    }
    pub fn preview_id(&self) -> &str {
        &self.preview_id
    }
    pub fn metadata(&self) -> serde_json::Value {
        let (operation, snapshot_id, bundle_sha256, count) = match &self.scope.kind {
            BackupScopeKind::Discovery => ("list", None, None, 0),
            BackupScopeKind::CleanupDiscovery => ("cleanup_list", None, None, 0),
            BackupScopeKind::SelectedDeletion {
                snapshot_id,
                bundle_sha256,
                objects,
                ..
            } => (
                "delete",
                Some(snapshot_id),
                Some(bundle_sha256),
                objects.len(),
            ),
            BackupScopeKind::Selected {
                snapshot_id,
                bundle_sha256,
                objects,
                direction,
                ..
            } => (
                if *direction == BackupTransferDirectionV1::Upload {
                    "upload"
                } else {
                    "download"
                },
                Some(snapshot_id),
                Some(bundle_sha256),
                objects.len(),
            ),
        };
        serde_json::json!({"schema_version":1,"preview_id":self.preview_id,"context_id":self.context_id,
            "source_id":self.scope.source_id,"destination_id":self.destination_id,"purpose_id":aw_models::SYNC_EGRESS_PURPOSE_V1,
            "retention_id":self.retention_id,"retention_disclosure":self.retention_disclosure,
            "policy_version":self.policy.version.to_string(),"vault_id":self.scope.vault_id,"key_epoch":self.scope.key_epoch.to_string(),
            "operation":operation,"snapshot_id":snapshot_id,"bundle_sha256":bundle_sha256,"object_count":count,"expires_at":self.expires_at.to_rfc3339()})
    }
    pub(crate) fn scope_bytes(&self) -> Result<Vec<u8>, EgressReasonCodeV1> {
        let mut bytes = b"PeakActivity-Backup-Approval-v1\0".to_vec();
        bytes.extend(serde_json::to_vec(&serde_json::json!({"scope":self.scope.as_ref(),"policy":self.policy,"context_id":self.context_id,
            "destination_id":self.destination_id,"retention_id":self.retention_id,"preview_id":self.preview_id,
            "created_at":self.created_at,"expires_at":self.expires_at})).map_err(|_|EgressReasonCodeV1::InvalidPayload)?);
        Ok(bytes)
    }
}

impl ReviewedBackupPermitV1 {
    pub fn approval_id(&self) -> &str {
        &self.approval_id
    }
    pub(crate) fn validate_response(
        &self,
        request: &SyncRelayRequestV1,
        bytes: &[u8],
    ) -> Result<(), EgressReasonCodeV1> {
        let response: SyncRelayResponseV1 =
            serde_json::from_slice(bytes).map_err(|_| EgressReasonCodeV1::InvalidPayload)?;
        response
            .validate_for(request)
            .map_err(|_| EgressReasonCodeV1::InvalidPayload)?;
        if let Some(envelope) = &response.envelope {
            let BackupScopeKind::Selected { objects, .. } = &self.preview.scope.kind else {
                return Err(EgressReasonCodeV1::InvalidPayload);
            };
            if envelope.vault_id != self.preview.scope.vault_id
                || envelope.key_epoch != self.preview.scope.key_epoch
                || objects.get(&envelope.object_id) != Some(&object_digest(envelope)?)
            {
                return Err(EgressReasonCodeV1::InvalidPayload);
            }
        }
        Ok(())
    }
}

pub(crate) fn object_digest(object: &SyncEnvelopeV1) -> Result<[u8; 32], EgressReasonCodeV1> {
    let bytes = serde_json::to_vec(object).map_err(|_| EgressReasonCodeV1::InvalidPayload)?;
    Ok(ring::digest::digest(&ring::digest::SHA256, &bytes)
        .as_ref()
        .try_into()
        .unwrap())
}

impl BackupScopeV1 {
    pub fn discovery(key: &VaultDataKeyV1, source_id: &str) -> Result<Self, EgressReasonCodeV1> {
        if source_id.is_empty()
            || source_id.len() > 128
            || !source_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        {
            return Err(EgressReasonCodeV1::InvalidPayload);
        }
        Ok(Self {
            source_id: source_id.into(),
            vault_id: URL_SAFE_NO_PAD.encode(key.vault_id()),
            key_epoch: key.key_epoch(),
            kind: BackupScopeKind::Discovery,
        })
    }

    pub fn cleanup_discovery(
        key: &VaultDataKeyV1,
        source_id: &str,
    ) -> Result<Self, EgressReasonCodeV1> {
        let mut scope = Self::discovery(key, source_id)?;
        scope.kind = BackupScopeKind::CleanupDiscovery;
        Ok(scope)
    }
    pub fn selected_deletion(
        proof: &aw_sync_e2ee::SnapshotDeletionProofV1,
        remaining: &[SyncEnvelopeV1],
        source_id: &str,
    ) -> Result<Self, EgressReasonCodeV1> {
        let fact = proof.fact();
        fact.validate()
            .map_err(|_| EgressReasonCodeV1::InvalidPayload)?;
        if source_id.is_empty()
            || source_id.len() > 128
            || !source_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
            || remaining.is_empty()
            || remaining.len() > MAX_BACKUP_SCAN_OBJECTS
        {
            return Err(EgressReasonCodeV1::InvalidPayload);
        }
        let mut objects = BTreeMap::new();
        let mut bytes = 0usize;
        for object in remaining {
            if !proof.allows_object(object) {
                return Err(EgressReasonCodeV1::InvalidPayload);
            }
            bytes = bytes
                .checked_add(
                    serde_json::to_vec(object)
                        .map_err(|_| EgressReasonCodeV1::InvalidPayload)?
                        .len(),
                )
                .ok_or(EgressReasonCodeV1::InvalidPayload)?;
            if bytes > MAX_BACKUP_BUNDLE_BYTES
                || objects
                    .insert(object.object_id.clone(), object_digest(object)?)
                    .is_some()
            {
                return Err(EgressReasonCodeV1::InvalidPayload);
            }
        }
        Ok(Self {
            source_id: source_id.into(),
            vault_id: fact.vault_id.clone(),
            key_epoch: fact
                .key_epoch
                .parse()
                .map_err(|_| EgressReasonCodeV1::InvalidPayload)?,
            kind: BackupScopeKind::SelectedDeletion {
                snapshot_id: fact.snapshot_id.clone(),
                bundle_sha256: fact.bundle_sha256.clone(),
                objects,
                sample: remaining[0].clone(),
            },
        })
    }
    pub(crate) fn grants_free_cleanup(&self, request: &SyncRelayRequestV1) -> bool {
        self.validate_request(request).is_ok()
            && matches!(
                (&self.kind, request.operation),
                (
                    BackupScopeKind::CleanupDiscovery,
                    SyncRelayOperationV1::ListOpaqueHeads
                ) | (
                    BackupScopeKind::SelectedDeletion { .. },
                    SyncRelayOperationV1::DeleteSelectedBackup
                )
            )
    }

    pub fn selected(
        key: &VaultDataKeyV1,
        snapshot: &EncryptedSyncSnapshotV1,
        source_id: &str,
        direction: BackupTransferDirectionV1,
    ) -> Result<Self, EgressReasonCodeV1> {
        let mut scope = Self::discovery(key, source_id)?;
        snapshot
            .validate()
            .map_err(|_| EgressReasonCodeV1::InvalidPayload)?;
        if snapshot.envelopes.len() > MAX_BACKUP_SCAN_OBJECTS {
            return Err(EgressReasonCodeV1::InvalidPayload);
        }
        let mut size = 0usize;
        let mut builder = SnapshotIndexBuilderV1::new(key);
        let mut objects = BTreeMap::new();
        for object in &snapshot.envelopes {
            size = size
                .checked_add(
                    serde_json::to_vec(object)
                        .map_err(|_| EgressReasonCodeV1::InvalidPayload)?
                        .len(),
                )
                .ok_or(EgressReasonCodeV1::InvalidPayload)?;
            if size > MAX_BACKUP_BUNDLE_BYTES {
                return Err(EgressReasonCodeV1::InvalidPayload);
            }
            builder
                .push(object)
                .map_err(|_| EgressReasonCodeV1::InvalidPayload)?;
            objects.insert(object.object_id.clone(), object_digest(object)?);
        }
        let index = builder
            .finish()
            .map_err(|_| EgressReasonCodeV1::InvalidPayload)?;
        let group = index
            .groups
            .first()
            .filter(|group| {
                index.groups.len() == 1
                    && group.complete
                    && group.snapshot_id == snapshot.snapshot_id
            })
            .ok_or(EgressReasonCodeV1::InvalidPayload)?;
        decrypt_snapshot(key, snapshot).map_err(|_| EgressReasonCodeV1::InvalidPayload)?;
        scope.kind = BackupScopeKind::Selected {
            snapshot_id: snapshot.snapshot_id.clone(),
            bundle_sha256: group
                .bundle_sha256
                .clone()
                .ok_or(EgressReasonCodeV1::InvalidPayload)?,
            direction,
            objects,
            sample: snapshot.envelopes[0].clone(),
        };
        Ok(scope)
    }

    pub(crate) fn sample_request(&self) -> SyncRelayRequestV1 {
        let mut request = SyncRelayRequestV1 {
            schema_version: 1,
            operation: SyncRelayOperationV1::ListOpaqueHeads,
            object_id: None,
            vault_id: Some(self.vault_id.clone()),
            envelope: None,
            cursor: None,
            limit: Some(16),
        };
        if let BackupScopeKind::Selected {
            direction, sample, ..
        } = &self.kind
        {
            request.operation = if *direction == BackupTransferDirectionV1::Upload {
                SyncRelayOperationV1::PutIfAbsent
            } else {
                SyncRelayOperationV1::Get
            };
            request.object_id = Some(sample.object_id.clone());
            request.limit = None;
            if *direction == BackupTransferDirectionV1::Upload {
                request.envelope = Some(sample.clone());
            } else {
                request.vault_id = None;
            }
        }
        if let BackupScopeKind::SelectedDeletion { sample, .. } = &self.kind {
            request.operation = SyncRelayOperationV1::DeleteSelectedBackup;
            request.object_id = Some(sample.object_id.clone());
            request.envelope = Some(sample.clone());
            request.limit = None;
        }
        request
    }

    pub(crate) fn validate_request(
        &self,
        request: &SyncRelayRequestV1,
    ) -> Result<(), EgressReasonCodeV1> {
        request
            .validate()
            .map_err(|_| EgressReasonCodeV1::InvalidPayload)?;
        match &self.kind {
            BackupScopeKind::Discovery | BackupScopeKind::CleanupDiscovery
                if request.operation == SyncRelayOperationV1::ListOpaqueHeads
                    && request.vault_id.as_ref() == Some(&self.vault_id) =>
            {
                Ok(())
            }
            BackupScopeKind::SelectedDeletion { objects, .. } => {
                let object = request
                    .envelope
                    .as_ref()
                    .ok_or(EgressReasonCodeV1::ApprovalRequired)?;
                if request.operation != SyncRelayOperationV1::DeleteSelectedBackup
                    || object.vault_id != self.vault_id
                    || object.key_epoch != self.key_epoch
                    || request.vault_id.as_ref() != Some(&self.vault_id)
                    || objects.get(&object.object_id) != Some(&object_digest(object)?)
                {
                    return Err(EgressReasonCodeV1::ApprovalRequired);
                }
                Ok(())
            }
            BackupScopeKind::Selected {
                objects, direction, ..
            } => {
                let id = request
                    .object_id
                    .as_ref()
                    .ok_or(EgressReasonCodeV1::ApprovalRequired)?;
                let digest = objects
                    .get(id)
                    .ok_or(EgressReasonCodeV1::ApprovalRequired)?;
                match (direction, request.operation) {
                    (BackupTransferDirectionV1::Download, SyncRelayOperationV1::Get) => Ok(()),
                    (BackupTransferDirectionV1::Upload, SyncRelayOperationV1::PutIfAbsent) => {
                        let envelope = request
                            .envelope
                            .as_ref()
                            .ok_or(EgressReasonCodeV1::InvalidPayload)?;
                        if envelope.vault_id == self.vault_id
                            && envelope.key_epoch == self.key_epoch
                            && &object_digest(envelope)? == digest
                        {
                            Ok(())
                        } else {
                            Err(EgressReasonCodeV1::InvalidPayload)
                        }
                    }
                    _ => Err(EgressReasonCodeV1::ApprovalRequired),
                }
            }
            _ => Err(EgressReasonCodeV1::ApprovalRequired),
        }
    }
}
