use crate::{
    decrypt_snapshot, EncryptedSyncSnapshotV1, SnapshotIndexBuilderV1, SyncErrorV1, VaultDataKeyV1,
    MAX_BACKUP_BUNDLE_BYTES, MAX_BACKUP_SCAN_OBJECTS,
};
use aw_models::{SnapshotDeletionFactV1, SnapshotDeletionObjectV1};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::digest::{digest, SHA256};
use std::collections::BTreeMap;
use zeroize::Zeroizing;
const RECORD_DOMAIN: &[u8] = b"PeakActivity-Backup-Deletion-Record-v1\0";

pub struct SnapshotDeletionProofV1 {
    fact: SnapshotDeletionFactV1,
    key_binding: Zeroizing<[u8; 32]>,
    verified_objects: BTreeMap<String, String>,
}
impl SnapshotDeletionProofV1 {
    pub fn authenticate(
        key: &VaultDataKeyV1,
        snapshot: &EncryptedSyncSnapshotV1,
    ) -> Result<Self, SyncErrorV1> {
        Self::bounded(
            key,
            snapshot,
            MAX_BACKUP_SCAN_OBJECTS,
            MAX_BACKUP_BUNDLE_BYTES,
        )
    }
    fn bounded(
        key: &VaultDataKeyV1,
        snapshot: &EncryptedSyncSnapshotV1,
        object_limit: usize,
        byte_limit: usize,
    ) -> Result<Self, SyncErrorV1> {
        if snapshot.envelopes.len() > object_limit {
            return Err(SyncErrorV1::PayloadTooLarge);
        }
        snapshot.validate()?;
        let mut builder = SnapshotIndexBuilderV1::new(key);
        let mut bytes = 0usize;
        let mut objects = Vec::new();
        for object in &snapshot.envelopes {
            let encoded = serde_json::to_vec(object).map_err(|_| SyncErrorV1::InvalidEnvelope)?;
            bytes = bytes
                .checked_add(encoded.len())
                .ok_or(SyncErrorV1::PayloadTooLarge)?;
            if bytes > byte_limit {
                return Err(SyncErrorV1::PayloadTooLarge);
            }
            builder.push(object)?;
            objects.push(SnapshotDeletionObjectV1 {
                object_id: object.object_id.clone(),
                envelope_sha256: digest(&SHA256, &encoded)
                    .as_ref()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect(),
            });
        }
        let index = builder.finish()?;
        let group = index
            .groups
            .first()
            .filter(|g| {
                index.groups.len() == 1
                    && g.complete
                    && g.snapshot_id == snapshot.snapshot_id
                    && g.object_ids.len() == objects.len()
            })
            .ok_or(SyncErrorV1::InvalidEnvelope)?;
        let _plaintext = decrypt_snapshot(key, snapshot)?;
        let fact = SnapshotDeletionFactV1 {
            schema_version: 1,
            vault_id: URL_SAFE_NO_PAD.encode(key.vault_id()),
            key_epoch: key.key_epoch().to_string(),
            snapshot_id: snapshot.snapshot_id.clone(),
            bundle_sha256: group
                .bundle_sha256
                .clone()
                .ok_or(SyncErrorV1::InvalidEnvelope)?,
            objects,
        };
        fact.validate().map_err(|_| SyncErrorV1::InvalidEnvelope)?;
        let verified_objects = fact
            .objects
            .iter()
            .map(|o| (o.object_id.clone(), o.envelope_sha256.clone()))
            .collect();
        Ok(Self {
            fact,
            key_binding: Zeroizing::new(key.backup_deletion_binding()),
            verified_objects,
        })
    }
    pub fn seal(&self, key: &VaultDataKeyV1) -> Result<EncryptedSyncSnapshotV1, SyncErrorV1> {
        if *self.key_binding != key.backup_deletion_binding() {
            return Err(SyncErrorV1::InvalidKeyScope);
        }
        let mut plaintext = Zeroizing::new(RECORD_DOMAIN.to_vec());
        plaintext.extend(serde_json::to_vec(&self.fact).map_err(|_| SyncErrorV1::InvalidEnvelope)?);
        crate::encrypt_snapshot(key, &plaintext)
    }
    pub fn matches_record(&self, key: &VaultDataKeyV1, record: &EncryptedSyncSnapshotV1) -> bool {
        *self.key_binding == key.backup_deletion_binding()
            && Self::open_record(key, record).is_ok_and(|fact| fact == self.fact)
    }
    pub fn open_record(
        key: &VaultDataKeyV1,
        record: &EncryptedSyncSnapshotV1,
    ) -> Result<SnapshotDeletionFactV1, SyncErrorV1> {
        let _record_proof = Self::authenticate(key, record)?;
        let plaintext = decrypt_snapshot(key, record)?;
        let bytes = plaintext
            .strip_prefix(RECORD_DOMAIN)
            .ok_or(SyncErrorV1::InvalidEnvelope)?;
        let fact: SnapshotDeletionFactV1 =
            serde_json::from_slice(bytes).map_err(|_| SyncErrorV1::InvalidEnvelope)?;
        if fact.vault_id != URL_SAFE_NO_PAD.encode(key.vault_id())
            || fact.key_epoch != key.key_epoch().to_string()
        {
            return Err(SyncErrorV1::InvalidKeyScope);
        }
        Ok(fact)
    }
    pub fn resume(
        key: &VaultDataKeyV1,
        record: &EncryptedSyncSnapshotV1,
        remaining: &[aw_models::SyncEnvelopeV1],
    ) -> Result<Self, SyncErrorV1> {
        let fact = Self::open_record(key, record)?;
        if remaining.is_empty() || remaining.len() > fact.objects.len() {
            return Err(SyncErrorV1::InvalidEnvelope);
        }
        let expected: BTreeMap<_, _> = fact
            .objects
            .iter()
            .enumerate()
            .map(|(index, o)| (o.object_id.as_str(), (index, o.envelope_sha256.as_str())))
            .collect();
        let mut verified_objects = BTreeMap::new();
        let mut bytes = 0usize;
        for object in remaining {
            let (index, hash) = expected
                .get(object.object_id.as_str())
                .ok_or(SyncErrorV1::InvalidEnvelope)?;
            let encoded = serde_json::to_vec(object).map_err(|_| SyncErrorV1::InvalidEnvelope)?;
            bytes = bytes
                .checked_add(encoded.len())
                .ok_or(SyncErrorV1::PayloadTooLarge)?;
            if bytes > MAX_BACKUP_BUNDLE_BYTES {
                return Err(SyncErrorV1::PayloadTooLarge);
            }
            let actual: String = digest(&SHA256, &encoded)
                .as_ref()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            let header = crate::inspect_snapshot_chunk(key, object)?;
            if actual != *hash
                || header.snapshot_id != fact.snapshot_id
                || header.index as usize != *index
                || header.count as usize != fact.objects.len()
                || verified_objects
                    .insert(object.object_id.clone(), actual)
                    .is_some()
            {
                return Err(SyncErrorV1::InvalidEnvelope);
            }
        }
        Ok(Self {
            fact,
            key_binding: Zeroizing::new(key.backup_deletion_binding()),
            verified_objects,
        })
    }
    pub fn allows_object(&self, object: &aw_models::SyncEnvelopeV1) -> bool {
        let Some(expected) = self.verified_objects.get(&object.object_id) else {
            return false;
        };
        serde_json::to_vec(object).is_ok_and(|bytes| {
            digest(&SHA256, &bytes)
                .as_ref()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
                == *expected
        })
    }
    pub fn is_complete(&self) -> bool {
        self.verified_objects.len() == self.fact.objects.len()
    }
    pub fn fact(&self) -> &SnapshotDeletionFactV1 {
        &self.fact
    }
    #[cfg(test)]
    pub(super) fn authenticate_with_limits(
        key: &VaultDataKeyV1,
        snapshot: &EncryptedSyncSnapshotV1,
        objects: usize,
        bytes: usize,
    ) -> Result<Self, SyncErrorV1> {
        Self::bounded(key, snapshot, objects, bytes)
    }
}

impl std::fmt::Debug for SnapshotDeletionProofV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SnapshotDeletionProofV1(..)")
    }
}
