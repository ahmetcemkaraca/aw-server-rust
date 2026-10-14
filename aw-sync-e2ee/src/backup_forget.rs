use crate::{MergeErrorV1, SyncOperationV1};
use aw_models::{
    BackupForgetFragmentV1, SnapshotDeletionFactV1, SyncOperationKindV1,
    BACKUP_FORGET_OBJECTS_PER_FRAGMENT,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use std::collections::{BTreeMap, BTreeSet};
const OP_BYTES: usize = 512 * 1024;
const PENDING_BYTES: usize = 32 * 1024 * 1024;
fn hash(fact: &SnapshotDeletionFactV1) -> Result<String, MergeErrorV1> {
    let bytes = serde_json::to_vec(fact).map_err(|_| MergeErrorV1::InvalidOperation)?;
    Ok(ring::digest::digest(&ring::digest::SHA256, &bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}
pub fn create_backup_forget_operations(
    device: [u8; 16],
    first_counter: u64,
    fact: &SnapshotDeletionFactV1,
) -> Result<Vec<SyncOperationV1>, MergeErrorV1> {
    fact.validate()
        .map_err(|_| MergeErrorV1::InvalidOperation)?;
    let count = fact
        .objects
        .len()
        .div_ceil(BACKUP_FORGET_OBJECTS_PER_FRAGMENT);
    if first_counter == 0
        || first_counter
            .checked_add(count as u64 - 1)
            .is_none_or(|last| last > i64::MAX as u64)
    {
        return Err(MergeErrorV1::InvalidOperation);
    }
    let digest = hash(fact)?;
    fact.objects
        .chunks(BACKUP_FORGET_OBJECTS_PER_FRAGMENT)
        .enumerate()
        .map(|(index, objects)| {
            let operation = SyncOperationV1 {
                schema_version: 1,
                device_id: URL_SAFE_NO_PAD.encode(device),
                counter: first_counter + index as u64,
                origin_device_id: URL_SAFE_NO_PAD.encode(device),
                local_event_id: None,
                sync_bucket_id: None,
                bucket_descriptor: None,
                kind: SyncOperationKindV1::BackupForget,
                policy_version: None,
                fields: BTreeMap::new(),
                backup_forget_fragment: Some(BackupForgetFragmentV1 {
                    schema_version: 1,
                    fact_sha256: digest.clone(),
                    vault_id: fact.vault_id.clone(),
                    key_epoch: fact.key_epoch.clone(),
                    snapshot_id: fact.snapshot_id.clone(),
                    bundle_sha256: fact.bundle_sha256.clone(),
                    fragment_index: index as u32,
                    fragment_count: count as u32,
                    total_objects: fact.objects.len() as u32,
                    objects: objects.to_vec(),
                }),
            };
            operation.validate()?;
            if serde_json::to_vec(&operation)
                .map_err(|_| MergeErrorV1::InvalidOperation)?
                .len()
                > OP_BYTES
            {
                return Err(MergeErrorV1::InvalidOperation);
            }
            Ok(operation)
        })
        .collect()
}
// Callers authenticate the operation stream; complete metadata never grants ciphertext deletion authority.
pub fn assemble_backup_forget_operations(
    operations: &[SyncOperationV1],
) -> Result<Vec<SnapshotDeletionFactV1>, MergeErrorV1> {
    let mut groups: BTreeMap<(&str, &str), BTreeMap<u32, &BackupForgetFragmentV1>> =
        BTreeMap::new();
    if operations.len() > 100000 {
        return Err(MergeErrorV1::InvalidOperation);
    }
    let mut observed = BTreeMap::new();
    let mut entries = 0usize;
    let mut bytes = 0usize;
    for op in operations
        .iter()
        .filter(|op| op.kind == SyncOperationKindV1::BackupForget)
    {
        op.validate()?;
        let fragment = op
            .backup_forget_fragment
            .as_ref()
            .ok_or(MergeErrorV1::InvalidOperation)?;
        let group = groups
            .entry((&op.device_id, &fragment.fact_sha256))
            .or_default();
        if let Some(previous) = group.values().next() {
            if (
                previous.schema_version,
                &previous.vault_id,
                &previous.key_epoch,
                &previous.snapshot_id,
                &previous.bundle_sha256,
                previous.fragment_count,
                previous.total_objects,
            ) != (
                fragment.schema_version,
                &fragment.vault_id,
                &fragment.key_epoch,
                &fragment.snapshot_id,
                &fragment.bundle_sha256,
                fragment.fragment_count,
                fragment.total_objects,
            ) {
                return Err(MergeErrorV1::InvalidOperation);
            }
        }
        if let Some(previous) = group.get(&fragment.fragment_index) {
            if *previous != fragment {
                return Err(MergeErrorV1::InvalidOperation);
            }
            continue;
        }
        let identity = (fragment.fact_sha256.as_str(), fragment.fragment_index);
        if let Some(previous) = observed.get(&identity) {
            if *previous != fragment {
                return Err(MergeErrorV1::InvalidOperation);
            }
        } else {
            entries = entries
                .checked_add(fragment.objects.len())
                .ok_or(MergeErrorV1::InvalidOperation)?;
            bytes = bytes
                .checked_add(
                    serde_json::to_vec(fragment)
                        .map_err(|_| MergeErrorV1::InvalidOperation)?
                        .len(),
                )
                .ok_or(MergeErrorV1::InvalidOperation)?;
            if entries > 100000 || bytes > crate::MAX_BACKUP_BUNDLE_BYTES {
                return Err(MergeErrorV1::InvalidOperation);
            }
            observed.insert(identity, fragment);
        }
        group.insert(fragment.fragment_index, fragment);
    }
    let mut complete = Vec::new();
    let mut completed = BTreeSet::new();
    let mut pending = 0usize;
    for group in groups.values() {
        let first = group
            .values()
            .next()
            .ok_or(MergeErrorV1::InvalidOperation)?;
        if group.len() != first.fragment_count as usize {
            for fragment in group.values() {
                pending = pending
                    .checked_add(
                        serde_json::to_vec(fragment)
                            .map_err(|_| MergeErrorV1::InvalidOperation)?
                            .len(),
                    )
                    .ok_or(MergeErrorV1::InvalidOperation)?;
            }
            if pending > PENDING_BYTES {
                return Err(MergeErrorV1::InvalidOperation);
            }
            continue;
        }
        let mut fact = first.partial_fact();
        fact.objects.clear();
        for (expected, (index, fragment)) in group.iter().enumerate() {
            if *index != expected as u32 {
                return Err(MergeErrorV1::InvalidOperation);
            }
            fact.objects.extend_from_slice(&fragment.objects);
        }
        fact.validate()
            .map_err(|_| MergeErrorV1::InvalidOperation)?;
        if fact.objects.len() != first.total_objects as usize || hash(&fact)? != first.fact_sha256 {
            return Err(MergeErrorV1::InvalidOperation);
        }
        if completed.insert(&first.fact_sha256) {
            complete.push(fact);
        }
    }
    Ok(complete)
}
