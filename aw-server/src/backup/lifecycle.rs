use super::*;
use aw_models::SnapshotDeletionFactV1;
use aw_sync_e2ee::SnapshotDeletionProofV1;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeletionInvocation {
    #[serde(rename = "requestJson")]
    request_json: String,
    #[serde(rename = "userAccepted")]
    user_accepted: Option<bool>,
}
impl Drop for DeletionInvocation {
    fn drop(&mut self) {
        self.request_json.zeroize();
    }
}
struct Prepared {
    key: VaultDataKeyV1,
    state: SyncBackupSourceStateV1,
    reference: BackupSelectionV1,
    fact: SnapshotDeletionFactV1,
    proof: Option<SnapshotDeletionProofV1>,
    record: Option<EncryptedSyncSnapshotV1>,
    folder: Option<FolderBackupDeletionV1>,
    retry: bool,
}
pub(super) fn reference_for_fact(fact: &SnapshotDeletionFactV1, source: &str) -> BackupSelectionV1 {
    BackupSelectionV1 {
        schema_version: 1,
        source_id: source.into(),
        vault_id: fact.vault_id.clone(),
        key_epoch: fact.key_epoch.clone(),
        snapshot_id: fact.snapshot_id.clone(),
        object_count: fact.objects.len(),
        bundle_sha256: fact.bundle_sha256.clone(),
    }
}
pub(super) fn retained_fact(
    lease: &EgressLease<'_>,
    context: &str,
    reference: &BackupSelectionV1,
) -> Result<Option<SnapshotDeletionFactV1>, String> {
    let mut cursor = None;
    loop {
        let page = lease
            .list_sync_backup_deletions(context.into(), cursor, 64)
            .map_err(|_| "Protected deletion history could not be read")?;
        for fact in page.facts {
            if fact.vault_id == reference.vault_id
                && fact.key_epoch == reference.key_epoch
                && fact.snapshot_id == reference.snapshot_id
            {
                if reference_for_fact(&fact, &reference.source_id) != *reference {
                    return Err("Protected deletion intent does not match this selection".into());
                }
                return Ok(Some(fact));
            }
        }
        match page.next_cursor {
            None => return Ok(None),
            Some(next) => cursor = Some(next),
        }
    }
}
fn prepare(store: &Datastore, request: &BackupRequest) -> Result<Prepared, String> {
    if request.schema_version != 1
        || !matches!(request.source_id.as_str(), "local" | "folder")
        || !hex64(&request.context_id)
        || (request.source_id == "local" && request.folder_path.is_some())
        || (request.source_id == "folder"
            && request
                .folder_path
                .as_ref()
                .is_none_or(|path| path.is_empty()))
    {
        return Err("Backup deletion request is invalid".into());
    }
    let reference = request
        .selection
        .as_ref()
        .ok_or("Select an authenticated historical backup first")?;
    reference.validate()?;
    if !store.is_encrypted() {
        return Err("Unlock the encrypted vault before deleting backups".into());
    }
    let lease = store
        .egress_lease()
        .map_err(|_| "Unlock the encrypted vault before deleting backups")?;
    let state = lease
        .sync_backup_source()
        .map_err(|_| "Backup source is unavailable")?;
    if request.context_id != state.context_id {
        return Err("Backup source changed; refresh the catalogue".into());
    }
    let key = source_key(&state, request.recovery.as_ref())?
        .ok_or("A matching recovery kit is required")?;
    let folder = request
        .folder_path
        .as_ref()
        .map(FolderBackupDeletionV1::open_existing)
        .transpose()?;
    let source = if let Some(path) = request.folder_path.as_ref() {
        BackupSource::Folder(
            FolderSyncObjectStoreV1::open_readonly(path)
                .map_err(|_| "Choose an existing safe backup folder")?,
        )
    } else {
        BackupSource::Local(&lease)
    };
    let source_id = match &source {
        BackupSource::Local(_) => "local".into(),
        BackupSource::Folder(folder) => folder.backup_source_id(&state.context_id),
        BackupSource::Cached(_) => unreachable!(),
    };
    if reference.source_id != source_id
        || reference.vault_id != URL_SAFE_NO_PAD.encode(key.vault_id())
        || reference.key_epoch != key.key_epoch().to_string()
    {
        return Err("Selected backup source or key changed".into());
    }
    if state
        .current_snapshot_id
        .is_some_and(|id| URL_SAFE_NO_PAD.encode(id) == reference.snapshot_id)
        && state.material.as_ref().is_some_and(|material| {
            *material.vault_id() == key.vault_id() && material.key_epoch() == key.key_epoch()
        })
    {
        return Err(
            "The current backup is protected; create a fresh snapshot before deleting this version"
                .into(),
        );
    }
    let known = retained_fact(&lease, &state.context_id, reference)?;
    let record = folder
        .as_ref()
        .map(|folder| folder.load_intent(&key, &reference.bundle_sha256))
        .transpose()?
        .flatten();
    let (fact, proof, retry) = if let Some(record) = record.as_ref() {
        let fact = SnapshotDeletionProofV1::open_record(&key, record)
            .map_err(|_| "Folder deletion intent did not authenticate")?;
        if reference_for_fact(&fact, &source_id) != *reference || known.as_ref() != Some(&fact) {
            return Err("Retry requires the identical protected deletion intent".into());
        }
        let remaining = folder.as_ref().unwrap().remaining(&fact)?;
        let proof = if remaining.is_empty() {
            None
        } else {
            Some(
                SnapshotDeletionProofV1::resume(&key, record, &remaining)
                    .map_err(|_| "Remaining backup bytes changed; review the copy conflict")?,
            )
        };
        (fact, proof, true)
    } else if let Some(fact) = known {
        let mut envelopes = Vec::new();
        for object in &fact.objects {
            if let Some(object) = source.object(&object.object_id)? {
                envelopes.push(object);
            }
        }
        if envelopes.is_empty() {
            if folder.is_some() {
                return Err("Folder retry requires its retained sealed intent".into());
            }
            (fact, None, true)
        } else {
            if envelopes.len() != fact.objects.len() {
                return Err("A partial local copy has no retained sealed authority; its bytes were preserved".into());
            }
            let snapshot = EncryptedSyncSnapshotV1 {
                schema_version: 1,
                snapshot_id: fact.snapshot_id.clone(),
                envelopes,
            };
            crate::sync_control::decrypt_recovery_snapshot(&key, &snapshot)?;
            let proof = SnapshotDeletionProofV1::authenticate(&key, &snapshot)
                .map_err(|_| "Retained backup did not authenticate")?;
            if proof.fact() != &fact {
                return Err("Retained backup differs from its protected deletion intent".into());
            }
            (fact, Some(proof), true)
        }
    } else {
        let (index, _) = source.catalogue(&state, Some(&key))?;
        let group = index
            .groups
            .iter()
            .find(|group| group.snapshot_id == reference.snapshot_id && group.complete)
            .ok_or("Selected backup is missing or incomplete")?;
        if selection(&key, group, &source_id) != *reference {
            return Err("Selected backup changed; refresh the catalogue".into());
        }
        let (snapshot, _) = bundle(&source, &key, group)?;
        let proof = SnapshotDeletionProofV1::authenticate(&key, &snapshot)
            .map_err(|_| "Selected backup did not authenticate")?;
        (proof.fact().clone(), Some(proof), false)
    };
    check_source(&lease, &state)?;
    drop(source);
    drop(lease);
    Ok(Prepared {
        key,
        state,
        reference: reference.clone(),
        fact,
        proof,
        record,
        folder,
        retry,
    })
}
pub(super) fn invoke(store: &Datastore, command: &str, args: Value) -> Result<Value, String> {
    let input = serde_json::from_value::<ObjectRecord<DeletionInvocation>>(args)
        .map_err(|_| "Backup deletion arguments are invalid")?
        .0;
    if input.request_json.len() > MAX_BACKUP_CONTROL_BYTES {
        return Err("Backup deletion request exceeds64KiB".into());
    }
    if (command == "preview_sync_backup_delete" && input.user_accepted.is_some())
        || (command == "delete_selected_sync_backup" && input.user_accepted != Some(true))
    {
        return Err(
            "Review and explicitly accept the backup deletion before removing this copy".into(),
        );
    }
    let request = serde_json::from_str::<ObjectRecord<BackupRequest>>(&input.request_json)
        .map_err(|_| "Backup deletion request is invalid or ambiguous")?
        .0;
    let mut prepared = prepare(store, &request)?;
    if command == "preview_sync_backup_delete" {
        return Ok(
            json!({"schema_version":1,"context_id":prepared.state.context_id,"selection":prepared.reference,"object_count":prepared.fact.objects.len(),"retry":prepared.retry,"copy_scope":request.source_id}),
        );
    }
    let at = chrono::Utc::now().to_rfc3339();
    let result = if let Some(folder) = prepared.folder.as_ref() {
        let record = if let Some(proof) = prepared.proof.take() {
            let sealed = proof
                .seal(&prepared.key)
                .map_err(|_| "Deletion intent could not be sealed")?;
            store
                .record_sync_backup_deletion_intent(prepared.state.context_id.clone(), proof, at)
                .map_err(|_| "The protected deletion intent could not be committed")?;
            let lease = store
                .egress_lease()
                .map_err(|_| "The vault closed before folder deletion")?;
            check_source(&lease, &prepared.state)?;
            folder.publish_accepted_intent(&prepared.key, &sealed)?;
            let remaining = folder.remaining(&prepared.fact)?;
            let resumed = if remaining.is_empty() {
                None
            } else {
                Some(
                    SnapshotDeletionProofV1::resume(&prepared.key, &sealed, &remaining)
                        .map_err(|_| "Selected folder bytes changed before deletion")?,
                )
            };
            folder.delete_recorded(
                &prepared.key,
                resumed.as_ref(),
                &prepared.reference.bundle_sha256,
            )?
        } else {
            let lease = store
                .egress_lease()
                .map_err(|_| "The vault closed before folder deletion retry")?;
            check_source(&lease, &prepared.state)?;
            folder.publish_accepted_intent(
                &prepared.key,
                prepared
                    .record
                    .as_ref()
                    .ok_or("No retained folder intent")?,
            )?;
            folder.delete_recorded(&prepared.key, None, &prepared.reference.bundle_sha256)?
        };
        record
    } else {
        let count = if let Some(proof) = prepared.proof.take() {
            store
                .delete_sync_backup(prepared.state.context_id.clone(), proof, at)
                .map_err(|_| "The exact historical backup could not be deleted atomically")?
        } else {
            0
        };
        BackupCopyDeletionV1 {
            deleted: count,
            absent: prepared.fact.objects.len().saturating_sub(count),
            conflict: 0,
            failed: 0,
            durable: true,
        }
    };
    let mut output =
        serde_json::to_value(result).map_err(|_| "Backup deletion outcome could not be encoded")?;
    output["schema_version"] = json!(1);
    output["context_id"] = json!(prepared.state.context_id);
    output["selection"] = serde_json::to_value(prepared.reference)
        .map_err(|_| "Backup deletion selection could not be encoded")?;
    output["copy_scope"] = json!(request.source_id);
    Ok(output)
}
