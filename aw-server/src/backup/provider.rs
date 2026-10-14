use super::*;
use aw_egress::{
    BackupEgressPreviewV1, BackupScopeV1, BackupTransferDirectionV1, EgressBackupRelayTransportV1,
    EgressProxy, ReviewedBackupPermitV1, VerifiedPolicyV1,
};
use aw_models::{SyncEnvelopeV1, SyncRelayOperationV1, SyncRelayRequestV1};
use aw_sync_e2ee::{SyncRelayTransportV1, MAX_BACKUP_SCAN_BYTES};
use chrono::{DateTime, Duration, Utc};
use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex},
};

const CONTROL_BYTES: usize = 128 * 1024;
const MAX_PENDING: usize = 32;

#[derive(Clone, Copy, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Operation {
    List,
    CleanupList,
    Delete,
    Upload,
    Download,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreviewRequest {
    schema_version: u32,
    context_id: String,
    operation: Operation,
    destination_id: String,
    source_json: String,
    #[serde(default, deserialize_with = "optional_record")]
    selection: Option<BackupSelectionV1>,
}
impl Drop for PreviewRequest {
    fn drop(&mut self) {
        self.source_json.zeroize();
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApproveRequest {
    schema_version: u32,
    context_id: String,
    preview_id: String,
    user_accepted: bool,
    source_json: String,
}
impl Drop for ApproveRequest {
    fn drop(&mut self) {
        self.source_json.zeroize();
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunRequest {
    schema_version: u32,
    context_id: String,
    job_id: String,
    source_json: String,
}
impl Drop for RunRequest {
    fn drop(&mut self) {
        self.source_json.zeroize();
    }
}

#[derive(Clone)]
struct Pending {
    preview: BackupEgressPreviewV1,
    operation: Operation,
    selection: Option<BackupSelectionV1>,
    context: String,
    source_id: String,
    destination_id: String,
    expires: DateTime<Utc>,
}
struct Job {
    pending: Pending,
    permit: ReviewedBackupPermitV1,
}
#[derive(Clone)]
struct Catalogue {
    context: String,
    source_id: String,
    destination_id: String,
    expires: DateTime<Utc>,
    objects: Arc<BTreeMap<String, SyncEnvelopeV1>>,
    cleanup_only: bool,
}
#[derive(Default)]
struct State {
    context: String,
    previews: HashMap<String, Pending>,
    jobs: HashMap<String, Job>,
    catalogue: Option<Catalogue>,
}

#[derive(Clone)]
pub struct BackupWorkflowV1 {
    state: Arc<Mutex<State>>,
    work: Arc<Mutex<()>>,
}
impl Default for BackupWorkflowV1 {
    fn default() -> Self {
        Self::new()
    }
}

fn parse<T: serde::de::DeserializeOwned>(raw: String) -> Result<T, String> {
    let raw = Zeroizing::new(raw);
    if raw.len() > CONTROL_BYTES {
        return Err("Provider control request exceeds128KiB".into());
    }
    serde_json::from_str::<ObjectRecord<T>>(&raw)
        .map(|record| record.0)
        .map_err(|_| "Provider request is invalid or ambiguous".into())
}
fn token() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|_| "Secure randomness is unavailable")?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
fn context(store: &Datastore, expected: &str, schema: u32) -> Result<(), String> {
    if schema != 1
        || !hex64(expected)
        || !store.is_encrypted()
        || store
            .get_sync_policy_context()
            .map_err(|_| "Unlock the encrypted vault")?
            .context_id
            != expected
    {
        return Err("Provider context changed; refresh and review again".into());
    }
    Ok(())
}

struct Prepared {
    key: VaultDataKeyV1,
    anchor: Anchor,
    snapshot: Option<EncryptedSyncSnapshotV1>,
    reference: Option<BackupSelectionV1>,
}
struct Anchor {
    context: String,
    pointer: Option<[u8; 16]>,
    key: Option<[u8; 32]>,
}
impl Anchor {
    fn read(store: &Datastore) -> Result<Self, String> {
        let lease = store
            .egress_lease()
            .map_err(|_| "Unlock the encrypted vault")?;
        let state = lease
            .sync_backup_source()
            .map_err(|_| "Backup source is unavailable")?;
        Ok(Self {
            context: state.context_id,
            pointer: state.current_snapshot_id,
            key: key_binding(state.material.as_ref()),
        })
    }
    fn check(&self, store: &Datastore) -> Result<(), String> {
        let fresh = Self::read(store)?;
        if fresh.context != self.context || fresh.pointer != self.pointer || fresh.key != self.key {
            return Err("Backup source changed; review again".into());
        }
        Ok(())
    }
}
fn prepare(store: &Datastore, raw: &str, upload: bool) -> Result<Prepared, String> {
    if raw.len() > MAX_BACKUP_CONTROL_BYTES {
        return Err("Backup source request exceeds64KiB".into());
    }
    let request: BackupRequest = serde_json::from_str::<ObjectRecord<BackupRequest>>(raw)
        .map_err(|_| "Backup source request is invalid")?
        .0;
    context(store, &request.context_id, request.schema_version)?;
    if !upload
        && (request.source_id != "local"
            || request.selection.is_some()
            || request.folder_path.is_some())
    {
        return Err("Provider discovery/download requires a local key context".into());
    }
    let (key, anchor) = {
        let lease = store
            .egress_lease()
            .map_err(|_| "Unlock the encrypted vault")?;
        let state = lease
            .sync_backup_source()
            .map_err(|_| "Backup source is unavailable")?;
        if state.context_id != request.context_id {
            return Err("Backup source changed".into());
        }
        let key = source_key(&state, request.recovery.as_ref())?
            .ok_or("Provide a matching recovery kit")?;
        (
            key,
            Anchor {
                context: state.context_id,
                pointer: state.current_snapshot_id,
                key: key_binding(state.material.as_ref()),
            },
        )
    };
    let snapshot = if upload {
        let raw_export = super::invoke(
            store,
            "export_selected_sync_backup",
            json!({"requestJson":raw}),
        )?;
        let snapshot: EncryptedSyncSnapshotV1 =
            serde_json::from_str(raw_export.as_str().ok_or("Backup export is invalid")?)
                .map_err(|_| "Backup export is invalid")?;
        summary(crate::sync_control::decrypt_recovery_snapshot(
            &key, &snapshot,
        )?)?;
        Some(snapshot)
    } else {
        None
    };
    anchor.check(store)?;
    Ok(Prepared {
        key,
        anchor,
        snapshot,
        reference: request.selection,
    })
}

impl BackupWorkflowV1 {
    pub fn validate_request(kind: &str, raw: &str) -> Result<(), String> {
        match kind {
            "preview" => {
                let _: PreviewRequest = parse(raw.to_owned())?;
            }
            "approve" => {
                let _: ApproveRequest = parse(raw.to_owned())?;
            }
            "run" => {
                let _: RunRequest = parse(raw.to_owned())?;
            }
            _ => return Err("Provider operation is invalid".into()),
        }
        Ok(())
    }
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(State::default())),
            work: Arc::new(Mutex::new(())),
        }
    }
    fn work(&self) -> Result<std::sync::MutexGuard<'_, ()>, String> {
        self.work
            .try_lock()
            .map_err(|_| "A provider backup operation is already running".into())
    }
    fn state(&self, context: &str) -> Result<std::sync::MutexGuard<'_, State>, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "Provider workflow is unavailable")?;
        if state.context != context {
            *state = State {
                context: context.into(),
                ..Default::default()
            };
        }
        let now = Utc::now();
        state.previews.retain(|_, pending| pending.expires > now);
        state.jobs.retain(|_, job| job.pending.expires > now);
        if state
            .catalogue
            .as_ref()
            .is_some_and(|catalogue| catalogue.expires <= now)
        {
            state.catalogue = None;
        }
        Ok(state)
    }
    fn catalogue(
        &self,
        context: &str,
        reference: &BackupSelectionV1,
        destination: &str,
    ) -> Result<Catalogue, String> {
        let state = self.state(context)?;
        let catalogue = state
            .catalogue
            .as_ref()
            .ok_or("Discover the provider catalogue first")?;
        if catalogue.context != context
            || catalogue.source_id != reference.source_id
            || catalogue.destination_id != destination
        {
            return Err("Provider selection source changed".into());
        }
        Ok(catalogue.clone())
    }
    fn selected(
        &self,
        store: &Datastore,
        operation: Operation,
        expected_selection: Option<&BackupSelectionV1>,
        context: &str,
        destination: &str,
        prepared: &Prepared,
    ) -> Result<(BackupScopeV1, EncryptedSyncSnapshotV1), String> {
        if operation == Operation::Upload {
            let snapshot = prepared.snapshot.as_ref().ok_or("Select a local backup")?;
            let reference = prepared.reference.as_ref().ok_or("Select a local backup")?;
            if Some(reference) != expected_selection {
                return Err("Local backup selection changed".into());
            }
            return Ok((
                BackupScopeV1::selected(
                    &prepared.key,
                    snapshot,
                    &reference.source_id,
                    BackupTransferDirectionV1::Upload,
                )
                .map_err(|_| "Local backup did not authenticate")?,
                snapshot.clone(),
            ));
        }
        let reference = expected_selection.ok_or("Select a provider backup")?;
        let catalogue = self.catalogue(context, reference, destination)?;
        if operation == Operation::Download && catalogue.cleanup_only {
            return Err("Cleanup discovery cannot authorize a download".into());
        }
        let source = BackupSource::Cached(&catalogue.objects);
        let lease = store
            .egress_lease()
            .map_err(|_| "Unlock the encrypted vault")?;
        let state = lease
            .sync_backup_source()
            .map_err(|_| "Backup source is unavailable")?;
        drop(lease);
        if operation == Operation::Delete {
            return self
                .deletion(store, reference, &catalogue, prepared)
                .map(|(scope, snapshot, _)| (scope, snapshot));
        }
        let (index, _) = source.catalogue(&state, Some(&prepared.key))?;
        let group = index
            .groups
            .iter()
            .find(|group| group.snapshot_id == reference.snapshot_id && group.complete)
            .ok_or("Provider backup is incomplete")?;
        if selection(&prepared.key, group, &catalogue.source_id) != *reference {
            return Err("Provider backup selection changed".into());
        }
        let lease = store
            .egress_lease()
            .map_err(|_| "Unlock the encrypted vault")?;
        lease
            .ensure_sync_backup_not_deleted(
                context.into(),
                reference.vault_id.clone(),
                prepared.key.key_epoch(),
                reference.snapshot_id.clone(),
                group.object_ids.clone(),
            )
            .map_err(|_| "This backup has been forgotten and cannot be downloaded")?;
        drop(lease);
        let (snapshot, recovery) = bundle(&source, &prepared.key, group)?;
        summary(recovery)?;
        Ok((
            BackupScopeV1::selected(
                &prepared.key,
                &snapshot,
                &reference.source_id,
                BackupTransferDirectionV1::Download,
            )
            .map_err(|_| "Provider backup did not authenticate")?,
            snapshot,
        ))
    }
    fn deletion(
        &self,
        store: &Datastore,
        reference: &BackupSelectionV1,
        catalogue: &Catalogue,
        prepared: &Prepared,
    ) -> Result<
        (
            BackupScopeV1,
            EncryptedSyncSnapshotV1,
            aw_sync_e2ee::SnapshotDeletionProofV1,
        ),
        String,
    > {
        let lease = store
            .egress_lease()
            .map_err(|_| "Unlock the encrypted vault")?;
        let state = lease
            .sync_backup_source()
            .map_err(|_| "Backup source is unavailable")?;
        if reference.vault_id != URL_SAFE_NO_PAD.encode(prepared.key.vault_id())
            || reference.key_epoch != prepared.key.key_epoch().to_string()
            || state
                .current_snapshot_id
                .is_some_and(|id| URL_SAFE_NO_PAD.encode(id) == reference.snapshot_id)
                && state.material.as_ref().is_some_and(|m| {
                    *m.vault_id() == prepared.key.vault_id()
                        && m.key_epoch() == prepared.key.key_epoch()
                })
        {
            return Err("The selected backup is changed or current and protected".into());
        }
        let known = lifecycle::retained_fact(&lease, &state.context_id, reference)?;
        let record = lease
            .sync_backup_provider_intent(state.context_id.clone(), reference.bundle_sha256.clone())
            .map_err(|_| "Protected retry intent is unavailable")?;
        let source = BackupSource::Cached(&catalogue.objects);
        let (snapshot, proof) =
            if let (Some(fact), Some(record)) = (known.as_ref(), record.as_ref()) {
                if aw_sync_e2ee::SnapshotDeletionProofV1::open_record(&prepared.key, record)
                    .ok()
                    .as_ref()
                    != Some(fact)
                {
                    return Err("Retry intent did not authenticate".into());
                }
                let remaining = fact
                    .objects
                    .iter()
                    .filter_map(|o| catalogue.objects.get(&o.object_id).cloned())
                    .collect::<Vec<_>>();
                let proof = aw_sync_e2ee::SnapshotDeletionProofV1::resume(
                    &prepared.key,
                    record,
                    &remaining,
                )
                .map_err(|_| {
                    "Remaining provider copy is absent or changed; refresh its cleanup catalogue"
                })?;
                (
                    EncryptedSyncSnapshotV1 {
                        schema_version: 1,
                        snapshot_id: reference.snapshot_id.clone(),
                        envelopes: remaining,
                    },
                    proof,
                )
            } else {
                let (index, _) = source.catalogue(&state, Some(&prepared.key))?;
                let group = index
                    .groups
                    .iter()
                    .find(|g| g.complete && g.snapshot_id == reference.snapshot_id)
                    .ok_or("Provider copy is incomplete and has no retained sealed intent")?;
                if selection(&prepared.key, group, &catalogue.source_id) != *reference {
                    return Err("Provider backup selection changed".into());
                }
                let (snapshot, _) = bundle(&source, &prepared.key, group)?;
                let proof =
                    aw_sync_e2ee::SnapshotDeletionProofV1::authenticate(&prepared.key, &snapshot)
                        .map_err(|_| "Provider backup did not authenticate")?;
                if known.as_ref().is_some_and(|fact| fact != proof.fact()) {
                    return Err("Provider copy differs from its protected intent".into());
                }
                (snapshot, proof)
            };
        let scope =
            BackupScopeV1::selected_deletion(&proof, &snapshot.envelopes, &reference.source_id)
                .map_err(|_| "Selected cleanup scope is invalid")?;
        Ok((scope, snapshot, proof))
    }
    fn discovery_scope(
        operation: Operation,
        key: &VaultDataKeyV1,
        source: &str,
    ) -> Result<BackupScopeV1, String> {
        if operation == Operation::CleanupList {
            BackupScopeV1::cleanup_discovery(key, source)
        } else {
            BackupScopeV1::discovery(key, source)
        }
        .map_err(|_| "Provider discovery scope is invalid".into())
    }
    pub fn preview(
        &self,
        store: &Datastore,
        proxy: &EgressProxy,
        policy: &VerifiedPolicyV1,
        raw: String,
    ) -> Result<Value, String> {
        let request: PreviewRequest = parse(raw)?;
        let _work = self.work()?;
        context(store, &request.context_id, request.schema_version)?;
        if !matches!(request.operation, Operation::Download | Operation::Delete)
            && request.selection.is_some()
        {
            return Err("Unexpected provider selection".into());
        }
        let prepared = prepare(
            store,
            &request.source_json,
            request.operation == Operation::Upload,
        )?;
        let source_id = match request.operation {
            Operation::List | Operation::CleanupList => format!("relay-{}", token()?),
            Operation::Upload => prepared
                .reference
                .as_ref()
                .ok_or("Select a local backup")?
                .source_id
                .clone(),
            Operation::Download | Operation::Delete => request
                .selection
                .as_ref()
                .ok_or("Select a provider backup")?
                .source_id
                .clone(),
        };
        let expected_selection = if request.operation == Operation::Upload {
            prepared.reference.clone()
        } else {
            request.selection.clone()
        };
        let scope = if matches!(request.operation, Operation::List | Operation::CleanupList) {
            Self::discovery_scope(request.operation, &prepared.key, &source_id)?
        } else {
            self.selected(
                store,
                request.operation,
                expected_selection.as_ref(),
                &request.context_id,
                &request.destination_id,
                &prepared,
            )?
            .0
        };
        let preview = proxy
            .preview_backup(
                policy,
                scope,
                &request.destination_id,
                Utc::now(),
                chrono::Local::now().offset().local_minus_utc(),
            )
            .map_err(|_| "Provider operation is blocked by policy")?;
        let pending = Pending {
            preview,
            operation: request.operation,
            selection: expected_selection,
            context: request.context_id.clone(),
            source_id,
            destination_id: request.destination_id.clone(),
            expires: Utc::now() + Duration::minutes(5),
        };
        prepared.anchor.check(store)?;
        let result = pending.preview.metadata();
        let mut state = self.state(&request.context_id)?;
        if state.previews.len() + state.jobs.len() >= MAX_PENDING {
            return Err("Too many pending provider reviews".into());
        }
        state
            .previews
            .insert(pending.preview.preview_id().into(), pending);
        Ok(result)
    }
    pub fn approve(
        &self,
        store: &Datastore,
        proxy: &EgressProxy,
        policy: &VerifiedPolicyV1,
        raw: String,
    ) -> Result<Value, String> {
        let request: ApproveRequest = parse(raw)?;
        let _work = self.work()?;
        context(store, &request.context_id, request.schema_version)?;
        if !request.user_accepted {
            return Err("Review and accept the provider operation first".into());
        }
        let pending = self
            .state(&request.context_id)?
            .previews
            .remove(&request.preview_id)
            .ok_or("Provider review expired; review again")?;
        let prepared = prepare(
            store,
            &request.source_json,
            pending.operation == Operation::Upload,
        )?;
        let scope = if matches!(pending.operation, Operation::List | Operation::CleanupList) {
            Self::discovery_scope(pending.operation, &prepared.key, &pending.source_id)?
        } else {
            self.selected(
                store,
                pending.operation,
                pending.selection.as_ref(),
                &pending.context,
                &pending.destination_id,
                &prepared,
            )?
            .0
        };
        if !pending.preview.matches_scope(&scope) {
            return Err("Provider source changed; review again".into());
        }
        let permit = proxy
            .approve_backup(
                policy,
                &pending.preview,
                true,
                Utc::now(),
                chrono::Local::now().offset().local_minus_utc(),
            )
            .map_err(|_| "Provider review is stale or blocked")?;
        prepared.anchor.check(store)?;
        let job_id = token()?;
        self.state(&request.context_id)?
            .jobs
            .insert(job_id.clone(), Job { pending, permit });
        Ok(json!({"schema_version":1,"context_id":request.context_id,"job_id":job_id}))
    }
    pub fn run(
        &self,
        store: &Datastore,
        proxy: &EgressProxy,
        policy: &VerifiedPolicyV1,
        raw: String,
    ) -> Result<Value, String> {
        let request: RunRequest = parse(raw)?;
        let _work = self.work()?;
        context(store, &request.context_id, request.schema_version)?;
        let job = self
            .state(&request.context_id)?
            .jobs
            .remove(&request.job_id)
            .ok_or("Provider job expired or already ran")?;
        let prepared = prepare(
            store,
            &request.source_json,
            job.pending.operation == Operation::Upload,
        )?;
        let transport =
            EgressBackupRelayTransportV1::new(proxy.clone(), policy.clone(), job.permit);
        if matches!(
            job.pending.operation,
            Operation::List | Operation::CleanupList
        ) {
            return self.discover(store, &transport, &job.pending, &prepared);
        }
        if job.pending.operation == Operation::Delete {
            let reference = job
                .pending
                .selection
                .as_ref()
                .ok_or("Select a provider copy")?;
            let catalogue =
                self.catalogue(&request.context_id, reference, &job.pending.destination_id)?;
            let (_, snapshot, proof) = self.deletion(store, reference, &catalogue, &prepared)?;
            let record = proof
                .seal(&prepared.key)
                .map_err(|_| "Cleanup intent could not be sealed")?;
            let fact = proof.fact().clone();
            store
                .record_sync_backup_provider_intent(
                    request.context_id.clone(),
                    proof,
                    &prepared.key,
                    record,
                    Utc::now().to_rfc3339(),
                )
                .map_err(|_| "Protected cleanup intent could not be committed")?;
            prepared.anchor.check(store)?;
            let mut deleted = 0usize;
            let mut absent = 0usize;
            let mut unknown = 0usize;
            let mut acknowledged = Vec::new();
            for (index, object) in snapshot.envelopes.iter().enumerate() {
                if prepared.anchor.check(store).is_err() {
                    unknown = snapshot.envelopes.len() - index;
                    break;
                }
                let operation = SyncRelayRequestV1 {
                    schema_version: 1,
                    operation: SyncRelayOperationV1::DeleteSelectedBackup,
                    object_id: Some(object.object_id.clone()),
                    vault_id: Some(object.vault_id.clone()),
                    envelope: Some(object.clone()),
                    cursor: None,
                    limit: None,
                };
                match transport.request(
                    &job.pending.destination_id,
                    aw_models::SYNC_EGRESS_PURPOSE_V1,
                    &operation,
                ) {
                    Ok(response) if response.validate_for(&operation).is_ok() => {
                        if response.deleted == Some(true) {
                            deleted += 1;
                        } else {
                            absent += 1;
                        }
                        acknowledged.push(object.object_id.clone());
                    }
                    _ => {
                        unknown = snapshot.envelopes.len() - index;
                        break;
                    }
                }
            }
            let already_absent = fact.objects.len() - snapshot.envelopes.len();
            absent += already_absent;
            if let Ok(mut state) = self.state(&request.context_id) {
                if let Some(cache) = state.catalogue.as_mut() {
                    if cache.source_id == catalogue.source_id {
                        let objects = Arc::make_mut(&mut cache.objects);
                        for id in acknowledged {
                            objects.remove(&id);
                        }
                    }
                }
            }
            prepared.anchor.check(store)?;
            return Ok(
                json!({"schema_version":1,"context_id":request.context_id,"selection":reference,"copy_scope":"provider","deleted":deleted,"absent":absent,"conflict":0,"failed":0,"unknown":unknown,"durable":false}),
            );
        }
        let (_, snapshot) = self.selected(
            store,
            job.pending.operation,
            job.pending.selection.as_ref(),
            &job.pending.context,
            &job.pending.destination_id,
            &prepared,
        )?;
        let mut downloaded = Vec::new();
        let mut completed = 0usize;
        for object in &snapshot.envelopes {
            prepared.anchor.check(store)?;
            let upload = job.pending.operation == Operation::Upload;
            let operation = SyncRelayRequestV1 {
                schema_version: 1,
                operation: if upload {
                    SyncRelayOperationV1::PutIfAbsent
                } else {
                    SyncRelayOperationV1::Get
                },
                object_id: Some(object.object_id.clone()),
                vault_id: if upload {
                    Some(object.vault_id.clone())
                } else {
                    None
                },
                envelope: if upload { Some(object.clone()) } else { None },
                cursor: None,
                limit: None,
            };
            let response = match transport.request(
                &job.pending.destination_id,
                aw_models::SYNC_EGRESS_PURPOSE_V1,
                &operation,
            ) {
                Ok(response) => response,
                Err(_) => {
                    return Ok(
                        json!({"schema_version":1,"context_id":request.context_id,"status":"partial","completed_objects":completed,"object_count":snapshot.envelopes.len(),"local_selection":null}),
                    )
                }
            };
            response
                .validate_for(&operation)
                .map_err(|_| "Provider response is invalid")?;
            if !upload {
                let Some(envelope) = response.envelope else {
                    return Ok(
                        json!({"schema_version":1,"context_id":request.context_id,"status":"partial","completed_objects":completed,"object_count":snapshot.envelopes.len(),"local_selection":null}),
                    );
                };
                downloaded.push(envelope);
            }
            completed += 1;
        }
        prepared.anchor.check(store)?;
        let local = if job.pending.operation == Operation::Download {
            let snapshot = EncryptedSyncSnapshotV1 {
                schema_version: 1,
                snapshot_id: snapshot.snapshot_id,
                envelopes: downloaded,
            };
            summary(crate::sync_control::decrypt_recovery_snapshot(
                &prepared.key,
                &snapshot,
            )?)?;
            store
                .stage_sync_backup_objects(
                    request.context_id.clone(),
                    snapshot.envelopes.clone(),
                    Utc::now().to_rfc3339(),
                )
                .map_err(|_| "Downloaded backup could not be staged atomically")?;
            let mut builder = SnapshotIndexBuilderV1::new(&prepared.key);
            for object in &snapshot.envelopes {
                builder
                    .push(object)
                    .map_err(|_| "Downloaded backup is invalid")?;
            }
            let index = builder
                .finish()
                .map_err(|_| "Downloaded backup is invalid")?;
            Some(selection(&prepared.key, &index.groups[0], "local"))
        } else {
            None
        };
        Ok(
            json!({"schema_version":1,"context_id":request.context_id,"status":"complete","completed_objects":completed,"object_count":snapshot.envelopes.len(),"local_selection":local}),
        )
    }
    fn discover(
        &self,
        store: &Datastore,
        transport: &EgressBackupRelayTransportV1,
        pending: &Pending,
        prepared: &Prepared,
    ) -> Result<Value, String> {
        let mut objects = BTreeMap::new();
        let mut bytes = 0usize;
        let mut cursor = None;
        loop {
            prepared.anchor.check(store)?;
            let request = SyncRelayRequestV1 {
                schema_version: 1,
                operation: SyncRelayOperationV1::ListOpaqueHeads,
                object_id: None,
                vault_id: Some(URL_SAFE_NO_PAD.encode(prepared.key.vault_id())),
                envelope: None,
                cursor: cursor.clone(),
                limit: Some(16),
            };
            let response = transport
                .request(
                    &pending.destination_id,
                    aw_models::SYNC_EGRESS_PURPOSE_V1,
                    &request,
                )
                .map_err(|_| "Provider discovery failed; no catalogue was published")?;
            response
                .validate_for(&request)
                .map_err(|_| "Provider catalogue is invalid")?;
            for object in response.objects {
                bytes = bytes
                    .checked_add(
                        serde_json::to_vec(&object)
                            .map_err(|_| "Provider object is invalid")?
                            .len(),
                    )
                    .ok_or("Provider catalogue exceeds its limits")?;
                if objects.len() >= MAX_BACKUP_SCAN_OBJECTS || bytes > MAX_BACKUP_SCAN_BYTES {
                    return Err("Provider catalogue exceeds its limits".into());
                }
                if objects.insert(object.object_id.clone(), object).is_some() {
                    return Err("Provider catalogue contains duplicate objects".into());
                }
            }
            match response.next_cursor {
                None => break,
                Some(next) => {
                    if cursor.as_ref().is_some_and(|old| &next <= old)
                        || objects
                            .last_key_value()
                            .is_none_or(|(last, _)| last != &next)
                    {
                        return Err("Provider cursor is invalid".into());
                    }
                    cursor = Some(next);
                }
            }
        }
        let source = BackupSource::Cached(&objects);
        let lease = store
            .egress_lease()
            .map_err(|_| "Unlock the encrypted vault")?;
        let state = lease
            .sync_backup_source()
            .map_err(|_| "Backup source is unavailable")?;
        drop(lease);
        let (index, namespaces) = source.catalogue(&state, Some(&prepared.key))?;
        let lease = store
            .egress_lease()
            .map_err(|_| "Unlock the encrypted vault")?;
        let facts = lease
            .export_sync_backup_deletions(pending.context.clone())
            .map_err(|_| "Protected cleanup history is unavailable")?;
        drop(lease);
        let vault = URL_SAFE_NO_PAD.encode(prepared.key.vault_id());
        let epoch = prepared.key.key_epoch().to_string();
        let facts: BTreeMap<_, _> = facts
            .iter()
            .filter(|f| f.vault_id == vault && f.key_epoch == epoch)
            .map(|f| (f.snapshot_id.as_str(), f))
            .collect();
        let mut versions = Vec::new();
        let mut listed = std::collections::BTreeSet::new();
        for group in &index.groups {
            listed.insert(group.snapshot_id.as_str());
            let details = if group.complete {
                bundle(&source, &prepared.key, group)
                    .and_then(|(_, recovery)| summary(recovery))
                    .ok()
            } else {
                None
            };
            let current = state
                .current_snapshot_id
                .is_some_and(|id| URL_SAFE_NO_PAD.encode(id) == group.snapshot_id)
                && state.material.as_ref().is_some_and(|m| {
                    *m.vault_id() == prepared.key.vault_id()
                        && m.key_epoch() == prepared.key.key_epoch()
                });
            let known = facts.get(group.snapshot_id.as_str()).copied();
            let deletion = if current {
                None
            } else if let Some(fact) = known {
                Some(lifecycle::reference_for_fact(fact, &pending.source_id))
            } else if details.is_some() {
                Some(selection(&prepared.key, group, &pending.source_id))
            } else {
                None
            };
            let mut row = json!({"snapshot_id":group.snapshot_id,"key_epoch":prepared.key.key_epoch().to_string(),"object_count":group.object_ids.len(),"observed_object_count":group.object_ids.len(),"declared_object_count":group.declared_object_count,
                "status":if known.is_some(){"forgotten"}else if details.is_some(){"authenticated"}else if group.complete{"invalid_recovery"}else{"incomplete"},"current":current,"deletion_selection":deletion,"selection":if details.is_some()&&known.is_none()&&pending.operation!=Operation::CleanupList{Some(selection(&prepared.key,group,&pending.source_id))}else{None},"event_count":null,"query_start":null,"query_end":null,"policy_continuity_present":null});
            if let Some(fact) = known {
                row["object_count"] = json!(fact.objects.len());
            }
            if let Some(details) = details {
                row.as_object_mut()
                    .unwrap()
                    .extend(details.as_object().unwrap().clone());
            }
            versions.push(row);
        }
        for (id, fact) in &facts {
            if listed.contains(id) {
                continue;
            }
            versions.push(json!({"snapshot_id":fact.snapshot_id,"key_epoch":fact.key_epoch,"object_count":fact.objects.len(),"observed_object_count":0,"declared_object_count":null,"status":"forgotten","current":false,"selection":null,"deletion_selection":null,"event_count":null,"query_start":null,"query_end":null,"policy_continuity_present":null}));
        }
        if versions.len() > MAX_BACKUP_SCAN_OBJECTS
            || serde_json::to_vec(&versions)
                .map_err(|_| "Provider catalogue is invalid")?
                .len()
                > 32 * 1024 * 1024
        {
            return Err("Provider catalogue exceeds its metadata limits".into());
        }
        prepared.anchor.check(store)?;
        self.state(&pending.context)?.catalogue = Some(Catalogue {
            context: pending.context.clone(),
            source_id: pending.source_id.clone(),
            destination_id: pending.destination_id.clone(),
            expires: pending.expires,
            objects: Arc::new(objects),
            cleanup_only: pending.operation == Operation::CleanupList,
        });
        Ok(
            json!({"schema_version":1,"context_id":pending.context,"source_id":pending.source_id,"vault_id":URL_SAFE_NO_PAD.encode(prepared.key.vault_id()),"key_epoch":prepared.key.key_epoch().to_string(),
            "requires_recovery_kit":false,"cleanup_only":pending.operation==Operation::CleanupList,"namespaces":namespaces,"versions":versions,"invalid_object_count":index.invalid_objects.len(),"operation_object_count":index.operation_objects}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn provider_catalogue_expiry_and_worker_change_release_ciphertext_cache() {
        let workflow = BackupWorkflowV1::new();
        let cache = Arc::new(BTreeMap::new());
        let cached = |expires| Catalogue {
            context: "a".into(),
            source_id: "relay-fixture".into(),
            destination_id: "fixture".into(),
            expires,
            objects: cache.clone(),
            cleanup_only: false,
        };
        workflow.state("a").unwrap().catalogue = Some(cached(Utc::now() + Duration::minutes(1)));
        assert!(workflow.state("a").unwrap().catalogue.is_some());
        workflow.state("a").unwrap().catalogue = Some(cached(Utc::now() - Duration::seconds(1)));
        assert!(workflow.state("a").unwrap().catalogue.is_none());
        workflow.state("a").unwrap().catalogue = Some(cached(Utc::now() + Duration::minutes(1)));
        assert!(workflow.state("b").unwrap().catalogue.is_none());
        assert_eq!(Arc::strong_count(&cache), 1);
    }
}
