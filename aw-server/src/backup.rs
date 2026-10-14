//! Read-only authenticated backup selection; restoring a target is a separate workflow.
use aw_datastore::{Datastore, EgressLease, SyncBackupSourceStateV1, SyncKeyMaterial};
use aw_models::RecoveryKitV1;
use aw_sync_e2ee::{
    open_recovery_kit, unwrap_vault_data_key, AccountRootKeyV1, EncryptedSyncSnapshotV1,
    FolderSyncObjectStoreV1, SnapshotIndexBuilderV1, SnapshotObjectGroupV1, SnapshotObjectIndexV1,
    SyncObjectStoreErrorV1, SyncObjectStoreV1, VaultDataKeyV1, WrappedVaultDataKeyV1,
    MAX_BACKUP_BUNDLE_BYTES, MAX_BACKUP_SCAN_OBJECTS,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zeroize::{Zeroize, Zeroizing};

const MAX_BACKUP_CONTROL_BYTES: usize = 64 * 1024;

mod lifecycle;
mod folder_io;
pub use folder_io::{FolderBackupDeletionV1,BackupCopyDeletionV1};
mod provider;
pub use provider::BackupWorkflowV1;

struct ObjectRecord<T>(T);
impl<'de, T: Deserialize<'de>> Deserialize<'de> for ObjectRecord<T> {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Record<T>(std::marker::PhantomData<T>);
        impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for Record<T> {
            type Value = ObjectRecord<T>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                map: M,
            ) -> Result<Self::Value, M::Error> {
                T::deserialize(serde::de::value::MapAccessDeserializer::new(map)).map(ObjectRecord)
            }
        }
        d.deserialize_map(Record(std::marker::PhantomData))
    }
}
fn optional_record<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    Option::<ObjectRecord<T>>::deserialize(d).map(|value| value.map(|record| record.0))
}
fn required_record<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<T, D::Error> {
    ObjectRecord::<T>::deserialize(d).map(|record| record.0)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Invocation {
    #[serde(rename = "requestJson")]
    request_json: String,
}
impl Drop for Invocation {
    fn drop(&mut self) {
        self.request_json.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryCredentials {
    #[serde(deserialize_with = "required_record")]
    kit: RecoveryKitV1,
    phrase: String,
}
impl Drop for RecoveryCredentials {
    fn drop(&mut self) {
        self.phrase.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupRequest {
    schema_version: u32,
    source_id: String,
    context_id: String,
    #[serde(default, deserialize_with = "optional_record")]
    recovery: Option<RecoveryCredentials>,
    #[serde(default, deserialize_with = "optional_record")]
    selection: Option<BackupSelectionV1>,
    folder_path: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BackupSelectionV1 {
    pub schema_version: u32,
    pub source_id: String,
    pub vault_id: String,
    pub key_epoch: String,
    pub snapshot_id: String,
    pub object_count: usize,
    pub bundle_sha256: String,
}

pub struct SelectedBackupRestoreInputV1 {
    pub kit: RecoveryKitV1,
    pub phrase: Zeroizing<String>,
    pub snapshot: EncryptedSyncSnapshotV1,
    pub target_context_id: String,
}

/// Keeps the encrypted bundle and full-u64 values inside Rust instead of sending it through JS.
pub fn selected_restore_input(
    store: &Datastore,
    request_json: String,
) -> Result<SelectedBackupRestoreInputV1, String> {
    let input = Invocation { request_json };
    if input.request_json.len() > MAX_BACKUP_CONTROL_BYTES {
        return Err("Backup request exceeds64KiB".into());
    }
    let request = serde_json::from_str::<ObjectRecord<BackupRequest>>(&input.request_json)
        .map_err(|_| "Selected restore request is invalid or ambiguous")?
        .0;
    let recovery = request
        .recovery
        .as_ref()
        .ok_or("A matching recovery kit is required for restore")?;
    let raw = invoke(
        store,
        "export_selected_sync_backup",
        json!({"requestJson":input.request_json.clone()}),
    )?;
    let snapshot = serde_json::from_str(raw.as_str().ok_or("Selected backup export is invalid")?)
        .map_err(|_| "Selected backup export is invalid")?;
    Ok(SelectedBackupRestoreInputV1 {
        kit: recovery.kit.clone(),
        phrase: Zeroizing::new(recovery.phrase.clone()),
        snapshot,
        target_context_id: request.context_id,
    })
}

impl BackupSelectionV1 {
    fn validate(&self) -> Result<(), String> {
        let epoch = self
            .key_epoch
            .parse::<u64>()
            .map_err(|_| "Backup epoch is invalid")?;
        if self.schema_version != 1
            || !(self.source_id == "local"
                || self.source_id.strip_prefix("folder-").is_some_and(hex64))
            || epoch == 0
            || epoch.to_string() != self.key_epoch
            || self.object_count == 0
            || self.object_count > MAX_BACKUP_SCAN_OBJECTS
            || !opaque_id(&self.vault_id)
            || !opaque_id(&self.snapshot_id)
            || !hex64(&self.bundle_sha256)
        {
            return Err("Backup selection is invalid".into());
        }
        Ok(())
    }
}

fn opaque_id(value: &str) -> bool {
    URL_SAFE_NO_PAD
        .decode(value)
        .is_ok_and(|bytes| bytes.len() == 16 && URL_SAFE_NO_PAD.encode(bytes) == value)
}
fn hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn key_from_material(material: &SyncKeyMaterial) -> Result<VaultDataKeyV1, String> {
    let root = AccountRootKeyV1::from_bytes(Zeroizing::new(*material.account_root_key()));
    unwrap_vault_data_key(
        &root,
        &WrappedVaultDataKeyV1 {
            schema_version: 1,
            vault_id: URL_SAFE_NO_PAD.encode(material.vault_id()),
            key_epoch: material.key_epoch(),
            nonce: URL_SAFE_NO_PAD.encode(material.wrapped_nonce()),
            ciphertext: URL_SAFE_NO_PAD.encode(material.wrapped_ciphertext()),
        },
    )
    .map_err(|_| "Backup source keys did not authenticate".into())
}

fn source_key(
    state: &SyncBackupSourceStateV1,
    recovery: Option<&RecoveryCredentials>,
) -> Result<Option<VaultDataKeyV1>, String> {
    if let Some(credentials) = recovery {
        let keys = open_recovery_kit(&credentials.kit, &credentials.phrase)
            .map_err(|_| "Recovery kit or phrase did not authenticate")?;
        return unwrap_vault_data_key(&keys.account_root_key, &keys.wrapped_vault_key)
            .map(Some)
            .map_err(|_| "Recovery key did not authenticate".into());
    }
    state.material.as_ref().map(key_from_material).transpose()
}

fn key_binding(material: Option<&SyncKeyMaterial>) -> Option<[u8; 32]> {
    material.map(|key| {
        let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
        hash.update(b"PeakActivity-Backup-Local-Anchor-v1\0");
        hash.update(key.account_root_key());
        hash.update(key.vault_id());
        hash.update(&key.key_epoch().to_be_bytes());
        hash.update(key.wrapped_nonce());
        hash.update(key.wrapped_ciphertext());
        hash.finish().as_ref().try_into().unwrap()
    })
}

fn check_source(lease: &EgressLease<'_>, original: &SyncBackupSourceStateV1) -> Result<(), String> {
    let current = lease
        .sync_backup_source()
        .map_err(|_| "Backup source is unavailable")?;
    if current.context_id != original.context_id
        || current.current_snapshot_id != original.current_snapshot_id
        || key_binding(current.material.as_ref()) != key_binding(original.material.as_ref())
    {
        return Err("Backup source changed; refresh the catalogue".into());
    }
    Ok(())
}

enum BackupSource<'lease, 'worker> {
    Local(&'lease EgressLease<'worker>),
    Folder(FolderSyncObjectStoreV1),
    Cached(&'lease std::collections::BTreeMap<String,aw_models::SyncEnvelopeV1>),
}

impl BackupSource<'_, '_> {
    fn object(&self, id: &str) -> Result<Option<aw_models::SyncEnvelopeV1>, String> {
        match self {
            Self::Local(lease) => lease
                .sync_backup_object(id.into())
                .map_err(|_| "Selected backup object is unavailable".into()),
            Self::Folder(folder) => folder
                .get(id)
                .map_err(|_| "Selected folder backup object is unavailable".into()),
            Self::Cached(objects)=>Ok(objects.get(id).cloned()),
        }
    }

    fn catalogue(
        &self,
        state: &SyncBackupSourceStateV1,
        key: Option<&VaultDataKeyV1>,
    ) -> Result<(SnapshotObjectIndexV1, Vec<Value>), String> {
        match self {
            Self::Local(lease)=>Ok((key.map(|key|scan_local(lease,key)).transpose()?.unwrap_or_default(),
                state.namespaces.iter().map(|ns|json!({"vault_id":ns.vault_id,"key_epoch":ns.key_epoch.to_string(),"object_count":ns.object_count})).collect())),
            Self::Folder(folder)=> {
                let mut namespaces=std::collections::BTreeMap::new();
                let mut builder=key.map(SnapshotIndexBuilderV1::new);
                folder.visit_backup_objects(|object| {
                    *namespaces.entry((object.vault_id.clone(),object.key_epoch)).or_insert(0usize)+=1;
                    if let (Some(key),Some(builder))=(key,builder.as_mut()) {
                        if object.vault_id==URL_SAFE_NO_PAD.encode(key.vault_id()) {
                            builder.push(object).map_err(|_|SyncObjectStoreErrorV1::CorruptObject)?;
                        }
                    }
                    Ok(())
                }).map_err(|_|"Folder backup scan is unavailable, corrupt or exceeds its limits")?;
                Ok((builder.map(SnapshotIndexBuilderV1::finish).transpose().map_err(|_|"Folder backup scan did not complete")?.unwrap_or_default(),
                    namespaces.into_iter().map(|((vault_id,epoch),count)|json!({"vault_id":vault_id,"key_epoch":epoch.to_string(),"object_count":count})).collect()))
            }
            Self::Cached(objects)=> {
                let mut builder=key.map(SnapshotIndexBuilderV1::new);
                let mut namespaces=std::collections::BTreeMap::new();
                for object in objects.values() {
                    *namespaces.entry((object.vault_id.clone(),object.key_epoch)).or_insert(0usize)+=1;
                    if let (Some(key),Some(builder))=(key,builder.as_mut()) {
                        if object.vault_id==URL_SAFE_NO_PAD.encode(key.vault_id()) {builder.push(object).map_err(|_|"Cached backup is corrupt")?;}
                    }
                }
                Ok((builder.map(SnapshotIndexBuilderV1::finish).transpose().map_err(|_|"Cached backup is corrupt")?.unwrap_or_default(),
                    namespaces.into_iter().map(|((vault,epoch),count)|json!({"vault_id":vault,"key_epoch":epoch.to_string(),"object_count":count})).collect()))
            }
        }
    }
}

fn scan_local(
    lease: &EgressLease<'_>,
    key: &VaultDataKeyV1,
) -> Result<SnapshotObjectIndexV1, String> {
    let mut builder = SnapshotIndexBuilderV1::new(key);
    let mut cursor = None;
    loop {
        let page = lease
            .sync_backup_objects(URL_SAFE_NO_PAD.encode(key.vault_id()), cursor.clone(), 64)
            .map_err(|_| "Backup objects could not be read")?;
        for object in &page.objects {
            builder
                .push(object)
                .map_err(|_| "Backup scan is corrupt or exceeds its limits")?;
        }
        match page.next_cursor {
            None => break,
            Some(next) => cursor = Some(next),
        }
    }
    builder
        .finish()
        .map_err(|_| "Backup scan did not complete".into())
}

fn bundle(
    source: &BackupSource<'_, '_>,
    key: &VaultDataKeyV1,
    group: &SnapshotObjectGroupV1,
) -> Result<
    (
        EncryptedSyncSnapshotV1,
        crate::sync_control::SyncRecoverySnapshotV1,
    ),
    String,
> {
    if !group.complete {
        return Err("Backup chunks are incomplete".into());
    }
    let mut envelopes = Vec::new();
    let mut bytes = 0usize;
    let mut check = SnapshotIndexBuilderV1::new(key);
    for id in &group.object_ids {
        let object = source
            .object(id)?
            .ok_or("Selected backup object is missing")?;
        bytes = bytes
            .checked_add(
                serde_json::to_vec(&object)
                    .map_err(|_| "Backup object could not be encoded")?
                    .len(),
            )
            .ok_or("Backup bundle limit exceeded")?;
        if bytes > MAX_BACKUP_BUNDLE_BYTES {
            return Err("Backup bundle exceeds256MiB".into());
        }
        check
            .push(&object)
            .map_err(|_| "Selected backup object did not authenticate")?;
        envelopes.push(object);
    }
    let verified = check
        .finish()
        .map_err(|_| "Selected backup did not authenticate")?;
    if verified.groups.len() != 1
        || verified.groups[0].snapshot_id != group.snapshot_id
        || !verified.groups[0].complete
        || verified.groups[0].bundle_sha256 != group.bundle_sha256
    {
        return Err("Selected backup changed; refresh the catalogue".into());
    }
    let snapshot = EncryptedSyncSnapshotV1 {
        schema_version: 1,
        snapshot_id: group.snapshot_id.clone(),
        envelopes,
    };
    let recovery = crate::sync_control::decrypt_recovery_snapshot(key, &snapshot)?;
    Ok((snapshot, recovery))
}

fn summary(recovery: crate::sync_control::SyncRecoverySnapshotV1) -> Result<Value, String> {
    let mut count = 0usize;
    let mut start = None;
    let mut end = None;
    for bucket in recovery.activity.buckets.into_values() {
        if let Some(events) = bucket.events {
            let (events, skipped) = events.take_inner_with_skipped();
            if skipped != 0 {
                return Err("Backup contains invalid activity records".into());
            }
            for event in events {
                count = count
                    .checked_add(1)
                    .ok_or("Backup activity count overflow")?;
                if start.is_none_or(|at| event.timestamp < at) {
                    start = Some(event.timestamp);
                }
                if end.is_none_or(|at| event.timestamp > at) {
                    end = Some(event.timestamp);
                }
            }
        }
    }
    Ok(
        json!({"event_count":count,"query_start":start.map(|at|at.to_rfc3339()),"query_end":end.map(|at|at.to_rfc3339()),
        "policy_continuity_present":recovery.sync.policy.is_some()}),
    )
}

fn selection(
    key: &VaultDataKeyV1,
    group: &SnapshotObjectGroupV1,
    source_id: &str,
) -> BackupSelectionV1 {
    BackupSelectionV1 {
        schema_version: 1,
        source_id: source_id.into(),
        vault_id: URL_SAFE_NO_PAD.encode(key.vault_id()),
        key_epoch: key.key_epoch().to_string(),
        snapshot_id: group.snapshot_id.clone(),
        object_count: group.object_ids.len(),
        bundle_sha256: group.bundle_sha256.clone().unwrap(),
    }
}

pub fn invoke(store: &Datastore, command: &str, args: Value) -> Result<Value, String> {
    if matches!(command,"preview_sync_backup_delete"|"delete_selected_sync_backup"){return lifecycle::invoke(store,command,args);}
    let input = serde_json::from_value::<ObjectRecord<Invocation>>(args)
        .map_err(|_| "Backup request arguments are invalid")?
        .0;
    if input.request_json.len() > MAX_BACKUP_CONTROL_BYTES {
        return Err("Backup request exceeds64KiB".into());
    }
    let request = serde_json::from_str::<ObjectRecord<BackupRequest>>(&input.request_json)
        .map_err(|_| "Backup request is invalid or ambiguous")?
        .0;
    if request.schema_version != 1
        || !matches!(request.source_id.as_str(), "local" | "folder")
        || (request.source_id == "local" && request.folder_path.is_some())
        || (request.source_id == "folder"
            && request
                .folder_path
                .as_ref()
                .is_none_or(|path| path.is_empty()))
        || !hex64(&request.context_id)
        || (command == "list_sync_backups" && request.selection.is_some())
    {
        return Err("Backup request is invalid".into());
    }
    if !store.is_encrypted() {
        return Err("Unlock the encrypted vault to browse backups".into());
    }
    // Use only the captured request channel while this guard is held; nested worker reads can deadlock.
    let lease = store
        .egress_lease()
        .map_err(|_| "Unlock the encrypted vault to browse backups")?;
    let state = lease
        .sync_backup_source()
        .map_err(|_| "Backup source is unavailable")?;
    if request.context_id != state.context_id {
        return Err("Backup source changed; refresh the catalogue".into());
    }
    let key = source_key(&state, request.recovery.as_ref())?;
    let source = if request.source_id == "local" {
        BackupSource::Local(&lease)
    } else {
        BackupSource::Folder(
            FolderSyncObjectStoreV1::open_readonly(request.folder_path.as_ref().unwrap())
                .map_err(|_| "Choose an existing safe backup folder")?,
        )
    };
    let source_id = match &source {
        BackupSource::Local(_) => "local".into(),
        BackupSource::Folder(folder) => folder.backup_source_id(&state.context_id),
        BackupSource::Cached(_)=>unreachable!(),
    };
    let (index, namespaces) = source.catalogue(&state, key.as_ref())?;
    let Some(key) = key else {
        if command != "list_sync_backups" {
            return Err("A matching recovery kit is required".into());
        }
        check_source(&lease, &state)?;
        return Ok(
            json!({"schema_version":1,"source_id":source_id,"context_id":state.context_id,
            "vault_id":null,"key_epoch":null,"requires_recovery_kit":true,"namespaces":namespaces,
            "versions":[],"invalid_object_count":0,"operation_object_count":0}),
        );
    };
    if command == "export_selected_sync_backup" {
        let reference = request
            .selection
            .as_ref()
            .ok_or("Select an authenticated backup first")?;
        reference.validate()?;
        let group = index
            .groups
            .iter()
            .find(|group| group.snapshot_id == reference.snapshot_id && group.complete)
            .ok_or("Selected backup is missing or incomplete")?;
        if reference != &selection(&key, group, &source_id) {
            return Err("Selected backup changed; refresh the catalogue".into());
        }
        lease.ensure_sync_backup_not_deleted(state.context_id.clone(),reference.vault_id.clone(),key.key_epoch(),reference.snapshot_id.clone(),group.object_ids.clone()).map_err(|_|"Selected backup is marked deleted and cannot be exported or restored")?;
        let (snapshot, recovery) = bundle(&source, &key, group)?;
        summary(recovery)?;
        let output = serde_json::to_string(&snapshot)
            .map_err(|_| "Selected encrypted backup could not be encoded")?;
        check_source(&lease, &state)?;
        return Ok(Value::String(output));
    }
    if command != "list_sync_backups" {
        return Err("Backup operation is unavailable".into());
    }
    let forgotten=lease.export_sync_backup_deletions(state.context_id.clone()).map_err(|_|"Protected backup deletion history could not be read")?;
    let vault=URL_SAFE_NO_PAD.encode(key.vault_id());let epoch=key.key_epoch().to_string();
    let forgotten:std::collections::BTreeMap<_,_>=forgotten.iter().filter(|f|f.vault_id==vault&&f.key_epoch==epoch).map(|f|(f.snapshot_id.as_str(),f)).collect();
    let mut listed=std::collections::BTreeSet::new();
    let mut versions = Vec::new();
    for group in &index.groups {
        listed.insert(group.snapshot_id.as_str());
        let known=forgotten.get(group.snapshot_id.as_str()).copied();
        let deleted=known.is_some();
        let current=state.current_snapshot_id.is_some_and(|id|URL_SAFE_NO_PAD.encode(id)==group.snapshot_id)&&state.material.as_ref().is_some_and(|m|*m.vault_id()==key.vault_id()&&m.key_epoch()==key.key_epoch());
        let authenticated = if group.complete {
            bundle(&source, &key, group)
                .and_then(|(_, recovery)| summary(recovery))
                .ok()
        } else {
            None
        };
        let ready = authenticated.is_some() && !deleted;
        let mut row = json!({"snapshot_id":group.snapshot_id,"key_epoch":key.key_epoch().to_string(),
            "object_count":group.object_ids.len(),"observed_object_count":group.object_ids.len(),"declared_object_count":group.declared_object_count,
            "status":if deleted {"forgotten"}else if ready {"authenticated"} else if group.complete {"invalid_recovery"} else {"incomplete"},
            "selection":if ready {Some(selection(&key,group,&source_id))} else {None},
            "current":current,"deletion_selection":if !current&&authenticated.is_some(){Some(known.map(|fact|lifecycle::reference_for_fact(fact,&source_id)).unwrap_or_else(||selection(&key,group,&source_id)))}else{None},
            "event_count":null,"query_start":null,"query_end":null,"policy_continuity_present":null});
        if let Some(fact)=known {
            row["object_count"]=json!(fact.objects.len());
            if !current && request.source_id=="folder" {
                let safe=FolderBackupDeletionV1::open_existing(request.folder_path.as_ref().unwrap())?.load_intent(&key,&fact.bundle_sha256)?.is_some_and(|record|aw_sync_e2ee::SnapshotDeletionProofV1::open_record(&key,&record).ok().as_ref()==Some(fact));
                if safe {
                    row["deletion_selection"]=json!(lifecycle::reference_for_fact(fact,&source_id));
                    row["observed_object_count"]=json!(FolderBackupDeletionV1::open_existing(request.folder_path.as_ref().unwrap())?.remaining(fact)?.len());
                }
            }
        }
        if let Some(summary) = authenticated {
            row.as_object_mut()
                .unwrap()
                .extend(summary.as_object().unwrap().clone());
        }
        versions.push(row);
    }
    for (id,fact) in &forgotten {
        if listed.contains(id){continue;}
        let (retry,observed)=if request.source_id=="folder" {
            let folder=FolderBackupDeletionV1::open_existing(request.folder_path.as_ref().unwrap())?;
            let record=folder.load_intent(&key,&fact.bundle_sha256)?;
            let retry=record.is_some_and(|record|aw_sync_e2ee::SnapshotDeletionProofV1::open_record(&key,&record).ok().as_ref()==Some(fact));
            (retry,if retry{folder.remaining(fact)?.len()}else{0})
        }else{(true,0)};
        if retry {versions.push(json!({"snapshot_id":fact.snapshot_id,"key_epoch":fact.key_epoch,"object_count":fact.objects.len(),"observed_object_count":observed,"declared_object_count":null,"status":"forgotten","selection":null,"current":false,"deletion_selection":lifecycle::reference_for_fact(fact,&source_id),"event_count":null,"query_start":null,"query_end":null,"policy_continuity_present":null}));}
    }
    if versions.len()>MAX_BACKUP_SCAN_OBJECTS || serde_json::to_vec(&versions).map_err(|_|"Backup catalogue is invalid")?.len()>32*1024*1024 {return Err("Backup catalogue exceeds its metadata limits".into());}
    check_source(&lease, &state)?;
    Ok(
        json!({"schema_version":1,"source_id":source_id,"context_id":state.context_id,
        "vault_id":URL_SAFE_NO_PAD.encode(key.vault_id()),"key_epoch":key.key_epoch().to_string(),
        "requires_recovery_kit":false,"namespaces":namespaces,"versions":versions,
        "invalid_object_count":index.invalid_objects.len(),"operation_object_count":index.operation_objects}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_anchor_rejects_pointer_and_key_changes_within_same_worker() {
        let store = Datastore::open_encrypted(":memory:".into(), "a".repeat(64)).unwrap();
        let root = aw_sync_e2ee::generate_account_root_key().unwrap();
        let (key, wrapped) =
            aw_sync_e2ee::create_vault_data_key(&root, &URL_SAFE_NO_PAD.encode([0x71; 16]), 1)
                .unwrap();
        let material = SyncKeyMaterial::new(
            root.secret_for_storage(),
            [0x71; 16],
            1,
            URL_SAFE_NO_PAD
                .decode(wrapped.nonce)
                .unwrap()
                .try_into()
                .unwrap(),
            URL_SAFE_NO_PAD
                .decode(wrapped.ciphertext)
                .unwrap()
                .try_into()
                .unwrap(),
        );
        store.install_sync_key_material(&material).unwrap();
        let snapshot = aw_sync_e2ee::encrypt_snapshot(&key, b"fixture").unwrap();
        let snapshot = aw_datastore::SyncSnapshotV1::new(
            URL_SAFE_NO_PAD
                .decode(snapshot.snapshot_id)
                .unwrap()
                .try_into()
                .unwrap(),
            snapshot.envelopes,
        );
        let lease = store.egress_lease().unwrap();
        let original = lease.sync_backup_source().unwrap();
        check_source(&lease, &original).unwrap();
        let writer = store.clone();
        std::thread::spawn(move || writer.save_sync_snapshot(material, snapshot).unwrap())
            .join()
            .unwrap();
        assert_eq!(
            lease.sync_backup_source().unwrap().context_id,
            original.context_id
        );
        assert!(check_source(&lease, &original).is_err());
        let current = lease.sync_backup_source().unwrap();
        let changed =
            SyncKeyMaterial::new(Zeroizing::new([8; 32]), [0x71; 16], 1, [7; 24], [6; 48]);
        assert_ne!(
            key_binding(current.material.as_ref()),
            key_binding(Some(&changed))
        );
        drop(lease);
        store.close();
    }
}
