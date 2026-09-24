//! Platform-neutral local E2EE controls shared by Android and desktop command adapters.
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::collections::{BTreeMap, VecDeque};

use aw_datastore::{
    Datastore, DatastoreError, SyncApplyBatchV1, SyncBaselineProgressV1,
    SyncDeviceIdentity, SyncHeadCommitV1, SyncKeyMaterial, SyncManifestHeadV1,
    SyncRecoveryStateV1, SyncRecoveryTrustedDeviceV1, SyncSnapshotV1,
};
use aw_models::{
    BucketsExport, DevicePublicIdentityV1, SyncChunkHeaderV1, SyncEnvelopeV1,
    SyncOperationKindV1, SYNC_SCHEMA_VERSION_V1,
};
use aw_sync_e2ee::{
    accept_key_transfer, begin_pairing, complete_pairing,
    create_key_transfer,
    create_recovery_kit as make_recovery_kit, create_vault_data_key,
    decrypt_chunk, decrypt_manifest, decrypt_snapshot, derive_pairing_session, encrypt_manifest,
    encrypt_snapshot, generate_account_root_key, generate_device_identity, inspect_snapshot_chunk, open_recovery_kit, respond_to_pairing,
    rotate_account_and_vault_key, pending_tombstone_ack_device_ids, unwrap_vault_data_key,
    AccountRootKeyV1, DeviceIdentityV1, EncryptedKeyTransferV1,
    PairingConfirmationV1, PairingEphemeralKeyV1, PairingInvitationV1, PairingOfferV1,
    PairingResponseV1, PairingSessionV1, RecoveryKitV1,
    VaultDataKeyV1, WrappedVaultDataKeyV1, EncryptedSyncSnapshotV1,
    SyncManifestV1, SyncObjectStoreErrorV1, SyncObjectStoreV1, SyncOperationV1,
    SyncTombstoneAckV1,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::digest::{digest, SHA256};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value};
use zeroize::Zeroizing;

pub struct SyncControl {
    recovery_kit_pending: AtomicBool,
    pairing: Mutex<Option<PendingPairing>>,
}

struct PendingPairing {
    identity: DeviceIdentityV1,
    invitation: PairingInvitationV1,
    recipient: bool,
    ephemeral: Option<PairingEphemeralKeyV1>,
    offer: Option<PairingOfferV1>,
    session: Option<PairingSessionV1>,
}

const MAX_SYNC_OBJECT_SCAN: usize = 100_000;
const MAX_MANIFESTS_PER_CYCLE: usize = 64;
const MAX_OPERATIONS_PER_MANIFEST: usize = 64;
const MAX_TOMBSTONE_ACKS_PER_MANIFEST: usize = 64;
// ponytail: retain signed manifests until cross-device tombstone ACKs are replicated; add bounded GC once that proof path exists.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncRunError {
    pub retryable: bool,
}

impl SyncRunError {
    fn denied() -> Self { Self { retryable: false } }
    fn temporary() -> Self { Self { retryable: true } }
}

impl From<&str> for SyncRunError {
    fn from(_: &str) -> Self { Self::denied() }
}

impl From<String> for SyncRunError {
    fn from(_: String) -> Self { Self::denied() }
}

fn sync_datastore_error(error: DatastoreError) -> SyncRunError {
    match error {
        DatastoreError::Locked | DatastoreError::MpscError => SyncRunError::temporary(),
        _ => SyncRunError::denied(),
    }
}

fn sync_relay_error(error: SyncObjectStoreErrorV1) -> SyncRunError {
    match error {
        SyncObjectStoreErrorV1::Io | SyncObjectStoreErrorV1::TransportUnavailable => SyncRunError::temporary(),
        _ => SyncRunError::denied(),
    }
}

fn sync_device_bytes(value: &str) -> Result<[u8; 16], String> {
    URL_SAFE_NO_PAD.decode(value)
        .map_err(|_| "A sync device ID is invalid")?
        .try_into()
        .map_err(|_| "A sync device ID is invalid".into())
}

fn sync_hash_bytes(value: &str) -> Result<[u8; 32], String> {
    URL_SAFE_NO_PAD.decode(value)
        .map_err(|_| "A sync manifest hash is invalid")?
        .try_into()
        .map_err(|_| "A sync manifest hash is invalid".into())
}

fn local_sync_manifests(
    store: &Datastore,
    data_key: &VaultDataKeyV1,
    vault_id: &str,
    key_epoch: u64,
    identity: &DeviceIdentityV1,
    head: SyncManifestHeadV1,
) -> Result<(Vec<SyncEnvelopeV1>, u64, Vec<SyncTombstoneAckV1>), String> {
    if head.revision == 0 {
        if head.head_hash != [0; 32] { return Err("The local sync stream head is invalid".into()); }
        return Ok((Vec::new(), 0, Vec::new()));
    }
    let public = identity.public_identity();
    let vault_bytes = sync_device_bytes(vault_id)?;
    let mut manifests = Vec::<(SyncEnvelopeV1, SyncManifestV1)>::new();
    let mut cursor = None;
    let mut scanned = 0usize;
    loop {
        let page = store.list_sync_objects(vault_id.into(), cursor.clone(), 64)
            .map_err(|_| "The encrypted sync outbox could not be read")?;
        scanned += page.objects.len();
        if scanned > MAX_SYNC_OBJECT_SCAN { return Err("The encrypted sync outbox exceeds its scan limit".into()); }
        for envelope in page.objects {
            if envelope.vault_id != vault_id { return Err("The encrypted sync outbox contains another vault ID".into()); }
            if envelope.key_epoch != key_epoch { continue; }
            if inspect_snapshot_chunk(data_key, &envelope).is_ok() { continue; }
            let manifest = decrypt_manifest(data_key, &envelope)
                .map_err(|_| "A local sync manifest failed authentication")?;
            if manifest.writer_device_id != public.device_id { continue; }
            manifest.verify_signature(&public, &vault_bytes)
                .map_err(|_| "A local sync manifest signature is invalid")?;
            manifests.push((envelope, manifest));
        }
        let Some(next) = page.next_cursor else { break; };
        if cursor.as_deref() == Some(next.as_str()) { return Err("Sync outbox cursor did not advance".into()); }
        cursor = Some(next);
    }

    let mut revision = head.revision;
    let mut head_hash = head.head_hash;
    let mut chain = Vec::new();
    while revision > 0 {
        let expected_hash = URL_SAFE_NO_PAD.encode(head_hash);
        let (_, manifest) = manifests.iter()
            .find(|(_, manifest)| manifest.revision == revision && manifest.head_hash == expected_hash)
            .ok_or("The local manifest head has no encrypted object")?;
        chain.push(manifest.clone());
        head_hash = sync_hash_bytes(&manifest.parent_hash)?;
        revision -= 1;
    }
    if head_hash != [0; 32] { return Err("The local sync manifest chain has invalid ancestry".into()); }
    chain.reverse();
    let last_counter = chain.iter().flat_map(|manifest| manifest.operations.iter())
        .map(|operation| operation.counter).max().unwrap_or(0);
    let acknowledgements = chain.iter()
        .flat_map(|manifest| manifest.tombstone_acknowledgements.iter().cloned())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let envelopes = chain.into_iter().map(|manifest| {
        manifests.iter().find(|(_, candidate)| candidate.head_hash == manifest.head_hash && candidate.revision == manifest.revision)
            .map(|(envelope, _)| envelope.clone())
            .ok_or_else(|| "The local sync manifest object is unavailable".to_owned())
    }).collect::<Result<Vec<_>, _>>()?;
    Ok((envelopes, last_counter, acknowledgements))
}

fn append_local_manifests(
    store: &Datastore,
    data_key: &VaultDataKeyV1,
    identity: &DeviceIdentityV1,
    vault_id: [u8; 16],
    key_epoch: u64,
    mut head: SyncManifestHeadV1,
    mut after_counter: u64,
    acknowledgements: Vec<SyncTombstoneAckV1>,
) -> Result<(SyncManifestHeadV1, Vec<SyncEnvelopeV1>), String> {
    let public = identity.public_identity();
    let vault_id_text = URL_SAFE_NO_PAD.encode(vault_id);
    let mut queued = Vec::new();
    let stored_at = chrono::Utc::now().to_rfc3339();
    let mut acknowledgement_cursor = 0usize;

    for _ in 0..MAX_MANIFESTS_PER_CYCLE {
        let page = store.list_sync_operations(*identity.device_id_bytes(), key_epoch, after_counter, 256)
            .map_err(|_| "The encrypted sync operation log could not be read")?;
        if page.is_empty() && acknowledgement_cursor == acknowledgements.len() { break; }
        let mut count = page.len().min(MAX_OPERATIONS_PER_MANIFEST);
        let mut acknowledgement_count = (acknowledgements.len() - acknowledgement_cursor)
            .min(MAX_TOMBSTONE_ACKS_PER_MANIFEST);
        let (manifest, envelope) = loop {
            let mut operations = Vec::with_capacity(count);
            for record in &page[..count] {
                let hash = digest(&SHA256, record.operation_json.as_bytes());
                if hash.as_ref() != &record.content_hash[..] {
                    return Err("A stored sync operation failed its content hash".into());
                }
                let operation: SyncOperationV1 = serde_json::from_str(&record.operation_json)
                    .map_err(|_| "A stored sync operation is invalid")?;
                operation.validate().map_err(|_| "A stored sync operation is invalid")?;
                if operation.device_id != public.device_id || operation.counter != record.counter {
                    return Err("A stored sync operation has a different writer identity".into());
                }
                operations.push(operation);
            }
            let revision = head.revision.checked_add(1)
                .ok_or("The local sync manifest revision is exhausted")?;
            let acks = acknowledgements[acknowledgement_cursor..acknowledgement_cursor + acknowledgement_count].to_vec();
            let manifest = match SyncManifestV1::new_signed_with_tombstone_acks(
                identity, vault_id, key_epoch, revision, head.head_hash, operations, acks,
            ) {
                Ok(manifest) => manifest,
                Err(_) if count > 1 => { count = (count + 1) / 2; continue; }
                Err(_) if count > 0 && acknowledgement_count > 0 => { acknowledgement_count = 0; continue; }
                Err(_) if acknowledgement_count > 1 => {
                    acknowledgement_count = (acknowledgement_count + 1) / 2;
                    continue;
                }
                Err(_) => return Err("The local sync manifest could not be signed".into()),
            };
            let mut object_id = [0u8; 16];
            getrandom::getrandom(&mut object_id).map_err(|_| "Secure randomness is unavailable")?;
            let header = SyncChunkHeaderV1 {
                schema_version: SYNC_SCHEMA_VERSION_V1,
                object_id: URL_SAFE_NO_PAD.encode(object_id),
                vault_id: vault_id_text.clone(),
                key_epoch,
            };
            match encrypt_manifest(data_key, &header, &manifest) {
                Ok(envelope) => break (manifest, envelope),
                Err(_) if count > 1 => count = (count + 1) / 2,
                Err(_) if count > 0 && acknowledgement_count > 0 => acknowledgement_count = 0,
                Err(_) if acknowledgement_count > 1 => acknowledgement_count = (acknowledgement_count + 1) / 2,
                Err(_) => return Err("A sync operation exceeds the encrypted manifest limit".into()),
            }
        };
        let next = SyncManifestHeadV1::new(manifest.revision, sync_hash_bytes(&manifest.head_hash)?);
        store.put_sync_object(envelope.clone(), stored_at.clone())
            .map_err(|_| "The encrypted manifest could not be retained in the local outbox")?;
        match store.commit_sync_manifest_head(vault_id, key_epoch, *identity.device_id_bytes(), head, next)
            .map_err(|_| "The local sync manifest head could not be advanced")? {
            SyncHeadCommitV1::Advanced | SyncHeadCommitV1::Duplicate => (),
        }
        if count > 0 { after_counter = page[count - 1].counter; }
        acknowledgement_cursor += acknowledgement_count;
        head = next;
        queued.push(envelope);
    }
    Ok((head, queued))
}

impl SyncControl {
    pub const fn new() -> Self {
        Self {
            recovery_kit_pending: AtomicBool::new(false),
            pairing: Mutex::new(None),
        }
    }
}

fn argument<T: DeserializeOwned>(args: &Value, key: &str) -> Result<T, String> {
    serde_json::from_value(args.get(key).cloned().ok_or_else(|| format!("Missing {key}"))?)
        .map_err(|_| format!("Invalid {key}"))
}

fn load_or_create_device_identity(store: &Datastore) -> Result<(DeviceIdentityV1, bool), String> {
    if let Some(stored) = store.load_sync_device_identity()
        .map_err(|_| "The encrypted vault cannot load its sync identity")?
    {
        return Ok((DeviceIdentityV1::from_bytes(
            *stored.device_id(), Zeroizing::new(*stored.private_key()), Zeroizing::new(*stored.signing_seed()),
        ), false));
    }
    let identity = generate_device_identity().map_err(|error| error.to_string())?;
    store.create_sync_device_identity(&SyncDeviceIdentity::new(
        *identity.device_id_bytes(), identity.secret_for_storage(), identity.signing_seed_for_storage(),
    )).map_err(|_| "The encrypted vault cannot save its sync identity")?;
    Ok((identity, true))
}

fn create_sync_pairing(control: &SyncControl, store: &Datastore, args: Value) -> Result<Value, String> {
    let recipient: aw_models::DevicePublicIdentityV1 = argument(&args, "recipient")?;
    let (identity, _) = load_or_create_device_identity(store)?;
    let (invitation, ephemeral) = begin_pairing(&identity, &recipient).map_err(|error| error.to_string())?;
    let mut pending = control.pairing.lock().map_err(|_| "Device pairing state is unavailable")?;
    if pending.is_some() { return Err("Finish or cancel the current device pairing first".into()); }
    *pending = Some(PendingPairing {
        identity, invitation: invitation.clone(), recipient: false,
        ephemeral: Some(ephemeral), offer: None, session: None,
    });
    serde_json::to_value(invitation).map_err(|_| "Pairing invitation could not be encoded".into())
}

fn respond_sync_pairing(control: &SyncControl, store: &Datastore, args: Value) -> Result<Value, String> {
    let invitation: PairingInvitationV1 = argument(&args, "invitation")?;
    let (identity, _) = load_or_create_device_identity(store)?;
    let (response, ephemeral) = respond_to_pairing(&identity, &invitation).map_err(|error| error.to_string())?;
    let mut pending = control.pairing.lock().map_err(|_| "Device pairing state is unavailable")?;
    if pending.is_some() { return Err("Finish or cancel the current device pairing first".into()); }
    *pending = Some(PendingPairing {
        identity, invitation, recipient: true,
        ephemeral: Some(ephemeral), offer: None, session: None,
    });
    serde_json::to_value(response).map_err(|_| "Pairing response could not be encoded".into())
}

fn complete_sync_pairing(control: &SyncControl, args: Value) -> Result<Value, String> {
    let response: PairingResponseV1 = argument(&args, "response")?;
    let mut pending = control.pairing.lock().map_err(|_| "Device pairing state is unavailable")?;
    let state = pending.as_mut().ok_or("Start or respond to a pairing before completing it")?;
    if state.recipient { return Err("This device is waiting for the initiating device".into()); }
    let offer = complete_pairing(state.invitation.clone(), response).map_err(|error| error.to_string())?;
    let ephemeral = state.ephemeral.take().ok_or("The pairing invitation expired; start again")?;
    let session = derive_pairing_session(&state.identity, ephemeral, offer.clone()).map_err(|error| error.to_string())?;
    let display = PairingDisplay { offer: offer.clone(), verification_code: session.verification_code().to_owned() };
    state.session = Some(session);
    state.offer = Some(offer);
    serde_json::to_value(display).map_err(|_| "Pairing offer could not be encoded".into())
}

fn prepare_sync_pairing(control: &SyncControl, args: Value) -> Result<Value, String> {
    let offer: PairingOfferV1 = argument(&args, "offer")?;
    let mut pending = control.pairing.lock().map_err(|_| "Device pairing state is unavailable")?;
    let state = pending.as_mut().ok_or("Respond to an invitation before preparing an offer")?;
    if !state.recipient { return Err("The initiating device prepares the offer".into()); }
    if state.invitation.offer_id != offer.offer_id { return Err("Pairing offer does not match the active invitation".into()); }
    let ephemeral = state.ephemeral.take().ok_or("The pairing response expired; start again")?;
    let session = derive_pairing_session(&state.identity, ephemeral, offer.clone()).map_err(|error| error.to_string())?;
    let code = session.verification_code().to_owned();
    state.session = Some(session);
    state.offer = Some(offer);
    Ok(json!(code))
}

fn confirm_sync_pairing(control: &SyncControl, args: Value) -> Result<Value, String> {
    let displayed_code = args.get("displayedCode").and_then(Value::as_str).ok_or("Pairing code is required")?;
    let user_confirmed = args.get("userConfirmed").and_then(Value::as_bool) == Some(true);
    let mut pending = control.pairing.lock().map_err(|_| "Device pairing state is unavailable")?;
    let session = pending.as_mut().and_then(|state| state.session.as_mut())
        .ok_or("Compare the pairing code before confirming")?;
    let confirmation = aw_sync_e2ee::confirm_pairing(session, displayed_code, user_confirmed)
        .map_err(|error| error.to_string())?;
    serde_json::to_value(confirmation).map_err(|_| "Pairing confirmation could not be encoded".into())
}

fn create_sync_key_transfer(control: &SyncControl, store: &Datastore, args: Value) -> Result<Value, String> {
    let peer_confirmation: PairingConfirmationV1 = argument(&args, "peerConfirmation")?;
    let mut pending = control.pairing.lock().map_err(|_| "Device pairing state is unavailable")?;
    let state = pending.as_ref().ok_or("Confirm a device pairing before transferring keys")?;
    if state.recipient { return Err("The responding device accepts the key transfer".into()); }
    let session = state.session.as_ref().ok_or("Compare and confirm the pairing code first")?;
    let (root, wrapped, material) = load_or_generate_sync_keys(store)?;
    let transfer = create_key_transfer(session, &peer_confirmation, &root, &wrapped).map_err(|error| error.to_string())?;
    let offer = state.offer.as_ref().ok_or("The pairing offer is unavailable")?;
    let recipient = &offer.recipient;
    ensure_peer_not_revoked(store, &recipient.device_id)?;
    store.record_sync_pairing(
        material, decode_fixed::<16>(&offer.offer_id)?,
        decode_fixed::<16>(&recipient.device_id)?,
        decode_fixed::<32>(&recipient.x25519_public_key)?,
        decode_fixed::<32>(&recipient.ed25519_public_key)?,
        chrono::Utc::now().to_rfc3339(),
    ).map_err(|_| "The encrypted vault cannot save sync keys and trusted-device history")?;
    *pending = None;
    serde_json::to_value(transfer).map_err(|_| "Encrypted key transfer could not be encoded".into())
}

fn accept_sync_key_transfer(control: &SyncControl, store: &Datastore, args: Value) -> Result<Value, String> {
    let peer_confirmation: PairingConfirmationV1 = argument(&args, "peerConfirmation")?;
    let transfer: EncryptedKeyTransferV1 = argument(&args, "transfer")?;
    if store.load_sync_key_material().map_err(|_| "The encrypted vault cannot inspect sync keys")?.is_some() {
        return Err("This device already has sync keys; its existing data was preserved".into());
    }
    let mut pending = control.pairing.lock().map_err(|_| "Device pairing state is unavailable")?;
    let state = pending.as_ref().ok_or("Prepare and confirm a pairing before accepting keys")?;
    if !state.recipient { return Err("The initiating device creates the key transfer".into()); }
    let session = state.session.as_ref().ok_or("Compare and confirm the pairing code first")?;
    let offer = state.offer.as_ref().ok_or("The pairing offer is unavailable")?;
    let imported = accept_key_transfer(session, &peer_confirmation, &transfer).map_err(|error| error.to_string())?;
    ensure_peer_not_revoked(store, &offer.issuer.device_id)?;
    let material = material_from_keys(&imported.account_root_key, &imported.wrapped_vault_key)?;
    let peer = offer.issuer.clone();
    store.record_sync_pairing(
        Some(material), decode_fixed::<16>(&offer.offer_id)?,
        decode_fixed::<16>(&peer.device_id)?, decode_fixed::<32>(&peer.x25519_public_key)?,
        decode_fixed::<32>(&peer.ed25519_public_key)?,
        chrono::Utc::now().to_rfc3339(),
    ).map_err(|_| "The encrypted vault cannot save transferred keys and device history")?;
    *pending = None;
    serde_json::to_value(peer).map_err(|_| "Paired device could not be encoded".into())
}

#[derive(Serialize)]
struct DeviceSummary {
    schema_version: u32,
    device_id: String,
    x25519_public_key: String,
    ed25519_public_key: Option<String>,
    is_current_device: bool,
    paired_at: Option<String>,
    revoked_at: Option<String>,
    needs_repair: bool,
}

#[derive(Serialize)]
struct RecoveryDisplay {
    recovery_phrase: String,
    kit: RecoveryKitV1,
}

#[derive(Serialize)]
struct PairingDisplay {
    offer: PairingOfferV1,
    verification_code: String,
}

#[derive(Serialize)]
struct SyncRestorePreview {
    schema_version: u32,
    device_id: Option<String>,
    vault_id: String,
    key_epoch: u64,
    snapshot_id: String,
    object_count: usize,
    version_start: String,
    version_end: String,
    tombstone_count: usize,
    query_start: Option<String>,
    query_end: Option<String>,
    policy_conflict_count: usize,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct SyncRecoverySnapshotV1 {
    schema_version: u32,
    activity: BucketsExport,
    sync: SyncRecoveryStateV1,
}

#[derive(Serialize)]
struct SyncTombstoneStatus {
    origin_device_id: String,
    local_event_id: u64,
    tombstone_counter: u64,
    active_device_ids: Vec<String>,
    pending_device_ids: Vec<String>,
}

impl SyncControl {
    pub fn invoke(&self, store: &Datastore, command: &str, args: Value) -> Result<Value, String> {
        match command {
            "create_local_sync_identity" => create_local_sync_identity(store),
            "list_sync_devices" => list_sync_devices(store),
            "list_sync_device_access_history" => list_sync_device_access_history(store),
            "list_sync_tombstone_statuses" => list_sync_tombstone_statuses(store),
            "export_sync_snapshot" => export_sync_snapshot(store),
            "rotate_sync_keys" => self.rotate_sync_keys(store),
            "revoke_sync_device" => self.revoke_sync_device(store, args),
            "create_sync_pairing" => create_sync_pairing(self, store, args),
            "respond_sync_pairing" => respond_sync_pairing(self, store, args),
            "complete_sync_pairing" => complete_sync_pairing(self, args),
            "prepare_sync_pairing" => prepare_sync_pairing(self, args),
            "confirm_sync_pairing" => confirm_sync_pairing(self, args),
            "create_sync_key_transfer" => create_sync_key_transfer(self, store, args),
            "accept_sync_key_transfer" => accept_sync_key_transfer(self, store, args),
            "cancel_sync_pairing" => {
                *self.pairing.lock().map_err(|_| "Device pairing state is unavailable")? = None;
                Ok(Value::Null)
            }
            "create_sync_recovery_kit" => self.create_recovery_kit(store),
            "create_current_sync_snapshot" => self.create_current_sync_snapshot(store),
            "cancel_sync_recovery_kit" => {
                self.recovery_kit_pending.store(false, Ordering::Release);
                Ok(Value::Null)
            }
            "confirm_sync_recovery_saved" => self.confirm_recovery_saved(store, args),
            "sync_recovery_confirmed" => store
                .sync_recovery_confirmation()
                .map(|confirmation| json!(confirmation.is_some()))
                .map_err(|_| "The encrypted vault cannot read recovery status".into()),
            "sync_enabled" => store.sync_enabled()
                .map(|enabled| json!(enabled))
                .map_err(|_| "The encrypted vault cannot read sync consent".into()),
            "verify_sync_recovery_kit" => verify_recovery_kit(args),
            "preview_sync_recovery_restore" => preview_recovery_restore(store, args),
            "restore_sync_recovery_kit" => self.restore_recovery_kit(store, args),
            _ => Err("This E2EE sync operation is not available on this platform yet".into()),
        }
    }

    /// Bounded local-only preparation; it performs no relay request.
    pub fn prepare_sync_baseline(
        &self,
        store: &Datastore,
        limit: usize,
    ) -> Result<SyncBaselineProgressV1, String> {
        if store.sync_recovery_confirmation()
            .map_err(|_| "The encrypted vault cannot inspect recovery status")?.is_none()
        {
            return Err("Confirm a recovery kit before preparing sync".into());
        }
        let keys = store.load_sync_key_material()
            .map_err(|_| "The encrypted vault cannot load sync keys")?
            .ok_or("Sync keys are unavailable")?;
        let root = AccountRootKeyV1::from_bytes(Zeroizing::new(*keys.account_root_key()));
        unwrap_vault_data_key(&root, &wrapped_key_from_material(&keys))
            .map_err(|_| "Current sync keys could not be verified")?;
        let identity = store.load_sync_device_identity()
            .map_err(|_| "The encrypted vault cannot load its sync identity")?
            .ok_or("Create a local sync identity first")?;
        if !store.list_sync_trusted_devices()
            .map_err(|_| "The encrypted vault cannot list trusted devices")?
            .iter()
            .any(|device| device.device_id != *identity.device_id()
                && device.revoked_at.is_none()
                && device.key_epoch == keys.key_epoch()
                && device.ed25519_public_key.is_some())
        {
            return Err("Pair and verify another current-epoch device before preparing sync".into());
        }
        let progress = store.begin_sync_baseline()
            .map_err(|_| "The encrypted vault cannot start sync baseline preparation")?;
        if progress.complete { return Ok(progress); }
        store.process_sync_baseline_batch(limit)
            .map_err(|_| "The encrypted vault cannot advance sync baseline preparation".into())
    }

    /// Exchanges signed operation manifests; relay payloads remain encrypted and opaque.
    pub fn sync_operations<R: SyncObjectStoreV1>(
        &self,
        store: &Datastore,
        remote: &R,
    ) -> Result<Value, SyncRunError> {
        if !store.sync_enabled().map_err(sync_datastore_error)? {
            return Err("Network sync is disabled by local consent".into());
        }
        if store.egress_kill_switch().map_err(sync_datastore_error)? {
            return Err("Network sync is disabled by the egress kill switch".into());
        }
        if store.sync_recovery_confirmation()
            .map_err(|_| "The encrypted vault cannot inspect recovery status")?.is_none()
        {
            return Err("Confirm a recovery kit before network sync".into());
        }
        let consent = store.sync_egress_consent()
            .map_err(|_| "The encrypted vault cannot read sync consent")?
            .ok_or("Network sync is disabled by local consent")?;
        if consent.purpose_id != aw_models::SYNC_EGRESS_PURPOSE_V1 {
            return Err("The selected purpose is not the signed sync purpose".into());
        }
        let keys = store.load_sync_key_material()
            .map_err(|_| "The encrypted vault cannot load sync keys")?
            .ok_or("Sync keys are unavailable")?;
        let stored_identity = store.load_sync_device_identity()
            .map_err(|_| "The encrypted vault cannot load its sync identity")?
            .ok_or("Create a local sync identity first")?;
        let local_identity = DeviceIdentityV1::from_bytes(
            *stored_identity.device_id(),
            Zeroizing::new(*stored_identity.private_key()),
            Zeroizing::new(*stored_identity.signing_seed()),
        );
        let local_device_id = *local_identity.device_id_bytes();
        let trusted = store.list_sync_trusted_devices()
            .map_err(|_| "The encrypted vault cannot list trusted devices")?;
        if !trusted.iter().any(|device| {
                device.device_id != local_device_id
                && device.revoked_at.is_none()
                && device.key_epoch == keys.key_epoch()
                && device.ed25519_public_key.is_some()
        }) {
            return Err("Pair and verify another current-epoch device before network sync".into());
        }
        let baseline = store.begin_sync_baseline()
            .map_err(|_| "The encrypted vault cannot inspect sync baseline progress")?;
        if !baseline.complete {
            return Err("Finish preparing the signed sync baseline before network sync".into());
        }
        let root = AccountRootKeyV1::from_bytes(Zeroizing::new(*keys.account_root_key()));
        let wrapped = wrapped_key_from_material(&keys);
        let data_key = unwrap_vault_data_key(&root, &wrapped).map_err(|_| "Current sync keys could not be verified")?;
        let vault_id = URL_SAFE_NO_PAD.encode(keys.vault_id());
        let local_head = store.load_sync_manifest_head(*keys.vault_id(), keys.key_epoch(), local_device_id)
            .map_err(|_| "The encrypted vault cannot read its local sync stream head")?
            .unwrap_or_else(SyncManifestHeadV1::genesis);
        // ponytail: retain the stream chain until signed ACKs and recovery checkpoints exist; pruning earlier can strand an offline peer.
        let (prior_manifests, last_counter, represented_acknowledgements) = local_sync_manifests(
            store,
            &data_key,
            &vault_id,
            keys.key_epoch(),
            &local_identity,
            local_head,
        )?;
        let represented_acknowledgements = represented_acknowledgements.into_iter().collect::<std::collections::BTreeSet<_>>();
        let acknowledgements = store.list_local_sync_tombstone_acknowledgements()
            .map_err(|_| "The encrypted tombstone acknowledgement log could not be read")?
            .into_iter()
            .filter(|acknowledgement| !represented_acknowledgements.contains(acknowledgement))
            .collect();
        let (local_head, new_manifests) = append_local_manifests(
            store,
            &data_key,
            &local_identity,
            *keys.vault_id(),
            keys.key_epoch(),
            local_head,
            last_counter,
            acknowledgements,
        )?;

        let remote_envelopes = remote.list_opaque_heads(&vault_id).map_err(sync_relay_error)?;
        if remote_envelopes.len() > MAX_SYNC_OBJECT_SCAN {
            return Err("The relay returned too many sync objects".into());
        }
        let mut remote_ids = BTreeMap::new();
        for (index, envelope) in remote_envelopes.iter().enumerate() {
            envelope.validate().map_err(|_| "The relay returned an invalid encrypted object")?;
            if envelope.vault_id != vault_id { return Err("Relay returned a different vault ID".into()); }
            if let Some(previous) = remote_ids.insert(envelope.object_id.clone(), index) {
                if &remote_envelopes[previous] != envelope {
                    return Err("The relay reused an immutable sync object ID".into());
                }
            }
        }

        let mut uploaded = 0usize;
        for envelope in prior_manifests.into_iter().chain(new_manifests) {
            if let Some(index) = remote_ids.get(&envelope.object_id) {
                if &remote_envelopes[*index] != &envelope {
                    return Err("The relay reused an immutable sync object ID".into());
                }
                continue;
            }
            if remote.put_if_absent(&envelope).map_err(sync_relay_error)? {
                uploaded += 1;
            }
        }

        let mut trusted_keys = BTreeMap::new();
        for device in trusted.into_iter().filter(|device| {
            device.device_id != local_device_id
                && device.revoked_at.is_none()
                && device.key_epoch == keys.key_epoch()
        }) {
            let Some(ed25519_public_key) = device.ed25519_public_key else { continue; };
            trusted_keys.insert(device.device_id, DevicePublicIdentityV1 {
                schema_version: SYNC_SCHEMA_VERSION_V1,
                device_id: URL_SAFE_NO_PAD.encode(device.device_id),
                x25519_public_key: URL_SAFE_NO_PAD.encode(device.x25519_public_key),
                ed25519_public_key: URL_SAFE_NO_PAD.encode(ed25519_public_key),
            });
        }

        let mut remote_manifests = BTreeMap::<[u8; 16], BTreeMap<u64, SyncManifestV1>>::new();
        let mut downloaded = 0usize;
        for envelope in remote_envelopes {
            if envelope.key_epoch != keys.key_epoch() { continue; }
            if inspect_snapshot_chunk(&data_key, &envelope).is_ok() { continue; }
            let manifest = decrypt_manifest(&data_key, &envelope)
                .map_err(|_| "A relayed operation manifest failed authentication")?;
            let writer = sync_device_bytes(&manifest.writer_device_id)?;
            if writer == local_device_id { continue; }
            let Some(public) = trusted_keys.get(&writer) else { continue; };
            manifest.verify_signature(public, keys.vault_id())
                .map_err(|_| "A relayed operation manifest has an invalid device signature")?;
            let stream = remote_manifests.entry(writer).or_default();
            if let Some(existing) = stream.get(&manifest.revision) {
                if existing.head_hash != manifest.head_hash {
                    return Err("A trusted device published a sync stream fork".into());
                }
                continue;
            }
            if store.put_sync_object(envelope, chrono::Utc::now().to_rfc3339())
                .map_err(sync_datastore_error)?
            {
                downloaded += 1;
            }
            stream.insert(manifest.revision, manifest);
        }

        let mut pending = BTreeMap::new();
        for (writer, manifests) in remote_manifests {
            let head = store.load_sync_manifest_head(*keys.vault_id(), keys.key_epoch(), writer)
                .map_err(|_| "The encrypted vault cannot read a trusted sync stream head")?
                .unwrap_or_else(SyncManifestHeadV1::genesis);
            pending.insert(writer, (head, manifests.into_iter().collect::<VecDeque<_>>()));
        }
        let mut applied = 0usize;
        // Retry a blocked writer after another stream may have supplied its event or tombstone prerequisite.
        while !pending.is_empty() {
            let writers = pending.keys().copied().collect::<Vec<_>>();
            let mut progressed = false;
            let mut deferred_error = None;
            let mut finished = Vec::new();
            for writer in writers {
                let Some((head, manifests)) = pending.get_mut(&writer) else { continue; };
                let Some((revision, manifest)) = manifests.front().cloned() else {
                    finished.push(writer);
                    continue;
                };
                if revision < head.revision {
                    manifests.pop_front();
                    progressed = true;
                } else if revision == head.revision {
                    if sync_hash_bytes(&manifest.head_hash)? != head.head_hash {
                        return Err("A trusted device published a sync stream fork".into());
                    }
                    manifests.pop_front();
                    progressed = true;
                } else {
                    if revision != head.revision.saturating_add(1) {
                        return Err("A trusted sync stream is missing a manifest revision".into());
                    }
                    let next = SyncManifestHeadV1::new(manifest.revision, sync_hash_bytes(&manifest.head_hash)?);
                    match store.apply_sync_operations(SyncApplyBatchV1 { manifest }) {
                        Ok(SyncHeadCommitV1::Advanced) => applied += 1,
                        Ok(SyncHeadCommitV1::Duplicate) => (),
                        Err(error) => {
                            deferred_error.get_or_insert_with(|| sync_datastore_error(error));
                            continue;
                        }
                    }
                    manifests.pop_front();
                    *head = next;
                    progressed = true;
                }
                if manifests.is_empty() { finished.push(writer); }
            }
            for writer in finished { pending.remove(&writer); }
            if !pending.is_empty() && !progressed {
                return Err(deferred_error.unwrap_or_else(SyncRunError::denied));
            }
        }
        Ok(json!({
            "uploaded_manifests": uploaded,
            "downloaded_manifests": downloaded,
            "applied_manifests": applied,
            "key_epoch": keys.key_epoch(),
            "stream_revision": local_head.revision,
        }))
    }

    fn create_recovery_kit(&self, store: &Datastore) -> Result<Value, String> {
        self.recovery_kit_pending
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| "Save or cancel the current one-time recovery phrase first")?;
        let result = (|| {
            if store.sync_recovery_confirmation()
                .map_err(|_| "The encrypted vault cannot inspect recovery status")?.is_some()
            {
                return Err("A recovery phrase is already confirmed; rotate the sync root before replacing it".into());
            }
            let (root, wrapped, material) = load_or_generate_sync_keys(store)?;
            let (phrase, kit) = make_recovery_kit(&root, &wrapped).map_err(|error| error.to_string())?;
            if let Some(material) = material {
                store.install_sync_key_material(&material)
                    .map_err(|_| "The encrypted vault cannot save sync recovery keys")?;
            }
            serde_json::to_value(RecoveryDisplay { recovery_phrase: phrase, kit })
                .map_err(|_| "The recovery kit could not be encoded".into())
        })();
        if result.is_err() {
            self.recovery_kit_pending.store(false, Ordering::Release);
        }
        result
    }

    fn confirm_recovery_saved(&self, store: &Datastore, args: Value) -> Result<Value, String> {
        if args.get("userConfirmed").and_then(Value::as_bool) != Some(true) {
            return Err("Confirm only after saving the recovery phrase".into());
        }
        if !self.recovery_kit_pending.load(Ordering::Acquire) {
            return Err("Create a recovery kit before confirming it was saved".into());
        }
        store.confirm_sync_recovery_saved(chrono::Utc::now().to_rfc3339())
            .map_err(|_| "The encrypted vault cannot save recovery confirmation".to_string())?;
        self.recovery_kit_pending.store(false, Ordering::Release);
        Ok(Value::Null)
    }

    fn create_current_sync_snapshot(&self, store: &Datastore) -> Result<Value, String> {
        if store.sync_recovery_confirmation()
            .map_err(|_| "The encrypted vault cannot inspect recovery status")?.is_none()
        {
            return Err("Confirm a recovery kit for the current sync keys before creating a snapshot".into());
        }
        let material = store.load_sync_key_material()
            .map_err(|_| "The encrypted vault cannot load its sync keys")?
            .ok_or("Create or receive sync keys before creating a snapshot")?;
        let key_epoch = material.key_epoch();
        let root = AccountRootKeyV1::from_bytes(Zeroizing::new(*material.account_root_key()));
        let wrapped = wrapped_key_from_material(&material);
        let data_key = unwrap_vault_data_key(&root, &wrapped).map_err(|error| error.to_string())?;
        let snapshot = encrypt_current_snapshot(store, &data_key)?;
        let snapshot_id = URL_SAFE_NO_PAD.encode(snapshot.snapshot_id);
        let object_count = snapshot.envelopes.len();
        if let Some(previous) = store.load_sync_snapshot()
            .map_err(|_| "The encrypted vault cannot read its current snapshot")?
        {
            queue_snapshot_envelopes(store, &previous)?;
        }
        queue_snapshot_envelopes(store, &snapshot)?;
        store.save_sync_snapshot(material, snapshot)
            .map_err(|_| "The encrypted activity snapshot could not be stored".to_string())?;
        Ok(json!({"schema_version": 1, "key_epoch": key_epoch, "snapshot_id": snapshot_id, "object_count": object_count}))
    }

    fn rotate_sync_keys(&self, store: &Datastore) -> Result<Value, String> {
        if self.recovery_kit_pending.load(Ordering::Acquire) {
            return Err("Save or cancel the current recovery kit before rotating sync keys".into());
        }
        let (material, data_key) = rotated_sync_key_material(store)?;
        let epoch = material.key_epoch();
        let snapshot = encrypt_current_snapshot(store, &data_key)?;
        let rotated = store.rotate_sync_key_material(
            material,
            snapshot,
            None,
            chrono::Utc::now().to_rfc3339(),
        ).map_err(|_| "The encrypted vault could not rotate sync keys".to_string())?;
        if !rotated { return Err("Sync key rotation was not applied".into()); }
        Ok(json!(epoch))
    }

    fn revoke_sync_device(&self, store: &Datastore, args: Value) -> Result<Value, String> {
        if self.recovery_kit_pending.load(Ordering::Acquire) {
            return Err("Save or cancel the current recovery kit before revoking a device".into());
        }
        let device_id = decode_fixed::<16>(args.get("deviceId").and_then(Value::as_str)
            .ok_or("Device ID is required")?)?;
        if store.load_sync_device_identity()
            .map_err(|_| "The encrypted vault cannot load its sync identity")?
            .is_some_and(|identity| identity.device_id() == &device_id)
        {
            return Err("The current device cannot revoke itself".into());
        }
        if !store.list_sync_trusted_devices()
            .map_err(|_| "The encrypted vault cannot inspect device access")?
            .iter().any(|device| device.device_id == device_id && device.revoked_at.is_none())
        {
            return Err("The selected device is no longer active".into());
        }
        let (material, data_key) = rotated_sync_key_material(store)?;
        let snapshot = encrypt_current_snapshot(store, &data_key)?;
        let revoked = store.rotate_sync_key_material(
            material,
            snapshot,
            Some(device_id),
            chrono::Utc::now().to_rfc3339(),
        ).map_err(|_| "The encrypted vault could not revoke the selected device".to_string())?;
        Ok(json!(revoked))
    }

    fn restore_recovery_kit(&self, store: &Datastore, args: Value) -> Result<Value, String> {
        if args.get("userAccepted").and_then(Value::as_bool) != Some(true) {
            return Err("Review and accept the restore preview before restoring activity".into());
        }
        let (material, snapshot, export, preview) = validate_recovery_restore(store, args)?;
        let identity = generate_device_identity().map_err(|error| error.to_string())?;
        let local_identity = SyncDeviceIdentity::new(
            *identity.device_id_bytes(), identity.secret_for_storage(), identity.signing_seed_for_storage(),
        );
        store.restore_sync_recovery_data(export.activity, material, snapshot, export.sync, local_identity)
            .map_err(|_| "The encrypted activity snapshot could not be restored atomically".to_string())?;
        self.recovery_kit_pending.store(true, Ordering::Release);
        serde_json::to_value(preview).map_err(|_| "Restore preview could not be encoded".into())
    }
}

fn create_local_sync_identity(store: &Datastore) -> Result<Value, String> {
    let (identity, _) = load_or_create_device_identity(store)?;
    serde_json::to_value(identity.public_identity())
        .map_err(|_| "The sync identity could not be encoded".into())
}

fn list_sync_devices(store: &Datastore) -> Result<Value, String> {
    let key_epoch = store.load_sync_key_material()
        .map_err(|_| "The encrypted vault cannot load its sync keys")?
        .map(|material| material.key_epoch())
        .unwrap_or(0);
    let current = store.load_sync_device_identity()
        .map_err(|_| "The encrypted vault cannot load its sync identity")?;
    let mut devices = Vec::new();
    let current_id = current.map(|stored| {
        let identity = DeviceIdentityV1::from_bytes(
            *stored.device_id(),
            Zeroizing::new(*stored.private_key()),
            Zeroizing::new(*stored.signing_seed()),
        );
        let public = identity.public_identity();
        let device_id = public.device_id.clone();
        devices.push(DeviceSummary {
            schema_version: 1,
            device_id: device_id.clone(),
            x25519_public_key: public.x25519_public_key,
            ed25519_public_key: Some(public.ed25519_public_key),
            is_current_device: true,
            paired_at: None,
            revoked_at: None,
            needs_repair: false,
        });
        device_id
    });
    for trusted in store.list_sync_trusted_devices()
        .map_err(|_| "The encrypted vault cannot list trusted sync devices")?
    {
        let device_id = URL_SAFE_NO_PAD.encode(trusted.device_id);
        if current_id.as_deref() == Some(device_id.as_str()) { continue; }
        let needs_repair = trusted.key_epoch != key_epoch || trusted.ed25519_public_key.is_none();
        devices.push(DeviceSummary {
            schema_version: 1,
            device_id,
            x25519_public_key: URL_SAFE_NO_PAD.encode(trusted.x25519_public_key),
            ed25519_public_key: trusted.ed25519_public_key.map(|key| URL_SAFE_NO_PAD.encode(key)),
            is_current_device: false,
            paired_at: Some(trusted.paired_at),
            revoked_at: trusted.revoked_at,
            needs_repair,
        });
    }
    serde_json::to_value(devices).map_err(|_| "Sync devices could not be encoded".into())
}

fn list_sync_device_access_history(store: &Datastore) -> Result<Value, String> {
    let history = store.list_sync_device_access_history(100)
        .map_err(|_| "The encrypted vault cannot read sync device history")?
        .into_iter()
        .map(|event| json!({
            "device_id": URL_SAFE_NO_PAD.encode(event.device_id),
            "action": event.action,
            "occurred_at": event.occurred_at,
        }))
        .collect::<Vec<_>>();
    Ok(json!(history))
}

fn load_or_generate_sync_keys(
    store: &Datastore,
) -> Result<(AccountRootKeyV1, WrappedVaultDataKeyV1, Option<SyncKeyMaterial>), String> {
    if let Some(stored) = store.load_sync_key_material()
        .map_err(|_| "The encrypted vault cannot load its sync keys")?
    {
        let root = AccountRootKeyV1::from_bytes(Zeroizing::new(*stored.account_root_key()));
        let wrapped = WrappedVaultDataKeyV1 {
            schema_version: 1,
            vault_id: URL_SAFE_NO_PAD.encode(stored.vault_id()),
            key_epoch: stored.key_epoch(),
            nonce: URL_SAFE_NO_PAD.encode(stored.wrapped_nonce()),
            ciphertext: URL_SAFE_NO_PAD.encode(stored.wrapped_ciphertext()),
        };
        wrapped.validate().map_err(|error| error.to_string())?;
        unwrap_vault_data_key(&root, &wrapped).map_err(|error| error.to_string())?;
        return Ok((root, wrapped, None));
    }
    let root = generate_account_root_key().map_err(|error| error.to_string())?;
    let mut vault_id = [0u8; 16];
    getrandom::getrandom(&mut vault_id).map_err(|_| "Secure randomness is unavailable")?;
    let (_, wrapped) = create_vault_data_key(&root, &URL_SAFE_NO_PAD.encode(vault_id), 1)
        .map_err(|error| error.to_string())?;
    let material = material_from_keys(&root, &wrapped)?;
    Ok((root, wrapped, Some(material)))
}

fn rotated_sync_key_material(store: &Datastore) -> Result<(SyncKeyMaterial, VaultDataKeyV1), String> {
    let stored = store.load_sync_key_material()
        .map_err(|_| "The encrypted vault cannot load its sync keys")?
        .ok_or("Create sync keys before rotating them")?;
    let root = AccountRootKeyV1::from_bytes(Zeroizing::new(*stored.account_root_key()));
    let wrapped = WrappedVaultDataKeyV1 {
        schema_version: 1,
        vault_id: URL_SAFE_NO_PAD.encode(stored.vault_id()),
        key_epoch: stored.key_epoch(),
        nonce: URL_SAFE_NO_PAD.encode(stored.wrapped_nonce()),
        ciphertext: URL_SAFE_NO_PAD.encode(stored.wrapped_ciphertext()),
    };
    let (next_root, data_key, next_wrapped) =
        rotate_account_and_vault_key(&root, &wrapped).map_err(|error| error.to_string())?;
    Ok((material_from_keys(&next_root, &next_wrapped)?, data_key))
}

fn encrypt_current_snapshot(store: &Datastore, data_key: &VaultDataKeyV1) -> Result<SyncSnapshotV1, String> {
    let plaintext = current_activity_plaintext(store, data_key)?;
    let encrypted = encrypt_snapshot(data_key, &plaintext).map_err(|error| error.to_string())?;
    let verified = decrypt_snapshot(data_key, &encrypted).map_err(|error| error.to_string())?;
    if verified.as_slice() != plaintext.as_slice() {
        return Err("The staged activity snapshot did not verify".into());
    }
    Ok(SyncSnapshotV1::new(decode_fixed::<16>(&encrypted.snapshot_id)?, encrypted.envelopes))
}

fn current_activity_plaintext(store: &Datastore, data_key: &VaultDataKeyV1) -> Result<Zeroizing<Vec<u8>>, String> {
    store.prepare_sync_snapshot_mappings()
        .map_err(|_| "The encrypted vault cannot prepare stable recovery event identities")?;
    let mut buckets = store.get_buckets()
        .map_err(|_| "The encrypted vault cannot read activity buckets")?;
    for (bucket_id, bucket) in &mut buckets {
        bucket.events = Some(aw_models::TryVec::new(
            store.get_events(bucket_id, None, None, None)
                .map_err(|_| "The encrypted vault cannot read activity events")?,
        ));
    }
    let mut sync = store.export_sync_recovery_state(data_key.key_epoch())
        .map_err(|_| "The encrypted vault cannot read sync recovery state")?;
    if store.load_sync_key_material()
        .map_err(|_| "The encrypted vault cannot inspect sync key epoch")?
        .is_some_and(|material| material.key_epoch() == data_key.key_epoch())
    {
        if let Some(stored) = store.load_sync_device_identity()
            .map_err(|_| "The encrypted vault cannot read its sync identity")?
        {
            let identity = DeviceIdentityV1::from_bytes(
                *stored.device_id(), Zeroizing::new(*stored.private_key()), Zeroizing::new(*stored.signing_seed()),
            );
            let public = identity.public_identity();
            let device_id = *identity.device_id_bytes();
            if !sync.trusted_devices.iter().any(|device| device.device_id == device_id) {
                sync.trusted_devices.push(SyncRecoveryTrustedDeviceV1 {
                    device_id,
                    x25519_public_key: decode_fixed::<32>(&public.x25519_public_key)?,
                    ed25519_public_key: decode_fixed::<32>(&public.ed25519_public_key)?,
                    paired_at: chrono::Utc::now().to_rfc3339(),
                });
            }
        }
    }
    sync.trusted_devices.sort_by_key(|device| device.device_id);
    Ok(Zeroizing::new(serde_json::to_vec(&SyncRecoverySnapshotV1 {
        schema_version: 1,
        activity: BucketsExport { buckets },
        sync,
    })
        .map_err(|_| "Activity snapshot could not be encoded")?))
}

fn queue_snapshot_envelopes(store: &Datastore, snapshot: &SyncSnapshotV1) -> Result<(), String> {
    let stored_at = chrono::Utc::now().to_rfc3339();
    for envelope in &snapshot.envelopes {
        envelope.validate().map_err(|_| "Snapshot contains an invalid encrypted envelope")?;
        store.put_sync_object(envelope.clone(), stored_at.clone())
            .map_err(|_| "Encrypted snapshot object could not be queued")?;
    }
    Ok(())
}

fn export_sync_snapshot(store: &Datastore) -> Result<Value, String> {
    if store.sync_recovery_confirmation()
        .map_err(|_| "The encrypted vault cannot inspect recovery status")?.is_none()
    {
        return Err("Confirm a recovery kit for the current sync keys before exporting a snapshot".into());
    }
    let keys = store.load_sync_key_material()
        .map_err(|_| "The encrypted vault cannot load its sync keys")?
        .ok_or("Sync snapshot keys are missing")?;
    let root = AccountRootKeyV1::from_bytes(Zeroizing::new(*keys.account_root_key()));
    let wrapped = wrapped_key_from_material(&keys);
    let data_key = unwrap_vault_data_key(&root, &wrapped).map_err(|error| error.to_string())?;
    let stored = store.load_sync_snapshot()
        .map_err(|_| "The encrypted vault cannot load its sync snapshot")?
        .ok_or("Create a current encrypted snapshot before exporting it")?;
    let export = EncryptedSyncSnapshotV1 {
        schema_version: 1,
        snapshot_id: URL_SAFE_NO_PAD.encode(stored.snapshot_id),
        envelopes: stored.envelopes,
    };
    let plaintext = decrypt_snapshot(&data_key, &export).map_err(|error| error.to_string())?;
    let recovery: SyncRecoverySnapshotV1 = serde_json::from_slice(&plaintext)
        .map_err(|_| "The encrypted sync snapshot is invalid")?;
    if recovery.schema_version != 1
        || recovery.sync.schema_version != SYNC_SCHEMA_VERSION_V1
        || recovery.sync.key_epoch != keys.key_epoch()
    {
        return Err("The encrypted sync snapshot does not match the current key epoch".into());
    }
    serde_json::to_value(export).map_err(|_| "Encrypted snapshot could not be encoded".into())
}

fn list_sync_tombstone_statuses(store: &Datastore) -> Result<Value, String> {
    let Some(keys) = store.load_sync_key_material()
        .map_err(|_| "The encrypted vault cannot load its sync keys")? else { return Ok(json!([])); };
    let root = AccountRootKeyV1::from_bytes(Zeroizing::new(*keys.account_root_key()));
    let wrapped = WrappedVaultDataKeyV1 {
        schema_version: 1,
        vault_id: URL_SAFE_NO_PAD.encode(keys.vault_id()),
        key_epoch: keys.key_epoch(),
        nonce: URL_SAFE_NO_PAD.encode(keys.wrapped_nonce()),
        ciphertext: URL_SAFE_NO_PAD.encode(keys.wrapped_ciphertext()),
    };
    let data_key = unwrap_vault_data_key(&root, &wrapped).map_err(|_| "The encrypted vault cannot unlock sync manifests")?;
    let vault_id = URL_SAFE_NO_PAD.encode(keys.vault_id());
    let mut cursor = None;
    let mut tombstones = std::collections::BTreeSet::new();
    loop {
        let page = store.list_sync_objects(vault_id.clone(), cursor.clone(), 64)
            .map_err(|_| "The encrypted vault cannot list sync manifests")?;
        for envelope in page.objects {
            if envelope.key_epoch != keys.key_epoch() { continue; }
            let manifest = match decrypt_manifest(&data_key, &envelope) {
                Ok(manifest) => manifest,
                Err(_) if inspect_snapshot_chunk(&data_key, &envelope).is_ok() => continue,
                Err(_) => return Err("A stored sync object failed authentication or validation".into()),
            };
            for operation in manifest.operations {
                if operation.kind != SyncOperationKindV1::Tombstone { continue; }
                let origin = decode_fixed::<16>(&operation.origin_device_id)?;
                let event_id = operation.local_event_id.ok_or("A stored tombstone has no event ID")?;
                tombstones.insert((origin, event_id, operation.counter));
            }
        }
        let Some(next) = page.next_cursor else { break; };
        if cursor.as_deref() == Some(next.as_str()) { return Err("Sync manifest listing did not advance".into()); }
        cursor = Some(next);
    }
    let statuses = tombstones.into_iter().map(|(origin, event_id, counter)| {
        let state = store.sync_tombstone_ack_state(origin, event_id, counter)
            .map_err(|_| "The encrypted vault cannot inspect tombstone acknowledgements")?;
        let pending = pending_tombstone_ack_device_ids(&state.active_device_ids, &state.acknowledged_device_ids);
        Ok::<_, String>(SyncTombstoneStatus {
            origin_device_id: URL_SAFE_NO_PAD.encode(origin),
            local_event_id: event_id,
            tombstone_counter: counter,
            active_device_ids: state.active_device_ids.iter().map(|id| URL_SAFE_NO_PAD.encode(id)).collect(),
            pending_device_ids: pending.into_iter().map(|id| URL_SAFE_NO_PAD.encode(id)).collect(),
        })
    }).collect::<Result<Vec<_>, String>>()?;
    serde_json::to_value(statuses).map_err(|_| "Tombstone status could not be encoded".into())
}

fn material_from_keys(root: &AccountRootKeyV1, wrapped: &WrappedVaultDataKeyV1) -> Result<SyncKeyMaterial, String> {
    wrapped.validate().map_err(|error| error.to_string())?;
    Ok(SyncKeyMaterial::new(
        root.secret_for_storage(), decode_fixed::<16>(&wrapped.vault_id)?,
        wrapped.key_epoch, decode_fixed::<24>(&wrapped.nonce)?,
        decode_fixed::<48>(&wrapped.ciphertext)?,
    ))
}

fn wrapped_key_from_material(material: &SyncKeyMaterial) -> WrappedVaultDataKeyV1 {
    WrappedVaultDataKeyV1 {
        schema_version: 1,
        vault_id: URL_SAFE_NO_PAD.encode(material.vault_id()),
        key_epoch: material.key_epoch(),
        nonce: URL_SAFE_NO_PAD.encode(material.wrapped_nonce()),
        ciphertext: URL_SAFE_NO_PAD.encode(material.wrapped_ciphertext()),
    }
}

fn ensure_peer_not_revoked(store: &Datastore, device_id: &str) -> Result<(), String> {
    let device_id = decode_fixed::<16>(device_id)?;
    if store.list_sync_trusted_devices()
        .map_err(|_| "The encrypted vault cannot inspect device access")?
        .iter().any(|device| device.device_id == device_id && device.revoked_at.is_some())
    {
        return Err("This device was revoked and cannot receive sync keys again".into());
    }
    Ok(())
}

fn decode_fixed<const N: usize>(value: &str) -> Result<[u8; N], String> {
    URL_SAFE_NO_PAD.decode(value)
        .map_err(|_| "Stored sync keys are invalid")?
        .try_into()
        .map_err(|_| "Stored sync keys are invalid".into())
}

fn verify_recovery_kit(args: Value) -> Result<Value, String> {
    let kit: RecoveryKitV1 = serde_json::from_value(args.get("kit").cloned().ok_or("Recovery kit is required")?)
        .map_err(|_| "Recovery kit is invalid")?;
    let phrase = args.get("recoveryPhrase").and_then(Value::as_str)
        .ok_or("Recovery phrase is required")?;
    let recovered = open_recovery_kit(&kit, phrase).map_err(|error| error.to_string())?;
    Ok(json!({
        "vault_id": recovered.wrapped_vault_key.vault_id,
        "key_epoch": recovered.wrapped_vault_key.key_epoch,
    }))
}

fn preview_recovery_restore(store: &Datastore, args: Value) -> Result<Value, String> {
    let (_, _, _, preview) = validate_recovery_restore(store, args)?;
    serde_json::to_value(preview).map_err(|_| "Restore preview could not be encoded".into())
}

fn validate_recovery_restore(
    store: &Datastore,
    args: Value,
) -> Result<(SyncKeyMaterial, SyncSnapshotV1, SyncRecoverySnapshotV1, SyncRestorePreview), String> {
    if store.load_sync_key_material()
        .map_err(|_| "The encrypted vault cannot inspect sync keys")?.is_some()
        || store.load_sync_snapshot()
            .map_err(|_| "The encrypted vault cannot inspect sync snapshots")?.is_some()
        || !store.get_buckets().map_err(|_| "The encrypted vault cannot inspect local activity")?.is_empty()
    {
        return Err("Sync snapshot restore requires a clean activity vault".into());
    }
    if store.capture_policy()
        .map_err(|_| "The encrypted vault cannot inspect recording state")?.recording
    {
        return Err("Pause recording before restoring a sync snapshot".into());
    }
    let kit: RecoveryKitV1 = argument(&args, "kit")?;
    let phrase = args.get("recoveryPhrase").and_then(Value::as_str)
        .ok_or("Recovery phrase is required")?;
    let snapshot: EncryptedSyncSnapshotV1 = argument(&args, "snapshot")?;
    snapshot.validate().map_err(|error| error.to_string())?;
    let recovered = open_recovery_kit(&kit, phrase).map_err(|error| error.to_string())?;
    let data_key = unwrap_vault_data_key(&recovered.account_root_key, &recovered.wrapped_vault_key)
        .map_err(|error| error.to_string())?;
    let plaintext = decrypt_snapshot(&data_key, &snapshot).map_err(|error| error.to_string())?;
    let export: SyncRecoverySnapshotV1 = serde_json::from_slice(&plaintext)
        .map_err(|_| "The encrypted activity snapshot is invalid")?;
    if export.schema_version != 1
        || export.sync.schema_version != SYNC_SCHEMA_VERSION_V1
        || export.sync.key_epoch != recovered.wrapped_vault_key.key_epoch
    {
        return Err("The encrypted sync recovery state is invalid".into());
    }

    let mut query_start: Option<String> = None;
    let mut query_end: Option<String> = None;
    for event in export.activity.buckets.values().flat_map(|bucket| {
        bucket.events.iter().flat_map(|events| events.iter())
    }) {
        let timestamp = event.timestamp.to_rfc3339();
        if query_start.as_ref().is_none_or(|start| timestamp.as_str() < start.as_str()) {
            query_start = Some(timestamp.clone());
        }
        if query_end.as_ref().is_none_or(|end| timestamp.as_str() > end.as_str()) {
            query_end = Some(timestamp);
        }
    }
    let device_id = store.load_sync_device_identity()
        .map_err(|_| "The encrypted vault cannot inspect its device identity")?
        .map(|identity| URL_SAFE_NO_PAD.encode(identity.device_id()));
    let snapshot_id = snapshot.snapshot_id.clone();
    let preview = SyncRestorePreview {
        schema_version: snapshot.schema_version,
        device_id,
        vault_id: recovered.wrapped_vault_key.vault_id.clone(),
        key_epoch: recovered.wrapped_vault_key.key_epoch,
        snapshot_id: snapshot_id.clone(),
        object_count: snapshot.envelopes.len(),
        version_start: snapshot_id.clone(),
        version_end: snapshot_id,
        tombstone_count: export.sync.event_mappings.iter().filter(|mapping| mapping.deleted).count(),
        query_start,
        query_end,
        policy_conflict_count: 0,
    };
    let material = material_from_keys(&recovered.account_root_key, &recovered.wrapped_vault_key)?;
    let stored_snapshot = SyncSnapshotV1::new(decode_fixed::<16>(&snapshot.snapshot_id)?, snapshot.envelopes);
    Ok((material, stored_snapshot, export, preview))
}
