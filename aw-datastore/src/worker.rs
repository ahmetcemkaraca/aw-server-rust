use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::thread;
use std::sync::{Arc, RwLock, RwLockReadGuard};
use std::sync::atomic::{AtomicBool, Ordering};

use chrono::DateTime;
use chrono::Duration;
use chrono::Utc;

use rusqlite::Connection;
use rusqlite::DropBehavior;
use rusqlite::Transaction;
use rusqlite::TransactionBehavior;

use aw_models::{
    AIInsightHistoryV1, AIInsightV1, AISettingsV1, Bucket, BucketsExport, CapturePolicy, EgressApprovalScopeV1, EgressApprovalV1,
    EgressReceiptV1, EgressUserPolicyV1, Event, SignedEgressPolicyBundleV1, TryVec,
};
#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
use aw_models::{
    PluginManifestV1, PluginOwnedEventV1,
    PluginStorageIntentV1, PluginWriteIntentV1,
};
const CAPTURE_KEY: &str = "peakactivity.capture_policy";
const EGRESS_KEY_PREFIX: &str = "egress.";

use crate::privacy_filter::PrivacyFilterEngine;
use crate::DatastoreError;
use crate::DatastoreInstance;
use crate::DatastoreMethod;
use crate::datastore::{AI_HISTORY_KEY, AI_SETTINGS_KEY};
use crate::EventCorrection;
use crate::EgressSecrets;
#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
use crate::SyncDeviceIdentity;
#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
use crate::SyncKeyMaterial;
#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
use crate::{
    SyncDeviceAccessEvent, SyncEgressConsentV1, SyncHeadCommitV1, SyncManifestHeadV1, SyncObjectHistoryV1,
    SyncObjectPageV1, SyncSnapshotV1, SyncTombstoneAckStateV1, SyncTombstoneIdentityV1,
    SyncRecoveryStateV1, SyncStoredOperationV1, SyncTrustedDevice,
};
#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
use crate::{SyncApplyBatchV1, SyncBaselineProgressV1};

#[derive(Clone)]
pub(crate) struct PayloadTag([u8; 32]);

impl fmt::Debug for PayloadTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("<redacted>") }
}

#[derive(Clone)]
pub(crate) struct EgressApprovalId(String);

impl fmt::Debug for EgressApprovalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("<redacted>") }
}

type RequestSender = mpsc_requests::RequestSender<Command, Result<Response, DatastoreError>>;
type RequestReceiver = mpsc_requests::RequestReceiver<Command, Result<Response, DatastoreError>>;

#[derive(Clone)]
pub struct Datastore {
    worker: Arc<RwLock<Option<Worker>>>,
    encrypted: Arc<AtomicBool>,
}

struct Worker {
    requester: RequestSender,
    thread: thread::JoinHandle<()>,
}

/// Keeps a vault worker open while an approved egress send is in flight.
pub struct EgressLease<'a> {
    worker: RwLockReadGuard<'a, Option<Worker>>,
}

impl EgressLease<'_> {
    fn request(&self, command: Command) -> Result<Response, DatastoreError> {
        let worker = self.worker.as_ref().ok_or(DatastoreError::Locked)?;
        let receiver = worker.requester.request(command)
            .map_err(|_| DatastoreError::InternalError("Datastore request channel unavailable".into()))?;
        receiver.collect().map_err(|_| DatastoreError::InternalError("Datastore response unavailable".into()))?
    }

    pub fn egress_kill_switch(&self) -> Result<bool, DatastoreError> {
        match self.request(Command::GetEgressKillSwitch())? {
            Response::Boolean(enabled) => Ok(enabled),
            _ => Err(DatastoreError::InternalError("Unexpected egress switch response".into())),
        }
    }

    pub fn consume_egress_approval(
        &self,
        id: &str,
        destination_id: &str,
        purpose_id: &str,
        retention_id: &str,
        policy_version: u64,
        payload_tag: [u8; 32],
        now: DateTime<Utc>,
    ) -> Result<EgressApprovalScopeV1, DatastoreError> {
        match self.request(Command::ConsumeEgressApproval(
            EgressApprovalId(id.into()), destination_id.into(), purpose_id.into(), retention_id.into(),
            policy_version, PayloadTag(payload_tag), now,
        ))? {
            Response::EgressApprovalScope(scope) => Ok(scope),
            _ => Err(DatastoreError::InternalError("Unexpected egress approval response".into())),
        }
    }

    pub fn record_egress_receipt(&self, receipt: &EgressReceiptV1) -> Result<(), DatastoreError> {
        _unwrap_empty_response(self.request(Command::RecordEgressReceipt(receipt.clone()))?)
    }
}

impl fmt::Debug for Datastore {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Datastore()")
    }
}

/*
 * TODO:
 * - Allow read requests to go straight through a read-only db connection instead of requesting the
 * worker thread for better performance?
 */

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub(crate) enum Response {
    Empty(),
    Bucket(Bucket),
    BucketMap(HashMap<String, Bucket>),
    Event(Event),
    EventList(Vec<Event>),
    Count(i64),
    KeyValue(String),
    KeyValues(HashMap<String, String>),
    CapturePolicy(CapturePolicy),
    ImportSummary(ImportSummary),
    EventCorrections(Vec<EventCorrection>),
    EgressReceipts(Vec<EgressReceiptV1>),
    EgressApprovals(Vec<EgressApprovalV1>),
    EgressApproval(Option<EgressApprovalV1>),
    EgressApprovalScope(EgressApprovalScopeV1),
    EgressSecrets(EgressSecrets),
    EgressApprovalId(EgressApprovalId),
    EgressPolicyState(Option<(SignedEgressPolicyBundleV1, EgressUserPolicyV1)>),
    EgressUserPolicy(EgressUserPolicyV1),
    AISettings(AISettingsV1),
    AISettingsUpdate(Option<AISettingsV1>),
    AIInsightHistory(AIInsightHistoryV1),
    AIInsightHistoryUpdate(Option<AIInsightHistoryV1>),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    PluginStorage(BTreeMap<String, serde_json::Value>),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    PluginEvents(Vec<PluginOwnedEventV1>),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    SyncDeviceIdentity(Option<SyncDeviceIdentity>),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    SyncKeyMaterial(Option<SyncKeyMaterial>),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    SyncSnapshot(Option<SyncSnapshotV1>),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    SyncRecoveryState(SyncRecoveryStateV1),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    SyncObject(Option<aw_models::SyncEnvelopeV1>),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    SyncObjectsPage(SyncObjectPageV1),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    SyncObjectHistory(Vec<SyncObjectHistoryV1>),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    SyncTombstoneAckState(SyncTombstoneAckStateV1),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    SyncEgressConsent(Option<SyncEgressConsentV1>),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    SyncRecoveryConfirmation(Option<String>),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    SyncTrustedDevices(Vec<SyncTrustedDevice>),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    SyncDeviceAccessHistory(Vec<SyncDeviceAccessEvent>),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    SyncManifestHead(Option<SyncManifestHeadV1>),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    SyncHeadCommit(SyncHeadCommitV1),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    SyncOperations(Vec<SyncStoredOperationV1>),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    SyncCounter(u64),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    SyncBaselineProgress(SyncBaselineProgressV1),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    SyncBaselineState(Option<SyncBaselineProgressV1>),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    SyncTombstoneAcknowledgements(Vec<aw_sync_e2ee::SyncTombstoneAckV1>),
    Boolean(bool),
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ImportSummary {
    pub buckets_created: usize,
    pub buckets_merged: usize,
    pub events_imported: usize,
    pub events_skipped: usize,
    pub events_changed: usize,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub(crate) enum Command {
    CreateBucket(Bucket),
    DeleteBucket(String),
    GetBucket(String),
    GetBuckets(),
    InsertEvents(String, Vec<Event>),
    ImportEvents(String, Vec<Event>),
    PreviewImportEvents(String, Vec<Event>),
    ImportBuckets(BucketsExport, bool),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    RestoreSyncSnapshotData(BucketsExport),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    RestoreSyncRecoveryData(BucketsExport, SyncKeyMaterial, SyncSnapshotV1, SyncRecoveryStateV1, SyncDeviceIdentity),
    CorrectEvent(String, Event),
    SplitEvent(String, i64, DateTime<Utc>),
    MergeEvents(String, i64, i64),
    GetEventCorrections(String, i64),
    DeleteEventsInRange(String, DateTime<Utc>, DateTime<Utc>),
    ApplyRawRetention(u32, DateTime<Utc>),
    EnableCapturePolicy(),
    GetCapturePolicy(),
    SetCapturePolicy(CapturePolicy),
    PauseCapture(),
    ResetPrivacy(),
    Heartbeat(String, Event, f64),
    GetEvent(String, i64),
    GetEvents(
        String,
        Option<DateTime<Utc>>,
        Option<DateTime<Utc>>,
        Option<u64>,
        bool,
    ),
    GetEventCount(String, Option<DateTime<Utc>>, Option<DateTime<Utc>>),
    DeleteEventsById(String, Vec<i64>),
    ForceCommit(),
    GetKeyValues(String),
    GetEgressKillSwitch(),
    SetEgressKillSwitch(bool),
    RecordEgressReceipt(EgressReceiptV1),
    GetEgressReceipts(usize),
    GetEgressApprovals(usize, DateTime<Utc>),
    GetEgressApproval(EgressApprovalId, DateTime<Utc>),
    GetOrCreateEgressSecrets(),
    CreateEgressApproval(String, String, String, u64, EgressApprovalScopeV1, PayloadTag, Option<DateTime<Utc>>, DateTime<Utc>),
    ConsumeEgressApproval(EgressApprovalId, String, String, String, u64, PayloadTag, DateTime<Utc>),
    ClearEgressApprovals(),
    GetEgressPolicyState(),
    StoreEgressPolicyState(SignedEgressPolicyBundleV1, EgressUserPolicyV1),
    GetEgressUserPolicy(),
    StoreEgressUserPolicy(EgressUserPolicyV1),
    GetAISettings(),
    CompareAndSetAISettings(u64, AISettingsV1),
    GetAIInsightHistory(),
    SaveAIInsight(AIInsightV1),
    DeleteAIInsight(String),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    GetPluginStorage(PluginManifestV1),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    ApplyPluginStorageIntents(PluginManifestV1, Vec<PluginStorageIntentV1>),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    DeletePluginStorage(PluginManifestV1),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    GetPluginEvents(PluginManifestV1),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    ApplyPluginWriteIntents(PluginManifestV1, Vec<PluginWriteIntentV1>),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    DeletePluginData(PluginManifestV1),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    GetSyncDeviceIdentity(),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    CreateSyncDeviceIdentity(SyncDeviceIdentity),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    GetSyncKeyMaterial(),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    GetSyncSnapshot(),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    GetSyncRecoveryState(u64),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    PrepareSyncSnapshotMappings(),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    SaveSyncSnapshot(SyncKeyMaterial, SyncSnapshotV1),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    GetSyncEnabled(),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    GetSyncEgressConsent(),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    SetSyncEnabled(bool, Option<String>, Option<String>),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    GetSyncObject(String),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    PutSyncObject(aw_models::SyncEnvelopeV1, String),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    ListSyncObjects(String, Option<String>, usize),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    DeleteSyncObjectAfterTombstones(String, Vec<SyncTombstoneIdentityV1>, String),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    ListSyncObjectHistory(usize),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    InstallSyncKeyMaterial(SyncKeyMaterial),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    InstallSyncRecovery(SyncKeyMaterial, SyncSnapshotV1),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    RotateSyncKeyMaterial(SyncKeyMaterial, SyncSnapshotV1, Option<[u8; 16]>, String),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    GetSyncRecoveryConfirmation(),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    ConfirmSyncRecoverySaved(String),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    RecordSyncPairing(Option<SyncKeyMaterial>, [u8; 16], [u8; 16], [u8; 32], [u8; 32], String),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    GetSyncTrustedDevices(),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    GetSyncDeviceAccessHistory(usize),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    GetSyncManifestHead([u8; 16], u64, [u8; 16]),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    CommitSyncManifestHead([u8; 16], u64, [u8; 16], SyncManifestHeadV1, SyncManifestHeadV1),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    PutSyncOperation(SyncStoredOperationV1),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    ListSyncOperations([u8; 16], u64, u64, usize),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    NextSyncOperationCounter([u8; 16]),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    AckSyncTombstone([u8; 16], u64, u64, [u8; 16], String),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    CanCollectSyncTombstone([u8; 16], u64, u64),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    GetSyncTombstoneAckState([u8; 16], u64, u64),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    BeginSyncBaseline(),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    GetSyncBaselineProgress(),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    ListLocalSyncTombstoneAcknowledgements(),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    ProcessSyncBaselineBatch(usize),
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    ApplySyncOperations(SyncApplyBatchV1),
    GetKeyValue(String),
    SetKeyValue(String, String),
    CompareAndSetKeyValue(String, Option<String>, Option<String>),
    DeleteKeyValue(String),
    RefreshPrivacyFilter(),
    RenameBucket(String, String),
    MigrateHostname(String),
    MigrateTestBucketNames(),
    Close(),
}

impl Command {
    fn requires_encrypted_vault(&self) -> bool {
        if matches!(self,
            Self::GetAISettings() | Self::CompareAndSetAISettings(_, _)
                | Self::GetAIInsightHistory() | Self::SaveAIInsight(_) | Self::DeleteAIInsight(_)
        ) {
            return true;
        }
        #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
        {
            matches!(
                self,
                Self::GetPluginStorage(_)
                    | Self::ApplyPluginStorageIntents(_, _)
                    | Self::DeletePluginStorage(_)
                    | Self::GetPluginEvents(_)
                    | Self::ApplyPluginWriteIntents(_, _)
                    | Self::DeletePluginData(_)
                    | Self::RestoreSyncSnapshotData(_)
                    | Self::RestoreSyncRecoveryData(_, _, _, _, _)
                    | Self::GetSyncDeviceIdentity()
                    | Self::CreateSyncDeviceIdentity(_)
                    | Self::GetSyncKeyMaterial()
                    | Self::GetSyncSnapshot()
                    | Self::GetSyncRecoveryState(_)
                    | Self::PrepareSyncSnapshotMappings()
                    | Self::SaveSyncSnapshot(_, _)
                    | Self::GetSyncEnabled()
                    | Self::GetSyncEgressConsent()
                    | Self::SetSyncEnabled(_, _, _)
                    | Self::GetSyncObject(_)
                    | Self::PutSyncObject(_, _)
                    | Self::ListSyncObjects(_, _, _)
                    | Self::DeleteSyncObjectAfterTombstones(_, _, _)
                    | Self::ListSyncObjectHistory(_)
                    | Self::InstallSyncKeyMaterial(_)
                    | Self::InstallSyncRecovery(_, _)
                    | Self::RotateSyncKeyMaterial(_, _, _, _)
                    | Self::GetSyncRecoveryConfirmation()
                    | Self::ConfirmSyncRecoverySaved(_)
                    | Self::RecordSyncPairing(_, _, _, _, _, _)
                    | Self::GetSyncTrustedDevices()
                    | Self::GetSyncDeviceAccessHistory(_)
                    | Self::GetSyncManifestHead(_, _, _)
                    | Self::CommitSyncManifestHead(_, _, _, _, _)
                    | Self::PutSyncOperation(_)
                    | Self::ListSyncOperations(_, _, _, _)
                    | Self::NextSyncOperationCounter(_)
                    | Self::AckSyncTombstone(_, _, _, _, _)
                    | Self::CanCollectSyncTombstone(_, _, _)
                    | Self::GetSyncTombstoneAckState(_, _, _)
                    | Self::BeginSyncBaseline()
                    | Self::GetSyncBaselineProgress()
                    | Self::ListLocalSyncTombstoneAcknowledgements()
                    | Self::ProcessSyncBaselineBatch(_)
                    | Self::ApplySyncOperations(_)
                    | Self::GetAISettings()
                    | Self::CompareAndSetAISettings(_, _)
            )
        }
        #[cfg(not(any(feature = "encryption", feature = "encryption-vendored")))]
        {
            false
        }
    }
}

struct PlannedImportBucket {
    id: String,
    create: Option<Bucket>,
    events: Vec<Event>,
}

struct ImportPlan {
    summary: ImportSummary,
    buckets: Vec<PlannedImportBucket>,
}

fn _unwrap_empty_response(response: Response) -> Result<(), DatastoreError> {
    match response {
        Response::Empty() => Ok(()),
        _ => panic!("Invalid response"),
    }
}

fn import_identity(event: &Event) -> Result<(DateTime<Utc>, i64, String), DatastoreError> {
    let duration = event.duration.num_nanoseconds()
        .ok_or_else(|| DatastoreError::InvalidImport("An event duration is out of range".into()))?;
    let data: BTreeMap<_, _> = event.data.iter().collect();
    let data = serde_json::to_string(&data)
        .map_err(|_| DatastoreError::InvalidImport("An event could not be encoded".into()))?;
    Ok((event.timestamp, duration, data))
}

struct DatastoreWorker {
    responder: RequestReceiver,
    legacy_import: bool,
    quit: bool,
    uncommitted_events: usize,
    commit: bool,
    last_heartbeat: HashMap<String, Option<Event>>,
    privacy_engine: PrivacyFilterEngine,
    capture_policy: Option<CapturePolicy>,
    capture_breaks: HashSet<String>,
}

impl DatastoreWorker {
    pub fn new(
        responder: mpsc_requests::RequestReceiver<Command, Result<Response, DatastoreError>>,
        legacy_import: bool,
    ) -> Self {
        DatastoreWorker {
            responder,
            legacy_import,
            quit: false,
            uncommitted_events: 0,
            commit: false,
            last_heartbeat: HashMap::new(),
            privacy_engine: PrivacyFilterEngine::new(vec![]),
            capture_policy: None,
            capture_breaks: HashSet::new(),
        }
    }

    fn work_loop(&mut self, method: DatastoreMethod) {
        // Open SQLite connection
        let mut conn = match &method {
            DatastoreMethod::Memory() => {
                Connection::open_in_memory().expect("Failed to create in-memory datastore")
            }
            DatastoreMethod::File(path) => {
                Connection::open(path).expect("Failed to create datastore")
            }
            #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
            DatastoreMethod::FileEncrypted(path, key) => {
                let conn = Connection::open(path).expect("Failed to create encrypted datastore");
                conn.pragma_update(None, "key", key.as_str())
                    .expect("Failed to set SQLCipher encryption key");
                // PRAGMA key always succeeds even with a wrong passphrase; the
                // first real SQL query is what fails. Read user_version immediately
                // to surface an incorrect key as a clear error rather than an
                // opaque panic later.
                conn.pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                    .expect("Failed to open encrypted database: wrong passphrase or not an encrypted database");
                info!("Opened encrypted database at {}", path);
                conn
            }
        };

        // WAL turns each commit into a single sequential WAL append+fsync where
        // delete mode paid two fsyncs plus journal-file churn, and lets future
        // reader connections proceed while a commit is in flight.
        // synchronous=FULL is set explicitly (rather than relying on the
        // default) so a commit remains durable on disk the moment it returns;
        // with NORMAL the WAL is only synced at checkpoints, which would
        // silently widen the loss window on power failure.
        // In-memory databases ignore the request (journal_mode stays "memory").
        let journal_mode: String = conn
            .pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))
            .expect("Failed to query journal_mode");
        if !matches!(&method, DatastoreMethod::Memory()) && journal_mode != "wal" {
            warn!("Failed to enable WAL (journal_mode={journal_mode}), continuing without it");
        }
        conn.pragma_update(None, "synchronous", "FULL")
            .expect("Failed to set synchronous=FULL");

        let encrypted = {
            #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
            {
                matches!(&method, DatastoreMethod::FileEncrypted(_, _))
            }
            #[cfg(not(any(feature = "encryption", feature = "encryption-vendored")))]
            {
                false
            }
        };
        let mut ds = DatastoreInstance::new(&conn, true, encrypted).unwrap();

        // Ensure legacy import
        if self.legacy_import {
            let transaction = match conn.transaction_with_behavior(TransactionBehavior::Immediate) {
                Ok(transaction) => transaction,
                Err(err) => {
                    panic!("Unable to start immediate transaction on SQLite database! {err}")
                }
            };
            match ds.ensure_legacy_import(&transaction) {
                Ok(_) => (),
                Err(err) => error!("Failed to do legacy import: {:?}", err),
            }
            match transaction.commit() {
                Ok(_) => (),
                Err(err) => {
                    error!("Failed to commit legacy import transaction: {err}");
                    // Continue without panicking — legacy import will be retried on
                    // next startup if the commit didn't persist.
                }
            }
        }

        // Start handling and respond to requests
        loop {
            let last_commit_time: DateTime<Utc> = Utc::now();
            let mut tx: Transaction =
                match conn.transaction_with_behavior(TransactionBehavior::Immediate) {
                    Ok(tx) => tx,
                    Err(err) => {
                        error!("Unable to start transaction! {:?}", err);
                        // Wait 1s before retrying
                        std::thread::sleep(std::time::Duration::from_millis(1000));
                        continue;
                    }
                };
            tx.set_drop_behavior(DropBehavior::Commit);

            self.uncommitted_events = 0;
            self.commit = false;
            // ForceCommit and Close promise the caller that their data is
            // committed, so their acks are held back until the transaction
            // below has actually committed. Acking first (as before) let a
            // caller reopen the database and read a pre-commit snapshot —
            // harmless under the rollback journal's locking, but a real race
            // in WAL mode where readers never block on the writer.
            // Native capture writes also wait for commit; legacy batching is
            // retained only when the explicit native capture policy is absent.
            let mut deferred_ack = None;
            loop {
                let (request, response_sender) = match self.responder.poll() {
                    Ok((req, res_sender)) => (req, res_sender),
                    Err(err) => {
                        // All references to responder is gone, quit
                        error!("DB worker quitting, error: {err:?}");
                        self.quit = true;
                        break;
                    }
                };
                let correction_write = matches!(&request, Command::InsertEvents(_, events) if events.iter().any(|event| event.id.is_some()));
                // ponytail: commit each native vault write before acknowledging it;
                // add batched durable receipts only if collector throughput requires them.
                let commit_sensitive = matches!(
                    &request,
                    Command::ForceCommit()
                        | Command::Close()
                        | Command::EnableCapturePolicy()
                        | Command::SetCapturePolicy(_)
                        | Command::PauseCapture()
                        | Command::ResetPrivacy()
                        | Command::ImportBuckets(_, true)
                        | Command::CorrectEvent(_, _)
                        | Command::SplitEvent(_, _, _)
                        | Command::MergeEvents(_, _, _)
                        | Command::DeleteBucket(_)
                        | Command::DeleteEventsById(_, _)
                        | Command::DeleteEventsInRange(_, _, _)
                        | Command::ApplyRawRetention(_, _)
                        | Command::SetEgressKillSwitch(_)
                        | Command::RecordEgressReceipt(_)
                        | Command::GetOrCreateEgressSecrets()
                        | Command::CreateEgressApproval(_, _, _, _, _, _, _, _)
                        | Command::ConsumeEgressApproval(_, _, _, _, _, _, _)
                        | Command::ClearEgressApprovals()
                        | Command::StoreEgressPolicyState(_, _)
                        | Command::StoreEgressUserPolicy(_)
                        | Command::CompareAndSetAISettings(_, _)
                        | Command::SaveAIInsight(_)
                        | Command::DeleteAIInsight(_)
                        | Command::CompareAndSetKeyValue(_, _, _)
                );
                let native_capture_commit = self.capture_policy.is_some()
                    && matches!(
                        &request,
                        Command::CreateBucket(_)
                            | Command::DeleteBucket(_)
                            | Command::InsertEvents(_, _)
                            | Command::ImportEvents(_, _)
                            | Command::Heartbeat(_, _, _)
                            | Command::DeleteEventsById(_, _)
                            | Command::SetKeyValue(_, _)
                            | Command::DeleteKeyValue(_)
                            | Command::RenameBucket(_, _)
                            | Command::MigrateHostname(_)
                            | Command::MigrateTestBucketNames()
                    );
                let ack_after_commit = correction_write || commit_sensitive || native_capture_commit;
                #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
                let ack_after_commit = ack_after_commit
                    || matches!(
                        &request,
                        Command::CreateSyncDeviceIdentity(_)
                            | Command::InstallSyncKeyMaterial(_)
                            | Command::RestoreSyncSnapshotData(_)
                            | Command::RestoreSyncRecoveryData(_, _, _, _, _)
                            | Command::PrepareSyncSnapshotMappings()
                            | Command::SaveSyncSnapshot(_, _)
                            | Command::InstallSyncRecovery(_, _)
                            | Command::RotateSyncKeyMaterial(_, _, _, _)
                            | Command::PutSyncObject(_, _)
                            | Command::DeleteSyncObjectAfterTombstones(_, _, _)
                            | Command::SetSyncEnabled(_, _, _)
                            | Command::ConfirmSyncRecoverySaved(_)
                            | Command::RecordSyncPairing(_, _, _, _, _, _)
                            | Command::CommitSyncManifestHead(_, _, _, _, _)
                            | Command::PutSyncOperation(_)
                            | Command::NextSyncOperationCounter(_)
                            | Command::AckSyncTombstone(_, _, _, _, _)
                            | Command::BeginSyncBaseline()
                            | Command::ProcessSyncBaselineBatch(_)
                            | Command::ApplySyncOperations(_)
                    );
                let response = self.handle_request(request, &mut ds, &tx);
                if ack_after_commit {
                    // Both commands force a commit, so the loop ends here.
                    deferred_ack = Some((response_sender, response));
                    break;
                }
                response_sender.respond(response);

                let now: DateTime<Utc> = Utc::now();
                let commit_interval_passed: bool = (now - last_commit_time) > Duration::seconds(15);
                if self.commit
                    || commit_interval_passed
                    || self.uncommitted_events > 100
                    || self.quit
                {
                    break;
                };
            }
            debug!(
                "Committing DB! Force commit {}, {} uncommitted events",
                self.commit, self.uncommitted_events
            );
            match tx.commit() {
                Ok(_) => {
                    if let Some((sender, response)) = deferred_ack.take() {
                        sender.respond(response);
                    }
                }
                Err(err) => {
                    if let Some(policy) = &mut self.capture_policy { policy.recording = false; }
                    self.last_heartbeat.clear();
                    error!(
                        "Failed to commit datastore transaction ({} events lost): {err}",
                        self.uncommitted_events
                    );
                    // Native writes have not been acknowledged and recording is blocked.
                    // Legacy batched callers may already have received an early response.
                    if let Some((sender, _)) = deferred_ack.take() {
                        sender.respond(Err(DatastoreError::InternalError(format!(
                            "Failed to commit datastore transaction: {err}"
                        ))));
                    }
                }
            }
            if self.quit {
                break;
            };
        }
        info!("DB Worker thread finished");
    }

    fn filter_event(&self, bucket: &str, event: Event, capture: bool) -> Option<Event> {
        if let Some(policy) = &self.capture_policy {
            // User regex redactions cannot hide an app/private marker to loosen consent.
            policy.filter(bucket, event.clone(), capture)?;
        }
        let event = self.privacy_engine.filter_event(bucket, event)?;
        match &self.capture_policy {
            Some(policy) => policy.filter(bucket, event, capture),
            None => Some(event),
        }
    }

    fn plan_import(
        &self,
        ds: &mut DatastoreInstance,
        tx: &Transaction,
        source: BucketsExport,
        apply_filters: bool,
    ) -> Result<ImportPlan, DatastoreError> {
        let mut summary = ImportSummary::default();
        let mut planned = Vec::new();
        let mut bucket_ids = HashSet::new();

        for (_, mut bucket) in source.buckets {
            if bucket.id.trim().is_empty() || !bucket_ids.insert(bucket.id.clone()) {
                return Err(DatastoreError::InvalidImport("Bucket IDs must be non-empty and unique".into()));
            }
            let (input, unparsed) = bucket.events.take()
                .map(TryVec::take_inner_with_skipped)
                .unwrap_or_default();
            summary.events_skipped += unparsed;

            let mut filtered = Vec::with_capacity(input.len());
            for event in input {
                if event.duration < Duration::zero()
                    || event.duration.num_nanoseconds().is_none()
                    || event.timestamp.timestamp_nanos_opt().is_none()
                    || event.timestamp.checked_add_signed(event.duration).is_none()
                {
                    return Err(DatastoreError::InvalidImport("An event has an invalid timestamp or duration".into()));
                }
                let original = event.clone();
                let filtered_event = if apply_filters {
                    self.filter_event(&bucket.id, event, false)
                } else {
                    Some(event)
                };
                match filtered_event {
                    Some(mut event) => {
                        let changed = event != original;
                        event.id = None;
                        filtered.push((event, changed));
                    }
                    None => summary.events_skipped += 1,
                }
            }

            let exists = match ds.get_bucket(&bucket.id) {
                Ok(_) => true,
                Err(DatastoreError::NoSuchBucket(_)) => false,
                Err(error) => return Err(error),
            };
            let mut identities = HashSet::new();
            if exists && !filtered.is_empty() {
                let start = filtered.iter().map(|(event, _)| event.timestamp).min().unwrap();
                let end = filtered.iter()
                    .map(|(event, _)| event.timestamp + event.duration)
                    .max().unwrap();
                identities.extend(ds.get_events_unclipped(tx, &bucket.id, Some(start), Some(end), None)?
                    .iter().map(import_identity).collect::<Result<Vec<_>, _>>()?);
            }

            let mut events = Vec::with_capacity(filtered.len());
            for (event, changed) in filtered {
                if !apply_filters || identities.insert(import_identity(&event)?) {
                    summary.events_imported += 1;
                    if changed { summary.events_changed += 1; }
                    events.push(event);
                } else {
                    summary.events_skipped += 1;
                }
            }

            if exists {
                summary.buckets_merged += 1;
                if !events.is_empty() {
                    planned.push(PlannedImportBucket { id: bucket.id, create: None, events });
                }
            } else {
                summary.buckets_created += 1;
                bucket.events = None;
                planned.push(PlannedImportBucket { id: bucket.id.clone(), create: Some(bucket), events });
            }
        }

        Ok(ImportPlan { summary, buckets: planned })
    }

    fn import_buckets(
        &mut self,
        ds: &mut DatastoreInstance,
        tx: &Transaction,
        source: BucketsExport,
        commit: bool,
        apply_filters: bool,
    ) -> Result<ImportSummary, DatastoreError> {
        let plan = self.plan_import(ds, tx, source, apply_filters)?;
        if !commit { return Ok(plan.summary); }

        tx.execute_batch("SAVEPOINT peakactivity_import")
            .map_err(|_| DatastoreError::InternalError("Could not begin atomic import".into()))?;
        let ImportPlan { summary, mut buckets } = plan;
        let result = (|| {
            for item in &mut buckets {
                if let Some(mut bucket) = item.create.take() {
                    bucket.events = Some(TryVec::new(std::mem::take(&mut item.events)));
                    ds.create_bucket(tx, bucket)?;
                } else {
                    ds.insert_events(tx, &item.id, std::mem::take(&mut item.events))?;
                }
            }
            tx.execute_batch("RELEASE SAVEPOINT peakactivity_import")
                .map_err(|_| DatastoreError::InternalError("Could not finish atomic import".into()))?;
            Ok::<(), DatastoreError>(())
        })();

        if let Err(error) = result {
            if tx.execute_batch("ROLLBACK TO SAVEPOINT peakactivity_import; RELEASE SAVEPOINT peakactivity_import").is_err() {
                let _ = tx.execute_batch("ROLLBACK");
                return Err(DatastoreError::InternalError("Import failed and rollback could not be confirmed; the datastore transaction was aborted".into()));
            }
            ds.reload_buckets(tx)?;
            return Err(error);
        }

        for bucket in &buckets { self.last_heartbeat.insert(bucket.id.clone(), None); }
        self.uncommitted_events += summary.events_imported;
        self.commit = true;
        Ok(summary)
    }

    fn correct_event(
        &mut self,
        ds: &mut DatastoreInstance,
        tx: &Transaction,
        bucket: &str,
        event: Event,
    ) -> Result<Event, DatastoreError> {
        if event.id.is_none() {
            return Err(DatastoreError::InvalidCorrection("An event ID is required".into()));
        }
        let event = self.filter_event(bucket, event, false)
            .ok_or_else(|| DatastoreError::InvalidCorrection("Correction violates current privacy controls".into()))?;
        let corrected = ds.correct_event(tx, bucket, &event, "local-ui")?;
        self.last_heartbeat.insert(bucket.to_string(), None);
        self.capture_breaks.insert(bucket.to_string());
        self.commit = true;
        Ok(corrected)
    }

    fn split_event(
        &mut self,
        ds: &mut DatastoreInstance,
        tx: &Transaction,
        bucket: &str,
        event_id: i64,
        split_at: DateTime<Utc>,
    ) -> Result<Vec<Event>, DatastoreError> {
        let original = ds.get_event(tx, bucket, event_id)?;
        let end = original.timestamp.checked_add_signed(original.duration)
            .ok_or_else(|| DatastoreError::InvalidCorrection("Event time range is invalid".into()))?;
        if original.duration <= Duration::zero() || split_at <= original.timestamp || split_at >= end {
            return Err(DatastoreError::InvalidCorrection("Split time must be inside the event".into()));
        }
        if bucket == "aw-stopwatch" && original.data.get("running").and_then(serde_json::Value::as_bool) == Some(true) {
            return Err(DatastoreError::InvalidCorrection("Stop the manual timer before splitting its current entry".into()));
        }
        let left = Event::new(original.timestamp, split_at - original.timestamp, original.data.clone());
        let right = Event::new(split_at, end - split_at, original.data);
        let left = self.filter_event(bucket, left, false)
            .ok_or_else(|| DatastoreError::InvalidCorrection("Split violates current privacy controls".into()))?;
        let right = self.filter_event(bucket, right, false)
            .ok_or_else(|| DatastoreError::InvalidCorrection("Split violates current privacy controls".into()))?;
        let parts = ds.replace_events_atomic(tx, bucket, &[event_id], vec![left, right], "local-ui-split", &["timestamp", "duration"])?;
        self.last_heartbeat.insert(bucket.to_string(), None);
        self.capture_breaks.insert(bucket.to_string());
        self.uncommitted_events += parts.len();
        self.commit = true;
        Ok(parts)
    }

    fn merge_events(
        &mut self,
        ds: &mut DatastoreInstance,
        tx: &Transaction,
        bucket: &str,
        first_id: i64,
        second_id: i64,
    ) -> Result<Event, DatastoreError> {
        if first_id == second_id {
            return Err(DatastoreError::InvalidCorrection("Choose two different events".into()));
        }
        let first = ds.get_event(tx, bucket, first_id)?;
        let second = ds.get_event(tx, bucket, second_id)?;
        if bucket == "aw-stopwatch" && [ &first, &second ].iter().any(|event|
            event.data.get("running").and_then(serde_json::Value::as_bool) == Some(true)) {
            return Err(DatastoreError::InvalidCorrection("Stop the manual timer before merging its current entry".into()));
        }
        let first = self.filter_event(bucket, first, false)
            .ok_or_else(|| DatastoreError::InvalidCorrection("Merge violates current privacy controls".into()))?;
        let second = self.filter_event(bucket, second, false)
            .ok_or_else(|| DatastoreError::InvalidCorrection("Merge violates current privacy controls".into()))?;
        let (earlier, later) = if first.timestamp <= second.timestamp { (first, second) } else { (second, first) };
        let earlier_end = earlier.timestamp.checked_add_signed(earlier.duration)
            .ok_or_else(|| DatastoreError::InvalidCorrection("Event time range is invalid".into()))?;
        if earlier.duration <= Duration::zero() || later.duration <= Duration::zero()
            || earlier_end != later.timestamp || earlier.data != later.data {
            return Err(DatastoreError::InvalidCorrection("Only adjacent events with the same minimized data can be merged".into()));
        }
        let duration = earlier.duration.checked_add(&later.duration)
            .ok_or_else(|| DatastoreError::InvalidCorrection("Merged event duration is out of range".into()))?;
        let merged = Event::new(earlier.timestamp, duration, earlier.data);
        let merged = self.filter_event(bucket, merged, false)
            .ok_or_else(|| DatastoreError::InvalidCorrection("Merge violates current privacy controls".into()))?;
        let mut result = ds.replace_events_atomic(tx, bucket, &[first_id, second_id], vec![merged], "local-ui-merge", &["timestamp", "duration"])?;
        self.last_heartbeat.insert(bucket.to_string(), None);
        self.capture_breaks.insert(bucket.to_string());
        self.uncommitted_events += result.len();
        self.commit = true;
        result.pop().ok_or_else(|| DatastoreError::InternalError("Merged event was not returned".into()))
    }

    fn apply_raw_retention(
        &mut self,
        ds: &mut DatastoreInstance,
        tx: &Transaction,
        days: u32,
        now: DateTime<Utc>,
    ) -> Result<u64, DatastoreError> {
        if days > 3650 { return Err(DatastoreError::InvalidRetentionPolicy); }
        if days == 0 { return Ok(0); }
        let cutoff = now.checked_sub_signed(Duration::days(i64::from(days)))
            .ok_or(DatastoreError::InvalidRetentionPolicy)?;
        let buckets = ds.get_buckets();
        let targets: Vec<_> = buckets.into_iter().filter_map(|(id, bucket)| {
            bucket.metadata.start.filter(|start| *start < cutoff).map(|start| (id, start))
        }).collect();
        if targets.is_empty() { return Ok(0); }

        tx.execute_batch("SAVEPOINT peakactivity_retention")
            .map_err(|_| DatastoreError::InternalError("Could not begin retention cleanup".into()))?;
        let result = (|| {
            let mut removed = 0;
            for (id, start) in &targets {
                removed += ds.delete_events_in_range(tx, id, *start, cutoff)?;
            }
            tx.execute_batch("RELEASE SAVEPOINT peakactivity_retention")
                .map_err(|_| DatastoreError::InternalError("Could not finish retention cleanup".into()))?;
            Ok::<u64, DatastoreError>(removed)
        })();
        let removed = match result {
            Ok(removed) => removed,
            Err(error) => {
                if tx.execute_batch("ROLLBACK TO SAVEPOINT peakactivity_retention; RELEASE SAVEPOINT peakactivity_retention").is_err() {
                    let _ = tx.execute_batch("ROLLBACK");
                    return Err(DatastoreError::InternalError("Retention failed and rollback could not be confirmed; the datastore transaction was aborted".into()));
                }
                ds.reload_buckets(tx)?;
                return Err(error);
            }
        };
        for (id, _) in targets {
            self.last_heartbeat.insert(id.clone(), None);
            self.capture_breaks.insert(id);
        }
        self.uncommitted_events += removed as usize;
        self.commit = true;
        Ok(removed)
    }

    fn save_capture_policy(&mut self, ds: &mut DatastoreInstance, tx: &Transaction,
                           mut policy: CapturePolicy, force_epoch: bool) -> Result<Response, DatastoreError> {
        policy.validate().map_err(|error| DatastoreError::InternalError(error.into()))?;
        let current = self.capture_policy.as_ref()
            .ok_or_else(|| DatastoreError::InternalError("Capture policy unavailable".into()))?;
        if policy.revision != current.revision || policy.effective_from != current.effective_from {
            return Err(DatastoreError::InternalError("capture-policy-conflict".into()));
        }
        policy.effective_from = current.effective_from;
        if !force_epoch && &policy == current { return Ok(Response::CapturePolicy(current.clone())); }
        policy.revision = current.revision.checked_add(1)
            .ok_or_else(|| DatastoreError::InternalError("Capture policy revision exhausted".into()))?;
        policy.effective_from = Utc::now();
        ds.insert_key_value(tx, CAPTURE_KEY, &serde_json::to_string(&policy).unwrap())?;
        self.capture_policy = Some(policy.clone());
        self.last_heartbeat.clear();
        self.capture_breaks.clear();
        self.commit = true;
        Ok(Response::CapturePolicy(policy))
    }

    fn handle_request(
        &mut self,
        request: Command,
        ds: &mut DatastoreInstance,
        tx: &Transaction,
    ) -> Result<Response, DatastoreError> {
        match request {
            Command::EnableCapturePolicy() => {
                let mut policy = match ds.get_key_value(tx, CAPTURE_KEY) {
                    Ok(value) => serde_json::from_str::<CapturePolicy>(&value)
                        .map_err(|_| DatastoreError::InternalError("Invalid saved capture policy".into()))?,
                    Err(DatastoreError::NoSuchKey(_)) => CapturePolicy::default(),
                    Err(error) => return Err(error),
                };
                policy.validate().map_err(|error| DatastoreError::InternalError(error.into()))?;
                // A new process/unlock starts a new capture epoch; old buffers cannot replay.
                policy.effective_from = Utc::now();
                policy.revision = policy.revision.checked_add(1)
                    .ok_or_else(|| DatastoreError::InternalError("Capture policy revision exhausted".into()))?;
                match ds.get_key_value(tx, "settings.privacy_filters") {
                    Ok(value) => self.privacy_engine = PrivacyFilterEngine::from_json(&value)
                        .map_err(|_| DatastoreError::InternalError("Invalid saved privacy filters".into()))?,
                    Err(DatastoreError::NoSuchKey(_)) => {},
                    Err(error) => return Err(error),
                }
                ds.insert_key_value(tx, CAPTURE_KEY, &serde_json::to_string(&policy).unwrap())?;
                self.capture_policy = Some(policy.clone());
                self.last_heartbeat.clear();
                self.capture_breaks.clear();
                self.commit = true;
                Ok(Response::CapturePolicy(policy))
            }
            Command::GetCapturePolicy() => self.capture_policy.clone().map(Response::CapturePolicy)
                .ok_or_else(|| DatastoreError::InternalError("Capture policy is not configured".into())),
            Command::SetCapturePolicy(policy) => self.save_capture_policy(ds, tx, policy, false),
            Command::ResetPrivacy() => {
                let mut saved = std::collections::BTreeMap::new();
                for key in [CAPTURE_KEY, "settings.privacy_filters"] {
                    match ds.get_key_value(tx, key) {
                        Ok(value) => { saved.insert(key, value); },
                        Err(DatastoreError::NoSuchKey(_)) => {},
                        Err(error) => return Err(error),
                    }
                }
                let backup_key = format!("peakactivity.privacy_backup.{}", Utc::now().timestamp_nanos_opt().unwrap_or(0));
                ds.insert_key_value(tx, &backup_key, &serde_json::to_string(&saved).unwrap())?;
                let mut policy = CapturePolicy::default();
                policy.revision = self.capture_policy.as_ref().map_or(1, |p| p.revision.saturating_add(1));
                ds.insert_key_value(tx, CAPTURE_KEY, &serde_json::to_string(&policy).unwrap())?;
                ds.insert_key_value(tx, "settings.privacy_filters", "[]")?;
                self.capture_policy = Some(policy.clone());
                self.privacy_engine = PrivacyFilterEngine::new(vec![]);
                self.last_heartbeat.clear();
                self.capture_breaks.clear();
                self.commit = true;
                Ok(Response::CapturePolicy(policy))
            }
            Command::PauseCapture() => {
                let mut policy = self.capture_policy.clone()
                    .ok_or_else(|| DatastoreError::InternalError("Capture policy unavailable".into()))?;
                policy.recording = false;
                policy.paused_until = None;
                let result = self.save_capture_policy(ds, tx, policy, true);
                if result.is_err() {
                    if let Some(policy) = &mut self.capture_policy {
                        policy.recording = false;
                        policy.effective_from = Utc::now();
                        policy.revision = policy.revision.saturating_add(1);
                    }
                    self.last_heartbeat.clear();
                    self.capture_breaks.clear();
                }
                result
            }
            Command::CreateBucket(mut bucket) => {
                if let Some(events) = bucket.events.take() {
                    bucket.events = Some(TryVec::new(events.take_inner().into_iter()
                        .filter_map(|mut event| {
                            event.id = None;
                            self.filter_event(&bucket.id, event, false)
                        }).collect()));
                }
                match ds.create_bucket(tx, bucket) {
                Ok(_) => {
                    self.commit = true;
                    Ok(Response::Empty())
                }
                Err(e) => Err(e),
                }
            },
            Command::DeleteBucket(bucketname) => match ds.delete_bucket(tx, &bucketname) {
                Ok(_) => {
                    self.last_heartbeat.remove(&bucketname);
                    self.capture_breaks.remove(&bucketname);
                    self.commit = true;
                    Ok(Response::Empty())
                }
                Err(e) => Err(e),
            },
            Command::GetBucket(bucketname) => match ds.get_bucket(&bucketname) {
                Ok(b) => Ok(Response::Bucket(b)),
                Err(e) => Err(e),
            },
            Command::GetBuckets() => Ok(Response::BucketMap(ds.get_buckets())),
            Command::InsertEvents(bucketname, events) => {
                if events.iter().any(|event| event.id.is_some()) {
                    if events.iter().any(|event| event.id.is_none()) {
                        return Err(DatastoreError::InvalidCorrection("New events and corrections must be submitted separately".into()));
                    }
                    let corrected = events.into_iter().map(|event| {
                        self.filter_event(&bucketname, event, false)
                            .ok_or_else(|| DatastoreError::InvalidCorrection("Correction violates current privacy controls".into()))
                    }).collect::<Result<Vec<_>, _>>()?;
                    let corrected = ds.correct_events(tx, &bucketname, &corrected, "local-api")?;
                    self.last_heartbeat.insert(bucketname.clone(), None);
                    self.capture_breaks.insert(bucketname);
                    self.uncommitted_events += corrected.len();
                    self.commit = true;
                    return Ok(Response::EventList(corrected));
                }
                let input_count = events.len();
                let filtered = events.into_iter().filter_map(|event| self.filter_event(&bucketname, event, true)).collect::<Vec<_>>();
                if self.capture_policy.is_some() && filtered.len() < input_count { self.capture_breaks.insert(bucketname.clone()); }
                if filtered.is_empty() {
                    return Ok(Response::EventList(vec![]));
                }
                match ds.insert_events(tx, &bucketname, filtered) {
                    Ok(events) => {
                        self.uncommitted_events += events.len();
                        self.last_heartbeat.insert(bucketname.to_string(), None); // invalidate last_heartbeat cache
                        Ok(Response::EventList(events))
                    }
                    Err(e) => Err(e),
                }
            }
            Command::ImportEvents(bucketname, events) => {
                let filtered = events.into_iter().filter_map(|mut event| {
                    event.id = None;
                    self.filter_event(&bucketname, event, false)
                }).collect();
                let result = ds.insert_events(tx, &bucketname, filtered)?;
                self.uncommitted_events += result.len();
                self.last_heartbeat.insert(bucketname, None);
                Ok(Response::EventList(result))
            }
            Command::PreviewImportEvents(bucketname, events) => Ok(Response::EventList(events.into_iter()
                .filter_map(|event| self.filter_event(&bucketname, event, false)).collect())),
                Command::ImportBuckets(source, commit) => self.import_buckets(ds, tx, source, commit, true)
                    .map(Response::ImportSummary),
                #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
                Command::RestoreSyncSnapshotData(source) => {
                    let has_sync_keys = ds.get_sync_key_material(tx)?.is_some();
                    let has_sync_snapshot = ds.get_sync_snapshot(tx)?.is_some();
                    if has_sync_keys || has_sync_snapshot || !ds.get_buckets().is_empty() {
                        return Err(DatastoreError::InvalidImport(
                            "Encrypted sync snapshots can be restored only into a clean vault".into(),
                        ));
                    }
                    self.import_buckets(ds, tx, source, true, false).map(Response::ImportSummary)
                }
                #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
                Command::RestoreSyncRecoveryData(source, material, snapshot, state, identity) => {
                    let has_sync_keys = ds.get_sync_key_material(tx)?.is_some();
                    let has_sync_snapshot = ds.get_sync_snapshot(tx)?.is_some();
                    if has_sync_keys || has_sync_snapshot || !ds.get_buckets().is_empty()
                        || self.capture_policy.as_ref().is_some_and(|policy| policy.recording)
                    {
                        return Err(DatastoreError::InvalidImport(
                            "Encrypted sync snapshots require a clean vault with recording paused".into(),
                        ));
                    }
                    let old_commit = self.commit;
                    let old_uncommitted_events = self.uncommitted_events;
                    tx.execute_batch("SAVEPOINT peakactivity_sync_recovery")
                        .map_err(|_| DatastoreError::InternalError("Could not begin atomic sync recovery".into()))?;
                    let result = (|| {
                        let summary = self.import_buckets(ds, tx, source, true, false)?;
                        ds.install_sync_recovery_data(tx, &material, &snapshot, &state, &identity)?;
                        tx.execute_batch("RELEASE SAVEPOINT peakactivity_sync_recovery")
                            .map_err(|_| DatastoreError::InternalError("Could not finish atomic sync recovery".into()))?;
                        Ok::<_, DatastoreError>(summary)
                    })();
                    match result {
                        Ok(summary) => Ok(Response::ImportSummary(summary)),
                        Err(error) => {
                            self.commit = old_commit;
                            self.uncommitted_events = old_uncommitted_events;
                            if tx.execute_batch("ROLLBACK TO SAVEPOINT peakactivity_sync_recovery; RELEASE SAVEPOINT peakactivity_sync_recovery").is_err() {
                                let _ = tx.execute_batch("ROLLBACK");
                                return Err(DatastoreError::InternalError("Sync recovery failed and rollback could not be confirmed".into()));
                            }
                            ds.reload_buckets(tx)?;
                            Err(error)
                        }
                    }
                }
            Command::Heartbeat(bucketname, event, pulsetime) => {
                ds.get_bucket(&bucketname)?;
                if self.capture_policy.is_some() && event.data.get("capture_break") == Some(&serde_json::Value::Bool(true)) {
                    self.capture_breaks.insert(bucketname.clone());
                }
                // Apply privacy filter to heartbeat
                let filtered = match self.filter_event(&bucketname, event.clone(), true) {
                    Some(event) => event,
                    None => {
                        if self.capture_policy.is_some() {
                            self.capture_breaks.insert(bucketname.clone());
                            self.last_heartbeat.insert(bucketname, None);
                            return Ok(Response::Event(Event { data: Default::default(), duration: Duration::zero(), id: None, ..event }));
                        }
                        // Heartbeat dropped by filter — return last cached event so the
                        // watcher's heartbeat-merge state machine continues correctly.
                        // Fall back to the incoming event itself if no prior event is cached
                        // (avoids returning a zero-timestamp default Event).
                        let last = self
                            .last_heartbeat
                            .get(&bucketname)
                            .and_then(|e| e.clone())
                            .unwrap_or(event);
                        return Ok(Response::Event(last));
                    }
                };
                if let Some(policy) = &self.capture_policy {
                    let previous = match self.last_heartbeat.get(&bucketname).and_then(Clone::clone) {
                        Some(event) => Some(event),
                        None => ds.get_events(tx, &bucketname, None, None, Some(1))?.pop(),
                    };
                    let boundary = policy.paused_until.map_or(policy.effective_from, |until| until.max(policy.effective_from));
                    if self.capture_breaks.remove(&bucketname) || previous.as_ref().is_none_or(|event| event.timestamp < boundary) {
                        let inserted = ds.insert_events(tx, &bucketname, vec![filtered])?.pop()
                            .ok_or_else(|| DatastoreError::InternalError("Capture insert returned no event".into()))?;
                        self.last_heartbeat.insert(bucketname, Some(inserted.clone()));
                        self.uncommitted_events += 1;
                        return Ok(Response::Event(inserted));
                    }
                    self.last_heartbeat.insert(bucketname.clone(), previous);
                }
                match ds.heartbeat(
                    tx,
                    &bucketname,
                    filtered,
                    pulsetime,
                    &mut self.last_heartbeat,
                ) {
                    Ok(e) => {
                        self.uncommitted_events += 1;
                        Ok(Response::Event(e))
                    }
                    Err(e) => Err(e),
                }
            }
            Command::GetEvent(bucketname, event_id) => {
                match ds.get_event(tx, &bucketname, event_id) {
                    Ok(el) => Ok(Response::Event(el)),
                    Err(e) => Err(e),
                }
            }
            Command::CorrectEvent(bucketname, event) => self.correct_event(ds, tx, &bucketname, event)
                .map(Response::Event),
            Command::SplitEvent(bucketname, event_id, split_at) => self
                .split_event(ds, tx, &bucketname, event_id, split_at)
                .map(Response::EventList),
            Command::MergeEvents(bucketname, first_id, second_id) => self
                .merge_events(ds, tx, &bucketname, first_id, second_id)
                .map(Response::Event),
            Command::GetEventCorrections(bucketname, event_id) => ds
                .get_event_corrections(tx, &bucketname, event_id)
                .map(Response::EventCorrections),
            Command::GetEvents(bucketname, starttime_opt, endtime_opt, limit_opt, unclipped) => {
                let result = if unclipped {
                    ds.get_events_unclipped(tx, &bucketname, starttime_opt, endtime_opt, limit_opt)
                } else {
                    ds.get_events(tx, &bucketname, starttime_opt, endtime_opt, limit_opt)
                };
                match result {
                    Ok(el) => Ok(Response::EventList(el)),
                    Err(e) => Err(e),
                }
            }
            Command::GetEventCount(bucketname, starttime_opt, endtime_opt) => {
                match ds.get_event_count(tx, &bucketname, starttime_opt, endtime_opt) {
                    Ok(n) => Ok(Response::Count(n)),
                    Err(e) => Err(e),
                }
            }
            Command::DeleteEventsById(bucketname, event_ids) => {
                match ds.delete_events_by_id(tx, &bucketname, event_ids) {
                    Ok(()) => {
                        self.last_heartbeat.insert(bucketname.clone(), None);
                        self.capture_breaks.insert(bucketname);
                        self.commit = true;
                        Ok(Response::Empty())
                    }
                    Err(e) => Err(e),
                }
            }
            Command::DeleteEventsInRange(bucketname, start, end) => {
                match ds.delete_events_in_range(tx, &bucketname, start, end) {
                    Ok(removed) => {
                        self.last_heartbeat.insert(bucketname.clone(), None);
                        self.capture_breaks.insert(bucketname);
                        self.commit = true;
                        Ok(Response::Count(removed as i64))
                    }
                    Err(error) => Err(error),
                }
            }
            Command::ApplyRawRetention(days, now) => self.apply_raw_retention(ds, tx, days, now)
                .map(|removed| Response::Count(removed as i64)),
            Command::ForceCommit() => {
                self.commit = true;
                Ok(Response::Empty())
            }
            Command::GetKeyValues(pattern) => match ds.get_key_values(tx, pattern.as_str()) {
                Ok(result) => Ok(Response::KeyValues(result)),
                Err(e) => Err(e),
            },
            #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
            Command::GetPluginStorage(manifest) => ds.get_plugin_storage(tx, &manifest)
                .map(Response::PluginStorage),
            #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
            Command::ApplyPluginStorageIntents(manifest, intents) => {
                match ds.apply_plugin_storage_intents(tx, &manifest, &intents) {
                    Ok(()) => { self.commit = true; Ok(Response::Empty()) }
                    Err(error) => Err(error),
                }
            }
            #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
            Command::DeletePluginStorage(manifest) => match ds.delete_plugin_storage(tx, &manifest) {
                Ok(()) => { self.commit = true; Ok(Response::Empty()) }
                Err(error) => Err(error),
            },
            #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
            Command::GetPluginEvents(manifest) => ds.get_plugin_events(tx, &manifest)
                .map(Response::PluginEvents),
            #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
            Command::ApplyPluginWriteIntents(manifest, intents) => match ds.apply_plugin_write_intents(tx, &manifest, &intents) {
                Ok(()) => { self.commit = true; Ok(Response::Empty()) }
                Err(error) => Err(error),
            },
            #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
            Command::DeletePluginData(manifest) => match ds.delete_plugin_data(tx, &manifest) {
                Ok(()) => { self.commit = true; Ok(Response::Empty()) }
                Err(error) => Err(error),
            },
            #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
            Command::GetSyncDeviceIdentity() => ds
                .get_sync_device_identity(tx)
                .map(Response::SyncDeviceIdentity),
            #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
            Command::CreateSyncDeviceIdentity(identity) => {
                match ds.create_sync_device_identity(tx, &identity) {
                    Ok(()) => {
                        self.commit = true;
                        Ok(Response::Empty())
                    }
                    Err(error) => Err(error),
                }
            }
            #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
            Command::GetSyncKeyMaterial() => ds
                .get_sync_key_material(tx)
                .map(Response::SyncKeyMaterial),
            #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
            Command::GetSyncSnapshot() => ds.get_sync_snapshot(tx).map(Response::SyncSnapshot),
            #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
            Command::GetSyncRecoveryState(key_epoch) => ds
                .get_sync_recovery_state(tx, key_epoch)
                .map(Response::SyncRecoveryState),
            #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
            Command::PrepareSyncSnapshotMappings() => match ds.prepare_sync_snapshot_mappings(tx) {
                Ok(()) => { self.commit = true; Ok(Response::Empty()) }
                Err(error) => Err(error),
            },
            #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
            Command::SaveSyncSnapshot(material, snapshot) => {
                let current = ds.get_sync_key_material(tx)?
                    .ok_or_else(|| DatastoreError::InternalError("Sync keys are not installed".into()))?;
                if current.account_root_key() != material.account_root_key()
                    || current.vault_id() != material.vault_id()
                    || current.key_epoch() != material.key_epoch()
                    || current.wrapped_nonce() != material.wrapped_nonce()
                    || current.wrapped_ciphertext() != material.wrapped_ciphertext()
                {
                    return Err(DatastoreError::InternalError("Sync snapshot key material is stale".into()));
                }
                ds.replace_sync_snapshot(tx, &snapshot, &material)?;
                self.commit = true;
                Ok(Response::Empty())
            }
            #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
            Command::GetSyncEnabled() => ds.sync_enabled(tx).map(Response::Boolean),
            #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
            Command::GetSyncEgressConsent() => ds.sync_egress_consent(tx).map(Response::SyncEgressConsent),
            #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
            Command::SetSyncEnabled(enabled, destination_id, purpose_id) => match ds.set_sync_enabled(tx, enabled, destination_id.as_deref(), purpose_id.as_deref()) {
                Ok(()) => { self.commit = true; Ok(Response::Empty()) }
                Err(error) => Err(error),
            },
            #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
            Command::GetSyncObject(object_id) => ds.get_sync_object(tx, &object_id).map(Response::SyncObject),
            #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
            Command::PutSyncObject(envelope, stored_at) => {
                match ds.put_sync_object(tx, &envelope, &stored_at) {
                    Ok(inserted) => {
                        self.commit |= inserted;
                        Ok(Response::Boolean(inserted))
                    }
                    Err(error) => Err(error),
                }
            }
            #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
            Command::ListSyncObjects(vault_id, after, limit) => ds.list_sync_objects(tx, &vault_id, after.as_deref(), limit).map(Response::SyncObjectsPage),
            #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
            Command::DeleteSyncObjectAfterTombstones(object_id, tombstones, deleted_at) => {
                match ds.delete_sync_object_after_tombstones(tx, &object_id, &tombstones, &deleted_at) {
                    Ok(deleted) => {
                        self.commit |= deleted;
                        Ok(Response::Boolean(deleted))
                    }
                    Err(error) => Err(error),
                }
            }
            #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
            Command::ListSyncObjectHistory(limit) => ds.list_sync_object_history(tx, limit).map(Response::SyncObjectHistory),
            #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
            Command::InstallSyncKeyMaterial(material) => {
                match ds.install_sync_key_material(tx, &material) {
                    Ok(()) => {
                        self.commit = true;
                        Ok(Response::Empty())
                    }
                    Err(error) => Err(error),
                }
            }
            #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
            Command::InstallSyncRecovery(material, snapshot) => {
                match ds.install_sync_recovery(tx, &material, &snapshot) {
                    Ok(()) => {
                        self.commit = true;
                        Ok(Response::Empty())
                    }
                    Err(error) => Err(error),
                }
            }
            #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
            Command::RotateSyncKeyMaterial(material, snapshot, revoke_device, occurred_at) => {
                match ds.rotate_sync_key_material(tx, &material, &snapshot, revoke_device.as_ref(), &occurred_at) {
                    Ok(rotated) => {
                        self.commit |= rotated;
                        Ok(Response::Boolean(rotated))
                    }
                    Err(error) => Err(error),
                }
            }
            #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
            Command::GetSyncRecoveryConfirmation() => ds
                .sync_recovery_confirmation(tx)
                .map(Response::SyncRecoveryConfirmation),
            #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
            Command::ConfirmSyncRecoverySaved(confirmed_at) => {
                match ds.confirm_sync_recovery_saved(tx, &confirmed_at) {
                    Ok(()) => {
                        self.commit = true;
                        Ok(Response::Empty())
                    }
                    Err(error) => Err(error),
                }
            }
            #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
            Command::RecordSyncPairing(material, offer_id, device_id, x25519_public_key, ed25519_public_key, occurred_at) => {
                match ds.record_sync_pairing(
                    tx,
                    material.as_ref(),
                    &offer_id,
                    &device_id,
                    &x25519_public_key,
                    &ed25519_public_key,
                    &occurred_at,
                ) {
                    Ok(()) => {
                        self.commit = true;
                        Ok(Response::Empty())
                    }
                    Err(error) => Err(error),
                }
            }
            #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
            Command::GetSyncTrustedDevices() => ds
                .get_sync_trusted_devices(tx)
                .map(Response::SyncTrustedDevices),
            #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
            Command::GetSyncDeviceAccessHistory(limit) => ds
                .get_sync_device_access_history(tx, limit)
                .map(Response::SyncDeviceAccessHistory),
            #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
            Command::GetSyncManifestHead(vault_id, key_epoch, device_id) => ds
                .get_sync_manifest_head(tx, &vault_id, key_epoch, &device_id)
                .map(Response::SyncManifestHead),
            #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
            Command::CommitSyncManifestHead(vault_id, key_epoch, device_id, expected, next) => {
                match ds.commit_sync_manifest_head(tx, &vault_id, key_epoch, &device_id, expected, next) {
                    Ok(result) => {
                        self.commit |= result == SyncHeadCommitV1::Advanced;
                        Ok(Response::SyncHeadCommit(result))
                    }
                    Err(error) => Err(error),
                }
            }
            #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
            Command::PutSyncOperation(operation) => {
                match ds.put_sync_operation(tx, &operation) {
                    Ok(inserted) => {
                        self.commit |= inserted;
                        Ok(Response::Boolean(inserted))
                    }
                    Err(error) => Err(error),
                }
            }
            #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
            Command::ListSyncOperations(device_id, key_epoch, after_counter, limit) => ds
                .list_sync_operations(tx, &device_id, key_epoch, after_counter, limit)
                .map(Response::SyncOperations),
            #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
            Command::NextSyncOperationCounter(device_id) => {
                match ds.next_sync_operation_counter(tx, &device_id) {
                    Ok(counter) => {
                        self.commit = true;
                        Ok(Response::SyncCounter(counter))
                    }
                    Err(error) => Err(error),
                }
            }
            #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
            Command::AckSyncTombstone(origin, event_id, counter, device, acknowledged_at) => {
                match ds.record_sync_tombstone_ack(tx, &origin, event_id, counter, &device, &acknowledged_at) {
                    Ok(inserted) => {
                        self.commit |= inserted;
                        Ok(Response::Boolean(inserted))
                    }
                    Err(error) => Err(error),
                }
            }
            #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
            Command::CanCollectSyncTombstone(origin, event_id, counter) => ds
                .can_collect_sync_tombstone(tx, &origin, event_id, counter)
                .map(Response::Boolean),
            #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
            Command::GetSyncTombstoneAckState(origin, event_id, counter) => ds
                .sync_tombstone_ack_state(tx, &origin, event_id, counter)
                .map(Response::SyncTombstoneAckState),
            #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
            Command::BeginSyncBaseline() => ds.begin_sync_baseline(tx).map(Response::SyncBaselineProgress),
            #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
            Command::GetSyncBaselineProgress() => ds.sync_baseline_progress(tx).map(Response::SyncBaselineState),
            #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
            Command::ListLocalSyncTombstoneAcknowledgements() => ds
                .list_local_sync_tombstone_acknowledgements(tx)
                .map(Response::SyncTombstoneAcknowledgements),
            #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
            Command::ProcessSyncBaselineBatch(limit) => ds
                .process_sync_baseline_batch(tx, limit)
                .map(Response::SyncBaselineProgress),
            #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
            Command::ApplySyncOperations(batch) => ds
                .apply_sync_operations(tx, &batch)
                .map(Response::SyncHeadCommit),
            Command::GetEgressKillSwitch() => ds.egress_kill_switch(tx).map(Response::Boolean),
            Command::SetEgressKillSwitch(enabled) => match ds.set_egress_kill_switch(tx, enabled) {
                Ok(()) => { self.commit = true; Ok(Response::Empty()) }
                Err(error) => Err(error),
            },
            Command::RecordEgressReceipt(receipt) => match ds.insert_egress_receipt(tx, &receipt) {
                Ok(()) => { self.commit = true; Ok(Response::Empty()) }
                Err(error) => Err(error),
            },
            Command::GetEgressReceipts(limit) => ds.get_egress_receipts(tx, limit).map(Response::EgressReceipts),
            Command::GetEgressApprovals(limit, now) => ds.get_egress_approvals(tx, limit, now).map(Response::EgressApprovals),
            Command::GetEgressApproval(id, now) => ds.get_egress_approval(tx, &id.0, now).map(Response::EgressApproval),
            Command::GetOrCreateEgressSecrets() => ds.get_or_create_egress_secrets(tx).map(Response::EgressSecrets),
            Command::CreateEgressApproval(destination, purpose, retention, version, scope, tag, expiry, now) =>
                ds.create_egress_approval(tx, &destination, &purpose, &retention, version, scope, &tag.0, expiry, now)
                    .map(|id| Response::EgressApprovalId(EgressApprovalId(id))),
            Command::ConsumeEgressApproval(id, destination, purpose, retention, version, tag, now) =>
                ds.consume_egress_approval(tx, &id.0, &destination, &purpose, &retention, version, &tag.0, now)
                    .map(Response::EgressApprovalScope),
            Command::ClearEgressApprovals() => ds.clear_egress_approvals(tx).map(|_| Response::Empty()),
            Command::GetEgressPolicyState() => ds.get_egress_policy_state(tx).map(Response::EgressPolicyState),
            Command::StoreEgressPolicyState(bundle, user) => match ds.store_egress_policy_state(tx, &bundle, &user) {
                Ok(()) => { self.commit = true; Ok(Response::Empty()) }
                Err(error) => Err(error),
            },
            Command::GetEgressUserPolicy() => ds.get_egress_user_policy(tx).map(Response::EgressUserPolicy),
            Command::StoreEgressUserPolicy(user) => match ds.store_egress_user_policy(tx, &user) {
                Ok(()) => { self.commit = true; Ok(Response::Empty()) }
                Err(error) => Err(error),
            },
            Command::GetAISettings() => {
                let settings = match ds.get_key_value(tx, AI_SETTINGS_KEY) {
                    Ok(serialized) => serde_json::from_str::<AISettingsV1>(&serialized)
                        .map_err(|_| DatastoreError::InternalError("Stored AI settings are invalid".into()))?,
                    Err(DatastoreError::NoSuchKey(_)) => AISettingsV1::default(),
                    Err(error) => return Err(error),
                };
                settings.validate()
                    .map_err(|_| DatastoreError::InternalError("Stored AI settings are invalid".into()))?;
                Ok(Response::AISettings(settings))
            }
            Command::CompareAndSetAISettings(expected_revision, settings) => {
                settings.validate()
                    .map_err(|_| DatastoreError::InternalError("Invalid AI settings".into()))?;
                let current = match ds.get_key_value(tx, AI_SETTINGS_KEY) {
                    Ok(serialized) => serde_json::from_str::<AISettingsV1>(&serialized)
                        .map_err(|_| DatastoreError::InternalError("Stored AI settings are invalid".into()))?,
                    Err(DatastoreError::NoSuchKey(_)) => AISettingsV1::default(),
                    Err(error) => return Err(error),
                };
                current.validate()
                    .map_err(|_| DatastoreError::InternalError("Stored AI settings are invalid".into()))?;
                if current.revision != expected_revision || settings.revision != expected_revision {
                    return Ok(Response::AISettingsUpdate(None));
                }
                let Some(next_revision) = expected_revision.checked_add(1) else {
                    return Err(DatastoreError::InternalError("AI settings revision is exhausted".into()));
                };
                let mut updated = settings;
                updated.revision = next_revision;
                updated.validate()
                    .map_err(|_| DatastoreError::InternalError("Invalid AI settings".into()))?;
                let serialized = serde_json::to_string(&updated)
                    .map_err(|_| DatastoreError::InternalError("AI settings could not be encoded".into()))?;
                ds.insert_key_value(tx, AI_SETTINGS_KEY, &serialized)?;
                self.commit = true;
                Ok(Response::AISettingsUpdate(Some(updated)))
            }
            Command::GetAIInsightHistory() => {
                let history = match ds.get_key_value(tx, AI_HISTORY_KEY) {
                    Ok(serialized) => serde_json::from_str::<AIInsightHistoryV1>(&serialized)
                        .map_err(|_| DatastoreError::InternalError("Stored AI history is invalid".into()))?,
                    Err(DatastoreError::NoSuchKey(_)) => AIInsightHistoryV1::default(),
                    Err(error) => return Err(error),
                };
                history.validate()
                    .map_err(|_| DatastoreError::InternalError("Stored AI history is invalid".into()))?;
                Ok(Response::AIInsightHistory(history))
            }
            Command::SaveAIInsight(insight) => {
                let mut history = match ds.get_key_value(tx, AI_HISTORY_KEY) {
                    Ok(serialized) => serde_json::from_str::<AIInsightHistoryV1>(&serialized)
                        .map_err(|_| DatastoreError::InternalError("Stored AI history is invalid".into()))?,
                    Err(DatastoreError::NoSuchKey(_)) => AIInsightHistoryV1::default(),
                    Err(error) => return Err(error),
                };
                history.validate().map_err(|_| DatastoreError::InternalError("Stored AI history is invalid".into()))?;
                insight.validate().map_err(|_| DatastoreError::InternalError("Invalid AI insight".into()))?;
                if let Some(existing) = history.insights.iter().find(|existing| existing.insight_id == insight.insight_id) {
                    return if existing == &insight {
                        Ok(Response::AIInsightHistoryUpdate(Some(history)))
                    } else {
                        Err(DatastoreError::InternalError("AI insight ID conflict".into()))
                    };
                }
                let Some(revision) = history.revision.checked_add(1) else {
                    return Err(DatastoreError::InternalError("AI history revision is exhausted".into()));
                };
                if history.insights.len() >= aw_models::AI_MAX_HISTORY_ENTRIES_V1 {
                    history.insights.remove(0);
                }
                history.revision = revision;
                history.insights.push(insight);
                history.validate().map_err(|_| DatastoreError::InternalError("Invalid AI history".into()))?;
                let serialized = serde_json::to_string(&history)
                    .map_err(|_| DatastoreError::InternalError("AI history could not be encoded".into()))?;
                ds.insert_key_value(tx, AI_HISTORY_KEY, &serialized)?;
                self.commit = true;
                Ok(Response::AIInsightHistoryUpdate(Some(history)))
            }
            Command::DeleteAIInsight(insight_id) => {
                let mut history = match ds.get_key_value(tx, AI_HISTORY_KEY) {
                    Ok(serialized) => serde_json::from_str::<AIInsightHistoryV1>(&serialized)
                        .map_err(|_| DatastoreError::InternalError("Stored AI history is invalid".into()))?,
                    Err(DatastoreError::NoSuchKey(_)) => AIInsightHistoryV1::default(),
                    Err(error) => return Err(error),
                };
                history.validate().map_err(|_| DatastoreError::InternalError("Stored AI history is invalid".into()))?;
                let Some(index) = history.insights.iter().position(|insight| insight.insight_id == insight_id) else {
                    return Ok(Response::AIInsightHistoryUpdate(None));
                };
                history.insights.remove(index);
                let Some(revision) = history.revision.checked_add(1) else {
                    return Err(DatastoreError::InternalError("AI history revision is exhausted".into()));
                };
                history.revision = revision;
                let serialized = serde_json::to_string(&history)
                    .map_err(|_| DatastoreError::InternalError("AI history could not be encoded".into()))?;
                ds.insert_key_value(tx, AI_HISTORY_KEY, &serialized)?;
                self.commit = true;
                Ok(Response::AIInsightHistoryUpdate(Some(history)))
            }
            Command::SetKeyValue(key, _) | Command::DeleteKeyValue(key) if key == CAPTURE_KEY =>
                Err(DatastoreError::InternalError("Use the capture controls to change this policy".into())),
            Command::SetKeyValue(key, _) | Command::DeleteKeyValue(key) if key == AI_SETTINGS_KEY || key == AI_HISTORY_KEY =>
                Err(DatastoreError::InternalError("Use the typed AI settings API to change AI settings".into())),
            Command::SetKeyValue(key, _) | Command::DeleteKeyValue(key) if key.starts_with(EGRESS_KEY_PREFIX) =>
                Err(DatastoreError::InternalError("Use the Privacy Firewall controls to change this policy".into())),
            Command::CompareAndSetKeyValue(key, _, _) if key == CAPTURE_KEY =>
                Err(DatastoreError::InternalError("Use the capture controls to change this policy".into())),
            Command::CompareAndSetKeyValue(key, _, _) if key == AI_SETTINGS_KEY || key == AI_HISTORY_KEY =>
                Err(DatastoreError::InternalError("Use the typed AI settings API to change AI settings".into())),
            Command::CompareAndSetKeyValue(key, _, _) if key.starts_with(EGRESS_KEY_PREFIX) =>
                Err(DatastoreError::InternalError("Use the Privacy Firewall controls to change this policy".into())),
            Command::SetKeyValue(key, data) => match ds.insert_key_value(tx, &key, &data) {
                Ok(()) => Ok(Response::Empty()),
                Err(e) => Err(e),
            },
            Command::CompareAndSetKeyValue(key, expected, data) => {
                let current = match ds.get_key_value(tx, &key) {
                    Ok(value) => Some(value),
                    Err(DatastoreError::NoSuchKey(_)) => None,
                    Err(error) => return Err(error),
                };
                if current != expected {
                    return Ok(Response::Boolean(false));
                }
                match data {
                    Some(data) => ds.insert_key_value(tx, &key, &data)?,
                    None => ds.delete_key_value(tx, &key)?,
                }
                self.commit = true;
                Ok(Response::Boolean(true))
            }
            Command::GetKeyValue(key) if key.starts_with(EGRESS_KEY_PREFIX) =>
                Err(DatastoreError::InternalError("Privacy Firewall state cannot be read through generic settings".into())),
            Command::GetKeyValue(key) if key == AI_SETTINGS_KEY || key == AI_HISTORY_KEY =>
                Err(DatastoreError::InternalError("Use the typed AI settings API to read AI settings".into())),
            Command::GetKeyValue(key) => match ds.get_key_value(tx, &key) {
                Ok(result) => Ok(Response::KeyValue(result)),
                Err(e) => Err(e),
            },
            Command::DeleteKeyValue(key) => match ds.delete_key_value(tx, &key) {
                Ok(()) => Ok(Response::Empty()),
                Err(e) => Err(e),
            },
            Command::RefreshPrivacyFilter() => {
                // Reload privacy filter rules from settings
                match ds.get_key_value(tx, "settings.privacy_filters") {
                    Ok(json_str) => match PrivacyFilterEngine::from_json(&json_str) {
                        Ok(engine) => self.privacy_engine = engine,
                        Err(e) => warn!("Failed to parse privacy_filters setting: {e}"),
                    },
                    Err(_) => {
                        // Settings key absent — clear rules so removing the key disables filtering
                        self.privacy_engine = PrivacyFilterEngine::new(vec![]);
                    }
                }
                Ok(Response::Empty())
            }
            Command::RenameBucket(old_id, new_id) => match ds.rename_bucket(tx, &old_id, &new_id) {
                Ok(()) => {
                    self.commit = true;
                    Ok(Response::Empty())
                }
                Err(e) => Err(e),
            },
            Command::MigrateHostname(new_hostname) => {
                match ds.migrate_hostname(tx, &new_hostname) {
                    Ok(count) => {
                        if count > 0 {
                            self.commit = true;
                        }
                        Ok(Response::Count(count as i64))
                    }
                    Err(e) => Err(e),
                }
            }
            Command::MigrateTestBucketNames() => match ds.migrate_test_bucket_names(tx) {
                Ok(count) => {
                    if count > 0 {
                        self.commit = true;
                    }
                    Ok(Response::Count(count as i64))
                }
                Err(e) => Err(e),
            },
            Command::Close() => {
                self.quit = true;
                ds.set_egress_kill_switch(tx, true).map(|_| Response::Empty())
            }
        }
    }
}

impl Datastore {
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn load_sync_device_identity(&self) -> Result<Option<SyncDeviceIdentity>, DatastoreError> {
        match self.request(Command::GetSyncDeviceIdentity())? {
            Response::SyncDeviceIdentity(identity) => Ok(identity),
            _ => Err(DatastoreError::InternalError("Unexpected sync identity response".into())),
        }
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn create_sync_device_identity(
        &self,
        identity: &SyncDeviceIdentity,
    ) -> Result<(), DatastoreError> {
        _unwrap_empty_response(self.request(Command::CreateSyncDeviceIdentity(identity.clone()))?)
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn load_sync_key_material(&self) -> Result<Option<SyncKeyMaterial>, DatastoreError> {
        match self.request(Command::GetSyncKeyMaterial())? {
            Response::SyncKeyMaterial(material) => Ok(material),
            _ => Err(DatastoreError::InternalError("Unexpected sync key response".into())),
        }
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn load_sync_snapshot(&self) -> Result<Option<SyncSnapshotV1>, DatastoreError> {
        match self.request(Command::GetSyncSnapshot())? {
            Response::SyncSnapshot(snapshot) => Ok(snapshot),
            _ => Err(DatastoreError::InternalError("Unexpected sync snapshot response".into())),
        }
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn export_sync_recovery_state(&self, key_epoch: u64) -> Result<SyncRecoveryStateV1, DatastoreError> {
        match self.request(Command::GetSyncRecoveryState(key_epoch))? {
            Response::SyncRecoveryState(state) => Ok(state),
            _ => Err(DatastoreError::InternalError("Unexpected recovery state response".into())),
        }
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn prepare_sync_snapshot_mappings(&self) -> Result<(), DatastoreError> {
        _unwrap_empty_response(self.request(Command::PrepareSyncSnapshotMappings())?)
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn save_sync_snapshot(&self, material: SyncKeyMaterial, snapshot: SyncSnapshotV1) -> Result<(), DatastoreError> {
        _unwrap_empty_response(self.request(Command::SaveSyncSnapshot(material, snapshot))?)
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn get_sync_object(&self, object_id: String) -> Result<Option<aw_models::SyncEnvelopeV1>, DatastoreError> {
        match self.request(Command::GetSyncObject(object_id))? {
            Response::SyncObject(envelope) => Ok(envelope),
            _ => Err(DatastoreError::InternalError("Unexpected sync object response".into())),
        }
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn put_sync_object(
        &self,
        envelope: aw_models::SyncEnvelopeV1,
        stored_at: String,
    ) -> Result<bool, DatastoreError> {
        match self.request(Command::PutSyncObject(envelope, stored_at))? {
            Response::Boolean(inserted) => Ok(inserted),
            _ => Err(DatastoreError::InternalError("Unexpected sync object response".into())),
        }
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn list_sync_objects(
        &self,
        vault_id: String,
        after_object_id: Option<String>,
        limit: usize,
    ) -> Result<SyncObjectPageV1, DatastoreError> {
        match self.request(Command::ListSyncObjects(vault_id, after_object_id, limit))? {
            Response::SyncObjectsPage(page) => Ok(page),
            _ => Err(DatastoreError::InternalError("Unexpected sync object list response".into())),
        }
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn delete_sync_object_after_tombstones(
        &self,
        object_id: String,
        tombstones: Vec<SyncTombstoneIdentityV1>,
        deleted_at: String,
    ) -> Result<bool, DatastoreError> {
        match self.request(Command::DeleteSyncObjectAfterTombstones(object_id, tombstones, deleted_at))? {
            Response::Boolean(deleted) => Ok(deleted),
            _ => Err(DatastoreError::InternalError("Unexpected sync object delete response".into())),
        }
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn list_sync_object_history(&self, limit: usize) -> Result<Vec<SyncObjectHistoryV1>, DatastoreError> {
        match self.request(Command::ListSyncObjectHistory(limit))? {
            Response::SyncObjectHistory(history) => Ok(history),
            _ => Err(DatastoreError::InternalError("Unexpected sync object history response".into())),
        }
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn sync_enabled(&self) -> Result<bool, DatastoreError> {
        match self.request(Command::GetSyncEnabled())? {
            Response::Boolean(enabled) => Ok(enabled),
            _ => Err(DatastoreError::InternalError("Unexpected sync state response".into())),
        }
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn sync_egress_consent(&self) -> Result<Option<SyncEgressConsentV1>, DatastoreError> {
        match self.request(Command::GetSyncEgressConsent())? {
            Response::SyncEgressConsent(consent) => Ok(consent),
            _ => Err(DatastoreError::InternalError("Unexpected sync consent response".into())),
        }
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn set_sync_enabled(
        &self,
        enabled: bool,
        destination_id: Option<String>,
        purpose_id: Option<String>,
    ) -> Result<(), DatastoreError> {
        _unwrap_empty_response(self.request(Command::SetSyncEnabled(enabled, destination_id, purpose_id))?)
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn install_sync_key_material(&self, material: &SyncKeyMaterial) -> Result<(), DatastoreError> {
        _unwrap_empty_response(self.request(Command::InstallSyncKeyMaterial(material.clone()))?)
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn install_sync_recovery(
        &self,
        material: SyncKeyMaterial,
        snapshot: SyncSnapshotV1,
    ) -> Result<(), DatastoreError> {
        _unwrap_empty_response(self.request(Command::InstallSyncRecovery(material, snapshot))?)
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn sync_recovery_confirmation(&self) -> Result<Option<String>, DatastoreError> {
        match self.request(Command::GetSyncRecoveryConfirmation())? {
            Response::SyncRecoveryConfirmation(confirmed_at) => Ok(confirmed_at),
            _ => Err(DatastoreError::InternalError("Unexpected recovery confirmation response".into())),
        }
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn confirm_sync_recovery_saved(&self, confirmed_at: String) -> Result<(), DatastoreError> {
        _unwrap_empty_response(self.request(Command::ConfirmSyncRecoverySaved(confirmed_at))?)
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn record_sync_pairing(
        &self,
        material: Option<SyncKeyMaterial>,
        offer_id: [u8; 16],
        device_id: [u8; 16],
        x25519_public_key: [u8; 32],
        ed25519_public_key: [u8; 32],
        occurred_at: String,
    ) -> Result<(), DatastoreError> {
        _unwrap_empty_response(self.request(Command::RecordSyncPairing(
            material,
            offer_id,
            device_id,
            x25519_public_key,
            ed25519_public_key,
            occurred_at,
        ))?)
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn rotate_sync_key_material(
        &self,
        material: SyncKeyMaterial,
        snapshot: SyncSnapshotV1,
        revoke_device: Option<[u8; 16]>,
        occurred_at: String,
    ) -> Result<bool, DatastoreError> {
        match self.request(Command::RotateSyncKeyMaterial(material, snapshot, revoke_device, occurred_at))? {
            Response::Boolean(rotated) => Ok(rotated),
            _ => Err(DatastoreError::InternalError("Unexpected sync rotation response".into())),
        }
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn list_sync_trusted_devices(&self) -> Result<Vec<SyncTrustedDevice>, DatastoreError> {
        match self.request(Command::GetSyncTrustedDevices())? {
            Response::SyncTrustedDevices(devices) => Ok(devices),
            _ => Err(DatastoreError::InternalError("Unexpected sync device response".into())),
        }
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn list_sync_device_access_history(
        &self,
        limit: usize,
    ) -> Result<Vec<SyncDeviceAccessEvent>, DatastoreError> {
        match self.request(Command::GetSyncDeviceAccessHistory(limit))? {
            Response::SyncDeviceAccessHistory(events) => Ok(events),
            _ => Err(DatastoreError::InternalError("Unexpected sync history response".into())),
        }
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn load_sync_manifest_head(
        &self,
        vault_id: [u8; 16],
        key_epoch: u64,
        device_id: [u8; 16],
    ) -> Result<Option<SyncManifestHeadV1>, DatastoreError> {
        match self.request(Command::GetSyncManifestHead(vault_id, key_epoch, device_id))? {
            Response::SyncManifestHead(head) => Ok(head),
            _ => Err(DatastoreError::InternalError("Unexpected sync head response".into())),
        }
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn commit_sync_manifest_head(
        &self,
        vault_id: [u8; 16],
        key_epoch: u64,
        device_id: [u8; 16],
        expected: SyncManifestHeadV1,
        next: SyncManifestHeadV1,
    ) -> Result<SyncHeadCommitV1, DatastoreError> {
        match self.request(Command::CommitSyncManifestHead(vault_id, key_epoch, device_id, expected, next))? {
            Response::SyncHeadCommit(result) => Ok(result),
            _ => Err(DatastoreError::InternalError("Unexpected sync head update response".into())),
        }
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn put_sync_operation(&self, operation: SyncStoredOperationV1) -> Result<bool, DatastoreError> {
        match self.request(Command::PutSyncOperation(operation))? {
            Response::Boolean(inserted) => Ok(inserted),
            _ => Err(DatastoreError::InternalError("Unexpected sync operation response".into())),
        }
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn list_sync_operations(
        &self,
        device_id: [u8; 16],
        key_epoch: u64,
        after_counter: u64,
        limit: usize,
    ) -> Result<Vec<SyncStoredOperationV1>, DatastoreError> {
        match self.request(Command::ListSyncOperations(device_id, key_epoch, after_counter, limit))? {
            Response::SyncOperations(operations) => Ok(operations),
            _ => Err(DatastoreError::InternalError("Unexpected sync operation list response".into())),
        }
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn begin_sync_baseline(&self) -> Result<SyncBaselineProgressV1, DatastoreError> {
        match self.request(Command::BeginSyncBaseline())? {
            Response::SyncBaselineProgress(progress) => Ok(progress),
            _ => Err(DatastoreError::InternalError("Unexpected sync baseline response".into())),
        }
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn sync_baseline_progress(&self) -> Result<Option<SyncBaselineProgressV1>, DatastoreError> {
        match self.request(Command::GetSyncBaselineProgress())? {
            Response::SyncBaselineState(progress) => Ok(progress),
            _ => Err(DatastoreError::InternalError("Unexpected sync baseline response".into())),
        }
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn list_local_sync_tombstone_acknowledgements(
        &self,
    ) -> Result<Vec<aw_sync_e2ee::SyncTombstoneAckV1>, DatastoreError> {
        match self.request(Command::ListLocalSyncTombstoneAcknowledgements())? {
            Response::SyncTombstoneAcknowledgements(acknowledgements) => Ok(acknowledgements),
            _ => Err(DatastoreError::InternalError("Unexpected tombstone acknowledgements response".into())),
        }
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn process_sync_baseline_batch(&self, limit: usize) -> Result<SyncBaselineProgressV1, DatastoreError> {
        match self.request(Command::ProcessSyncBaselineBatch(limit))? {
            Response::SyncBaselineProgress(progress) => Ok(progress),
            _ => Err(DatastoreError::InternalError("Unexpected sync baseline response".into())),
        }
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn apply_sync_operations(&self, batch: SyncApplyBatchV1) -> Result<SyncHeadCommitV1, DatastoreError> {
        match self.request(Command::ApplySyncOperations(batch))? {
            Response::SyncHeadCommit(result) => Ok(result),
            _ => Err(DatastoreError::InternalError("Unexpected sync apply response".into())),
        }
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn next_sync_operation_counter(
        &self,
        device_id: [u8; 16],
    ) -> Result<u64, DatastoreError> {
        match self.request(Command::NextSyncOperationCounter(device_id))? {
            Response::SyncCounter(counter) => Ok(counter),
            _ => Err(DatastoreError::InternalError("Unexpected sync counter response".into())),
        }
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn acknowledge_sync_tombstone(
        &self,
        origin_device_id: [u8; 16],
        local_event_id: u64,
        tombstone_counter: u64,
        device_id: [u8; 16],
        acknowledged_at: String,
    ) -> Result<bool, DatastoreError> {
        match self.request(Command::AckSyncTombstone(
            origin_device_id,
            local_event_id,
            tombstone_counter,
            device_id,
            acknowledged_at,
        ))? {
            Response::Boolean(inserted) => Ok(inserted),
            _ => Err(DatastoreError::InternalError("Unexpected tombstone acknowledgement response".into())),
        }
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn can_collect_sync_tombstone(
        &self,
        origin_device_id: [u8; 16],
        local_event_id: u64,
        tombstone_counter: u64,
    ) -> Result<bool, DatastoreError> {
        match self.request(Command::CanCollectSyncTombstone(
            origin_device_id,
            local_event_id,
            tombstone_counter,
        ))? {
            Response::Boolean(collectible) => Ok(collectible),
            _ => Err(DatastoreError::InternalError("Unexpected tombstone collection response".into())),
        }
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn sync_tombstone_ack_state(
        &self,
        origin_device_id: [u8; 16],
        local_event_id: u64,
        tombstone_counter: u64,
    ) -> Result<SyncTombstoneAckStateV1, DatastoreError> {
        match self.request(Command::GetSyncTombstoneAckState(origin_device_id, local_event_id, tombstone_counter))? {
            Response::SyncTombstoneAckState(state) => Ok(state),
            _ => Err(DatastoreError::InternalError("Unexpected tombstone acknowledgement state response".into())),
        }
    }

    pub fn egress_lease(&self) -> Result<EgressLease<'_>, DatastoreError> {
        let worker = self.worker.read().map_err(|_| DatastoreError::Locked)?;
        if worker.is_none() { return Err(DatastoreError::Locked); }
        Ok(EgressLease { worker })
    }

    fn capture_response(&self, command: Command) -> Result<CapturePolicy, DatastoreError> {
        match self.request(command)? {
            Response::CapturePolicy(policy) => Ok(policy),
            _ => Err(DatastoreError::InternalError("Unexpected capture response".into())),
        }
    }

    pub fn enable_capture_policy(&self) -> Result<CapturePolicy, DatastoreError> {
        self.capture_response(Command::EnableCapturePolicy())
    }

    pub fn capture_policy(&self) -> Result<CapturePolicy, DatastoreError> {
        self.capture_response(Command::GetCapturePolicy())
    }

    pub fn reset_privacy(&self) -> Result<CapturePolicy, DatastoreError> {
        self.capture_response(Command::ResetPrivacy())
    }

    pub fn pause_capture(&self) -> Result<CapturePolicy, DatastoreError> {
        self.capture_response(Command::PauseCapture())
    }

    pub fn set_capture_policy(&self, policy: CapturePolicy) -> Result<CapturePolicy, DatastoreError> {
        self.capture_response(Command::SetCapturePolicy(policy))
    }

    pub fn import_events(&self, bucket: &str, events: &[Event]) -> Result<Vec<Event>, DatastoreError> {
        match self.request(Command::ImportEvents(bucket.into(), events.to_vec()))? {
            Response::EventList(events) => Ok(events),
            _ => Err(DatastoreError::InternalError("Unexpected import response".into())),
        }
    }

    pub fn preview_import_events(&self, bucket: &str, events: &[Event]) -> Result<Vec<Event>, DatastoreError> {
        match self.request(Command::PreviewImportEvents(bucket.into(), events.to_vec()))? {
            Response::EventList(events) => Ok(events),
            _ => Err(DatastoreError::InternalError("Unexpected import preview response".into())),
        }
    }

    pub fn preview_import_buckets(&self, source: BucketsExport) -> Result<ImportSummary, DatastoreError> {
        match self.request(Command::ImportBuckets(source, false))? {
            Response::ImportSummary(summary) => Ok(summary),
            _ => Err(DatastoreError::InternalError("Unexpected import preview response".into())),
        }
    }

    pub fn import_buckets(&self, source: BucketsExport) -> Result<ImportSummary, DatastoreError> {
        match self.request(Command::ImportBuckets(source, true))? {
            Response::ImportSummary(summary) => Ok(summary),
            _ => Err(DatastoreError::InternalError("Unexpected import response".into())),
        }
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn restore_sync_snapshot_data(&self, source: BucketsExport) -> Result<ImportSummary, DatastoreError> {
        match self.request(Command::RestoreSyncSnapshotData(source))? {
            Response::ImportSummary(summary) => Ok(summary),
            _ => Err(DatastoreError::InternalError("Unexpected recovery import response".into())),
        }
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn restore_sync_recovery_data(
        &self,
        source: BucketsExport,
        material: SyncKeyMaterial,
        snapshot: SyncSnapshotV1,
        state: SyncRecoveryStateV1,
        identity: SyncDeviceIdentity,
    ) -> Result<ImportSummary, DatastoreError> {
        match self.request(Command::RestoreSyncRecoveryData(source, material, snapshot, state, identity))? {
            Response::ImportSummary(summary) => Ok(summary),
            _ => Err(DatastoreError::InternalError("Unexpected sync recovery response".into())),
        }
    }

    /// Open a SQLCipher vault without silently creating plaintext or replacing a
    /// database whose key is unavailable. Callers own first-run key persistence.
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn open_encrypted(dbpath: String, key: String) -> Result<Self, DatastoreError> {
        let key = zeroize::Zeroizing::new(key);
        if key.len() < 32 {
            return Err(DatastoreError::InternalError("Vault key is missing or invalid".into()));
        }
        let failure = |_| DatastoreError::InternalError(
            "Vault could not be opened; verify the key and database without replacing either".into()
        );
        {
            let conn = Connection::open(&dbpath).map_err(failure)?;
            let version: String = conn.pragma_query_value(None, "cipher_version", |row| row.get(0))
                .map_err(failure)?;
            if version.is_empty() {
                return Err(DatastoreError::InternalError("SQLCipher is required for the vault".into()));
            }
            conn.pragma_update(None, "key", key.as_str()).map_err(failure)?;
            let _: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))
                .map_err(failure)?;
        }
        let datastore = Self::_new_internal(DatastoreMethod::FileEncrypted(dbpath, key), false);
        // Wait for schema initialization before exposing the handle to any caller.
        datastore.get_buckets()?;
        Ok(datastore)
    }

    pub fn new(dbpath: String, legacy_import: bool) -> Self {
        let method = DatastoreMethod::File(dbpath);
        Datastore::_new_internal(method, legacy_import)
    }

    pub fn new_in_memory(legacy_import: bool) -> Self {
        let method = DatastoreMethod::Memory();
        Datastore::_new_internal(method, legacy_import)
    }

    /// Create an encrypted datastore using SQLCipher.
    ///
    /// Requires the `encryption` or `encryption-vendored` feature flag.
    /// Build with: `cargo build --no-default-features --features encryption`
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn new_encrypted(dbpath: String, key: String, legacy_import: bool) -> Self {
        let method = DatastoreMethod::FileEncrypted(dbpath, zeroize::Zeroizing::new(key));
        Datastore::_new_internal(method, legacy_import)
    }

    fn _new_internal(method: DatastoreMethod, legacy_import: bool) -> Self {
        let encrypted = {
            #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
            if matches!(&method, DatastoreMethod::FileEncrypted(_, _)) { true } else { false }
            #[cfg(not(any(feature = "encryption", feature = "encryption-vendored")))]
            false
        };
        let (requester, responder) =
            mpsc_requests::channel::<Command, Result<Response, DatastoreError>>();
        let thread = thread::spawn(move || {
            let mut di = DatastoreWorker::new(responder, legacy_import);
            di.work_loop(method);
        });
        Datastore {
            worker: Arc::new(RwLock::new(Some(Worker { requester, thread }))),
            encrypted: Arc::new(AtomicBool::new(encrypted)),
        }
    }

    pub fn new_locked() -> Self {
        Self { worker: Arc::new(RwLock::new(None)), encrypted: Arc::new(AtomicBool::new(false)) }
    }

    pub fn is_locked(&self) -> bool {
        self.worker.read().map_or(true, |worker| worker.is_none())
    }

    pub fn is_encrypted(&self) -> bool {
        self.encrypted.load(Ordering::Acquire)
    }

    /// All clones share this gate. It remains closed if validation/opening fails.
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn unlock_encrypted(&self, path: String, key: String) -> Result<(), DatastoreError> {
        let mut worker = self.worker.write().map_err(|_| DatastoreError::Locked)?;
        if worker.is_some() { return Err(DatastoreError::InternalError("Vault is already open".into())); }
        let opened = Self::open_encrypted(path, key)?;
        *worker = opened.worker.write().map_err(|_| DatastoreError::Locked)?.take();
        self.encrypted.store(true, Ordering::Release);
        Ok(())
    }

    /// Wait for in-flight calls, flush the worker and release its connection/key.
    pub fn lock(&self) -> Result<(), DatastoreError> {
        let mut slot = self.worker.write().map_err(|_| DatastoreError::Locked)?;
        if let Some(worker) = slot.take() {
            let result = worker.requester.request(Command::Close()).map_err(|_| DatastoreError::Locked)
                .and_then(|reply| reply.collect().map_err(|_| DatastoreError::Locked))
                .and_then(|reply| reply).and_then(_unwrap_empty_response);
            worker.thread.join().map_err(|_| DatastoreError::InternalError("Vault worker stopped unexpectedly".into()))?;
            result?;
        }
        Ok(())
    }

    /// Send a command to the worker thread and wait for its response.
    ///
    /// Fails with `InternalError` instead of panicking when the worker thread
    /// is gone (e.g. it panicked on an earlier request), so callers such as
    /// HTTP endpoints can degrade to a 5xx response instead of crashing the
    /// request.
    fn request(&self, cmd: Command) -> Result<Response, DatastoreError> {
        if cmd.requires_encrypted_vault() && !self.is_encrypted() {
            return Err(DatastoreError::InternalError("E2EE sync requires a SQLCipher vault".into()));
        }
        let slot = self.worker.read().map_err(|_| DatastoreError::Locked)?;
        let worker = slot.as_ref().ok_or(DatastoreError::Locked)?;
        let receiver = worker.requester.request(cmd)
            .map_err(|_| DatastoreError::InternalError("Datastore request channel unavailable".into()))?;
        receiver.collect().map_err(|_| DatastoreError::InternalError("Datastore response unavailable".into()))?
    }

    pub fn create_bucket(&self, bucket: &Bucket) -> Result<(), DatastoreError> {
        let cmd = Command::CreateBucket(bucket.clone());
        _unwrap_empty_response(self.request(cmd)?)
    }

    pub fn delete_bucket(&self, bucket_id: &str) -> Result<(), DatastoreError> {
        let cmd = Command::DeleteBucket(bucket_id.to_string());
        _unwrap_empty_response(self.request(cmd)?)
    }

    pub fn get_bucket(&self, bucket_id: &str) -> Result<Bucket, DatastoreError> {
        let cmd = Command::GetBucket(bucket_id.to_string());
        match self.request(cmd)? {
            Response::Bucket(b) => Ok(b),
            _ => panic!("Invalid response"),
        }
    }

    pub fn get_buckets(&self) -> Result<HashMap<String, Bucket>, DatastoreError> {
        let cmd = Command::GetBuckets();
        match self.request(cmd)? {
            Response::BucketMap(bm) => Ok(bm),
            e => Err(DatastoreError::InternalError(format!(
                "Invalid response: {e:?}"
            ))),
        }
    }

    pub fn insert_events(
        &self,
        bucket_id: &str,
        events: &[Event],
    ) -> Result<Vec<Event>, DatastoreError> {
        let cmd = Command::InsertEvents(bucket_id.to_string(), events.to_vec());
        match self.request(cmd)? {
            Response::EventList(events) => Ok(events),
            _ => panic!("Invalid response"),
        }
    }

    pub fn heartbeat(
        &self,
        bucket_id: &str,
        heartbeat: Event,
        pulsetime: f64,
    ) -> Result<Event, DatastoreError> {
        let cmd = Command::Heartbeat(bucket_id.to_string(), heartbeat, pulsetime);
        match self.request(cmd)? {
            Response::Event(e) => Ok(e),
            _ => panic!("Invalid response"),
        }
    }

    pub fn get_event(&self, bucket_id: &str, event_id: i64) -> Result<Event, DatastoreError> {
        let cmd = Command::GetEvent(bucket_id.to_string(), event_id);
        match self.request(cmd)? {
            Response::Event(el) => Ok(el),
            _ => panic!("Invalid response"),
        }
    }

    pub fn correct_event(&self, bucket_id: &str, event: Event) -> Result<Event, DatastoreError> {
        match self.request(Command::CorrectEvent(bucket_id.to_string(), event))? {
            Response::Event(event) => Ok(event),
            _ => Err(DatastoreError::InternalError("Unexpected correction response".into())),
        }
    }

    pub fn split_event(
        &self,
        bucket_id: &str,
        event_id: i64,
        split_at: DateTime<Utc>,
    ) -> Result<Vec<Event>, DatastoreError> {
        match self.request(Command::SplitEvent(bucket_id.to_string(), event_id, split_at))? {
            Response::EventList(events) => Ok(events),
            _ => Err(DatastoreError::InternalError("Unexpected split response".into())),
        }
    }

    pub fn merge_events(&self, bucket_id: &str, first_id: i64, second_id: i64) -> Result<Event, DatastoreError> {
        match self.request(Command::MergeEvents(bucket_id.to_string(), first_id, second_id))? {
            Response::Event(event) => Ok(event),
            _ => Err(DatastoreError::InternalError("Unexpected merge response".into())),
        }
    }

    pub fn get_event_corrections(&self, bucket_id: &str, event_id: i64) -> Result<Vec<EventCorrection>, DatastoreError> {
        match self.request(Command::GetEventCorrections(bucket_id.to_string(), event_id))? {
            Response::EventCorrections(history) => Ok(history),
            _ => Err(DatastoreError::InternalError("Unexpected correction history response".into())),
        }
    }

    pub fn delete_events_in_range(
        &self,
        bucket_id: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<u64, DatastoreError> {
        match self.request(Command::DeleteEventsInRange(bucket_id.to_string(), start, end))? {
            Response::Count(removed) => u64::try_from(removed)
                .map_err(|_| DatastoreError::InternalError("Invalid deleted-event count".into())),
            _ => Err(DatastoreError::InternalError("Unexpected range-delete response".into())),
        }
    }

    pub fn apply_raw_retention(&self, days: u32, now: DateTime<Utc>) -> Result<u64, DatastoreError> {
        match self.request(Command::ApplyRawRetention(days, now))? {
            Response::Count(removed) => u64::try_from(removed)
                .map_err(|_| DatastoreError::InternalError("Invalid retention delete count".into())),
            _ => Err(DatastoreError::InternalError("Unexpected retention response".into())),
        }
    }

    pub fn get_events(
        &self,
        bucket_id: &str,
        starttime_opt: Option<DateTime<Utc>>,
        endtime_opt: Option<DateTime<Utc>>,
        limit_opt: Option<u64>,
    ) -> Result<Vec<Event>, DatastoreError> {
        let cmd = Command::GetEvents(
            bucket_id.to_string(),
            starttime_opt,
            endtime_opt,
            limit_opt,
            false,
        );
        match self.request(cmd)? {
            Response::EventList(el) => Ok(el),
            _ => panic!("Invalid response"),
        }
    }

    pub fn get_events_unclipped(
        &self,
        bucket_id: &str,
        starttime_opt: Option<DateTime<Utc>>,
        endtime_opt: Option<DateTime<Utc>>,
        limit_opt: Option<u64>,
    ) -> Result<Vec<Event>, DatastoreError> {
        let cmd = Command::GetEvents(
            bucket_id.to_string(),
            starttime_opt,
            endtime_opt,
            limit_opt,
            true,
        );
        match self.request(cmd)? {
            Response::EventList(el) => Ok(el),
            _ => panic!("Invalid response"),
        }
    }

    pub fn get_event_count(
        &self,
        bucket_id: &str,
        starttime_opt: Option<DateTime<Utc>>,
        endtime_opt: Option<DateTime<Utc>>,
    ) -> Result<i64, DatastoreError> {
        let cmd = Command::GetEventCount(bucket_id.to_string(), starttime_opt, endtime_opt);
        match self.request(cmd)? {
            Response::Count(n) => Ok(n),
            _ => panic!("Invalid response"),
        }
    }

    pub fn delete_events_by_id(
        &self,
        bucket_id: &str,
        event_ids: Vec<i64>,
    ) -> Result<(), DatastoreError> {
        let cmd = Command::DeleteEventsById(bucket_id.to_string(), event_ids);
        _unwrap_empty_response(self.request(cmd)?)
    }

    pub fn force_commit(&self) -> Result<(), DatastoreError> {
        let cmd = Command::ForceCommit();
        _unwrap_empty_response(self.request(cmd)?)
    }

    pub fn get_key_values(&self, pattern: &str) -> Result<HashMap<String, String>, DatastoreError> {
        let cmd = Command::GetKeyValues(pattern.to_string());
        match self.request(cmd)? {
            Response::KeyValues(value) => Ok(value),
            _ => panic!("Invalid response"),
        }
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn get_plugin_storage(
        &self,
        manifest: &PluginManifestV1,
    ) -> Result<BTreeMap<String, serde_json::Value>, DatastoreError> {
        match self.request(Command::GetPluginStorage(manifest.clone()))? {
            Response::PluginStorage(storage) => Ok(storage),
            _ => Err(DatastoreError::InternalError("Unexpected plugin storage response".into())),
        }
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn apply_plugin_storage_intents(
        &self,
        manifest: &PluginManifestV1,
        intents: &[PluginStorageIntentV1],
    ) -> Result<(), DatastoreError> {
        _unwrap_empty_response(self.request(Command::ApplyPluginStorageIntents(manifest.clone(), intents.to_vec()))?)
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn delete_plugin_storage(&self, manifest: &PluginManifestV1) -> Result<(), DatastoreError> {
        _unwrap_empty_response(self.request(Command::DeletePluginStorage(manifest.clone()))?)
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn get_plugin_events(&self, manifest: &PluginManifestV1) -> Result<Vec<PluginOwnedEventV1>, DatastoreError> {
        match self.request(Command::GetPluginEvents(manifest.clone()))? {
            Response::PluginEvents(events) => Ok(events),
            _ => Err(DatastoreError::InternalError("Unexpected plugin event response".into())),
        }
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn apply_plugin_write_intents(
        &self,
        manifest: &PluginManifestV1,
        intents: &[PluginWriteIntentV1],
    ) -> Result<(), DatastoreError> {
        _unwrap_empty_response(self.request(Command::ApplyPluginWriteIntents(manifest.clone(), intents.to_vec()))?)
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn delete_plugin_data(&self, manifest: &PluginManifestV1) -> Result<(), DatastoreError> {
        _unwrap_empty_response(self.request(Command::DeletePluginData(manifest.clone()))?)
    }

    pub fn egress_kill_switch(&self) -> Result<bool, DatastoreError> {
        match self.request(Command::GetEgressKillSwitch())? {
            Response::Boolean(enabled) => Ok(enabled),
            _ => Err(DatastoreError::InternalError("Unexpected egress switch response".into())),
        }
    }

    pub fn set_egress_kill_switch(&self, enabled: bool) -> Result<(), DatastoreError> {
        _unwrap_empty_response(self.request(Command::SetEgressKillSwitch(enabled))?)
    }

    pub fn record_egress_receipt(&self, receipt: &EgressReceiptV1) -> Result<(), DatastoreError> {
        _unwrap_empty_response(self.request(Command::RecordEgressReceipt(receipt.clone()))?)
    }

    pub fn get_egress_receipts(&self, limit: usize) -> Result<Vec<EgressReceiptV1>, DatastoreError> {
        match self.request(Command::GetEgressReceipts(limit))? {
            Response::EgressReceipts(receipts) => Ok(receipts),
            _ => Err(DatastoreError::InternalError("Unexpected egress receipts response".into())),
        }
    }

    pub fn get_egress_approvals(&self, limit: usize, now: DateTime<Utc>) -> Result<Vec<EgressApprovalV1>, DatastoreError> {
        match self.request(Command::GetEgressApprovals(limit.min(100), now))? {
            Response::EgressApprovals(approvals) => Ok(approvals),
            _ => Err(DatastoreError::InternalError("Unexpected egress approvals response".into())),
        }
    }

    pub fn get_egress_approval(&self, id: &str, now: DateTime<Utc>) -> Result<Option<EgressApprovalV1>, DatastoreError> {
        match self.request(Command::GetEgressApproval(EgressApprovalId(id.into()), now))? {
            Response::EgressApproval(approval) => Ok(approval),
            _ => Err(DatastoreError::InternalError("Unexpected egress approval response".into())),
        }
    }

    pub fn get_or_create_egress_secrets(&self) -> Result<EgressSecrets, DatastoreError> {
        match self.request(Command::GetOrCreateEgressSecrets())? {
            Response::EgressSecrets(secrets) => Ok(secrets),
            _ => Err(DatastoreError::InternalError("Unexpected egress secrets response".into())),
        }
    }

    pub fn create_egress_approval(
        &self,
        destination_id: &str,
        purpose_id: &str,
        retention_id: &str,
        policy_version: u64,
        scope: EgressApprovalScopeV1,
        payload_tag: [u8; 32],
        expires_at: Option<DateTime<Utc>>,
        created_at: DateTime<Utc>,
    ) -> Result<String, DatastoreError> {
        match self.request(Command::CreateEgressApproval(
            destination_id.into(), purpose_id.into(), retention_id.into(), policy_version,
            scope, PayloadTag(payload_tag), expires_at, created_at,
        ))? {
            Response::EgressApprovalId(id) => Ok(id.0),
            _ => Err(DatastoreError::InternalError("Unexpected egress approval response".into())),
        }
    }

    pub fn consume_egress_approval(
        &self,
        id: &str,
        destination_id: &str,
        purpose_id: &str,
        retention_id: &str,
        policy_version: u64,
        payload_tag: [u8; 32],
        now: DateTime<Utc>,
    ) -> Result<EgressApprovalScopeV1, DatastoreError> {
        match self.request(Command::ConsumeEgressApproval(
            EgressApprovalId(id.into()), destination_id.into(), purpose_id.into(), retention_id.into(),
            policy_version, PayloadTag(payload_tag), now,
        ))? {
            Response::EgressApprovalScope(scope) => Ok(scope),
            _ => Err(DatastoreError::InternalError("Unexpected egress approval response".into())),
        }
    }

    pub fn clear_egress_approvals(&self) -> Result<(), DatastoreError> {
        _unwrap_empty_response(self.request(Command::ClearEgressApprovals())?)
    }

    pub fn get_egress_policy_state(
        &self,
    ) -> Result<Option<(SignedEgressPolicyBundleV1, EgressUserPolicyV1)>, DatastoreError> {
        match self.request(Command::GetEgressPolicyState())? {
            Response::EgressPolicyState(state) => Ok(state),
            _ => Err(DatastoreError::InternalError("Unexpected egress policy response".into())),
        }
    }

    pub fn store_egress_policy_state(
        &self,
        bundle: &SignedEgressPolicyBundleV1,
        user_policy: &EgressUserPolicyV1,
    ) -> Result<(), DatastoreError> {
        _unwrap_empty_response(self.request(Command::StoreEgressPolicyState(
            bundle.clone(), user_policy.clone(),
        ))?)
    }

    pub fn get_egress_user_policy(&self) -> Result<EgressUserPolicyV1, DatastoreError> {
        match self.request(Command::GetEgressUserPolicy())? {
            Response::EgressUserPolicy(policy) => Ok(policy),
            _ => Err(DatastoreError::InternalError("Unexpected egress user policy response".into())),
        }
    }

    pub fn store_egress_user_policy(&self, user_policy: &EgressUserPolicyV1) -> Result<(), DatastoreError> {
        _unwrap_empty_response(self.request(Command::StoreEgressUserPolicy(user_policy.clone()))?)
    }

    pub fn get_ai_settings(&self) -> Result<AISettingsV1, DatastoreError> {
        match self.request(Command::GetAISettings())? {
            Response::AISettings(settings) => Ok(settings),
            _ => Err(DatastoreError::InternalError("Unexpected AI settings response".into())),
        }
    }

    /// Replace AI settings only when the caller still holds the current revision.
    pub fn compare_and_set_ai_settings(
        &self,
        expected_revision: u64,
        settings: AISettingsV1,
    ) -> Result<Option<AISettingsV1>, DatastoreError> {
        match self.request(Command::CompareAndSetAISettings(expected_revision, settings))? {
            Response::AISettingsUpdate(updated) => Ok(updated),
            _ => Err(DatastoreError::InternalError("Unexpected AI settings update response".into())),
        }
    }

    pub fn get_ai_insight_history(&self) -> Result<AIInsightHistoryV1, DatastoreError> {
        match self.request(Command::GetAIInsightHistory())? {
            Response::AIInsightHistory(history) => Ok(history),
            _ => Err(DatastoreError::InternalError("Unexpected AI history response".into())),
        }
    }

    pub fn save_ai_insight(&self, insight: AIInsightV1) -> Result<AIInsightHistoryV1, DatastoreError> {
        match self.request(Command::SaveAIInsight(insight))? {
            Response::AIInsightHistoryUpdate(Some(history)) => Ok(history),
            _ => Err(DatastoreError::InternalError("Unexpected AI history save response".into())),
        }
    }

    pub fn delete_ai_insight(&self, insight_id: &str) -> Result<Option<AIInsightHistoryV1>, DatastoreError> {
        match self.request(Command::DeleteAIInsight(insight_id.into()))? {
            Response::AIInsightHistoryUpdate(history) => Ok(history),
            _ => Err(DatastoreError::InternalError("Unexpected AI history delete response".into())),
        }
    }

    pub fn get_key_value(&self, key: &str) -> Result<String, DatastoreError> {
        let cmd = Command::GetKeyValue(key.to_string());
        match self.request(cmd)? {
            Response::KeyValue(kv) => Ok(kv),
            _ => panic!("Invalid response"),
        }
    }

    pub fn set_key_value(&self, key: &str, data: &str) -> Result<(), DatastoreError> {
        let cmd = Command::SetKeyValue(key.to_string(), data.to_string());
        _unwrap_empty_response(self.request(cmd)?)
    }

    /// Atomically replace a local setting only if its previous value is unchanged.
    pub fn compare_and_set_key_value(
        &self,
        key: &str,
        expected: Option<&str>,
        data: Option<&str>,
    ) -> Result<bool, DatastoreError> {
        match self.request(Command::CompareAndSetKeyValue(
            key.to_string(), expected.map(str::to_string), data.map(str::to_string),
        ))? {
            Response::Boolean(updated) => Ok(updated),
            _ => Err(DatastoreError::InternalError("Unexpected key-value update response".into())),
        }
    }

    pub fn delete_key_value(&self, key: &str) -> Result<(), DatastoreError> {
        let cmd = Command::DeleteKeyValue(key.to_string());
        _unwrap_empty_response(self.request(cmd)?)
    }

    pub fn refresh_privacy_filter(&self) -> Result<(), DatastoreError> {
        _unwrap_empty_response(self.request(Command::RefreshPrivacyFilter())?)
    }

    /// Renames a bucket from `old_id` to `new_id`.
    pub fn rename_bucket(&self, old_id: &str, new_id: &str) -> Result<(), DatastoreError> {
        let cmd = Command::RenameBucket(old_id.to_string(), new_id.to_string());
        _unwrap_empty_response(self.request(cmd)?)
    }

    /// Migrates all buckets whose hostname is "unknown" or "Unknown" to `new_hostname`.
    /// Returns the number of buckets updated.
    pub fn migrate_hostname(&self, new_hostname: &str) -> Result<usize, DatastoreError> {
        let cmd = Command::MigrateHostname(new_hostname.to_string());
        match self.request(cmd)? {
            Response::Count(n) => Ok(n as usize),
            _ => Err(DatastoreError::InternalError(
                "Unexpected response to MigrateHostname command".to_string(),
            )),
        }
    }

    /// Migrates all buckets whose name starts with `aw-watcher-android-test` to use
    /// `aw-watcher-android` instead (e.g. debug-build buckets from older app versions).
    /// Returns the number of buckets updated.
    pub fn migrate_test_bucket_names(&self) -> Result<usize, DatastoreError> {
        let cmd = Command::MigrateTestBucketNames();
        match self.request(cmd)? {
            Response::Count(n) => Ok(n as usize),
            _ => Err(DatastoreError::InternalError(
                "Unexpected response to MigrateTestBucketNames command".to_string(),
            )),
        }
    }

    // Should block until worker has stopped
    pub fn close(&self) {
        if self.lock().is_err() { warn!("Datastore closed with an error"); }
    }
}

#[cfg(test)]
mod egress_lease_tests {
    use super::*;

    #[test]
    fn egress_lease_keeps_vault_worker_open_until_release() {
        let store = Datastore::new_in_memory(false);
        let lease = store.egress_lease().unwrap();
        assert!(store.worker.try_write().is_err());
        drop(lease);
        let write_lock = store.worker.try_write().unwrap();
        drop(write_lock);
        store.close();
    }
}
