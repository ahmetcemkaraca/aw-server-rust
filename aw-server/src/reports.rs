//! Owned, in-memory report runs. Datastore ACKs are consumed even after cancellation.
use aw_datastore::{Datastore, PreparedReportImportV1};
use aw_entitlements::RuntimeFeatureAccessV1;
use aw_models::*;
use std::{
    io::Write,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use ReportExecutionErrorV1 as Error;
type Result<T> = std::result::Result<T, Error>;
const RETENTION: Duration = Duration::from_secs(120);

pub struct NativeReportFeatureAccessV1(pub Arc<RuntimeFeatureAccessV1>);
impl ReportFeatureAccessV1 for NativeReportFeatureAccessV1 {
    fn with_access(&self, action: Box<dyn FnOnce() -> Result<()> + '_>) -> Result<()> {
        let now =
            crate::feature_access::current_time().map_err(|_| Error::EntitlementUnavailable)?;
        self.0
            .with_feature_access("advanced-reports", now, action)
            .map_err(|_| Error::EntitlementUnavailable)?
    }
}
struct EpochAccess {
    access: Arc<dyn ReportFeatureAccessV1>,
    epoch: Arc<AtomicU64>,
    expected: u64,
}
impl ReportFeatureAccessV1 for EpochAccess {
    fn with_access(&self, action: Box<dyn FnOnce() -> Result<()> + '_>) -> Result<()> {
        if self.epoch.load(Ordering::Acquire) != self.expected {
            return Err(Error::Cancelled);
        }
        self.access.with_access(Box::new(|| {
            if self.epoch.load(Ordering::Acquire) != self.expected {
                return Err(Error::Cancelled);
            }
            action()
        }))
    }
}
struct Active {
    id: String,
    capability: ReportCapabilityV1,
    epoch: u64,
    control: Arc<QueryControl>,
    release: bool,
}
struct Terminal {
    id: String,
    capability: ReportCapabilityV1,
    epoch: u64,
    finished: Instant,
    normal: Arc<[u8]>,
    raw: Arc<[u8]>,
}
#[derive(Default)]
struct State {
    active: Option<Active>,
    terminal: Option<Terminal>,
    preview: Option<(Instant, Arc<PreparedReportImportV1>)>,
    preview_sequence: u64,
}
pub struct ReportCoordinatorV1 {
    store: Datastore,
    access: Arc<dyn ReportFeatureAccessV1>,
    epoch: Arc<AtomicU64>,
    state: Mutex<State>,
}
impl State {
    fn expire(&mut self) {
        if self
            .terminal
            .as_ref()
            .is_some_and(|t| t.finished.elapsed() >= RETENTION)
        {
            self.terminal = None;
        }
        if self
            .preview
            .as_ref()
            .is_some_and(|(time, _)| time.elapsed() >= RETENTION)
        {
            self.preview = None;
        }
    }
}
fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0; N];
    getrandom::getrandom(&mut bytes).map_err(|_| Error::InternalError)?;
    Ok(bytes)
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn owner(left: &ReportCapabilityV1, right: &ReportCapabilityV1) -> bool {
    bool::from(left.as_bytes().ct_eq(right.as_bytes()))
}
struct Encoder<'a> {
    bytes: Vec<u8>,
    control: Option<&'a QueryControl>,
    limit: usize,
    error: Option<Error>,
}
impl Write for Encoder<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let admission = (|| {
            if self
                .bytes
                .len()
                .checked_add(bytes.len())
                .is_none_or(|n| n > self.limit)
            {
                return Err(Error::ByteLimit);
            }
            if let Some(control) = self.control {
                control.charge_fuel(1)?;
                control.charge_values(1)?;
                control.charge_bytes(bytes.len() as u64)?;
            }
            Ok(())
        })();
        if let Err(error) = admission {
            self.error.get_or_insert(error);
            return Err(std::io::Error::other("report encoding limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn encode(
    value: &impl serde::Serialize,
    control: Option<&QueryControl>,
    limit: usize,
) -> Result<Arc<[u8]>> {
    let mut encoder = Encoder {
        bytes: Vec::new(),
        control,
        limit,
        error: None,
    };
    serde_json::to_writer(&mut encoder, value)
        .map_err(|_| encoder.error.unwrap_or(Error::DataIntegrity))?;
    if let Some(control) = control {
        control.charge_bytes(encoder.bytes.len() as u64)?;
        control.checkpoint()?;
    }
    Ok(Arc::from(encoder.bytes))
}
fn patch_execution(body: &mut Arc<[u8]>, elapsed: u64) -> Result<()> {
    let bytes = Arc::get_mut(body).ok_or(Error::InternalError)?;
    let prefix = b"\"execution_ms\":";
    let needle = b"\"execution_ms\":18446744073709551615";
    let offset = bytes[..bytes.len().min(512)]
        .windows(needle.len())
        .position(|part| part == needle)
        .ok_or(Error::InternalError)?
        + prefix.len();
    // A reserved numeric slot permits final timing without copying either complete body.
    let digits = elapsed.to_string();
    let slot = &mut bytes[offset..offset + 20];
    slot.fill(b' ');
    slot[20 - digits.len()..].copy_from_slice(digits.as_bytes());
    Ok(())
}
impl ReportCoordinatorV1 {
    pub fn new(store: Datastore, access: Arc<RuntimeFeatureAccessV1>) -> Arc<Self> {
        let shared = store.clone();
        store.share_report_runtime(move || {
            Self::build(shared, Arc::new(NativeReportFeatureAccessV1(access)))
        })
    }
    fn build(store: Datastore, access: Arc<dyn ReportFeatureAccessV1>) -> Arc<Self> {
        let coordinator = Arc::new(Self {
            store: store.clone(),
            access,
            epoch: Arc::new(AtomicU64::new(0)),
            state: Mutex::new(State::default()),
        });
        let weak = Arc::downgrade(&coordinator);
        store.set_report_invalidator(Arc::new(move || {
            if let Some(coordinator) = weak.upgrade() {
                coordinator.invalidate();
            }
        }));
        coordinator
    }
    fn lock_state(&self) -> Result<std::sync::MutexGuard<'_, State>> {
        self.state.lock().map_err(|_| Error::InternalError)
    }
    fn access_at(&self, expected: u64) -> Arc<dyn ReportFeatureAccessV1> {
        Arc::new(EpochAccess {
            access: self.access.clone(),
            epoch: self.epoch.clone(),
            expected,
        })
    }
    pub fn invalidate(&self) {
        self.epoch.fetch_add(1, Ordering::AcqRel);
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(active) = &state.active {
            active.control.cancel();
        }
        state.terminal = None;
        state.preview = None;
        // Active ownership/capacity remains until its worker ACK and stage have exited.
    }
    pub fn library(&self) -> Result<ReportLibraryV1> {
        self.store.report_library()
    }
    pub fn update_library(&self, request: UpdateReportLibraryRequestV1) -> Result<ReportLibraryV1> {
        request.validate()?;
        self.store
            .update_report_library(request, self.access_at(self.epoch.load(Ordering::Acquire)))
    }
    pub fn export_library(
        &self,
        request: ReportPortableExportRequestV1,
    ) -> Result<ReportPortableExportV1> {
        request.validate()?;
        self.store
            .export_report_library(request.include_category_sets)
    }
    pub fn preview_import(
        &self,
        package: PortableReportPackV1,
    ) -> Result<ReportImportPreviewResponseV1> {
        package.validate()?;
        let epoch = self.epoch.load(Ordering::Acquire);
        let sequence = {
            let mut state = self.lock_state()?;
            state.preview_sequence = state
                .preview_sequence
                .checked_add(1)
                .ok_or(Error::InternalError)?;
            state.preview = None;
            state.preview_sequence
        };
        let prepared = self
            .store
            .prepare_report_import(package, self.access_at(epoch))?;
        let mut state = self.lock_state()?;
        if self.epoch.load(Ordering::Acquire) != epoch {
            return Err(Error::Cancelled);
        }
        if state.preview_sequence != sequence {
            return Err(Error::StaleConfiguration);
        }
        let preview = prepared.preview().clone();
        state.preview = Some((Instant::now(), prepared));
        Ok(preview)
    }
    pub fn commit_import(&self, request: ReportImportCommitRequestV1) -> Result<ReportLibraryV1> {
        request.validate()?;
        let epoch = self.epoch.load(Ordering::Acquire);
        let prepared = {
            let mut state = self.lock_state()?;
            state.expire();
            if !state
                .preview
                .as_ref()
                .is_some_and(|(_, p)| p.preview().preview_id == request.preview_id)
            {
                return Err(Error::StaleConfiguration);
            }
            state.preview.take().ok_or(Error::StaleConfiguration)?.1
        };
        self.store
            .commit_report_import(prepared, self.access_at(epoch))
    }
    pub fn start(
        self: &Arc<Self>,
        request: AdvancedReportRunRequestV1,
    ) -> Result<ReportRunStartResponseV1> {
        request.validate()?;
        let id = hex(&random::<16>()?);
        let capability = ReportCapabilityV1::from_bytes(random::<32>()?);
        let control = Arc::new(QueryControl::managed());
        let epoch = self.epoch.load(Ordering::Acquire);
        {
            let mut state = self.lock_state()?;
            state.expire();
            if state.active.is_some() {
                return Err(Error::SourceUnavailable);
            }
            if self.epoch.load(Ordering::Acquire) != epoch {
                return Err(Error::Cancelled);
            }
            state.active = Some(Active {
                id: id.clone(),
                capability: capability.clone(),
                epoch,
                control: control.clone(),
                release: false,
            });
        }
        let coordinator = self.clone();
        let run_id = id.clone();
        if std::thread::Builder::new()
            .name("peak-report".into())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    coordinator.execute(&run_id, epoch, request, &control)
                }))
                .unwrap_or(Err(Error::InternalError));
                if let Err(reason) = result {
                    coordinator.fail(&run_id, epoch, &control, reason);
                }
            })
            .is_err()
        {
            let mut state = self.lock_state()?;
            if state.active.as_ref().is_some_and(|a| a.id == id) {
                state.active = None;
            }
            return Err(Error::InternalError);
        }
        Ok(ReportRunStartResponseV1 {
            schema_version: 1,
            run_id: id,
            capability,
            state: ReportRunStateV1::Queued,
        })
    }
    fn execute(
        &self,
        id: &str,
        epoch: u64,
        request: AdvancedReportRunRequestV1,
        control: &Arc<QueryControl>,
    ) -> Result<()> {
        let access = self.access_at(epoch);
        // This blocking call retains and collects the worker's synchronous receiver.
        let snapshot = self
            .store
            .read_report_inputs(request, control.clone(), access.clone())?;
        let mut bodies = None;
        access.with_access(Box::new(|| {
            control.checkpoint()?;
            let calculated = aw_query::reports::calculate_report(&snapshot, control)?;
            let stats = control.stats();
            control.charge_bytes((std::mem::size_of::<ReportRunStatusV1>() + id.len()) as u64)?;
            let mut status = ReportRunStatusV1 {
                schema_version: 1,
                run_id: id.into(),
                state: ReportRunStateV1::Complete,
                queue_wait_ms: stats.queue_wait_ms,
                execution_ms: Some(u64::MAX),
                reason: None,
                result: Some(calculated.completed),
            };
            let normal = encode(
                &status,
                Some(control),
                QueryLimits::MANAGED.max_bytes as usize,
            )?;
            status
                .result
                .as_mut()
                .ok_or(Error::InternalError)?
                .raw_events = Some(calculated.raw_periods);
            let raw = encode(
                &status,
                Some(control),
                QueryLimits::MANAGED.max_bytes as usize,
            )?;
            control.charge_bytes(40)?;
            bodies = Some((normal, raw));
            Ok(())
        }))?;
        access.with_access(Box::new(|| {
            control.checkpoint()?;
            let (mut normal, mut raw) = bodies.take().ok_or(Error::InternalError)?;
            let mut state = self.lock_state()?;
            if self.epoch.load(Ordering::Acquire) != epoch {
                return Err(Error::Cancelled);
            }
            let active = state
                .active
                .as_ref()
                .filter(|a| a.id == id && a.epoch == epoch)
                .ok_or(Error::Cancelled)?;
            control.checkpoint()?;
            let capability = active.capability.clone();
            let release = active.release;
            let elapsed = control.stats().execution_ms.ok_or(Error::InternalError)?;
            patch_execution(&mut normal, elapsed)?;
            patch_execution(&mut raw, elapsed)?;
            if !release {
                state.terminal = Some(Terminal {
                    id: id.into(),
                    capability,
                    epoch,
                    finished: Instant::now(),
                    normal,
                    raw,
                });
            }
            Ok(())
        }))?;
        control.checkpoint()?;
        let mut state = self.lock_state()?;
        if state
            .active
            .as_ref()
            .is_some_and(|active| active.id == id && active.epoch == epoch)
        {
            state.active = None;
        }
        Ok(())
    }
    fn fail(&self, id: &str, epoch: u64, control: &QueryControl, reason: Error) {
        let stats = control.stats();
        let state = match reason {
            Error::Cancelled => ReportRunStateV1::Cancelled,
            Error::RowLimit
            | Error::ByteLimit
            | Error::ValueLimit
            | Error::FuelLimit
            | Error::Deadline => ReportRunStateV1::Limited,
            _ => ReportRunStateV1::Failed,
        };
        let status = ReportRunStatusV1 {
            schema_version: 1,
            run_id: id.into(),
            state,
            queue_wait_ms: stats.queue_wait_ms,
            execution_ms: stats.execution_ms,
            reason: Some(reason),
            result: None,
        };
        let body = encode(&status, None, 16 * 1024);
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.state.clear_poison();
        if !state
            .active
            .as_ref()
            .is_some_and(|a| a.id == id && a.epoch == epoch)
        {
            return;
        }
        let active = state.active.take().unwrap();
        if state
            .terminal
            .as_ref()
            .is_some_and(|terminal| terminal.id == id)
        {
            state.terminal = None;
        }
        if active.release || self.epoch.load(Ordering::Acquire) != epoch {
            return;
        }
        if let Ok(body) = body {
            state.terminal = Some(Terminal {
                id: id.into(),
                capability: active.capability,
                epoch,
                finished: Instant::now(),
                normal: body.clone(),
                raw: body,
            });
        }
    }
    pub fn read(
        &self,
        request: ReportRunReadRequestV1,
        capability: &ReportCapabilityV1,
    ) -> Result<Arc<[u8]>> {
        request.validate()?;
        let mut state = self.lock_state()?;
        state.expire();
        if let Some(active) = state.active.as_ref().filter(|a| a.id == request.run_id) {
            if !owner(&active.capability, capability)
                || active.epoch != self.epoch.load(Ordering::Acquire)
            {
                return Err(Error::SourceUnavailable);
            }
            let stats = active.control.stats();
            let status = ReportRunStatusV1 {
                schema_version: 1,
                run_id: active.id.clone(),
                state: if stats.execution_ms.is_some() {
                    ReportRunStateV1::Running
                } else {
                    ReportRunStateV1::Queued
                },
                queue_wait_ms: stats.queue_wait_ms,
                execution_ms: stats.execution_ms,
                reason: None,
                result: None,
            };
            return encode(&status, None, 16 * 1024);
        }
        let terminal = state
            .terminal
            .as_ref()
            .filter(|t| {
                t.id == request.run_id
                    && owner(&t.capability, capability)
                    && t.epoch == self.epoch.load(Ordering::Acquire)
            })
            .ok_or(Error::SourceUnavailable)?;
        Ok(if request.include_raw_events {
            terminal.raw.clone()
        } else {
            terminal.normal.clone()
        })
    }
    pub fn cancel(
        &self,
        request: ReportRunOwnerRequestV1,
        capability: &ReportCapabilityV1,
    ) -> Result<ReportRunCancelResponseV1> {
        request.validate()?;
        let mut state = self.lock_state()?;
        state.expire();
        if let Some(active) = state.active.as_ref().filter(|a| {
            a.id == request.run_id
                && owner(&a.capability, capability)
                && a.epoch == self.epoch.load(Ordering::Acquire)
        }) {
            active.control.cancel();
        } else if !state.terminal.as_ref().is_some_and(|t| {
            t.id == request.run_id
                && owner(&t.capability, capability)
                && t.epoch == self.epoch.load(Ordering::Acquire)
        }) {
            return Err(Error::SourceUnavailable);
        }
        Ok(ReportRunCancelResponseV1 {
            schema_version: 1,
            run_id: request.run_id,
            requested: true,
        })
    }
    pub fn release(
        &self,
        request: ReportRunOwnerRequestV1,
        capability: &ReportCapabilityV1,
    ) -> Result<ReportRunReleaseResponseV1> {
        request.validate()?;
        let mut state = self.lock_state()?;
        state.expire();
        let released;
        if let Some(active) = state.active.as_mut().filter(|a| {
            a.id == request.run_id
                && owner(&a.capability, capability)
                && a.epoch == self.epoch.load(Ordering::Acquire)
        }) {
            active.control.cancel();
            active.release = true;
            released = false;
        } else if state.terminal.as_ref().is_some_and(|t| {
            t.id == request.run_id
                && owner(&t.capability, capability)
                && t.epoch == self.epoch.load(Ordering::Acquire)
        }) {
            state.terminal = None;
            released = true;
        } else {
            return Err(Error::SourceUnavailable);
        }
        Ok(ReportRunReleaseResponseV1 {
            schema_version: 1,
            run_id: request.run_id,
            released,
        })
    }
}

#[cfg(all(test, any(feature = "encryption", feature = "encryption-vendored")))]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use std::sync::{atomic::AtomicUsize, mpsc};
    mod entitlement_fixture {
        include!("../tests/support/entitlement.rs");
    }
    struct Gate {
        native: Arc<dyn ReportFeatureAccessV1>,
        at: usize,
        calls: AtomicUsize,
        reached: mpsc::Sender<()>,
        resume: Mutex<mpsc::Receiver<()>>,
        panic: bool,
        after: bool,
    }
    impl ReportFeatureAccessV1 for Gate {
        fn with_access(&self, action: Box<dyn FnOnce() -> Result<()> + '_>) -> Result<()> {
            let blocked = self.calls.fetch_add(1, Ordering::AcqRel) + 1 == self.at;
            if blocked && !self.after {
                self.reached.send(()).unwrap();
                self.resume
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap();
                assert!(!self.panic, "synthetic stage panic");
            }
            let result = self.native.with_access(action);
            if blocked && self.after {
                self.reached.send(()).unwrap();
                self.resume
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap();
            }
            result
        }
    }
    fn gate(
        native: Arc<dyn ReportFeatureAccessV1>,
        at: usize,
        panic: bool,
    ) -> (Arc<Gate>, mpsc::Receiver<()>, mpsc::Sender<()>) {
        let (reached, waiting) = mpsc::channel();
        let (resume, receiver) = mpsc::channel();
        (
            Arc::new(Gate {
                native,
                at,
                calls: AtomicUsize::new(0),
                reached,
                resume: Mutex::new(receiver),
                panic,
                after: false,
            }),
            waiting,
            resume,
        )
    }
    fn request() -> AdvancedReportRunRequestV1 {
        serde_json::from_value(json!({"schema_version":1,"template_id":"work","expected_library_revision":1,"ordered_host_ids":["Host"],"current_periods":[{"local_date":"2026-01-01","interval":"2026-01-01T00:00:00Z/2026-01-02T00:00:00Z"}],"previous_periods":null,"timezone":"Europe/Berlin","timezone_resolution":"client-local-calendar-v1","day_start":"00:00"})).unwrap()
    }
    fn fixture_with_source() -> (
        Datastore,
        Arc<aw_entitlements::RuntimeFeatureAccessV1>,
        Arc<entitlement_fixture::MemorySource>,
    ) {
        let now = entitlement_fixture::aw_server_time();
        let (runtime, source) = entitlement_fixture::configured_access(
            entitlement_fixture::report_proof(now, 1, false, false),
            now,
        );
        let store = Datastore::new_encrypted(":memory:".into(), "9a".repeat(32), false);
        for (id, kind, data) in [
            (
                "aw-watcher-window_Host",
                "currentwindow",
                json!({"app":"Editor"}),
            ),
            (
                "aw-watcher-afk_Host",
                "afkstatus",
                json!({"status":"not-afk"}),
            ),
        ] {
            store
                .create_bucket(&Bucket {
                    bid: None,
                    id: id.into(),
                    _type: kind.into(),
                    client: "test".into(),
                    hostname: "Host".into(),
                    created: None,
                    data: Default::default(),
                    metadata: Default::default(),
                    events: None,
                    last_updated: None,
                })
                .unwrap();
            store
                .insert_events(
                    id,
                    &[Event::new(
                        "2026-01-01T12:00:00Z".parse().unwrap(),
                        chrono::Duration::seconds(60),
                        data.as_object().unwrap().clone(),
                    )],
                )
                .unwrap();
        }
        store.set_key_value("settings.classes", "[]").unwrap();
        store.update_report_library(serde_json::from_value(json!({"schema_version":1,"expected_revision":0,"library":{"schema_version":1,"revision":0,"templates":[{"id":"work","name":"Work","content_version":1,"method_id":"work-time-report","method_version":1,"sections":["daily"],"category_paths":[],"break_time_seconds":0,"rule_pack":null}],"rule_packs":[]}})).unwrap(),Arc::new(NativeReportFeatureAccessV1(runtime.clone()))).unwrap();
        (store, runtime, source)
    }
    fn fixture() -> (Datastore, Arc<aw_entitlements::RuntimeFeatureAccessV1>) {
        let (store, runtime, _) = fixture_with_source();
        (store, runtime)
    }
    fn read(coordinator: &ReportCoordinatorV1, start: &ReportRunStartResponseV1) -> Result<Value> {
        let bytes = coordinator.read(
            ReportRunReadRequestV1 {
                schema_version: 1,
                run_id: start.run_id.clone(),
                include_raw_events: false,
            },
            &start.capability,
        )?;
        Ok(serde_json::from_slice(&bytes).unwrap())
    }
    fn terminal(coordinator: &ReportCoordinatorV1, start: &ReportRunStartResponseV1) -> Value {
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            let status = read(coordinator, start).unwrap();
            if !matches!(status["state"].as_str(), Some("queued" | "running")) {
                return status;
            }
            assert!(Instant::now() < until);
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    fn await_exit(coordinator: &ReportCoordinatorV1) {
        let until = Instant::now() + Duration::from_secs(5);
        while coordinator.state.lock().unwrap().active.is_some() {
            assert!(Instant::now() < until);
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    #[test]
    fn report_runtime_revalidates_real_signed_access_between_actual_stages() {
        for stage in [2, 3] {
            let (store, runtime) = fixture();
            let (access, reached, resume) = gate(
                Arc::new(NativeReportFeatureAccessV1(runtime.clone())),
                stage,
                false,
            );
            let coordinator = ReportCoordinatorV1::build(store, access);
            let start = coordinator.start(request()).unwrap();
            reached.recv_timeout(Duration::from_secs(5)).unwrap();
            let now = entitlement_fixture::aw_server_time();
            assert!(runtime
                .install(entitlement_fixture::report_proof(now, 2, true, false), now)
                .is_err());
            resume.send(()).unwrap();
            let status = terminal(&coordinator, &start);
            assert_eq!(status["state"], "failed");
            assert_eq!(status["reason"], "entitlement-unavailable");
            assert_eq!(status["result"], Value::Null);
            assert_eq!(coordinator.library().unwrap().revision, 1);
        }
    }
    #[test]
    fn report_runtime_publication_timing_includes_serialization_and_stage_wait() {
        let (store, runtime) = fixture();
        let (access, reached, resume) =
            gate(Arc::new(NativeReportFeatureAccessV1(runtime)), 3, false);
        let coordinator = ReportCoordinatorV1::build(store, access);
        let start = coordinator.start(request()).unwrap();
        reached.recv_timeout(Duration::from_secs(5)).unwrap();
        std::thread::sleep(Duration::from_millis(30));
        resume.send(()).unwrap();
        let status = terminal(&coordinator, &start);
        assert_eq!(status["state"], "complete");
        assert!(
            status["execution_ms"].as_u64().unwrap() >= 30,
            "completion timing omitted the publication stage wait"
        );
    }
    #[test]
    fn report_runtime_cancel_and_release_keep_capacity_until_real_worker_ack() {
        for release in [false, true] {
            let (store, runtime) = fixture();
            let coordinator = ReportCoordinatorV1::new(store.clone(), runtime.clone());
            let (hold, reached, resume) =
                gate(Arc::new(NativeReportFeatureAccessV1(runtime)), 1, false);
            let mut library = store.report_library().unwrap();
            library.templates[0].name = "Changed".into();
            library.templates[0].content_version = 2;
            let writer = store.clone();
            let worker = std::thread::spawn(move || {
                writer.update_report_library(
                    UpdateReportLibraryRequestV1 {
                        schema_version: 1,
                        expected_revision: 1,
                        library,
                    },
                    hold,
                )
            });
            reached.recv_timeout(Duration::from_secs(5)).unwrap();
            let start = coordinator.start(request()).unwrap();
            let status = read(&coordinator, &start).unwrap();
            assert_eq!(status["state"], "queued");
            assert_eq!(status["execution_ms"], Value::Null);
            let owner = ReportRunOwnerRequestV1 {
                schema_version: 1,
                run_id: start.run_id.clone(),
            };
            assert!(
                coordinator
                    .cancel(owner.clone(), &start.capability)
                    .unwrap()
                    .requested
            );
            if release {
                assert!(
                    !coordinator
                        .release(owner, &start.capability)
                        .unwrap()
                        .released
                );
            }
            assert_eq!(
                coordinator.start(request()).err(),
                Some(Error::SourceUnavailable)
            );
            assert_eq!(read(&coordinator, &start).unwrap()["state"], "queued");
            resume.send(()).unwrap();
            worker.join().unwrap().unwrap();
            await_exit(&coordinator);
            if release {
                assert_eq!(
                    read(&coordinator, &start).err(),
                    Some(Error::SourceUnavailable)
                );
            } else {
                let status = terminal(&coordinator, &start);
                assert_eq!(status["state"], "cancelled");
                assert_eq!(status["result"], Value::Null);
                assert_eq!(status["execution_ms"], Value::Null);
            }
            store
                .set_key_value("ordinary.after_cancel", "usable")
                .unwrap();
            assert_eq!(
                store.get_key_value("ordinary.after_cancel").unwrap(),
                "usable"
            );
        }
    }
    #[test]
    fn report_runtime_lock_clears_before_worker_wait_and_blocks_late_publication() {
        let (store, runtime) = fixture();
        let coordinator = ReportCoordinatorV1::new(store.clone(), runtime.clone());
        let old = coordinator.start(request()).unwrap();
        terminal(&coordinator, &old);
        let preview=coordinator.preview_import(serde_json::from_value(json!({"schema_version":1,"templates":[],"rule_packs":[],"category_sets":[{"id":"review","name":"Review","classes":[]}]})).unwrap()).unwrap();
        let (hold, reached, resume) =
            gate(Arc::new(NativeReportFeatureAccessV1(runtime)), 1, false);
        let mut library = store.report_library().unwrap();
        library.templates[0].name = "Changed".into();
        library.templates[0].content_version = 2;
        let writer = store.clone();
        let worker = std::thread::spawn(move || {
            writer.update_report_library(
                UpdateReportLibraryRequestV1 {
                    schema_version: 1,
                    expected_revision: 1,
                    library,
                },
                hold,
            )
        });
        reached.recv_timeout(Duration::from_secs(5)).unwrap();
        let queued = coordinator.start(request()).unwrap();
        let closer = store.clone();
        let (closed, waiting) = mpsc::channel();
        std::thread::spawn(move || closed.send(closer.lock()).unwrap());
        let until = Instant::now() + Duration::from_secs(5);
        while coordinator.epoch.load(Ordering::Acquire) == 0 {
            assert!(Instant::now() < until);
            std::thread::yield_now();
        }
        assert_eq!(
            read(&coordinator, &old).err(),
            Some(Error::SourceUnavailable)
        );
        assert_eq!(
            read(&coordinator, &queued).err(),
            Some(Error::SourceUnavailable)
        );
        assert!(coordinator.state.lock().unwrap().preview.is_none());
        assert!(coordinator.state.lock().unwrap().active.is_some());
        assert!(waiting.try_recv().is_err());
        assert_eq!(
            coordinator.start(request()).err(),
            Some(Error::SourceUnavailable)
        );
        assert_eq!(
            coordinator
                .commit_import(ReportImportCommitRequestV1 {
                    schema_version: 1,
                    preview_id: preview.preview_id,
                    accept: true
                })
                .err(),
            Some(Error::StaleConfiguration)
        );
        resume.send(()).unwrap();
        worker.join().unwrap().unwrap();
        waiting
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap();
        await_exit(&coordinator);
        assert!(coordinator.state.lock().unwrap().terminal.is_none());
        assert!(store.is_locked());
    }
    #[test]
    fn report_runtime_publication_keeps_capacity_until_stage_exit() {
        let (store, runtime) = fixture();
        let (mut access, reached, resume) =
            gate(Arc::new(NativeReportFeatureAccessV1(runtime)), 3, false);
        Arc::get_mut(&mut access).unwrap().after = true;
        let coordinator = ReportCoordinatorV1::build(store, access);
        let start = coordinator.start(request()).unwrap();
        reached.recv_timeout(Duration::from_secs(5)).unwrap();
        let retained = coordinator.state.lock().unwrap().active.is_some();
        resume.send(()).unwrap();
        await_exit(&coordinator);
        assert!(
            retained,
            "publication released capacity before the access stage exited"
        );
        assert_eq!(terminal(&coordinator, &start)["state"], "complete");
    }
    #[test]
    fn report_runtime_coordinator_is_shared_by_datastore_clones_without_a_cycle() {
        let (store, runtime) = fixture();
        let one = ReportCoordinatorV1::new(store.clone(), runtime.clone());
        let two = ReportCoordinatorV1::new(store.clone(), runtime);
        assert!(
            Arc::ptr_eq(&one, &two),
            "same datastore created independent report capacity"
        );
        let weak = Arc::downgrade(&one);
        drop(one);
        drop(two);
        assert!(
            weak.upgrade().is_none(),
            "report runtime retained an Arc cycle"
        );
    }
    #[test]
    fn report_runtime_release_after_publication_clears_prepared_terminal_after_stage_exit() {
        let (store, runtime) = fixture();
        let (mut access, reached, resume) =
            gate(Arc::new(NativeReportFeatureAccessV1(runtime)), 3, false);
        Arc::get_mut(&mut access).unwrap().after = true;
        let coordinator = ReportCoordinatorV1::build(store, access);
        let start = coordinator.start(request()).unwrap();
        reached.recv_timeout(Duration::from_secs(5)).unwrap();
        let release = coordinator
            .release(
                ReportRunOwnerRequestV1 {
                    schema_version: 1,
                    run_id: start.run_id.clone(),
                },
                &start.capability,
            )
            .unwrap();
        assert!(!release.released);
        resume.send(()).unwrap();
        await_exit(&coordinator);
        assert_eq!(
            read(&coordinator, &start).err(),
            Some(Error::SourceUnavailable)
        );
    }
    #[test]
    fn report_runtime_queued_signed_revocation_denies_snapshot_without_partial_result() {
        let (store, runtime) = fixture();
        let coordinator = ReportCoordinatorV1::new(store.clone(), runtime.clone());
        let (hold, reached, resume) = gate(
            Arc::new(NativeReportFeatureAccessV1(runtime.clone())),
            1,
            false,
        );
        let mut library = store.report_library().unwrap();
        library.templates[0].name = "Changed".into();
        library.templates[0].content_version = 2;
        let writer = store.clone();
        let worker = std::thread::spawn(move || {
            writer.update_report_library(
                UpdateReportLibraryRequestV1 {
                    schema_version: 1,
                    expected_revision: 1,
                    library,
                },
                hold,
            )
        });
        reached.recv_timeout(Duration::from_secs(5)).unwrap();
        let start = coordinator.start(request()).unwrap();
        assert_eq!(
            read(&coordinator, &start).unwrap()["execution_ms"],
            Value::Null
        );
        let now = entitlement_fixture::aw_server_time();
        assert!(runtime
            .install(entitlement_fixture::report_proof(now, 2, true, false), now)
            .is_err());
        resume.send(()).unwrap();
        assert_eq!(
            worker.join().unwrap().err(),
            Some(Error::EntitlementUnavailable)
        );
        let status = terminal(&coordinator, &start);
        assert_eq!(status["reason"], "entitlement-unavailable");
        assert_eq!(status["result"], Value::Null);
        assert_eq!(store.report_library().unwrap().revision, 1);
    }
    #[test]
    fn report_runtime_expired_signed_source_is_reloaded_after_snapshot() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let (store, runtime, source) = fixture_with_source();
        let (access, reached, resume) =
            gate(Arc::new(NativeReportFeatureAccessV1(runtime)), 2, false);
        let coordinator = ReportCoordinatorV1::build(store, access);
        let start = coordinator.start(request()).unwrap();
        reached.recv_timeout(Duration::from_secs(5)).unwrap();
        let now = entitlement_fixture::aw_server_time();
        let mut expired = source.proof.lock().unwrap().clone().unwrap();
        let claims = &mut expired.entitlement.payload.claims;
        claims.issued_at = now - 7200;
        claims.expires_at = now - 3600;
        claims.grace_until = now - 1;
        expired.entitlement.signature = URL_SAFE_NO_PAD.encode(
            entitlement_fixture::key()
                .sign(&expired.entitlement.payload.signing_bytes().unwrap())
                .as_ref(),
        );
        *source.proof.lock().unwrap() = Some(expired);
        resume.send(()).unwrap();
        let status = terminal(&coordinator, &start);
        assert_eq!(status["reason"], "entitlement-unavailable");
        assert_eq!(status["result"], Value::Null);
    }
    #[test]
    fn report_runtime_failed_entitlement_persistence_stays_closed_and_preserves_inner_errors() {
        use aw_entitlements::EntitlementSourceV1;
        use ring::signature::KeyPair;
        struct Failing {
            inner: entitlement_fixture::MemorySource,
            fail: std::sync::atomic::AtomicBool,
        }
        impl EntitlementSourceV1 for Failing {
            fn load(
                &self,
            ) -> std::result::Result<Option<aw_entitlements::StoredEntitlementV1>, &'static str>
            {
                self.inner.load()
            }
            fn save(
                &self,
                proof: &aw_entitlements::StoredEntitlementV1,
            ) -> std::result::Result<(), &'static str> {
                if self.fail.load(Ordering::Acquire) {
                    Err("synthetic persistence failure")
                } else {
                    self.inner.save(proof)
                }
            }
            fn revocation_floor(&self, scope: &str) -> std::result::Result<u64, &'static str> {
                self.inner.revocation_floor(scope)
            }
            fn advance_revocation_floor(
                &self,
                scope: &str,
                sequence: u64,
            ) -> std::result::Result<(), &'static str> {
                self.inner.advance_revocation_floor(scope, sequence)
            }
        }
        let source = Arc::new(Failing {
            inner: Default::default(),
            fail: std::sync::atomic::AtomicBool::new(false),
        });
        let runtime = Arc::new(RuntimeFeatureAccessV1::new(
            std::collections::BTreeMap::from([(
                entitlement_fixture::KEY_ID.into(),
                entitlement_fixture::key()
                    .public_key()
                    .as_ref()
                    .try_into()
                    .unwrap(),
            )]),
            1,
            source.clone(),
        ));
        let now = entitlement_fixture::aw_server_time();
        runtime
            .install(entitlement_fixture::report_proof(now, 1, false, false), now)
            .unwrap();
        let access = NativeReportFeatureAccessV1(runtime.clone());
        assert_eq!(
            access.with_access(Box::new(|| Err(Error::ByteLimit))),
            Err(Error::ByteLimit)
        );
        source.fail.store(true, Ordering::Release);
        assert!(runtime
            .install(entitlement_fixture::report_proof(now, 2, false, false), now)
            .is_err());
        let mut called = false;
        assert_eq!(
            access.with_access(Box::new(|| {
                called = true;
                Ok(())
            })),
            Err(Error::EntitlementUnavailable)
        );
        assert!(!called);
        assert_eq!(
            source
                .inner
                .proof
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .revocations
                .as_ref()
                .unwrap()
                .sequence,
            1
        );
    }
    #[test]
    fn report_runtime_preview_replacement_expiry_and_commit_use_only_captured_payload() {
        let (store, runtime) = fixture();
        let coordinator = ReportCoordinatorV1::new(store.clone(), runtime);
        let package = |id: &str| {
            serde_json::from_value(json!({"schema_version":1,"templates":[],"rule_packs":[],"category_sets":[{"id":id,"name":id,"classes":[]}]})).unwrap()
        };
        let first = coordinator.preview_import(package("first")).unwrap();
        let second = coordinator.preview_import(package("second")).unwrap();
        assert_eq!(
            coordinator
                .commit_import(ReportImportCommitRequestV1 {
                    schema_version: 1,
                    preview_id: first.preview_id,
                    accept: true
                })
                .err(),
            Some(Error::StaleConfiguration)
        );
        let committed = coordinator
            .commit_import(ReportImportCommitRequestV1 {
                schema_version: 1,
                preview_id: second.preview_id,
                accept: true,
            })
            .unwrap();
        assert_eq!(store.report_library().unwrap(), committed);
        let sets: Value =
            serde_json::from_str(&store.get_key_value("settings.category_sets").unwrap()).unwrap();
        assert!(sets
            .as_array()
            .unwrap()
            .iter()
            .any(|set| set["id"] == second.mappings[0].to_id));
        let third = coordinator.preview_import(package("third")).unwrap();
        let before = store.get_key_values("%").unwrap();
        coordinator
            .state
            .lock()
            .unwrap()
            .preview
            .as_mut()
            .unwrap()
            .0 -= RETENTION;
        assert_eq!(
            coordinator
                .commit_import(ReportImportCommitRequestV1 {
                    schema_version: 1,
                    preview_id: third.preview_id,
                    accept: true
                })
                .err(),
            Some(Error::StaleConfiguration)
        );
        assert_eq!(store.get_key_values("%").unwrap(), before);
    }
    #[test]
    fn report_runtime_serialization_shares_the_input_and_calculation_budget() {
        let (store, runtime) = fixture();
        let control = Arc::new(QueryControl::managed());
        let snapshot = store
            .read_report_inputs(
                request(),
                control.clone(),
                Arc::new(NativeReportFeatureAccessV1(runtime)),
            )
            .unwrap();
        let calculated = aw_query::reports::calculate_report(&snapshot, &control).unwrap();
        let mut status = ReportRunStatusV1 {
            schema_version: 1,
            run_id: "a".repeat(32),
            state: ReportRunStateV1::Complete,
            queue_wait_ms: Some(0),
            execution_ms: Some(0),
            reason: None,
            result: Some(calculated.completed),
        };
        encode(&status, Some(&control), 32 * 1024 * 1024).unwrap();
        status.result.as_mut().unwrap().raw_events = Some(calculated.raw_periods);
        control
            .charge_bytes(QueryLimits::MANAGED.max_bytes - control.stats().bytes - 100)
            .unwrap();
        assert_eq!(
            encode(&status, Some(&control), 32 * 1024 * 1024).err(),
            Some(Error::ByteLimit)
        );
    }
    #[test]
    fn report_runtime_terminal_expiry_replacement_and_panic_never_reuse_raw_or_capacity() {
        let (store, runtime) = fixture();
        let coordinator = ReportCoordinatorV1::new(store, runtime);
        let old = coordinator.start(request()).unwrap();
        terminal(&coordinator, &old);
        let new = coordinator.start(request()).unwrap();
        terminal(&coordinator, &new);
        assert_eq!(
            read(&coordinator, &old).err(),
            Some(Error::SourceUnavailable)
        );
        coordinator
            .state
            .lock()
            .unwrap()
            .terminal
            .as_mut()
            .unwrap()
            .finished -= RETENTION;
        assert_eq!(
            read(&coordinator, &new).err(),
            Some(Error::SourceUnavailable)
        );
        let (store, runtime) = fixture();
        let (access, reached, resume) =
            gate(Arc::new(NativeReportFeatureAccessV1(runtime)), 2, true);
        let coordinator = ReportCoordinatorV1::build(store.clone(), access);
        let start = coordinator.start(request()).unwrap();
        reached.recv_timeout(Duration::from_secs(5)).unwrap();
        resume.send(()).unwrap();
        let status = terminal(&coordinator, &start);
        assert_eq!(status["state"], "failed");
        assert_eq!(status["reason"], "internal-error");
        assert_eq!(status["result"], Value::Null);
        assert!(coordinator.state.lock().unwrap().active.is_none());
        assert!(store.get_buckets().is_ok());
    }
}
