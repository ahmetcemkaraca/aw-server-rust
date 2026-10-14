//! Companion binding; relay work uses shared privacy and separate signed-plan gates.
use crate::sync_control::SyncControl;
pub use crate::companion_entitlements::CompanionEntitlementCallbacksV1;
use aw_datastore::{Datastore, DatastoreError, ManualActivityEntryV1};
use aw_models::CapturePolicy;
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet};
use std::ffi::CString;
use std::fmt::Write;
use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Component, Path};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use zeroize::{Zeroize, Zeroizing};

const MAX_REQUEST_BYTES: usize = 16 * 1_048_576;
const MAX_PATH_BYTES: usize = 4096;
const MANUAL_SHARING_KEY: &str = "ios_manual_report_sharing_v1";
const MAX_REPORT_ENTRIES: usize = 10_000;
static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);
static CONTEXTS: LazyLock<Mutex<BTreeMap<u64, Arc<Companion>>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

struct Companion {
    store: Datastore,
    control: SyncControl,
    closing: AtomicBool,
    network: crate::companion_network::CompanionNetwork,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    command: String,
    arguments: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SharingRequest {
    enabled: bool,
    #[serde(default)]
    #[serde(rename = "userConfirmed")]
    user_confirmed: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManualSnapshotRequest {
    entries: Vec<ManualActivityEntryV1>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReportRequest {
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    #[serde(default)]
    exclude_entry_ids: Vec<String>,
}

fn manual_sharing(store: &Datastore) -> Result<bool, String> {
    match manual_sharing_value(store)?.as_deref() {
        None | Some("false") => Ok(false),
        Some("true") => Ok(true),
        _ => Err("The stored manual sharing consent is invalid".into()),
    }
}

fn manual_sharing_value(store: &Datastore) -> Result<Option<String>, String> {
    match store.get_key_value(MANUAL_SHARING_KEY) {
        Ok(value) => Ok(Some(value)),
        Err(DatastoreError::NoSuchKey(_)) => Ok(None),
        Err(_) => Err("The encrypted vault cannot read manual sharing consent".into()),
    }
}

fn incoming_manual_report(store: &Datastore, request: ReportRequest) -> Result<Value, String> {
    if request.end <= request.start
        || request.end - request.start > Duration::hours(48)
        || request.exclude_entry_ids.len() > MAX_REPORT_ENTRIES
    {
        return Err("The report interval or entry limit is invalid".into());
    }
    let exclude = request
        .exclude_entry_ids
        .iter()
        .map(|id| {
            CapturePolicy::canonical_manual_entry_id(id)
                .ok_or("The excluded manual entry ID is invalid")
        })
        .collect::<Result<HashSet<_>, _>>()?;
    let buckets = store
        .get_buckets()
        .map_err(|_| "The encrypted manual reports are unavailable")?;
    if buckets.len() > 256 {
        return Err("The report exceeds its bucket limit".into());
    }
    let mut scanned = 0usize;
    let mut count = 0u64;
    let mut seconds = 0u64;
    for bucket in buckets
        .values()
        .filter(|bucket| bucket._type == "general.stopwatch")
    {
        let remaining = MAX_REPORT_ENTRIES - scanned;
        let events = store
            .get_events_unclipped(
                &bucket.id,
                Some(request.start),
                Some(request.end),
                Some((remaining + 1) as u64),
            )
            .map_err(|_| "The encrypted manual reports are unavailable")?;
        scanned += events.len();
        if scanned > MAX_REPORT_ENTRIES {
            return Err("The report exceeds its entry limit".into());
        }
        for event in events {
            if event.timestamp < request.start
                || event.timestamp >= request.end
                || event.data.get("running").and_then(Value::as_bool) != Some(false)
            {
                continue;
            }
            if event
                .data
                .get("manual_entry_id")
                .and_then(Value::as_str)
                .is_some_and(|id| exclude.contains(id))
            {
                continue;
            }
            let duration = event.duration.num_seconds();
            if !(1..=86_400).contains(&duration) {
                continue;
            }
            count += 1;
            seconds += duration as u64;
        }
    }
    Ok(json!({"entry_count":count,"total_duration_seconds":seconds}))
}

fn invoke_local(context: &Companion, command: &str, args: Value) -> Result<Value, String> {
    match command {
        "manual_report_sharing" => manual_sharing(&context.store).map(Value::Bool),
        "set_manual_report_sharing" => {
            let request: SharingRequest =
                serde_json::from_value(args).map_err(|_| "Invalid manual sharing request")?;
            if request.enabled && !request.user_confirmed {
                return Err("Confirm manual dates and durations before sharing".into());
            }
            if !request.enabled {
                context.network.pause()?;
            }
            let current = manual_sharing_value(&context.store)?;
            let saved = context
                .store
                .compare_and_set_key_value(
                    MANUAL_SHARING_KEY,
                    current.as_deref(),
                    Some(if request.enabled { "true" } else { "false" }),
                )
                .map_err(|_| "The encrypted vault could not save manual sharing consent")?;
            if !saved {
                return Err("Manual sharing consent changed; review and try again".into());
            }
            Ok(Value::Bool(request.enabled))
        }
        "reconcile_manual_entries" => {
            if !manual_sharing(&context.store)? {
                return Err("Manual report sharing is Off".into());
            }
            let request: ManualSnapshotRequest =
                serde_json::from_value(args).map_err(|_| "Invalid manual activity snapshot")?;
            let result = context
                .store
                .reconcile_manual_entries(&request.entries)
                .map_err(|_| {
                    "Manual projection was not committed; local entries remain preserved"
                })?;
            serde_json::to_value(result)
                .map_err(|_| "Manual projection response is unavailable".into())
        }
        "synced_manual_report" => {
            let request: ReportRequest =
                serde_json::from_value(args).map_err(|_| "Invalid manual report request")?;
            incoming_manual_report(&context.store, request)
        }
        _ => match context.network.invoke(command, args.clone()) {
            Some(result) => result,
            None => context.control.invoke(&context.store, command, args),
        },
    }
}

fn checked_path(value: &str) -> Option<&Path> {
    let path = Path::new(value);
    if !path.is_absolute() || value.contains('\0') || !path.parent()?.is_dir() {
        return None;
    }
    let mut current = std::path::PathBuf::new();
    for part in path.components() {
        if matches!(part, Component::ParentDir | Component::CurDir) {
            return None;
        }
        current.push(part);
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.is_symlink() => return None,
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && current == path => {}
            Err(_) => return None,
        }
    }
    let exists = match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        _ => return None,
    };
    for suffix in ["-wal", "-shm", "-journal"] {
        match std::fs::symlink_metadata(format!("{value}{suffix}")) {
            Ok(metadata) if exists && metadata.is_file() => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return None,
        }
    }
    Some(path)
}

/// Buffers must be readable for their lengths. The key is exactly 32 bytes;
/// Swift owns its persistence and must not create it over an existing vault.
#[no_mangle]
pub unsafe extern "C" fn peakactivity_companion_open(
    path: *const u8,
    path_len: usize,
    key: *const u8,
    key_len: usize,
) -> u64 {
    peakactivity_companion_open_with_release_trust(
        path,
        path_len,
        key,
        key_len,
        std::ptr::null(),
        0,
    )
}

/// Trust bytes must come from the code-signed application resource, never a UI or
/// RPC argument. Malformed resources are rejected before opening the vault.
#[no_mangle]
pub unsafe extern "C" fn peakactivity_companion_open_with_release_trust(
    path: *const u8,
    path_len: usize,
    key: *const u8,
    key_len: usize,
    trust: *const u8,
    trust_len: usize,
) -> u64 {
    peakactivity_companion_open_with_security(path,path_len,key,key_len,trust,trust_len,
        std::ptr::null(),0,CompanionEntitlementCallbacksV1::default())
}

/// Callback context ownership transfers at entry, including failed opens. Callbacks
/// must be thread-safe. Invalid billing configuration closes paid work only.
#[no_mangle]
pub unsafe extern "C" fn peakactivity_companion_open_with_security(
    path:*const u8,path_len:usize,key:*const u8,key_len:usize,
    trust:*const u8,trust_len:usize,entitlement_trust:*const u8,entitlement_len:usize,
    callbacks:CompanionEntitlementCallbacksV1,
) -> u64 {
    let source=Arc::new(crate::companion_entitlements::CompanionEntitlementSource {callbacks});
    catch_unwind(AssertUnwindSafe(|| {
        if path.is_null()
            || key.is_null()
            || !(1..=MAX_PATH_BYTES).contains(&path_len)
            || key_len != 32
        {
            return 0;
        }
        if trust_len > crate::companion_release_trust::MAX_RELEASE_TRUST_BYTES
            || (trust_len != 0 && trust.is_null())
        {
            return 0;
        }
        let trust_bytes = if trust_len == 0 {
            &[]
        } else {
            std::slice::from_raw_parts(trust, trust_len)
        };
        let Ok(release_keys) = crate::companion_release_trust::parse_release_trust(trust_bytes)
        else {
            return 0;
        };
        let mut feature_access=Arc::default();
        if source.available() && entitlement_len<=16_384 && (entitlement_len==0 || !entitlement_trust.is_null()) {
            let bytes=if entitlement_len==0 {&[]} else {std::slice::from_raw_parts(entitlement_trust,entitlement_len)};
            if let Ok((keys,floor))=crate::feature_access::parse_release_entitlement_trust(bytes) {
                if !keys.is_empty() {
                    feature_access=Arc::new(aw_entitlements::RuntimeFeatureAccessV1::new(keys,floor,source.clone()));
                }
            }
        }
        let Ok(path) = std::str::from_utf8(std::slice::from_raw_parts(path, path_len)) else {
            return 0;
        };
        if checked_path(path).is_none() {
            return 0;
        }
        let mut secret = Zeroizing::new(String::with_capacity(64));
        for byte in std::slice::from_raw_parts(key, key_len) {
            if write!(&mut *secret, "{byte:02x}").is_err() {
                return 0;
            }
        }
        let Ok(store) = Datastore::open_encrypted(path.to_owned(), secret.to_string()) else {
            return 0;
        };
        // The companion has no recorder; shared restore still requires a valid paused policy.
        if !store
            .enable_capture_policy()
            .is_ok_and(|policy| !policy.recording)
        {
            store.close();
            return 0;
        }
        let Ok(handle) = NEXT_HANDLE.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
            value.checked_add(1)
        }) else {
            store.close();
            return 0;
        };
        let Ok(mut contexts) = CONTEXTS.lock() else {
            store.close();
            return 0;
        };
        contexts.insert(
            handle,
            Arc::new(Companion {
                network: crate::companion_network::CompanionNetwork::from_release_keys(
                    store.clone(),
                    release_keys,
                ).with_feature_access(feature_access),
                store,
                control: SyncControl::new(),
                closing: AtomicBool::new(false),
            }),
        );
        handle
    }))
    .unwrap_or(0)
}

/// The request buffer must be readable for its length. Free the returned string
/// exactly once with peakactivity_companion_response_free; it may hold a recovery phrase.
#[no_mangle]
pub unsafe extern "C" fn peakactivity_companion_invoke(
    handle: u64,
    bytes: *const u8,
    length: usize,
) -> *mut c_char {
    let result = catch_unwind(AssertUnwindSafe(|| -> Result<Value, String> {
        if bytes.is_null() || !(1..=MAX_REQUEST_BYTES).contains(&length) {
            return Err("The native request exceeds its limit or is missing".into());
        }
        let request: Request = serde_json::from_slice(std::slice::from_raw_parts(bytes, length))
            .map_err(|_| "The native request is invalid")?;
        if request.command.len() > 128 || !request.arguments.is_object() {
            return Err("The native request is invalid".into());
        }
        let contexts = CONTEXTS
            .lock()
            .map_err(|_| "The encrypted sync vault is unavailable")?;
        let context = contexts
            .get(&handle)
            .cloned()
            .ok_or("The encrypted sync vault is closed")?;
        drop(contexts);
        if context.closing.load(Ordering::Acquire) {
            return Err("The encrypted sync vault is closing".into());
        }
        invoke_local(&context, &request.command, request.arguments)
    }))
    .unwrap_or_else(|_| Err("The native operation could not be completed".into()));
    let response = match result {
        Ok(value) => json!({"result":value}),
        Err(error) => json!({"error":error}),
    };
    // JSON escapes NUL characters before crossing the C string boundary.
    CString::new(response.to_string())
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

/// Stale and repeated closes are rejected without dereferencing caller memory.
#[no_mangle]
pub extern "C" fn peakactivity_companion_close(handle: u64) -> bool {
    catch_unwind(AssertUnwindSafe(|| {
        let Ok(contexts) = CONTEXTS.lock() else {
            return false;
        };
        let Some(context) = contexts.get(&handle).cloned() else {
            return false;
        };
        drop(contexts);
        if context
            .closing
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        context.store.invalidate_report_runtime();
        if context.network.pause().is_err() {
            context.closing.store(false, Ordering::Release);
            return false;
        }
        if context.store.lock().is_err() {
            context.closing.store(false, Ordering::Release);
            return false;
        }
        let Ok(mut contexts) = CONTEXTS.lock() else {
            return false;
        };
        contexts.remove(&handle);
        true
    }))
    .unwrap_or(false)
}

/// Pause is separate from the serial Swift actor, so a whole relay cycle cannot
/// delay it. It waits for the current bounded request, then stops further sends.
#[no_mangle]
pub extern "C" fn peakactivity_companion_pause_sync(handle: u64) -> bool {
    catch_unwind(AssertUnwindSafe(|| {
        let context = match CONTEXTS.lock() {
            Ok(contexts) => contexts.get(&handle).cloned(),
            Err(_) => None,
        };
        context.is_some_and(|context| context.network.pause().is_ok())
    }))
    .unwrap_or(false)
}

/// Pass only a live result returned by peakactivity_companion_invoke, once.
#[no_mangle]
pub unsafe extern "C" fn peakactivity_companion_response_free(response: *mut c_char) {
    if !response.is_null() {
        let mut bytes = CString::from_raw(response).into_bytes_with_nul();
        bytes.zeroize();
    }
}
