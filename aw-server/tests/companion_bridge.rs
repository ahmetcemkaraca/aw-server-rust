#![cfg(feature = "companion")]

use aw_server::companion::{
    peakactivity_companion_close, peakactivity_companion_invoke, peakactivity_companion_open,
    peakactivity_companion_open_with_release_trust, peakactivity_companion_response_free,
};

#[test]
fn release_trust_is_constructor_only_and_invalid_resources_never_create_a_vault() {
    let root = directory();
    let path = root.join("sync.db").to_string_lossy().into_owned();
    let key = [0xA1; 32];
    unsafe {
        for bytes in [
            b"{}".as_slice(),
            b"not-json",
            br#"{"schema_version":2,"keys":[]}"#,
            br#"{"schema_version":1,"keys":[],"url":"https://untrusted.example.invalid"}"#,
        ] {
            assert_eq!(
                peakactivity_companion_open_with_release_trust(
                    path.as_ptr(),
                    path.len(),
                    key.as_ptr(),
                    key.len(),
                    bytes.as_ptr(),
                    bytes.len()
                ),
                0
            );
            assert!(!root.join("sync.db").exists());
        }
        assert_eq!(
            peakactivity_companion_open_with_release_trust(
                path.as_ptr(),
                path.len(),
                key.as_ptr(),
                key.len(),
                std::ptr::null(),
                1
            ),
            0
        );
        let bytes = serde_json::to_vec(&json!({"schema_version":1,"keys":[{
            "id":"synthetic-release", "ed25519_public_key":vec![0xA2;32],
        }]}))
        .unwrap();
        let handle = peakactivity_companion_open_with_release_trust(
            path.as_ptr(),
            path.len(),
            key.as_ptr(),
            key.len(),
            bytes.as_ptr(),
            bytes.len(),
        );
        assert_ne!(handle, 0);
        let status = invoke(handle, "sync_network_status", json!({}));
        assert_eq!(
            status["result"]["egress"]["trusted_policy_keys"], 1,
            "{status}"
        );
        assert_eq!(status["result"]["sync"]["enabled"], false);
        assert!(invoke(handle, "set_release_trust", json!({"keys":[]}))["error"].is_string());
        assert!(invoke(handle, "sync_network_status", json!({"keys":[]}))["error"].is_string());
        assert!(peakactivity_companion_close(handle));
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn native_snapshot_restore_uses_a_fresh_paused_vault_and_preserves_sync_continuity() {
    let root = directory();
    let source = root.join("source.db").to_string_lossy().into_owned();
    let target = root.join("target.db").to_string_lossy().into_owned();
    let key = [0x91; 32];
    unsafe {
        let sender =
            peakactivity_companion_open(source.as_ptr(), source.len(), key.as_ptr(), key.len());
        let recipient =
            peakactivity_companion_open(target.as_ptr(), target.len(), key.as_ptr(), key.len());
        assert_ne!(sender, 0);
        assert_ne!(recipient, 0);
        assert!(
            invoke(recipient, "create_local_sync_identity", json!({}))["result"]["device_id"]
                .is_string()
        );
        let kit = invoke(sender, "create_sync_recovery_kit", json!({}))["result"].clone();
        assert!(kit["kit"].is_object());
        assert!(invoke(
            sender,
            "confirm_sync_recovery_saved",
            json!({"userConfirmed":true})
        )["error"]
            .is_null());
        invoke(
            sender,
            "set_manual_report_sharing",
            json!({"enabled":true,"userConfirmed":true}),
        );
        let projected = invoke(
            sender,
            "reconcile_manual_entries",
            json!({"entries":[{
                "id":"00112233-4455-6677-8899-aabbccddeeff", "timestamp":"2026-10-12T12:00:00Z", "duration_seconds":600,
            }]}),
        );
        assert_eq!(projected["result"]["inserted"], 1, "{projected}");
        let created = invoke(sender, "create_current_sync_snapshot", json!({}));
        assert!(created["error"].is_null(), "{created}");
        let snapshot = invoke(sender, "export_sync_snapshot", json!({}))["result"].clone();
        assert!(snapshot["envelopes"].is_array());
        let mut args =
            json!({"kit":kit["kit"],"recoveryPhrase":kit["recovery_phrase"],"snapshot":snapshot});
        let preview = invoke(recipient, "preview_sync_recovery_restore", args.clone());
        assert!(preview["result"]["snapshot_id"].is_string(), "{preview}");
        assert!(invoke(recipient, "restore_sync_recovery_kit", args.clone())["error"].is_string());
        args["userAccepted"] = json!(true);
        let restored = invoke(recipient, "restore_sync_recovery_kit", args.clone());
        assert_eq!(restored["result"], preview["result"], "{restored}");
        let report = invoke(
            recipient,
            "synced_manual_report",
            json!({"start":"2026-10-12T00:00:00Z","end":"2026-10-13T00:00:00Z"}),
        );
        assert_eq!(report["result"]["total_duration_seconds"], 600, "{report}");
        invoke(
            recipient,
            "set_manual_report_sharing",
            json!({"enabled":true,"userConfirmed":true}),
        );
        let empty_local = invoke(recipient, "reconcile_manual_entries", json!({"entries":[]}));
        assert_eq!(empty_local["result"]["deleted"], 0, "{empty_local}");
        let retained = invoke(
            recipient,
            "synced_manual_report",
            json!({"start":"2026-10-12T00:00:00Z","end":"2026-10-13T00:00:00Z"}),
        );
        assert_eq!(
            retained["result"]["total_duration_seconds"], 600,
            "{retained}"
        );
        assert!(invoke(recipient, "restore_sync_recovery_kit", args)["error"].is_string());
        assert_eq!(
            invoke(recipient, "sync_enabled", json!({}))["result"],
            false
        );
        assert!(invoke(recipient, "create_current_sync_snapshot", json!({}))["error"].is_string());
        assert!(invoke(
            recipient,
            "confirm_sync_recovery_saved",
            json!({"userConfirmed":true})
        )["error"]
            .is_null());
        assert!(
            invoke(recipient, "create_current_sync_snapshot", json!({}))["result"]["snapshot_id"]
                .is_string()
        );
        assert!(peakactivity_companion_close(sender));
        assert!(peakactivity_companion_close(recipient));
    }
    fs::remove_dir_all(root).unwrap();
}
use serde_json::{json, Value};
use std::ffi::CStr;
use std::fs;
use std::path::PathBuf;

fn directory() -> PathBuf {
    let root =
        std::env::temp_dir().join(format!("peakactivity-companion-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&root).unwrap();
    root
}

unsafe fn invoke(handle: u64, command: &str, arguments: Value) -> Value {
    let request = serde_json::to_vec(&json!({"command": command, "arguments": arguments})).unwrap();
    let pointer = peakactivity_companion_invoke(handle, request.as_ptr(), request.len());
    assert!(!pointer.is_null());
    let response = serde_json::from_slice(CStr::from_ptr(pointer).to_bytes()).unwrap();
    peakactivity_companion_response_free(pointer);
    response
}

mod entitlement_tests {
    use super::*;
    use aw_entitlements::{EntitlementSourceV1, MAX_STORED_ENTITLEMENT_BYTES_V1};
    use aw_server::companion::{
        peakactivity_companion_open_with_security, CompanionEntitlementCallbacksV1,
    };
    use ring::signature::KeyPair;
    use std::{
        ffi::c_void,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
    };
    mod fixture {
        include!("support/entitlement.rs");
    }

    struct Context {
        source: Arc<fixture::MemorySource>,
        released: Arc<AtomicUsize>,
        failure: u8,
    }
    unsafe extern "C" fn load(
        context: *mut c_void,
        output: *mut u8,
        capacity: usize,
        length: *mut usize,
    ) -> i32 {
        let context = &*(context as *const Context);
        if context.failure == 1 {
            *length = capacity + 1;
            return 0;
        }
        let Some(proof) = context.source.load().unwrap() else {
            *length = 0;
            return 1;
        };
        let bytes = serde_json::to_vec(&proof).unwrap();
        if bytes.len() > capacity {
            return -1;
        }
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), output, bytes.len());
        *length = bytes.len();
        0
    }
    unsafe extern "C" fn save(context: *mut c_void, input: *const u8, length: usize) -> i32 {
        let context = &*(context as *const Context);
        if context.failure == 2 || length > MAX_STORED_ENTITLEMENT_BYTES_V1 {
            return -1;
        }
        match serde_json::from_slice(std::slice::from_raw_parts(input, length)) {
            Ok(proof) => {
                if context.source.save(&proof).is_ok() {
                    0
                } else {
                    -1
                }
            }
            Err(_) => -1,
        }
    }
    unsafe extern "C" fn floor(
        context: *mut c_void,
        input: *const u8,
        length: usize,
        sequence: *mut u64,
    ) -> i32 {
        let context = &*(context as *const Context);
        if context.failure == 3 {
            return -1;
        }
        let Ok(scope) = std::str::from_utf8(std::slice::from_raw_parts(input, length)) else {
            return -1;
        };
        match context.source.revocation_floor(scope) {
            Ok(value) => {
                *sequence = value;
                0
            }
            Err(_) => -1,
        }
    }
    unsafe extern "C" fn advance(
        context: *mut c_void,
        input: *const u8,
        length: usize,
        sequence: u64,
    ) -> i32 {
        let context = &*(context as *const Context);
        let Ok(scope) = std::str::from_utf8(std::slice::from_raw_parts(input, length)) else {
            return -1;
        };
        if context
            .source
            .advance_revocation_floor(scope, sequence)
            .is_ok()
        {
            0
        } else {
            -1
        }
    }
    unsafe extern "C" fn release(context: *mut c_void) {
        let context = Box::from_raw(context as *mut Context);
        context.released.fetch_add(1, Ordering::SeqCst);
    }
    fn callbacks(
        source: Arc<fixture::MemorySource>,
        released: Arc<AtomicUsize>,
        failure: u8,
    ) -> CompanionEntitlementCallbacksV1 {
        CompanionEntitlementCallbacksV1 {
            context: Box::into_raw(Box::new(Context {
                source,
                released,
                failure,
            })) as *mut c_void,
            load: Some(load),
            save: Some(save),
            floor: Some(floor),
            advance: Some(advance),
            release: Some(release),
        }
    }
    fn trust() -> Vec<u8> {
        serde_json::to_vec(&json!({"schema_version":1,"keys":[{
            "id":fixture::KEY_ID,"ed25519_public_key":fixture::key().public_key().as_ref(),
        }],"minimum_revocation_sequence":1}))
        .unwrap()
    }

    #[test]
    fn native_entitlement_callback_context_is_released_once_even_on_failed_open() {
        let released = Arc::new(AtomicUsize::new(0));
        unsafe {
            assert_eq!(
                peakactivity_companion_open_with_security(
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    0,
                    callbacks(
                        Arc::new(fixture::MemorySource::default()),
                        released.clone(),
                        0
                    ),
                ),
                0
            );
        }
        assert_eq!(released.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn native_entitlement_import_uses_separate_callbacks_and_revocation_closes_paid_access() {
        let root = directory();
        let path = root.join("entitlement.db").to_string_lossy().into_owned();
        let key = [0xD1; 32];
        let source = Arc::new(fixture::MemorySource::default());
        let released = Arc::new(AtomicUsize::new(0));
        let trust = trust();
        let now = fixture::aw_server_time();
        let proof = fixture::proof(now, 1, false);
        unsafe {
            let handle = peakactivity_companion_open_with_security(
                path.as_ptr(),
                path.len(),
                key.as_ptr(),
                key.len(),
                std::ptr::null(),
                0,
                trust.as_ptr(),
                trust.len(),
                callbacks(source.clone(), released.clone(), 0),
            );
            assert_ne!(handle, 0);
            assert_eq!(released.load(Ordering::SeqCst), 0);
            assert!(invoke(handle, "entitlement_status", json!({}))["result"].is_null());
            let status = invoke(handle, "import_entitlement", json!({"proof":proof}));
            assert_eq!(status["result"]["sync_allowed"], true, "{status}");
            assert_eq!(status["result"].as_object().unwrap().len(), 6);
            assert!(!status
                .to_string()
                .contains(&proof.entitlement.payload.claims.account_id));
            assert!(!status
                .to_string()
                .contains(&proof.entitlement.payload.claims.entitlement_id));
            assert_eq!(*source.floor.lock().unwrap(), 1);
            assert!(invoke(
                handle,
                "import_entitlement",
                json!({"proof":proof,"keys":[]})
            )["error"]
                .is_string());
            let revoked = fixture::proof(now, 2, true);
            assert!(
                invoke(handle, "import_entitlement", json!({"proof":revoked}))["error"].is_string()
            );
            assert_eq!(*source.floor.lock().unwrap(), 2);
            assert!(invoke(handle, "entitlement_status", json!({}))["error"].is_string());
            assert!(
                invoke(handle, "import_entitlement", json!({"proof":proof}))["error"].is_string()
            );
            assert!(invoke(
                handle,
                "set_sync_enabled",
                json!({"enabled":true,"userConfirmed":true,
                "destination_id":"relay","purpose_id":"sync-object-v1"})
            )["error"]
                .is_string());
            assert!(
                invoke(handle, "create_local_sync_identity", json!({}))["result"]["device_id"]
                    .is_string()
            );
            assert!(
                invoke(handle, "create_sync_recovery_kit", json!({}))["result"]["kit"].is_object()
            );
            assert!(peakactivity_companion_close(handle));
        }
        assert_eq!(released.load(Ordering::SeqCst), 1);
        let store = aw_datastore::Datastore::open_encrypted(path.clone(), "d1".repeat(32)).unwrap();
        let activity = serde_json::to_string(&store.get_buckets().unwrap()).unwrap();
        let metadata = serde_json::to_string(&store.get_key_values("%").unwrap()).unwrap();
        for id in [
            &proof.entitlement.payload.claims.account_id,
            &proof.entitlement.payload.claims.entitlement_id,
        ] {
            assert!(!activity.contains(id));
            assert!(!metadata.contains(id));
        }
        store.lock().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn native_entitlement_invalid_trust_closes_paid_work_and_preserves_local_vault() {
        let root = directory();
        let key = [0xD2; 32];
        for (index, bytes) in [
            b"{}".as_slice(),
            br#"{"schema_version":2,"keys":[],"minimum_revocation_sequence":0}"#,
            b"",
        ]
        .into_iter()
        .enumerate()
        {
            let path = root
                .join(format!("invalid-{index}.db"))
                .to_string_lossy()
                .into_owned();
            let released = Arc::new(AtomicUsize::new(0));
            unsafe {
                let handle = peakactivity_companion_open_with_security(
                    path.as_ptr(),
                    path.len(),
                    key.as_ptr(),
                    key.len(),
                    std::ptr::null(),
                    0,
                    bytes.as_ptr(),
                    bytes.len(),
                    callbacks(
                        Arc::new(fixture::MemorySource::default()),
                        released.clone(),
                        0,
                    ),
                );
                assert_ne!(handle, 0);
                assert_eq!(released.load(Ordering::SeqCst), 1);
                assert!(invoke(
                    handle,
                    "import_entitlement",
                    json!({"proof":fixture::proof(fixture::aw_server_time(),1,false)})
                )["error"]
                    .is_string());
                assert!(
                    invoke(handle, "create_local_sync_identity", json!({}))["result"]["device_id"]
                        .is_string()
                );
                assert!(peakactivity_companion_close(handle));
            }
            assert_eq!(released.load(Ordering::SeqCst), 1);
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn native_entitlement_callback_bounds_and_store_failures_keep_local_work_available() {
        let root = directory();
        let trust = trust();
        let key = [0xD3; 32];
        for failure in 1..=3 {
            let path = root
                .join(format!("callback-{failure}.db"))
                .to_string_lossy()
                .into_owned();
            let released = Arc::new(AtomicUsize::new(0));
            unsafe {
                let handle = peakactivity_companion_open_with_security(
                    path.as_ptr(),
                    path.len(),
                    key.as_ptr(),
                    key.len(),
                    std::ptr::null(),
                    0,
                    trust.as_ptr(),
                    trust.len(),
                    callbacks(
                        Arc::new(fixture::MemorySource::default()),
                        released.clone(),
                        failure,
                    ),
                );
                assert_ne!(handle, 0);
                assert!(invoke(
                    handle,
                    "import_entitlement",
                    json!({"proof":fixture::proof(fixture::aw_server_time(),1,false)})
                )["error"]
                    .is_string());
                assert!(
                    invoke(handle, "create_local_sync_identity", json!({}))["result"]["device_id"]
                        .is_string()
                );
                assert!(peakactivity_companion_close(handle));
            }
            assert_eq!(released.load(Ordering::SeqCst), 1);
        }
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn native_bridge_preserves_encrypted_identity_and_rejects_missing_or_wrong_keys() {
    let root = directory();
    let path = root.join("sync.db").to_string_lossy().into_owned();
    let key = [0x51; 32];
    unsafe {
        assert!(peakactivity_companion_open(path.as_ptr(), path.len(), key.as_ptr(), 31) == 0);
        assert!(!root.join("sync.db").exists());
        let handle =
            peakactivity_companion_open(path.as_ptr(), path.len(), key.as_ptr(), key.len());
        assert!(handle != 0);
        let identity = invoke(handle, "create_local_sync_identity", json!({}));
        assert!(identity["result"]["device_id"].is_string());
        assert_eq!(invoke(handle, "sync_enabled", json!({}))["result"], false);
        assert!(invoke(handle, "set_sync_enabled", json!({"enabled":true}))["error"].is_string());
        assert!(peakactivity_companion_close(handle));
        assert!(!peakactivity_companion_close(handle));
        assert!(invoke(handle, "sync_enabled", json!({}))["error"].is_string());
        assert!(!fs::read(root.join("sync.db"))
            .unwrap()
            .starts_with(b"SQLite format 3"));
        let wrong = [0x52; 32];
        assert!(
            peakactivity_companion_open(path.as_ptr(), path.len(), wrong.as_ptr(), wrong.len())
                == 0
        );
        let reopened =
            peakactivity_companion_open(path.as_ptr(), path.len(), key.as_ptr(), key.len());
        assert!(reopened != 0);
        assert_eq!(
            invoke(reopened, "create_local_sync_identity", json!({})),
            identity
        );
        peakactivity_companion_close(reopened);
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn native_bridge_uses_shared_recovery_crypto_and_bounds_untrusted_requests() {
    let root = directory();
    let path = root.join("sync.db").to_string_lossy().into_owned();
    let key = [0x61; 32];
    unsafe {
        let handle =
            peakactivity_companion_open(path.as_ptr(), path.len(), key.as_ptr(), key.len());
        assert!(handle != 0);
        let kit = invoke(handle, "create_sync_recovery_kit", json!({}));
        let displayed = kit.get("result").expect("shared recovery display");
        let verified = invoke(
            handle,
            "verify_sync_recovery_kit",
            json!({
                "kit": displayed["kit"], "recoveryPhrase": displayed["recovery_phrase"],
            }),
        );
        assert!(verified["result"]["vault_id"].is_string());
        let decoded: aw_sync_e2ee::RecoveryKitV1 =
            serde_json::from_value(displayed["kit"].clone()).unwrap();
        let recovered = aw_sync_e2ee::open_recovery_kit(
            &decoded,
            displayed["recovery_phrase"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(
            verified["result"]["vault_id"],
            recovered.wrapped_vault_key.vault_id
        );
        assert!(invoke(
            handle,
            "verify_sync_recovery_kit",
            json!({
                "kit": displayed["kit"], "recoveryPhrase":"invalid recovery phrase",
            })
        )["error"]
            .is_string());
        for request in [
            b"not-json".as_slice(),
            b"\xff",
            br#"{"command":"sync_enabled","arguments":{},"unexpected":true}"#,
        ] {
            let pointer = peakactivity_companion_invoke(handle, request.as_ptr(), request.len());
            assert!(!pointer.is_null());
            let response: Value =
                serde_json::from_slice(CStr::from_ptr(pointer).to_bytes()).unwrap();
            assert!(response["error"].is_string());
            peakactivity_companion_response_free(pointer);
        }
        let pointer = peakactivity_companion_invoke(handle, std::ptr::null(), usize::MAX);
        assert!(!pointer.is_null());
        assert!(CStr::from_ptr(pointer).to_str().unwrap().contains("error"));
        peakactivity_companion_response_free(pointer);
        peakactivity_companion_response_free(std::ptr::null_mut());
        peakactivity_companion_close(handle);
        assert!(!peakactivity_companion_close(0));
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn native_bridge_preserves_orphan_sidecars_and_rejects_nonregular_or_linked_vaults() {
    let root = directory();
    let path = root.join("sync.db").to_string_lossy().into_owned();
    let key = [0x71; 32];
    for suffix in ["-wal", "-shm", "-journal"] {
        let sidecar = root.join(format!("sync.db{suffix}"));
        fs::write(&sidecar, b"preserved recovery bytes").unwrap();
        unsafe {
            assert_eq!(
                peakactivity_companion_open(path.as_ptr(), path.len(), key.as_ptr(), key.len()),
                0
            );
        }
        assert!(!root.join("sync.db").exists());
        assert_eq!(fs::read(&sidecar).unwrap(), b"preserved recovery bytes");
        fs::remove_file(sidecar).unwrap();
    }
    fs::create_dir(root.join("sync.db")).unwrap();
    unsafe {
        assert_eq!(
            peakactivity_companion_open(path.as_ptr(), path.len(), key.as_ptr(), key.len()),
            0
        );
    }
    fs::remove_dir(root.join("sync.db")).unwrap();
    #[cfg(unix)]
    {
        let original = root.join("preserve.bin");
        fs::write(&original, b"preserved original").unwrap();
        std::os::unix::fs::symlink(&original, root.join("sync.db")).unwrap();
        unsafe {
            assert_eq!(
                peakactivity_companion_open(path.as_ptr(), path.len(), key.as_ptr(), key.len()),
                0
            );
        }
        assert_eq!(fs::read(original).unwrap(), b"preserved original");
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn manual_sharing_requires_explicit_consent_and_projects_only_dates_and_durations() {
    let root = directory();
    let path = root.join("sync.db").to_string_lossy().into_owned();
    let key = [0x81; 32];
    let id = "00112233-4455-6677-8899-aabbccddeeff";
    let timestamp = "2026-10-12T12:00:00Z";
    unsafe {
        let handle =
            peakactivity_companion_open(path.as_ptr(), path.len(), key.as_ptr(), key.len());
        assert_ne!(handle, 0);
        assert_eq!(
            invoke(handle, "manual_report_sharing", json!({}))["result"],
            false
        );
        let entries = json!({"entries":[{"id":id,"timestamp":timestamp,"duration_seconds":600}]});
        assert!(invoke(handle, "reconcile_manual_entries", entries.clone())["error"].is_string());
        assert!(invoke(
            handle,
            "set_manual_report_sharing",
            json!({"enabled":true,"userConfirmed":false})
        )["error"]
            .is_string());
        assert!(invoke(
            handle,
            "set_manual_report_sharing",
            json!({"enabled":true,"userConfirmed":true,"note":"local only"})
        )["error"]
            .is_string());
        assert_eq!(
            invoke(
                handle,
                "set_manual_report_sharing",
                json!({"enabled":true,"userConfirmed":true})
            )["result"],
            true
        );
        let projected = invoke(handle, "reconcile_manual_entries", entries.clone());
        assert_eq!(projected["result"]["inserted"], 1, "{projected}");
        let again = invoke(handle, "reconcile_manual_entries", entries);
        assert_eq!(again["result"]["inserted"], 0);
        assert_eq!(again["result"]["corrected"], 0);
        assert!(invoke(
            handle,
            "reconcile_manual_entries",
            json!({"entries":[{
                "id":id,"timestamp":timestamp,"duration_seconds":600,"note":"local only",
            }]})
        )["error"]
            .is_string());
        let report = invoke(
            handle,
            "synced_manual_report",
            json!({"start":"2026-10-12T00:00:00Z","end":"2026-10-13T00:00:00Z","exclude_entry_ids":[id]}),
        );
        assert_eq!(
            report["result"]["entry_count"], 0,
            "local AES entries already appear in the local report"
        );
        assert_eq!(invoke(handle, "sync_enabled", json!({}))["result"], false);
        assert!(peakactivity_companion_close(handle));
        let reopened =
            peakactivity_companion_open(path.as_ptr(), path.len(), key.as_ptr(), key.len());
        assert_eq!(
            invoke(reopened, "manual_report_sharing", json!({}))["result"],
            true
        );
        assert!(peakactivity_companion_close(reopened));
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn incoming_manual_report_is_bounded_aggregate_and_never_returns_private_notes() {
    use aw_datastore::Datastore;
    use aw_models::{Bucket, BucketMetadata, Event};
    use chrono::{DateTime, Duration, Utc};
    let root = directory();
    let path = root.join("sync.db").to_string_lossy().into_owned();
    let key = [0x91; 32];
    unsafe {
        let handle =
            peakactivity_companion_open(path.as_ptr(), path.len(), key.as_ptr(), key.len());
        assert!(peakactivity_companion_close(handle));
    }
    let store = Datastore::open_encrypted(path.clone(), "91".repeat(32)).unwrap();
    let timestamp: DateTime<Utc> = "2026-10-12T12:00:00Z".parse().unwrap();
    for (id, kind, duration) in [
        ("aw-sync-opaque-peer", "general.stopwatch", 600),
        ("aw-sync-opaque-window", "currentwindow", 500),
    ] {
        store
            .create_bucket(&Bucket {
                bid: None,
                id: id.into(),
                _type: kind.into(),
                client: "paired-device".into(),
                hostname: "opaque".into(),
                created: None,
                data: Default::default(),
                metadata: BucketMetadata::default(),
                events: None,
                last_updated: None,
            })
            .unwrap();
        store
            .insert_events(
                id,
                &[Event::new(
                    timestamp,
                    Duration::seconds(duration),
                    json!({"label":"PRIVATE NOTE SENTINEL","running":false})
                        .as_object()
                        .unwrap()
                        .clone(),
                )],
            )
            .unwrap();
    }
    store.close();
    unsafe {
        let handle =
            peakactivity_companion_open(path.as_ptr(), path.len(), key.as_ptr(), key.len());
        let report = invoke(
            handle,
            "synced_manual_report",
            json!({"start":"2026-10-12T00:00:00Z","end":"2026-10-13T00:00:00Z"}),
        );
        assert_eq!(
            report["result"],
            json!({"entry_count":1,"total_duration_seconds":600})
        );
        assert!(!report.to_string().contains("PRIVATE NOTE SENTINEL"));
        assert!(invoke(
            handle,
            "synced_manual_report",
            json!({"start":"2026-10-13T00:00:00Z","end":"2026-10-12T00:00:00Z"})
        )["error"]
            .is_string());
        assert!(peakactivity_companion_close(handle));
    }
    fs::remove_dir_all(root).unwrap();
}
