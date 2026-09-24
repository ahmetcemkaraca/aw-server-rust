// Based On the following guide from Mozilla:
//   https://mozilla.github.io/firefox-browser-architecture/experiments/2017-09-21-rust-on-android.html

extern crate android_logger;

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use crate::device_id;
use crate::dirs;

use android_logger::Config;
use rocket::serde::json::json;

#[no_mangle]
pub extern "C" fn rust_greeting(to: *const c_char) -> *mut c_char {
    let c_str = unsafe { CStr::from_ptr(to) };
    let recipient = match c_str.to_str() {
        Err(_) => "there",
        Ok(string) => string,
    };

    CString::new("Hello ".to_owned() + recipient + " (from Rust!)")
        .unwrap()
        .into_raw()
}

#[cfg(target_os = "android")]
#[allow(non_snake_case)]
pub mod android {
    extern crate jni;

    use self::jni::objects::{JByteArray, JClass, JString};
    use self::jni::sys::{jboolean, jdouble, jint, jstring, JNI_FALSE, JNI_TRUE};
    use self::jni::JNIEnv;
    use super::*;

    use std::fmt::Write;
    use std::path::PathBuf;
    use std::sync::Mutex;
    use zeroize::Zeroizing;
    use crate::sessions::{Scope, Sessions};

    use crate::endpoints;
    use crate::endpoints::ServerState;
    use aw_client_rust::blocking::AwClient;
    use aw_client_rust::classes::default_classes;
    use aw_client_rust::classes::{CategoryId, CategorySpec};
    use aw_client_rust::queries::{
        build_android_canonical_events, AndroidQueryParams, QueryParamsBase,
    };
    use aw_datastore::Datastore;
    use aw_models::{Bucket, Event, TimeInterval};

    static DATASTORE: Mutex<Option<Datastore>> = Mutex::new(None);
    static VAULT_KEY: Mutex<Option<Zeroizing<[u8; 32]>>> = Mutex::new(None);
    static LOCAL_SESSIONS: Mutex<Option<Sessions>> = Mutex::new(None);
    static SYNC_CONTROL: crate::sync_control::SyncControl = crate::sync_control::SyncControl::new();

    fn local_sessions() -> Sessions {
        let mut sessions = LOCAL_SESSIONS.lock().expect("local session store unavailable");
        sessions.get_or_insert_with(|| Sessions::new(5600, false)).clone()
    }

    fn key_as_hex(key: &[u8; 32]) -> String {
        let mut hex = String::with_capacity(64);
        for byte in key {
            write!(&mut hex, "{byte:02x}").expect("writing to a String cannot fail");
        }
        hex
    }

    fn openDatastore() -> Result<Datastore, String> {
        let mut stored_datastore = DATASTORE.lock().map_err(|_| "vault state unavailable".to_string())?;
        if let Some(datastore) = stored_datastore.as_ref() {
            return Ok(datastore.clone());
        }
        let stored_key = VAULT_KEY.lock().map_err(|_| "vault state unavailable".to_string())?;
        let key = stored_key.as_ref().ok_or_else(|| "vault key unavailable".to_string())?;
        let db_dir = dirs::db_path(false)
            .map_err(|_| "vault path unavailable".to_string())?
            .to_str()
            .ok_or_else(|| "vault path is not valid UTF-8".to_string())?
            .to_string();
        let datastore = Datastore::open_encrypted(db_dir, key_as_hex(&**key))
            .map_err(|_| "encrypted vault could not be opened".to_string())?;
        *stored_datastore = Some(datastore.clone());
        Ok(datastore)
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_activitywatch_android_RustInterface_greeting(
        env: JNIEnv,
        _: JClass,
        java_pattern: JString,
    ) -> jstring {
        // Our Java companion code might pass-in "world" as a string, hence the name.
        let world = rust_greeting(
            env.get_string(java_pattern)
                .expect("invalid pattern string")
                .as_ptr(),
        );
        // Retake pointer so that we can use it below and allow memory to be freed when it goes out of scope.
        let world_ptr = CString::from_raw(world);
        let output = env
            .new_string(world_ptr.to_str().unwrap())
            .expect("Couldn't create java string!");

        output.into_raw()
    }

    unsafe fn jstring_to_string(env: &JNIEnv, string: JString) -> String {
        let jstr = env.get_string(string).expect("Failed to get Java string");
        jstr.into()
    }

    unsafe fn string_to_jstring(env: &JNIEnv, string: String) -> jstring {
        env.new_string(string)
            .expect("Couldn't create java string")
            .into_raw()
    }

    unsafe fn create_error_object(env: &JNIEnv, msg: String) -> jstring {
        let obj = json!({ "error": &msg });
        string_to_jstring(&env, obj.to_string())
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_activitywatch_android_RustInterface_startServer(
        env: JNIEnv,
        _: JClass,
    ) {
        info!("Starting server...");
        start_server();
        info!("Server exited");
    }

    #[rocket::main]
    async fn start_server() {
        info!("Building server state...");

        // FIXME: Why is unsafe needed here? Can we get rid of it?
        let datastore = match openDatastore() {
            Ok(datastore) => datastore,
            Err(_) => {
                error!("Encrypted vault unavailable; server startup stopped");
                return;
            }
        };
        unsafe {
            let server_state: ServerState = endpoints::ServerState {
                datastore,
                asset_resolver: endpoints::AssetResolver::new(None),
                device_id: device_id::get_device_id(),
            };
            info!("Using server_state:: device_id: {}", server_state.device_id);

            let mut server_config = crate::config::create_config(false, None);
            server_config.port = 5600;
            server_config.auth.api_key = None;
            server_config.auth.sessions = Some(local_sessions());

            endpoints::build_rocket(server_state, server_config)
                .launch()
                .await;
        }
    }

    static mut INITIALIZED: bool = false;

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_activitywatch_android_RustInterface_initialize(
        env: JNIEnv,
        _: JClass,
    ) {
        if !INITIALIZED {
            android_logger::init_once(
                Config::default()
                    .with_max_level(log::LevelFilter::Info) // limit log level
                    .with_tag("aw-server-rust"), // logs will show under mytag tag
                                                 //.with_filter( // configure messages for specific crate
                                                 //    FilterBuilder::new()
                                                 //        .parse("debug,hello::crate=error")
                                                 //        .build())
            );
            info!("Initializing aw-server-rust...");
            debug!("Redirected aw-server-rust stdout/stderr to logcat");
        } else {
            info!("Already initialized");
        }
        INITIALIZED = true;

        // Without this it might not work due to weird error probably arising from Rust optimizing away the JNIEnv:
        //  JNI DETECTED ERROR IN APPLICATION: use of deleted weak global reference
        string_to_jstring(&env, "test".to_string());
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_activitywatch_android_RustInterface_setDataDir(
        env: JNIEnv,
        _: JClass,
        java_dir: JString,
    ) {
        let path = &jstring_to_string(&env, java_dir);
        debug!("Setting android data dir as {}", path);
        dirs::set_android_data_dir(path);
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_activitywatch_android_RustInterface_setVaultKey(
        env: JNIEnv,
        _: JClass,
        java_key: JByteArray,
    ) -> jboolean {
        let mut bytes = match env.convert_byte_array(java_key) {
            Ok(bytes) if bytes.len() == 32 => bytes,
            Ok(mut bytes) => {
                bytes.fill(0);
                return JNI_FALSE;
            }
            Err(_) => return JNI_FALSE,
        };
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        bytes.fill(0);
        let datastore = match DATASTORE.lock() {
            Ok(datastore) => datastore,
            Err(_) => {
                key.fill(0);
                return JNI_FALSE;
            }
        };
        let mut stored_key = match VAULT_KEY.lock() {
            Ok(key) => key,
            Err(_) => {
                key.fill(0);
                return JNI_FALSE;
            }
        };
        match stored_key.as_ref() {
            Some(existing) if &**existing == &key => {
                key.fill(0);
                JNI_TRUE
            }
            Some(_) => {
                key.fill(0);
                JNI_FALSE
            }
            None if datastore.is_none() => {
                *stored_key = Some(Zeroizing::new(key));
                JNI_TRUE
            }
            None => {
                key.fill(0);
                JNI_FALSE
            }
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_activitywatch_android_RustInterface_initializeVault(
        _: JNIEnv,
        _: JClass,
    ) -> jboolean {
        match openDatastore() {
            Ok(_) => JNI_TRUE,
            Err(_) => JNI_FALSE,
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_activitywatch_android_RustInterface_nativeLocalCommand(
        env: JNIEnv,
        _: JClass,
        java_command: JString,
        java_arguments: JString,
    ) -> jstring {
        let command = jstring_to_string(&env, java_command);
        let arguments = jstring_to_string(&env, java_arguments);
        let result = if command == "local_session" {
            local_sessions().mint(Scope::Admin)
                .map(serde_json::Value::String)
                .map_err(|_| "Local dashboard session is unavailable".to_string())
        } else {
            match serde_json::from_str(&arguments) {
                Ok(arguments) => match openDatastore() {
                    Ok(store) => SYNC_CONTROL.invoke(&store, &command, arguments),
                    Err(error) => Err(error),
                },
                Err(_) => Err("Invalid native operation arguments".into()),
            }
        };
        let response = match result {
            Ok(result) => json!({"result": result}),
            Err(error) => json!({"error": error}),
        };
        string_to_jstring(&env, response.to_string())
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_activitywatch_android_RustInterface_nativePreviewLegacyMigration(
        env: JNIEnv,
        _: JClass,
    ) -> jstring {
        let path = match dirs::db_path(false) {
            Ok(path) => path,
            Err(_) => return create_error_object(&env, "local database path unavailable".into()),
        };
        match aw_datastore::vault::preview_plaintext(&path) {
            Ok(preview) => string_to_jstring(
                &env,
                json!({"buckets": preview.buckets, "events": preview.events}).to_string(),
            ),
            Err(_) => create_error_object(&env, "existing database cannot be migrated as plaintext".into()),
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_activitywatch_android_RustInterface_nativeMigrateLegacyVault(
        env: JNIEnv,
        _: JClass,
        java_key: JByteArray,
        accepted: jboolean,
    ) -> jboolean {
        if accepted != JNI_TRUE {
            return JNI_FALSE;
        }
        let mut bytes = match env.convert_byte_array(java_key) {
            Ok(bytes) if bytes.len() == 32 => bytes,
            Ok(mut bytes) => {
                bytes.fill(0);
                return JNI_FALSE;
            }
            Err(_) => return JNI_FALSE,
        };
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        bytes.fill(0);
        let hex_key = Zeroizing::new(key_as_hex(&key));
        key.fill(0);
        let path = match dirs::db_path(false) {
            Ok(path) => path,
            Err(_) => return JNI_FALSE,
        };
        match aw_datastore::vault::migrate_plaintext(&path, hex_key.as_str()) {
            Ok(_) => JNI_TRUE,
            Err(_) => JNI_FALSE,
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_activitywatch_android_RustInterface_nativeGetBuckets(
        env: JNIEnv,
        _: JClass,
    ) -> jstring {
        let buckets = openDatastore().expect("vault must be initialized before use").get_buckets().unwrap();
        string_to_jstring(&env, json!(buckets).to_string())
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_activitywatch_android_RustInterface_nativeCreateBucket(
        env: JNIEnv,
        _: JClass,
        java_bucket: JString,
    ) -> jstring {
        let bucket = jstring_to_string(&env, java_bucket);
        let bucket_json: Bucket = match serde_json::from_str(&bucket) {
            Ok(json) => json,
            Err(err) => return create_error_object(&env, err.to_string()),
        };
        match openDatastore().expect("vault must be initialized before use").create_bucket(&bucket_json) {
            Ok(()) => string_to_jstring(&env, "Bucket successfully created".to_string()),
            Err(e) => create_error_object(
                &env,
                format!("Something went wrong when trying to create bucket: {:?}", e),
            ),
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_activitywatch_android_RustInterface_nativeHeartbeat(
        env: JNIEnv,
        _: JClass,
        java_bucket_id: JString,
        java_event: JString,
        java_pulsetime: jdouble,
    ) -> jstring {
        let bucket_id = jstring_to_string(&env, java_bucket_id);
        let event = jstring_to_string(&env, java_event);
        let pulsetime = java_pulsetime as f64;
        let event_json: Event = match serde_json::from_str(&event) {
            Ok(json) => json,
            Err(err) => return create_error_object(&env, err.to_string()),
        };
        match openDatastore().expect("vault must be initialized before use").heartbeat(&bucket_id, event_json, pulsetime) {
            Ok(_) => string_to_jstring(&env, "Heartbeat successfully received".to_string()),
            Err(e) => create_error_object(
                &env,
                format!(
                    "Something went wrong when trying to send heartbeat: {:?}",
                    e
                ),
            ),
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_activitywatch_android_RustInterface_nativeGetEvents(
        env: JNIEnv,
        _: JClass,
        java_bucket_id: JString,
        java_limit: jint,
    ) -> jstring {
        let bucket_id = jstring_to_string(&env, java_bucket_id);
        let limit = java_limit as u64;
        match openDatastore().expect("vault must be initialized before use").get_events(&bucket_id, None, None, Some(limit)) {
            Ok(events) => string_to_jstring(&env, json!(events).to_string()),
            Err(e) => create_error_object(
                &env,
                format!("Something went wrong when trying to get events: {:?}", e),
            ),
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_activitywatch_android_RustInterface_nativeMigrateHostname(
        env: JNIEnv,
        _: JClass,
        hostname: JString,
    ) -> jstring {
        let hostname = jstring_to_string(&env, hostname);
        if hostname.is_empty() {
            return create_error_object(&env, "hostname must not be empty".to_string());
        }
        match openDatastore().expect("vault must be initialized before use").migrate_hostname(&hostname) {
            Ok(count) => {
                string_to_jstring(&env, format!("Migrated hostname for {} bucket(s)", count))
            }
            Err(e) => create_error_object(&env, format!("Failed to migrate hostname: {:?}", e)),
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_activitywatch_android_RustInterface_migrateAndroidBucketName(
        env: JNIEnv,
        _: JClass,
    ) -> jstring {
        match openDatastore().expect("vault must be initialized before use").rename_bucket("aw-android-test", "aw-android") {
            Ok(()) => string_to_jstring(
                &env,
                "Renamed bucket 'aw-android-test' to 'aw-android'".to_string(),
            ),
            Err(e) => create_error_object(&env, format!("Failed to rename bucket: {:?}", e)),
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_activitywatch_android_RustInterface_migrateWatcherAndroidBucketNames(
        env: JNIEnv,
        _: JClass,
    ) -> jstring {
        match openDatastore().expect("vault must be initialized before use").migrate_test_bucket_names() {
            Ok(count) => string_to_jstring(
                &env,
                format!("Migrated {} 'aw-watcher-android-test' bucket(s)", count),
            ),
            Err(e) => create_error_object(
                &env,
                format!("Failed to migrate watcher bucket names: {:?}", e),
            ),
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_activitywatch_android_RustInterface_nativeQuery(
        env: JNIEnv,
        _: JClass,
        java_query: JString,
        java_timeperiods: JString,
    ) -> jstring {
        let query_code = jstring_to_string(&env, java_query);
        let timeperiods_str = jstring_to_string(&env, java_timeperiods);
        let timeperiods: Vec<TimeInterval> = match serde_json::from_str(&timeperiods_str) {
            Ok(json) => json,
            Err(err) => return create_error_object(&env, err.to_string()),
        };

        let datastore = openDatastore().expect("vault must be initialized before use");
        let mut results = Vec::new();

        for interval in &timeperiods {
            let result = match aw_query::query(&query_code, interval, &datastore) {
                Ok(data) => data,
                Err(e) => {
                    return create_error_object(
                        &env,
                        format!("Something went wrong when trying to query: {:?}", e),
                    )
                }
            };
            results.push(result);
        }

        string_to_jstring(&env, json!(results).to_string())
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_activitywatch_android_RustInterface_nativeAndroidQuery(
        env: JNIEnv,
        _: JClass,
        java_timeperiods: JString,
    ) -> jstring {
        let timeperiods_str = jstring_to_string(&env, java_timeperiods);

        let timeperiods: Vec<TimeInterval> = match serde_json::from_str(&timeperiods_str) {
            Ok(json) => json,
            Err(err) => return create_error_object(&env, err.to_string()),
        };

        // Hardcoded bucket ID
        let bid_android = "aw-watcher-android".to_string();

        // Get classes from server settings via HTTP API
        let query_token = match local_sessions().mint(Scope::Admin) {
            Ok(token) => token,
            Err(_) => return create_error_object(&env, "Local query session is unavailable".into()),
        };
        let classes = match AwClient::new("127.0.0.1", 5600, &query_token) {
            Ok(client) => {
                match client.get_setting("classes") {
                    Ok(classes_value) => {
                        // Parse the server-side classes from JSON value
                        match serde_json::from_value::<Vec<aw_models::Class>>(classes_value) {
                            Ok(server_classes) => {
                                if server_classes.is_empty() {
                                    info!("Server classes list is empty, using default classes");
                                    default_classes()
                                } else {
                                    // Convert from aw_models::Class to CategorySpec format
                                    server_classes
                                        .iter()
                                        .map(|c| {
                                            let category_id: CategoryId = c.name.clone();
                                            let category_spec = CategorySpec {
                                                spec_type: c.rule.rule_type.clone(),
                                                regex: c.rule.regex.clone().unwrap_or_default(),
                                                ignore_case: c.rule.ignore_case.unwrap_or(false),
                                            };
                                            (category_id, category_spec)
                                        })
                                        .collect()
                                }
                            }
                            Err(e) => {
                                warn!("Failed to parse server classes, using defaults: {:?}", e);
                                default_classes()
                            }
                        }
                    }
                    Err(e) => {
                        info!("Failed to get server classes, using defaults: {:?}", e);
                        default_classes()
                    }
                }
            }
            Err(e) => {
                warn!(
                    "Failed to create client for fetching classes, using defaults: {:?}",
                    e
                );
                default_classes()
            }
        };

        // Build canonical Android query
        let params = AndroidQueryParams {
            base: QueryParamsBase {
                bid_browsers: Vec::new(),
                classes,
                filter_classes: Vec::new(),
                filter_afk: true,
                include_audible: true,
            },
            bid_android,
        };
        let query_code = format!(
            r#"{}
duration = sum_durations(events);
cat_events = sort_by_duration(merge_events_by_keys(events, ["$category"]));
RETURN = {{"events": events, "duration": duration, "cat_events": cat_events}};"#,
            build_android_canonical_events(&params)
        );

        let datastore = openDatastore().expect("vault must be initialized before use");
        let mut results = Vec::new();

        for interval in &timeperiods {
            let result = match aw_query::query(&query_code, interval, &datastore) {
                Ok(data) => data,
                Err(e) => {
                    return create_error_object(
                        &env,
                        format!("Something went wrong when trying to query: {:?}", e),
                    )
                }
            };
            results.push(result);
        }

        string_to_jstring(&env, json!(results).to_string())
    }
}
