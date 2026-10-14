//! Native signed-plan metadata stays outside the activity datastore.
use aw_entitlements::{
    EntitlementSourceV1, RuntimeFeatureAccessV1, StoredEntitlementV1,
    MAX_STORED_ENTITLEMENT_BYTES_V1,
};
use jni::{
    objects::{GlobalRef, JObject, JValue},
    JNIEnv, JavaVM,
};
use std::sync::{Arc, OnceLock};
use zeroize::Zeroizing;

static RUNTIME: OnceLock<Arc<RuntimeFeatureAccessV1>> = OnceLock::new();
pub fn runtime() -> Arc<RuntimeFeatureAccessV1> {
    RUNTIME.get_or_init(|| Arc::default()).clone()
}

struct AndroidEntitlementSource {
    vm: JavaVM,
    object: GlobalRef,
}
impl AndroidEntitlementSource {
    fn with_env<T>(
        &self,
        work: impl FnOnce(&JNIEnv) -> Result<T, &'static str>,
    ) -> Result<T, &'static str> {
        let env = self
            .vm
            .attach_current_thread()
            .map_err(|_| "The native entitlement store is unavailable")?;
        let result = work(&env);
        if env.exception_check().unwrap_or(true) {
            let _ = env.exception_clear();
            return Err("The native entitlement store is unavailable");
        }
        result
    }
    fn bytes(&self, method: &str, maximum: usize) -> Result<Option<Vec<u8>>, &'static str> {
        self.with_env(|env| {
            let object = env
                .call_method(self.object.as_obj(), method, "()[B", &[])
                .and_then(|value| value.l())
                .map_err(|_| "The native entitlement store could not be read")?;
            if object.is_null() {
                return Ok(None);
            }
            let array = object.into_raw() as jni::sys::jbyteArray;
            let length = env
                .get_array_length(array)
                .map_err(|_| "The native entitlement data is invalid")?;
            if length < 0 || length as usize > maximum {
                return Err("The native entitlement data exceeds its limit");
            }
            env.convert_byte_array(array)
                .map(Some)
                .map_err(|_| "The native entitlement data is invalid")
        })
    }
}

pub fn install(env: &JNIEnv, object: JObject) -> Result<(), &'static str> {
    if RUNTIME.get().is_some() {
        return Ok(());
    }
    let configured = (|| {
        let source = Arc::new(AndroidEntitlementSource {
            vm: env
                .get_java_vm()
                .map_err(|_| "The native entitlement store is unavailable")?,
            object: env
                .new_global_ref(object)
                .map_err(|_| "The native entitlement store is unavailable")?,
        });
        let trust = source
            .bytes("releaseTrust", 16_384)?
            .ok_or("The embedded entitlement trust is unavailable")?;
        let (keys, floor) = crate::feature_access::parse_release_entitlement_trust(&trust)?;
        Ok(Arc::new(RuntimeFeatureAccessV1::new(keys, floor, source)))
    })();
    // Failed initialization stays closed until restart so status and HTTP share one gate.
    let _ = RUNTIME.set(configured.as_ref().cloned().unwrap_or_default());
    configured.map(|_| ())
}

impl EntitlementSourceV1 for AndroidEntitlementSource {
    fn load(&self) -> Result<Option<StoredEntitlementV1>, &'static str> {
        let Some(bytes) = self.bytes("load", MAX_STORED_ENTITLEMENT_BYTES_V1)? else {
            return Ok(None);
        };
        let bytes = Zeroizing::new(bytes);
        if !bytes
            .iter()
            .find(|byte| !byte.is_ascii_whitespace())
            .is_some_and(|byte| *byte == b'{')
        {
            return Err("The native signed plan document is invalid");
        }
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| "The native signed plan document is invalid")
    }
    fn save(&self, proof: &StoredEntitlementV1) -> Result<(), &'static str> {
        let bytes = Zeroizing::new(
            serde_json::to_vec(proof).map_err(|_| "The signed plan could not be encoded")?,
        );
        if bytes.len() > MAX_STORED_ENTITLEMENT_BYTES_V1 {
            return Err("The signed plan exceeds its limit");
        }
        self.with_env(|env| {
            let array = env
                .byte_array_from_slice(&bytes)
                .map_err(|_| "The native signed plan could not be saved")?;
            let object = unsafe { JObject::from_raw(array) };
            let saved = env
                .call_method(
                    self.object.as_obj(),
                    "save",
                    "([B)Z",
                    &[JValue::Object(object)],
                )
                .and_then(|value| value.z())
                .map_err(|_| "The native signed plan could not be saved")?;
            if saved {
                Ok(())
            } else {
                Err("The native signed plan could not be saved")
            }
        })
    }
    fn revocation_floor(&self, scope: &str) -> Result<u64, &'static str> {
        self.with_env(|env| {
            let scope = env
                .new_string(scope)
                .map_err(|_| "The native entitlement checkpoint is unavailable")?;
            let value = env
                .call_method(
                    self.object.as_obj(),
                    "floor",
                    "(Ljava/lang/String;)Ljava/lang/String;",
                    &[JValue::Object(scope.into())],
                )
                .and_then(|value| value.l())
                .map_err(|_| "The native entitlement checkpoint is unavailable")?;
            let value = env
                .get_string(value.into())
                .map_err(|_| "The native entitlement checkpoint is invalid")?;
            value
                .to_str()
                .map_err(|_| "The native entitlement checkpoint is invalid")?
                .parse()
                .map_err(|_| "The native entitlement checkpoint is invalid")
        })
    }
    fn advance_revocation_floor(&self, scope: &str, sequence: u64) -> Result<(), &'static str> {
        self.with_env(|env| {
            let scope = env
                .new_string(scope)
                .map_err(|_| "The native entitlement checkpoint is unavailable")?;
            let sequence = env
                .new_string(sequence.to_string())
                .map_err(|_| "The native entitlement checkpoint is unavailable")?;
            let saved = env
                .call_method(
                    self.object.as_obj(),
                    "advance",
                    "(Ljava/lang/String;Ljava/lang/String;)Z",
                    &[
                        JValue::Object(scope.into()),
                        JValue::Object(sequence.into()),
                    ],
                )
                .and_then(|value| value.z())
                .map_err(|_| "The native entitlement checkpoint could not be saved")?;
            if saved {
                Ok(())
            } else {
                Err("The native entitlement checkpoint could not be saved")
            }
        })
    }
}
