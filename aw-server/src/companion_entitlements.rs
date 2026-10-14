//! Native billing callbacks own a retained context independent of activity storage.
use aw_entitlements::{EntitlementSourceV1, StoredEntitlementV1, MAX_STORED_ENTITLEMENT_BYTES_V1};
use std::ffi::c_void;
use zeroize::Zeroizing;

#[repr(C)]
pub struct CompanionEntitlementCallbacksV1 {
    pub context: *mut c_void,
    pub load: Option<unsafe extern "C" fn(*mut c_void, *mut u8, usize, *mut usize) -> i32>,
    pub save: Option<unsafe extern "C" fn(*mut c_void, *const u8, usize) -> i32>,
    pub floor: Option<unsafe extern "C" fn(*mut c_void, *const u8, usize, *mut u64) -> i32>,
    pub advance: Option<unsafe extern "C" fn(*mut c_void, *const u8, usize, u64) -> i32>,
    pub release: Option<unsafe extern "C" fn(*mut c_void)>,
}

impl Default for CompanionEntitlementCallbacksV1 {
    fn default() -> Self {
        Self {
            context: std::ptr::null_mut(),
            load: None,
            save: None,
            floor: None,
            advance: None,
            release: None,
        }
    }
}

pub(crate) struct CompanionEntitlementSource {
    pub callbacks: CompanionEntitlementCallbacksV1,
}
// The native ABI requires callbacks/context to support concurrent native threads.
unsafe impl Send for CompanionEntitlementSource {}
unsafe impl Sync for CompanionEntitlementSource {}

impl CompanionEntitlementSource {
    pub fn available(&self) -> bool {
        let callbacks = &self.callbacks;
        !callbacks.context.is_null()
            && callbacks.load.is_some()
            && callbacks.save.is_some()
            && callbacks.floor.is_some()
            && callbacks.advance.is_some()
            && callbacks.release.is_some()
    }
}

impl Drop for CompanionEntitlementSource {
    fn drop(&mut self) {
        if !self.callbacks.context.is_null() {
            if let Some(release) = self.callbacks.release {
                unsafe { release(self.callbacks.context) }
            }
        }
    }
}

impl EntitlementSourceV1 for CompanionEntitlementSource {
    fn load(&self) -> Result<Option<StoredEntitlementV1>, &'static str> {
        let callback = self
            .callbacks
            .load
            .ok_or("The native entitlement store is unavailable")?;
        let mut bytes = Zeroizing::new(vec![0u8; MAX_STORED_ENTITLEMENT_BYTES_V1]);
        let mut length = 0;
        let result = unsafe {
            callback(
                self.callbacks.context,
                bytes.as_mut_ptr(),
                bytes.len(),
                &mut length,
            )
        };
        if result == 1 && length == 0 {
            return Ok(None);
        }
        if result != 0 || !(1..=bytes.len()).contains(&length) {
            return Err("The native entitlement store could not be read");
        }
        bytes.truncate(length);
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
        let callback = self
            .callbacks
            .save
            .ok_or("The native entitlement store is unavailable")?;
        let bytes = Zeroizing::new(
            serde_json::to_vec(proof)
                .map_err(|_| "The signed plan document could not be encoded")?,
        );
        if bytes.len() > MAX_STORED_ENTITLEMENT_BYTES_V1 {
            return Err("The signed plan document exceeds its limit");
        }
        if unsafe { callback(self.callbacks.context, bytes.as_ptr(), bytes.len()) } != 0 {
            return Err("The native entitlement store could not save the signed plan");
        }
        Ok(())
    }
    fn revocation_floor(&self, scope: &str) -> Result<u64, &'static str> {
        let callback = self
            .callbacks
            .floor
            .ok_or("The native entitlement checkpoint is unavailable")?;
        let mut sequence = 0;
        if unsafe {
            callback(
                self.callbacks.context,
                scope.as_ptr(),
                scope.len(),
                &mut sequence,
            )
        } != 0
        {
            return Err("The native entitlement checkpoint could not be read");
        }
        Ok(sequence)
    }
    fn advance_revocation_floor(&self, scope: &str, sequence: u64) -> Result<(), &'static str> {
        let callback = self
            .callbacks
            .advance
            .ok_or("The native entitlement checkpoint is unavailable")?;
        if unsafe {
            callback(
                self.callbacks.context,
                scope.as_ptr(),
                scope.len(),
                sequence,
            )
        } != 0
        {
            return Err("The native entitlement checkpoint could not be preserved");
        }
        Ok(())
    }
}
