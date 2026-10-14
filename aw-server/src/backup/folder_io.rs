//! Existing-folder deletion: sealed intent precedes IO; only reauthenticated exact bytes may be removed.
use aw_models::{SnapshotDeletionFactV1, SyncEnvelopeV1};
use aw_sync_e2ee::{
    EncryptedSyncSnapshotV1, SnapshotDeletionProofV1, VaultDataKeyV1, MAX_BACKUP_BUNDLE_BYTES,
};
use serde::Serialize;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};
const ENVELOPE_BYTES: usize = 2 * 1024 * 1024;
#[derive(Default, Debug, Serialize)]
pub struct BackupCopyDeletionV1 {
    pub deleted: usize,
    pub absent: usize,
    pub conflict: usize,
    pub failed: usize,
    pub durable: bool,
}
pub struct FolderBackupDeletionV1 {
    root: platform::Directory,
}
fn failure<T>(_: T) -> String {
    "Backup folder operation failed; changed and unverified files were preserved".into()
}
fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn intent_name(bundle: &str) -> Result<String, String> {
    if !hash(bundle) {
        return Err(failure("invalid digest"));
    }
    Ok(format!(".peakactivity-delete-{bundle}.intent"))
}
fn read_bytes(file: File, limit: usize) -> io::Result<Vec<u8>> {
    let meta = file.metadata()?;
    if !meta.is_file() || meta.len() > limit as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Not a bounded regular file",
        ));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Reparse point"));
        }
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "File exceeds limit",
        ));
    }
    Ok(bytes)
}
fn envelope(file: File, id: &str) -> io::Result<SyncEnvelopeV1> {
    let value: SyncEnvelopeV1 = serde_json::from_slice(&read_bytes(file, ENVELOPE_BYTES)?)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid encrypted object"))?;
    value
        .validate()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid encrypted object"))?;
    if value.object_id != id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Changed object identifier",
        ));
    }
    Ok(value)
}
impl FolderBackupDeletionV1 {
    pub fn open_existing(path: impl AsRef<Path>) -> Result<Self, String> {
        Ok(Self {
            root: platform::Directory::open(path.as_ref()).map_err(failure)?,
        })
    }
    pub fn load_intent(
        &self,
        key: &VaultDataKeyV1,
        bundle: &str,
    ) -> Result<Option<EncryptedSyncSnapshotV1>, String> {
        let name = intent_name(bundle)?;
        let Some(file) = self.root.read(&name).map_err(failure)? else {
            return Ok(None);
        };
        let record: EncryptedSyncSnapshotV1 =
            serde_json::from_slice(&read_bytes(file, MAX_BACKUP_BUNDLE_BYTES).map_err(failure)?)
                .map_err(failure)?;
        let fact = SnapshotDeletionProofV1::open_record(key, &record).map_err(failure)?;
        if fact.bundle_sha256 != bundle {
            return Err(failure("Intent digest changed"));
        }
        Ok(Some(record))
    }
    pub fn persist_intent(
        &self,
        key: &VaultDataKeyV1,
        proof: &SnapshotDeletionProofV1,
    ) -> Result<EncryptedSyncSnapshotV1, String> {
        let bundle = &proof.fact().bundle_sha256;
        if let Some(record) = self.load_intent(key, bundle)? {
            if SnapshotDeletionProofV1::open_record(key, &record).map_err(failure)? != *proof.fact()
            {
                return Err(failure("Intent changed"));
            }
            self.publish_accepted_intent(key, &record)?;
            return Ok(record);
        }
        if !proof.is_complete() {
            return Err(failure("Incomplete new intent"));
        }
        let record = proof.seal(key).map_err(failure)?;
        self.publish_accepted_intent(key, &record)?;
        Ok(record)
    }
    // The common controller calls this only after the protected complete-proof intent committed.
    pub(super) fn publish_accepted_intent(
        &self,
        key: &VaultDataKeyV1,
        record: &EncryptedSyncSnapshotV1,
    ) -> Result<(), String> {
        let fact = SnapshotDeletionProofV1::open_record(key, record).map_err(failure)?;
        if let Some(existing) = self.load_intent(key, &fact.bundle_sha256)? {
            if SnapshotDeletionProofV1::open_record(key, &existing).map_err(failure)? != fact {
                return Err(failure("Intent changed"));
            }
        } else {
            let bytes = serde_json::to_vec(record).map_err(failure)?;
            if bytes.len() > MAX_BACKUP_BUNDLE_BYTES {
                return Err(failure("Intent exceeds limit"));
            }
            self.root
                .publish(&intent_name(&fact.bundle_sha256)?, &bytes)
                .map_err(failure)?;
        }
        for object in &fact.objects {
            let name = format!(".peakactivity-delete-{}.marker", object.object_id);
            if let Some(file) = self.root.read(&name).map_err(failure)? {
                if read_bytes(file, 64).map_err(failure)? != fact.bundle_sha256.as_bytes() {
                    return Err(failure("Admission marker changed"));
                }
            } else {
                self.root
                    .publish(&name, fact.bundle_sha256.as_bytes())
                    .map_err(failure)?;
            }
        }
        self.root.sync().map_err(failure)
    }
    pub fn remaining(&self, fact: &SnapshotDeletionFactV1) -> Result<Vec<SyncEnvelopeV1>, String> {
        fact.validate().map_err(failure)?;
        let quarantine = self
            .root
            .quarantine(&fact.bundle_sha256, false)
            .map_err(failure)?;
        let mut output = Vec::new();
        let mut bytes = 0usize;
        for object in &fact.objects {
            let name = format!("{}.json", object.object_id);
            let active = self
                .root
                .read(&name)
                .map_err(failure)?
                .map(|f| envelope(f, &object.object_id))
                .transpose()
                .map_err(failure)?;
            let held = quarantine
                .as_ref()
                .map(|q| q.read(&name))
                .transpose()
                .map_err(failure)?
                .flatten()
                .map(|f| envelope(f, &object.object_id))
                .transpose()
                .map_err(failure)?;
            if active.is_some() && held.is_some() {
                return Err(failure("Two copies require conflict review"));
            }
            if let Some(object) = active.or(held) {
                bytes = bytes
                    .checked_add(serde_json::to_vec(&object).map_err(failure)?.len())
                    .ok_or_else(|| failure("Limit overflow"))?;
                if bytes > MAX_BACKUP_BUNDLE_BYTES {
                    return Err(failure("Remaining bundle exceeds limit"));
                }
                output.push(object);
            }
        }
        Ok(output)
    }
    pub fn delete_recorded(
        &self,
        key: &VaultDataKeyV1,
        proof: Option<&SnapshotDeletionProofV1>,
        bundle: &str,
    ) -> Result<BackupCopyDeletionV1, String> {
        let record = self
            .load_intent(key, bundle)?
            .ok_or_else(|| failure("No durable intent"))?;
        let fact = SnapshotDeletionProofV1::open_record(key, &record).map_err(failure)?;
        if proof.is_some_and(|proof| proof.fact() != &fact) {
            return Err(failure("Different deletion authority"));
        }
        for object in &fact.objects {
            let marker = self
                .root
                .read(&format!(".peakactivity-delete-{}.marker", object.object_id))
                .map_err(failure)?
                .ok_or_else(|| failure("Admission marker is incomplete"))?;
            if read_bytes(marker, 64).map_err(failure)? != bundle.as_bytes() {
                return Err(failure("Admission marker changed"));
            }
        }
        self.root.sync().map_err(failure)?;
        let quarantine = self.root.quarantine(bundle, true).map_err(failure)?;
        let mut result = BackupCopyDeletionV1::default();
        for object in &fact.objects {
            match self
                .root
                .remove_verified(quarantine.as_ref(), &object.object_id, proof)
            {
                Ok(platform::Removal::Deleted) => result.deleted += 1,
                Ok(platform::Removal::Absent) => result.absent += 1,
                Ok(platform::Removal::Conflict) => result.conflict += 1,
                Err(_) => result.failed += 1,
            }
        }
        result.durable =
            self.root.sync().is_ok() && quarantine.as_ref().is_none_or(|q| q.sync().is_ok());
        Ok(result)
    }
}

#[cfg(unix)]
mod platform {
    use super::*;
    use std::{
        ffi::CString,
        os::unix::{
            ffi::OsStrExt,
            io::{AsRawFd, FromRawFd},
        },
        path::Component,
    };
    pub enum Removal {
        Deleted,
        Absent,
        Conflict,
    }
    pub struct Directory(File);
    #[cfg(test)]
    std::thread_local! {static SYNC_FAULT:std::cell::Cell<(usize,usize)>=const{std::cell::Cell::new((0,0))};}
    #[cfg(test)]
    pub(super) fn fail_sync_call(call: usize) {
        SYNC_FAULT.with(|state| state.set((call, 0)));
    }

    fn name(value: &str) -> io::Result<CString> {
        if value.is_empty() || value.contains('/') || value == "." || value == ".." {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid child name",
            ));
        }
        CString::new(value)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid child name"))
    }
    fn opened(fd: i32) -> io::Result<File> {
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(unsafe { File::from_raw_fd(fd) })
        }
    }
    impl Directory {
        pub fn open(path: &Path) -> io::Result<Self> {
            let path = if path.is_absolute() {
                path.to_path_buf()
            } else {
                std::env::current_dir()?.join(path)
            };
            let mut current = Self(opened(unsafe {
                libc::open(
                    c"/".as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                )
            })?);
            for part in path.components() {
                match part {
                    Component::RootDir | Component::CurDir => (),
                    Component::Normal(part) => {
                        let part = CString::new(part.as_bytes()).map_err(|_| {
                            io::Error::new(io::ErrorKind::InvalidInput, "Invalid path")
                        })?;
                        current = Self(opened(unsafe {
                            libc::openat(
                                current.0.as_raw_fd(),
                                part.as_ptr(),
                                libc::O_RDONLY
                                    | libc::O_DIRECTORY
                                    | libc::O_NOFOLLOW
                                    | libc::O_CLOEXEC,
                            )
                        })?);
                    }
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "Parent traversal is not allowed",
                        ))
                    }
                }
            }
            Ok(current)
        }
        pub fn read(&self, child: &str) -> io::Result<Option<File>> {
            let child = name(child)?;
            match opened(unsafe {
                libc::openat(
                    self.0.as_raw_fd(),
                    child.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
                )
            }) {
                Ok(file) => Ok(Some(file)),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(error),
            }
        }
        pub fn sync(&self) -> io::Result<()> {
            #[cfg(test)]
            if SYNC_FAULT.with(|state| {
                let (fail, count) = state.get();
                state.set((fail, count + 1));
                fail != 0 && count + 1 == fail
            }) {
                return Err(io::Error::other("Synthetic directory sync failure"));
            }
            self.0.sync_all()
        }
        fn rename(&self, child: &str, destination: &Self, target: &str) -> io::Result<()> {
            let child = name(child)?;
            let target = name(target)?;
            #[cfg(any(target_os = "linux", target_os = "android"))]
            let result = unsafe {
                // Avoid a new Bionic symbol on supported Android API26 devices.
                libc::syscall(
                    libc::SYS_renameat2,
                    self.0.as_raw_fd() as libc::c_long,
                    child.as_ptr(),
                    destination.0.as_raw_fd() as libc::c_long,
                    target.as_ptr(),
                    libc::RENAME_NOREPLACE as libc::c_ulong,
                )
            };
            #[cfg(target_os = "macos")]
            let result = unsafe {
                libc::renameatx_np(
                    self.0.as_raw_fd(),
                    child.as_ptr(),
                    destination.0.as_raw_fd(),
                    target.as_ptr(),
                    libc::RENAME_EXCL,
                )
            };
            #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Exclusive rename is unavailable",
            ));
            #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
            if result != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
        fn unlink(&self, child: &str) -> io::Result<()> {
            let child = name(child)?;
            if unsafe { libc::unlinkat(self.0.as_raw_fd(), child.as_ptr(), 0) } != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
        pub fn publish(&self, child: &str, bytes: &[u8]) -> io::Result<()> {
            let mut random = [0u8; 16];
            ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut random)
                .map_err(|_| io::Error::other("Randomness unavailable"))?;
            let temporary = format!(
                ".peakactivity-intent-{}.tmp",
                base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, random)
            );
            let temp = name(&temporary)?;
            let mut file = opened(unsafe {
                libc::openat(
                    self.0.as_raw_fd(),
                    temp.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            })?;
            file.write_all(bytes)?;
            file.sync_all()?;
            drop(file);
            self.rename(&temporary, self, child)?;
            self.sync()
        }
        pub fn quarantine(&self, bundle: &str, create: bool) -> io::Result<Option<Self>> {
            let child = name(&format!(".peakactivity-delete-{bundle}"))?;
            if create {
                let status = unsafe { libc::mkdirat(self.0.as_raw_fd(), child.as_ptr(), 0o700) };
                if status != 0 && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists
                {
                    return Err(io::Error::last_os_error());
                }
                self.sync()?;
            }
            match opened(unsafe {
                libc::openat(
                    self.0.as_raw_fd(),
                    child.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            }) {
                Ok(file) => {
                    use std::os::unix::fs::MetadataExt;
                    let meta = file.metadata()?;
                    if meta.mode() & 0o077 != 0 || meta.uid() != unsafe { libc::geteuid() } {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "Unsafe operation directory",
                        ));
                    }
                    Ok(Some(Self(file)))
                }
                Err(error) if !create && error.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(error),
            }
        }
        pub fn remove_verified(
            &self,
            quarantine: Option<&Self>,
            id: &str,
            proof: Option<&SnapshotDeletionProofV1>,
        ) -> io::Result<Removal> {
            let quarantine =
                quarantine.ok_or_else(|| io::Error::other("No operation directory"))?;
            let child = format!("{id}.json");
            let held = quarantine.read(&child);
            match held {
                Ok(Some(_)) => {
                    if self.read(&child)?.is_some() {
                        return Ok(Removal::Conflict);
                    }
                }
                Ok(None) => match self.rename(&child, quarantine, &child) {
                    Ok(()) => {
                        self.sync()?;
                        quarantine.sync()?;
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        return Ok(Removal::Absent)
                    }
                    Err(error) => return Err(error),
                },
                Err(error) => {
                    if error.raw_os_error() == Some(libc::ELOOP) {
                        let _ = quarantine.rename(&child, self, &child);
                        return Ok(Removal::Conflict);
                    }
                    return Err(error);
                }
            }
            let file = match quarantine.read(&child) {
                Ok(Some(file)) => file,
                Ok(None) => return Err(io::Error::other("Moved file disappeared")),
                Err(error) => {
                    if error.raw_os_error() == Some(libc::ELOOP) {
                        let _ = quarantine.rename(&child, self, &child);
                        return Ok(Removal::Conflict);
                    }
                    return Err(error);
                }
            };
            let verified = envelope(file, id)
                .is_ok_and(|envelope| proof.is_some_and(|proof| proof.allows_object(&envelope)));
            if !verified {
                let _ = quarantine.rename(&child, self, &child);
                self.sync()?;
                quarantine.sync()?;
                return Ok(Removal::Conflict);
            }
            // POSIX cannot prevent an already-open same-UID writer; keep the private quarantine pinned throughout.
            quarantine.unlink(&child)?;
            quarantine.sync()?;
            Ok(Removal::Deleted)
        }
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::{
        ffi::c_void,
        fs::OpenOptions,
        os::windows::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
            io::AsRawHandle,
        },
        path::{Component, PathBuf},
    };
    pub enum Removal {
        Deleted,
        Absent,
        Conflict,
    }
    pub struct Directory {
        path: PathBuf,
        _parents: Vec<File>,
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn MoveFileExW(from: *const u16, to: *const u16, flags: u32) -> i32;
        fn SetFileInformationByHandle(
            handle: *mut c_void,
            class: i32,
            info: *const c_void,
            bytes: u32,
        ) -> i32;
    }
    fn child(name: &str) -> io::Result<()> {
        if name.is_empty() || name.contains(['/', '\\', ':']) || name == "." || name == ".." {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid child name",
            ));
        }
        Ok(())
    }
    impl Directory {
        pub fn open(path: &Path) -> io::Result<Self> {
            let absolute = if path.is_absolute() {
                path.to_path_buf()
            } else {
                std::env::current_dir()?.join(path)
            };
            let mut current = PathBuf::new();
            let mut parents = Vec::new();
            for part in absolute.components() {
                if matches!(part, Component::ParentDir) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Parent traversal is not allowed",
                    ));
                }
                current.push(part.as_os_str());
                if matches!(part, Component::Prefix(_)) {
                    continue;
                }
                let file = OpenOptions::new()
                    .access_mode(0x80)
                    .share_mode(3)
                    .custom_flags(0x02200000)
                    .open(&current)?;
                let meta = file.metadata()?;
                if !meta.is_dir() || meta.file_attributes() & 0x400 != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Unsafe directory",
                    ));
                }
                parents.push(file);
            }
            let root = OpenOptions::new()
                .access_mode(0x80000000 | 0x40000000)
                .share_mode(3)
                .custom_flags(0x02200000)
                .open(&absolute)?;
            parents.push(root);
            Ok(Self {
                path: absolute,
                _parents: parents,
            })
        }
        pub fn read(&self, name: &str) -> io::Result<Option<File>> {
            child(name)?;
            match OpenOptions::new()
                .read(true)
                .share_mode(1)
                .custom_flags(0x00200000)
                .open(self.path.join(name))
            {
                Ok(file) => Ok(Some(file)),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(error),
            }
        }
        pub fn sync(&self) -> io::Result<()> {
            self._parents
                .last()
                .ok_or_else(|| io::Error::other("No pinned root"))?
                .sync_all()
        }
        pub fn publish(&self, name: &str, bytes: &[u8]) -> io::Result<()> {
            child(name)?;
            let mut random = [0u8; 16];
            ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut random)
                .map_err(|_| io::Error::other("Randomness unavailable"))?;
            let temporary = self.path.join(format!(
                ".peakactivity-intent-{}.tmp",
                base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, random)
            ));
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .share_mode(0)
                .custom_flags(0x80200000)
                .open(&temporary)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            drop(file);
            let from = temporary
                .as_os_str()
                .encode_wide()
                .chain(Some(0))
                .collect::<Vec<_>>();
            let to = self.path.join(name);
            let to = to
                .as_os_str()
                .encode_wide()
                .chain(Some(0))
                .collect::<Vec<_>>();
            if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), 8) } == 0 {
                return Err(io::Error::last_os_error());
            }
            self.sync()
        }
        pub fn quarantine(&self, _bundle: &str, _create: bool) -> io::Result<Option<Self>> {
            Ok(None)
        }
        pub fn remove_verified(
            &self,
            _quarantine: Option<&Self>,
            id: &str,
            proof: Option<&SnapshotDeletionProofV1>,
        ) -> io::Result<Removal> {
            let name = format!("{id}.json");
            child(&name)?;
            let file = match OpenOptions::new()
                .access_mode(0x80000000 | 0x10000)
                .share_mode(1)
                .custom_flags(0x00200000)
                .open(self.path.join(name))
            {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    return Ok(Removal::Absent)
                }
                Err(error) => return Err(error),
            };
            let bytes = read_bytes(file.try_clone()?, ENVELOPE_BYTES)?;
            let object: SyncEnvelopeV1 = serde_json::from_slice(&bytes)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid object"))?;
            if object.object_id != id
                || object.validate().is_err()
                || !proof.is_some_and(|proof| proof.allows_object(&object))
            {
                return Ok(Removal::Conflict);
            }
            let delete = 1u8;
            if unsafe {
                SetFileInformationByHandle(
                    file.as_raw_handle(),
                    4,
                    &delete as *const u8 as *const c_void,
                    1,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            drop(file);
            Ok(Removal::Deleted)
        }
    }
}
#[cfg(not(any(unix, windows)))]
compile_error!("Backup deletion requires a supported pinned filesystem implementation");

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use aw_sync_e2ee::SyncObjectStoreV1;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    fn fixture() -> (
        std::path::PathBuf,
        VaultDataKeyV1,
        aw_sync_e2ee::EncryptedSyncSnapshotV1,
    ) {
        let path = std::env::temp_dir().join(format!(
            "peak-folder-fault-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let store = aw_sync_e2ee::FolderSyncObjectStoreV1::open(&path).unwrap();
        let key = aw_sync_e2ee::create_vault_data_key(
            &aw_sync_e2ee::generate_account_root_key().unwrap(),
            &URL_SAFE_NO_PAD.encode([1; 16]),
            1,
        )
        .unwrap()
        .0;
        let snapshot = aw_sync_e2ee::encrypt_snapshot(&key, &vec![7; 1_100_000]).unwrap();
        for object in &snapshot.envelopes {
            store.put_if_absent(object).unwrap();
        }
        (path, key, snapshot)
    }
    #[test]
    fn folder_delete_committed_full_intent_can_publish_after_a_source_piece_disappears() {
        let (path, key, snapshot) = fixture();
        let io = FolderBackupDeletionV1::open_existing(&path).unwrap();
        let proof = SnapshotDeletionProofV1::authenticate(&key, &snapshot).unwrap();
        let record = proof.seal(&key).unwrap();
        let fact = proof.fact().clone();
        let store =
            aw_datastore::Datastore::open_encrypted(":memory:".into(), "a".repeat(64)).unwrap();
        store
            .record_sync_backup_deletion_intent(
                store.get_sync_policy_context().unwrap().context_id,
                proof,
                "2026-10-14T12:00:00Z".into(),
            )
            .unwrap();
        std::fs::remove_file(path.join(format!("{}.json", snapshot.envelopes[0].object_id)))
            .unwrap();
        io.publish_accepted_intent(&key, &record).unwrap();
        let remaining = io.remaining(&fact).unwrap();
        assert_eq!(remaining.len(), 1);
        let resumed = SnapshotDeletionProofV1::resume(&key, &record, &remaining).unwrap();
        let result = io
            .delete_recorded(&key, Some(&resumed), &fact.bundle_sha256)
            .unwrap();
        assert_eq!(result.deleted, 1);
        assert_eq!(result.absent, 1);
        assert!(result.durable);
        store.close();
        drop(io);
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn folder_delete_directory_sync_refusal_before_io_preserves_every_object() {
        let (path, key, snapshot) = fixture();
        let io = FolderBackupDeletionV1::open_existing(&path).unwrap();
        let proof = SnapshotDeletionProofV1::authenticate(&key, &snapshot).unwrap();
        let hash = proof.fact().bundle_sha256.clone();
        io.persist_intent(&key, &proof).unwrap();
        platform::fail_sync_call(1);
        let refused = io.delete_recorded(&key, Some(&proof), &hash);
        platform::fail_sync_call(0);
        assert!(refused.is_err());
        for object in &snapshot.envelopes {
            assert!(path.join(format!("{}.json", object.object_id)).exists());
        }
        drop(io);
        std::fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn folder_delete_final_directory_sync_uncertainty_never_reports_durable_completion() {
        let (path, key, snapshot) = fixture();
        let io = FolderBackupDeletionV1::open_existing(&path).unwrap();
        let proof = SnapshotDeletionProofV1::authenticate(&key, &snapshot).unwrap();
        let hash = proof.fact().bundle_sha256.clone();
        io.persist_intent(&key, &proof).unwrap();
        platform::fail_sync_call(9);
        let outcome = io.delete_recorded(&key, Some(&proof), &hash).unwrap();
        platform::fail_sync_call(0);
        assert_eq!(outcome.deleted, 2);
        assert!(!outcome.durable);
        assert!(io.load_intent(&key, &hash).unwrap().is_some());
        let retry = io.delete_recorded(&key, None, &hash).unwrap();
        assert_eq!(retry.absent, 2);
        assert!(retry.durable);
        drop(io);
        std::fs::remove_dir_all(path).unwrap();
    }
}
