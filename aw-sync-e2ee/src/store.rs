use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use aw_models::{
    SyncEnvelopeV1, SyncRelayOperationV1, SyncRelayRequestV1, SyncRelayResponseV1,
    SyncWireErrorV1, SYNC_ID_BYTES, SYNC_MAX_CHUNK_BYTES,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use crate::crypto::fill_random;
use crate::SyncTombstoneDeletionPermitV1;
const MAX_ENVELOPE_JSON_BYTES: usize = SYNC_MAX_CHUNK_BYTES * 2;
const SYNC_RELAY_PAGE_SIZE: u16 = 16;
const MAX_SYNC_RELAY_PAGES: usize = 100_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncObjectStoreErrorV1 {
    InvalidObjectId,
    InvalidEnvelope,
    UnsafeDirectory,
    CorruptObject,
    ObjectConflict,
    PolicyDenied,
    Io,
    TransportUnavailable,
}

impl fmt::Display for SyncObjectStoreErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidObjectId => "invalid opaque sync object ID",
            Self::InvalidEnvelope => "invalid encrypted sync envelope",
            Self::UnsafeDirectory => "sync object directory is unsafe",
            Self::CorruptObject => "stored sync object is corrupt",
            Self::ObjectConflict => "sync object ID already contains different ciphertext",
            Self::PolicyDenied => "sync request was denied by consent or signed policy",
            Self::Io => "sync object storage is unavailable",
            Self::TransportUnavailable => "signed sync relay destination is unavailable",
        })
    }
}

impl std::error::Error for SyncObjectStoreErrorV1 {}

pub trait SyncObjectStoreV1: Send + Sync {
    fn put_if_absent(&self, envelope: &SyncEnvelopeV1) -> Result<bool, SyncObjectStoreErrorV1>;
    fn get(&self, object_id: &str) -> Result<Option<SyncEnvelopeV1>, SyncObjectStoreErrorV1>;
    fn list_opaque_heads(&self, vault_id: &str) -> Result<Vec<SyncEnvelopeV1>, SyncObjectStoreErrorV1>;
    fn delete_after_tombstone(
        &self,
        permit: &SyncTombstoneDeletionPermitV1,
    ) -> Result<bool, SyncObjectStoreErrorV1>;
}

/// The implementation must resolve destination and purpose through the signed
/// egress registry; this interface intentionally has no URL parameter.
pub trait SyncRelayTransportV1: Send + Sync {
    fn request(
        &self,
        destination_id: &str,
        purpose_id: &str,
        request: &SyncRelayRequestV1,
    ) -> Result<SyncRelayResponseV1, SyncObjectStoreErrorV1>;
}

pub struct SyncHttpObjectStoreV1<T> {
    destination_id: String,
    purpose_id: String,
    transport: T,
}

impl<T: SyncRelayTransportV1> SyncHttpObjectStoreV1<T> {
    pub fn new(
        destination_id: String,
        purpose_id: String,
        transport: T,
    ) -> Result<Self, SyncObjectStoreErrorV1> {
        if !valid_identifier(&destination_id) || !valid_identifier(&purpose_id) {
            return Err(SyncObjectStoreErrorV1::TransportUnavailable);
        }
        Ok(Self { destination_id, purpose_id, transport })
    }

    fn request(
        &self,
        request: SyncRelayRequestV1,
    ) -> Result<SyncRelayResponseV1, SyncObjectStoreErrorV1> {
        request.validate().map_err(|error| match error {
            SyncWireErrorV1::InvalidIdentifierLength | SyncWireErrorV1::InvalidBase64 => SyncObjectStoreErrorV1::InvalidObjectId,
            _ => SyncObjectStoreErrorV1::InvalidEnvelope,
        })?;
        let response = self.transport.request(&self.destination_id, &self.purpose_id, &request)?;
        response.validate_for(&request).map_err(|_| SyncObjectStoreErrorV1::CorruptObject)?;
        Ok(response)
    }
}

impl<T: SyncRelayTransportV1> SyncObjectStoreV1 for SyncHttpObjectStoreV1<T> {
    fn put_if_absent(&self, envelope: &SyncEnvelopeV1) -> Result<bool, SyncObjectStoreErrorV1> {
        envelope.validate().map_err(|_| SyncObjectStoreErrorV1::InvalidEnvelope)?;
        let response = self.request(SyncRelayRequestV1 {
            schema_version: 1,
            operation: SyncRelayOperationV1::PutIfAbsent,
            object_id: Some(envelope.object_id.clone()),
            vault_id: Some(envelope.vault_id.clone()),
            envelope: Some(envelope.clone()),
            cursor: None,
            limit: None,
        })?;
        if response.schema_version != 1 || response.envelope.is_some() || response.deleted.is_some()
            || response.next_cursor.is_some()
            || !response.objects.is_empty()
        {
            return Err(SyncObjectStoreErrorV1::CorruptObject);
        }
        response.inserted.ok_or(SyncObjectStoreErrorV1::CorruptObject)
    }

    fn get(&self, object_id: &str) -> Result<Option<SyncEnvelopeV1>, SyncObjectStoreErrorV1> {
        decode_id(object_id)?;
        let response = self.request(SyncRelayRequestV1 {
            schema_version: 1,
            operation: SyncRelayOperationV1::Get,
            object_id: Some(object_id.to_owned()),
            vault_id: None,
            envelope: None,
            cursor: None,
            limit: None,
        })?;
        if response.schema_version != 1 || response.inserted.is_some() || response.deleted.is_some()
            || response.next_cursor.is_some()
            || !response.objects.is_empty()
        {
            return Err(SyncObjectStoreErrorV1::CorruptObject);
        }
        match response.envelope {
            Some(envelope) if envelope.object_id == object_id => {
                envelope.validate().map_err(|_| SyncObjectStoreErrorV1::CorruptObject)?;
                Ok(Some(envelope))
            }
            Some(_) => Err(SyncObjectStoreErrorV1::CorruptObject),
            None => Ok(None),
        }
    }

    fn list_opaque_heads(&self, vault_id: &str) -> Result<Vec<SyncEnvelopeV1>, SyncObjectStoreErrorV1> {
        decode_id(vault_id)?;
        let mut objects = Vec::new();
        let mut cursor = None;
        for _ in 0..MAX_SYNC_RELAY_PAGES {
            let response = self.request(SyncRelayRequestV1 {
                schema_version: 1,
                operation: SyncRelayOperationV1::ListOpaqueHeads,
                object_id: None,
                vault_id: Some(vault_id.to_owned()),
                envelope: None,
                cursor: cursor.clone(),
                limit: Some(SYNC_RELAY_PAGE_SIZE),
            })?;
            if response.schema_version != 1 || response.inserted.is_some() || response.deleted.is_some()
                || response.envelope.is_some() || response.objects.len() > SYNC_RELAY_PAGE_SIZE as usize
            {
                return Err(SyncObjectStoreErrorV1::CorruptObject);
            }
            for envelope in &response.objects {
                envelope.validate().map_err(|_| SyncObjectStoreErrorV1::CorruptObject)?;
                if envelope.vault_id != vault_id
                    || cursor.as_ref().is_some_and(|last| envelope.object_id.as_str() <= last.as_str())
                {
                    return Err(SyncObjectStoreErrorV1::CorruptObject);
                }
            }
            objects.extend(response.objects);
            match response.next_cursor {
                Some(next) => {
                    decode_id(&next)?;
                    if objects.last().is_none_or(|last| last.object_id.as_str() != next) {
                        return Err(SyncObjectStoreErrorV1::CorruptObject);
                    }
                    cursor = Some(next);
                }
                None => return Ok(objects),
            }
        }
        Err(SyncObjectStoreErrorV1::TransportUnavailable)
    }

    fn delete_after_tombstone(
        &self,
        permit: &SyncTombstoneDeletionPermitV1,
    ) -> Result<bool, SyncObjectStoreErrorV1> {
        let object_id = permit.object_id();
        decode_id(object_id)?;
        let response = self.request(SyncRelayRequestV1 {
            schema_version: 1,
            operation: SyncRelayOperationV1::DeleteAfterTombstone,
            object_id: Some(object_id.to_owned()),
            vault_id: None,
            envelope: None,
            cursor: None,
            limit: None,
        })?;
        if response.schema_version != 1 || response.inserted.is_some()
            || response.envelope.is_some() || response.next_cursor.is_some() || !response.objects.is_empty()
        {
            return Err(SyncObjectStoreErrorV1::CorruptObject);
        }
        response.deleted.ok_or(SyncObjectStoreErrorV1::CorruptObject)
    }
}

pub struct FolderSyncObjectStoreV1 {
    root: PathBuf,
}

impl FolderSyncObjectStoreV1 {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SyncObjectStoreErrorV1> {
        let path = path.as_ref();
        if let Ok(metadata) = fs::symlink_metadata(path) {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(SyncObjectStoreErrorV1::UnsafeDirectory);
            }
        }
        fs::create_dir_all(path).map_err(|_| SyncObjectStoreErrorV1::Io)?;
        let root = fs::canonicalize(path).map_err(|_| SyncObjectStoreErrorV1::Io)?;
        let metadata = fs::symlink_metadata(&root).map_err(|_| SyncObjectStoreErrorV1::Io)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(SyncObjectStoreErrorV1::UnsafeDirectory);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                .map_err(|_| SyncObjectStoreErrorV1::Io)?;
        }
        Ok(Self { root })
    }

    fn object_path(&self, object_id: &str) -> Result<PathBuf, SyncObjectStoreErrorV1> {
        decode_id(object_id)?;
        Ok(self.root.join(format!("{object_id}.json")))
    }

    fn read_envelope(&self, path: &Path, expected_id: &str) -> Result<SyncEnvelopeV1, SyncObjectStoreErrorV1> {
        let metadata = fs::symlink_metadata(path).map_err(|_| SyncObjectStoreErrorV1::Io)?;
        if metadata.file_type().is_symlink() || !metadata.is_file()
            || metadata.len() as usize > MAX_ENVELOPE_JSON_BYTES
        {
            return Err(SyncObjectStoreErrorV1::CorruptObject);
        }
        let file = File::open(path).map_err(|_| SyncObjectStoreErrorV1::Io)?;
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take((MAX_ENVELOPE_JSON_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| SyncObjectStoreErrorV1::Io)?;
        if bytes.len() > MAX_ENVELOPE_JSON_BYTES {
            return Err(SyncObjectStoreErrorV1::CorruptObject);
        }
        let envelope: SyncEnvelopeV1 = serde_json::from_slice(&bytes)
            .map_err(|_| SyncObjectStoreErrorV1::CorruptObject)?;
        envelope.validate().map_err(|_| SyncObjectStoreErrorV1::CorruptObject)?;
        if envelope.object_id != expected_id {
            return Err(SyncObjectStoreErrorV1::CorruptObject);
        }
        Ok(envelope)
    }

    fn sync_directory(&self) -> Result<(), SyncObjectStoreErrorV1> {
        #[cfg(unix)]
        File::open(&self.root)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| SyncObjectStoreErrorV1::Io)?;
        // Windows publishes the temp file with MOVEFILE_WRITE_THROUGH below.
        Ok(())
    }
}

impl SyncObjectStoreV1 for FolderSyncObjectStoreV1 {
    fn put_if_absent(&self, envelope: &SyncEnvelopeV1) -> Result<bool, SyncObjectStoreErrorV1> {
        envelope.validate().map_err(|_| SyncObjectStoreErrorV1::InvalidEnvelope)?;
        let destination = self.object_path(&envelope.object_id)?;
        let bytes = serde_json::to_vec(envelope).map_err(|_| SyncObjectStoreErrorV1::InvalidEnvelope)?;
        if bytes.len() > MAX_ENVELOPE_JSON_BYTES {
            return Err(SyncObjectStoreErrorV1::InvalidEnvelope);
        }
        let mut random = [0u8; SYNC_ID_BYTES];
        fill_random(&mut random).map_err(|_| SyncObjectStoreErrorV1::Io)?;
        let temporary = self.root.join(format!(".{}.tmp", URL_SAFE_NO_PAD.encode(random)));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary).map_err(|_| SyncObjectStoreErrorV1::Io)?;
        let write = file.write_all(&bytes).and_then(|_| file.sync_all());
        drop(file);
        if write.is_err() {
            let _ = fs::remove_file(&temporary);
            return Err(SyncObjectStoreErrorV1::Io);
        }
        match publish_no_replace(&temporary, &destination) {
            Ok(()) => {
                self.sync_directory()?;
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let _ = fs::remove_file(&temporary);
                if self.read_envelope(&destination, &envelope.object_id)? == *envelope {
                    Ok(false)
                } else {
                    Err(SyncObjectStoreErrorV1::ObjectConflict)
                }
            }
            Err(_) => {
                let _ = fs::remove_file(&temporary);
                Err(SyncObjectStoreErrorV1::Io)
            }
        }
    }

    fn get(&self, object_id: &str) -> Result<Option<SyncEnvelopeV1>, SyncObjectStoreErrorV1> {
        let path = self.object_path(object_id)?;
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() => Err(SyncObjectStoreErrorV1::CorruptObject),
            Ok(_) => self.read_envelope(&path, object_id).map(Some),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(SyncObjectStoreErrorV1::Io),
        }
    }

    fn list_opaque_heads(&self, vault_id: &str) -> Result<Vec<SyncEnvelopeV1>, SyncObjectStoreErrorV1> {
        decode_id(vault_id)?;
        let mut objects = Vec::new();
        for entry in fs::read_dir(&self.root).map_err(|_| SyncObjectStoreErrorV1::Io)? {
            let entry = entry.map_err(|_| SyncObjectStoreErrorV1::Io)?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue; };
            let Some(object_id) = name.strip_suffix(".json") else { continue; };
            decode_id(object_id)?;
            let envelope = self.read_envelope(&entry.path(), object_id)?;
            if envelope.vault_id == vault_id {
                objects.push(envelope);
            }
        }
        objects.sort_by(|left, right| left.object_id.cmp(&right.object_id));
        Ok(objects)
    }

    fn delete_after_tombstone(
        &self,
        permit: &SyncTombstoneDeletionPermitV1,
    ) -> Result<bool, SyncObjectStoreErrorV1> {
        let object_id = permit.object_id();
        let path = self.object_path(object_id)?;
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() => Err(SyncObjectStoreErrorV1::CorruptObject),
            Ok(_) => {
                fs::remove_file(path).map_err(|_| SyncObjectStoreErrorV1::Io)?;
                self.sync_directory()?;
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(_) => Err(SyncObjectStoreErrorV1::Io),
        }
    }
}

fn publish_no_replace(source: &Path, destination: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        #[link(name = "kernel32")]
        extern "system" {
            fn MoveFileExW(source: *const u16, destination: *const u16, flags: u32) -> i32;
        }
        let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
        let destination: Vec<u16> = destination.as_os_str().encode_wide().chain(Some(0)).collect();
        // MOVEFILE_WRITE_THROUGH without MOVEFILE_REPLACE_EXISTING is atomic no-replace.
        if unsafe { MoveFileExW(source.as_ptr(), destination.as_ptr(), 8) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        fs::hard_link(source, destination)?;
        fs::remove_file(source)
    }
}

fn decode_id(value: &str) -> Result<[u8; SYNC_ID_BYTES], SyncObjectStoreErrorV1> {
    URL_SAFE_NO_PAD.decode(value).map_err(|_| SyncObjectStoreErrorV1::InvalidObjectId)?
        .try_into().map_err(|_| SyncObjectStoreErrorV1::InvalidObjectId)
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty() && value.len() <= 64 && value.bytes().enumerate().all(|(index, byte)| {
        byte.is_ascii_lowercase() || (index > 0 && (byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')))
    })
}
