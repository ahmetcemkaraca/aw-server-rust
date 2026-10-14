use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SnapshotDeletionObjectV1 {
    pub object_id: String,
    pub envelope_sha256: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SnapshotDeletionFactV1 {
    pub schema_version: u32,
    pub vault_id: String,
    pub key_epoch: String,
    pub snapshot_id: String,
    pub bundle_sha256: String,
    pub objects: Vec<SnapshotDeletionObjectV1>,
}
fn id(v: &str) -> bool {
    URL_SAFE_NO_PAD
        .decode(v)
        .is_ok_and(|bytes| bytes.len() == 16 && URL_SAFE_NO_PAD.encode(bytes) == v)
}
fn hash(v: &str) -> bool {
    v.len() == 64
        && v.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl SnapshotDeletionFactV1 {
    pub fn validate(&self) -> Result<(), crate::SyncWireErrorV1> {
        let epoch = self.key_epoch.parse::<u64>().ok();
        let mut ids = BTreeSet::new();
        if self.schema_version != 1
            || !id(&self.vault_id)
            || !id(&self.snapshot_id)
            || epoch.is_none_or(|epoch| epoch == 0 || epoch.to_string() != self.key_epoch)
            || !hash(&self.bundle_sha256)
            || self.objects.is_empty()
            || self.objects.len() > 100000
            || self.objects.iter().any(|o| {
                !id(&o.object_id) || !hash(&o.envelope_sha256) || !ids.insert(&o.object_id)
            })
        {
            return Err(crate::SyncWireErrorV1::InvalidSyncRequest);
        }
        Ok(())
    }
}
fn record<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<T, D::Error> {
    struct Object<T>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for Object<T> {
        type Value = T;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a backup deletion metadata object")
        }
        fn visit_map<M: serde::de::MapAccess<'de>>(self, map: M) -> Result<T, M::Error> {
            T::deserialize(serde::de::value::MapAccessDeserializer::new(map))
        }
    }
    d.deserialize_map(Object(std::marker::PhantomData))
}
impl<'de> Deserialize<'de> for SnapshotDeletionObjectV1 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            object_id: String,
            envelope_sha256: String,
        }
        let wire: Wire = record(d)?;
        if !id(&wire.object_id) || !hash(&wire.envelope_sha256) {
            return Err(serde::de::Error::custom("Invalid backup deletion object"));
        }
        Ok(Self {
            object_id: wire.object_id,
            envelope_sha256: wire.envelope_sha256,
        })
    }
}
impl<'de> Deserialize<'de> for SnapshotDeletionFactV1 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            schema_version: u32,
            vault_id: String,
            key_epoch: String,
            snapshot_id: String,
            bundle_sha256: String,
            objects: Vec<SnapshotDeletionObjectV1>,
        }
        let wire: Wire = record(d)?;
        let fact = Self {
            schema_version: wire.schema_version,
            vault_id: wire.vault_id,
            key_epoch: wire.key_epoch,
            snapshot_id: wire.snapshot_id,
            bundle_sha256: wire.bundle_sha256,
            objects: wire.objects,
        };
        fact.validate()
            .map_err(|_| serde::de::Error::custom("Invalid backup deletion fact"))?;
        Ok(fact)
    }
}

pub const BACKUP_FORGET_OBJECTS_PER_FRAGMENT: usize = 2000;
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BackupForgetFragmentV1 {
    pub schema_version: u32,
    pub fact_sha256: String,
    pub vault_id: String,
    pub key_epoch: String,
    pub snapshot_id: String,
    pub bundle_sha256: String,
    pub fragment_index: u32,
    pub fragment_count: u32,
    pub total_objects: u32,
    pub objects: Vec<SnapshotDeletionObjectV1>,
}
impl BackupForgetFragmentV1 {
    pub fn validate(&self) -> Result<(), crate::SyncWireErrorV1> {
        let total = self.total_objects as usize;
        let width = BACKUP_FORGET_OBJECTS_PER_FRAGMENT;
        if total == 0
            || total > 100000
            || !hash(&self.fact_sha256)
            || self.fragment_count as usize != total.div_ceil(width)
            || self.fragment_index >= self.fragment_count
            || self.objects.len()
                != width.min(total.saturating_sub(self.fragment_index as usize * width))
        {
            return Err(crate::SyncWireErrorV1::InvalidSyncRequest);
        }
        self.partial_fact().validate()
    }
    pub fn partial_fact(&self) -> SnapshotDeletionFactV1 {
        SnapshotDeletionFactV1 {
            schema_version: self.schema_version,
            vault_id: self.vault_id.clone(),
            key_epoch: self.key_epoch.clone(),
            snapshot_id: self.snapshot_id.clone(),
            bundle_sha256: self.bundle_sha256.clone(),
            objects: self.objects.clone(),
        }
    }
}
impl<'de> Deserialize<'de> for BackupForgetFragmentV1 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            schema_version: u32,
            fact_sha256: String,
            vault_id: String,
            key_epoch: String,
            snapshot_id: String,
            bundle_sha256: String,
            fragment_index: u32,
            fragment_count: u32,
            total_objects: u32,
            objects: Vec<SnapshotDeletionObjectV1>,
        }
        let w: Wire = record(d)?;
        let value = Self {
            schema_version: w.schema_version,
            fact_sha256: w.fact_sha256,
            vault_id: w.vault_id,
            key_epoch: w.key_epoch,
            snapshot_id: w.snapshot_id,
            bundle_sha256: w.bundle_sha256,
            fragment_index: w.fragment_index,
            fragment_count: w.fragment_count,
            total_objects: w.total_objects,
            objects: w.objects,
        };
        value
            .validate()
            .map_err(|_| serde::de::Error::custom("Invalid backup forget fragment"))?;
        Ok(value)
    }
}
