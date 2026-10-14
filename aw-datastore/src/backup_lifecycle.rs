use crate::{DatastoreError, DatastoreInstance};
use aw_models::SnapshotDeletionFactV1;
use aw_sync_e2ee::SnapshotDeletionProofV1;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::DateTime;
use rusqlite::{params, Connection, OptionalExtension};
fn invalid() -> DatastoreError {
    DatastoreError::InternalError("Backup deletion is invalid, changed or protected".into())
}
impl DatastoreInstance {
    pub(crate) fn reject_deleted_backup_object(
        &self,
        conn: &Connection,
        id: &str,
    ) -> Result<(), DatastoreError> {
        let deleted = conn
            .query_row(
                "SELECT 1 FROM sync_backup_deleted_objects WHERE object_id=?1",
                [id],
                |_| Ok(()),
            )
            .optional()
            .map_err(|_| invalid())?
            .is_some();
        if deleted {
            return Err(invalid());
        }
        Ok(())
    }
    pub(crate) fn reject_deleted_backup_version(
        &self,
        conn: &Connection,
        vault: &str,
        epoch: u64,
        snapshot: &[u8; 16],
    ) -> Result<(), DatastoreError> {
        let deleted=conn.query_row("SELECT 1 FROM sync_backup_deletions WHERE vault_id=?1 AND key_epoch=?2 AND snapshot_id=?3",params![vault,epoch.to_string(),URL_SAFE_NO_PAD.encode(snapshot)],|_|Ok(())).optional().map_err(|_|invalid())?.is_some();
        if deleted {
            return Err(invalid());
        }
        Ok(())
    }
    pub(crate) fn get_sync_backup_deletion(
        &self,
        conn: &Connection,
        id: &str,
    ) -> Result<Option<SnapshotDeletionFactV1>, DatastoreError> {
        if !URL_SAFE_NO_PAD
            .decode(id)
            .is_ok_and(|bytes| bytes.len() == 16 && URL_SAFE_NO_PAD.encode(bytes) == id)
        {
            return Err(invalid());
        }
        let stored=conn.query_row("SELECT d.fact_json,o.envelope_sha256 FROM sync_backup_deleted_objects o LEFT JOIN sync_backup_deletions d USING(vault_id,key_epoch,snapshot_id,bundle_sha256) WHERE o.object_id=?1",[id],|row|Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?))).optional().map_err(|_|invalid())?;
        stored
            .map(|(raw, hash)| {
                let fact: SnapshotDeletionFactV1 =
                    serde_json::from_str(&raw).map_err(|_| invalid())?;
                if !fact
                    .objects
                    .iter()
                    .any(|o| o.object_id == id && o.envelope_sha256 == hash)
                {
                    return Err(invalid());
                }
                Ok(fact)
            })
            .transpose()
    }
    fn protect_current_backup(
        &self,
        conn: &Connection,
        fact: &SnapshotDeletionFactV1,
    ) -> Result<(), DatastoreError> {
        let current=conn.query_row("SELECT 1 FROM sync_snapshot_current p JOIN sync_snapshot_chunks c ON c.snapshot_id=p.snapshot_id WHERE c.vault_id=?1 AND CAST(c.key_epoch AS TEXT)=?2 AND p.snapshot_id=?3 LIMIT 1",params![fact.vault_id,fact.key_epoch,URL_SAFE_NO_PAD.decode(&fact.snapshot_id).map_err(|_|invalid())?],|_|Ok(())).optional().map_err(|_|invalid())?.is_some();
        if current {
            return Err(invalid());
        }
        for object in &fact.objects {
            if conn
                .query_row(
                    "SELECT 1 FROM sync_snapshot_chunks WHERE object_id=?1",
                    [&object.object_id],
                    |_| Ok(()),
                )
                .optional()
                .map_err(|_| invalid())?
                .is_some()
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
    pub(crate) fn record_sync_backup_deletion_intent(
        &self,
        conn: &Connection,
        context: &str,
        proof: &SnapshotDeletionProofV1,
        at: &str,
    ) -> Result<usize, DatastoreError> {
        self.deletion_context(context)?;
        if DateTime::parse_from_rfc3339(at).is_err() {
            return Err(invalid());
        }
        self.deletion_ledger_integrity(conn)?;
        let fact = proof.fact();
        fact.validate().map_err(|_| invalid())?;
        let existing=conn.query_row("SELECT rowid FROM sync_backup_deletions WHERE vault_id=?1 AND key_epoch=?2 AND snapshot_id=?3",params![fact.vault_id,fact.key_epoch,fact.snapshot_id],|row|row.get::<_,i64>(0)).optional().map_err(|_|invalid())?;
        if let Some(row) = existing {
            if self.checked_deletion_fact(conn, row)?.0 != *fact {
                return Err(invalid());
            }
        } else if !proof.is_complete() {
            return Err(invalid());
        }
        self.protect_current_backup(conn, fact)?;
        // An identical partial retry authorizes only external remaining bytes; local ciphertext stays untouched.
        if proof.is_complete() {
            for object in &fact.objects {
                if self
                    .get_sync_backup_object(conn, &object.object_id)?
                    .is_some_and(|envelope| !proof.allows_object(&envelope))
                {
                    return Err(invalid());
                }
            }
        }
        self.merge_sync_backup_deletions(conn, context, std::slice::from_ref(fact), at)
    }
    pub(crate) fn record_sync_backup_provider_intent(
        &self,
        conn: &Connection,
        context: &str,
        proof: &SnapshotDeletionProofV1,
        record: &aw_sync_e2ee::EncryptedSyncSnapshotV1,
        at: &str,
    ) -> Result<(), DatastoreError> {
        let raw = serde_json::to_string(record).map_err(|_| invalid())?;
        if raw.len() > 32 * 1024 * 1024 {
            return Err(invalid());
        }
        record.validate().map_err(|_| invalid())?;
        crate::datastore::with_savepoint(conn, "backup_provider_intent", || {
            self.record_sync_backup_deletion_intent(conn, context, proof, at)?;
            let fact = proof.fact();
            conn.execute("UPDATE sync_backup_deletions SET sealed_record_json=?1 WHERE vault_id=?2 AND key_epoch=?3 AND snapshot_id=?4 AND bundle_sha256=?5",
                params![raw,fact.vault_id,fact.key_epoch,fact.snapshot_id,fact.bundle_sha256]).map_err(|_|invalid())?;
            Ok(())
        })
    }
    pub(crate) fn get_sync_backup_provider_intent(
        &self,
        conn: &Connection,
        context: &str,
        bundle: &str,
    ) -> Result<Option<aw_sync_e2ee::EncryptedSyncSnapshotV1>, DatastoreError> {
        self.deletion_context(context)?;
        if bundle.len() != 64
            || !bundle
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(invalid());
        }
        let length:Option<Option<i64>>=conn.query_row("SELECT length(CAST(sealed_record_json AS BLOB)) FROM sync_backup_deletions WHERE bundle_sha256=?1",[bundle],|r|r.get(0)).optional().map_err(|_|invalid())?;
        let Some(Some(length)) = length else {
            return Ok(None);
        };
        if !(1..=32 * 1024 * 1024).contains(&length) {
            return Err(invalid());
        }
        let raw: String = conn
            .query_row(
                "SELECT sealed_record_json FROM sync_backup_deletions WHERE bundle_sha256=?1",
                [bundle],
                |r| r.get(0),
            )
            .map_err(|_| invalid())?;
        serde_json::from_str(&raw).map(Some).map_err(|_| invalid())
    }
    pub(crate) fn delete_sync_backup(
        &self,
        conn: &Connection,
        context: &str,
        proof: &SnapshotDeletionProofV1,
        at: &str,
    ) -> Result<usize, DatastoreError> {
        let actual: String = self
            .policy_context
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        if !self.encrypted || context != actual || DateTime::parse_from_rfc3339(at).is_err() {
            return Err(invalid());
        }
        let fact = proof.fact();
        fact.validate().map_err(|_| invalid())?;
        let existing=conn.query_row("SELECT fact_json FROM sync_backup_deletions WHERE vault_id=?1 AND key_epoch=?2 AND snapshot_id=?3",params![fact.vault_id,fact.key_epoch,fact.snapshot_id],|row|row.get::<_,String>(0)).optional().map_err(|_|invalid())?;
        if existing.as_ref().is_some_and(|raw| {
            serde_json::from_str::<SnapshotDeletionFactV1>(raw)
                .ok()
                .as_ref()
                != Some(fact)
        }) || (existing.is_none() && !proof.is_complete())
        {
            return Err(invalid());
        }
        self.protect_current_backup(conn, fact)?;
        let mut present = Vec::new();
        for object in &fact.objects {
            let stored = self.get_sync_backup_object(conn, &object.object_id)?;
            match stored {
                Some(envelope) if proof.allows_object(&envelope) => {
                    present.push(object.object_id.as_str())
                }
                None if existing.is_some() => {}
                _ => return Err(invalid()),
            }
            let marker=conn.query_row("SELECT envelope_sha256,vault_id,key_epoch,snapshot_id,bundle_sha256 FROM sync_backup_deleted_objects WHERE object_id=?1",[&object.object_id],|row|Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?,row.get::<_,String>(3)?,row.get::<_,String>(4)?))).optional().map_err(|_|invalid())?;
            if marker.is_some_and(|m| {
                m != (
                    object.envelope_sha256.clone(),
                    fact.vault_id.clone(),
                    fact.key_epoch.clone(),
                    fact.snapshot_id.clone(),
                    fact.bundle_sha256.clone(),
                )
            }) {
                return Err(invalid());
            }
        }
        if present.is_empty() {
            return Ok(0);
        }
        crate::datastore::with_savepoint(conn, "backup_version_delete", || {
            if existing.is_none() {
                let raw = serde_json::to_string(fact).map_err(|_| invalid())?;
                conn.execute("INSERT INTO sync_backup_deletions(vault_id,key_epoch,snapshot_id,bundle_sha256,fact_json,deleted_at) VALUES(?1,?2,?3,?4,?5,?6)",params![fact.vault_id,fact.key_epoch,fact.snapshot_id,fact.bundle_sha256,raw,at]).map_err(|_|invalid())?;
                for object in &fact.objects {
                    conn.execute("INSERT INTO sync_backup_deleted_objects(object_id,envelope_sha256,vault_id,key_epoch,snapshot_id,bundle_sha256) VALUES(?1,?2,?3,?4,?5,?6)",params![object.object_id,object.envelope_sha256,fact.vault_id,fact.key_epoch,fact.snapshot_id,fact.bundle_sha256]).map_err(|_|invalid())?;
                }
            }
            for id in &present {
                if conn
                    .execute("DELETE FROM sync_objects WHERE object_id=?1", [id])
                    .map_err(|_| invalid())?
                    != 1
                {
                    return Err(invalid());
                }
                conn.execute("INSERT INTO sync_object_history(object_id,action,occurred_at) VALUES(?1,'deleted',?2)",params![id,at]).map_err(|_|invalid())?;
            }
            Ok(present.len())
        })
    }
}

const PAGE_BYTES: usize = 32 * 1024 * 1024;
const FACT_BYTES: usize = 16 * 1024 * 1024;
const LEDGER_BYTES: usize = aw_sync_e2ee::MAX_BACKUP_BUNDLE_BYTES;
const LEDGER_ENTRIES: usize = aw_sync_e2ee::MAX_BACKUP_SCAN_OBJECTS;
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncBackupDeletionCursorV1 {
    pub context_id: String,
    pub after_row: String,
    pub through_row: String,
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct SyncBackupDeletionPageV1 {
    pub context_id: String,
    pub facts: Vec<SnapshotDeletionFactV1>,
    pub next_cursor: Option<SyncBackupDeletionCursorV1>,
}
fn row_number(value: &str) -> Result<i64, DatastoreError> {
    let n = value.parse::<i64>().map_err(|_| invalid())?;
    if n < 0 || n.to_string() != value {
        return Err(invalid());
    }
    Ok(n)
}
impl DatastoreInstance {
    fn deletion_context(&self, expected: &str) -> Result<String, DatastoreError> {
        let actual: String = self
            .policy_context
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        if !self.encrypted || expected != actual {
            return Err(invalid());
        }
        Ok(actual)
    }
    fn deletion_ledger_integrity(&self, conn: &Connection) -> Result<(), DatastoreError> {
        if conn.query_row("SELECT 1 FROM sync_backup_deleted_objects o LEFT JOIN sync_backup_deletions d USING(vault_id,key_epoch,snapshot_id,bundle_sha256) WHERE d.vault_id IS NULL LIMIT 1",[],|_|Ok(())).optional().map_err(|_|invalid())?.is_some(){return Err(invalid());}
        Ok(())
    }
    fn checked_deletion_fact(
        &self,
        conn: &Connection,
        row_id: i64,
    ) -> Result<(SnapshotDeletionFactV1, usize), DatastoreError> {
        let (length,vault,epoch,snapshot,bundle):(i64,String,String,String,String)=conn.query_row("SELECT length(CAST(fact_json AS BLOB)),vault_id,key_epoch,snapshot_id,bundle_sha256 FROM sync_backup_deletions WHERE rowid=?1",[row_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).map_err(|_|invalid())?;
        if length < 0 || length as usize > FACT_BYTES {
            return Err(invalid());
        }
        let raw: String = conn
            .query_row(
                "SELECT fact_json FROM sync_backup_deletions WHERE rowid=?1",
                [row_id],
                |r| r.get(0),
            )
            .map_err(|_| invalid())?;
        let fact: SnapshotDeletionFactV1 = serde_json::from_str(&raw).map_err(|_| invalid())?;
        if (
            &fact.vault_id,
            &fact.key_epoch,
            &fact.snapshot_id,
            &fact.bundle_sha256,
        ) != (&vault, &epoch, &snapshot, &bundle)
        {
            return Err(invalid());
        }
        let mut children=conn.prepare_cached("SELECT object_id,envelope_sha256 FROM sync_backup_deleted_objects WHERE vault_id=?1 AND key_epoch=?2 AND snapshot_id=?3 AND bundle_sha256=?4").map_err(|_|invalid())?;
        let rows = children
            .query_map(params![vault, epoch, snapshot, bundle], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })
            .map_err(|_| invalid())?;
        let expected: std::collections::BTreeMap<_, _> = fact
            .objects
            .iter()
            .map(|o| (o.object_id.as_str(), o.envelope_sha256.as_str()))
            .collect();
        let mut count = 0;
        for row in rows {
            let (id, hash) = row.map_err(|_| invalid())?;
            count += 1;
            if count > expected.len() || expected.get(id.as_str()) != Some(&hash.as_str()) {
                return Err(invalid());
            }
        }
        if count != expected.len() {
            return Err(invalid());
        }
        Ok((fact, raw.len()))
    }
    pub(crate) fn list_sync_backup_deletions(
        &self,
        conn: &Connection,
        context: &str,
        cursor: Option<&SyncBackupDeletionCursorV1>,
        limit: usize,
    ) -> Result<SyncBackupDeletionPageV1, DatastoreError> {
        let context = self.deletion_context(context)?;
        if !(1..=64).contains(&limit) {
            return Err(invalid());
        }
        self.deletion_ledger_integrity(conn)?;
        let max_row: i64 = conn
            .query_row(
                "SELECT COALESCE(MAX(rowid),0) FROM sync_backup_deletions",
                [],
                |r| r.get(0),
            )
            .map_err(|_| invalid())?;
        let (after, through) = if let Some(cursor) = cursor {
            if cursor.context_id != context {
                return Err(invalid());
            }
            let after = row_number(&cursor.after_row)?;
            let through = row_number(&cursor.through_row)?;
            if after > through || through > max_row {
                return Err(invalid());
            }
            (after, through)
        } else {
            (0, max_row)
        };
        let mut query=conn.prepare_cached("SELECT rowid FROM sync_backup_deletions WHERE rowid>?1 AND rowid<=?2 ORDER BY rowid LIMIT ?3").map_err(|_|invalid())?;
        let rows = query
            .query_map(params![after, through, (limit + 1) as i64], |r| {
                r.get::<_, i64>(0)
            })
            .map_err(|_| invalid())?;
        let mut facts = Vec::new();
        let mut bytes = 0usize;
        let mut entries = 0usize;
        let mut last = after;
        let mut more = false;
        for row in rows {
            let id = row.map_err(|_| invalid())?;
            if facts.len() == limit {
                more = true;
                break;
            }
            let (fact, size) = self.checked_deletion_fact(conn, id)?;
            let next_bytes = bytes.checked_add(size).ok_or_else(invalid)?;
            let next_entries = entries
                .checked_add(fact.objects.len())
                .ok_or_else(invalid)?;
            if next_bytes > PAGE_BYTES || next_entries > LEDGER_ENTRIES {
                if facts.is_empty() {
                    return Err(invalid());
                }
                more = true;
                break;
            }
            bytes = next_bytes;
            entries = next_entries;
            last = id;
            facts.push(fact);
        }
        Ok(SyncBackupDeletionPageV1 {
            context_id: context.clone(),
            facts,
            next_cursor: more.then(|| SyncBackupDeletionCursorV1 {
                context_id: context,
                after_row: last.to_string(),
                through_row: through.to_string(),
            }),
        })
    }
    pub(crate) fn export_sync_backup_deletions(
        &self,
        conn: &Connection,
        context: &str,
    ) -> Result<Vec<SnapshotDeletionFactV1>, DatastoreError> {
        let mut cursor = None;
        let mut output = Vec::new();
        let mut bytes = 0usize;
        let mut entries = 0usize;
        loop {
            let page = self.list_sync_backup_deletions(conn, context, cursor.as_ref(), 64)?;
            for fact in page.facts {
                bytes = bytes
                    .checked_add(serde_json::to_vec(&fact).map_err(|_| invalid())?.len())
                    .ok_or_else(invalid)?;
                entries = entries
                    .checked_add(fact.objects.len())
                    .ok_or_else(invalid)?;
                if bytes > LEDGER_BYTES
                    || entries > LEDGER_ENTRIES
                    || output.len() >= LEDGER_ENTRIES
                {
                    return Err(invalid());
                }
                output.push(fact);
            }
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        Ok(output)
    }
    // Receive metadata only after authenticated recovery or signed-manifest admission; this never erases ciphertext.
    pub(crate) fn merge_sync_backup_deletions(
        &self,
        conn: &Connection,
        context: &str,
        facts: &[SnapshotDeletionFactV1],
        at: &str,
    ) -> Result<usize, DatastoreError> {
        self.deletion_context(context)?;
        if DateTime::parse_from_rfc3339(at).is_err() || facts.len() > LEDGER_ENTRIES {
            return Err(invalid());
        }
        self.deletion_ledger_integrity(conn)?;
        let admitted = admitted_backup_deletion_facts(facts)?;
        crate::datastore::with_savepoint(conn, "backup_fact_merge", || {
            let mut inserted = 0;
            for fact in admitted {
                let identity = (&fact.vault_id, &fact.key_epoch, &fact.snapshot_id);
                let existing=conn.query_row("SELECT rowid FROM sync_backup_deletions WHERE vault_id=?1 AND key_epoch=?2 AND snapshot_id=?3",params![identity.0,identity.1,identity.2],|r|r.get::<_,i64>(0)).optional().map_err(|_|invalid())?;
                if let Some(id) = existing {
                    if self.checked_deletion_fact(conn, id)?.0 != *fact {
                        return Err(invalid());
                    }
                    continue;
                }
                for object in &fact.objects {
                    if conn
                        .query_row(
                            "SELECT 1 FROM sync_backup_deleted_objects WHERE object_id=?1",
                            [&object.object_id],
                            |_| Ok(()),
                        )
                        .optional()
                        .map_err(|_| invalid())?
                        .is_some()
                    {
                        return Err(invalid());
                    }
                }
                let raw = serde_json::to_string(fact).map_err(|_| invalid())?;
                conn.execute("INSERT INTO sync_backup_deletions(vault_id,key_epoch,snapshot_id,bundle_sha256,fact_json,deleted_at) VALUES(?1,?2,?3,?4,?5,?6)",params![fact.vault_id,fact.key_epoch,fact.snapshot_id,fact.bundle_sha256,raw,at]).map_err(|_|invalid())?;
                for object in &fact.objects {
                    conn.execute("INSERT INTO sync_backup_deleted_objects(object_id,envelope_sha256,vault_id,key_epoch,snapshot_id,bundle_sha256) VALUES(?1,?2,?3,?4,?5,?6)",params![object.object_id,object.envelope_sha256,fact.vault_id,fact.key_epoch,fact.snapshot_id,fact.bundle_sha256]).map_err(|_|invalid())?;
                }
                inserted += 1;
            }
            Ok(inserted)
        })
    }
}

pub(crate) fn admitted_backup_deletion_facts(
    facts: &[SnapshotDeletionFactV1],
) -> Result<Vec<&SnapshotDeletionFactV1>, DatastoreError> {
    if facts.len() > LEDGER_ENTRIES {
        return Err(invalid());
    }
    let mut versions = std::collections::BTreeMap::new();
    let mut ownership = std::collections::BTreeMap::new();
    let mut bytes = 0usize;
    let mut entries = 0usize;
    for fact in facts {
        fact.validate().map_err(|_| invalid())?;
        bytes = bytes
            .checked_add(serde_json::to_vec(fact).map_err(|_| invalid())?.len())
            .ok_or_else(invalid)?;
        entries = entries
            .checked_add(fact.objects.len())
            .ok_or_else(invalid)?;
        if bytes > LEDGER_BYTES || entries > LEDGER_ENTRIES {
            return Err(invalid());
        }
        let identity = (&fact.vault_id, &fact.key_epoch, &fact.snapshot_id);
        if let Some(previous) = versions.insert(identity, fact) {
            if previous != fact {
                return Err(invalid());
            }
        }
        for object in &fact.objects {
            let value = (&object.envelope_sha256, identity, &fact.bundle_sha256);
            if ownership
                .insert(&object.object_id, value)
                .is_some_and(|previous| previous != value)
            {
                return Err(invalid());
            }
        }
    }
    let mut seen = std::collections::BTreeSet::new();
    Ok(facts
        .iter()
        .filter(|fact| seen.insert((&fact.vault_id, &fact.key_epoch, &fact.snapshot_id)))
        .collect())
}

impl DatastoreInstance {
    pub(crate) fn ensure_sync_backup_not_deleted(
        &self,
        conn: &Connection,
        context: &str,
        vault: &str,
        epoch: u64,
        snapshot: &str,
        objects: &[String],
    ) -> Result<(), DatastoreError> {
        self.deletion_context(context)?;
        let snapshot_id: [u8; 16] = URL_SAFE_NO_PAD
            .decode(snapshot)
            .map_err(|_| invalid())?
            .try_into()
            .map_err(|_| invalid())?;
        if URL_SAFE_NO_PAD.encode(snapshot_id) != snapshot
            || objects.is_empty()
            || objects.len() > LEDGER_ENTRIES
        {
            return Err(invalid());
        }
        self.reject_deleted_backup_version(conn, vault, epoch, &snapshot_id)?;
        for id in objects {
            aw_models::SyncChunkHeaderV1 {
                schema_version: 1,
                object_id: id.clone(),
                vault_id: vault.into(),
                key_epoch: epoch,
            }
            .validate()
            .map_err(|_| invalid())?;
            self.reject_deleted_backup_object(conn, id)?;
        }
        Ok(())
    }
}

impl DatastoreInstance {
    pub(crate) fn flush_pending_backup_forgets(
        &self,
        conn: &Connection,
    ) -> Result<(), DatastoreError> {
        let (device, epoch) = self.local_sync_writer(conn)?;
        let context = self.deletion_context(
            &self
                .policy_context
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
        )?;
        let facts = self.export_sync_backup_deletions(conn, &context)?;
        if facts.is_empty() {
            return Ok(());
        }
        let writer = URL_SAFE_NO_PAD.encode(device);
        let operations = self
            .all_sync_operations_for_epoch(conn, epoch)?
            .into_iter()
            .filter(|op| op.device_id == writer)
            .collect::<Vec<_>>();
        let published =
            aw_sync_e2ee::assemble_backup_forget_operations(&operations).map_err(|_| invalid())?;
        let known = published
            .iter()
            .map(|fact| ((&fact.vault_id, &fact.key_epoch, &fact.snapshot_id), fact))
            .collect::<std::collections::BTreeMap<_, _>>();
        for fact in facts {
            if known
                .get(&(&fact.vault_id, &fact.key_epoch, &fact.snapshot_id))
                .copied()
                == Some(&fact)
            {
                continue;
            }
            let counter = self.next_sync_operation_counter(conn, &device)?;
            for operation in aw_sync_e2ee::create_backup_forget_operations(device, counter, &fact)
                .map_err(|_| invalid())?
            {
                self.store_local_sync_operation(conn, device, epoch, &operation)?;
            }
        }
        self.check_sync_operation_history_bound(conn, epoch)?;
        Ok(())
    }
}

/// Captured only from a verified encrypted worker/file; never admitted from JSON or IPC.
#[derive(Debug, Default)]
pub struct SyncBackupContinuityV1 {
    pub(crate) facts: Vec<SnapshotDeletionFactV1>,
    pub(crate) records: Vec<(
        SnapshotDeletionFactV1,
        aw_sync_e2ee::EncryptedSyncSnapshotV1,
    )>,
}
impl DatastoreInstance {
    pub(crate) fn export_sync_backup_continuity(
        &self,
        conn: &Connection,
        context: &str,
    ) -> Result<SyncBackupContinuityV1, DatastoreError> {
        let facts = self.export_sync_backup_deletions(conn, context)?;
        let columns = conn
            .prepare("PRAGMA table_info(sync_backup_deletions)")
            .map_err(|_| invalid())?
            .query_map([], |r| r.get::<_, String>(1))
            .map_err(|_| invalid())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| invalid())?;
        if !columns.iter().any(|c| c == "sealed_record_json") {
            return Ok(SyncBackupContinuityV1 {
                facts,
                records: Vec::new(),
            });
        }
        let mut records = Vec::new();
        let mut bytes = 0usize;
        for fact in &facts {
            if let Some(record) =
                self.get_sync_backup_provider_intent(conn, context, &fact.bundle_sha256)?
            {
                record.validate().map_err(|_| invalid())?;
                bytes = bytes
                    .checked_add(serde_json::to_vec(&record).map_err(|_| invalid())?.len())
                    .ok_or_else(invalid)?;
                if bytes > LEDGER_BYTES {
                    return Err(invalid());
                }
                records.push((fact.clone(), record));
            }
        }
        Ok(SyncBackupContinuityV1 { facts, records })
    }
    pub(crate) fn merge_sync_backup_continuity(
        &self,
        conn: &Connection,
        context: &str,
        continuity: SyncBackupContinuityV1,
        at: &str,
    ) -> Result<(), DatastoreError> {
        self.deletion_context(context)?;
        let mut bytes = 0usize;
        let mut admitted = Vec::new();
        let known=continuity.facts.iter().map(|f|((f.vault_id.as_str(),f.key_epoch.as_str(),f.snapshot_id.as_str()),f)).collect::<std::collections::BTreeMap<_,_>>();
        for (fact, record) in continuity.records {
            if known.get(&(fact.vault_id.as_str(),fact.key_epoch.as_str(),fact.snapshot_id.as_str())).copied()!=Some(&fact) {
                return Err(invalid());
            }
            record.validate().map_err(|_| invalid())?;
            let raw = serde_json::to_string(&record).map_err(|_| invalid())?;
            bytes = bytes.checked_add(raw.len()).ok_or_else(invalid)?;
            if raw.len() > 32 * 1024 * 1024 || bytes > LEDGER_BYTES {
                return Err(invalid());
            }
            admitted.push((fact, record, raw));
        }
        crate::datastore::with_savepoint(conn, "backup_continuity", || {
            self.merge_sync_backup_deletions(conn, context, &continuity.facts, at)?;
            for (fact, _record, raw) in admitted {
                if let Some(existing) =
                    self.get_sync_backup_provider_intent(conn, context, &fact.bundle_sha256)?
                {
                    // Both records came from verified protected databases; randomized seals differ legitimately.
                    existing.validate().map_err(|_| invalid())?;
                } else {
                    conn.execute("UPDATE sync_backup_deletions SET sealed_record_json=?1 WHERE vault_id=?2 AND key_epoch=?3 AND snapshot_id=?4 AND bundle_sha256=?5",params![raw,fact.vault_id,fact.key_epoch,fact.snapshot_id,fact.bundle_sha256]).map_err(|_|invalid())?;
                }
            }
            Ok(())
        })
    }
}
