pub(crate) const REPORT_LIBRARY_KEY: &str = "reports.library.v1";

use aw_models::{PortableReportPackV1, ReportImportPreviewResponseV1, ReportPortableExportV1};
use aw_models::{
    ReportExecutionErrorV1 as Error, ReportFeatureAccessV1, ReportLibraryV1,
    UpdateReportLibraryRequestV1,
};
use rusqlite::{Connection, TransactionBehavior};
use std::{fmt, sync::Arc};

pub fn report_calculation_sha256(
    categories: &[aw_models::ReportCategoryV1],
) -> Result<String, Error> {
    calculation_sha256(categories, None)
}
fn calculation_sha256(
    categories: &[aw_models::ReportCategoryV1],
    control: Option<&aw_models::QueryControl>,
) -> Result<String, Error> {
    use serde::Serialize;
    #[derive(Serialize)]
    struct Rule<'a> {
        #[serde(skip_serializing_if = "Option::is_none")]
        ignore_case: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        regex: Option<&'a str>,
        #[serde(rename = "type")]
        kind: &'static str,
    }
    #[derive(Serialize)]
    struct Category<'a> {
        name: &'a [String],
        rule: Rule<'a>,
    }
    struct Digest(ring::digest::Context);
    impl std::io::Write for Digest {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    if categories.len() > 1000 {
        return Err(Error::StaleConfiguration);
    }
    let mut digest = Digest(ring::digest::Context::new(&ring::digest::SHA256));
    digest.0.update(b"PeakActivity:report-category-rules:v1\0[");
    for (index, c) in categories.iter().enumerate() {
        if let Some(control) = control {
            control.charge_fuel(1)?;
        }
        if c.name.is_empty()
            || c.name.len() > 8
            || !c.name.iter().all(|s| aw_models::valid_report_label(s, 128))
        {
            return Err(Error::StaleConfiguration);
        }
        let rule = if c.rule.kind == Some(aw_models::ReportRuleTypeV1::Regex) {
            let regex = c
                .rule
                .regex
                .as_deref()
                .filter(|s| s.len() <= 4096)
                .ok_or(Error::StaleConfiguration)?;
            Rule {
                kind: "regex",
                regex: Some(regex),
                ignore_case: Some(c.rule.ignore_case.unwrap_or(false)),
            }
        } else {
            Rule {
                kind: "none",
                regex: None,
                ignore_case: None,
            }
        };
        if index > 0 {
            digest.0.update(b",");
        }
        serde_json::to_writer(
            &mut digest,
            &Category {
                name: &c.name,
                rule,
            },
        )
        .map_err(|_| Error::DataIntegrity)?;
    }
    digest.0.update(b"]");
    Ok(digest
        .0
        .finish()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

const IMPORT_KEYS: [&str; 4] = [
    "settings.category_sets",
    "settings.active_set_ids",
    "settings.classes",
    REPORT_LIBRARY_KEY,
];
struct ReportImportBeforeV1 {
    values: [Option<String>; 4],
}
pub struct PreparedReportImportV1 {
    preview: ReportImportPreviewResponseV1,
    _payload: PortableReportPackV1,
    before: ReportImportBeforeV1,
    after: [Option<String>; 4],
    expires: std::time::Instant,
}
impl PreparedReportImportV1 {
    pub fn preview(&self) -> &ReportImportPreviewResponseV1 {
        &self.preview
    }
}
impl fmt::Debug for PreparedReportImportV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<private report import>")
    }
}
pub(crate) enum ReportResponseV1 {
    Library(ReportLibraryV1),
    Prepared(Arc<PreparedReportImportV1>),
    Export(ReportPortableExportV1),
    Inputs(Arc<aw_models::ReportInputSnapshotV1>),
}
impl fmt::Debug for ReportResponseV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<private report response>")
    }
}
#[derive(Clone)]
pub(crate) enum ReportOperationV1 {
    Library,
    Prepare(PortableReportPackV1, Arc<dyn ReportFeatureAccessV1>),
    Commit(Arc<PreparedReportImportV1>, Arc<dyn ReportFeatureAccessV1>),
    Export(bool),
    Inputs(
        aw_models::AdvancedReportRunRequestV1,
        Arc<aw_models::QueryControl>,
        Arc<dyn ReportFeatureAccessV1>,
    ),
    Update(UpdateReportLibraryRequestV1, Arc<dyn ReportFeatureAccessV1>),
}
impl fmt::Debug for ReportOperationV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<private report operation>")
    }
}
impl ReportOperationV1 {
    pub(crate) fn owns_transaction(&self) -> bool {
        matches!(
            self,
            Self::Update(_, _) | Self::Prepare(_, _) | Self::Commit(_, _) | Self::Inputs(_, _, _)
        )
    }
    pub(crate) fn read(&self, conn: &Connection) -> Result<ReportResponseV1, Error> {
        match self {
            Self::Library => load_library(conn).map(ReportResponseV1::Library),
            Self::Export(include) => export_library(conn, *include).map(ReportResponseV1::Export),
            _ => Err(Error::InternalError),
        }
    }
    pub(crate) fn execute_owned(
        self,
        conn: &mut Connection,
        ds: &crate::DatastoreInstance,
    ) -> Result<ReportResponseV1, Error> {
        match self {
            Self::Update(request, access) => {
                update_library(conn, request, access.as_ref()).map(ReportResponseV1::Library)
            }
            Self::Prepare(package, access) => {
                prepare_import(conn, package, access.as_ref()).map(ReportResponseV1::Prepared)
            }
            Self::Inputs(request, control, access) => {
                read_inputs(conn, request, control, access.as_ref()).map(ReportResponseV1::Inputs)
            }
            Self::Commit(prepared, access) => {
                commit_import(conn, ds, &prepared, access.as_ref()).map(ReportResponseV1::Library)
            }
            _ => Err(Error::InternalError),
        }
    }
}

fn matches_value(conn: &Connection, key: &str, expected: Option<&str>) -> Result<bool, Error> {
    let mut statement = conn
        .prepare("SELECT value FROM key_value WHERE key=?1")
        .map_err(|_| Error::DataIntegrity)?;
    let mut rows = statement.query([key]).map_err(|_| Error::DataIntegrity)?;
    let Some(row) = rows.next().map_err(|_| Error::DataIntegrity)? else {
        return Ok(expected.is_none());
    };
    let current = row
        .get_ref(0)
        .map_err(|_| Error::DataIntegrity)?
        .as_str()
        .map_err(|_| Error::DataIntegrity)?;
    Ok(expected == Some(current))
}
pub(crate) fn load_library(conn: &Connection) -> Result<ReportLibraryV1, Error> {
    let mut statement = conn
        .prepare("SELECT value FROM key_value WHERE key=?1")
        .map_err(|_| Error::DataIntegrity)?;
    let mut rows = statement
        .query([REPORT_LIBRARY_KEY])
        .map_err(|_| Error::DataIntegrity)?;
    let Some(row) = rows.next().map_err(|_| Error::DataIntegrity)? else {
        return Ok(ReportLibraryV1::default());
    };
    let serialized = row
        .get_ref(0)
        .map_err(|_| Error::DataIntegrity)?
        .as_str()
        .map_err(|_| Error::DataIntegrity)?;
    if serialized.len() > aw_models::REPORT_LIBRARY_MAX_BYTES_V1 {
        return Err(Error::ByteLimit);
    }
    let library: ReportLibraryV1 =
        serde_json::from_str(serialized).map_err(|_| Error::DataIntegrity)?;
    library.validate().map_err(|_| Error::DataIntegrity)?;
    Ok(library)
}
fn surviving<T: PartialEq>(current: &[T], next: &[T]) -> bool {
    let mut old = current.iter();
    next.iter().all(|item| old.any(|prior| prior == item))
}
fn removal(current: &ReportLibraryV1, next: &ReportLibraryV1) -> bool {
    surviving(&current.templates, &next.templates)
        && surviving(&current.rule_packs, &next.rule_packs)
}
fn check_versions(current: &ReportLibraryV1, next: &ReportLibraryV1) -> Result<(), Error> {
    for t in &next.templates {
        let expected = match current.templates.iter().find(|old| old.id == t.id) {
            None => 1,
            Some(old) => {
                let mut content = t.clone();
                content.content_version = old.content_version;
                if content == *old {
                    old.content_version
                } else {
                    old.content_version
                        .checked_add(1)
                        .ok_or(Error::StaleConfiguration)?
                }
            }
        };
        if expected != t.content_version {
            return Err(Error::StaleConfiguration);
        }
    }
    for p in &next.rule_packs {
        let expected = match current.rule_packs.iter().find(|old| old.id == p.id) {
            None => 1,
            Some(old) => {
                let mut content = p.clone();
                content.content_version = old.content_version;
                if content == *old {
                    old.content_version
                } else {
                    old.content_version
                        .checked_add(1)
                        .ok_or(Error::StaleConfiguration)?
                }
            }
        };
        if expected != p.content_version {
            return Err(Error::StaleConfiguration);
        }
    }
    Ok(())
}
pub(crate) fn write_value(conn: &Connection, key: &str, data: &str) -> Result<(), Error> {
    conn.execute(
        "INSERT OR REPLACE INTO key_value(key,value,last_modified) VALUES(?1,?2,?3)",
        rusqlite::params![key, data, chrono::Utc::now().timestamp()],
    )
    .map_err(|_| Error::DataIntegrity)?;
    Ok(())
}
fn update_library(
    conn: &mut Connection,
    request: UpdateReportLibraryRequestV1,
    access: &dyn ReportFeatureAccessV1,
) -> Result<ReportLibraryV1, Error> {
    request.validate()?;
    let current = load_library(conn)?;
    if current.revision != request.expected_revision {
        return Err(Error::StaleConfiguration);
    }
    let free = current == request.library || removal(&current, &request.library);
    let mut output = None;
    let action = || {
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| Error::DataIntegrity)?;
        let current = load_library(&tx)?;
        if current.revision != request.expected_revision {
            return Err(Error::StaleConfiguration);
        }
        if current == request.library {
            output = Some(current);
            tx.commit().map_err(|_| Error::DataIntegrity)?;
            return Ok(());
        }
        if free && !removal(&current, &request.library) {
            return Err(Error::StaleConfiguration);
        }
        check_versions(&current, &request.library)?;
        let mut next = request.library;
        next.revision = current
            .revision
            .checked_add(1)
            .ok_or(Error::StaleConfiguration)?;
        next.validate()?;
        let serialized = serde_json::to_string(&next).map_err(|_| Error::DataIntegrity)?;
        write_value(&tx, REPORT_LIBRARY_KEY, &serialized)?;
        tx.commit().map_err(|_| Error::DataIntegrity)?;
        output = Some(next);
        Ok(())
    };
    if free {
        action()?;
    } else {
        access.with_access(Box::new(action))?;
    }
    output.ok_or(Error::InternalError)
}

use aw_models::{
    QueryControl, ReportCategoryV1, ReportImportKindV1, ReportImportMappingV1,
    ReportPortableCategorySetV1,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    time::{Duration, Instant},
};

// Count the encoded representation before allocating retained copies.
fn charge_serialized(value: &impl Serialize, control: &QueryControl) -> Result<(), Error> {
    struct Counter<'a>(&'a QueryControl);
    impl std::io::Write for Counter<'_> {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0
                .charge_bytes(bytes.len() as u64)
                .map_err(|_| std::io::Error::other("report limit"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(Counter(control), value)
        .map_err(|_| control.checkpoint().err().unwrap_or(Error::DataIntegrity))
}
fn encode(value: &impl Serialize, control: &QueryControl) -> Result<String, Error> {
    charge_serialized(value, control)?;
    serde_json::to_string(value).map_err(|_| Error::DataIntegrity)
}
fn bounded_value(
    conn: &Connection,
    key: &str,
    control: &QueryControl,
) -> Result<Option<String>, Error> {
    let mut statement = conn
        .prepare("SELECT value FROM key_value WHERE key=?1")
        .map_err(|_| Error::DataIntegrity)?;
    let mut rows = statement.query([key]).map_err(|_| Error::DataIntegrity)?;
    let Some(row) = rows.next().map_err(|_| Error::DataIntegrity)? else {
        return Ok(None);
    };
    let borrowed = row
        .get_ref(0)
        .map_err(|_| Error::DataIntegrity)?
        .as_str()
        .map_err(|_| Error::DataIntegrity)?;
    if key == REPORT_LIBRARY_KEY && borrowed.len() > aw_models::REPORT_LIBRARY_MAX_BYTES_V1 {
        return Err(Error::ByteLimit);
    }
    control.charge_bytes(borrowed.len() as u64)?;
    Ok(Some(borrowed.to_owned()))
}

// Decode dynamic JSON with one shared admission budget, including escaped strings and keys.
pub(crate) fn decode_json(text: &str, control: &QueryControl) -> Result<serde_json::Value, Error> {
    use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
    struct Seed<'a> {
        control: &'a QueryControl,
        depth: usize,
    }
    struct Key<'a>(&'a QueryControl);
    fn failure<E: de::Error>(r: Result<(), Error>) -> Result<(), E> {
        r.map_err(E::custom)
    }
    impl<'de> DeserializeSeed<'de> for Key<'_> {
        type Value = String;
        fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<String, D::Error> {
            failure(self.0.charge_values(1))?;
            failure(self.0.charge_bytes(std::mem::size_of::<String>() as u64))?;
            struct Text<'a>(&'a QueryControl);
            impl Visitor<'_> for Text<'_> {
                type Value = String;
                fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str("an object key")
                }
                fn visit_str<E: de::Error>(self, s: &str) -> Result<String, E> {
                    failure(self.0.charge_bytes(s.len() as u64))?;
                    Ok(s.to_owned())
                }
                fn visit_string<E: de::Error>(self, s: String) -> Result<String, E> {
                    failure(self.0.charge_bytes(s.len() as u64))?;
                    Ok(s)
                }
            }
            d.deserialize_string(Text(self.0))
        }
    }
    impl<'de> DeserializeSeed<'de> for Seed<'_> {
        type Value = serde_json::Value;
        fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
            if self.depth > 64 {
                return Err(de::Error::custom("report nesting limit"));
            }
            failure(self.control.charge_fuel(1))?;
            failure(self.control.charge_values(1))?;
            failure(
                self.control
                    .charge_bytes(std::mem::size_of::<serde_json::Value>() as u64),
            )?;
            d.deserialize_any(self)
        }
    }
    impl<'de> Visitor<'de> for Seed<'_> {
        type Value = serde_json::Value;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("bounded report JSON")
        }
        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(serde_json::Value::Null)
        }
        fn visit_bool<E: de::Error>(self, n: bool) -> Result<Self::Value, E> {
            Ok(n.into())
        }
        fn visit_i64<E: de::Error>(self, n: i64) -> Result<Self::Value, E> {
            Ok(n.into())
        }
        fn visit_u64<E: de::Error>(self, n: u64) -> Result<Self::Value, E> {
            Ok(n.into())
        }
        fn visit_f64<E: de::Error>(self, n: f64) -> Result<Self::Value, E> {
            serde_json::Number::from_f64(n)
                .map(serde_json::Value::Number)
                .ok_or_else(|| E::custom("nonfinite report number"))
        }
        fn visit_str<E: de::Error>(self, s: &str) -> Result<Self::Value, E> {
            failure(self.control.charge_bytes(s.len() as u64))?;
            Ok(s.into())
        }
        fn visit_string<E: de::Error>(self, s: String) -> Result<Self::Value, E> {
            failure(self.control.charge_bytes(s.len() as u64))?;
            Ok(s.into())
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut values = Vec::new();
            while let Some(value) = seq.next_element_seed(Seed {
                control: self.control,
                depth: self.depth + 1,
            })? {
                values.push(value);
            }
            Ok(serde_json::Value::Array(values))
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut values = serde_json::Map::new();
            while let Some(key) = map.next_key_seed(Key(self.control))? {
                if values.contains_key(&key) {
                    return Err(de::Error::custom("duplicate report field"));
                }
                let value = map.next_value_seed(Seed {
                    control: self.control,
                    depth: self.depth + 1,
                })?;
                values.insert(key, value);
            }
            Ok(serde_json::Value::Object(values))
        }
    }
    control.charge_bytes(text.len() as u64)?;
    let mut decoder = serde_json::Deserializer::from_str(text);
    let value = Seed { control, depth: 1 }
        .deserialize(&mut decoder)
        .map_err(|_| control.checkpoint().err().unwrap_or(Error::DataIntegrity))?;
    decoder.end().map_err(|_| Error::DataIntegrity)?;
    Ok(value)
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredReportCategorySetV1 {
    pub(crate) id: String,
    pub(crate) categories: Vec<ReportCategoryV1>,
}
pub(crate) fn resolve_category_sets(
    raw: Option<&str>,
    legacy: Option<&str>,
    control: &QueryControl,
) -> Result<Vec<StoredReportCategorySetV1>, Error> {
    let value = match raw {
        Some(raw) => decode_json(raw, control)?,
        None => serde_json::Value::Null,
    };
    let mut sets: Vec<StoredReportCategorySetV1> = if value.is_null() {
        Vec::new()
    } else {
        let array = value.as_array().ok_or(Error::StaleConfiguration)?;
        if !array.iter().all(serde_json::Value::is_object) {
            return Err(Error::StaleConfiguration);
        }
        serde_json::from_value(value).map_err(|_| Error::StaleConfiguration)?
    };
    if sets.is_empty() {
        let categories = match legacy {
            Some(raw) => {
                let value = decode_json(raw, control)?;
                if value.is_null() {
                    decode_json(aw_models::REPORT_DEFAULT_CATEGORIES_JSON_V1, control)?
                } else {
                    value
                }
            }
            None => decode_json(aw_models::REPORT_DEFAULT_CATEGORIES_JSON_V1, control)?,
        };
        let categories: Vec<ReportCategoryV1> =
            serde_json::from_value(categories).map_err(|_| Error::StaleConfiguration)?;
        sets.push(StoredReportCategorySetV1 {
            id: "default".into(),
            categories,
        });
    }
    for set in &sets {
        if !aw_models::valid_report_label(&set.id, 128) {
            return Err(Error::StaleConfiguration);
        }
        calculation_sha256(&set.categories, Some(control))?;
    }
    Ok(sets)
}
pub(crate) fn resolve_active_sets(
    raw: Option<&str>,
    sets: &[StoredReportCategorySetV1],
    control: &QueryControl,
) -> Result<Vec<String>, Error> {
    let active = match raw {
        Some(raw) => decode_json(raw, control)?,
        None => serde_json::Value::Null,
    };
    let active: Vec<String> = if active.is_null() {
        Vec::new()
    } else {
        serde_json::from_value(active).map_err(|_| Error::StaleConfiguration)?
    };
    if !active
        .iter()
        .all(|id| aw_models::valid_report_label(id, 128))
    {
        return Err(Error::StaleConfiguration);
    }
    Ok(if active.is_empty() {
        vec![sets[0].id.clone()]
    } else {
        active
    })
}
fn fresh_id(
    original: &str,
    reserved: &mut BTreeSet<String>,
    max: usize,
    control: &QueryControl,
) -> Result<String, Error> {
    control.charge_bytes((original.len() + std::mem::size_of::<String>()) as u64)?;
    for number in 1..=reserved.len() + 1 {
        control.charge_fuel(1)?;
        let suffix = format!("-import-{number}");
        let mut prefix = original.len().min(max - suffix.len());
        while !original.is_char_boundary(prefix) {
            prefix -= 1;
        }
        control
            .charge_bytes((2 * (prefix + suffix.len()) + std::mem::size_of::<String>()) as u64)?;
        let id = format!("{}{suffix}", &original[..prefix]);
        if reserved.insert(id.clone()) {
            return Ok(id);
        }
    }
    Err(Error::InternalError)
}
fn import_id(
    kind: ReportImportKindV1,
    id: &str,
    reserved: &mut BTreeSet<String>,
    collisions: &BTreeSet<String>,
    max: usize,
    mappings: &mut Vec<ReportImportMappingV1>,
    control: &QueryControl,
) -> Result<String, Error> {
    control
        .charge_bytes((id.len() + 2 * max + std::mem::size_of::<ReportImportMappingV1>()) as u64)?;
    let to_id = if collisions.contains(id) {
        fresh_id(id, reserved, max, control)?
    } else {
        id.to_owned()
    };
    mappings.push(ReportImportMappingV1 {
        kind,
        from_id: id.into(),
        to_id: to_id.clone(),
    });
    Ok(to_id)
}
fn prepare_import(
    conn: &mut Connection,
    package: PortableReportPackV1,
    access: &dyn ReportFeatureAccessV1,
) -> Result<Arc<PreparedReportImportV1>, Error> {
    package.validate()?;
    if package.templates.is_empty()
        && package.rule_packs.is_empty()
        && package.category_sets.is_empty()
    {
        return Err(Error::StaleConfiguration);
    }
    let mut output = None;
    access.with_access(Box::new(|| {
        let control = QueryControl::managed();
        control.begin_execution()?;
        charge_serialized(&package, &control)?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(|_| Error::DataIntegrity)?;
        let mut prior = [None, None, None, None];
        for (index, key) in IMPORT_KEYS.iter().enumerate() {
            prior[index] = bounded_value(&tx, key, &control)?;
        }
        let library: ReportLibraryV1 = match prior[3].as_deref() {
            Some(raw) => {
                if raw.len() > aw_models::REPORT_LIBRARY_MAX_BYTES_V1 {
                    return Err(Error::ByteLimit);
                }
                serde_json::from_value(decode_json(raw, &control)?)
                    .map_err(|_| Error::DataIntegrity)?
            }
            None => ReportLibraryV1::default(),
        };
        library.validate().map_err(|_| Error::DataIntegrity)?;
        let mut sets = resolve_category_sets(prior[0].as_deref(), prior[2].as_deref(), &control)?;
        let virtual_baseline = match prior[0].as_deref() {
            None => true,
            Some(raw) => {
                let value = decode_json(raw, &control)?;
                value.is_null() || value.as_array().is_some_and(Vec::is_empty)
            }
        };
        let active = if virtual_baseline {
            vec!["default".into()]
        } else {
            resolve_active_sets(prior[1].as_deref(), &sets, &control)?
        };
        for (id, copies) in sets
            .iter()
            .map(|s| (&s.id, 2))
            .chain(library.rule_packs.iter().map(|p| (&p.id, 2)))
            .chain(library.templates.iter().map(|t| (&t.id, 2)))
            .chain(package.category_sets.iter().map(|s| (&s.id, 1)))
            .chain(package.rule_packs.iter().map(|p| (&p.id, 1)))
            .chain(package.templates.iter().map(|t| (&t.id, 1)))
        {
            control.charge_bytes(((id.len() + std::mem::size_of::<String>()) * copies) as u64)?;
        }
        let set_collisions = sets.iter().map(|s| s.id.clone()).collect::<BTreeSet<_>>();
        let pack_collisions = library
            .rule_packs
            .iter()
            .map(|p| p.id.clone())
            .collect::<BTreeSet<_>>();
        let template_collisions = library
            .templates
            .iter()
            .map(|t| t.id.clone())
            .collect::<BTreeSet<_>>();
        let mut set_ids = set_collisions.clone();
        set_ids.extend(package.category_sets.iter().map(|s| s.id.clone()));
        let mut pack_ids = pack_collisions.clone();
        pack_ids.extend(package.rule_packs.iter().map(|p| p.id.clone()));
        let mut template_ids = template_collisions.clone();
        template_ids.extend(package.templates.iter().map(|t| t.id.clone()));
        let mut mappings = Vec::new();
        charge_serialized(&package, &control)?;
        for set in &package.category_sets {
            let id = import_id(
                ReportImportKindV1::CategorySet,
                &set.id,
                &mut set_ids,
                &set_collisions,
                128,
                &mut mappings,
                &control,
            )?;
            sets.push(StoredReportCategorySetV1 {
                id,
                categories: set.classes.clone(),
            });
        }
        let mut proposal = library;
        for pack in &package.rule_packs {
            let mut imported = pack.clone();
            imported.id = import_id(
                ReportImportKindV1::RulePack,
                &pack.id,
                &mut pack_ids,
                &pack_collisions,
                64,
                &mut mappings,
                &control,
            )?;
            imported.content_version = 1;
            for reference in &mut imported.category_sets {
                if let Some(set) = package
                    .category_sets
                    .iter()
                    .find(|set| set.id == reference.id)
                {
                    if calculation_sha256(&set.classes, Some(&control))?
                        != reference.calculation_sha256
                    {
                        return Err(Error::StaleConfiguration);
                    }
                    reference.id = mappings
                        .iter()
                        .find(|m| {
                            m.kind == ReportImportKindV1::CategorySet && m.from_id == reference.id
                        })
                        .ok_or(Error::InternalError)?
                        .to_id
                        .clone();
                }
            }
            proposal.rule_packs.push(imported);
        }
        for template in &package.templates {
            let mut imported = template.clone();
            imported.id = import_id(
                ReportImportKindV1::Template,
                &template.id,
                &mut template_ids,
                &template_collisions,
                64,
                &mut mappings,
                &control,
            )?;
            imported.content_version = 1;
            if let Some(pin) = &mut imported.rule_pack {
                pin.id = mappings
                    .iter()
                    .find(|m| m.kind == ReportImportKindV1::RulePack && m.from_id == pin.id)
                    .ok_or(Error::StaleConfiguration)?
                    .to_id
                    .clone();
                pin.content_version = 1;
            }
            proposal.templates.push(imported);
        }
        proposal.revision = proposal
            .revision
            .checked_add(1)
            .ok_or(Error::StaleConfiguration)?;
        proposal.validate()?;
        let mut after = [
            Some(encode(&sets, &control)?),
            Some(encode(&active, &control)?),
            None,
            Some(encode(&proposal, &control)?),
        ];
        if !virtual_baseline {
            // Preserve the exact existing nonempty selection; only an absent/empty selection is materialized.
            if let Some(raw) = prior[1].as_deref() {
                let value = decode_json(raw, &control)?;
                if value.as_array().is_some_and(|ids| !ids.is_empty()) {
                    control.charge_bytes(raw.len() as u64)?;
                    after[1] = Some(raw.into());
                }
            }
        }
        if let Some(raw) = prior[2].as_deref() {
            control.charge_bytes(raw.len() as u64)?;
            after[2] = Some(raw.into());
        }
        let mut nonce = [0; 16];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut nonce)
            .map_err(|_| Error::InternalError)?;
        let preview = ReportImportPreviewResponseV1 {
            schema_version: 1,
            preview_id: nonce.iter().map(|b| format!("{b:02x}")).collect(),
            mappings,
            proposed_library: proposal,
            expires_in_seconds: 120,
        };
        preview.validate()?;
        charge_serialized(&preview, &control)?;
        charge_serialized(&preview.proposed_library, &control)?;
        tx.commit().map_err(|_| Error::DataIntegrity)?;
        output = Some(Arc::new(PreparedReportImportV1 {
            preview,
            _payload: package,
            before: ReportImportBeforeV1 { values: prior },
            after,
            expires: Instant::now() + Duration::from_secs(120),
        }));
        Ok(())
    }))?;
    output.ok_or(Error::InternalError)
}
fn commit_import(
    conn: &mut Connection,
    ds: &crate::DatastoreInstance,
    prepared: &PreparedReportImportV1,
    access: &dyn ReportFeatureAccessV1,
) -> Result<ReportLibraryV1, Error> {
    if Instant::now() >= prepared.expires {
        return Err(Error::StaleConfiguration);
    }
    access.with_access(Box::new(|| {
        if Instant::now() >= prepared.expires {
            return Err(Error::StaleConfiguration);
        }
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| Error::DataIntegrity)?;
        for (index, key) in IMPORT_KEYS.iter().enumerate() {
            if !matches_value(&tx, key, prepared.before.values[index].as_deref())? {
                return Err(Error::StaleConfiguration);
            }
        }
        for (index, key) in IMPORT_KEYS.iter().enumerate() {
            if prepared.after[index] != prepared.before.values[index] {
                match &prepared.after[index] {
                    Some(raw) if *key != REPORT_LIBRARY_KEY => ds
                        .insert_key_value(&tx, key, raw)
                        .map_err(|_| Error::DataIntegrity)?,
                    Some(raw) => write_value(&tx, key, raw)?,
                    None if *key != REPORT_LIBRARY_KEY => ds
                        .delete_key_value(&tx, key)
                        .map_err(|_| Error::DataIntegrity)?,
                    None => {
                        tx.execute("DELETE FROM key_value WHERE key=?1", [key])
                            .map_err(|_| Error::DataIntegrity)?;
                    }
                }
            }
        }
        tx.commit().map_err(|_| Error::DataIntegrity)
    }))?;
    Ok(prepared.preview.proposed_library.clone())
}
fn export_library(conn: &Connection, include: bool) -> Result<ReportPortableExportV1, Error> {
    let control = QueryControl::managed();
    let library = load_library(conn)?;
    charge_serialized(&library, &control)?;
    let mut result = ReportPortableExportV1 {
        schema_version: 1,
        package: PortableReportPackV1 {
            schema_version: 1,
            templates: library.templates,
            rule_packs: library.rule_packs,
            category_sets: Vec::new(),
        },
        unavailable_set_ids: Vec::new(),
    };
    if include {
        let sets_raw = bounded_value(conn, IMPORT_KEYS[0], &control)?;
        let classes = bounded_value(conn, IMPORT_KEYS[2], &control)?;
        let sets = match resolve_category_sets(sets_raw.as_deref(), classes.as_deref(), &control) {
            Ok(sets) => sets,
            Err(Error::StaleConfiguration | Error::DataIntegrity) => Vec::new(),
            Err(error) => return Err(error),
        };
        let mut seen = BTreeSet::new();
        for pack in &result.package.rule_packs {
            for reference in &pack.category_sets {
                if !seen.insert(reference.id.clone()) {
                    continue;
                }
                if let Some(set) = sets.iter().find(|s| s.id == reference.id) {
                    if calculation_sha256(&set.categories, Some(&control))?
                        == reference.calculation_sha256
                    {
                        charge_serialized(&set.categories, &control)?;
                        let name = set
                            .id
                            .chars()
                            .scan(0, |bytes, c| {
                                *bytes += c.len_utf8();
                                (*bytes <= 80).then_some(c)
                            })
                            .collect();
                        result
                            .package
                            .category_sets
                            .push(ReportPortableCategorySetV1 {
                                id: set.id.clone(),
                                name,
                                classes: set.categories.clone(),
                            });
                        continue;
                    }
                }
                result.unavailable_set_ids.push(reference.id.clone());
            }
        }
    }
    result.validate()?;
    charge_serialized(&result, &control)?;
    Ok(result)
}

struct ReportProgress<'a>(&'a Connection);
impl<'a> ReportProgress<'a> {
    fn install(conn: &'a Connection, control: Arc<QueryControl>) -> Self {
        conn.progress_handler(1000, Some(move || control.charge_fuel(1000).is_err()));
        Self(conn)
    }
}
impl Drop for ReportProgress<'_> {
    fn drop(&mut self) {
        self.0.progress_handler(0, None::<fn() -> bool>);
    }
}
fn read_inputs(
    conn: &mut Connection,
    request: aw_models::AdvancedReportRunRequestV1,
    control: Arc<QueryControl>,
    access: &dyn ReportFeatureAccessV1,
) -> Result<Arc<aw_models::ReportInputSnapshotV1>, Error> {
    use aw_models::{
        ReportEffectiveRuleV1, ReportInputBucketV1, ReportInputPeriodV1, ReportInputSnapshotV1,
        ReportSourceV1,
    };
    use std::collections::BTreeMap;
    request.validate()?;
    if !control.is_managed() {
        return Err(Error::StaleConfiguration);
    }
    control.begin_execution()?;
    let mut output = None;
    access.with_access(Box::new(||{
        control.checkpoint()?;charge_serialized(&request,&control)?;
        control.charge_values((request.current_periods.len()+request.previous_periods.as_ref().map_or(0,Vec::len)+request.ordered_host_ids.len()) as u64)?;
        let tx=conn.transaction_with_behavior(TransactionBehavior::Deferred).map_err(|_|Error::DataIntegrity)?;
        let progress=ReportProgress::install(&tx,control.clone());
        let captured_at=chrono::Utc::now();
        let raw=bounded_value(&tx,REPORT_LIBRARY_KEY,&control)?.ok_or(Error::StaleConfiguration)?;
        if raw.len()>aw_models::REPORT_LIBRARY_MAX_BYTES_V1 {return Err(Error::ByteLimit);}
        let library:ReportLibraryV1=serde_json::from_value(decode_json(&raw,&control)?).map_err(|_|Error::DataIntegrity)?;
        library.validate().map_err(|_|Error::DataIntegrity)?;
        if library.revision!=request.expected_library_revision {return Err(Error::StaleConfiguration);}
        let selected=library.templates.iter().find(|t|t.id==request.template_id).ok_or(Error::StaleConfiguration)?;
        charge_serialized(selected,&control)?;let template=selected.clone();
        let rule_pack=if let Some(pin)=&template.rule_pack {
            let pack=library.rule_packs.iter().find(|p|p.id==pin.id && p.content_version==pin.content_version).ok_or(Error::StaleConfiguration)?;
            charge_serialized(pack,&control)?;Some(pack.clone())
        } else {None};
        let sets_raw=bounded_value(&tx,IMPORT_KEYS[0],&control)?;
        let legacy=bounded_value(&tx,IMPORT_KEYS[2],&control)?;
        let sets=resolve_category_sets(sets_raw.as_deref(),legacy.as_deref(),&control)?;
        let active=if let Some(pack)=&rule_pack {
            control.charge_bytes(pack.category_sets.iter().map(|r|(r.id.len()+std::mem::size_of::<String>()) as u64).sum())?;
            let mut ids=Vec::new();
            for reference in &pack.category_sets {
                control.charge_values(1)?;control.charge_fuel(1)?;
                let set=sets.iter().find(|s|s.id==reference.id).ok_or(Error::StaleConfiguration)?;
                if calculation_sha256(&set.categories,Some(&control))?!=reference.calculation_sha256 {return Err(Error::StaleConfiguration);}
                ids.push(reference.id.clone());
            }
            ids
        } else {
            let raw=bounded_value(&tx,IMPORT_KEYS[1],&control)?;
            // The virtual default ignores a persisted selection, just like the free loader.
            let virtual_default=match sets_raw.as_deref() {None=>true,Some(raw)=>{let value=decode_json(raw,&control)?;value.is_null()||value.as_array().is_some_and(Vec::is_empty)}};
            if virtual_default {vec!["default".into()]} else {resolve_active_sets(raw.as_deref(),&sets,&control)?}
        };
        let mut seen=BTreeSet::new();let mut effective_rules=Vec::new();
        for id in &active {
            let Some(set)=sets.iter().find(|s|s.id==*id) else {continue;};
            for (index,category) in set.categories.iter().enumerate() {
                control.charge_fuel(1)?;
                if seen.contains(&category.name) {continue;}
                charge_serialized(category,&control)?;
                control.charge_values(2)?;control.charge_bytes((std::mem::size_of::<ReportEffectiveRuleV1>()+std::mem::size_of::<&Vec<String>>()+id.len()) as u64)?;
                seen.insert(&category.name);
                let mut rule=category.rule.clone();
                if rule.kind!=Some(aw_models::ReportRuleTypeV1::Regex) {rule=aw_models::ReportCategoryRuleV1 {kind:Some(aw_models::ReportRuleTypeV1::None),regex:None,ignore_case:None};}
                effective_rules.push(ReportEffectiveRuleV1 {set_id:id.clone(),category_path:category.name.clone(),rule_index:index as u64,rule});
            }
        }
        report_parent_baseline(&mut effective_rules,&control)?;
        let mut available=BTreeMap::new();
        {
            let error=|_|control.checkpoint().err().unwrap_or(Error::DataIntegrity);
            let mut statement=tx.prepare("SELECT id,name,type FROM buckets WHERE type IN ('currentwindow','afkstatus') ORDER BY name").map_err(error)?;
            let mut rows=statement.query([]).map_err(error)?;
            while let Some(row)=rows.next().map_err(error)? {
                control.charge_fuel(1)?;control.charge_values(1)?;
                let id:i64=row.get(0).map_err(error)?;
                let name=row.get_ref(1).map_err(error)?.as_str().map_err(|_|Error::DataIntegrity)?;
                let kind=row.get_ref(2).map_err(error)?.as_str().map_err(|_|Error::DataIntegrity)?;
                if name.len()>1024 {return Err(Error::ByteLimit);}
                control.charge_bytes((name.len()+kind.len()+std::mem::size_of::<(String,(i64,String))>()) as u64)?;
                available.insert(name.to_owned(),(id,kind.to_owned()));
            }
        }
        let mut sources=Vec::new();
        for host in &request.ordered_host_ids {
            control.charge_values(1)?;control.charge_bytes((3*host.len()+"aw-watcher-window_".len()+"aw-watcher-afk_".len()+std::mem::size_of::<ReportSourceV1>()) as u64)?;
            let window_bucket_id=format!("aw-watcher-window_{host}");let afk_bucket_id=format!("aw-watcher-afk_{host}");
            if available.get(&window_bucket_id).is_none_or(|(_,kind)|kind!="currentwindow") || available.get(&afk_bucket_id).is_none_or(|(_,kind)|kind!="afkstatus") {return Err(Error::SourceUnavailable);}
            sources.push(ReportSourceV1 {host_id:host.clone(),window_bucket_id,afk_bucket_id});
        }
        let mut input_periods=Vec::new();
        for period in request.current_periods.iter().chain(request.previous_periods.iter().flatten()) {
            control.checkpoint()?;
            let (start,end)=period.bounds()?;
            let start_ns=start.timestamp_nanos_opt().ok_or(Error::StaleConfiguration)?;
            let end_ns=end.timestamp_nanos_opt().ok_or(Error::StaleConfiguration)?;
            control.charge_values(1)?;control.charge_bytes((std::mem::size_of::<ReportInputPeriodV1>()+period.local_date.len()+period.interval.len()) as u64)?;
            let mut buckets=Vec::new();
            for source in &sources {
                for id in [&source.window_bucket_id,&source.afk_bucket_id] {
                    control.checkpoint()?;
                    let bucketrow=available.get(id).ok_or(Error::SourceUnavailable)?.0;
                    let events=crate::DatastoreInstance::read_report_events(&tx,bucketrow,start_ns,end_ns,&control)?;
                    control.charge_values(1)?;control.charge_bytes((std::mem::size_of::<ReportInputBucketV1>()+id.len()) as u64)?;
                    buckets.push(ReportInputBucketV1 {bucket_id:id.clone(),rows:events.len() as u64,events});
                }
            }
            input_periods.push(ReportInputPeriodV1 {period:period.clone(),buckets});
        }
        let mut available_source_buckets=Vec::new();
        for id in available.keys() {control.charge_values(1)?;control.charge_bytes((std::mem::size_of::<String>()+id.len()) as u64)?;available_source_buckets.push(id.clone());}
        control.checkpoint()?;drop(progress);tx.commit().map_err(|_|Error::DataIntegrity)?;
        control.charge_values(1)?;control.charge_bytes(std::mem::size_of::<ReportInputSnapshotV1>() as u64)?;
        output=Some(Arc::new(ReportInputSnapshotV1 {library_revision:library.revision,request,template,rule_pack,effective_rules,sources,available_source_buckets,input_periods,captured_at}));Ok(())
    }))?;
    output.ok_or(Error::InternalError)
}

fn report_parent_baseline(
    rules: &mut Vec<aw_models::ReportEffectiveRuleV1>,
    control: &QueryControl,
) -> Result<(), Error> {
    fn joined(path: &[String], control: &QueryControl) -> Result<String, Error> {
        let size = path
            .iter()
            .try_fold(path.len().saturating_sub(1), |total, part| {
                total.checked_add(part.len())
            })
            .ok_or(Error::ByteLimit)?;
        control.charge_values(1)?;
        control.charge_bytes((size + std::mem::size_of::<String>()) as u64)?;
        Ok(path.join(">"))
    }
    let mut known = BTreeSet::new();
    for rule in rules.iter() {
        control.charge_fuel(1)?;
        known.insert(joined(&rule.category_path, control)?);
    }
    let original_count = rules.len();
    for index in 0..original_count {
        let mut depth = rules[index].category_path.len();
        while depth > 1 {
            control.charge_fuel(1)?;
            depth -= 1;
            let key = joined(&rules[index].category_path[..depth], control)?;
            // The free resolver stops this ancestor walk at an existing join('>') key.
            if known.contains(&key) {
                break;
            }
            if rules.len() >= 128000 {
                return Err(Error::ValueLimit);
            }
            control.charge_values(depth as u64 + 1)?;
            control.charge_bytes(
                (std::mem::size_of::<aw_models::ReportEffectiveRuleV1>()
                    + rules[index].set_id.len()
                    + depth * std::mem::size_of::<String>()
                    + rules[index].category_path[..depth]
                        .iter()
                        .map(String::len)
                        .sum::<usize>()) as u64,
            )?;
            let parent = aw_models::ReportEffectiveRuleV1 {
                set_id: rules[index].set_id.clone(),
                category_path: rules[index].category_path[..depth].to_vec(),
                rule_index: rules.len() as u64,
                rule: aw_models::ReportCategoryRuleV1 {
                    kind: Some(aw_models::ReportRuleTypeV1::None),
                    regex: None,
                    ignore_case: None,
                },
            };
            known.insert(key);
            rules.push(parent);
        }
    }
    for (index, rule) in rules.iter_mut().enumerate() {
        control.charge_fuel(1)?;
        rule.rule_index = index as u64;
    }
    Ok(())
}
