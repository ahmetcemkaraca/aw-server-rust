use crate::{QueryLimits, ReportExecutionErrorV1};
use chrono::{DateTime, NaiveDate, Utc};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::{collections::BTreeSet, fmt, marker::PhantomData};

pub const REPORT_LIBRARY_MAX_BYTES_V1: usize = 1024 * 1024;
pub const REPORT_PORTABLE_MAX_BYTES_V1: usize = 4 * 1024 * 1024;
pub const REPORT_DEFAULT_CATEGORIES_JSON_V1: &str =
    include_str!("generated/report-default-categories-v1.json");
type ReportResult<T> = Result<T, ReportExecutionErrorV1>;

// Route through deserialize_map before deriving field checks: arrays are never records.
macro_rules! record {
    ($name:ident { $( $(#[$attr:meta])* $field:ident: $ty:ty ),* $(,)? }) => {
        #[derive(Clone, Debug, PartialEq, Serialize)]
        pub struct $name { $( $(#[$attr])* pub $field: $ty, )* }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Fields { $( $(#[$attr])* $field: $ty, )* }
                struct Record;
                impl<'de> Visitor<'de> for Record {
                    type Value = $name;
                    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(stringify!($name)) }
                    fn visit_map<M: MapAccess<'de>>(self, map: M) -> Result<Self::Value, M::Error> {
                        let v = Fields::deserialize(de::value::MapAccessDeserializer::new(map))?;
                        Ok($name { $( $field: v.$field, )* })
                    }
                }
                d.deserialize_map(Record)
            }
        }
    };
}
pub(crate) use record;

pub(crate) fn limited_vec<'de, D, T, const N: usize>(d: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Sequence<T, const N: usize>(PhantomData<T>);
    struct Reject;
    impl<'de> DeserializeSeed<'de> for Reject {
        type Value = ();
        fn deserialize<D: Deserializer<'de>>(self, _: D) -> Result<(), D::Error> {
            Err(de::Error::custom("Report collection limit exceeded"))
        }
    }
    impl<'de, T: Deserialize<'de>, const N: usize> Visitor<'de> for Sequence<T, N> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a bounded report collection")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Vec<T>, A::Error> {
            let mut values = Vec::new();
            loop {
                if values.len() == N {
                    let _ = a.next_element_seed(Reject)?;
                    break;
                }
                match a.next_element()? {
                    Some(v) => values.push(v),
                    None => break,
                }
            }
            Ok(values)
        }
    }
    d.deserialize_seq(Sequence::<T, N>(PhantomData))
}
fn required_option<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(d)
}

pub(crate) fn limited_string<'de, D: Deserializer<'de>, const N: usize>(d: D) -> Result<String, D::Error> {
    struct Text<const N: usize>;
    impl<const N: usize> Visitor<'_> for Text<N> {
        type Value = String;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("bounded report text")
        }
        fn visit_str<E: de::Error>(self, v: &str) -> Result<String, E> {
            if v.len() > N {
                return Err(E::custom("Report text limit exceeded"));
            }
            Ok(v.to_owned())
        }
    }
    d.deserialize_str(Text::<N>)
}

pub(crate) fn limited_strings<'de, D: Deserializer<'de>, const N: usize, const BYTES: usize>(
    d: D,
) -> Result<Vec<String>, D::Error> {
    struct Text<const N: usize>(String);
    impl<'de, const N: usize> Deserialize<'de> for Text<N> {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            limited_string::<D, N>(d).map(Self)
        }
    }
    limited_vec::<D, Text<BYTES>, N>(d).map(|v| v.into_iter().map(|s| s.0).collect())
}
fn limited_paths<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Vec<String>>, D::Error> {
    struct Path(Vec<String>);
    impl<'de> Deserialize<'de> for Path {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            limited_strings::<D, 8, 128>(d).map(Self)
        }
    }
    limited_vec::<D, Path, 100>(d).map(|v| v.into_iter().map(|p| p.0).collect())
}
fn required_periods_option<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<Option<Vec<ResolvedPeriodV1>>, D::Error> {
    struct Periods(Vec<ResolvedPeriodV1>);
    impl<'de> Deserialize<'de> for Periods {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            limited_vec::<D, ResolvedPeriodV1, 186>(d).map(Self)
        }
    }
    Option::<Periods>::deserialize(d).map(|v| v.map(|p| p.0))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReportSectionV1 {
    Daily,
    Weekly,
    Monthly,
    Comparison,
    CategorySummary,
    ProjectSummary,
    AppSummary,
    DomainSummary,
    ActiveAway,
    FocusBlocks,
    ContextSwitches,
    MeetingLoad,
}

record!(ReportLibraryV1 {
    schema_version: u16, revision: u64,
    #[serde(deserialize_with = "limited_vec::<_, _, 100>")] templates: Vec<ReportTemplateV1>,
    #[serde(deserialize_with = "limited_vec::<_, _, 100>")] rule_packs: Vec<ReportRulePackV1>,
});
record!(ReportTemplateV1 {
    #[serde(deserialize_with = "limited_string::<_, 64>")] id: String,
    #[serde(deserialize_with = "limited_string::<_, 80>")] name: String,
    content_version: u64,
    #[serde(deserialize_with = "limited_string::<_, 80>")] method_id: String,
    method_version: u16,
    #[serde(deserialize_with = "limited_vec::<_, _, 12>")] sections: Vec<ReportSectionV1>,
    #[serde(deserialize_with = "limited_paths")] category_paths: Vec<Vec<String>>,
    break_time_seconds: u32,
    #[serde(deserialize_with = "required_option")] rule_pack: Option<ReportRulePackRefV1>,
});
record!(ReportRulePackRefV1 {
    #[serde(deserialize_with = "limited_string::<_, 64>")]
    id: String,
    content_version: u64,
});
record!(ReportRulePackV1 {
    #[serde(deserialize_with = "limited_string::<_, 64>")] id: String,
    #[serde(deserialize_with = "limited_string::<_, 80>")] name: String,
    content_version: u64,
    #[serde(deserialize_with = "limited_vec::<_, _, 16>")] category_sets: Vec<ReportCategorySetRefV1>,
});
record!(ReportCategorySetRefV1 {
    #[serde(deserialize_with = "limited_string::<_, 128>")]
    id: String,
    #[serde(deserialize_with = "limited_string::<_, 64>")]
    calculation_sha256: String,
});
record!(ResolvedPeriodV1 {
    #[serde(deserialize_with = "limited_string::<_, 10>")]
    local_date: String,
    #[serde(deserialize_with = "limited_string::<_, 128>")]
    interval: String,
});
record!(AdvancedReportRunRequestV1 {
    schema_version: u16,
    #[serde(deserialize_with = "limited_string::<_, 64>")] template_id: String,
    expected_library_revision: u64,
    #[serde(deserialize_with = "limited_strings::<_, 8, 128>")] ordered_host_ids: Vec<String>,
    #[serde(deserialize_with = "limited_vec::<_, _, 186>")] current_periods: Vec<ResolvedPeriodV1>,
    #[serde(deserialize_with = "required_periods_option")] previous_periods: Option<Vec<ResolvedPeriodV1>>,
    #[serde(deserialize_with = "limited_string::<_, 128>")] timezone: String,
    #[serde(deserialize_with = "limited_string::<_, 80>")] timezone_resolution: String,
    #[serde(deserialize_with = "limited_string::<_, 5>")] day_start: String,
});
record!(PortableReportPackV1 {
    schema_version: u16,
    #[serde(deserialize_with = "limited_vec::<_, _, 100>")] templates: Vec<ReportTemplateV1>,
    #[serde(deserialize_with = "limited_vec::<_, _, 100>")] rule_packs: Vec<ReportRulePackV1>,
    #[serde(deserialize_with = "limited_vec::<_, _, 100>")] category_sets: Vec<ReportPortableCategorySetV1>,
});
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportRuleTypeV1 {
    None,
    Regex,
}
record!(ReportCategoryRuleV1 {
    #[serde(rename = "type", default)] kind: Option<ReportRuleTypeV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")] regex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")] ignore_case: Option<bool>,
});
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(untagged)]
pub enum ReportCosmeticScoreV1 {
    Number(serde_json::Number),
    Text(String),
}
impl<'de> Deserialize<'de> for ReportCosmeticScoreV1 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Score;
        impl Visitor<'_> for Score {
            type Value = ReportCosmeticScoreV1;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a finite cosmetic weight")
            }
            fn visit_i64<E: de::Error>(self, n: i64) -> Result<Self::Value, E> {
                Ok(ReportCosmeticScoreV1::Number(n.into()))
            }
            fn visit_u64<E: de::Error>(self, n: u64) -> Result<Self::Value, E> {
                Ok(ReportCosmeticScoreV1::Number(n.into()))
            }
            fn visit_f64<E: de::Error>(self, n: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(n)
                    .map(ReportCosmeticScoreV1::Number)
                    .ok_or_else(|| E::custom("Invalid cosmetic weight"))
            }
            fn visit_str<E: de::Error>(self, text: &str) -> Result<Self::Value, E> {
                if text.len() > 64 || !text.trim().parse::<f64>().is_ok_and(f64::is_finite) {
                    return Err(E::custom("Invalid cosmetic weight"));
                }
                Ok(ReportCosmeticScoreV1::Text(text.to_owned()))
            }
        }
        d.deserialize_any(Score)
    }
}
record!(ReportCategoryDataV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")] color: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")] score: Option<ReportCosmeticScoreV1>,
});
record!(ReportCategoryV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")] id: Option<u64>,
    #[serde(deserialize_with = "limited_strings::<_, 8, 128>")] name: Vec<String>,
    rule: ReportCategoryRuleV1,
    #[serde(default, skip_serializing_if = "Option::is_none")] data: Option<ReportCategoryDataV1>,
});
record!(ReportPortableCategorySetV1 {
    #[serde(deserialize_with = "limited_string::<_, 128>")] id: String,
    #[serde(deserialize_with = "limited_string::<_, 80>")] name: String,
    #[serde(deserialize_with = "limited_vec::<_, _, 1000>")] classes: Vec<ReportCategoryV1>,
});
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportRunStateV1 {
    Queued,
    Running,
    Complete,
    Limited,
    Cancelled,
    Failed,
}
record!(ReportRunStatusV1 {
    schema_version: u16,
    #[serde(deserialize_with = "limited_string::<_, 32>")] run_id: String,
    state: ReportRunStateV1,
    #[serde(deserialize_with = "required_option")] queue_wait_ms: Option<u64>,
    #[serde(deserialize_with = "required_option")] execution_ms: Option<u64>,
    #[serde(deserialize_with = "required_option")] reason: Option<ReportExecutionErrorV1>,
    #[serde(deserialize_with = "required_option")] result: Option<ReportCompletedV1>,
});
#[derive(Clone, PartialEq, Eq)]
pub struct ReportCapabilityV1([u8; 32]);
impl fmt::Debug for ReportCapabilityV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted report capability>")
    }
}
impl ReportCapabilityV1 {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub fn from_hex(text: &str) -> ReportResult<Self> {
        require(valid_lower_hex(text, 64))?;
        let nibble = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
        let mut bytes = [0; 32];
        for (i, pair) in text.as_bytes().chunks_exact(2).enumerate() {
            bytes[i] = nibble(pair[0]) * 16 + nibble(pair[1]);
        }
        Ok(Self(bytes))
    }
}
impl Serialize for ReportCapabilityV1 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let text: String = self.0.iter().map(|b| format!("{b:02x}")).collect();
        s.serialize_str(&text)
    }
}
impl<'de> Deserialize<'de> for ReportCapabilityV1 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = limited_string::<D, 64>(d)?;
        Self::from_hex(&text).map_err(de::Error::custom)
    }
}
record!(ReportRunStartResponseV1 {
    schema_version: u16,
    #[serde(deserialize_with = "limited_string::<_, 32>")]
    run_id: String,
    capability: ReportCapabilityV1,
    state: ReportRunStateV1,
});
record!(ReportRunReadRequestV1 {
    schema_version: u16,
    #[serde(deserialize_with = "limited_string::<_, 32>")]
    run_id: String,
    include_raw_events: bool,
});
record!(ReportRunOwnerRequestV1 {
    schema_version: u16,
    #[serde(deserialize_with = "limited_string::<_, 32>")]
    run_id: String,
});
record!(ReportRunCancelResponseV1 {
    schema_version: u16,
    run_id: String,
    requested: bool
});
record!(ReportRunReleaseResponseV1 {
    schema_version: u16,
    run_id: String,
    released: bool
});
record!(ReportImportCommitRequestV1 {
    schema_version: u16,
    #[serde(deserialize_with = "limited_string::<_, 32>")]
    preview_id: String,
    accept: bool,
});
record!(UpdateReportLibraryRequestV1 {
    schema_version: u16,
    expected_revision: u64,
    library: ReportLibraryV1
});
record!(ReportPortableExportRequestV1 {
    schema_version: u16,
    include_category_sets: bool
});
record!(ReportPortableExportV1 {
    schema_version: u16, package: PortableReportPackV1,
    #[serde(deserialize_with = "limited_strings::<_, 1600, 128>")] unavailable_set_ids: Vec<String>,
});
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReportImportKindV1 {
    CategorySet,
    RulePack,
    Template,
}
record!(ReportImportMappingV1 {
    kind: ReportImportKindV1,
    #[serde(deserialize_with = "limited_string::<_, 128>")]
    from_id: String,
    #[serde(deserialize_with = "limited_string::<_, 128>")]
    to_id: String,
});
record!(ReportImportPreviewResponseV1 {
    schema_version: u16,
    #[serde(deserialize_with = "limited_string::<_, 32>")] preview_id: String,
    #[serde(deserialize_with = "limited_vec::<_, _, 300>")] mappings: Vec<ReportImportMappingV1>,
    proposed_library: ReportLibraryV1, expires_in_seconds: u32,
});
impl ReportRunStartResponseV1 {
    pub fn validate(&self) -> ReportResult<()> {
        require(
            self.schema_version == 1
                && valid_lower_hex(&self.run_id, 32)
                && self.state == ReportRunStateV1::Queued,
        )
    }
}
impl ReportRunReadRequestV1 {
    pub fn validate(&self) -> ReportResult<()> {
        require(self.schema_version == 1 && valid_lower_hex(&self.run_id, 32))
    }
}
impl ReportRunOwnerRequestV1 {
    pub fn validate(&self) -> ReportResult<()> {
        require(self.schema_version == 1 && valid_lower_hex(&self.run_id, 32))
    }
}
impl ReportImportCommitRequestV1 {
    pub fn validate(&self) -> ReportResult<()> {
        require(self.schema_version == 1 && valid_lower_hex(&self.preview_id, 32) && self.accept)
    }
}
impl UpdateReportLibraryRequestV1 {
    pub fn validate(&self) -> ReportResult<()> {
        require(self.schema_version == 1 && self.library.revision == self.expected_revision)?;
        self.library.validate()
    }
}
impl ReportRunCancelResponseV1 {
    pub fn validate(&self) -> ReportResult<()> {
        require(self.schema_version == 1 && valid_lower_hex(&self.run_id, 32) && self.requested)
    }
}
impl ReportRunReleaseResponseV1 {
    pub fn validate(&self) -> ReportResult<()> {
        require(self.schema_version == 1 && valid_lower_hex(&self.run_id, 32))
    }
}
impl ReportPortableExportRequestV1 {
    pub fn validate(&self) -> ReportResult<()> {
        require(self.schema_version == 1)
    }
}
impl ReportPortableExportV1 {
    pub fn validate(&self) -> ReportResult<()> {
        require(self.schema_version == 1)?;
        self.package.validate()
    }
}
impl ReportImportPreviewResponseV1 {
    pub fn validate(&self) -> ReportResult<()> {
        require(
            self.schema_version == 1
                && valid_lower_hex(&self.preview_id, 32)
                && self.expires_in_seconds == 120
                && self.mappings.len() <= 300,
        )?;
        for m in &self.mappings {
            require(valid_report_label(&m.from_id, 128) && valid_report_label(&m.to_id, 128))?;
            if m.kind != ReportImportKindV1::CategorySet {
                require(valid_report_id(&m.from_id) && valid_report_id(&m.to_id))?;
            }
        }
        self.proposed_library.validate()
    }
}
// Only worker construction writes these inputs; query adapters receive an Arc.
pub struct ReportInputSnapshotV1 {
    pub request: AdvancedReportRunRequestV1,
    pub library_revision: u64,
    pub template: ReportTemplateV1,
    pub rule_pack: Option<ReportRulePackV1>,
    pub effective_rules: Vec<ReportEffectiveRuleV1>,
    pub sources: Vec<ReportSourceV1>,
    pub available_source_buckets: Vec<String>,
    pub input_periods: Vec<ReportInputPeriodV1>,
    pub captured_at: DateTime<Utc>,
}
pub struct ReportInputPeriodV1 {
    pub period: ResolvedPeriodV1,
    pub buckets: Vec<ReportInputBucketV1>,
}
pub struct ReportInputBucketV1 {
    pub bucket_id: String,
    pub rows: u64,
    pub events: Vec<crate::Event>,
}
record!(ReportCompletedV1 {
    parameters: ReportParametersV1,
    calculation_manifest: ReportCalculationManifestV1,
    source_coverage: ReportSourceCoverageV1,
    #[serde(deserialize_with = "required_option")] comparison: Option<ReportComparisonV1>,
    #[serde(deserialize_with = "limited_vec::<_, _, 186>")] weekly: Vec<ReportAggregateV1>,
    #[serde(deserialize_with = "limited_vec::<_, _, 186>")] monthly: Vec<ReportAggregateV1>,
    field_summaries: ReportFieldSummaryV1, metrics: ReportMetricsV1,
    summary: ReportSummaryV1,
    #[serde(deserialize_with = "limited_vec::<_, _, 186>")] daily: Vec<ReportDailyV1>,
    advanced_report_manifest: ReportAdvancedManifestV1,
    #[serde(deserialize_with = "required_option")] category_summary: Option<ReportCategorySummaryV1>,
    #[serde(rename = "rawEvents", default, skip_serializing_if = "Option::is_none")] raw_events: Option<Vec<RawReportPeriodV1>>,
});
record!(ReportDailyV1 {
    #[serde(deserialize_with = "limited_string::<_, 10>")]
    date: String,
    #[serde(serialize_with = "serialize_nonnegative")]
    duration: f64,
    sessions: u64,
    #[serde(rename = "avgSession", serialize_with = "serialize_nonnegative")]
    avg_session: f64,
});
record!(ReportSummaryV1 {
    #[serde(rename = "totalDuration", serialize_with = "serialize_nonnegative")]
    total_duration: f64,
    #[serde(rename = "totalSessions")]
    total_sessions: u64,
    #[serde(rename = "avgSessionLength", serialize_with = "serialize_nonnegative")]
    avg_session_length: f64,
});
record!(ReportParametersV1 {
    #[serde(deserialize_with = "limited_strings::<_, 8, 128>")] host_ids: Vec<String>,
    #[serde(deserialize_with = "limited_paths")] category_paths: Vec<Vec<String>>,
    break_time_seconds: u32,
    #[serde(deserialize_with = "limited_string::<_, 80>")] date_range: String,
    #[serde(deserialize_with = "limited_string::<_, 5>")] start_of_day: String,
});
record!(ReportCalculationCoverageV1 {
    requested_periods: u64,
    periods_with_events: u64,
    events_seen: u64,
    #[serde(deserialize_with = "limited_string::<_, 80>")]
    source_health: String,
    #[serde(deserialize_with = "limited_string::<_, 2048>")]
    limitation: String,
});
record!(ReportCalculationManifestV1 {
    schema_version: u16,
    #[serde(deserialize_with = "limited_string::<_, 80>")] method_id: String,
    method_version: u16,
    #[serde(deserialize_with = "limited_string::<_, 2048>")] formula: String,
    #[serde(deserialize_with = "limited_strings::<_, 186, 128>")] input_periods: Vec<String>,
    #[serde(deserialize_with = "limited_strings::<_, 8, 128>")] host_ids: Vec<String>,
    #[serde(deserialize_with = "limited_paths")] category_paths: Vec<Vec<String>>,
    #[serde(deserialize_with = "limited_string::<_, 80>")] date_range: String,
    #[serde(deserialize_with = "limited_string::<_, 5>")] start_of_day: String,
    break_time_seconds: u32, coverage: ReportCalculationCoverageV1,
});
record!(ReportClockSkewV1 {
    #[serde(deserialize_with = "limited_string::<_, 80>")]
    status: String,
    correction_bound_seconds: u32,
    #[serde(deserialize_with = "limited_string::<_, 2048>")]
    limitation: String,
});
record!(ReportSourceCoverageV1 {
    #[serde(deserialize_with = "limited_string::<_, 80>")] method_id: String,
    method_version: u16,
    #[serde(deserialize_with = "limited_strings::<_, 128, 1024>")] available_source_buckets: Vec<String>,
    #[serde(deserialize_with = "limited_strings::<_, 128, 1024>")] queried_source_buckets: Vec<String>,
    #[serde(deserialize_with = "limited_strings::<_, 186, 128>")] queried_periods: Vec<String>,
    #[serde(deserialize_with = "limited_strings::<_, 186, 10>")] partial_periods: Vec<String>,
    #[serde(deserialize_with = "limited_strings::<_, 186, 128>")] limited_periods: Vec<String>,
    source_row_limit: u64, report_row_limit: u64,
    #[serde(deserialize_with = "limited_string::<_, 128>")] timezone: String,
    #[serde(deserialize_with = "limited_string::<_, 80>")] source_health: String,
    clock_skew: ReportClockSkewV1,
});
record!(ReportAggregateV1 {
    method_id: String,
    method_version: u16,
    unit: String,
    period: String,
    start_date: String,
    end_date: String,
    days: u64,
    days_with_events: u64,
    #[serde(serialize_with = "serialize_nonnegative")]
    duration: f64,
    sessions: u64,
});
record!(ReportPeriodSummaryV1 {
    start_date: String,
    end_date: String,
    periods: u64,
    periods_with_events: u64,
    observed_events: u64,
    #[serde(serialize_with = "serialize_nonnegative")]
    duration: f64,
});
record!(ReportComparisonV1 {
    method_id: String, method_version: u16, current: ReportPeriodSummaryV1, previous: ReportPeriodSummaryV1,
    #[serde(serialize_with = "serialize_finite")] duration_change: f64,
    #[serde(deserialize_with = "required_option", serialize_with = "serialize_optional_finite")] duration_change_percent: Option<f64>,
    #[serde(deserialize_with = "required_option")] coverage_note: Option<String>,
});
record!(ReportFieldRowV1 {
    #[serde(deserialize_with = "limited_string::<_, 1048576>")]
    label: String,
    #[serde(serialize_with = "serialize_nonnegative")]
    duration: f64,
    sessions: u64,
});
record!(ReportActiveAwayV1 {
    #[serde(serialize_with = "serialize_nonnegative")]
    active_duration: f64,
    #[serde(serialize_with = "serialize_nonnegative")]
    away_duration: f64,
});
record!(ReportFieldSummaryV1 {
    method_id: String, method_version: u16,
    #[serde(deserialize_with = "limited_vec::<_, _, 250000>")] project: Vec<ReportFieldRowV1>,
    #[serde(deserialize_with = "limited_vec::<_, _, 250000>")] app: Vec<ReportFieldRowV1>,
    #[serde(deserialize_with = "limited_vec::<_, _, 250000>")] domain: Vec<ReportFieldRowV1>,
    #[serde(deserialize_with = "required_option")] active_away: Option<ReportActiveAwayV1>,
});
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportMetricOutcomeV1 {
    Calculated,
    CouldNotDetermine,
}
record!(ReportMetricIntervalV1 {
    start: String,
    end: String,
    #[serde(serialize_with = "serialize_nonnegative")]
    duration_seconds: f64,
});
record!(ReportFocusThresholdsV1 {
    minimum_duration_seconds: u32,
    maximum_gap_seconds: u32
});
record!(ReportContextThresholdsV1 {
    maximum_gap_seconds: u32
});
record!(ReportMeetingThresholdsV1 {
    minimum_interval_seconds: u32
});
record!(ReportFocusBlocksV1 {
    method_id: String, method_version: u16, outcome: ReportMetricOutcomeV1,
    thresholds: ReportFocusThresholdsV1,
    #[serde(deserialize_with = "limited_vec::<_, _, 250000>")] intervals: Vec<ReportMetricIntervalV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")] reason: Option<String>,
});
record!(ReportContextIntervalV1 {
    start: String,
    end: String,
    #[serde(serialize_with = "serialize_nonnegative")]
    gap_seconds: f64,
    #[serde(deserialize_with = "limited_string::<_, 1048576>")]
    from_app: String,
    #[serde(deserialize_with = "limited_string::<_, 1048576>")]
    to_app: String,
});
record!(ReportContextSwitchesV1 {
    method_id: String, method_version: u16, outcome: ReportMetricOutcomeV1, thresholds: ReportContextThresholdsV1,
    #[serde(deserialize_with = "limited_vec::<_, _, 250000>")] intervals: Vec<ReportContextIntervalV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")] reason: Option<String>,
});
record!(ReportMeetingLoadV1 {
    method_id: String, method_version: u16, outcome: ReportMetricOutcomeV1, thresholds: ReportMeetingThresholdsV1,
    #[serde(serialize_with = "serialize_nonnegative")] duration_seconds: f64,
    #[serde(deserialize_with = "limited_vec::<_, _, 250000>")] intervals: Vec<ReportMetricIntervalV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")] reason: Option<String>,
});
record!(ReportMetricsV1 {
    #[serde(deserialize_with = "required_option")] focus_blocks: Option<ReportFocusBlocksV1>,
    #[serde(deserialize_with = "required_option")] context_switches: Option<ReportContextSwitchesV1>,
    #[serde(deserialize_with = "required_option")] meeting_load: Option<ReportMeetingLoadV1>,
});
record!(ReportCategorySummaryRowV1 {
    #[serde(deserialize_with = "limited_strings::<_, 8, 128>")] category_path: Vec<String>,
    #[serde(serialize_with = "serialize_nonnegative")] duration: f64,
    sessions: u64,
});
record!(ReportCategorySummaryV1 {
    method_id: String, method_version: u16, formula: String,
    #[serde(deserialize_with = "limited_vec::<_, _, 250000>")] categories: Vec<ReportCategorySummaryRowV1>,
});
record!(ReportEffectiveRuleV1 {
    #[serde(deserialize_with = "limited_string::<_, 128>")] set_id: String,
    #[serde(deserialize_with = "limited_strings::<_, 8, 128>")] category_path: Vec<String>,
    rule_index: u64, rule: ReportCategoryRuleV1,
});
record!(ReportSourceV1 {
    #[serde(deserialize_with = "limited_string::<_, 128>")]
    host_id: String,
    #[serde(deserialize_with = "limited_string::<_, 1024>")]
    window_bucket_id: String,
    #[serde(deserialize_with = "limited_string::<_, 1024>")]
    afk_bucket_id: String,
});
record!(ReportSourceRowsV1 {
    interval: String,
    bucket_id: String,
    rows: u64
});
record!(ReportLimitsV1 {
    periods: u64,
    hosts: u64,
    source_rows: u64,
    merged_rows: u64,
    raw_rows: u64,
    bytes: u64,
    values: u64,
    fuel: u64,
    execution_seconds: u64,
    query_bytes: u64,
    ast_depth: u64,
    event_json_bytes: u64,
    regex_bytes: u64,
    regex_backtracks: u64,
    regex_cache_entries: u64,
});
impl From<QueryLimits> for ReportLimitsV1 {
    fn from(v: QueryLimits) -> Self {
        Self {
            periods: v.max_periods as u64,
            hosts: v.max_hosts as u64,
            source_rows: v.max_source_rows,
            merged_rows: v.max_merged_rows,
            raw_rows: v.max_rows,
            bytes: v.max_bytes,
            values: v.max_values,
            fuel: v.max_fuel,
            execution_seconds: v.execution_timeout.as_secs(),
            query_bytes: v.max_query_bytes as u64,
            ast_depth: v.max_ast_depth as u64,
            event_json_bytes: v.max_event_json_bytes as u64,
            regex_bytes: v.max_regex_bytes as u64,
            regex_backtracks: v.max_regex_backtracks as u64,
            regex_cache_entries: v.regex_cache_entries as u64,
        }
    }
}
record!(ReportAdvancedManifestV1 {
    schema_version: u16, library_revision: u64, resolved_request: AdvancedReportRunRequestV1,
    template: ReportTemplateV1,
    #[serde(deserialize_with = "required_option")] rule_pack: Option<ReportRulePackV1>,
    #[serde(deserialize_with = "limited_vec::<_, _, 128000>")] effective_rules: Vec<ReportEffectiveRuleV1>,
    #[serde(deserialize_with = "limited_vec::<_, _, 8>")] sources: Vec<ReportSourceV1>,
    #[serde(deserialize_with = "limited_vec::<_, _, 2976>")] source_rows: Vec<ReportSourceRowsV1>,
    #[serde(deserialize_with = "limited_string::<_, 128>")] snapshot_time: String,
    overlap_precedence: String, label_tie_break: String, limits: ReportLimitsV1,
});
record!(RawReportBucketV1 {
    bucket_id: String,
    #[serde(deserialize_with = "limited_vec::<_, _, 2000>")] events: Vec<ReportRawEventV1>,
});
record!(ReportRawEventV1 {
    #[serde(deserialize_with = "required_option")] id: Option<i64>,
    #[serde(deserialize_with = "limited_string::<_, 128>")] timestamp: String,
    #[serde(serialize_with = "serialize_nonnegative")] duration: f64,
    data: serde_json::Map<String, serde_json::Value>,
});
impl ReportRawEventV1 {
    pub fn from_event(event: &crate::Event) -> ReportResult<Self> {
        let nanos = event
            .duration
            .num_nanoseconds()
            .ok_or(ReportExecutionErrorV1::DataIntegrity)?;
        require(nanos >= 0 && event.timestamp.checked_add_signed(event.duration).is_some())?;
        Ok(Self {
            id: event.id,
            timestamp: event
                .timestamp
                .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true),
            duration: nanos as f64 / 1_000_000_000.0,
            data: event.data.clone(),
        })
    }
    pub fn validate(&self) -> ReportResult<()> {
        require(
            self.duration.is_finite()
                && self.duration >= 0.0
                && self.duration * 1_000_000_000.0 < i64::MAX as f64,
        )?;
        let time = DateTime::parse_from_rfc3339(&self.timestamp)
            .map_err(|_| ReportExecutionErrorV1::DataIntegrity)?;
        require(
            time.checked_add_signed(chrono::Duration::nanoseconds(
                (self.duration * 1_000_000_000.0) as i64,
            ))
            .is_some(),
        )?;
        serialized_size(&self.data, QueryLimits::MANAGED.max_event_json_bytes)
    }
}
record!(RawReportPeriodV1 {
    interval: String,
    #[serde(deserialize_with = "limited_vec::<_, _, 16>")] buckets: Vec<RawReportBucketV1>,
});

fn serialize_finite<S: serde::Serializer>(v: &f64, s: S) -> Result<S::Ok, S::Error> {
    if !v.is_finite() {
        return Err(serde::ser::Error::custom("Invalid report number"));
    }
    // Match JS export tokens for exact safe integers, including negative zero.
    if v.abs() <= 9_007_199_254_740_991.0 && v.fract() == 0.0 {
        s.serialize_i64(*v as i64)
    } else {
        s.serialize_f64(*v)
    }
}
fn serialize_nonnegative<S: serde::Serializer>(v: &f64, s: S) -> Result<S::Ok, S::Error> {
    if *v < 0.0 {
        return Err(serde::ser::Error::custom("Invalid report duration"));
    }
    serialize_finite(v, s)
}
fn serialize_optional_finite<S: serde::Serializer>(
    v: &Option<f64>,
    s: S,
) -> Result<S::Ok, S::Error> {
    if v.is_some_and(|n| !n.is_finite()) {
        return Err(serde::ser::Error::custom("Invalid report number"));
    }
    match v {
        Some(value) => serialize_finite(value, s),
        None => s.serialize_none(),
    }
}
impl PortableReportPackV1 {
    pub fn validate(&self) -> ReportResult<()> {
        require(
            self.schema_version == 1
                && self.category_sets.len() <= 100
                && unique(self.category_sets.iter().map(|s| &s.id)),
        )?;
        // Library validation is borrowed below; no duplicate full metadata allocation.
        validate_library_records(&self.templates, &self.rule_packs)?;
        for set in &self.category_sets {
            require(
                valid_report_label(&set.id, 128)
                    && valid_report_label(&set.name, 80)
                    && set.classes.len() <= 1000,
            )?;
            for c in &set.classes {
                require(valid_path(&c.name))?;
                if c.rule.kind == Some(ReportRuleTypeV1::Regex) {
                    require(c.rule.regex.as_ref().is_some_and(|s| s.len() <= 4096))?;
                } else {
                    require(c.rule.regex.as_ref().is_none_or(|s| s.len() <= 4096))?;
                }
                if let Some(data) = &c.data {
                    require(
                        data.color
                            .as_ref()
                            .is_none_or(|s| s.len() <= 128 && !s.chars().any(char::is_control)),
                    )?;
                }
            }
        }
        serialized_size(self, REPORT_PORTABLE_MAX_BYTES_V1)
    }
}
impl ReportTemplateV1 {
    pub fn validate(&self, pack: Option<&ReportRulePackV1>) -> ReportResult<()> {
        validate_library_records(
            std::slice::from_ref(self),
            pack.map(std::slice::from_ref).unwrap_or(&[]),
        )?;
        require(self.rule_pack.is_some() == pack.is_some())
    }
}
impl ReportCompletedV1 {
    pub fn validate(&self) -> ReportResult<()> {
        let good = |n: f64| n.is_finite() && n >= 0.0;
        require(
            !self.daily.is_empty()
                && self.daily.len() <= 186
                && good(self.summary.total_duration)
                && good(self.summary.avg_session_length),
        )?;
        for day in &self.daily {
            require(good(day.duration) && good(day.avg_session))?;
        }
        require(
            self.calculation_manifest.schema_version == 1
                && self.calculation_manifest.method_id == "work-time-report"
                && self.calculation_manifest.method_version == 1
                && self.calculation_manifest.coverage.source_health == "unknown",
        )?;
        require(
            self.source_coverage.method_id == "work-report-source-coverage"
                && self.source_coverage.method_version == 1
                && self.source_coverage.source_health == "unknown"
                && self.source_coverage.limited_periods.is_empty()
                && self.source_coverage.clock_skew.correction_bound_seconds == 0,
        )?;
        require(
            self.field_summaries.method_id == "work-time-field-summary"
                && self.field_summaries.method_version == 1,
        )?;
        let provenance = &self.advanced_report_manifest;
        provenance.resolved_request.validate()?;
        require(
            provenance.schema_version == 1
                && provenance.library_revision
                    == provenance.resolved_request.expected_library_revision
                && provenance.limits == ReportLimitsV1::from(QueryLimits::MANAGED)
                && provenance.overlap_precedence == "ordered-host-first-source-v1"
                && provenance.label_tie_break == "utf16-code-unit-v1",
        )?;
        let request = &provenance.resolved_request;
        let template = &provenance.template;
        template.validate(provenance.rule_pack.as_ref())?;
        require(template.id == request.template_id)?;
        let selected = |section: ReportSectionV1| template.sections.contains(&section);
        let parameters = &self.parameters;
        let calculation = &self.calculation_manifest;
        require(
            parameters.host_ids == request.ordered_host_ids
                && parameters.category_paths == template.category_paths
                && parameters.break_time_seconds == template.break_time_seconds
                && parameters.start_of_day == request.day_start
                && parameters.date_range == "custom"
                && calculation.host_ids == parameters.host_ids
                && calculation.category_paths == parameters.category_paths
                && calculation.break_time_seconds == parameters.break_time_seconds
                && calculation.start_of_day == parameters.start_of_day
                && calculation.date_range == parameters.date_range
                && calculation.input_periods.len() == self.daily.len(),
        )?;
        let mut total = 0.0;
        let mut sessions = 0u64;
        let mut observed = 0u64;
        let mut last = None;
        for (day, interval) in self.daily.iter().zip(&calculation.input_periods) {
            let period = ResolvedPeriodV1 {
                local_date: day.date.clone(),
                interval: interval.clone(),
            };
            period.bounds()?;
            let start = DateTime::parse_from_rfc3339(
                interval
                    .split_once('/')
                    .ok_or(ReportExecutionErrorV1::DataIntegrity)?
                    .0,
            )
            .map_err(|_| ReportExecutionErrorV1::DataIntegrity)?;
            require(
                day.date == start.date_naive().format("%Y-%m-%d").to_string()
                    && last.is_none_or(|date: &str| date < day.date.as_str())
                    && day.sessions <= 4000
                    && day.avg_session
                        == if day.sessions == 0 {
                            0.0
                        } else {
                            day.duration / day.sessions as f64
                        },
            )?;
            total += day.duration;
            sessions = sessions
                .checked_add(day.sessions)
                .ok_or(ReportExecutionErrorV1::DataIntegrity)?;
            observed += u64::from(day.sessions > 0);
            last = Some(day.date.as_str());
        }
        require(
            self.summary.total_duration == total
                && self.summary.total_sessions == sessions
                && self.summary.avg_session_length
                    == if sessions == 0 {
                        0.0
                    } else {
                        total / sessions as f64
                    }
                && calculation.coverage.requested_periods == self.daily.len() as u64
                && calculation.coverage.periods_with_events == observed
                && calculation.coverage.events_seen == sessions,
        )?;
        for (section, rows, unit) in [
            (ReportSectionV1::Weekly, &self.weekly, "week"),
            (ReportSectionV1::Monthly, &self.monthly, "month"),
        ] {
            require(rows.len() <= 186 && (selected(section) || rows.is_empty()))?;
            for row in rows {
                require(
                    row.method_id == "work-time-calendar-aggregate"
                        && row.method_version == 1
                        && row.unit == unit
                        && row.days > 0
                        && row.days <= 186
                        && row.days_with_events <= row.days
                        && row.period.len() <= 80
                        && row.start_date.len() == 10
                        && row.end_date.len() == 10,
                )?;
            }
        }
        require(
            (selected(ReportSectionV1::Comparison) || self.comparison.is_none())
                && (request.previous_periods.is_some() || self.comparison.is_none()),
        )?;
        if let Some(value) = &self.comparison {
            require(
                value.method_id == "work-time-period-comparison"
                    && value.method_version == 1
                    && value.current.periods == self.daily.len() as u64
                    && value.current.duration == total
                    && value.current.observed_events == sessions
                    && value.current.periods_with_events == observed
                    && value.previous.periods == value.current.periods
                    && value.duration_change == value.current.duration - value.previous.duration
                    && value.duration_change_percent
                        == if value.previous.duration == 0.0 {
                            None
                        } else {
                            Some(value.duration_change / value.previous.duration * 100.0)
                        }
                    && value.coverage_note.as_ref().is_none_or(|s| s.len() <= 2048),
            )?;
        }
        for (section, rows) in [
            (
                ReportSectionV1::ProjectSummary,
                &self.field_summaries.project,
            ),
            (ReportSectionV1::AppSummary, &self.field_summaries.app),
            (ReportSectionV1::DomainSummary, &self.field_summaries.domain),
        ] {
            require(rows.len() <= 250000 && (selected(section) || rows.is_empty()))?;
            for row in rows {
                require(
                    !row.label.is_empty() && row.label.len() <= 1048576 && row.sessions <= sessions,
                )?;
            }
        }
        require(
            selected(ReportSectionV1::ActiveAway) || self.field_summaries.active_away.is_none(),
        )?;
        let outcome = |state: ReportMetricOutcomeV1,
                       reason: &Option<String>,
                       count: usize|
         -> ReportResult<()> {
            require(count <= 250000)?;
            match state {
                ReportMetricOutcomeV1::Calculated => require(reason.is_none()),
                ReportMetricOutcomeV1::CouldNotDetermine => require(
                    count == 0
                        && reason
                            .as_ref()
                            .is_some_and(|s| !s.is_empty() && s.len() <= 2048),
                ),
            }
        };
        require(
            selected(ReportSectionV1::FocusBlocks) == self.metrics.focus_blocks.is_some()
                && selected(ReportSectionV1::ContextSwitches)
                    == self.metrics.context_switches.is_some()
                && selected(ReportSectionV1::MeetingLoad) == self.metrics.meeting_load.is_some()
                && selected(ReportSectionV1::CategorySummary) == self.category_summary.is_some(),
        )?;
        let intervals = |rows: &[ReportMetricIntervalV1]| -> ReportResult<()> {
            for row in rows {
                let a = DateTime::parse_from_rfc3339(&row.start)
                    .map_err(|_| ReportExecutionErrorV1::DataIntegrity)?;
                let b = DateTime::parse_from_rfc3339(&row.end)
                    .map_err(|_| ReportExecutionErrorV1::DataIntegrity)?;
                require(b >= a && row.duration_seconds.is_finite() && row.duration_seconds >= 0.0)?;
            }
            Ok(())
        };
        if let Some(value) = &self.metrics.focus_blocks {
            require(
                value.method_id == "focus-blocks"
                    && value.method_version == 1
                    && value.thresholds.minimum_duration_seconds == 1500
                    && value.thresholds.maximum_gap_seconds == 300,
            )?;
            outcome(value.outcome, &value.reason, value.intervals.len())?;
            intervals(&value.intervals)?;
        }
        if let Some(value) = &self.metrics.context_switches {
            require(
                value.method_id == "context-switches"
                    && value.method_version == 1
                    && value.thresholds.maximum_gap_seconds == 60,
            )?;
            outcome(value.outcome, &value.reason, value.intervals.len())?;
            for row in &value.intervals {
                require(
                    row.start.len() <= 128
                        && row.end.len() <= 128
                        && row.from_app.len() <= 1048576
                        && row.to_app.len() <= 1048576
                        && (0.0..=60.0).contains(&row.gap_seconds),
                )?;
            }
        }
        if let Some(value) = &self.metrics.meeting_load {
            require(
                value.method_id == "meeting-load"
                    && value.method_version == 1
                    && value.thresholds.minimum_interval_seconds == 300
                    && (value.outcome != ReportMetricOutcomeV1::CouldNotDetermine
                        || value.duration_seconds == 0.0),
            )?;
            outcome(value.outcome, &value.reason, value.intervals.len())?;
            intervals(&value.intervals)?;
        }
        if let Some(value) = &self.category_summary {
            require(
                value.method_id == "work-time-category-summary"
                    && value.method_version == 1
                    && value.formula.len() <= 2048
                    && value.categories.len() <= 250000,
            )?;
            for row in &value.categories {
                require(valid_path(&row.category_path) && row.sessions <= sessions)?;
            }
        }
        let coverage = &self.source_coverage;
        require(
            coverage.available_source_buckets.len() <= 128
                && coverage.queried_source_buckets.len() <= 128
                && coverage.queried_periods.len() <= 186
                && coverage.partial_periods.len() <= 186
                && coverage.source_row_limit == 2000
                && coverage.report_row_limit == 4000
                && coverage.timezone == request.timezone
                && matches!(
                    coverage.clock_skew.status.as_str(),
                    "unknown" | "not_applicable"
                )
                && coverage.clock_skew.limitation.len() <= 2048,
        )?;
        for id in coverage
            .available_source_buckets
            .iter()
            .chain(&coverage.queried_source_buckets)
        {
            require(valid_report_label(id, 1024))?;
        }
        require(
            provenance.effective_rules.len() <= 128000
                && provenance.sources.len() <= 8
                && provenance.source_rows.len() <= 2976
                && DateTime::parse_from_rfc3339(&provenance.snapshot_time).is_ok(),
        )?;
        for (index, rule) in provenance.effective_rules.iter().enumerate() {
            require(
                rule.rule_index == index as u64
                    && valid_report_label(&rule.set_id, 128)
                    && valid_path(&rule.category_path)
                    && rule.rule.regex.as_ref().is_none_or(|s| s.len() <= 4096),
            )?;
        }
        for source in &provenance.sources {
            require(
                valid_report_label(&source.host_id, 128)
                    && valid_report_label(&source.window_bucket_id, 1024)
                    && valid_report_label(&source.afk_bucket_id, 1024),
            )?;
        }
        let mut raw_count = 0u64;
        for row in &provenance.source_rows {
            require(
                row.rows <= 2000
                    && row.interval.len() <= 128
                    && valid_report_label(&row.bucket_id, 1024),
            )?;
            raw_count = raw_count
                .checked_add(row.rows)
                .ok_or(ReportExecutionErrorV1::DataIntegrity)?;
        }
        require(raw_count <= 250000)?;
        if let Some(periods) = &self.raw_events {
            require(periods.len() <= 186)?;
            let mut count = 0u64;
            for period in periods {
                require(period.interval.len() <= 128 && period.buckets.len() <= 16)?;
                for bucket in &period.buckets {
                    require(
                        valid_report_label(&bucket.bucket_id, 1024) && bucket.events.len() <= 2000,
                    )?;
                    count += bucket.events.len() as u64;
                    for event in &bucket.events {
                        event.validate()?;
                    }
                }
            }
            require(count <= 250000)?;
        }
        serialized_size(self, QueryLimits::MANAGED.max_bytes as usize)
    }
}
impl ReportRunStatusV1 {
    pub fn validate(&self) -> ReportResult<()> {
        require(self.schema_version == 1 && valid_lower_hex(&self.run_id, 32))?;
        use ReportRunStateV1::*;
        match self.state {
            Complete => {
                require(self.reason.is_none())?;
                self.result
                    .as_ref()
                    .ok_or(ReportExecutionErrorV1::DataIntegrity)?
                    .validate()?;
            }
            Queued | Running => require(self.result.is_none() && self.reason.is_none())?,
            Cancelled => require(
                self.result.is_none() && self.reason == Some(ReportExecutionErrorV1::Cancelled),
            )?,
            Limited => require(
                self.result.is_none()
                    && matches!(
                        self.reason,
                        Some(
                            ReportExecutionErrorV1::RowLimit
                                | ReportExecutionErrorV1::ByteLimit
                                | ReportExecutionErrorV1::ValueLimit
                                | ReportExecutionErrorV1::FuelLimit
                                | ReportExecutionErrorV1::Deadline
                        )
                    ),
            )?,
            Failed => require(
                self.result.is_none()
                    && matches!(
                        self.reason,
                        Some(
                            ReportExecutionErrorV1::StaleConfiguration
                                | ReportExecutionErrorV1::SourceUnavailable
                                | ReportExecutionErrorV1::EntitlementUnavailable
                                | ReportExecutionErrorV1::DataIntegrity
                                | ReportExecutionErrorV1::InternalError
                        )
                    ),
            )?,
        }
        Ok(())
    }
}

impl Default for ReportLibraryV1 {
    fn default() -> Self {
        Self {
            schema_version: 1,
            revision: 0,
            templates: Vec::new(),
            rule_packs: Vec::new(),
        }
    }
}
fn require(value: bool) -> ReportResult<()> {
    if value {
        Ok(())
    } else {
        Err(ReportExecutionErrorV1::StaleConfiguration)
    }
}
pub fn valid_report_label(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}
pub fn valid_report_id(value: &str) -> bool {
    valid_report_label(value, 64)
        && value
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}
pub fn valid_report_sha256(value: &str) -> bool {
    valid_lower_hex(value, 64)
}
pub fn valid_lower_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn valid_path(value: &[String]) -> bool {
    !value.is_empty() && value.len() <= 8 && value.iter().all(|s| valid_report_label(s, 128))
}
fn unique<T: Ord>(items: impl IntoIterator<Item = T>) -> bool {
    let mut seen = BTreeSet::new();
    items.into_iter().all(|item| seen.insert(item))
}

impl ReportLibraryV1 {
    pub fn validate(&self) -> ReportResult<()> {
        require(self.schema_version == 1)?;
        validate_library_records(&self.templates, &self.rule_packs)?;
        serialized_size(self, REPORT_LIBRARY_MAX_BYTES_V1)
    }
}
fn validate_library_records(
    templates: &[ReportTemplateV1],
    packs: &[ReportRulePackV1],
) -> ReportResult<()> {
    require(templates.len() <= 100 && packs.len() <= 100)?;
    require(unique(templates.iter().map(|t| &t.id)) && unique(packs.iter().map(|p| &p.id)))?;
    for p in packs {
        require(
            valid_report_id(&p.id)
                && valid_report_label(&p.name, 80)
                && p.content_version > 0
                && p.category_sets.len() <= 16,
        )?;
        require(unique(p.category_sets.iter().map(|r| &r.id)))?;
        for r in &p.category_sets {
            require(valid_report_label(&r.id, 128) && valid_report_sha256(&r.calculation_sha256))?;
        }
    }
    for t in templates {
        require(
            valid_report_id(&t.id) && valid_report_label(&t.name, 80) && t.content_version > 0,
        )?;
        require(
            t.method_id == "work-time-report"
                && t.method_version == 1
                && t.break_time_seconds <= 3600,
        )?;
        require(!t.sections.is_empty() && t.sections.len() <= 12 && unique(t.sections.iter()))?;
        require(
            t.category_paths.len() <= 100
                && unique(t.category_paths.iter())
                && t.category_paths.iter().all(|p| valid_path(p)),
        )?;
        if let Some(r) = &t.rule_pack {
            require(
                valid_report_id(&r.id)
                    && r.content_version > 0
                    && packs
                        .iter()
                        .any(|p| p.id == r.id && p.content_version == r.content_version),
            )?;
        }
    }
    Ok(())
}

pub fn serialized_size<T: Serialize>(value: &T, max: usize) -> ReportResult<()> {
    struct Count {
        used: usize,
        max: usize,
    }
    impl std::io::Write for Count {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.used = self
                .used
                .checked_add(bytes.len())
                .filter(|v| *v <= self.max)
                .ok_or_else(|| std::io::Error::other("Report byte limit exceeded"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(Count { used: 0, max }, value).map_err(|e| {
        if e.is_io() {
            ReportExecutionErrorV1::ByteLimit
        } else {
            ReportExecutionErrorV1::DataIntegrity
        }
    })
}

impl ResolvedPeriodV1 {
    pub fn bounds(&self) -> ReportResult<(DateTime<Utc>, DateTime<Utc>)> {
        let date = self.local_date.as_bytes();
        require(
            date.len() == 10
                && date[4] == b'-'
                && date[7] == b'-'
                && date
                    .iter()
                    .enumerate()
                    .all(|(i, b)| i == 4 || i == 7 || b.is_ascii_digit())
                && NaiveDate::parse_from_str(&self.local_date, "%Y-%m-%d").is_ok(),
        )?;
        let (a, b) = self
            .interval
            .split_once('/')
            .ok_or(ReportExecutionErrorV1::StaleConfiguration)?;
        let start = DateTime::parse_from_rfc3339(a)
            .map_err(|_| ReportExecutionErrorV1::StaleConfiguration)?;
        let end = DateTime::parse_from_rfc3339(b)
            .map_err(|_| ReportExecutionErrorV1::StaleConfiguration)?;
        require(end > start)?;
        Ok((start.with_timezone(&Utc), end.with_timezone(&Utc)))
    }
}
fn periods(values: &[ResolvedPeriodV1]) -> ReportResult<()> {
    require(!values.is_empty() && values.len() <= QueryLimits::MANAGED.max_periods)?;
    let mut last: Option<(&str, DateTime<Utc>)> = None;
    for v in values {
        let (a, b) = v.bounds()?;
        if let Some((date, end)) = last {
            require(v.local_date.as_str() > date && a >= end)?;
        }
        last = Some((&v.local_date, b));
    }
    Ok(())
}
impl AdvancedReportRunRequestV1 {
    pub fn validate(&self) -> ReportResult<()> {
        require(self.schema_version == 1 && valid_report_id(&self.template_id))?;
        require(
            !self.ordered_host_ids.is_empty()
                && self.ordered_host_ids.len() <= 8
                && unique(self.ordered_host_ids.iter()),
        )?;
        require(
            self.ordered_host_ids
                .iter()
                .all(|s| valid_report_label(s, 128)),
        )?;
        require(
            valid_report_label(&self.timezone, 128)
                && self.timezone_resolution == "client-local-calendar-v1",
        )?;
        let bytes = self.day_start.as_bytes();
        require(
            bytes.len() == 5
                && bytes[2] == b':'
                && [bytes[0], bytes[1], bytes[3], bytes[4]]
                    .iter()
                    .all(u8::is_ascii_digit),
        )?;
        let hour = (bytes[0] - b'0') * 10 + bytes[1] - b'0';
        let minute = (bytes[3] - b'0') * 10 + bytes[4] - b'0';
        require(hour <= 23 && minute <= 59)?;
        periods(&self.current_periods)?;
        if let Some(previous) = &self.previous_periods {
            require(
                previous.len() == self.current_periods.len()
                    && previous
                        .len()
                        .checked_add(self.current_periods.len())
                        .is_some_and(|n| n <= 186),
            )?;
            periods(previous)?;
            require(
                previous
                    .last()
                    .ok_or(ReportExecutionErrorV1::StaleConfiguration)?
                    .bounds()?
                    .1
                    <= self.current_periods[0].bounds()?.0,
            )?;
        }
        Ok(())
    }
}
