//! The only fields permitted in a client-facing approved timesheet.

use chrono::NaiveDate;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

pub const APPROVED_TIMESHEET_SCHEMA_VERSION_V1: u16 = 1;
pub const APPROVED_TIMESHEET_MAX_SECONDS_PER_DAY_V1: u32 = 86_400;
pub const APPROVED_TIMESHEET_MAX_NOTE_BYTES_V1: usize = 1_000;
pub const FREELANCER_REPORT_SIGNATURE_DOMAIN_V1: &[u8] = b"PeakActivity:FreelancerClientReportV1\0";
pub const FREELANCER_MAX_PROJECTS_V1: usize = 100;
pub const FREELANCER_MAX_CATEGORY_RULES_V1: usize = 1_000;
// ponytail: bound the single encrypted settings document at 1 MiB; split tables only if real workspaces exceed it.
pub const FREELANCER_MAX_WORKSPACE_BYTES_V1: usize = 1_048_576;
pub const INVOICE_DRAFT_MAX_DAYS_V1: u32 = 31;
// ponytail: keep amounts exact in JavaScript JSON numbers; use decimal strings if a real package exceeds this bound.
pub const FREELANCER_MAX_SAFE_MINOR_UNITS_V1: u64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApprovedTimesheetV1 {
    pub schema_version: u16,
    #[schemars(length(min = 1, max = 64))]
    pub project_alias: String,
    pub date: String,
    #[schemars(range(min = 1, max = 86400))]
    pub approved_duration_seconds: u32,
    #[schemars(length(max = 1000))]
    pub user_note: Option<String>,
}

impl ApprovedTimesheetV1 {
    pub fn validate(&self) -> Result<(), ApprovedTimesheetContractErrorV1> {
        if self.schema_version != APPROVED_TIMESHEET_SCHEMA_VERSION_V1 {
            return Err(ApprovedTimesheetContractErrorV1::UnsupportedVersion);
        }
        if !valid_alias(&self.project_alias) {
            return Err(ApprovedTimesheetContractErrorV1::InvalidProjectAlias);
        }
        let date = NaiveDate::parse_from_str(&self.date, "%Y-%m-%d")
            .map_err(|_| ApprovedTimesheetContractErrorV1::InvalidDate)?;
        if date.format("%Y-%m-%d").to_string() != self.date {
            return Err(ApprovedTimesheetContractErrorV1::InvalidDate);
        }
        if self.approved_duration_seconds == 0
            || self.approved_duration_seconds > APPROVED_TIMESHEET_MAX_SECONDS_PER_DAY_V1
        {
            return Err(ApprovedTimesheetContractErrorV1::InvalidDuration);
        }
        if self.user_note.as_ref().is_some_and(|note| {
            note.len() > APPROVED_TIMESHEET_MAX_NOTE_BYTES_V1
                || note.chars().any(char::is_control)
        }) {
            return Err(ApprovedTimesheetContractErrorV1::InvalidUserNote);
        }
        Ok(())
    }

    /// Stable compact JSON bytes for preview, hash and send of the same artifact.
    pub fn artifact_bytes(&self) -> Result<Vec<u8>, ApprovedTimesheetContractErrorV1> {
        self.validate()?;
        let canonical = serde_json::to_value(self)
            .map_err(|_| ApprovedTimesheetContractErrorV1::EncodingFailed)?;
        serde_json::to_vec(&canonical).map_err(|_| ApprovedTimesheetContractErrorV1::EncodingFailed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SignedClientReportV1 {
    pub schema_version: u16,
    pub timesheet: ApprovedTimesheetV1,
    #[schemars(length(equal = 64))]
    pub artifact_sha256: String,
    #[schemars(length(equal = 64))]
    pub signer_public_key_ed25519: String,
    #[schemars(length(equal = 128))]
    pub signature_ed25519: String,
}

impl SignedClientReportV1 {
    pub fn validate(&self) -> Result<(), FreelancerContractErrorV1> {
        self.timesheet.validate().map_err(|_| FreelancerContractErrorV1::InvalidSignedClientReport)?;
        if self.schema_version != 1
            || !valid_lower_hex(&self.artifact_sha256, 64)
            || !valid_lower_hex(&self.signer_public_key_ed25519, 64)
            || !valid_lower_hex(&self.signature_ed25519, 128)
        {
            return Err(FreelancerContractErrorV1::InvalidSignedClientReport);
        }
        Ok(())
    }
}

pub fn freelancer_report_signature_message_v1(
    timesheet: &ApprovedTimesheetV1,
) -> Result<Vec<u8>, FreelancerContractErrorV1> {
    let bytes = timesheet.artifact_bytes().map_err(|_| FreelancerContractErrorV1::InvalidSignedClientReport)?;
    let mut message = FREELANCER_REPORT_SIGNATURE_DOMAIN_V1.to_vec();
    message.extend_from_slice(&bytes);
    Ok(message)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovedTimesheetContractErrorV1 {
    UnsupportedVersion,
    InvalidProjectAlias,
    InvalidDate,
    InvalidDuration,
    InvalidUserNote,
    EncodingFailed,
}

impl fmt::Display for ApprovedTimesheetContractErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnsupportedVersion => "Unsupported approved timesheet version",
            Self::InvalidProjectAlias => "Invalid approved project alias",
            Self::InvalidDate => "Invalid approved timesheet date",
            Self::InvalidDuration => "Invalid approved duration",
            Self::InvalidUserNote => "Invalid approved timesheet note",
            Self::EncodingFailed => "Approved timesheet could not be encoded",
        })
    }
}

impl std::error::Error for ApprovedTimesheetContractErrorV1 {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FreelancerRoundingModeV1 {
    None,
    Up,
    Down,
    Nearest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FreelancerProjectV1 {
    #[schemars(length(min = 1, max = 64))]
    pub project_alias: String,
    #[serde(default)]
    #[schemars(length(min = 1, max = 64))]
    pub client_alias: Option<String>,
    #[schemars(length(min = 1, max = 120))]
    pub label: String,
    pub billable_default: bool,
    #[schemars(range(max = 3600))]
    pub rounding_increment_seconds: u32,
    pub rounding_mode: FreelancerRoundingModeV1,
    pub currency_code: Option<String>,
    pub hourly_rate_minor: Option<u64>,
    #[serde(default)]
    pub hourly_cost_minor: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FreelancerCategoryRuleV1 {
    #[schemars(length(min = 1, max = 16), inner(length(min = 1, max = 120)))]
    pub category_path: Vec<String>,
    #[schemars(length(min = 1, max = 64))]
    pub project_alias: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FreelancerWorkspaceV1 {
    pub schema_version: u16,
    pub revision: u64,
    #[schemars(length(max = 100))]
    pub projects: Vec<FreelancerProjectV1>,
    #[schemars(length(max = 1000))]
    pub category_rules: Vec<FreelancerCategoryRuleV1>,
}

impl FreelancerWorkspaceV1 {
    pub fn validate(&self) -> Result<(), FreelancerContractErrorV1> {
        if self.schema_version != 1
            || self.projects.len() > FREELANCER_MAX_PROJECTS_V1
            || self.category_rules.len() > FREELANCER_MAX_CATEGORY_RULES_V1
        {
            return Err(FreelancerContractErrorV1::InvalidWorkspace);
        }
        let mut aliases = BTreeSet::new();
        for project in &self.projects {
            validate_project(project)?;
            if !aliases.insert(project.project_alias.as_str()) {
                return Err(FreelancerContractErrorV1::DuplicateProjectAlias);
            }
        }
        let mut paths = BTreeSet::new();
        for rule in &self.category_rules {
            if !aliases.contains(rule.project_alias.as_str())
                || rule.category_path.is_empty()
                || rule.category_path.len() > 16
                || rule.category_path.iter().any(|part| !valid_local_label(part, 120))
                || !paths.insert(rule.category_path.as_slice())
            {
                return Err(FreelancerContractErrorV1::InvalidCategoryRule);
            }
        }
        let bytes = serde_json::to_vec(self).map_err(|_| FreelancerContractErrorV1::InvalidWorkspace)?;
        if bytes.len() > FREELANCER_MAX_WORKSPACE_BYTES_V1 {
            return Err(FreelancerContractErrorV1::InvalidWorkspace);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum InvoiceTaxStatusV1 {
    NotCalculated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum InvoiceDraftStatusV1 {
    Draft,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InvoiceDraftV1 {
    pub schema_version: u16,
    #[schemars(length(min = 1, max = 64))]
    pub project_alias: String,
    pub period_start: String,
    pub period_end: String,
    pub currency_code: String,
    #[schemars(range(min = 1, max = 2678400))]
    pub approved_duration_seconds: u32,
    pub hourly_rate_minor: u64,
    pub subtotal_minor: u64,
    pub status: InvoiceDraftStatusV1,
    pub tax_status: InvoiceTaxStatusV1,
}

impl InvoiceDraftV1 {
    pub fn validate(&self) -> Result<(), FreelancerContractErrorV1> {
        let start = parse_iso_date(&self.period_start);
        let end = parse_iso_date(&self.period_end);
        if self.schema_version != 1 || !valid_alias(&self.project_alias)
            || !valid_currency(&self.currency_code)
            || self.hourly_rate_minor > FREELANCER_MAX_SAFE_MINOR_UNITS_V1
            || start.is_none() || end.is_none()
            || end.zip(start).is_some_and(|(end, start)| {
                end < start || (end - start).num_days() >= i64::from(INVOICE_DRAFT_MAX_DAYS_V1)
            })
            || self.approved_duration_seconds == 0
            || self.approved_duration_seconds > INVOICE_DRAFT_MAX_DAYS_V1 * APPROVED_TIMESHEET_MAX_SECONDS_PER_DAY_V1
            || self.subtotal_minor != calculate_invoice_subtotal_minor(
                self.hourly_rate_minor, self.approved_duration_seconds,
            )?
            || self.status != InvoiceDraftStatusV1::Draft
            || self.tax_status != InvoiceTaxStatusV1::NotCalculated
        {
            return Err(FreelancerContractErrorV1::InvalidInvoiceDraft);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreelancerContractErrorV1 {
    InvalidWorkspace,
    DuplicateProjectAlias,
    InvalidProject,
    InvalidCategoryRule,
    InvalidRounding,
    InvalidInvoiceDraft,
    InvalidSignedClientReport,
    AmountOverflow,
}

impl fmt::Display for FreelancerContractErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidWorkspace => "Invalid local Freelancer workspace",
            Self::DuplicateProjectAlias => "Duplicate Freelancer project alias",
            Self::InvalidProject => "Invalid local Freelancer project",
            Self::InvalidCategoryRule => "Invalid local project category rule",
            Self::InvalidRounding => "Invalid Freelancer rounding policy",
            Self::InvalidInvoiceDraft => "Invalid local invoice draft",
            Self::InvalidSignedClientReport => "Invalid signed client report",
            Self::AmountOverflow => "Invoice draft amount exceeds the supported range",
        })
    }
}

impl std::error::Error for FreelancerContractErrorV1 {}

pub fn round_freelancer_duration(
    seconds: u32,
    increment_seconds: u32,
    mode: FreelancerRoundingModeV1,
) -> Result<u32, FreelancerContractErrorV1> {
    if seconds > APPROVED_TIMESHEET_MAX_SECONDS_PER_DAY_V1 {
        return Err(FreelancerContractErrorV1::InvalidRounding);
    }
    if mode == FreelancerRoundingModeV1::None {
        return if increment_seconds == 0 {
            Ok(seconds)
        } else {
            Err(FreelancerContractErrorV1::InvalidRounding)
        };
    }
    if !(1..=3_600).contains(&increment_seconds) {
        return Err(FreelancerContractErrorV1::InvalidRounding);
    }
    let seconds = u64::from(seconds);
    let increment = u64::from(increment_seconds);
    let rounded = match mode {
        FreelancerRoundingModeV1::None => unreachable!(),
        FreelancerRoundingModeV1::Up => seconds.div_ceil(increment) * increment,
        FreelancerRoundingModeV1::Down => seconds / increment * increment,
        FreelancerRoundingModeV1::Nearest => ((seconds + increment / 2) / increment) * increment,
    };
    u32::try_from(rounded)
        .ok()
        .filter(|duration| *duration <= APPROVED_TIMESHEET_MAX_SECONDS_PER_DAY_V1)
        .ok_or(FreelancerContractErrorV1::InvalidRounding)
}

pub fn calculate_invoice_subtotal_minor(
    hourly_rate_minor: u64,
    approved_duration_seconds: u32,
) -> Result<u64, FreelancerContractErrorV1> {
    // Currency is user-selected minor units; half-up is explicit and tax is excluded.
    let numerator = u128::from(hourly_rate_minor) * u128::from(approved_duration_seconds);
    let amount = numerator.checked_add(1_800)
        .ok_or(FreelancerContractErrorV1::AmountOverflow)? / 3_600;
    let amount = u64::try_from(amount).map_err(|_| FreelancerContractErrorV1::AmountOverflow)?;
    if amount > FREELANCER_MAX_SAFE_MINOR_UNITS_V1 {
        return Err(FreelancerContractErrorV1::AmountOverflow);
    }
    Ok(amount)
}

fn validate_project(project: &FreelancerProjectV1) -> Result<(), FreelancerContractErrorV1> {
    if !valid_alias(&project.project_alias)
        || project.client_alias.as_deref().is_some_and(|alias| !valid_alias(alias))
        || !valid_local_label(&project.label, 120)
        || project.rounding_increment_seconds > 3_600
        || (project.rounding_mode == FreelancerRoundingModeV1::None
            && project.rounding_increment_seconds != 0)
        || (project.rounding_mode != FreelancerRoundingModeV1::None
            && project.rounding_increment_seconds == 0)
        || project.currency_code.as_ref().is_some_and(|code| !valid_currency(code))
        || project.hourly_rate_minor.is_some_and(|rate| rate > FREELANCER_MAX_SAFE_MINOR_UNITS_V1)
        || project.hourly_cost_minor.is_some_and(|rate| rate > FREELANCER_MAX_SAFE_MINOR_UNITS_V1)
        || (project.hourly_rate_minor.is_some() || project.hourly_cost_minor.is_some()) != project.currency_code.is_some()
    {
        return Err(FreelancerContractErrorV1::InvalidProject);
    }
    Ok(())
}

fn valid_alias(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && is_alphanumeric(value.as_bytes()[0])
        && is_alphanumeric(value.as_bytes()[value.len() - 1])
        && value.bytes().all(|byte| is_alphanumeric(byte) || byte == b'-')
}

pub(crate) fn is_valid_project_alias(value: &str) -> bool {
    valid_alias(value)
}

fn valid_local_label(value: &str, max_bytes: usize) -> bool {
    !value.trim().is_empty()
        && value.len() <= max_bytes
        && !value.chars().any(char::is_control)
}

fn valid_currency(value: &str) -> bool {
    value.len() == 3 && value.bytes().all(|byte| byte.is_ascii_uppercase())
}

fn valid_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn parse_iso_date(value: &str) -> Option<NaiveDate> {
    NaiveDate::parse_from_str(value, "%Y-%m-%d")
        .ok()
        .filter(|date| date.format("%Y-%m-%d").to_string() == value)
}

fn is_alphanumeric(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit()
}
