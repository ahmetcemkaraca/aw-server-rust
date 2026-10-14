use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[repr(u8)]
pub enum ReportExecutionErrorV1 {
    RowLimit = 1,
    ByteLimit,
    ValueLimit,
    FuelLimit,
    Deadline,
    Cancelled,
    StaleConfiguration,
    SourceUnavailable,
    EntitlementUnavailable,
    DataIntegrity,
    InternalError,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueryLimits {
    pub max_periods: usize,
    pub max_hosts: usize,
    pub max_source_rows: u64,
    pub max_merged_rows: u64,
    pub max_rows: u64,
    pub max_bytes: u64,
    pub max_values: u64,
    pub max_fuel: u64,
    pub max_query_bytes: usize,
    pub max_ast_depth: usize,
    pub max_event_json_bytes: usize,
    pub max_regex_bytes: usize,
    pub max_regex_backtracks: usize,
    pub regex_cache_entries: usize,
    pub execution_timeout: Duration,
}
impl QueryLimits {
    pub const MANAGED: Self = Self {
        max_periods: 186,
        max_hosts: 8,
        max_source_rows: 2_000,
        max_merged_rows: 4_000,
        max_rows: 250_000,
        max_bytes: 32 * 1024 * 1024,
        max_values: 1_000_000,
        max_fuel: 5_000_000,
        max_query_bytes: 64 * 1024,
        max_ast_depth: 64,
        max_event_json_bytes: 1024 * 1024,
        max_regex_bytes: 4_096,
        max_regex_backtracks: 100_000,
        regex_cache_entries: 256,
        execution_timeout: Duration::from_secs(30),
    };
}

impl std::fmt::Display for ReportExecutionErrorV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::RowLimit => "row-limit",
            Self::ByteLimit => "byte-limit",
            Self::ValueLimit => "value-limit",
            Self::FuelLimit => "fuel-limit",
            Self::Deadline => "deadline",
            Self::Cancelled => "cancelled",
            Self::StaleConfiguration => "stale-configuration",
            Self::SourceUnavailable => "source-unavailable",
            Self::EntitlementUnavailable => "entitlement-unavailable",
            Self::DataIntegrity => "data-integrity",
            Self::InternalError => "internal-error",
        })
    }
}
impl std::error::Error for ReportExecutionErrorV1 {}

#[derive(Clone, Debug, Default)]
pub struct ReportControlStatsV1 {
    pub queue_wait_ms: Option<u64>,
    pub execution_ms: Option<u64>,
    pub rows: u64,
    pub bytes: u64,
    pub values: u64,
    pub fuel: u64,
}

#[derive(Clone)]
pub struct QueryControl {
    managed: bool,
    shared: Arc<ControlState>,
}
struct ControlState {
    created: Instant,
    started: OnceLock<Instant>,
    stopped: AtomicU8,
    rows: AtomicU64,
    bytes: AtomicU64,
    values: AtomicU64,
    fuel: AtomicU64,
    #[cfg(test)]
    fake_clock: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    fake_ms: AtomicU64,
}
impl QueryControl {
    fn new(managed: bool) -> Self {
        Self {
            managed,
            shared: Arc::new(ControlState {
                created: Instant::now(),
                started: OnceLock::new(),
                stopped: AtomicU8::new(0),
                rows: AtomicU64::new(0),
                bytes: AtomicU64::new(0),
                values: AtomicU64::new(0),
                fuel: AtomicU64::new(0),
                #[cfg(test)]
                fake_clock: std::sync::atomic::AtomicBool::new(false),
                #[cfg(test)]
                fake_ms: AtomicU64::new(0),
            }),
        }
    }
    pub fn managed() -> Self {
        Self::new(true)
    }
    pub fn unlimited() -> Self {
        Self::new(false)
    }
    pub fn charge_json_copy(
        &self,
        value: &serde_json::Value,
    ) -> Result<(), ReportExecutionErrorV1> {
        if !self.managed {
            return self.checkpoint();
        }
        self.charge_json_copy_inner(value, 1)
    }
    fn charge_json_copy_inner(
        &self,
        value: &serde_json::Value,
        depth: usize,
    ) -> Result<(), ReportExecutionErrorV1> {
        if depth > QueryLimits::MANAGED.max_ast_depth {
            return self.charge_values(QueryLimits::MANAGED.max_values + 1);
        }
        self.charge_fuel(1)?;
        self.charge_values(1)?;
        self.charge_bytes(std::mem::size_of::<serde_json::Value>() as u64)?;
        match value {
            serde_json::Value::String(text) => self.charge_bytes(text.len() as u64)?,
            serde_json::Value::Array(values) => {
                for value in values {
                    self.charge_json_copy_inner(value, depth + 1)?;
                }
            }
            serde_json::Value::Object(entries) => {
                for (key, value) in entries {
                    self.charge_values(1)?;
                    self.charge_bytes((key.len() + std::mem::size_of::<String>()) as u64)?;
                    self.charge_json_copy_inner(value, depth + 1)?;
                }
            }
            _ => {}
        }
        self.checkpoint()
    }
    pub fn charge_event_copy(&self, event: &crate::Event) -> Result<(), ReportExecutionErrorV1> {
        if !self.managed {
            return self.checkpoint();
        }
        self.charge_values(1)?;
        self.charge_bytes(std::mem::size_of::<crate::Event>() as u64)?;
        for (key, value) in &event.data {
            self.charge_values(1)?;
            self.charge_bytes((key.len() + std::mem::size_of::<String>()) as u64)?;
            self.charge_json_copy(value)?;
        }
        self.checkpoint()
    }
    pub fn is_managed(&self) -> bool {
        self.managed
    }
    pub fn begin_execution(&self) -> Result<(), ReportExecutionErrorV1> {
        self.checkpoint()?;
        self.shared.started.get_or_init(|| self.now());
        self.checkpoint()
    }
    pub fn cancel(&self) {
        let _ = self.stop(ReportExecutionErrorV1::Cancelled);
    }
    // The first failure stays latched even if a caller ignores a charge result.
    fn stop(&self, reason: ReportExecutionErrorV1) -> ReportExecutionErrorV1 {
        let stored = self
            .shared
            .stopped
            .compare_exchange(0, reason as u8, Ordering::AcqRel, Ordering::Acquire)
            .unwrap_or_else(|old| old);
        if stored == 0 {
            reason
        } else {
            decode_reason(stored)
        }
    }
    pub fn checkpoint(&self) -> Result<(), ReportExecutionErrorV1> {
        let stopped = self.shared.stopped.load(Ordering::Acquire);
        if stopped != 0 {
            return Err(decode_reason(stopped));
        }
        if self.managed
            && self.shared.started.get().is_some_and(|start| {
                self.now().saturating_duration_since(*start)
                    >= QueryLimits::MANAGED.execution_timeout
            })
        {
            return Err(self.stop(ReportExecutionErrorV1::Deadline));
        }
        Ok(())
    }
    fn charge(
        &self,
        counter: &AtomicU64,
        amount: u64,
        cap: u64,
        reason: ReportExecutionErrorV1,
    ) -> Result<(), ReportExecutionErrorV1> {
        self.checkpoint()?;
        if !self.managed {
            return Ok(());
        }
        if counter
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |old| {
                old.checked_add(amount).filter(|next| *next <= cap)
            })
            .is_err()
        {
            return Err(self.stop(reason));
        }
        self.checkpoint()
    }
    pub fn charge_rows(&self, amount: u64) -> Result<(), ReportExecutionErrorV1> {
        self.charge(
            &self.shared.rows,
            amount,
            QueryLimits::MANAGED.max_rows,
            ReportExecutionErrorV1::RowLimit,
        )
    }
    pub fn charge_bytes(&self, amount: u64) -> Result<(), ReportExecutionErrorV1> {
        self.charge(
            &self.shared.bytes,
            amount,
            QueryLimits::MANAGED.max_bytes,
            ReportExecutionErrorV1::ByteLimit,
        )
    }
    pub fn charge_values(&self, amount: u64) -> Result<(), ReportExecutionErrorV1> {
        self.charge(
            &self.shared.values,
            amount,
            QueryLimits::MANAGED.max_values,
            ReportExecutionErrorV1::ValueLimit,
        )
    }
    pub fn charge_fuel(&self, amount: u64) -> Result<(), ReportExecutionErrorV1> {
        self.charge(
            &self.shared.fuel,
            amount,
            QueryLimits::MANAGED.max_fuel,
            ReportExecutionErrorV1::FuelLimit,
        )
    }
    pub fn stats(&self) -> ReportControlStatsV1 {
        let started = self.shared.started.get();
        ReportControlStatsV1 {
            queue_wait_ms: started
                .map(|t| millis(t.saturating_duration_since(self.shared.created))),
            execution_ms: started.map(|t| millis(self.now().saturating_duration_since(*t))),
            rows: self.shared.rows.load(Ordering::Acquire),
            bytes: self.shared.bytes.load(Ordering::Acquire),
            values: self.shared.values.load(Ordering::Acquire),
            fuel: self.shared.fuel.load(Ordering::Acquire),
        }
    }
    fn now(&self) -> Instant {
        #[cfg(test)]
        if self.shared.fake_clock.load(Ordering::Relaxed) {
            return self
                .shared
                .created
                .checked_add(Duration::from_millis(
                    self.shared.fake_ms.load(Ordering::Relaxed),
                ))
                .unwrap_or(self.shared.created);
        }
        Instant::now()
    }
    #[cfg(test)]
    fn advance_clock(&self, millis: u64) {
        self.shared.fake_clock.store(true, Ordering::Relaxed);
        self.shared.fake_ms.fetch_add(millis, Ordering::Relaxed);
    }
}

fn millis(time: Duration) -> u64 {
    u64::try_from(time.as_millis()).unwrap_or(u64::MAX)
}
fn decode_reason(value: u8) -> ReportExecutionErrorV1 {
    use ReportExecutionErrorV1::*;
    match value {
        1 => RowLimit,
        2 => ByteLimit,
        3 => ValueLimit,
        4 => FuelLimit,
        5 => Deadline,
        6 => Cancelled,
        7 => StaleConfiguration,
        8 => SourceUnavailable,
        9 => EntitlementUnavailable,
        10 => DataIntegrity,
        _ => InternalError,
    }
}

pub trait ReportFeatureAccessV1: Send + Sync {
    fn with_access(
        &self,
        action: Box<dyn FnOnce() -> Result<(), ReportExecutionErrorV1> + '_>,
    ) -> Result<(), ReportExecutionErrorV1>;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn report_control_deadline_begins_only_after_queue_wait() {
        let control = QueryControl::managed();
        control.advance_clock(60_000);
        assert_eq!(control.checkpoint(), Ok(()));
        control.begin_execution().unwrap();
        assert_eq!(control.stats().queue_wait_ms, Some(60_000));
        control.advance_clock(30_001);
        assert_eq!(control.checkpoint(), Err(ReportExecutionErrorV1::Deadline));
    }
    #[test]
    fn report_control_deadline_cannot_be_extended_by_another_begin() {
        let control = QueryControl::managed();
        control.advance_clock(0);
        control.begin_execution().unwrap();
        control.advance_clock(1_000);
        control.begin_execution().unwrap();
        control.advance_clock(29_001);
        assert_eq!(control.checkpoint(), Err(ReportExecutionErrorV1::Deadline));
    }
}
