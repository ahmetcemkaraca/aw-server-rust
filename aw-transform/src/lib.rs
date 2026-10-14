#[macro_use]
extern crate log;

// TODO: Move this to some more suitable place
#[macro_export]
macro_rules! json_map {
    { $( $key:literal : $value:expr),* } => {{
        use serde_json::Value;
        use serde_json::map::Map;
        #[allow(unused_mut)]
        let mut map : Map<String, Value> = Map::new();
        $(
          map.insert( $key.to_string(), json!($value) );
        )*
        map
    }};
}

pub mod classify;

mod heartbeat;
pub use heartbeat::heartbeat;

mod find_bucket;
pub use find_bucket::find_bucket;

mod flood;
pub use flood::flood;

mod merge;
pub use merge::merge_events_by_keys;

mod chunk;
pub use chunk::chunk_events_by_key;

mod sort;
pub use sort::{sort_by_duration, sort_by_timestamp};

mod filter_keyvals;
pub use filter_keyvals::{exclude_keyvals, filter_keyvals, filter_keyvals_regex};

mod filter_period;
pub use filter_period::filter_period_intersect;

mod split_url;
pub use split_url::split_url_event;

mod period_union;
pub use period_union::period_union;

mod union_no_overlap;
pub use union_no_overlap::union_no_overlap;

pub use filter_keyvals::{exclude_keyvals_controlled, filter_keyvals_controlled};
pub use filter_period::filter_period_intersect_controlled;
pub use flood::flood_controlled;
pub use merge::merge_events_by_keys_controlled;
pub use sort::{sort_by_duration_controlled, sort_by_timestamp_controlled};
pub use union_no_overlap::union_no_overlap_controlled;

fn report_event_slot(
    control: &aw_models::QueryControl,
) -> Result<(), aw_models::ReportExecutionErrorV1> {
    control.charge_values(1)?;
    control.charge_bytes(std::mem::size_of::<aw_models::Event>() as u64)
}
fn report_event_end(
    event: &aw_models::Event,
    control: &aw_models::QueryControl,
) -> Result<chrono::DateTime<chrono::Utc>, aw_models::ReportExecutionErrorV1> {
    if !control.is_managed() {
        control.checkpoint()?;
        return Ok(event.calculate_endtime());
    }
    let duration = event
        .duration
        .num_nanoseconds()
        .filter(|n| *n >= 0)
        .ok_or(aw_models::ReportExecutionErrorV1::DataIntegrity)?;
    event
        .timestamp
        .checked_add_signed(chrono::Duration::nanoseconds(duration))
        .ok_or(aw_models::ReportExecutionErrorV1::DataIntegrity)
}
fn report_merged_slot(
    length: usize,
    control: &aw_models::QueryControl,
) -> Result<(), aw_models::ReportExecutionErrorV1> {
    if control.is_managed() && length >= aw_models::QueryLimits::MANAGED.max_merged_rows as usize {
        return Err(aw_models::ReportExecutionErrorV1::RowLimit);
    }
    report_event_slot(control)
}
