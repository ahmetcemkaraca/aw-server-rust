use aw_models::*;
use chrono::{DateTime, Datelike, NaiveDate, SecondsFormat, Utc};
use std::collections::BTreeMap;
use ReportExecutionErrorV1 as Error;
type Result<T> = std::result::Result<T, Error>;
pub struct ProcessedReportDayV1 {
    pub row: ReportDailyV1,
    pub events: Vec<Event>,
}
pub struct ReportQueryDayV1 {
    pub duration: f64,
    pub events: Vec<Event>,
}
pub(crate) fn record<T>(control: &QueryControl, fields: u64) -> Result<()> {
    control.charge_fuel(1)?;
    control.charge_values(fields + 1)?;
    control.charge_bytes(std::mem::size_of::<T>() as u64)
}
pub(crate) fn text(value: &str, control: &QueryControl) -> Result<String> {
    control.charge_values(1)?;
    control.charge_bytes(value.len() as u64)?;
    Ok(value.to_owned())
}
pub(crate) fn finite(value: f64) -> Result<f64> {
    if value.is_finite() {
        Ok(value)
    } else {
        Err(Error::DataIntegrity)
    }
}
fn valid_date(value: &str) -> Option<NaiveDate> {
    let bytes = value.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !bytes
            .iter()
            .enumerate()
            .all(|(i, b)| i == 4 || i == 7 || b.is_ascii_digit())
    {
        return None;
    }
    NaiveDate::parse_from_str(value, "%Y-%m-%d").ok()
}
fn js_trim(value: &str) -> &str {
    value.trim_matches(|c|matches!(c,'\u{0009}'..='\u{000d}'|' '| '\u{00a0}'|'\u{1680}'|'\u{2000}'..='\u{200a}'|'\u{2028}'|'\u{2029}'|'\u{202f}'|'\u{205f}'|'\u{3000}'|'\u{feff}'))
}
fn duration(event: &Event) -> Result<f64> {
    event
        .duration
        .num_nanoseconds()
        .filter(|n| *n >= 0)
        .map(|n| n as f64 / 1e9)
        .ok_or(Error::DataIntegrity)
}
fn event_ms(event: &Event) -> Result<(f64, f64)> {
    let start = event.timestamp.timestamp_millis() as f64;
    let end = finite(start + duration(event)? * 1000.0)?;
    Ok((start, end))
}
fn interval(start: f64, end: f64, control: &QueryControl) -> Result<ReportMetricIntervalV1> {
    record::<ReportMetricIntervalV1>(control, 3)?;
    Ok(ReportMetricIntervalV1 {
        start: iso_ms(start, control)?,
        end: iso_ms(end, control)?,
        duration_seconds: finite((end - start) / 1000.0)?,
    })
}
fn iso_ms(value: f64, control: &QueryControl) -> Result<String> {
    // JS Date TimeClip truncates fractional milliseconds after threshold arithmetic.
    if !value.is_finite() || value.abs() > 8_640_000_000_000_000.0 {
        return Err(Error::DataIntegrity);
    }
    control.charge_values(1)?;
    control.charge_bytes(32)?;
    Ok(DateTime::<Utc>::from_timestamp_millis(value.trunc() as i64)
        .ok_or(Error::DataIntegrity)?
        .to_rfc3339_opts(SecondsFormat::Millis, true))
}
fn copy_paths(paths: &[Vec<String>], control: &QueryControl) -> Result<Vec<Vec<String>>> {
    let mut copied = Vec::new();
    for path in paths {
        control.charge_values(1)?;
        control.charge_bytes(std::mem::size_of::<Vec<String>>() as u64)?;
        let mut row = Vec::new();
        for part in path {
            control.charge_bytes(std::mem::size_of::<String>() as u64)?;
            row.push(text(part, control)?);
        }
        copied.push(row);
    }
    Ok(copied)
}
pub fn calculate_daily(
    periods: &[ResolvedPeriodV1],
    results: Vec<ReportQueryDayV1>,
    params: &ReportParametersV1,
    control: &QueryControl,
) -> Result<(Vec<ProcessedReportDayV1>, ReportCalculationManifestV1)> {
    control.checkpoint()?;
    if periods.len() != results.len() {
        return Err(Error::DataIntegrity);
    }
    let mut days = Vec::new();
    let mut seen = 0u64;
    let mut with_events = 0u64;
    let mut intervals = Vec::new();
    for (period, result) in periods.iter().zip(results) {
        control.charge_fuel(1)?;
        period.bounds()?;
        if !result.duration.is_finite() || result.duration < 0.0 {
            return Err(Error::DataIntegrity);
        }
        let mut timed = Vec::new();
        for event in &result.events {
            control.charge_fuel(1)?;
            control.charge_values(1)?;
            control.charge_bytes(std::mem::size_of::<(f64, f64)>() as u64)?;
            timed.push(event_ms(event)?);
        }
        control.charge_bytes((timed.len() * std::mem::size_of::<(f64, f64)>()) as u64)?;
        timed.sort_by(|a, b| a.0.total_cmp(&b.0));
        control.checkpoint()?;
        let mut bridges = 0.0;
        if params.break_time_seconds > 0 {
            for pair in timed.windows(2) {
                control.charge_fuel(1)?;
                let gap = (pair[1].0 - pair[0].1) / 1000.0;
                if gap > 0.0 && gap <= params.break_time_seconds as f64 {
                    bridges = finite(bridges + gap)?;
                }
            }
        }
        let total = finite(result.duration + bridges)?;
        let sessions = result.events.len() as u64;
        seen = seen.checked_add(sessions).ok_or(Error::DataIntegrity)?;
        with_events += u64::from(sessions > 0);
        let start = period
            .interval
            .split_once('/')
            .ok_or(Error::DataIntegrity)?
            .0;
        let date = DateTime::parse_from_rfc3339(start)
            .map_err(|_| Error::DataIntegrity)?
            .date_naive();
        control.charge_values(1)?;
        control.charge_bytes(10)?;
        let date = date.format("%Y-%m-%d").to_string();
        record::<ProcessedReportDayV1>(control, 4)?;
        days.push(ProcessedReportDayV1 {
            row: ReportDailyV1 {
                date,
                duration: total,
                sessions,
                avg_session: if sessions > 0 {
                    total / sessions as f64
                } else {
                    0.0
                },
            },
            events: result.events,
        });
        control.charge_bytes(std::mem::size_of::<String>() as u64)?;
        intervals.push(text(&period.interval, control)?);
    }
    record::<ReportCalculationManifestV1>(control, 11)?;
    record::<ReportCalculationCoverageV1>(control, 5)?;
    let mut hosts = Vec::new();
    for host in &params.host_ids {
        control.charge_bytes(std::mem::size_of::<String>() as u64)?;
        hosts.push(text(host, control)?);
    }
    let manifest = ReportCalculationManifestV1 {
        schema_version: 1,
        method_id: text("work-time-report", control)?,
        method_version: 1,
        formula: text(
            "query duration plus positive adjacent gaps no greater than the selected break time",
            control,
        )?,
        input_periods: intervals,
        host_ids: hosts,
        category_paths: copy_paths(&params.category_paths, control)?,
        date_range: text(&params.date_range, control)?,
        start_of_day: text(&params.start_of_day, control)?,
        break_time_seconds: params.break_time_seconds,
        coverage: ReportCalculationCoverageV1 {
            requested_periods: periods.len() as u64,
            periods_with_events: with_events,
            events_seen: seen,
            source_health: text("unknown", control)?,
            limitation: text(
                "An empty period cannot distinguish no activity from missing capture.",
                control,
            )?,
        },
    };
    Ok((days, manifest))
}
fn ordered<'a>(
    days: &'a [ProcessedReportDayV1],
    control: &QueryControl,
) -> Result<Option<Vec<(&'a ProcessedReportDayV1, NaiveDate)>>> {
    let mut sorted = Vec::new();
    for day in days {
        control.charge_fuel(1)?;
        let Some(date) = valid_date(&day.row.date) else {
            return Ok(None);
        };
        control.charge_values(1)?;
        control.charge_bytes(std::mem::size_of::<(&ProcessedReportDayV1, NaiveDate)>() as u64)?;
        sorted.push((day, date));
    }
    control.charge_bytes(
        (sorted.len() * std::mem::size_of::<(&ProcessedReportDayV1, NaiveDate)>()) as u64,
    )?;
    sorted.sort_by_key(|(_, date)| *date);
    control.checkpoint()?;
    if sorted
        .windows(2)
        .any(|pair| pair[1].1.signed_duration_since(pair[0].1).num_days() != 1)
    {
        return Ok(None);
    }
    Ok(Some(sorted))
}
pub fn aggregate_days(
    days: &[ProcessedReportDayV1],
    unit: &str,
    control: &QueryControl,
) -> Result<Vec<ReportAggregateV1>> {
    control.checkpoint()?;
    if unit != "week" && unit != "month" {
        return Err(Error::InternalError);
    }
    let sorted = ordered(days, control)?.ok_or(Error::StaleConfiguration)?;
    let mut groups: Vec<ReportAggregateV1> = Vec::new();
    for (day, date) in sorted {
        control.charge_fuel(1)?;
        control.charge_bytes(10)?;
        let period = if unit == "week" {
            format!("{}-W{:02}", date.iso_week().year(), date.iso_week().week())
        } else {
            date.format("%Y-%m").to_string()
        };
        if groups.last().is_none_or(|group| group.period != period) {
            record::<ReportAggregateV1>(control, 10)?;
            groups.push(ReportAggregateV1 {
                method_id: text("work-time-calendar-aggregate", control)?,
                method_version: 1,
                unit: text(unit, control)?,
                period,
                start_date: text(&day.row.date, control)?,
                end_date: text(&day.row.date, control)?,
                days: 0,
                days_with_events: 0,
                duration: 0.0,
                sessions: 0,
            });
        }
        let group = groups.last_mut().ok_or(Error::InternalError)?;
        group.end_date = text(&day.row.date, control)?;
        group.days += 1;
        group.days_with_events += u64::from(day.row.sessions > 0);
        group.sessions = group
            .sessions
            .checked_add(day.row.sessions)
            .ok_or(Error::DataIntegrity)?;
        group.duration = finite(group.duration + day.row.duration)?;
    }
    Ok(groups)
}
fn period_summary(
    days: &[(&ProcessedReportDayV1, NaiveDate)],
    control: &QueryControl,
) -> Result<ReportPeriodSummaryV1> {
    record::<ReportPeriodSummaryV1>(control, 6)?;
    let mut events = 0u64;
    let mut periods = 0u64;
    let mut total = 0.0;
    for (day, _) in days {
        control.charge_fuel(1)?;
        events = events
            .checked_add(day.row.sessions)
            .ok_or(Error::DataIntegrity)?;
        periods += u64::from(day.row.sessions > 0);
        total = finite(total + day.row.duration)?;
    }
    Ok(ReportPeriodSummaryV1 {
        start_date: text(
            &days.first().ok_or(Error::InternalError)?.0.row.date,
            control,
        )?,
        end_date: text(
            &days.last().ok_or(Error::InternalError)?.0.row.date,
            control,
        )?,
        periods: days.len() as u64,
        periods_with_events: periods,
        observed_events: events,
        duration: total,
    })
}
pub fn compare_periods(
    current: &[ProcessedReportDayV1],
    previous: &[ProcessedReportDayV1],
    control: &QueryControl,
) -> Result<Option<ReportComparisonV1>> {
    let Some(a) = ordered(current, control)? else {
        return Ok(None);
    };
    let Some(b) = ordered(previous, control)? else {
        return Ok(None);
    };
    if a.is_empty() || a.len() != b.len() || b.last().ok_or(Error::InternalError)?.1 >= a[0].1 {
        return Ok(None);
    }
    let current = period_summary(&a, control)?;
    let previous = period_summary(&b, control)?;
    let change = finite(current.duration - previous.duration)?;
    let note = if current.observed_events == previous.observed_events {
        None
    } else {
        control.charge_values(1)?;
        control.charge_bytes(128)?;
        Some(if current.observed_events < previous.observed_events {
            format!(
                "Current period has fewer observed events ({} vs {}).",
                current.observed_events, previous.observed_events
            )
        } else {
            format!(
                "Previous period has fewer observed events ({} vs {}).",
                previous.observed_events, current.observed_events
            )
        })
    };
    record::<ReportComparisonV1>(control, 7)?;
    Ok(Some(ReportComparisonV1 {
        method_id: text("work-time-period-comparison", control)?,
        method_version: 1,
        duration_change_percent: if previous.duration > 0.0 {
            Some(finite(change / previous.duration * 100.0)?)
        } else {
            None
        },
        current,
        previous,
        duration_change: change,
        coverage_note: note,
    }))
}
fn field_add(
    map: &mut BTreeMap<String, (f64, u64)>,
    label: &str,
    value: f64,
    control: &QueryControl,
) -> Result<()> {
    if label.is_empty() {
        return Ok(());
    }
    control.charge_fuel(1)?;
    if let Some(row) = map.get_mut(label) {
        row.0 = finite(row.0 + value)?;
        row.1 = row.1.checked_add(1).ok_or(Error::DataIntegrity)?;
    } else {
        control.charge_values(1)?;
        control.charge_bytes(std::mem::size_of::<(String, (f64, u64))>() as u64)?;
        map.insert(text(label, control)?, (value, 1));
    }
    Ok(())
}
pub(crate) fn utf16_order(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}
fn field_rows(
    map: BTreeMap<String, (f64, u64)>,
    control: &QueryControl,
) -> Result<Vec<ReportFieldRowV1>> {
    let mut rows = Vec::new();
    for (label, (duration, sessions)) in map {
        record::<ReportFieldRowV1>(control, 3)?;
        rows.push(ReportFieldRowV1 {
            label,
            duration,
            sessions,
        });
    }
    control.charge_bytes((rows.len() * std::mem::size_of::<ReportFieldRowV1>()) as u64)?;
    rows.sort_by(|a, b| {
        b.duration
            .total_cmp(&a.duration)
            .then_with(|| utf16_order(&a.label, &b.label))
    });
    control.checkpoint()?;
    Ok(rows)
}
pub fn summarize_fields(
    days: &[ProcessedReportDayV1],
    control: &QueryControl,
) -> Result<ReportFieldSummaryV1> {
    record::<ReportFieldSummaryV1>(control, 6)?;
    let mut project = BTreeMap::new();
    let mut app = BTreeMap::new();
    let mut domain = BTreeMap::new();
    let mut active = 0.0;
    let mut away = 0.0;
    let mut seen = 0u64;
    let mut with_status = 0u64;
    for day in days {
        for event in &day.events {
            control.charge_fuel(1)?;
            let value = duration(event)?;
            seen += 1;
            if let Some(label) = event
                .data
                .get("project")
                .and_then(serde_json::Value::as_str)
            {
                field_add(&mut project, label, value, control)?;
            }
            if let Some(label) = event.data.get("app").and_then(serde_json::Value::as_str) {
                field_add(&mut app, label, value, control)?;
            }
            let candidate = event
                .data
                .get("domain")
                .and_then(serde_json::Value::as_str)
                .or_else(|| event.data.get("url").and_then(serde_json::Value::as_str));
            if let Some(candidate) = candidate {
                control.charge_bytes(
                    (candidate.len() * 4 + std::mem::size_of::<url::Url>() + 8) as u64,
                )?;
                let prefixed;
                if candidate.contains("://") {
                    prefixed = None;
                } else {
                    prefixed = Some(format!("https://{candidate}"));
                }
                if let Ok(parsed) = url::Url::parse(prefixed.as_deref().unwrap_or(candidate)) {
                    if let Some(host) = parsed.host_str() {
                        control.charge_bytes((host.len() * 3) as u64)?;
                        field_add(&mut domain, &host.to_lowercase(), value, control)?;
                    }
                }
            }
            if let Some(status) = event.data.get("status").and_then(serde_json::Value::as_str) {
                control.charge_bytes((status.len() * 3) as u64)?;
                match status.to_lowercase().as_str() {
                    "active" | "not-afk" => {
                        active = finite(active + value)?;
                        with_status += 1;
                    }
                    "afk" | "away" | "idle" => {
                        away = finite(away + value)?;
                        with_status += 1;
                    }
                    _ => {}
                }
            }
        }
    }
    let active_away = if seen > 0 && seen == with_status {
        record::<ReportActiveAwayV1>(control, 2)?;
        Some(ReportActiveAwayV1 {
            active_duration: active,
            away_duration: away,
        })
    } else {
        None
    };
    Ok(ReportFieldSummaryV1 {
        method_id: text("work-time-field-summary", control)?,
        method_version: 1,
        project: field_rows(project, control)?,
        app: field_rows(app, control)?,
        domain: field_rows(domain, control)?,
        active_away,
    })
}
struct Timed<'a> {
    date: &'a str,
    start: f64,
    end: f64,
    event: &'a Event,
}
fn timed<'a>(
    days: &'a [ProcessedReportDayV1],
    control: &QueryControl,
) -> Result<Option<Vec<Timed<'a>>>> {
    let mut events = Vec::new();
    for day in days {
        if valid_date(&day.row.date).is_none() {
            return Ok(None);
        }
        for event in &day.events {
            control.charge_fuel(1)?;
            let Ok((start, end)) = event_ms(event) else {
                return Ok(None);
            };
            record::<Timed>(control, 4)?;
            events.push(Timed {
                date: &day.row.date,
                start,
                end,
                event,
            });
        }
    }
    control.charge_bytes((events.len() * std::mem::size_of::<Timed>()) as u64)?;
    events.sort_by(|a, b| a.date.cmp(b.date).then_with(|| a.start.total_cmp(&b.start)));
    control.checkpoint()?;
    Ok(Some(events))
}
pub fn focus_blocks(
    days: &[ProcessedReportDayV1],
    control: &QueryControl,
) -> Result<ReportFocusBlocksV1> {
    record::<ReportFocusBlocksV1>(control, 6)?;
    record::<ReportFocusThresholdsV1>(control, 2)?;
    let mut result = ReportFocusBlocksV1 {
        method_id: text("focus-blocks", control)?,
        method_version: 1,
        outcome: ReportMetricOutcomeV1::Calculated,
        thresholds: ReportFocusThresholdsV1 {
            minimum_duration_seconds: 1500,
            maximum_gap_seconds: 300,
        },
        intervals: Vec::new(),
        reason: None,
    };
    let events = timed(days, control)?;
    let Some(events) = events.filter(|events| !events.is_empty()) else {
        result.outcome = ReportMetricOutcomeV1::CouldNotDetermine;
        result.reason = Some(text(
            "No valid observed event intervals are available; capture coverage is unknown.",
            control,
        )?);
        return Ok(result);
    };
    let mut block: Option<(&str, f64, f64)> = None;
    for event in events {
        control.charge_fuel(1)?;
        if let Some((date, _, end)) = block {
            if date == event.date && (event.start - end) / 1000.0 <= 300.0 {
                block.as_mut().ok_or(Error::InternalError)?.2 = end.max(event.end);
                continue;
            }
        }
        if let Some((_, a, b)) = block {
            if (b - a) / 1000.0 >= 1500.0 {
                result.intervals.push(interval(a, b, control)?);
            }
        }
        block = Some((event.date, event.start, event.end));
    }
    if let Some((_, a, b)) = block {
        if (b - a) / 1000.0 >= 1500.0 {
            result.intervals.push(interval(a, b, control)?);
        }
    }
    Ok(result)
}
pub fn context_switches(
    days: &[ProcessedReportDayV1],
    control: &QueryControl,
) -> Result<ReportContextSwitchesV1> {
    record::<ReportContextSwitchesV1>(control, 6)?;
    record::<ReportContextThresholdsV1>(control, 1)?;
    let mut result = ReportContextSwitchesV1 {
        method_id: text("context-switches", control)?,
        method_version: 1,
        outcome: ReportMetricOutcomeV1::Calculated,
        thresholds: ReportContextThresholdsV1 {
            maximum_gap_seconds: 60,
        },
        intervals: Vec::new(),
        reason: None,
    };
    let events = timed(days, control)?;
    let mut valid = events.as_ref().is_some_and(|events| events.len() >= 2);
    if let Some(events) = &events {
        for event in events {
            control.charge_fuel(1)?;
            if !event
                .event
                .data
                .get("app")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|s| !js_trim(s).is_empty())
            {
                valid = false;
            }
        }
    }
    if !valid {
        result.outcome = ReportMetricOutcomeV1::CouldNotDetermine;
        result.reason = Some(text(
            "At least two observed events with application names are required.",
            control,
        )?);
        return Ok(result);
    }
    let events = events.ok_or(Error::InternalError)?;
    for pair in events.windows(2) {
        control.charge_fuel(1)?;
        let a = &pair[0];
        let b = &pair[1];
        let gap = (b.start - a.end) / 1000.0;
        let from = js_trim(a.event.data["app"].as_str().ok_or(Error::DataIntegrity)?);
        let to = js_trim(b.event.data["app"].as_str().ok_or(Error::DataIntegrity)?);
        if a.date == b.date && (0.0..=60.0).contains(&gap) && from != to {
            record::<ReportContextIntervalV1>(control, 5)?;
            result.intervals.push(ReportContextIntervalV1 {
                start: iso_ms(a.end, control)?,
                end: iso_ms(b.start, control)?,
                gap_seconds: gap,
                from_app: text(from, control)?,
                to_app: text(to, control)?,
            });
        }
    }
    Ok(result)
}
fn meeting_path(path: &[String]) -> bool {
    path.iter().any(|s| {
        js_trim(s).eq_ignore_ascii_case("meeting") || js_trim(s).eq_ignore_ascii_case("meetings")
    })
}
pub fn meeting_load(
    days: &[ProcessedReportDayV1],
    paths: &[Vec<String>],
    control: &QueryControl,
) -> Result<ReportMeetingLoadV1> {
    record::<ReportMeetingLoadV1>(control, 7)?;
    record::<ReportMeetingThresholdsV1>(control, 1)?;
    let mut result = ReportMeetingLoadV1 {
        method_id: text("meeting-load", control)?,
        method_version: 1,
        outcome: ReportMetricOutcomeV1::Calculated,
        thresholds: ReportMeetingThresholdsV1 {
            minimum_interval_seconds: 300,
        },
        duration_seconds: 0.0,
        intervals: Vec::new(),
        reason: None,
    };
    let mut selected = false;
    for path in paths {
        control.charge_fuel(1)?;
        selected |= meeting_path(path);
    }
    let events = timed(days, control)?;
    let mut valid = selected && events.as_ref().is_some_and(|events| !events.is_empty());
    if let Some(events) = &events {
        for event in events {
            control.charge_fuel(1)?;
            let Some(path) = event
                .event
                .data
                .get("$category")
                .and_then(serde_json::Value::as_array)
            else {
                valid = false;
                continue;
            };
            for segment in path {
                control.charge_fuel(1)?;
                if !segment.is_string() {
                    valid = false;
                }
            }
        }
    }
    if !valid {
        result.outcome = ReportMetricOutcomeV1::CouldNotDetermine;
        result.reason = Some(text(
            if selected {
                "A meeting category and observed categorized events are required."
            } else {
                "Select a category path with a Meeting segment; meeting labels are never inferred."
            },
            control,
        )?);
        return Ok(result);
    }
    let events = events.ok_or(Error::InternalError)?;
    for event in events {
        control.charge_fuel(1)?;
        let path = event.event.data["$category"]
            .as_array()
            .ok_or(Error::DataIntegrity)?;
        let matched = path.iter().any(|s| {
            s.as_str().is_some_and(|s| {
                js_trim(s).eq_ignore_ascii_case("meeting")
                    || js_trim(s).eq_ignore_ascii_case("meetings")
            })
        });
        if matched && (event.end - event.start) / 1000.0 >= 300.0 {
            let value = interval(event.start, event.end, control)?;
            result.duration_seconds = finite(result.duration_seconds + value.duration_seconds)?;
            result.intervals.push(value);
        }
    }
    Ok(result)
}
