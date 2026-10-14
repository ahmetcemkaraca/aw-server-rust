pub mod plan;
pub mod work_report;
use aw_models::*;
use work_report::{finite, record, text};
use ReportExecutionErrorV1 as Error;
pub struct ReportCalculatedV1 {
    pub completed: ReportCompletedV1,
    pub raw_periods: Vec<RawReportPeriodV1>,
}
fn charge_serialized(value: &impl serde::Serialize, control: &QueryControl) -> Result<(), Error> {
    struct Charge<'a>(&'a QueryControl);
    impl std::io::Write for Charge<'_> {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0
                .charge_fuel(1)
                .and_then(|_| self.0.charge_values(1))
                .map_err(|_| std::io::Error::other("report limit"))?;
            self.0
                .charge_bytes(bytes.len() as u64)
                .map_err(|_| std::io::Error::other("report limit"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(Charge(control), value)
        .map_err(|_| control.checkpoint().err().unwrap_or(Error::DataIntegrity))
}
fn coverage(
    snapshot: &ReportInputSnapshotV1,
    control: &QueryControl,
) -> Result<ReportSourceCoverageV1, Error> {
    record::<ReportSourceCoverageV1>(control, 13)?;
    if snapshot.available_source_buckets.len() > 128 {
        return Err(Error::ValueLimit);
    }
    let mut available = Vec::new();
    for id in &snapshot.available_source_buckets {
        record::<String>(control, 1)?;
        available.push(text(id, control)?);
    }
    available.sort_by(|a, b| work_report::utf16_order(a, b));
    available.dedup();
    let mut queried = Vec::new();
    for source in &snapshot.sources {
        for id in [&source.window_bucket_id, &source.afk_bucket_id] {
            record::<String>(control, 1)?;
            queried.push(text(id, control)?);
        }
    }
    queried.sort_by(|a, b| work_report::utf16_order(a, b));
    queried.dedup();
    let mut periods = Vec::new();
    let mut partial = Vec::new();
    for period in &snapshot.input_periods {
        record::<String>(control, 1)?;
        periods.push(text(&period.period.interval, control)?);
        let (start, end) = period.period.bounds()?;
        if snapshot.captured_at > start && snapshot.captured_at < end {
            record::<String>(control, 1)?;
            partial.push(text(&period.period.local_date, control)?);
        }
    }
    let many = snapshot.sources.len() > 1;
    record::<ReportClockSkewV1>(control, 3)?;
    Ok(ReportSourceCoverageV1 {
        method_id: text("work-report-source-coverage", control)?,
        method_version: 1,
        available_source_buckets: available,
        queried_source_buckets: queried,
        queried_periods: periods,
        partial_periods: partial,
        limited_periods: Vec::new(),
        source_row_limit: 2000,
        report_row_limit: 4000,
        timezone: text(&snapshot.request.timezone, control)?,
        source_health: text("unknown", control)?,
        clock_skew: ReportClockSkewV1 {
            status: text(if many { "unknown" } else { "not_applicable" }, control)?,
            correction_bound_seconds: 0,
            limitation: text(
                if many {
                    "No device clock correction is applied; multi-device alignment is unknown."
                } else {
                    "No cross-device clock correction is applied."
                },
                control,
            )?,
        },
    })
}
fn category_summary(
    days: &[work_report::ProcessedReportDayV1],
    control: &QueryControl,
) -> Result<ReportCategorySummaryV1, Error> {
    let mut groups = std::collections::BTreeMap::new();
    for day in days {
        for event in &day.events {
            control.charge_fuel(1)?;
            let path = event
                .data
                .get("$category")
                .and_then(serde_json::Value::as_array)
                .ok_or(Error::DataIntegrity)?;
            if path.is_empty() || path.len() > 8 {
                return Err(Error::DataIntegrity);
            }
            control.charge_bytes((path.len() * std::mem::size_of::<&str>()) as u64)?;
            let mut key = Vec::new();
            for segment in path {
                control.charge_fuel(1)?;
                key.push(segment.as_str().ok_or(Error::DataIntegrity)?);
            }
            // Admit the map slot conservatively before insertion; repeated keys are not refunded.
            record::<(Vec<&str>, chrono::Duration, u64)>(control, 3)?;
            let group = groups
                .entry(key)
                .or_insert((chrono::Duration::zero(), 0u64));
            group.0 = group
                .0
                .checked_add(&event.duration)
                .ok_or(Error::DataIntegrity)?;
            group.1 = group.1.checked_add(1).ok_or(Error::DataIntegrity)?;
        }
    }
    let mut categories = Vec::new();
    for (path, (duration, sessions)) in groups {
        control.charge_fuel(1)?;
        let mut category_path = Vec::new();
        for segment in path {
            record::<String>(control, 1)?;
            category_path.push(text(segment, control)?);
        }
        record::<ReportCategorySummaryRowV1>(control, 3)?;
        categories.push(ReportCategorySummaryRowV1 {
            category_path,
            duration: duration.num_milliseconds() as f64 / 1000.0,
            sessions,
        });
    }
    control.charge_bytes(
        (categories.len() * std::mem::size_of::<ReportCategorySummaryRowV1>()) as u64,
    )?;
    control.charge_fuel((categories.len() as u64).saturating_mul(64))?;
    categories.sort_by(|a, b| {
        b.duration.total_cmp(&a.duration).then_with(|| {
            for (x, y) in a.category_path.iter().zip(&b.category_path) {
                let order = work_report::utf16_order(x, y);
                if !order.is_eq() {
                    return order;
                }
            }
            a.category_path.len().cmp(&b.category_path.len())
        })
    });
    control.checkpoint()?;
    record::<ReportCategorySummaryV1>(control, 4)?;
    Ok(ReportCategorySummaryV1 {
        method_id: text("work-time-category-summary", control)?,
        method_version: 1,
        formula: text(
            "categorized event durations grouped by category path; bridged gaps excluded",
            control,
        )?,
        categories,
    })
}
pub fn calculate_report(
    snapshot: &ReportInputSnapshotV1,
    control: &QueryControl,
) -> Result<ReportCalculatedV1, Error> {
    control.checkpoint()?;
    let plan = plan::compile_report_plan(snapshot, control)?;
    let source = crate::FrozenQuerySource::new(snapshot);
    let mut queried = Vec::new();
    for period in &plan.periods {
        control.charge_fuel(1)?;
        let (a, b) = period.bounds()?;
        let output =
            crate::query_controlled(&plan.code, &TimeInterval::new(a, b), &source, control)?;
        let events = output.controlled_events(control)?;
        let mut duration = chrono::Duration::zero();
        for event in &events {
            control.charge_fuel(1)?;
            duration = duration
                .checked_add(&event.duration)
                .ok_or(Error::DataIntegrity)?;
        }
        record::<work_report::ReportQueryDayV1>(control, 2)?;
        queried.push(work_report::ReportQueryDayV1 {
            duration: duration.num_milliseconds() as f64 / 1000.0,
            events,
        });
    }
    let current_count = snapshot.request.current_periods.len();
    if queried.len() != snapshot.input_periods.len() {
        return Err(Error::DataIntegrity);
    }
    control.charge_bytes(
        ((queried.len() - current_count) * std::mem::size_of::<work_report::ReportQueryDayV1>())
            as u64,
    )?;
    let previous_results = queried.split_off(current_count);
    record::<ReportParametersV1>(control, 5)?;
    charge_serialized(&snapshot.request.ordered_host_ids, control)?;
    charge_serialized(&snapshot.template.category_paths, control)?;
    let parameters = ReportParametersV1 {
        host_ids: snapshot.request.ordered_host_ids.clone(),
        category_paths: snapshot.template.category_paths.clone(),
        break_time_seconds: snapshot.template.break_time_seconds,
        date_range: text("custom", control)?,
        start_of_day: text(&snapshot.request.day_start, control)?,
    };
    let (current, calculation_manifest) = work_report::calculate_daily(
        &snapshot.request.current_periods,
        queried,
        &parameters,
        control,
    )?;
    let (previous, _) = work_report::calculate_daily(
        snapshot.request.previous_periods.as_deref().unwrap_or(&[]),
        previous_results,
        &parameters,
        control,
    )?;
    let selected = |section: ReportSectionV1| snapshot.template.sections.contains(&section);
    let weekly = if selected(ReportSectionV1::Weekly) {
        work_report::aggregate_days(&current, "week", control)?
    } else {
        Vec::new()
    };
    let monthly = if selected(ReportSectionV1::Monthly) {
        work_report::aggregate_days(&current, "month", control)?
    } else {
        Vec::new()
    };
    let comparison = if selected(ReportSectionV1::Comparison) {
        work_report::compare_periods(&current, &previous, control)?
    } else {
        None
    };
    let mut field_summaries = if [
        ReportSectionV1::ProjectSummary,
        ReportSectionV1::AppSummary,
        ReportSectionV1::DomainSummary,
        ReportSectionV1::ActiveAway,
    ]
    .iter()
    .any(|section| selected(*section))
    {
        work_report::summarize_fields(&current, control)?
    } else {
        record::<ReportFieldSummaryV1>(control, 6)?;
        ReportFieldSummaryV1 {
            method_id: text("work-time-field-summary", control)?,
            method_version: 1,
            project: Vec::new(),
            app: Vec::new(),
            domain: Vec::new(),
            active_away: None,
        }
    };
    if !selected(ReportSectionV1::ProjectSummary) {
        field_summaries.project.clear();
    }
    if !selected(ReportSectionV1::AppSummary) {
        field_summaries.app.clear();
    }
    if !selected(ReportSectionV1::DomainSummary) {
        field_summaries.domain.clear();
    }
    if !selected(ReportSectionV1::ActiveAway) {
        field_summaries.active_away = None;
    }
    record::<ReportMetricsV1>(control, 3)?;
    let metrics = ReportMetricsV1 {
        focus_blocks: if selected(ReportSectionV1::FocusBlocks) {
            Some(work_report::focus_blocks(&current, control)?)
        } else {
            None
        },
        context_switches: if selected(ReportSectionV1::ContextSwitches) {
            Some(work_report::context_switches(&current, control)?)
        } else {
            None
        },
        meeting_load: if selected(ReportSectionV1::MeetingLoad) {
            Some(work_report::meeting_load(
                &current,
                &parameters.category_paths,
                control,
            )?)
        } else {
            None
        },
    };
    let category_summary = if selected(ReportSectionV1::CategorySummary) {
        Some(category_summary(&current, control)?)
    } else {
        None
    };
    let mut total = 0.0;
    let mut sessions = 0u64;
    for day in &current {
        control.charge_fuel(1)?;
        total = finite(total + day.row.duration)?;
        sessions = sessions
            .checked_add(day.row.sessions)
            .ok_or(Error::DataIntegrity)?;
    }
    record::<ReportSummaryV1>(control, 3)?;
    let summary = ReportSummaryV1 {
        total_duration: total,
        total_sessions: sessions,
        avg_session_length: if sessions > 0 {
            total / sessions as f64
        } else {
            0.0
        },
    };
    let source_coverage = coverage(snapshot, control)?;
    let mut source_rows = Vec::new();
    let mut raw_periods = Vec::new();
    for period in &snapshot.input_periods {
        control.charge_fuel(1)?;
        let mut buckets = Vec::new();
        for bucket in &period.buckets {
            record::<ReportSourceRowsV1>(control, 3)?;
            source_rows.push(ReportSourceRowsV1 {
                interval: text(&period.period.interval, control)?,
                bucket_id: text(&bucket.bucket_id, control)?,
                rows: bucket.rows,
            });
            let mut events = Vec::new();
            for event in &bucket.events {
                control.charge_fuel(1)?;
                control.charge_event_copy(event)?;
                record::<ReportRawEventV1>(control, 4)?;
                control.charge_bytes(128)?;
                events.push(ReportRawEventV1::from_event(event)?);
            }
            record::<RawReportBucketV1>(control, 2)?;
            buckets.push(RawReportBucketV1 {
                bucket_id: text(&bucket.bucket_id, control)?,
                events,
            });
        }
        record::<RawReportPeriodV1>(control, 2)?;
        raw_periods.push(RawReportPeriodV1 {
            interval: text(&period.period.interval, control)?,
            buckets,
        });
    }
    record::<ReportAdvancedManifestV1>(control, 12)?;
    // Serialized content and native slots are separate cumulative copy admissions.
    record::<AdvancedReportRunRequestV1>(control, 10)?;
    record::<ReportTemplateV1>(control, 10)?;
    if let Some(pack) = &snapshot.rule_pack {
        record::<ReportRulePackV1>(control, 4)?;
        control.charge_bytes(
            (pack.category_sets.len() * std::mem::size_of::<ReportCategorySetRefV1>()) as u64,
        )?;
    }
    control.charge_bytes(
        (snapshot.effective_rules.len() * std::mem::size_of::<ReportEffectiveRuleV1>()
            + snapshot.sources.len() * std::mem::size_of::<ReportSourceV1>()) as u64,
    )?;
    for path in snapshot
        .template
        .category_paths
        .iter()
        .chain(snapshot.effective_rules.iter().map(|r| &r.category_path))
    {
        control.charge_fuel(1)?;
        control.charge_bytes(
            (std::mem::size_of::<Vec<String>>() + path.len() * std::mem::size_of::<String>())
                as u64,
        )?;
    }
    charge_serialized(&snapshot.request, control)?;
    charge_serialized(&snapshot.template, control)?;
    charge_serialized(&snapshot.rule_pack, control)?;
    charge_serialized(&snapshot.effective_rules, control)?;
    charge_serialized(&snapshot.sources, control)?;
    let advanced_report_manifest = ReportAdvancedManifestV1 {
        schema_version: 1,
        library_revision: snapshot.library_revision,
        resolved_request: snapshot.request.clone(),
        template: snapshot.template.clone(),
        rule_pack: snapshot.rule_pack.clone(),
        effective_rules: snapshot.effective_rules.clone(),
        sources: snapshot.sources.clone(),
        source_rows,
        snapshot_time: text(&snapshot.captured_at.to_rfc3339(), control)?,
        overlap_precedence: text("ordered-host-first-source-v1", control)?,
        label_tie_break: text("utf16-code-unit-v1", control)?,
        limits: ReportLimitsV1::from(QueryLimits::MANAGED),
    };
    let mut daily = Vec::new();
    for day in current {
        record::<ReportDailyV1>(control, 4)?;
        daily.push(day.row);
    }
    record::<ReportCompletedV1>(control, 12)?;
    let completed = ReportCompletedV1 {
        parameters,
        calculation_manifest,
        source_coverage,
        comparison,
        weekly,
        monthly,
        field_summaries,
        metrics,
        summary,
        daily,
        advanced_report_manifest,
        category_summary,
        raw_events: None,
    };
    completed.validate()?;
    control.checkpoint()?;
    Ok(ReportCalculatedV1 {
        completed,
        raw_periods,
    })
}
