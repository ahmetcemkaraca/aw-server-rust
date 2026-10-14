use aw_models::{
    QueryControl, QueryLimits, ReportExecutionErrorV1 as Error, ReportInputSnapshotV1,
    ReportRuleTypeV1, ResolvedPeriodV1,
};
use std::io::Write;
pub struct ReportPlanV1 {
    pub code: String,
    pub periods: Vec<ResolvedPeriodV1>,
}
struct Builder<'a> {
    bytes: Vec<u8>,
    control: &'a QueryControl,
    error: Option<Error>,
}
impl Write for Builder<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let result = (|| {
            if self
                .bytes
                .len()
                .checked_add(bytes.len())
                .is_none_or(|len| len > QueryLimits::MANAGED.max_query_bytes)
            {
                return Err(Error::ByteLimit);
            }
            self.control.charge_fuel(1)?;
            self.control.charge_bytes(bytes.len() as u64)?;
            Ok(())
        })();
        if let Err(error) = result {
            self.error.get_or_insert(error);
            return Err(std::io::Error::other("report plan limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl Builder<'_> {
    fn add(&mut self, text: &str) -> Result<(), Error> {
        self.write_all(text.as_bytes())
            .map_err(|_| self.error.unwrap_or(Error::InternalError))
    }
    fn json(&mut self, value: &impl serde::Serialize) -> Result<(), Error> {
        serde_json::to_writer(&mut *self, value)
            .map_err(|_| self.error.unwrap_or(Error::InternalError))
    }
}
pub fn compile_report_plan(
    snapshot: &ReportInputSnapshotV1,
    control: &QueryControl,
) -> Result<ReportPlanV1, Error> {
    control.checkpoint()?;
    snapshot.request.validate()?;
    if snapshot.sources.len() != snapshot.request.ordered_host_ids.len()
        || snapshot.sources.is_empty()
    {
        return Err(Error::SourceUnavailable);
    }
    snapshot.template.validate(snapshot.rule_pack.as_ref())?;
    if snapshot.library_revision != snapshot.request.expected_library_revision
        || snapshot.template.id != snapshot.request.template_id
    {
        return Err(Error::StaleConfiguration);
    }
    let expected = snapshot
        .request
        .current_periods
        .iter()
        .chain(snapshot.request.previous_periods.iter().flatten());
    let count = snapshot.request.current_periods.len()
        + snapshot
            .request
            .previous_periods
            .as_ref()
            .map_or(0, Vec::len);
    if snapshot.input_periods.len() != count {
        return Err(Error::DataIntegrity);
    }
    let mut raw_count = 0u64;
    for (period, expected) in snapshot.input_periods.iter().zip(expected) {
        control.charge_fuel(1)?;
        if &period.period != expected || period.buckets.len() != snapshot.sources.len() * 2 {
            return Err(Error::DataIntegrity);
        }
        for (index, source) in snapshot.sources.iter().enumerate() {
            for (offset, id) in [(0, &source.window_bucket_id), (1, &source.afk_bucket_id)] {
                control.charge_fuel(1)?;
                let bucket = &period.buckets[index * 2 + offset];
                if bucket.bucket_id != *id
                    || bucket.rows != bucket.events.len() as u64
                    || bucket.rows > 2000
                {
                    return Err(Error::DataIntegrity);
                }
                raw_count = raw_count.checked_add(bucket.rows).ok_or(Error::RowLimit)?;
                if raw_count > 250000 {
                    return Err(Error::RowLimit);
                }
            }
        }
    }
    let mut b = Builder {
        bytes: Vec::new(),
        control,
        error: None,
    };
    for (index, source) in snapshot.sources.iter().enumerate() {
        if source.host_id != snapshot.request.ordered_host_ids[index] {
            return Err(Error::SourceUnavailable);
        }
        control.charge_bytes((64 + source.host_id.len() * 2) as u64)?;
        if source.window_bucket_id != format!("aw-watcher-window_{}", source.host_id)
            || source.afk_bucket_id != format!("aw-watcher-afk_{}", source.host_id)
        {
            return Err(Error::SourceUnavailable);
        }
        control.charge_bytes(64)?;
        b.add(&format!("window_{index}=flood(query_bucket("))?;
        b.json(&source.window_bucket_id)?;
        b.add("));")?;
        control.charge_bytes(96)?;
        b.add(&format!(
            "active_{index}=filter_keyvals(flood(query_bucket("
        ))?;
        b.json(&source.afk_bucket_id)?;
        b.add(")),\"status\",[\"not-afk\"]);")?;
        control.charge_bytes(112)?;
        b.add(&format!(
            "events_{index}=filter_period_intersect(window_{index},active_{index});"
        ))?;
    }
    b.add("events=[];")?;
    for index in 0..snapshot.sources.len() {
        control.charge_fuel(1)?;
        control.charge_bytes(64)?;
        b.add(&format!("events=union_no_overlap(events,events_{index});"))?;
    }
    b.add("events=categorize(sort_by_timestamp(events),[")?;
    for (index, rule) in snapshot.effective_rules.iter().enumerate() {
        control.charge_fuel(1)?;
        if index > 0 {
            b.add(",")?;
        }
        b.add("[")?;
        b.json(&rule.category_path)?;
        b.add(",{")?;
        if rule.rule.kind == Some(ReportRuleTypeV1::Regex) {
            b.add("\"type\":\"regex\",\"regex\":")?;
            b.json(rule.rule.regex.as_ref().ok_or(Error::StaleConfiguration)?)?;
            b.add(",\"ignore_case\":")?;
            b.json(&rule.rule.ignore_case.unwrap_or(false))?;
        } else {
            b.add("\"type\":\"none\"")?;
        }
        b.add("}]")?;
    }
    b.add("]);")?;
    if !snapshot.template.category_paths.is_empty() {
        b.add("events=filter_keyvals(events,\"$category\",[")?;
        let mut first = true;
        control.charge_bytes((std::mem::size_of::<String>() + 13) as u64)?;
        let uncategorized = ["Uncategorized".to_owned()];
        for path in snapshot
            .effective_rules
            .iter()
            .map(|rule| rule.category_path.as_slice())
            .chain(std::iter::once(uncategorized.as_slice()))
        {
            control.charge_fuel(1)?;
            if snapshot
                .template
                .category_paths
                .iter()
                .any(|selected| path.starts_with(selected))
            {
                if !first {
                    b.add(",")?;
                }
                first = false;
                b.json(&path)?;
            }
        }
        b.add("]);")?;
    }
    b.add("return events;")?;
    let mut periods = Vec::new();
    for period in snapshot
        .request
        .current_periods
        .iter()
        .chain(snapshot.request.previous_periods.iter().flatten())
    {
        control.charge_values(1)?;
        control.charge_bytes(
            (std::mem::size_of::<ResolvedPeriodV1>()
                + period.local_date.len()
                + period.interval.len()) as u64,
        )?;
        periods.push(period.clone());
    }
    let code = String::from_utf8(b.bytes).map_err(|_| Error::InternalError)?;
    Ok(ReportPlanV1 { code, periods })
}
