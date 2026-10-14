use aw_models::{
    Event, QueryControl, ReportExecutionErrorV1 as Error, ReportInputSnapshotV1, TimeInterval,
};
pub struct FrozenQuerySource<'a> {
    pub(crate) regex_cache: std::cell::RefCell<aw_transform::classify::ControlledRegexCacheV1>,
    pub(crate) snapshot: &'a ReportInputSnapshotV1,
}
impl<'a> FrozenQuerySource<'a> {
    pub fn new(snapshot: &'a ReportInputSnapshotV1) -> Self {
        Self {
            snapshot,
            regex_cache: std::cell::RefCell::new(Default::default()),
        }
    }
    pub(crate) fn events(
        &self,
        id: &str,
        interval: &TimeInterval,
        limit: Option<usize>,
        control: &QueryControl,
    ) -> Result<Vec<Event>, Error> {
        let period = self
            .snapshot
            .input_periods
            .iter()
            .find(|p| {
                p.period
                    .bounds()
                    .is_ok_and(|(a, b)| a == *interval.start() && b == *interval.end())
            })
            .ok_or(Error::SourceUnavailable)?;
        let bucket = period
            .buckets
            .iter()
            .find(|b| b.bucket_id == id)
            .ok_or(Error::SourceUnavailable)?;
        let mut events = Vec::new();
        for event in bucket.events.iter().take(limit.unwrap_or(usize::MAX)) {
            control.charge_fuel(1)?;
            let duration = event
                .duration
                .num_nanoseconds()
                .filter(|n| *n >= 0)
                .ok_or(Error::DataIntegrity)?;
            let end = event
                .timestamp
                .checked_add_signed(chrono::Duration::nanoseconds(duration))
                .ok_or(Error::DataIntegrity)?;
            if end < *interval.start() || event.timestamp > *interval.end() {
                continue;
            }
            control.charge_event_copy(event)?;
            let mut clipped = event.clone();
            clipped.timestamp = clipped.timestamp.max(*interval.start());
            clipped.duration = end.min(*interval.end()) - clipped.timestamp;
            events.push(clipped);
        }
        control.checkpoint()?;
        Ok(events)
    }
    pub(crate) fn bucket_names(&self, control: &QueryControl) -> Result<Vec<String>, Error> {
        let mut names = Vec::new();
        for period in &self.snapshot.input_periods {
            for bucket in &period.buckets {
                control.charge_fuel(1)?;
                if names.contains(&bucket.bucket_id) {
                    continue;
                }
                control.charge_values(1)?;
                control.charge_bytes(
                    (bucket.bucket_id.len() + std::mem::size_of::<String>()) as u64,
                )?;
                names.push(bucket.bucket_id.clone());
            }
        }
        Ok(names)
    }
}
