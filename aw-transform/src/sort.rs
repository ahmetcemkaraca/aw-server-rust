use aw_models::Event;

/// Sort a list of events by timestamp
pub fn sort_by_timestamp(events: Vec<Event>) -> Vec<Event> {
    sort_by_timestamp_controlled(events, &aw_models::QueryControl::unlimited())
        .expect("unlimited timestamp sort")
}
pub fn sort_by_duration(events: Vec<Event>) -> Vec<Event> {
    sort_by_duration_controlled(events, &aw_models::QueryControl::unlimited())
        .expect("unlimited duration sort")
}
fn sort_admission(
    length: usize,
    control: &aw_models::QueryControl,
) -> Result<(), aw_models::ReportExecutionErrorV1> {
    control.charge_bytes((length * std::mem::size_of::<Event>()) as u64)?;
    let levels = if length < 2 {
        0
    } else {
        usize::BITS - (length - 1).leading_zeros()
    };
    control.charge_fuel((length as u64) * (levels as u64 + 1))
}
pub fn sort_by_timestamp_controlled(
    mut events: Vec<Event>,
    control: &aw_models::QueryControl,
) -> Result<Vec<Event>, aw_models::ReportExecutionErrorV1> {
    sort_admission(events.len(), control)?;
    events.sort_by_key(|e| e.timestamp);
    control.checkpoint()?;
    Ok(events)
}
pub fn sort_by_duration_controlled(
    mut events: Vec<Event>,
    control: &aw_models::QueryControl,
) -> Result<Vec<Event>, aw_models::ReportExecutionErrorV1> {
    sort_admission(events.len(), control)?;
    events.sort_by(|a, b| b.duration.cmp(&a.duration));
    control.checkpoint()?;
    Ok(events)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use chrono::DateTime;
    use chrono::Duration;
    use serde_json::json;

    use aw_models::Event;

    use super::{sort_by_duration, sort_by_timestamp};

    #[test]
    fn test_sort_by_timestamp() {
        let e1 = Event {
            id: None,
            timestamp: DateTime::from_str("2000-01-01T00:00:00Z").unwrap(),
            duration: Duration::seconds(1),
            data: json_map! {"test": json!(1)},
        };
        let e2 = Event {
            id: None,
            timestamp: DateTime::from_str("2000-01-01T00:00:03Z").unwrap(),
            duration: Duration::seconds(1),
            data: json_map! {"test": json!(1)},
        };
        let res = sort_by_timestamp(vec![e2.clone(), e1.clone()]);
        assert_eq!(res, vec![e1, e2]);
    }

    #[test]
    fn test_sort_by_duration() {
        let e1 = Event {
            id: None,
            timestamp: DateTime::from_str("2000-01-01T00:00:00Z").unwrap(),
            duration: Duration::seconds(2),
            data: json_map! {"test": json!(1)},
        };
        let e2 = Event {
            id: None,
            timestamp: DateTime::from_str("2000-01-01T00:00:03Z").unwrap(),
            duration: Duration::seconds(1),
            data: json_map! {"test": json!(1)},
        };
        let res = sort_by_duration(vec![e2.clone(), e1.clone()]);
        assert_eq!(res, vec![e1, e2]);
    }
}
