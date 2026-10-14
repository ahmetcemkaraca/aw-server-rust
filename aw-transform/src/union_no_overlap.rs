use aw_models::{Event, TimeInterval};
use chrono::{DateTime, Utc};

/// Merges two eventlists and removes overlap, the first eventlist will have precedence
///
/// aw-core implementation: https://github.com/ActivityWatch/aw-core/blob/master/aw_transform/union_no_overlap.py
///
/// # Example
/// ```ignore
///   events1  | xxx    xx     xxx     |
///   events1  |  ----     ------   -- |
///   result   | xxx--  xx ----xxx  -- |
/// ```
#[allow(clippy::collapsible_else_if)]
pub fn union_no_overlap(events1: Vec<Event>, events2: Vec<Event>) -> Vec<Event> {
    union_no_overlap_controlled(events1, events2, &aw_models::QueryControl::unlimited())
        .expect("unlimited source union")
}
pub fn union_no_overlap_controlled(
    events1: Vec<Event>,
    mut events2: Vec<Event>,
    control: &aw_models::QueryControl,
) -> Result<Vec<Event>, aw_models::ReportExecutionErrorV1> {
    control.checkpoint()?;
    let mut events_union: Vec<Event> = Vec::new();
    let mut e1_i = 0;
    let mut e2_i = 0;
    while e1_i < events1.len() && e2_i < events2.len() {
        control.charge_fuel(1)?;
        let e1 = &events1[e1_i];
        let e2 = &events2[e2_i];
        let e1_p = TimeInterval::new(e1.timestamp, crate::report_event_end(e1, control)?);
        let e2_p = TimeInterval::new(e2.timestamp, crate::report_event_end(e2, control)?);

        if e1_p.intersects(&e2_p) {
            if e1.timestamp <= e2.timestamp {
                crate::report_merged_slot(events_union.len(), control)?;
                control.charge_event_copy(e1)?;
                events_union.push(e1.clone());
                e1_i += 1;

                // If e2 continues after e1, we need to split up the event so we only get the part that comes after
                let (_, e2_next) =
                    split_event_controlled(e2, crate::report_event_end(e1, control)?, control)?;
                if let Some(e2_next) = e2_next {
                    events2[e2_i] = e2_next;
                } else {
                    e2_i += 1;
                }
            } else {
                let (e2_next, e2_next2) = split_event_controlled(e2, e1.timestamp, control)?;
                crate::report_merged_slot(events_union.len(), control)?;
                events_union.push(e2_next);
                e2_i += 1;
                if let Some(e2_next2) = e2_next2 {
                    control.charge_fuel((events2.len() - e2_i) as u64)?;
                    crate::report_event_slot(control)?;
                    events2.insert(e2_i, e2_next2);
                }
            }
        } else {
            if e1.timestamp <= e2.timestamp {
                crate::report_merged_slot(events_union.len(), control)?;
                control.charge_event_copy(e1)?;
                events_union.push(e1.clone());
                e1_i += 1;
            } else {
                crate::report_merged_slot(events_union.len(), control)?;
                control.charge_event_copy(e2)?;
                events_union.push(e2.clone());
                e2_i += 1;
            }
        }
    }

    // Now we just need to add any remaining events
    for event in events1[e1_i..].iter().chain(events2[e2_i..].iter()) {
        control.charge_fuel(1)?;
        crate::report_merged_slot(events_union.len(), control)?;
        control.charge_event_copy(event)?;
        events_union.push(event.clone());
    }
    control.checkpoint()?;
    Ok(events_union)
}

#[cfg(test)]
fn split_event(event: &Event, timestamp: DateTime<Utc>) -> (Event, Option<Event>) {
    split_event_controlled(event, timestamp, &aw_models::QueryControl::unlimited())
        .expect("unlimited split")
}

fn split_event_controlled(
    event: &Event,
    timestamp: DateTime<Utc>,
    control: &aw_models::QueryControl,
) -> Result<(Event, Option<Event>), aw_models::ReportExecutionErrorV1> {
    control.charge_fuel(1)?;
    let end = crate::report_event_end(event, control)?;
    control.charge_event_copy(event)?;
    if event.timestamp < timestamp && timestamp < end {
        control.charge_event_copy(event)?;
        Ok((
            Event::new(
                event.timestamp,
                timestamp - event.timestamp,
                event.data.clone(),
            ),
            Some(Event::new(timestamp, end - timestamp, event.data.clone())),
        ))
    } else {
        Ok((event.clone(), None))
    }
}

// Some tests
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_split_event() {
        let now = Utc::now();
        let td1h = Duration::hours(1);
        let e = Event {
            id: None,
            timestamp: now,
            duration: Duration::hours(2),
            data: serde_json::Map::new(),
        };
        let (e1, e2_opt) = split_event(&e, now + td1h);
        assert_eq!(e1.timestamp, now);
        assert_eq!(e1.duration, td1h);

        let e2 = e2_opt.unwrap();
        assert_eq!(e2.timestamp, now + td1h);
        assert_eq!(e2.duration, td1h);

        // Now a test which does not lead to a split
        let (e1, e2_opt) = split_event(&e, now);
        assert_eq!(e1.timestamp, now);
        assert_eq!(e1.duration, Duration::hours(2));
        assert!(e2_opt.is_none());
    }

    #[test]
    fn test_union_no_overlap() {
        // A test without any actual overlap
        let now = Utc::now();
        let td1h = Duration::hours(1);
        let e1 = Event::new(now, td1h, serde_json::Map::new());
        let e2 = Event::new(now + td1h, td1h, serde_json::Map::new());
        let events1 = vec![e1.clone()];
        let events2 = vec![e2.clone()];
        let events_union = union_no_overlap(events1, events2);

        assert_eq!(events_union.len(), 2);
        assert_eq!(events_union[0].timestamp, now);
        assert_eq!(events_union[0].duration, td1h);
        assert_eq!(events_union[1].timestamp, now + td1h);
        assert_eq!(events_union[1].duration, td1h);

        // Now do in reverse order
        let events1 = vec![e2];
        let events2 = vec![e1];
        let events_union = union_no_overlap(events1, events2);

        // Resulting order should be the same, since there is no overlap.
        assert_eq!(events_union.len(), 2);
        assert_eq!(events_union[0].timestamp, now);
        assert_eq!(events_union[0].duration, td1h);
        assert_eq!(events_union[1].timestamp, now + td1h);
        assert_eq!(events_union[1].duration, td1h);
    }

    #[test]
    fn test_union_no_overlap_with_overlap() {
        // A test where the events overlap
        let now = Utc::now();
        let td1h = Duration::hours(1);
        let e1 = Event::new(now, td1h, serde_json::Map::new());
        let e2 = Event::new(now, Duration::hours(2), serde_json::Map::new());
        let events1 = vec![e1];
        let events2 = vec![e2];
        let events_union = union_no_overlap(events1, events2);

        assert_eq!(events_union.len(), 2);
        assert_eq!(events_union[0].timestamp, now);
        assert_eq!(events_union[0].duration, td1h);
        assert_eq!(events_union[1].timestamp, now + td1h);
        assert_eq!(events_union[1].duration, td1h);

        // Now test the case where e2 starts before e1
        let e1 = Event::new(now + td1h, td1h, serde_json::Map::new());
        let e2 = Event::new(now, Duration::hours(2), serde_json::Map::new());
        let events1 = vec![e1];
        let events2 = vec![e2];
        let events_union = union_no_overlap(events1, events2);

        assert_eq!(events_union.len(), 2);
        assert_eq!(events_union[0].timestamp, now);
        assert_eq!(events_union[0].duration, td1h);
        assert_eq!(events_union[1].timestamp, now + td1h);
        assert_eq!(events_union[1].duration, td1h);
    }
}
