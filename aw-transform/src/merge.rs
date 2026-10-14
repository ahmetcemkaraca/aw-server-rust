use std::collections::HashMap;

use aw_models::Event;

/// Merge events with the same values at the specified keys
///
/// Doesn't care about if events are neighbouring or not, this transform merges
/// all events with the same key.
/// The timestamp will be the timestamp of the first event with a specific key value
///
/// # Example 1
/// A simple example only using one key
///
/// ```ignore
/// keys: ["a"]
/// input:
///   { duration: 1.0, data: { "a": 1 } }
///   { duration: 1.0, data: { "a": 1 } }
///   { duration: 1.0, data: { "a": 2 } }
///   { duration: 1.0, data: { "b": 1 } }
///   { duration: 1.0, data: { "a": 1 } }
/// output:
///   { duration: 3.0, data: { "a": 1 } }
///   { duration: 1.0, data: { "a": 2 } }
///   { duration: 1.0, data: { "b": 1 } }
/// ```
///
/// # Example 2
/// A more complex example only using two keys
/// ```ignore
/// keys: ["a", "b"]
/// input:
///   { duration: 1.0, data: { "a": 1, "b": 1 } }
///   { duration: 1.0, data: { "a": 2, "b": 2 } }
///   { duration: 1.0, data: { "a": 1, "b": 1 } }
///   { duration: 1.0, data: { "a": 1, "b": 2 } }
/// output:
///   { duration: 2.0, data: { "a": 1, "b": 1 } }
///   { duration: 1.0, data: { "a": 2, "b": 2 } }
///   { duration: 1.0, data: { "a": 1, "b": 2 } }
/// ```
#[allow(clippy::map_entry)]
pub fn merge_events_by_keys(events: Vec<Event>, keys: Vec<String>) -> Vec<Event> {
    merge_events_by_keys_controlled(events, keys, &aw_models::QueryControl::unlimited())
        .expect("unlimited grouping")
}
pub fn merge_events_by_keys_controlled(
    events: Vec<Event>,
    keys: Vec<String>,
    control: &aw_models::QueryControl,
) -> Result<Vec<Event>, aw_models::ReportExecutionErrorV1> {
    control.checkpoint()?;
    if keys.is_empty() {
        return Ok(Vec::new());
    }
    let mut grouped: HashMap<String, Event> = HashMap::new();
    'events: for mut event in events {
        control.charge_fuel(1)?;
        let mut values = Vec::new();
        for key in &keys {
            control.charge_fuel(1)?;
            let Some(value) = event.data.get(key) else {
                continue 'events;
            };
            control.charge_json_copy(value)?;
            // Admit encoded grouping keys before allocating their strings.
            struct Count(usize);
            impl std::io::Write for Count {
                fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                    self.0 = self
                        .0
                        .checked_add(b.len())
                        .ok_or_else(|| std::io::Error::other("report limit"))?;
                    Ok(b.len())
                }
                fn flush(&mut self) -> std::io::Result<()> {
                    Ok(())
                }
            }
            let mut count = Count(0);
            serde_json::to_writer(&mut count, value)
                .map_err(|_| aw_models::ReportExecutionErrorV1::DataIntegrity)?;
            control.charge_values(1)?;
            control.charge_bytes((count.0 + std::mem::size_of::<String>()) as u64)?;
            values.push(
                serde_json::to_string(value)
                    .map_err(|_| aw_models::ReportExecutionErrorV1::DataIntegrity)?,
            );
        }
        let size = values
            .iter()
            .try_fold(values.len().saturating_sub(1), |total, value| {
                total.checked_add(value.len())
            })
            .ok_or(aw_models::ReportExecutionErrorV1::ByteLimit)?;
        control.charge_bytes(size as u64)?;
        let key = values.join(".");
        if let Some(previous) = grouped.get_mut(&key) {
            previous.duration = previous
                .duration
                .checked_add(&event.duration)
                .ok_or(aw_models::ReportExecutionErrorV1::DataIntegrity)?;
        } else {
            crate::report_merged_slot(grouped.len(), control)?;
            control.charge_bytes(std::mem::size_of::<String>() as u64)?;
            event.id = None;
            grouped.insert(key, event);
        }
    }
    let mut output = Vec::new();
    for (_, event) in grouped {
        control.charge_fuel(1)?;
        crate::report_event_slot(control)?;
        output.push(event);
    }
    control.checkpoint()?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use chrono::DateTime;
    use chrono::Duration;
    use serde_json::json;

    use aw_models::Event;

    use crate::sort_by_timestamp;

    use super::merge_events_by_keys;

    #[test]
    fn test_merge_events_by_key() {
        let e1 = Event {
            id: None,
            timestamp: DateTime::from_str("2000-01-01T00:00:00Z").unwrap(),
            duration: Duration::seconds(1),
            data: json_map! {"test": json!(1)},
        };
        let e2 = Event {
            id: None,
            timestamp: DateTime::from_str("2000-01-01T00:00:01Z").unwrap(),
            duration: Duration::seconds(3),
            data: json_map! {"test2": json!(3)},
        };
        let e3 = Event {
            id: None,
            timestamp: DateTime::from_str("2000-01-01T00:00:02Z").unwrap(),
            duration: Duration::seconds(7),
            data: json_map! {"test": json!(6)},
        };
        let e4 = Event {
            id: None,
            timestamp: DateTime::from_str("2000-01-01T00:00:03Z").unwrap(),
            duration: Duration::seconds(9),
            data: json_map! {"test": json!(1)},
        };
        let in_events = vec![e1, e2, e3, e4];
        let res1 = merge_events_by_keys(in_events, vec!["test".to_string()]);
        // Needed, otherwise the order is undeterministic
        let res2 = sort_by_timestamp(res1);
        let expected = vec![
            Event {
                id: None,
                timestamp: DateTime::from_str("2000-01-01T00:00:00Z").unwrap(),
                duration: Duration::seconds(10),
                data: json_map! {"test": json!(1)},
            },
            Event {
                id: None,
                timestamp: DateTime::from_str("2000-01-01T00:00:02Z").unwrap(),
                duration: Duration::seconds(7),
                data: json_map! {"test": json!(6)},
            },
        ];
        assert_eq!(&res2, &expected);
    }
}
