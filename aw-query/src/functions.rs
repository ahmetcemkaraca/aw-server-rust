use crate::DataType;
use crate::QueryError;
use crate::VarEnv;
use aw_datastore::Datastore;

pub type QueryFn =
    fn(args: Vec<DataType>, env: &VarEnv, ds: &Datastore) -> Result<DataType, QueryError>;

pub fn fill_env(env: &mut VarEnv) {
    env.insert(
        "print".to_string(),
        DataType::Function("print".to_string(), qfunctions::print),
    );
    env.insert(
        "query_bucket".to_string(),
        DataType::Function("query_bucket".to_string(), qfunctions::query_bucket),
    );
    env.insert(
        "query_bucket_names".to_string(),
        DataType::Function(
            "query_bucket_names".to_string(),
            qfunctions::query_bucket_names,
        ),
    );
    env.insert(
        "sort_by_duration".to_string(),
        DataType::Function("sort_by_duration".to_string(), qfunctions::sort_by_duration),
    );
    env.insert(
        "sort_by_timestamp".to_string(),
        DataType::Function(
            "sort_by_timestamp".to_string(),
            qfunctions::sort_by_timestamp,
        ),
    );
    env.insert(
        "sum_durations".to_string(),
        DataType::Function("sum_durations".to_string(), qfunctions::sum_durations),
    );
    env.insert(
        "limit_events".to_string(),
        DataType::Function("limit_events".to_string(), qfunctions::limit_events),
    );
    env.insert(
        "event_count".to_string(),
        DataType::Function("event_count".to_string(), qfunctions::event_count),
    );
    env.insert(
        "contains".to_string(),
        DataType::Function("contains".to_string(), qfunctions::contains),
    );
    env.insert(
        "flood".to_string(),
        DataType::Function("flood".to_string(), qfunctions::flood),
    );
    env.insert(
        "find_bucket".to_string(),
        DataType::Function("find_bucket".to_string(), qfunctions::find_bucket),
    );
    env.insert(
        "merge_events_by_keys".to_string(),
        DataType::Function(
            "merge_events_by_keys".to_string(),
            qfunctions::merge_events_by_keys,
        ),
    );
    env.insert(
        "chunk_events_by_key".to_string(),
        DataType::Function(
            "chunk_events_by_key".to_string(),
            qfunctions::chunk_events_by_key,
        ),
    );
    env.insert(
        "exclude_keyvals".to_string(),
        DataType::Function("exclude_keyvals".to_string(), qfunctions::exclude_keyvals),
    );
    env.insert(
        "filter_keyvals".to_string(),
        DataType::Function("filter_keyvals".to_string(), qfunctions::filter_keyvals),
    );
    env.insert(
        "filter_keyvals_regex".to_string(),
        DataType::Function(
            "filter_keyvals_regex".to_string(),
            qfunctions::filter_keyvals_regex,
        ),
    );
    env.insert(
        "filter_period_intersect".to_string(),
        DataType::Function(
            "filter_period_intersect".to_string(),
            qfunctions::filter_period_intersect,
        ),
    );
    env.insert(
        "split_url_events".to_string(),
        DataType::Function("split_url_events".to_string(), qfunctions::split_url_events),
    );
    env.insert(
        "concat".to_string(),
        DataType::Function("concat".to_string(), qfunctions::concat),
    );
    env.insert(
        "categorize".to_string(),
        DataType::Function("categorize".into(), qfunctions::categorize),
    );
    env.insert(
        "categorize_explained".to_string(),
        DataType::Function(
            "categorize_explained".into(),
            qfunctions::categorize_explained,
        ),
    );
    env.insert(
        "tag".to_string(),
        DataType::Function("tag".into(), qfunctions::tag),
    );
    env.insert(
        "period_union".to_string(),
        DataType::Function("period_union".into(), qfunctions::period_union),
    );
    env.insert(
        "union_no_overlap".to_string(),
        DataType::Function("union_no_overlap".into(), qfunctions::union_no_overlap),
    );
}

mod qfunctions {
    use aw_datastore::Datastore;
    use aw_models::Event;
    use aw_transform::classify::Rule;

    use super::validate;
    use crate::DataType;
    use crate::QueryError;
    use crate::VarEnv;

    pub fn print(
        args: Vec<DataType>,
        _env: &VarEnv,
        _ds: &Datastore,
    ) -> Result<DataType, QueryError> {
        for arg in args {
            info!("{:?}", arg);
        }
        Ok(DataType::None())
    }

    pub fn query_bucket(
        args: Vec<DataType>,
        env: &VarEnv,
        ds: &Datastore,
    ) -> Result<DataType, QueryError> {
        // Typecheck
        validate::args_length(&args, 1).or_else(|_| validate::args_length(&args, 2))?;
        let mut args = args.into_iter();
        let bucket_id: String = args.next().unwrap().try_into()?;
        let limit: Option<usize> = args.next().map(TryInto::try_into).transpose()?;
        let limit = limit
            .map(|value| {
                u64::try_from(value).map_err(|_| {
                    QueryError::InvalidFunctionParameters("query_bucket limit is too large".into())
                })
            })
            .transpose()?;
        let interval = validate::get_timeinterval(env)?;

        let events = match ds.get_events(
            bucket_id.as_str(),
            Some(*interval.start()),
            Some(*interval.end()),
            limit,
        ) {
            Ok(events) => events,
            Err(e) => {
                return Err(QueryError::BucketQueryError(format!(
                    "Failed to query bucket: {e:?}"
                )))
            }
        };
        let mut ret = Vec::new();
        for event in events {
            ret.push(DataType::Event(event));
        }
        Ok(DataType::List(ret))
    }

    pub fn query_bucket_names(
        args: Vec<DataType>,
        _env: &VarEnv,
        ds: &Datastore,
    ) -> Result<DataType, QueryError> {
        validate::args_length(&args, 0)?;
        let mut bucketnames: Vec<DataType> = Vec::new();
        let buckets = match ds.get_buckets() {
            Ok(buckets) => buckets,
            Err(e) => {
                return Err(QueryError::BucketQueryError(format!(
                    "Failed to query bucket names: {e:?}"
                )))
            }
        };
        for bucketname in buckets.keys() {
            bucketnames.push(DataType::String(bucketname.to_string()));
        }
        Ok(DataType::List(bucketnames))
    }

    pub fn find_bucket(
        args: Vec<DataType>,
        _env: &VarEnv,
        ds: &Datastore,
    ) -> Result<DataType, QueryError> {
        validate::args_length(&args, 1).or_else(|_| validate::args_length(&args, 2))?;

        let mut args = args.into_iter();
        let bucket_filter: String = args.next().unwrap().try_into()?;
        let hostname_filter: Option<String> = match args.next() {
            Some(arg) => Some(arg.try_into()?),
            None => None,
        };

        let buckets = match ds.get_buckets() {
            Ok(buckets) => buckets,
            Err(e) => {
                return Err(QueryError::BucketQueryError(format!(
                    "Failed to query bucket names: {e:?}"
                )))
            }
        };
        let bucketname = match aw_transform::find_bucket(
            &bucket_filter,
            &hostname_filter,
            buckets.values(),
        ) {
            Some(bucketname) => bucketname,
            None => {
                return Err(QueryError::BucketQueryError(match hostname_filter {
                        None => {
                            format!("Failed to find bucket matching filter '{bucket_filter}'")
                        }
                        Some(hostname_filter) => format!(
                            "Failed to find bucket matching filter '{bucket_filter}' and hostname '{hostname_filter}'"
                        ),
                    }));
            }
        };
        Ok(DataType::String(bucketname))
    }

    pub fn contains(
        args: Vec<DataType>,
        _env: &VarEnv,
        _ds: &Datastore,
    ) -> Result<DataType, QueryError> {
        // typecheck
        validate::args_length(&args, 2)?;
        match args.first().unwrap() {
            DataType::List(ref list) => Ok(DataType::Bool(list.contains(&args[1]))),
            DataType::Dict(ref dict) => {
                let s = match &args[1] {
                    DataType::String(s) => s.to_string(),
                    _ => {
                        return Err(QueryError::InvalidFunctionParameters(format!(
                            "function contains got second argument {:?}, expected type String",
                            args[0]
                        )))
                    }
                };
                Ok(DataType::Bool(dict.contains_key(&s)))
            }
            _ => Err(QueryError::InvalidFunctionParameters(format!(
                "function contains got first argument {:?}, expected type List or Dict",
                args[0]
            ))),
        }
    }

    pub fn flood(
        args: Vec<DataType>,
        _env: &VarEnv,
        _ds: &Datastore,
    ) -> Result<DataType, QueryError> {
        // typecheck
        validate::args_length(&args, 1)?;
        let events: Vec<Event> = args.into_iter().next().unwrap().try_into()?;
        // Run flood
        let mut flooded_events = aw_transform::flood(events, chrono::Duration::seconds(5));
        // Put events back into DataType::Event container
        let mut tagged_flooded_events = Vec::new();
        for event in flooded_events.drain(..) {
            tagged_flooded_events.push(DataType::Event(event));
        }
        Ok(DataType::List(tagged_flooded_events))
    }

    pub fn categorize(
        args: Vec<DataType>,
        _env: &VarEnv,
        _ds: &Datastore,
    ) -> Result<DataType, QueryError> {
        // typecheck
        validate::args_length(&args, 2)?;
        let mut args = args.into_iter();
        let events: Vec<Event> = args.next().unwrap().try_into()?;
        let rules: Vec<(Vec<String>, Rule)> = args.next().unwrap().try_into()?;
        // Run categorize
        let mut flooded_events = aw_transform::classify::categorize(events, &rules);
        // Put events back into DataType::Event container
        let mut tagged_flooded_events = Vec::new();
        for event in flooded_events.drain(..) {
            tagged_flooded_events.push(DataType::Event(event));
        }
        Ok(DataType::List(tagged_flooded_events))
    }

    pub fn categorize_explained(
        args: Vec<DataType>,
        _env: &VarEnv,
        _ds: &Datastore,
    ) -> Result<DataType, QueryError> {
        validate::args_length(&args, 2)?;
        let mut args = args.into_iter();
        let events: Vec<Event> = args.next().unwrap().try_into()?;
        let rules: Vec<(Vec<String>, Rule)> = args.next().unwrap().try_into()?;
        let result = aw_transform::classify::categorize_with_trace(events, &rules)
            .into_iter()
            .map(|(mut event, trace)| {
                event.data.insert(
                    "$category_trace".into(),
                    serde_json::to_value(trace).expect("category trace is serializable"),
                );
                DataType::Event(event)
            })
            .collect();
        Ok(DataType::List(result))
    }

    pub fn tag(
        args: Vec<DataType>,
        _env: &VarEnv,
        _ds: &Datastore,
    ) -> Result<DataType, QueryError> {
        // typecheck
        validate::args_length(&args, 2)?;
        let mut args = args.into_iter();
        let events: Vec<Event> = args.next().unwrap().try_into()?;
        let rules: Vec<(String, Rule)> = args.next().unwrap().try_into()?;
        // Run categorize
        let mut flooded_events = aw_transform::classify::tag(events, &rules);
        // Put events back into DataType::Event container
        let mut tagged_flooded_events = Vec::new();
        for event in flooded_events.drain(..) {
            tagged_flooded_events.push(DataType::Event(event));
        }
        Ok(DataType::List(tagged_flooded_events))
    }

    pub fn sort_by_duration(
        args: Vec<DataType>,
        _env: &VarEnv,
        _ds: &Datastore,
    ) -> Result<DataType, QueryError> {
        // typecheck
        validate::args_length(&args, 1)?;
        let events: Vec<Event> = args.into_iter().next().unwrap().try_into()?;

        // Sort by duration
        let mut sorted_events = aw_transform::sort_by_duration(events);
        // Put events back into DataType::Event container
        let mut tagged_sorted_events = Vec::new();
        for event in sorted_events.drain(..) {
            tagged_sorted_events.push(DataType::Event(event));
        }
        Ok(DataType::List(tagged_sorted_events))
    }

    pub fn limit_events(
        args: Vec<DataType>,
        _env: &VarEnv,
        _ds: &Datastore,
    ) -> Result<DataType, QueryError> {
        // typecheck
        validate::args_length(&args, 2)?;
        let mut args = args.into_iter();
        let mut events: Vec<Event> = args.next().unwrap().try_into()?;
        let mut limit: usize = args.next().unwrap().try_into()?;

        if events.len() < limit {
            limit = events.len()
        }
        let mut limited_tagged_events = Vec::new();
        for event in events.drain(0..limit) {
            limited_tagged_events.push(DataType::Event(event));
        }
        Ok(DataType::List(limited_tagged_events))
    }

    pub fn event_count(
        args: Vec<DataType>,
        _env: &VarEnv,
        _ds: &Datastore,
    ) -> Result<DataType, QueryError> {
        validate::args_length(&args, 1)?;
        let events: Vec<Event> = args.into_iter().next().unwrap().try_into()?;
        Ok(DataType::Number(events.len() as f64))
    }

    pub fn sort_by_timestamp(
        args: Vec<DataType>,
        _env: &VarEnv,
        _ds: &Datastore,
    ) -> Result<DataType, QueryError> {
        // typecheck
        validate::args_length(&args, 1)?;
        let events: Vec<Event> = args.into_iter().next().unwrap().try_into()?;

        // Sort by duration
        let mut sorted_events = aw_transform::sort_by_timestamp(events);
        // Put events back into DataType::Event container
        let mut tagged_sorted_events = Vec::new();
        for event in sorted_events.drain(..) {
            tagged_sorted_events.push(DataType::Event(event));
        }
        Ok(DataType::List(tagged_sorted_events))
    }

    pub fn sum_durations(
        args: Vec<DataType>,
        _env: &VarEnv,
        _ds: &Datastore,
    ) -> Result<DataType, QueryError> {
        // typecheck
        validate::args_length(&args, 1)?;
        let mut events: Vec<Event> = args.into_iter().next().unwrap().try_into()?;

        // Sort by duration
        let mut sum_durations = chrono::Duration::zero();
        for event in events.drain(..) {
            sum_durations += event.duration;
        }
        Ok(DataType::Number(
            (sum_durations.num_milliseconds() as f64) / 1000.0,
        ))
    }

    pub fn merge_events_by_keys(
        args: Vec<DataType>,
        _env: &VarEnv,
        _ds: &Datastore,
    ) -> Result<DataType, QueryError> {
        // typecheck
        validate::args_length(&args, 2)?;
        let mut args = args.into_iter();
        let events: Vec<Event> = args.next().unwrap().try_into()?;
        let keys: Vec<String> = args.next().unwrap().try_into()?;

        let mut merged_events = aw_transform::merge_events_by_keys(events, keys);
        let mut merged_tagged_events = Vec::new();
        for event in merged_events.drain(..) {
            merged_tagged_events.push(DataType::Event(event));
        }
        Ok(DataType::List(merged_tagged_events))
    }

    pub fn chunk_events_by_key(
        args: Vec<DataType>,
        _env: &VarEnv,
        _ds: &Datastore,
    ) -> Result<DataType, QueryError> {
        // typecheck
        validate::args_length(&args, 2)?;
        let mut args = args.into_iter();
        let events: Vec<Event> = args.next().unwrap().try_into()?;
        let key: String = args.next().unwrap().try_into()?;

        let mut merged_events = aw_transform::chunk_events_by_key(events, &key);
        let mut merged_tagged_events = Vec::new();
        for event in merged_events.drain(..) {
            merged_tagged_events.push(DataType::Event(event));
        }
        Ok(DataType::List(merged_tagged_events))
    }

    pub fn filter_keyvals(
        args: Vec<DataType>,
        _env: &VarEnv,
        _ds: &Datastore,
    ) -> Result<DataType, QueryError> {
        // typecheck
        validate::args_length(&args, 3)?;
        let mut args = args.into_iter();
        let events = args.next().unwrap().try_into()?;
        let key: String = args.next().unwrap().try_into()?;
        let vals: Vec<_> = args.next().unwrap().try_into()?;

        let mut filtered_events = aw_transform::filter_keyvals(events, &key, &vals);
        let mut filtered_tagged_events = Vec::new();
        for event in filtered_events.drain(..) {
            filtered_tagged_events.push(DataType::Event(event));
        }
        Ok(DataType::List(filtered_tagged_events))
    }

    use fancy_regex::RegexBuilder;

    pub fn filter_keyvals_regex(
        args: Vec<DataType>,
        _env: &VarEnv,
        _ds: &Datastore,
    ) -> Result<DataType, QueryError> {
        // typecheck
        validate::args_length(&args, 3)?;
        let mut args = args.into_iter();
        let events = args.next().unwrap().try_into()?;
        let key: String = args.next().unwrap().try_into()?;
        let regex_str: String = args.next().unwrap().try_into()?;
        let regex = match RegexBuilder::new(&regex_str).build() {
            Ok(regex) => regex,
            Err(e) => {
                return Err(QueryError::RegexCompileError(format!(
                    "Failed to compile regex string '{regex_str}': {e}"
                )))
            }
        };

        let mut filtered_events = aw_transform::filter_keyvals_regex(events, &key, &regex);
        let mut filtered_tagged_events = Vec::new();
        for event in filtered_events.drain(..) {
            filtered_tagged_events.push(DataType::Event(event));
        }
        Ok(DataType::List(filtered_tagged_events))
    }

    pub fn exclude_keyvals(
        args: Vec<DataType>,
        _env: &VarEnv,
        _ds: &Datastore,
    ) -> Result<DataType, QueryError> {
        // typecheck
        validate::args_length(&args, 3)?;
        let mut args = args.into_iter();
        let events = args.next().unwrap().try_into()?;
        let key: String = args.next().unwrap().try_into()?;
        let vals: Vec<_> = args.next().unwrap().try_into()?;

        let mut filtered_events = aw_transform::exclude_keyvals(events, &key, &vals);
        let mut filtered_tagged_events = Vec::new();
        for event in filtered_events.drain(..) {
            filtered_tagged_events.push(DataType::Event(event));
        }
        Ok(DataType::List(filtered_tagged_events))
    }

    pub fn filter_period_intersect(
        args: Vec<DataType>,
        _env: &VarEnv,
        _ds: &Datastore,
    ) -> Result<DataType, QueryError> {
        // typecheck
        validate::args_length(&args, 2)?;
        let mut args = args.into_iter();
        let events: Vec<Event> = args.next().unwrap().try_into()?;
        let filter_events: Vec<Event> = args.next().unwrap().try_into()?;

        let mut filtered_events = aw_transform::filter_period_intersect(events, filter_events);
        let mut filtered_tagged_events = Vec::new();
        for event in filtered_events.drain(..) {
            filtered_tagged_events.push(DataType::Event(event));
        }
        Ok(DataType::List(filtered_tagged_events))
    }

    pub fn split_url_events(
        args: Vec<DataType>,
        _env: &VarEnv,
        _ds: &Datastore,
    ) -> Result<DataType, QueryError> {
        // typecheck
        validate::args_length(&args, 1)?;
        let mut events: Vec<Event> = args.into_iter().next().unwrap().try_into()?;

        let mut tagged_split_url_events = Vec::new();
        for mut event in events.drain(..) {
            aw_transform::split_url_event(&mut event);
            tagged_split_url_events.push(DataType::Event(event));
        }
        Ok(DataType::List(tagged_split_url_events))
    }

    pub fn concat(
        args: Vec<DataType>,
        _env: &VarEnv,
        _ds: &Datastore,
    ) -> Result<DataType, QueryError> {
        let mut event_list = Vec::new();
        for arg in args {
            let mut events: Vec<Event> = arg.try_into()?;
            for event in events.drain(..) {
                event_list.push(DataType::Event(event));
            }
        }
        Ok(DataType::List(event_list))
    }

    pub fn period_union(
        args: Vec<DataType>,
        _env: &VarEnv,
        _ds: &Datastore,
    ) -> Result<DataType, QueryError> {
        // typecheck
        validate::args_length(&args, 2)?;
        let mut args = args.into_iter();
        let events1: Vec<Event> = args.next().unwrap().try_into()?;
        let events2: Vec<Event> = args.next().unwrap().try_into()?;

        let mut result = aw_transform::period_union(&events1, &events2);
        let mut result_tagged = Vec::new();
        for event in result.drain(..) {
            result_tagged.push(DataType::Event(event));
        }
        Ok(DataType::List(result_tagged))
    }

    pub fn union_no_overlap(
        args: Vec<DataType>,
        _env: &VarEnv,
        _ds: &Datastore,
    ) -> Result<DataType, QueryError> {
        // typecheck
        validate::args_length(&args, 2)?;
        let mut args = args.into_iter();
        let events1: Vec<Event> = args.next().unwrap().try_into()?;
        let events2: Vec<Event> = args.next().unwrap().try_into()?;

        let mut result = aw_transform::union_no_overlap(events1, events2);
        let mut result_tagged = Vec::new();
        for event in result.drain(..) {
            result_tagged.push(DataType::Event(event));
        }
        Ok(DataType::List(result_tagged))
    }
}

mod validate {
    use crate::{DataType, QueryError, VarEnv};
    use aw_models::TimeInterval;

    pub fn args_length(args: &[DataType], len: usize) -> Result<(), QueryError> {
        if args.len() != len {
            return Err(QueryError::InvalidFunctionParameters(format!(
                "Expected {} parameters in function, got {}",
                len,
                args.len()
            )));
        }
        Ok(())
    }

    pub fn get_timeinterval(env: &VarEnv) -> Result<TimeInterval, QueryError> {
        let interval_str = match env.get("TIMEINTERVAL") {
            Some(data_ti) => match data_ti {
                DataType::String(ti_str) => ti_str,
                _ => {
                    return Err(QueryError::TimeIntervalError(
                        "TIMEINTERVAL is not of type string!".to_string(),
                    ))
                }
            },
            None => {
                return Err(QueryError::TimeIntervalError(
                    "TIMEINTERVAL not defined!".to_string(),
                ))
            }
        };
        match TimeInterval::new_from_string(interval_str) {
            Ok(ti) => Ok(ti),
            Err(_e) => Err(QueryError::TimeIntervalError(format!(
                "Failed to parse TIMEINTERVAL: {interval_str}"
            ))),
        }
    }
}

const CONTROLLED_NAMES: &[&str] = &[
    "query_bucket",
    "query_bucket_names",
    "sort_by_timestamp",
    "sort_by_duration",
    "sum_durations",
    "event_count",
    "limit_events",
    "flood",
    "filter_keyvals",
    "exclude_keyvals",
    "filter_period_intersect",
    "union_no_overlap",
    "categorize",
    "categorize_explained",
    "merge_events_by_keys",
    "concat",
    "contains",
];
fn controlled_marker(_: Vec<DataType>, _: &VarEnv, _: &Datastore) -> Result<DataType, QueryError> {
    unreachable!("controlled markers are never called")
}
pub(crate) fn fill_controlled_env(
    env: &mut VarEnv,
    control: &aw_models::QueryControl,
) -> Result<(), aw_models::ReportExecutionErrorV1> {
    for name in CONTROLLED_NAMES {
        control.charge_values(1)?;
        control
            .charge_bytes((2 * name.len() + std::mem::size_of::<(String, DataType)>()) as u64)?;
        env.insert(
            (*name).into(),
            DataType::Function((*name).into(), controlled_marker),
        );
    }
    Ok(())
}

fn controlled_arity(
    actual: usize,
    expected: usize,
) -> Result<(), aw_models::ReportExecutionErrorV1> {
    if actual == expected {
        Ok(())
    } else {
        Err(aw_models::ReportExecutionErrorV1::InternalError)
    }
}
fn controlled_wrap_events(
    events: Vec<aw_models::Event>,
    control: &aw_models::QueryControl,
) -> Result<DataType, aw_models::ReportExecutionErrorV1> {
    control.charge_values(events.len() as u64)?;
    control.charge_bytes((events.len() * std::mem::size_of::<DataType>()) as u64)?;
    Ok(DataType::List(
        events.into_iter().map(DataType::Event).collect(),
    ))
}
pub(crate) fn dispatch_controlled(
    name: &str,
    args: Vec<DataType>,
    env: &VarEnv,
    ti: &aw_models::TimeInterval,
    source: &crate::FrozenQuerySource,
    control: &aw_models::QueryControl,
) -> Result<DataType, aw_models::ReportExecutionErrorV1> {
    use aw_models::ReportExecutionErrorV1 as Error;
    control.charge_fuel(1)?;
    let count = args.len();
    let mut args = args.into_iter();
    macro_rules! take {
        () => {
            args.next().ok_or(Error::InternalError)?
        };
    }
    match name {
        "query_bucket" => {
            if count != 1 && count != 2 {
                return Err(Error::InternalError);
            }
            let id = take!().controlled_string()?;
            let limit = args.next().map(DataType::controlled_index).transpose()?;
            let actual = match env.get("TIMEINTERVAL") {
                Some(DataType::String(raw)) => {
                    if raw.len() > 128 {
                        return Err(Error::InternalError);
                    }
                    let (a, b) = raw.split_once('/').ok_or(Error::InternalError)?;
                    let a = chrono::DateTime::parse_from_rfc3339(a)
                        .map_err(|_| Error::InternalError)?
                        .with_timezone(&chrono::Utc);
                    let b = chrono::DateTime::parse_from_rfc3339(b)
                        .map_err(|_| Error::InternalError)?
                        .with_timezone(&chrono::Utc);
                    aw_models::TimeInterval::new(a, b)
                }
                _ => return Err(Error::InternalError),
            };
            controlled_wrap_events(source.events(&id, &actual, limit, control)?, control)
        }
        "query_bucket_names" => {
            controlled_arity(count, 0)?;
            let names = source.bucket_names(control)?;
            control.charge_values(names.len() as u64)?;
            control.charge_bytes((names.len() * std::mem::size_of::<DataType>()) as u64)?;
            Ok(DataType::List(
                names.into_iter().map(DataType::String).collect(),
            ))
        }
        "sort_by_timestamp" | "sort_by_duration" | "flood" => {
            controlled_arity(count, 1)?;
            let events = take!().controlled_events(control)?;
            let output = match name {
                "sort_by_timestamp" => aw_transform::sort_by_timestamp_controlled(events, control)?,
                "sort_by_duration" => aw_transform::sort_by_duration_controlled(events, control)?,
                _ => aw_transform::flood_controlled(events, chrono::Duration::seconds(5), control)?,
            };
            controlled_wrap_events(output, control)
        }
        "event_count" | "sum_durations" => {
            controlled_arity(count, 1)?;
            let events = take!().controlled_events(control)?;
            if name == "event_count" {
                return Ok(DataType::Number(events.len() as f64));
            }
            let mut total = chrono::Duration::zero();
            for event in events {
                control.charge_fuel(1)?;
                total = total
                    .checked_add(&event.duration)
                    .ok_or(Error::DataIntegrity)?;
            }
            Ok(DataType::Number(total.num_milliseconds() as f64 / 1000.0))
        }
        "filter_keyvals" | "exclude_keyvals" => {
            controlled_arity(count, 3)?;
            let events = take!().controlled_events(control)?;
            let key = take!().controlled_string()?;
            let values = take!().controlled_list()?;
            control
                .charge_bytes((values.len() * std::mem::size_of::<serde_json::Value>()) as u64)?;
            let mut decoded = Vec::new();
            for value in values {
                decoded.push(value.controlled_value(control)?);
            }
            let events = if name == "filter_keyvals" {
                aw_transform::filter_keyvals_controlled(events, &key, &decoded, control)?
            } else {
                aw_transform::exclude_keyvals_controlled(events, &key, &decoded, control)?
            };
            controlled_wrap_events(events, control)
        }
        "filter_period_intersect" | "union_no_overlap" => {
            controlled_arity(count, 2)?;
            let a = take!().controlled_events(control)?;
            let b = take!().controlled_events(control)?;
            let events = if name == "union_no_overlap" {
                aw_transform::union_no_overlap_controlled(a, b, control)?
            } else {
                aw_transform::filter_period_intersect_controlled(a, b, control)?
            };
            controlled_wrap_events(events, control)
        }
        "merge_events_by_keys" => {
            controlled_arity(count, 2)?;
            let events = take!().controlled_events(control)?;
            let keys = take!().controlled_strings(control)?;
            controlled_wrap_events(
                aw_transform::merge_events_by_keys_controlled(events, keys, control)?,
                control,
            )
        }
        "categorize" | "categorize_explained" => {
            controlled_arity(count, 2)?;
            let events = take!().controlled_events(control)?;
            let rules = take!().controlled_category_rules(control)?;
            let mut cache = source.regex_cache.borrow_mut();
            if name == "categorize" {
                return controlled_wrap_events(
                    aw_transform::classify::categorize_controlled(
                        events, &rules, &mut cache, control,
                    )?,
                    control,
                );
            }
            let traced = aw_transform::classify::categorize_with_trace_controlled(
                events, &rules, &mut cache, control,
            )?;
            let mut output = Vec::new();
            for (mut event, trace) in traced {
                control.charge_fuel(1)?;
                control.charge_values(1)?;
                control.charge_bytes(
                    ("$category_trace".len() + std::mem::size_of::<(String, serde_json::Value)>())
                        as u64,
                )?;
                let value =
                    aw_transform::classify::category_trace_value_controlled(&trace, control)?;
                event.data.insert("$category_trace".into(), value);
                control.charge_bytes(std::mem::size_of::<aw_models::Event>() as u64)?;
                output.push(event);
            }
            controlled_wrap_events(output, control)
        }
        "limit_events" => {
            controlled_arity(count, 2)?;
            let events = take!().controlled_events(control)?;
            let limit = take!().controlled_index()?;
            control.charge_values(limit.min(events.len()) as u64)?;
            control.charge_bytes(
                (limit.min(events.len()) * std::mem::size_of::<aw_models::Event>()) as u64,
            )?;
            controlled_wrap_events(events.into_iter().take(limit).collect(), control)
        }
        "contains" => {
            controlled_arity(count, 2)?;
            let container = take!();
            let needle = take!();
            let found = match container {
                DataType::List(items) => {
                    let mut found = false;
                    needle.validate_controlled(control)?;
                    for item in items {
                        control.charge_fuel(1)?;
                        item.validate_controlled(control)?;
                        if item == needle {
                            found = true;
                            break;
                        }
                    }
                    found
                }
                DataType::Dict(items) => items.contains_key(&needle.controlled_string()?),
                _ => return Err(Error::InternalError),
            };
            control.checkpoint()?;
            Ok(DataType::Bool(found))
        }
        "concat" => {
            controlled_arity(count, 2)?;
            let mut a = take!().controlled_list()?;
            let mut b = take!().controlled_list()?;
            control.charge_values(b.len() as u64)?;
            control.charge_bytes(((a.len() + b.len()) * std::mem::size_of::<DataType>()) as u64)?;
            a.append(&mut b);
            Ok(DataType::List(a))
        }
        _ => {
            let _ = ti;
            Err(Error::InternalError)
        }
    }
}
