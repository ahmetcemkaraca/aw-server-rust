/// Transforms for classifying (tagging and categorizing) events.
///
/// Based on code in aw_research: https://github.com/ActivityWatch/aw-research/blob/master/aw_research/classify.py
use aw_models::Event;
use fancy_regex::Regex;
use lru::LruCache;
use serde::Serialize;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, OnceLock};

const REGEX_CACHE_CAPACITY: usize = 512;

static REGEX_CACHE: OnceLock<Mutex<LruCache<String, Arc<Regex>>>> = OnceLock::new();

pub enum Rule {
    None,
    Regex(RegexRule),
}

impl RuleTrait for Rule {
    fn matches(&self, event: &Event) -> bool {
        match self {
            Rule::None => false,
            Rule::Regex(rule) => rule.matches(event),
        }
    }
}

trait RuleTrait {
    fn matches(&self, event: &Event) -> bool;
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CategoryDecisionOutcomeV1 {
    Matched,
    CouldNotDetermine,
}

#[derive(Serialize)]
pub struct CategoryRuleMatchV1 {
    pub rule_index: usize,
    pub category_path: Vec<String>,
}

#[derive(Serialize)]
pub struct CategoryDecisionV1 {
    pub schema_version: u32,
    pub method_id: &'static str,
    pub method_version: u32,
    pub outcome: CategoryDecisionOutcomeV1,
    pub matched_rules: Vec<CategoryRuleMatchV1>,
    pub selected_rule_index: Option<usize>,
    pub selected_category: Option<Vec<String>>,
}

pub fn explain_category(event: &Event, rules: &[(Vec<String>, Rule)]) -> CategoryDecisionV1 {
    let mut matched_rules = Vec::new();
    let mut selected: Option<(usize, Vec<String>)> = None;
    let mut selected_depth = 1; // categorize() keeps Uncategorized when a path is empty.

    for (rule_index, (category_path, rule)) in rules.iter().enumerate() {
        if !rule.matches(event) {
            continue;
        }

        matched_rules.push(CategoryRuleMatchV1 {
            rule_index,
            category_path: category_path.clone(),
        });

        if category_path.len() >= selected_depth {
            selected_depth = category_path.len();
            selected = Some((rule_index, category_path.clone()));
        }
    }

    let (selected_rule_index, selected_category) = match selected {
        Some((index, category)) => (Some(index), Some(category)),
        None => (None, None),
    };
    let outcome = if selected_category.is_some() {
        CategoryDecisionOutcomeV1::Matched
    } else {
        CategoryDecisionOutcomeV1::CouldNotDetermine
    };

    CategoryDecisionV1 {
        schema_version: 1,
        method_id: "category-rule-match",
        method_version: 1,
        outcome,
        matched_rules,
        selected_rule_index,
        selected_category,
    }
}

pub struct RegexRule {
    regex: Arc<Regex>,
    select_keys: Option<Vec<String>>,
}

impl RegexRule {
    pub fn new(
        regex_str: &str,
        ignore_case: bool,
        select_keys: Option<Vec<String>>,
    ) -> Result<RegexRule, fancy_regex::Error> {
        // Validate that select_keys is not an empty list, which would silently never match.
        if let Some(ref keys) = select_keys {
            if keys.is_empty() {
                return Err(fancy_regex::Error::ParseError(
                    0,
                    fancy_regex::ParseError::GeneralParseError(
                        "select_keys must not be empty".to_string(),
                    ),
                ));
            }
        }

        // can't use `RegexBuilder::case_insensitive` because it's not supported by fancy_regex,
        // so we need to prefix with `(?i)` to make it case insensitive.
        let full_regex_str = if ignore_case {
            format!("(?i){regex_str}")
        } else {
            regex_str.to_string()
        };

        let cache = REGEX_CACHE.get_or_init(|| {
            Mutex::new(LruCache::new(
                NonZeroUsize::new(REGEX_CACHE_CAPACITY).unwrap(),
            ))
        });
        let mut cache = cache.lock().unwrap();

        let regex = if let Some(re) = cache.get(&full_regex_str) {
            re.clone()
        } else {
            let re = Arc::new(Regex::new(&full_regex_str)?);
            cache.put(full_regex_str.clone(), re.clone());
            re
        };

        Ok(RegexRule { regex, select_keys })
    }

    fn value_matches(&self, value: &serde_json::Value) -> bool {
        match value.as_str() {
            Some(value) => self.regex.is_match(value).unwrap_or(false),
            None => false,
        }
    }
}

/// This struct defines the rules for classification.
/// For now it just needs to contain the regex to match with, but in the future it might contain a
/// glob-pattern, or other options for classifying.
/// It's puropse is to make the API easy to extend in the future without having to break backwards
/// compatibility (or have to maintain "old" query2 functions).
impl RuleTrait for RegexRule {
    fn matches(&self, event: &Event) -> bool {
        match &self.select_keys {
            Some(select_keys) => select_keys
                .iter()
                .filter_map(|key| event.data.get(key))
                .any(|val| self.value_matches(val)),
            None => event.data.values().any(|val| self.value_matches(val)),
        }
    }
}

impl From<Regex> for Rule {
    fn from(re: Regex) -> Self {
        Rule::Regex(RegexRule {
            regex: Arc::new(re),
            select_keys: None,
        })
    }
}

/// Categorizes a list of events
///
/// An event can only have one category, although the category may have a hierarchy,
/// for instance: "Work -> ActivityWatch -> aw-server-rust"
/// If multiple categories match, the deepest one will be chosen.
pub fn categorize(events: Vec<Event>, rules: &[(Vec<String>, Rule)]) -> Vec<Event> {
    categorize_with_trace(events, rules)
        .into_iter()
        .map(|(event, _)| event)
        .collect()
}

pub fn categorize_with_trace(
    events: Vec<Event>,
    rules: &[(Vec<String>, Rule)],
) -> Vec<(Event, CategoryDecisionV1)> {
    events
        .into_iter()
        .map(|mut event| {
            let decision = explain_category(&event, rules);
            let category = decision
                .selected_category
                .clone()
                .unwrap_or_else(|| vec!["Uncategorized".into()]);
            event
                .data
                .insert("$category".into(), serde_json::json!(category));
            (event, decision)
        })
        .collect()
}

/// Tags a list of events
///
/// An event can have many tags (as opposed to only one category) which will be put into the `$tags` key of
/// the event data object.
pub fn tag(mut events: Vec<Event>, rules: &[(String, Rule)]) -> Vec<Event> {
    let mut events_tagged = Vec::new();
    for event in events.drain(..) {
        events_tagged.push(tag_one(event, rules));
    }
    events_tagged
}

fn tag_one(mut event: Event, rules: &[(String, Rule)]) -> Event {
    let mut tags: Vec<String> = Vec::new();
    for (cls, rule) in rules {
        if rule.matches(&event) {
            tags.push(cls.clone());
        }
    }
    tags.sort_unstable();
    tags.dedup();
    event.data.insert("$tags".into(), serde_json::json!(tags));
    event
}

#[test]
fn test_rule() {
    let mut e_match = Event::default();
    e_match
        .data
        .insert("test".into(), serde_json::json!("just a test"));

    let mut e_no_match = Event::default();
    e_no_match
        .data
        .insert("nonono".into(), serde_json::json!("no match!"));

    let rule_from_regex = Rule::from(Regex::new("test").unwrap());
    let rule_from_new = Rule::Regex(RegexRule::new("test", false, None).unwrap());
    let rule_none = Rule::None;
    assert!(rule_from_regex.matches(&e_match));
    assert!(rule_from_new.matches(&e_match));
    assert!(!rule_from_regex.matches(&e_no_match));
    assert!(!rule_from_new.matches(&e_no_match));

    assert!(!rule_none.matches(&e_match));
}

#[test]
fn test_rule_lookahead() {
    // Originally requested by a user here, to match aw-server-python: https://canary.discord.com/channels/755040852727955476/755334543891759194/994291987878522961
    let mut e_match = Event::default();
    e_match
        .data
        .insert("test".into(), serde_json::json!("testing lookahead"));

    let rule_from_regex = Rule::from(Regex::new("testing (?!lookahead)").unwrap());
    assert!(!rule_from_regex.matches(&e_match));
}

#[test]
fn test_rule_select_keys() {
    let mut event = Event::default();
    event
        .data
        .insert("app".into(), serde_json::json!("terminal"));
    event
        .data
        .insert("title".into(), serde_json::json!("just a test"));
    event.data.insert("pid".into(), serde_json::json!(123));

    let title_only =
        Rule::Regex(RegexRule::new("test", false, Some(vec!["title".into()])).unwrap());
    let app_only = Rule::Regex(RegexRule::new("test", false, Some(vec!["app".into()])).unwrap());
    let missing_key =
        Rule::Regex(RegexRule::new("test", false, Some(vec!["missing".into()])).unwrap());
    let non_string_key =
        Rule::Regex(RegexRule::new("123", false, Some(vec!["pid".into()])).unwrap());

    assert!(title_only.matches(&event));
    assert!(!app_only.matches(&event));
    assert!(!missing_key.matches(&event));
    assert!(!non_string_key.matches(&event));
}

#[test]
fn test_rule_select_keys_empty_list() {
    // An empty select_keys list should return an error rather than
    // silently producing a rule that never matches anything.
    let result = RegexRule::new("test", false, Some(vec![]));
    assert!(result.is_err());
}

#[test]
fn test_malformed_regex_is_rejected() {
    assert!(RegexRule::new("[", false, None).is_err());
}
#[test]
fn test_categorize() {
    let mut e = Event::default();
    e.data
        .insert("test".into(), serde_json::json!("just a test"));

    let mut events = vec![e];
    let rules: Vec<(Vec<String>, Rule)> = vec![
        (
            vec!["Test".into()],
            Rule::from(Regex::new(r"test").unwrap()),
        ),
        (
            vec!["Test".into(), "Subtest".into()],
            Rule::from(Regex::new(r"test").unwrap()),
        ),
        (
            vec!["Other".into()],
            Rule::from(Regex::new(r"nonmatching").unwrap()),
        ),
    ];
    events = categorize(events, &rules);

    assert_eq!(events.len(), 1);
    assert_eq!(
        events.first().unwrap().data.get("$category").unwrap(),
        &serde_json::json!(vec!["Test", "Subtest"])
    );
}

#[test]
fn test_categorize_uncategorized() {
    // Checks that the category correctly becomes uncategorized when no category matches
    let mut e = Event::default();
    e.data
        .insert("test".into(), serde_json::json!("just a test"));

    let mut events = vec![e];
    let rules: Vec<(Vec<String>, Rule)> = vec![(
        vec!["Non-matching".into(), "test".into()],
        Rule::from(Regex::new(r"not going to match").unwrap()),
    )];
    events = categorize(events, &rules);

    assert_eq!(events.len(), 1);
    assert_eq!(
        events.first().unwrap().data.get("$category").unwrap(),
        &serde_json::json!(vec!["Uncategorized"])
    );
}

#[test]
fn test_tag() {
    let mut e = Event::default();
    e.data
        .insert("test".into(), serde_json::json!("just a test"));

    let mut events = vec![e];
    let rules: Vec<(String, Rule)> = vec![
        ("test".into(), Rule::from(Regex::new(r"test").unwrap())),
        ("test-2".into(), Rule::from(Regex::new(r"test").unwrap())),
        (
            "nomatch".into(),
            Rule::from(Regex::new(r"nomatch").unwrap()),
        ),
    ];
    events = tag(events, &rules);

    assert_eq!(events.len(), 1);

    let event = events.first().unwrap();
    let tags = event.data.get("$tags").unwrap();
    assert_eq!(tags, &serde_json::json!(vec!["test", "test-2"]));
}
