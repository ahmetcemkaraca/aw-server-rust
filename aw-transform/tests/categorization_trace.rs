use aw_models::Event;
use aw_transform::classify::{explain_category, RegexRule, Rule};
use serde_json::Value;

#[test]
fn shared_category_decision_vectors_are_deterministic() {
    let vectors: Value = serde_json::from_str(include_str!("../../test-vectors/categorization-v1.json")).unwrap();
    assert_eq!(vectors["schema_version"], 1);
    assert_eq!(vectors["method_id"], "category-rule-match");
    assert_eq!(vectors["method_version"], 1);

    for case in vectors["cases"].as_array().unwrap() {
        let event: Event = serde_json::from_value(case["event"].clone()).unwrap();
        let rules = case["rules"].as_array().unwrap().iter().map(|rule| {
            let category: Vec<String> = serde_json::from_value(rule["category"].clone()).unwrap();
            let pattern = rule["pattern"].as_str().unwrap();
            let keys: Vec<String> = serde_json::from_value(rule["keys"].clone()).unwrap();
            (category, Rule::Regex(RegexRule::new(pattern, false, Some(keys)).unwrap()))
        }).collect::<Vec<_>>();

        assert_eq!(
            serde_json::to_value(explain_category(&event, &rules)).unwrap(),
            case["expected"],
            "{}",
            case["id"].as_str().unwrap(),
        );
    }
}
