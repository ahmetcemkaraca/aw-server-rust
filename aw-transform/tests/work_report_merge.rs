use aw_models::Event;
use serde_json::Value;

#[test]
fn work_report_device_merge_matches_shared_overlap_vectors() {
    let vectors: Value = serde_json::from_str(include_str!(
        "../../test-vectors/work-report-merge-v1.json"
    ))
    .unwrap();
    assert_eq!(vectors["schema_version"], 1);
    assert_eq!(vectors["method_id"], "union-no-overlap");

    for case in vectors["cases"].as_array().unwrap() {
        let first: Vec<Event> = serde_json::from_value(case["first"].clone()).unwrap();
        let second: Vec<Event> = serde_json::from_value(case["second"].clone()).unwrap();
        let merged = aw_transform::union_no_overlap(first, second);
        assert_eq!(
            serde_json::to_value(merged).unwrap(),
            case["expected"],
            "{}",
            case["id"].as_str().unwrap()
        );
    }
}
