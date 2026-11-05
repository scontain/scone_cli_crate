use super::*;

#[test]
fn finds_a_nested_key_and_trims_it() {
    let json = r#"{"data":[{"other":1},{"casKey":"  abc123  "}]}"#;
    assert_eq!(cas_key_from_report(json).unwrap(), "abc123");
}

#[test]
fn rejects_reports_without_a_key() {
    assert!(cas_key_from_report(r#"{"a":"b"}"#).is_err());
    assert!(cas_key_from_report("not json").is_err());
}
