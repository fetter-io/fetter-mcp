use super::*;

#[test]
fn test_lookup_args_rejects_oversized_name() {
    let long_name = "a".repeat(MAX_NAME_LEN + 1);
    let json = serde_json::json!({ "name": long_name });
    let result: Result<LookupArgs, _> = serde_json::from_value(json);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("exceeds"));
}

#[test]
fn test_most_recent_not_vulnerable_args_rejects_oversized_name() {
    let long_name = "a".repeat(MAX_NAME_LEN + 1);
    let json = serde_json::json!({ "name": long_name });
    let result: Result<MostRecentNotVulnerableArgs, _> = serde_json::from_value(json);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("exceeds"));
}

#[test]
fn test_is_vulnerable_args_rejects_oversized_name() {
    let long_name = "a".repeat(MAX_NAME_LEN + 1);
    let json = serde_json::json!({ "name": long_name });
    let result: Result<IsVulnerableArgs, _> = serde_json::from_value(json);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("exceeds"));
}
