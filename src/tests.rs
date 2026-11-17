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

#[test]
fn test_args_reject_oversized_ecosystem() {
    let long = "a".repeat(MAX_ECOSYSTEM_LEN + 1);
    let json = serde_json::json!({ "name": "lodash", "ecosystem": long });
    let result: Result<LookupArgs, _> = serde_json::from_value(json.clone());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("ecosystem exceeds")
    );
    let result: Result<IsVulnerableArgs, _> = serde_json::from_value(json.clone());
    assert!(result.is_err());
    let result: Result<MostRecentNotVulnerableArgs, _> = serde_json::from_value(json);
    assert!(result.is_err());
}

#[test]
fn test_args_ecosystem_optional() {
    let json = serde_json::json!({ "name": "requests==2.31.0" });
    let args: IsVulnerableArgs = serde_json::from_value(json).unwrap();
    assert!(args.ecosystem.is_none());
    let json = serde_json::json!({ "name": "lodash@4.17.15", "ecosystem": "npm" });
    let args: IsVulnerableArgs = serde_json::from_value(json).unwrap();
    assert_eq!(args.ecosystem.as_deref(), Some("npm"));
}

#[test]
fn test_allowed_hosts() {
    let defaults = allowed_hosts(None).unwrap();
    assert!(defaults.contains(&"mcp.fetter.io".to_string()));
    assert!(defaults.contains(&"localhost".to_string()));
    assert_eq!(allowed_hosts(Some("")).unwrap(), defaults);
    assert_eq!(
        allowed_hosts(Some("a.example.com, b.example.com:8080,")).unwrap(),
        vec![
            "a.example.com".to_string(),
            "b.example.com:8080".to_string()
        ]
    );
    assert!(allowed_hosts(Some("*")).is_none());
}

#[test]
fn test_tools_listed() {
    let server = FetterMcpServer::new();
    let mut names: Vec<String> = server
        .tool_router
        .list_all()
        .into_iter()
        .map(|t| t.name.to_string())
        .collect();
    names.sort();
    assert_eq!(
        names,
        vec![
            "is_vulnerable",
            "list_ecosystems",
            "lookup",
            "most_recent_not_vulnerable"
        ]
    );
}
