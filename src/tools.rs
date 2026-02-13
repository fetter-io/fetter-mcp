use std::sync::Arc;
use std::time::Duration;

use fetter::{
    CacheConfig, CvssFilter, DepSpec, FlagCacheRefresh, FlagLog, FlagRetainPassing, LookupReport,
    UreqClient, path_cache,
};

use crate::summary::{LookupSummary, summarize};

/// Result of most_recent_not_vulnerable lookup
#[derive(Debug, serde::Serialize)]
pub struct SafeVersionResult {
    pub package: String,
    pub version: String,
    pub vulnerable: bool,
    pub vulnerabilities: Vec<()>,
}

/// Result of is_vulnerable lookup
#[derive(Debug, serde::Serialize)]
pub struct VulnerabilityCheckResult {
    pub package: String,
    pub version: String,
    pub vulnerable: bool,
    pub vulnerabilities: Vec<crate::summary::VulnSummary>,
}

/// Core logic for the lookup tool
pub fn lookup_impl(
    client: Arc<dyn UreqClient>,
    name: &str,
    limit: Option<usize>,
    cvss_filter: CvssFilter,
    retain_passing: bool,
) -> Result<LookupSummary, String> {
    let ds = DepSpec::from_string(name).map_err(|e| e.to_string())?;
    let cache_dir = path_cache(true).unwrap_or_else(std::env::temp_dir);
    let cache_config = CacheConfig::new(Duration::from_secs(3600), cache_dir);

    let lr = LookupReport::from_dep_spec(
        client,
        &ds,
        limit,
        &cache_config,
        FlagCacheRefresh(false),
        FlagLog(false),
        cvss_filter,
        FlagRetainPassing(retain_passing),
    )
    .map_err(|e| e.to_string())?;

    Ok(summarize(&lr))
}

/// Core logic for the most_recent_not_vulnerable tool
pub fn most_recent_not_vulnerable_impl(
    client: Arc<dyn UreqClient>,
    name: &str,
) -> Result<SafeVersionResult, String> {
    // Reject exact versions - we need to search for a safe one
    let ds = DepSpec::from_string(name).map_err(|e| e.to_string())?;
    if ds.get_exact().is_some() {
        return Err("Provide only a package name, not specific version.".to_string());
    }

    let summary = lookup_impl(client, name, Some(1), CvssFilter::All, true)?;
    let safe_version = summary.versions.iter().find(|v| !v.vulnerable);

    match safe_version {
        Some(v) => Ok(SafeVersionResult {
            package: summary.package,
            version: v.version.clone(),
            vulnerable: false,
            vulnerabilities: vec![],
        }),
        None => Err(format!(
            "No recent version of '{}' found without vulnerabilities",
            summary.package
        )),
    }
}

/// Core logic for the is_vulnerable tool
pub fn is_vulnerable_impl(
    client: Arc<dyn UreqClient>,
    name: &str,
) -> Result<VulnerabilityCheckResult, String> {
    // Require exact version
    let ds = DepSpec::from_string(name).map_err(|e| e.to_string())?;
    if ds.get_exact().is_none() {
        return Err("Exact version required (e.g., 'requests==2.31.0')".to_string());
    }

    let summary = lookup_impl(client, name, Some(1), CvssFilter::All, true)?;

    match summary.versions.first() {
        Some(v) => Ok(VulnerabilityCheckResult {
            package: summary.package,
            version: v.version.clone(),
            vulnerable: v.vulnerable,
            vulnerabilities: v.vulnerabilities.clone(),
        }),
        None => Err(format!("Version not found for '{}'", name)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fetter::UreqClientMock;
    use std::collections::HashMap;

    fn make_mock_client(
        pypi_json: &str,
        osv_batch_json: &str,
        osv_vuln_json: &str,
    ) -> Arc<dyn UreqClient> {
        let mut mock_get_map = HashMap::new();
        mock_get_map.insert("https://pypi.org".to_string(), pypi_json.to_string());
        mock_get_map.insert("https://api.osv.dev".to_string(), osv_vuln_json.to_string());

        let mut mock_post_map = HashMap::new();
        mock_post_map.insert(
            "https://api.osv.dev".to_string(),
            osv_batch_json.to_string(),
        );

        Arc::new(UreqClientMock {
            mock_get: Some(mock_get_map),
            mock_post: Some(mock_post_map),
        })
    }

    #[test]
    fn test_most_recent_not_vulnerable_finds_safe_version() {
        let pypi_json = r#"{"info":{"name":"testpkg"},"releases":{"1.0.0":[{"filename":"testpkg-1.0.0.whl"}]}}"#;
        let osv_batch_json = r#"{"results":[{"vulns":null}]}"#;
        let osv_vuln_json = r#"{}"#;

        let client = make_mock_client(pypi_json, osv_batch_json, osv_vuln_json);
        let result = most_recent_not_vulnerable_impl(client, "testpkg");

        assert!(result.is_ok());
        let safe = result.unwrap();
        assert_eq!(safe.package, "testpkg");
        assert_eq!(safe.version, "1.0.0");
        assert!(!safe.vulnerable);
    }

    #[test]
    fn test_most_recent_not_vulnerable_rejects_exact_version() {
        let pypi_json = r#"{}"#;
        let osv_batch_json = r#"{}"#;
        let osv_vuln_json = r#"{}"#;

        let client = make_mock_client(pypi_json, osv_batch_json, osv_vuln_json);
        let result = most_recent_not_vulnerable_impl(client, "testpkg==1.0.0");

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not specific version"));
    }

    #[test]
    fn test_most_recent_not_vulnerable_no_safe_version() {
        let pypi_json = r#"{"info":{"name":"vulnpkg"},"releases":{"1.0.0":[{"filename":"vulnpkg-1.0.0.whl"}]}}"#;
        let osv_batch_json =
            r#"{"results":[{"vulns":[{"id":"GHSA-1234","modified":"2024-01-01T00:00:00Z"}]}]}"#;
        let osv_vuln_json = r#"{"id":"GHSA-1234","summary":"A vulnerability","references":[]}"#;

        let client = make_mock_client(pypi_json, osv_batch_json, osv_vuln_json);
        let result = most_recent_not_vulnerable_impl(client, "vulnpkg");

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No recent version"));
    }

    #[test]
    fn test_is_vulnerable_detects_vulnerability() {
        let pypi_json = r#"{"info":{"name":"vulnpkg"},"releases":{"1.0.0":[{"filename":"vulnpkg-1.0.0.whl"}]}}"#;
        let osv_batch_json =
            r#"{"results":[{"vulns":[{"id":"GHSA-test","modified":"2024-01-01T00:00:00Z"}]}]}"#;
        let osv_vuln_json = r#"{"id":"GHSA-test","summary":"Test vuln","references":[]}"#;

        let client = make_mock_client(pypi_json, osv_batch_json, osv_vuln_json);
        let result = is_vulnerable_impl(client, "vulnpkg==1.0.0");

        assert!(result.is_ok());
        let check = result.unwrap();
        assert_eq!(check.package, "vulnpkg");
        assert!(check.vulnerable);
        assert_eq!(check.vulnerabilities.len(), 1);
    }

    #[test]
    fn test_is_vulnerable_safe_package() {
        let pypi_json = r#"{"info":{"name":"safepkg"},"releases":{"2.0.0":[{"filename":"safepkg-2.0.0.whl"}]}}"#;
        let osv_batch_json = r#"{"results":[{"vulns":null}]}"#;
        let osv_vuln_json = r#"{}"#;

        let client = make_mock_client(pypi_json, osv_batch_json, osv_vuln_json);
        let result = is_vulnerable_impl(client, "safepkg==2.0.0");

        assert!(result.is_ok());
        let check = result.unwrap();
        assert!(!check.vulnerable);
        assert!(check.vulnerabilities.is_empty());
    }

    #[test]
    fn test_is_vulnerable_rejects_non_exact_version() {
        let pypi_json = r#"{}"#;
        let osv_batch_json = r#"{}"#;
        let osv_vuln_json = r#"{}"#;

        let client = make_mock_client(pypi_json, osv_batch_json, osv_vuln_json);
        let result = is_vulnerable_impl(client, "testpkg>=1.0.0");

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Exact version required"));
    }
}
