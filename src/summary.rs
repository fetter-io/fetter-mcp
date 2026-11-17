use std::collections::HashMap;

use fetter::{Ecosystem, LookupReport, Tableable};
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct VulnSummary {
    pub id: String,
    pub summary: String,
    pub cvss_score: Option<f64>,
    pub severity: Option<String>,
    pub url: String,
}

#[derive(Serialize)]
pub struct VersionSummary {
    pub version: String,
    pub vulnerable: bool,
    pub vulnerabilities: Vec<VulnSummary>,
}

#[derive(Serialize)]
pub struct LookupSummary {
    pub ecosystem: String,
    pub package: String,
    pub versions: Vec<VersionSummary>,
    /// Versions that could not be checked against OSV; these are not known to be free of vulnerabilities.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unaudited: Vec<String>,
}

/// Extract the severity label from a CVSS display string such as `CVSS 5.3 (Medium): CVSS:3.1/...`.
fn severity_from_prime(prime: &str) -> Option<String> {
    let start = prime.find('(')? + 1;
    let end = start + prime[start..].find(')')?;
    let sev = prime[start..end].trim();
    (!sev.is_empty()).then(|| sev.to_string())
}

pub fn summarize(lr: &LookupReport, ecosystem: Ecosystem) -> LookupSummary {
    let records = lr.get_records();

    // We strongly assume that this report is only for one package; while this report can handle multiple packages, as used here it will only get requests for a single package
    let package = records
        .first()
        .map(|r| r.package.name.clone())
        .or_else(|| lr.unaudited.first().map(|p| p.name.clone()))
        .unwrap_or_default();
    let ecosystem = records
        .first()
        .map(|r| r.package.ecosystem)
        .unwrap_or(ecosystem)
        .cli_name()
        .to_string();

    // Deduplicate vuln details across records
    let mut vuln_cache: HashMap<String, VulnSummary> = HashMap::new();

    for record in records {
        for (vuln_id, info) in &record.vuln_infos {
            vuln_cache.entry(vuln_id.clone()).or_insert_with(|| {
                let (cvss_score, severity) = info
                    .cvss_details
                    .as_ref()
                    .and_then(|d| d.get_max_score().map(|s| (s, d.get_prime())))
                    .map(|(score, prime)| (Some(score), severity_from_prime(&prime)))
                    .unwrap_or((None, None));

                VulnSummary {
                    id: vuln_id.clone(),
                    summary: info.summary.clone().unwrap_or_default(),
                    cvss_score,
                    severity,
                    url: info.get_url(),
                }
            });
        }
    }

    let versions = records
        .iter()
        .map(|record| {
            let vulns: Vec<VulnSummary> = record
                .vuln_ids
                .iter()
                .filter_map(|id| vuln_cache.get(id).cloned())
                .collect();

            VersionSummary {
                version: record.package.version.to_string(),
                vulnerable: !vulns.is_empty(),
                vulnerabilities: vulns,
            }
        })
        .collect();

    let unaudited = lr.unaudited.iter().map(|p| p.version.to_string()).collect();

    LookupSummary {
        ecosystem,
        package,
        versions,
        unaudited,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fetter::{
        CacheConfig, CvssFilter, DepSpec, FlagCacheRefresh, FlagLog, FlagRetainPassing,
        LookupReport, UreqClient, UreqClientMock, path_cache,
    };
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;

    const DURATION_0: Duration = Duration::from_secs(0);

    fn make_lookup_report(
        pypi_json: &str,
        osv_batch_json: &str,
        osv_vuln_json: &str,
        dep_spec_str: &str,
        retain_passing: bool,
    ) -> LookupReport {
        let mut mock_get_map = HashMap::new();
        mock_get_map.insert("https://pypi.org".to_string(), pypi_json.to_string());
        mock_get_map.insert("https://api.osv.dev".to_string(), osv_vuln_json.to_string());

        let mut mock_post_map = HashMap::new();
        mock_post_map.insert(
            "https://api.osv.dev".to_string(),
            osv_batch_json.to_string(),
        );

        let client = Arc::new(UreqClientMock {
            mock_get: Some(mock_get_map),
            mock_post: Some(mock_post_map),
        }) as Arc<dyn UreqClient>;

        let dep_spec = DepSpec::from_string(dep_spec_str).unwrap();
        let cache_dir = path_cache(true).unwrap();
        let cache_config = CacheConfig::new(DURATION_0, cache_dir);

        LookupReport::from_dep_spec(
            client,
            &dep_spec,
            Some(5),
            &cache_config,
            FlagCacheRefresh(true),
            FlagLog(false),
            CvssFilter::All,
            FlagRetainPassing(retain_passing),
        )
        .unwrap()
    }

    #[test]
    fn test_severity_from_prime() {
        assert_eq!(
            severity_from_prime("CVSS 5.3 (Medium): CVSS:3.1/AV:N").as_deref(),
            Some("Medium")
        );
        assert_eq!(severity_from_prime("CVSS 5.3 (): x"), None);
        assert_eq!(severity_from_prime(""), None);
    }

    #[test]
    fn test_summarize_no_vulnerabilities() {
        let pypi_json = r#"{"info":{"name":"safepkg"},"releases":{"1.0.0":[{"filename":"safepkg-1.0.0.whl"}]}}"#;
        let osv_batch_json = r#"{"results":[{"vulns":null}]}"#;
        let osv_vuln_json = r#"{}"#;

        let lr = make_lookup_report(
            pypi_json,
            osv_batch_json,
            osv_vuln_json,
            "safepkg>=1.0.0",
            true,
        );
        let summary = summarize(&lr, fetter::Ecosystem::Python);

        assert_eq!(summary.ecosystem, "python");
        assert_eq!(summary.package, "safepkg");
        assert_eq!(summary.versions.len(), 1);
        assert_eq!(summary.versions[0].version, "1.0.0");
        assert!(!summary.versions[0].vulnerable);
        assert!(summary.versions[0].vulnerabilities.is_empty());
    }

    #[test]
    fn test_summarize_with_vulnerability() {
        let pypi_json = r#"{"info":{"name":"vulnpkg"},"releases":{"2.0.0":[{"filename":"vulnpkg-2.0.0.whl"}]}}"#;
        let osv_batch_json = r#"{"results":[{"vulns":[{"id":"GHSA-test-1234","modified":"2024-01-01T00:00:00Z"}]}]}"#;
        let osv_vuln_json = r#"{"id":"GHSA-test-1234","summary":"Test vulnerability","references":[{"type":"ADVISORY","url":"https://example.com"}],"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}]}"#;

        let lr = make_lookup_report(
            pypi_json,
            osv_batch_json,
            osv_vuln_json,
            "vulnpkg>=2.0.0",
            false,
        );
        let summary = summarize(&lr, fetter::Ecosystem::Python);

        assert_eq!(summary.package, "vulnpkg");
        assert_eq!(summary.versions.len(), 1);
        assert!(summary.versions[0].vulnerable);
        assert_eq!(summary.versions[0].vulnerabilities.len(), 1);
        assert_eq!(summary.versions[0].vulnerabilities[0].id, "GHSA-test-1234");
        assert_eq!(
            summary.versions[0].vulnerabilities[0].summary,
            "Test vulnerability"
        );
        assert_eq!(
            summary.versions[0].vulnerabilities[0].severity.as_deref(),
            Some("High")
        );
    }

    #[test]
    fn test_summarize_multiple_versions_mixed() {
        let pypi_json = r#"{"info":{"name":"mixpkg"},"releases":{"1.0.0":[{"filename":"mixpkg-1.0.0.whl"}],"2.0.0":[{"filename":"mixpkg-2.0.0.whl"}]}}"#;
        // First version has vuln, second is clean
        let osv_batch_json = r#"{"results":[{"vulns":[{"id":"GHSA-mix-1234","modified":"2024-01-01T00:00:00Z"}]},{"vulns":null}]}"#;
        let osv_vuln_json = r#"{"id":"GHSA-mix-1234","summary":"Mix vuln","references":[]}"#;

        let lr = make_lookup_report(
            pypi_json,
            osv_batch_json,
            osv_vuln_json,
            "mixpkg>=1.0.0",
            true,
        );
        let summary = summarize(&lr, fetter::Ecosystem::Python);

        assert_eq!(summary.package, "mixpkg");
        assert_eq!(summary.versions.len(), 2);

        // Find the vulnerable and safe versions
        let vuln_version = summary.versions.iter().find(|v| v.vulnerable);
        let safe_version = summary.versions.iter().find(|v| !v.vulnerable);

        assert!(vuln_version.is_some());
        assert!(safe_version.is_some());
        assert_eq!(vuln_version.unwrap().vulnerabilities.len(), 1);
        assert!(safe_version.unwrap().vulnerabilities.is_empty());
    }
}
