use std::sync::Arc;
use std::time::Duration;

use fetter::{
    CacheConfig, CvssFilter, DepSpec, Ecosystem, FlagCacheRefresh, FlagLog, FlagRetainPassing,
    LookupReport, UreqClient, path_cache,
};
use serde::Serialize;

use crate::summary::{LookupSummary, VulnSummary, summarize};

// -----------------------------------------------------------------------------
// Ecosystems

/// The ecosystem used when a request does not name one; preserves the Python-only behavior of fetter-mcp 1.x.
pub const DEFAULT_ECOSYSTEM: Ecosystem = Ecosystem::Python;

/// Ecosystems this server can look up: those with vulnerability data in OSV.
pub fn supported_ecosystems() -> Vec<Ecosystem> {
    Ecosystem::ALL.into_iter().filter(|e| e.has_osv()).collect()
}

fn supported_names() -> String {
    supported_ecosystems()
        .iter()
        .map(|e| e.cli_name())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Parse an optional ecosystem name: a fetter name (`python`, `npm`, ...) or an OSV name (`PyPI`, `crates.io`, ...), case-insensitively. A missing or empty name is the default ecosystem.
pub fn parse_ecosystem(name: Option<&str>) -> Result<Ecosystem, String> {
    let name = name.map(str::trim).unwrap_or("");
    if name.is_empty() {
        return Ok(DEFAULT_ECOSYSTEM);
    }
    let lower = name.to_lowercase();
    let found = Ecosystem::ALL
        .into_iter()
        .find(|e| e.cli_name() == lower || e.osv_name().to_lowercase() == lower);
    match found {
        Some(e) if e.has_osv() => Ok(e),
        Some(e) => Err(format!(
            "Ecosystem '{}' has no vulnerability data and is not supported; supported ecosystems: {}",
            e.cli_name(),
            supported_names()
        )),
        None => Err(format!(
            "Unknown ecosystem '{name}'; supported ecosystems: {}",
            supported_names()
        )),
    }
}

/// A description of a supported ecosystem, for `list_ecosystems`.
#[derive(Debug, Serialize)]
pub struct EcosystemInfo {
    pub name: &'static str,
    pub osv_name: &'static str,
    pub registry: &'static str,
    pub name_format: &'static str,
    pub exact_example: &'static str,
    pub range_example: &'static str,
}

#[derive(Debug, Serialize)]
pub struct EcosystemList {
    pub default: &'static str,
    pub ecosystems: Vec<EcosystemInfo>,
}

fn ecosystem_info(eco: Ecosystem) -> Option<EcosystemInfo> {
    // (registry, name_format, exact_example, range_example)
    let (registry, name_format, exact_example, range_example) = match eco {
        Ecosystem::Python => (
            "PyPI (pypi.org)",
            "PEP 508 requirement: name with an optional version specifier",
            "requests==2.31.0",
            "requests>=2.30,<3",
        ),
        Ecosystem::Npm => (
            "npm registry (registry.npmjs.org)",
            "name@requirement with an npm semver range; scoped names allowed",
            "lodash@4.17.15",
            "lodash@>=4.17.15 <4.17.22",
        ),
        Ecosystem::Cargo => (
            "crates.io (sparse index)",
            "name@requirement with Cargo semantics; a bare version is a caret range, so use '=' for an exact version",
            "time@=0.1.43",
            "serde@^1.0",
        ),
        Ecosystem::Gha => (
            "GitHub (git tags)",
            "owner/repo@ref (a subpath is reduced to owner/repo); a name alone checks all tags",
            "tj-actions/changed-files@v35",
            "actions/download-artifact",
        ),
        Ecosystem::VsCode => (
            "Open VSX (open-vsx.org)",
            "publisher.name@requirement with an npm semver range",
            "ms-python.python@2024.0.1",
            "ms-python.python@>=2024.0.0",
        ),
        Ecosystem::Go => (
            "Go module proxy (proxy.golang.org)",
            "module/path@requirement with an npm-style range",
            "golang.org/x/net@v0.17.0",
            "golang.org/x/net@>=v0.20.0 <v0.24.0",
        ),
        Ecosystem::Ruby => (
            "RubyGems (rubygems.org)",
            "gem@requirement with RubyGems operators",
            "nokogiri@1.13.8",
            "nokogiri@~> 1.16.0",
        ),
        Ecosystem::Php => (
            "Packagist (packagist.org)",
            "vendor/package@requirement with Composer constraints",
            "guzzlehttp/guzzle@7.4.0",
            "guzzlehttp/guzzle@~7.4.0",
        ),
        Ecosystem::Swift => (
            "Git repository tags",
            "host/owner/repo@requirement with an npm-style range",
            "github.com/sparkle-project/Sparkle@2.8.1",
            "github.com/sparkle-project/Sparkle@>=2.6.0 <2.9.0",
        ),
        // No OSV data: not offered by this server
        Ecosystem::PreCommit | Ecosystem::Chromium | Ecosystem::Firefox => return None,
    };
    Some(EcosystemInfo {
        name: eco.cli_name(),
        osv_name: eco.osv_name(),
        registry,
        name_format,
        exact_example,
        range_example,
    })
}

pub fn list_ecosystems_impl() -> EcosystemList {
    EcosystemList {
        default: DEFAULT_ECOSYSTEM.cli_name(),
        ecosystems: supported_ecosystems()
            .into_iter()
            .filter_map(ecosystem_info)
            .collect(),
    }
}

// -----------------------------------------------------------------------------
// Name parsing

/// Split `name@requirement` at the last `@` that is not the first character (scoped npm names start with `@`). Mirrors fetter's (crate-private) `split_name_requirement`.
pub fn split_name_requirement(arg: &str) -> (&str, Option<&str>) {
    match arg[1.min(arg.len())..].rfind('@') {
        Some(i) => {
            let at = i + 1;
            let req = arg[at + 1..].trim();
            (arg[..at].trim(), (!req.is_empty()).then_some(req))
        }
        None => (arg.trim(), None),
    }
}

/// An example of an exact name for error messages.
fn exact_example(eco: Ecosystem) -> &'static str {
    ecosystem_info(eco)
        .map(|i| i.exact_example)
        .unwrap_or("name@version")
}

// -----------------------------------------------------------------------------
// Results

/// Result of most_recent_not_vulnerable lookup
#[derive(Debug, Serialize)]
pub struct SafeVersionResult {
    pub ecosystem: String,
    pub package: String,
    pub version: String,
    pub vulnerable: bool,
    pub vulnerabilities: Vec<()>,
}

/// Result of is_vulnerable lookup
#[derive(Debug, Serialize)]
pub struct VulnerabilityCheckResult {
    pub ecosystem: String,
    pub package: String,
    pub version: String,
    pub vulnerable: bool,
    pub vulnerabilities: Vec<VulnSummary>,
}

// -----------------------------------------------------------------------------
// Implementations

pub fn lookup_impl(
    client: Arc<dyn UreqClient>,
    eco: Ecosystem,
    name: &str,
    limit: Option<usize>,
    cvss_filter: CvssFilter,
    retain_passing: bool,
) -> Result<LookupSummary, String> {
    let cache_dir = path_cache(true).unwrap_or_else(std::env::temp_dir);
    let cache_config = CacheConfig::new(Duration::from_secs(3600), cache_dir);

    let lr = match eco {
        Ecosystem::Python => {
            let ds = DepSpec::from_string(name).map_err(|e| e.to_string())?;
            LookupReport::from_dep_spec(
                client,
                &ds,
                limit,
                &cache_config,
                FlagCacheRefresh(false),
                FlagLog(false),
                cvss_filter,
                FlagRetainPassing(retain_passing),
            )
        }
        _ => LookupReport::from_name_requirement(
            client,
            eco,
            name,
            limit,
            &cache_config,
            FlagCacheRefresh(false),
            FlagLog(false),
            cvss_filter,
            FlagRetainPassing(retain_passing),
        ),
    }
    .map_err(|e| e.to_string())?;

    let mut summary = summarize(&lr, eco);
    if summary.package.is_empty() {
        // no versions matched: report the requested name
        summary.package = match eco {
            Ecosystem::Python => DepSpec::from_string(name)
                .map(|ds| ds.name)
                .unwrap_or_else(|_| name.to_string()),
            _ => split_name_requirement(name).0.to_string(),
        };
    }
    Ok(summary)
}

pub fn most_recent_not_vulnerable_impl(
    client: Arc<dyn UreqClient>,
    eco: Ecosystem,
    name: &str,
) -> Result<SafeVersionResult, String> {
    if eco == Ecosystem::Python {
        // Reject exact versions - we need to search for a safe one
        let ds = DepSpec::from_string(name).map_err(|e| e.to_string())?;
        if ds.get_exact().is_some() {
            return Err("Provide only a package name, not specific version.".to_string());
        }
    }

    let summary = lookup_impl(client, eco, name, Some(1), CvssFilter::All, true)?;
    let safe_version = summary.versions.iter().find(|v| !v.vulnerable);

    match safe_version {
        Some(v) => Ok(SafeVersionResult {
            ecosystem: summary.ecosystem.clone(),
            package: summary.package.clone(),
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

pub fn is_vulnerable_impl(
    client: Arc<dyn UreqClient>,
    eco: Ecosystem,
    name: &str,
) -> Result<VulnerabilityCheckResult, String> {
    let exact_err = || format!("Exact version required (e.g., '{}')", exact_example(eco));

    // Require exact version
    let query = match eco {
        Ecosystem::Python => {
            let ds = DepSpec::from_string(name).map_err(|e| e.to_string())?;
            if ds.get_exact().is_none() {
                return Err(exact_err());
            }
            name.to_string()
        }
        _ => {
            let (pkg, req) = split_name_requirement(name);
            let Some(version) = req else {
                return Err(exact_err());
            };
            // A bare Cargo version is a caret range; make it exact
            if eco == Ecosystem::Cargo && !version.starts_with('=') {
                format!("{pkg}@={version}")
            } else {
                format!("{pkg}@{version}")
            }
        }
    };

    // A limit of 2 exposes a requirement that matches more than one version
    let summary = lookup_impl(client, eco, &query, Some(2), CvssFilter::All, true)?;

    match summary.versions.as_slice() {
        [v] => Ok(VulnerabilityCheckResult {
            ecosystem: summary.ecosystem.clone(),
            package: summary.package.clone(),
            version: v.version.clone(),
            vulnerable: v.vulnerable,
            vulnerabilities: v.vulnerabilities.clone(),
        }),
        [] => Err(format!("Version not found for '{}'", name)),
        _ => Err(exact_err()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fetter::UreqClientMock;
    use std::collections::HashMap;

    fn make_mock_client(
        registry: (&str, &str),
        osv_batch_json: &str,
        osv_vuln_json: &str,
    ) -> Arc<dyn UreqClient> {
        let mut mock_get_map = HashMap::new();
        mock_get_map.insert(registry.0.to_string(), registry.1.to_string());
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

    fn pypi(json: &str) -> (&'static str, &str) {
        ("https://pypi.org", json)
    }

    fn npm(json: &str) -> (&'static str, &str) {
        ("https://registry.npmjs.org", json)
    }

    // -------------------------------------------------------------------------
    // ecosystems

    #[test]
    fn test_parse_ecosystem_default() {
        assert_eq!(parse_ecosystem(None).unwrap(), Ecosystem::Python);
        assert_eq!(parse_ecosystem(Some("  ")).unwrap(), Ecosystem::Python);
    }

    #[test]
    fn test_parse_ecosystem_names() {
        assert_eq!(parse_ecosystem(Some("npm")).unwrap(), Ecosystem::Npm);
        assert_eq!(parse_ecosystem(Some("Cargo")).unwrap(), Ecosystem::Cargo);
        assert_eq!(parse_ecosystem(Some("PyPI")).unwrap(), Ecosystem::Python);
        assert_eq!(
            parse_ecosystem(Some("crates.io")).unwrap(),
            Ecosystem::Cargo
        );
        assert_eq!(parse_ecosystem(Some("RubyGems")).unwrap(), Ecosystem::Ruby);
        assert_eq!(
            parse_ecosystem(Some("GitHub Actions")).unwrap(),
            Ecosystem::Gha
        );
    }

    #[test]
    fn test_parse_ecosystem_unsupported() {
        let e = parse_ecosystem(Some("chromium")).unwrap_err();
        assert!(e.contains("not supported"));
        assert!(e.contains("npm"));
        let e = parse_ecosystem(Some("cobol")).unwrap_err();
        assert!(e.contains("Unknown ecosystem"));
    }

    #[test]
    fn test_list_ecosystems_matches_supported() {
        let list = list_ecosystems_impl();
        assert_eq!(list.default, "python");
        let names: Vec<_> = list.ecosystems.iter().map(|e| e.name).collect();
        let expected: Vec<_> = supported_ecosystems()
            .iter()
            .map(|e| e.cli_name())
            .collect();
        assert_eq!(names, expected);
        assert_eq!(names.len(), 9);
        // every listed ecosystem parses
        for n in names {
            assert!(parse_ecosystem(Some(n)).is_ok());
        }
    }

    #[test]
    fn test_split_name_requirement() {
        assert_eq!(split_name_requirement("lodash"), ("lodash", None));
        assert_eq!(
            split_name_requirement("lodash@4.17.15"),
            ("lodash", Some("4.17.15"))
        );
        assert_eq!(
            split_name_requirement("@babel/core@^7.0.0"),
            ("@babel/core", Some("^7.0.0"))
        );
        assert_eq!(split_name_requirement("@babel/core"), ("@babel/core", None));
        assert_eq!(split_name_requirement("lodash@"), ("lodash", None));
        assert_eq!(split_name_requirement(""), ("", None));
    }

    // -------------------------------------------------------------------------
    // python

    #[test]
    fn test_most_recent_not_vulnerable_finds_safe_version() {
        let pypi_json = r#"{"info":{"name":"testpkg"},"releases":{"1.0.0":[{"filename":"testpkg-1.0.0.whl"}]}}"#;
        let osv_batch_json = r#"{"results":[{"vulns":null}]}"#;
        let osv_vuln_json = r#"{}"#;

        let client = make_mock_client(pypi(pypi_json), osv_batch_json, osv_vuln_json);
        let result = most_recent_not_vulnerable_impl(client, Ecosystem::Python, "testpkg");

        let safe = result.unwrap();
        assert_eq!(safe.ecosystem, "python");
        assert_eq!(safe.package, "testpkg");
        assert_eq!(safe.version, "1.0.0");
        assert!(!safe.vulnerable);
    }

    #[test]
    fn test_most_recent_not_vulnerable_rejects_exact_version() {
        let client = make_mock_client(pypi("{}"), "{}", "{}");
        let result = most_recent_not_vulnerable_impl(client, Ecosystem::Python, "testpkg==1.0.0");

        assert!(result.unwrap_err().contains("not specific version"));
    }

    #[test]
    fn test_most_recent_not_vulnerable_no_safe_version() {
        let pypi_json = r#"{"info":{"name":"vulnpkg"},"releases":{"1.0.0":[{"filename":"vulnpkg-1.0.0.whl"}]}}"#;
        let osv_batch_json =
            r#"{"results":[{"vulns":[{"id":"GHSA-1234","modified":"2024-01-01T00:00:00Z"}]}]}"#;
        let osv_vuln_json = r#"{"id":"GHSA-1234","summary":"A vulnerability","references":[]}"#;

        let client = make_mock_client(pypi(pypi_json), osv_batch_json, osv_vuln_json);
        let result = most_recent_not_vulnerable_impl(client, Ecosystem::Python, "vulnpkg");

        assert!(result.unwrap_err().contains("No recent version"));
    }

    #[test]
    fn test_is_vulnerable_detects_vulnerability() {
        let pypi_json = r#"{"info":{"name":"vulnpkg"},"releases":{"1.0.0":[{"filename":"vulnpkg-1.0.0.whl"}]}}"#;
        let osv_batch_json =
            r#"{"results":[{"vulns":[{"id":"GHSA-test","modified":"2024-01-01T00:00:00Z"}]}]}"#;
        let osv_vuln_json = r#"{"id":"GHSA-test","summary":"Test vuln","references":[]}"#;

        let client = make_mock_client(pypi(pypi_json), osv_batch_json, osv_vuln_json);
        let result = is_vulnerable_impl(client, Ecosystem::Python, "vulnpkg==1.0.0");

        let check = result.unwrap();
        assert_eq!(check.ecosystem, "python");
        assert_eq!(check.package, "vulnpkg");
        assert!(check.vulnerable);
        assert_eq!(check.vulnerabilities.len(), 1);
    }

    #[test]
    fn test_is_vulnerable_safe_package() {
        let pypi_json = r#"{"info":{"name":"safepkg"},"releases":{"2.0.0":[{"filename":"safepkg-2.0.0.whl"}]}}"#;
        let osv_batch_json = r#"{"results":[{"vulns":null}]}"#;

        let client = make_mock_client(pypi(pypi_json), osv_batch_json, "{}");
        let result = is_vulnerable_impl(client, Ecosystem::Python, "safepkg==2.0.0");

        let check = result.unwrap();
        assert!(!check.vulnerable);
        assert!(check.vulnerabilities.is_empty());
    }

    #[test]
    fn test_is_vulnerable_rejects_non_exact_version() {
        let client = make_mock_client(pypi("{}"), "{}", "{}");
        let result = is_vulnerable_impl(client, Ecosystem::Python, "testpkg>=1.0.0");

        assert!(result.unwrap_err().contains("Exact version required"));
    }

    // -------------------------------------------------------------------------
    // npm

    const NPM_JSON: &str = r#"{"name":"leftpad","versions":{"1.0.0":{},"1.1.0":{},"2.0.0":{}}}"#;

    #[test]
    fn test_lookup_npm_range() {
        let osv_batch_json = r#"{"results":[{"vulns":null},{"vulns":null}]}"#;
        let client = make_mock_client(npm(NPM_JSON), osv_batch_json, "{}");
        let summary = lookup_impl(
            client,
            Ecosystem::Npm,
            "leftpad@^1.0.0",
            None,
            CvssFilter::All,
            true,
        )
        .unwrap();
        assert_eq!(summary.ecosystem, "npm");
        assert_eq!(summary.package, "leftpad");
        let mut versions: Vec<_> = summary
            .versions
            .iter()
            .map(|v| v.version.as_str())
            .collect();
        versions.sort();
        assert_eq!(versions, vec!["1.0.0", "1.1.0"]);
    }

    #[test]
    fn test_is_vulnerable_npm_exact() {
        let osv_batch_json =
            r#"{"results":[{"vulns":[{"id":"GHSA-npm-1","modified":"2024-01-01T00:00:00Z"}]}]}"#;
        let osv_vuln_json = r#"{"id":"GHSA-npm-1","summary":"npm vuln","references":[]}"#;
        let client = make_mock_client(npm(NPM_JSON), osv_batch_json, osv_vuln_json);
        let check = is_vulnerable_impl(client, Ecosystem::Npm, "leftpad@1.1.0").unwrap();
        assert_eq!(check.ecosystem, "npm");
        assert_eq!(check.package, "leftpad");
        assert_eq!(check.version, "1.1.0");
        assert!(check.vulnerable);
        assert_eq!(check.vulnerabilities[0].id, "GHSA-npm-1");
    }

    #[test]
    fn test_is_vulnerable_npm_rejects_range_and_bare_name() {
        let osv_batch_json = r#"{"results":[{"vulns":null},{"vulns":null}]}"#;
        let client = make_mock_client(npm(NPM_JSON), osv_batch_json, "{}");
        let e = is_vulnerable_impl(client.clone(), Ecosystem::Npm, "leftpad@^1.0.0").unwrap_err();
        assert!(e.contains("Exact version required"), "{e}");
        let e = is_vulnerable_impl(client, Ecosystem::Npm, "leftpad").unwrap_err();
        assert!(e.contains("lodash@4.17.15"), "{e}");
    }

    #[test]
    fn test_most_recent_not_vulnerable_npm() {
        let osv_batch_json = r#"{"results":[{"vulns":null}]}"#;
        let client = make_mock_client(npm(NPM_JSON), osv_batch_json, "{}");
        let safe = most_recent_not_vulnerable_impl(client, Ecosystem::Npm, "leftpad").unwrap();
        assert_eq!(safe.ecosystem, "npm");
        assert_eq!(safe.version, "2.0.0");
    }
}
