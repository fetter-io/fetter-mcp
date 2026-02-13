use std::collections::HashMap;

use fetter::{LookupReport, Tableable};
use serde::Serialize;

#[derive(Clone, Serialize)]
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
    pub package: String,
    pub versions: Vec<VersionSummary>,
}

pub fn summarize(lr: &LookupReport) -> LookupSummary {
    let records = lr.get_records();

    // We strongly assume that this report is only for one package; while this report can handle multiple packages, as used here it will only get requests for a single package
    let package = records
        .first()
        .map(|r| r.package.name.clone())
        .unwrap_or_default();

    // Deduplicate vuln details across records
    let mut vuln_cache: HashMap<String, VulnSummary> = HashMap::new();

    for record in records {
        for (vuln_id, info) in &record.vuln_infos {
            vuln_cache.entry(vuln_id.clone()).or_insert_with(|| {
                let (cvss_score, severity) = info
                    .cvss_details
                    .as_ref()
                    .and_then(|d| d.get_max_score().map(|s| (s, d.get_prime())))
                    .map(|(score, prime)| {
                        let sev = prime.split_whitespace().nth(2).unwrap_or("").to_string();
                        (Some(score), if sev.is_empty() { None } else { Some(sev) })
                    })
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

    LookupSummary { package, versions }
}

// Unit tests for summarize are not practical because:
// 1. fetter's AuditReport/AuditRecord don't implement Deserialize
// 2. UreqClientMock exists in fetter but is not publicly exported
// 3. The UreqClient trait is also not exported, so we can't create our own mock
// Testing summarize is done via integration tests through the MCP server.
