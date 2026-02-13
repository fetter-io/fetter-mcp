use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use fetter::{
    CacheConfig, CvssFilter, DepSpec, FlagCacheRefresh, FlagLog, FlagRetainPassing, LookupReport,
    Tableable, UreqClientLive, path_cache,
};
use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler,
    handler::server::tool::{ToolCallContext, ToolRouter},
    handler::server::wrapper::Parameters,
    model::*,
    schemars,
    service::RequestContext,
    tool, tool_router,
    transport::streamable_http_server::{
        StreamableHttpService, session::local::LocalSessionManager,
    },
};
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// -----------------------------------------------------------------------------
// Tool Arguments

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct MostRecentNotVulnerableArgs {
    /// The package name to look up (e.g., "requests", "numpy", "flask").
    pub name: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LookupNameArgs {
    /// The package name to look up (e.g., "requests", "numpy>=2.0", "flask==3.0.0"). Note that when an exact "==" version is specified, the `limit` and `retain_passing` parameters have no effect.
    pub name: String,
    /// When the name is not an exact version, limit the number of recent versions to check.
    pub limit: Option<usize>,
    /// CVSS score filter: "all" to show all vulnerabilities, "max" to show only the
    /// maximum observed score, or a number (0.0-10.0) to filter by threshold
    pub cvss_filter: Option<String>,
    /// 'When the name is not an exact version, setting this to True will return refernces for all packages, include those with no vulnerabilities (default: false)
    pub retain_passing: Option<bool>,
}

// -----------------------------------------------------------------------------
// Summary types for clean MCP output

#[derive(Clone, Serialize)]
struct VulnSummary {
    id: String,
    summary: String,
    cvss_score: Option<f64>,
    severity: Option<String>,
    url: String,
}

#[derive(Serialize)]
struct VersionSummary {
    version: String,
    vulnerable: bool,
    vulnerabilities: Vec<VulnSummary>,
}

#[derive(Serialize)]
struct LookupSummary {
    package: String,
    versions: Vec<VersionSummary>,
}

fn summarize(lr: &LookupReport) -> LookupSummary {
    let records = lr.get_records();

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

// -----------------------------------------------------------------------------
// MCP Server

#[derive(Clone)]
pub struct FetterMcpServer {
    tool_router: ToolRouter<Self>,
}

impl Default for FetterMcpServer {
    fn default() -> Self {
        Self::new()
    }
}

#[tool_router]
impl FetterMcpServer {
    pub fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    /// Look up a package by name and return basic information
    #[tool(
        description = "Look up a package by name and (optionally) version number to find which versions are available and/or have vulnerabilities."
    )]
    async fn lookup_name(
        &self,
        Parameters(args): Parameters<LookupNameArgs>,
    ) -> Result<CallToolResult, McpError> {
        // TODO: this string should be sanatized
        let name = args.name.trim().to_string();

        let limit = args.limit.or(None);
        let retain_passing = args.retain_passing.unwrap_or(false);

        let cvss_filter = match args.cvss_filter.as_deref() {
            Some("max") => CvssFilter::MaxOnly,
            Some(s) => match s.parse::<f64>() {
                Ok(v) if (0.0..=10.0).contains(&v) => CvssFilter::Threshold(v),
                _ => CvssFilter::All,
            },
            None => CvssFilter::All,
        };

        if name.is_empty() {
            return Ok(CallToolResult::error(vec![Content::text(
                "Package name cannot be empty",
            )]));
        }

        let result = tokio::task::spawn_blocking(move || -> Result<serde_json::Value, String> {
            let client = Arc::new(UreqClientLive);
            let ds = DepSpec::from_string(&name).map_err(|e| e.to_string())?;
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

            let summary = summarize(&lr);
            serde_json::to_value(&summary).map_err(|e| e.to_string())
        })
        .await;

        match result {
            Ok(Ok(value)) => Ok(CallToolResult {
                content: vec![],
                structured_content: Some(value),
                is_error: Some(false),
                meta: None,
            }),
            Ok(Err(e)) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Lookup failed: {e}"
            ))])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Task failed: {e}"
            ))])),
        }
    }

    /// Find the most recent version of a package that has no known vulnerabilities
    #[tool(
        description = "Find the most recent version of a package that has no known vulnerabilities."
    )]
    async fn most_recent_not_vulnerable(
        &self,
        Parameters(args): Parameters<MostRecentNotVulnerableArgs>,
    ) -> Result<CallToolResult, McpError> {
        let name = args.name.trim().to_string();

        if name.is_empty() {
            return Ok(CallToolResult::error(vec![Content::text(
                "Package name cannot be empty",
            )]));
        }

        let result = tokio::task::spawn_blocking(move || -> Result<serde_json::Value, String> {
            let client = Arc::new(UreqClientLive);
            let ds = DepSpec::from_string(&name).map_err(|e| e.to_string())?;
            if ds.get_exact().is_some() {
                return Err("Provide only a package name, not specific version.".to_string());
            }
            let cache_dir = path_cache(true).unwrap_or_else(std::env::temp_dir);
            let cache_config = CacheConfig::new(Duration::from_secs(3600), cache_dir);

            let lr = LookupReport::from_dep_spec(
                client,
                &ds,
                Some(1),
                &cache_config,
                FlagCacheRefresh(false),
                FlagLog(false),
                CvssFilter::All,
                FlagRetainPassing(true),
            )
            .map_err(|e| e.to_string())?;

            let summary = summarize(&lr);

            // Find the first version that is not vulnerable
            let safe_version = summary.versions.iter().find(|v| !v.vulnerable);

            match safe_version {
                Some(v) => serde_json::to_value(&serde_json::json!({
                    "package": summary.package,
                    "version": v.version,
                    "vulnerable": false,
                }))
                .map_err(|e| e.to_string()),
                None => Err(format!(
                    "No recent version of '{}' found without vulnerabilities",
                    summary.package
                )),
            }
        })
        .await;

        match result {
            Ok(Ok(value)) => Ok(CallToolResult {
                content: vec![],
                structured_content: Some(value),
                is_error: Some(false),
                meta: None,
            }),
            Ok(Err(e)) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Lookup failed: {e}"
            ))])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Task failed: {e}"
            ))])),
        }
    }
}

impl ServerHandler for FetterMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::LATEST,
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: Implementation::from_build_env(),
            instructions: Some("Fetter MCP Server".to_string()),
        }
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult {
            tools: self.tool_router.list_all(),
            next_cursor: None,
            meta: None,
        })
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        self.tool_router
            .call(ToolCallContext::new(self, request, context))
            .await
    }
}

// -----------------------------------------------------------------------------
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,fetter_mcp=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting Fetter MCP Server");

    let service = StreamableHttpService::new(
        || Ok(FetterMcpServer::new()),
        LocalSessionManager::default().into(),
        Default::default(),
    );

    let router = axum::Router::new().nest_service("/mcp", service);

    let addr = SocketAddr::from(([0, 0, 0, 0], 4000));
    let listener = tokio::net::TcpListener::bind(addr).await?;

    axum::serve(listener, router)
        .with_graceful_shutdown(async {
            tokio::signal::ctrl_c()
                .await
                .expect("Failed to listen for ctrl-c");
            tracing::info!("Shutting down...");
        })
        .await?;

    Ok(())
}
