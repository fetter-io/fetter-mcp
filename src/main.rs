mod summary;
mod tools;

use std::sync::Arc;

use axum::{extract::Request, middleware::Next, response::Response};
use fetter::{CvssFilter, UreqClientLive};
use rmcp::{
    ErrorData as McpError, ServerHandler,
    handler::server::tool::ToolRouter,
    handler::server::wrapper::Parameters,
    model::*,
    schemars, tool, tool_handler, tool_router,
    transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
    },
};
use serde::Serialize;
use std::net::SocketAddr;
use tools::{
    is_vulnerable_impl, list_ecosystems_impl, lookup_impl, most_recent_not_vulnerable_impl,
    parse_ecosystem,
};

use serde::{Deserialize, Deserializer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// -----------------------------------------------------------------------------
// Bounded string deserialization

const MAX_NAME_LEN: usize = 256;
const MAX_FILTER_LEN: usize = 32;
const MAX_ECOSYSTEM_LEN: usize = 32;

fn deserialize_name<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    if s.len() > MAX_NAME_LEN {
        return Err(serde::de::Error::custom(format!(
            "name exceeds {MAX_NAME_LEN} characters"
        )));
    }
    Ok(s)
}

fn deserialize_bounded_opt<'de, D>(
    deserializer: D,
    label: &str,
    max: usize,
) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt: Option<String> = Option::deserialize(deserializer)?;
    if let Some(ref s) = opt
        && s.len() > max
    {
        return Err(serde::de::Error::custom(format!(
            "{label} exceeds {max} characters"
        )));
    }
    Ok(opt)
}

fn deserialize_filter<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_opt(deserializer, "cvss_filter", MAX_FILTER_LEN)
}

fn deserialize_ecosystem<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_opt(deserializer, "ecosystem", MAX_ECOSYSTEM_LEN)
}

// -----------------------------------------------------------------------------
// Tool Arguments

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct MostRecentNotVulnerableArgs {
    /// The package name to look up. For Python, a name only (e.g., "requests"). For other ecosystems, a name (e.g., "lodash", "serde", "actions/checkout"), optionally with an "@requirement" range to search within.
    #[serde(deserialize_with = "deserialize_name")]
    pub name: String,
    /// The package ecosystem: "python" (default), "npm", "cargo", "gha", "vscode", "go", "ruby", "php", or "swift". Call `list_ecosystems` for name formats and examples.
    #[serde(default, deserialize_with = "deserialize_ecosystem")]
    pub ecosystem: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct IsVulnerableArgs {
    /// The exact package name and version. For Python, use "==" (e.g., "requests==2.31.0"). For other ecosystems, use "name@version" (e.g., "lodash@4.17.15", "time@=0.1.43", "tj-actions/changed-files@v35").
    #[serde(deserialize_with = "deserialize_name")]
    pub name: String,
    /// The package ecosystem: "python" (default), "npm", "cargo", "gha", "vscode", "go", "ruby", "php", or "swift". Call `list_ecosystems` for name formats and examples.
    #[serde(default, deserialize_with = "deserialize_ecosystem")]
    pub ecosystem: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LookupArgs {
    /// The package name with an optional requirement. For Python, a PEP 508 specifier (e.g., "requests", "numpy>=2.0", "flask==3.0.0"). For other ecosystems, "name" or "name@requirement" in the ecosystem's native syntax (e.g., "lodash@>=4.17.15 <4.17.22", "serde@^1.0", "actions/checkout"). Note that when an exact version is specified, the `limit` and `retain_passing` parameters have no effect.
    #[serde(deserialize_with = "deserialize_name")]
    pub name: String,
    /// The package ecosystem: "python" (default), "npm", "cargo", "gha", "vscode", "go", "ruby", "php", or "swift". Call `list_ecosystems` for name formats and examples.
    #[serde(default, deserialize_with = "deserialize_ecosystem")]
    pub ecosystem: Option<String>,
    /// When the name is not an exact version, limit the number of recent versions to check.
    pub limit: Option<usize>,
    /// CVSS score filter: "all" to show all vulnerabilities, "max" to show only the
    /// maximum observed score, or a number (0.0-10.0) to filter by threshold
    #[serde(default, deserialize_with = "deserialize_filter")]
    pub cvss_filter: Option<String>,
    /// When the name is not an exact version, setting this to true will return references for all versions, including those with no vulnerabilities (default: false)
    pub retain_passing: Option<bool>,
}

// -----------------------------------------------------------------------------
// Helpers

fn error_result(msg: impl Into<String>) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(msg)])
}

/// Run a blocking lookup on the blocking thread pool, returning its serialized value as structured content, or an error result.
async fn run_blocking<T, F>(f: F) -> CallToolResult
where
    T: Serialize,
    F: FnOnce() -> Result<T, String> + Send + 'static,
{
    let result = tokio::task::spawn_blocking(move || {
        f().and_then(|s| serde_json::to_value(&s).map_err(|e| e.to_string()))
    })
    .await;

    match result {
        Ok(Ok(value)) => CallToolResult::structured(value),
        Ok(Err(e)) => error_result(format!("Lookup failed: {e}")),
        Err(e) => error_result(format!("Task failed: {e}")),
    }
}

// -----------------------------------------------------------------------------
// MCP Server

const INSTRUCTIONS: &str = "Fetter MCP Server: package versions and known vulnerabilities (from OSV) for Python, npm, Cargo, GitHub Actions, VS Code extensions, Go, Ruby, PHP, and Swift. Every tool takes an optional `ecosystem` (default \"python\"); call `list_ecosystems` for the supported ecosystems and their name formats.";

#[derive(Clone)]
pub struct FetterMcpServer {
    tool_router: ToolRouter<Self>,
}

impl Default for FetterMcpServer {
    fn default() -> Self {
        Self::new()
    }
}

// tool_router scans for all tool methods and generates the Self::tool_router() constructor
#[tool_router]
impl FetterMcpServer {
    pub fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    #[tool(
        description = "List the package ecosystems this server supports, with the default ecosystem, each ecosystem's registry, its package name format, and example names."
    )]
    async fn list_ecosystems(&self) -> Result<CallToolResult, McpError> {
        Ok(match serde_json::to_value(list_ecosystems_impl()) {
            Ok(value) => CallToolResult::structured(value),
            Err(e) => error_result(format!("Serialization failed: {e}")),
        })
    }

    #[tool(
        description = "Look up a package by name and (optionally) version requirement to find which versions are available and/or have vulnerabilities. Supports multiple ecosystems via `ecosystem` (default: python)."
    )]
    async fn lookup(
        &self,
        Parameters(args): Parameters<LookupArgs>,
    ) -> Result<CallToolResult, McpError> {
        let eco = match parse_ecosystem(args.ecosystem.as_deref()) {
            Ok(e) => e,
            Err(e) => return Ok(error_result(e)),
        };
        let name = args.name.trim().to_string();
        let limit = args.limit;
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
            return Ok(error_result("Package name cannot be empty"));
        }

        Ok(run_blocking(move || {
            let client = Arc::new(UreqClientLive);
            lookup_impl(client, eco, &name, limit, cvss_filter, retain_passing)
        })
        .await)
    }

    #[tool(
        description = "Find the most recent version of a package that has no known vulnerabilities. Supports multiple ecosystems via `ecosystem` (default: python)."
    )]
    async fn most_recent_not_vulnerable(
        &self,
        Parameters(args): Parameters<MostRecentNotVulnerableArgs>,
    ) -> Result<CallToolResult, McpError> {
        let eco = match parse_ecosystem(args.ecosystem.as_deref()) {
            Ok(e) => e,
            Err(e) => return Ok(error_result(e)),
        };
        let name = args.name.trim().to_string();

        if name.is_empty() {
            return Ok(error_result("Package name cannot be empty"));
        }

        Ok(run_blocking(move || {
            let client = Arc::new(UreqClientLive);
            most_recent_not_vulnerable_impl(client, eco, &name)
        })
        .await)
    }

    #[tool(
        description = "Check if a specific package version has known vulnerabilities. Requires an exact version: 'requests==2.31.0' for Python (the default ecosystem), or 'name@version' for other ecosystems (e.g., 'lodash@4.17.15' with ecosystem 'npm')."
    )]
    async fn is_vulnerable(
        &self,
        Parameters(args): Parameters<IsVulnerableArgs>,
    ) -> Result<CallToolResult, McpError> {
        let eco = match parse_ecosystem(args.ecosystem.as_deref()) {
            Ok(e) => e,
            Err(e) => return Ok(error_result(e)),
        };
        let name = args.name.trim().to_string();

        if name.is_empty() {
            return Ok(error_result("Package name cannot be empty"));
        }

        Ok(run_blocking(move || {
            let client = Arc::new(UreqClientLive);
            is_vulnerable_impl(client, eco, &name)
        })
        .await)
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for FetterMcpServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION"),
            ))
            .with_instructions(INSTRUCTIONS)
    }
}

// -----------------------------------------------------------------------------
// HTTP configuration

/// Hosts accepted in the `Host` header when `MCP_ALLOWED_HOSTS` is not set: loopback (local development) and the public hostnames CloudFront forwards.
const DEFAULT_ALLOWED_HOSTS: [&str; 5] = [
    "localhost",
    "127.0.0.1",
    "::1",
    "mcp.fetter.io",
    "www.mcp.fetter.io",
];

/// Parse a comma-separated `MCP_ALLOWED_HOSTS` value; `None` (unset) gives the defaults, and `*` disables Host validation.
fn allowed_hosts(env: Option<&str>) -> Option<Vec<String>> {
    match env.map(str::trim) {
        None | Some("") => Some(
            DEFAULT_ALLOWED_HOSTS
                .iter()
                .map(|s| s.to_string())
                .collect(),
        ),
        Some("*") => None,
        Some(list) => Some(
            list.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect(),
        ),
    }
}

fn http_config() -> StreamableHttpServerConfig {
    let config = StreamableHttpServerConfig::default();
    match allowed_hosts(std::env::var("MCP_ALLOWED_HOSTS").ok().as_deref()) {
        Some(hosts) => {
            tracing::info!("Allowed hosts: {}", hosts.join(", "));
            config.with_allowed_hosts(hosts)
        }
        None => {
            tracing::warn!("Host header validation disabled (MCP_ALLOWED_HOSTS=*)");
            config.disable_allowed_hosts()
        }
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

    let tenant_secret = std::env::var("TENANT_SECRET").ok();
    if tenant_secret.is_some() {
        tracing::info!("Starting Fetter MCP Server (origin validation enabled)");
    } else {
        tracing::warn!(
            "Starting Fetter MCP Server (TENANT_SECRET not set, origin validation disabled)"
        );
    }

    let service = StreamableHttpService::new(
        || Ok(FetterMcpServer::new()),
        LocalSessionManager::default().into(),
        http_config(),
    );

    let router =
        axum::Router::new()
            .nest_service("/mcp", service)
            .layer(axum::middleware::from_fn(
                move |req: Request, next: Next| {
                    let secret = tenant_secret.clone();
                    async move {
                        if let Some(ref expected) = secret {
                            let header = req
                                .headers()
                                .get("X-Fetter-MCP-Internal")
                                .and_then(|v| v.to_str().ok());
                            if header != Some(expected) {
                                return Ok(Response::builder()
                                    .status(403)
                                    .body(axum::body::Body::from("Forbidden"))
                                    .unwrap());
                            }
                        }
                        Ok::<_, std::convert::Infallible>(next.run(req).await)
                    }
                },
            ));

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
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

#[cfg(test)]
mod tests;
