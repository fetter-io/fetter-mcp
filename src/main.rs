use std::sync::Arc;
use std::time::Duration;

use fetter::{
    CacheConfig, CvssFilter, DepSpec, FlagCacheRefresh, FlagLog, FlagRetainPassing, LookupReport,
    UreqClientLive, path_cache,
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

use serde::Deserialize;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// -----------------------------------------------------------------------------
// Tool Arguments

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LookupNameArgs {
    /// The package name to look up (e.g., "requests", "numpy>=2.0", "flask==3.0.0")
    pub name: String,
    /// Maximum number of versions to check (default: 5)
    pub limit: Option<usize>,
    /// CVSS score filter: "all" to show all vulnerabilities, "max" to show only the
    /// maximum observed score, or a number (0.0-10.0) to filter by threshold
    pub cvss_filter: Option<String>,
    /// Whether to include packages with no vulnerabilities in results (default: false)
    pub retain_passing: Option<bool>,
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
    #[tool(description = "Look up a package by name to get basic information about it")]
    async fn lookup_name(
        &self,
        Parameters(args): Parameters<LookupNameArgs>,
    ) -> Result<CallToolResult, McpError> {
        let name = args.name.trim().to_string();
        let limit = args.limit.or(Some(5));
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

        let result = tokio::task::spawn_blocking(move || -> Result<String, String> {
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

            serde_json::to_string(&lr).map_err(|e| e.to_string())
        })
        .await;

        match result {
            Ok(Ok(json)) => Ok(CallToolResult::success(vec![Content::text(json)])),
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
