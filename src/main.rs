use std::future::Future;

use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler,
    handler::server::tool::{ToolCallContext, ToolRouter},
    handler::server::wrapper::Parameters,
    model::*,
    schemars, tool, tool_router,
    service::RequestContext,
    transport::streamable_http_server::{
        session::local::LocalSessionManager, StreamableHttpService,
    },
};
use serde::Deserialize;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

const BIND_ADDRESS: &str = "0.0.0.0:8000";

// ============================================================================
// Tool Arguments

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LookupNameArgs {
    /// The package name to look up (e.g., "requests", "numpy", "lodash")
    pub name: String,
}

// ============================================================================
// MCP Server

#[derive(Clone)]
pub struct FetterMcpServer {
    tool_router: ToolRouter<Self>,
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
        let name = args.name.trim();

        if name.is_empty() {
            return Ok(CallToolResult::error(vec![Content::text(
                "Package name cannot be empty",
            )]));
        }

        // TODO: Replace with actual fetter lookup logic
        // For now, return a stub response
        let response = serde_json::json!({
            "name": name,
            "found": true,
            "description": format!("Package '{}' lookup placeholder", name),
            "message": "This is a stub response. Implement actual fetter lookup here."
        });

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&response).unwrap_or_else(|_| response.to_string()),
        )]))
    }
}

impl ServerHandler for FetterMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::LATEST,
            capabilities: ServerCapabilities::builder()
                .enable_tools()
                .build(),
            server_info: Implementation::from_build_env(),
            instructions: Some(
                "Fetter MCP Server - Query package vulnerability information.\n\
                 Use the lookup_name tool to search for packages."
                    .to_string(),
            ),
        }
    }

    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListToolsResult, McpError>> + Send + '_ {
        async move {
            Ok(ListToolsResult {
                tools: self.tool_router.list_all(),
                next_cursor: None,
                meta: None,
            })
        }
    }

    fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<CallToolResult, McpError>> + Send + '_ {
        async move {
            self.tool_router
                .call(ToolCallContext::new(self, request, context))
                .await
        }
    }
}

// ============================================================================
// Main

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,fetter_mcp=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting Fetter MCP Server on {}", BIND_ADDRESS);

    let service = StreamableHttpService::new(
        || Ok(FetterMcpServer::new()),
        LocalSessionManager::default().into(),
        Default::default(),
    );

    let router = axum::Router::new().nest_service("/mcp", service);

    let listener = tokio::net::TcpListener::bind(BIND_ADDRESS).await?;
    tracing::info!("Server ready at http://{}/mcp", BIND_ADDRESS);

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

