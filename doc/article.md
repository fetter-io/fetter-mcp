

```bash
claude mcp add --transport http notion https://mcp.fetter.io/mcp
```

```bash
codex mcp add fetter --url https://mcp.fetter.io/mcp
```



Implementation:

Lookup functionality in fetter
    fetter lookup-bound ~/src/invsys
    fetter lookup-name requests

Lookup functionality in Fetter IO

The Agent Problem

Rust MCP
    rmcp core: https://github.com/modelcontextprotocol/rust-sdk
        Axum web server

    decorated functions that take Parameters and return CallToolResult
        Parameters are generic, specialized
        Implicit registration with decorator

    Serve /mcp on port 8080