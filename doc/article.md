

# Help You (or your Agent) Get the Right Python Version

# Help You (or your Agent) Get the Right Python Version




```bash
claude mcp add --transport http fetter https://mcp.fetter.io/mcp
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


Terraform
    EC2 with protection
        CloudFront: HTTPS, caching?
        WAF: rate limiting
    Need  Mcp-Session-Id header pass through
    Avoid skipping CloudFront with private header: X-Fetter-MCP-Internal
