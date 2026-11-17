# Fetter MCP

Fetter provides a remote [Model Context Protocol](https://modelcontextprotocol.io) (MCP) server at `https://mcp.fetter.io/mcp` that gives AI coding agents real-time access to package vulnerability data. Built on [fetter](https://github.com/fetter-io/fetter-rs), it queries package registries and [OSV](https://osv.dev) to surface known CVEs, CVSS scores, and safe versions so your agent can make informed dependency decisions as it writes code.

**Supported ecosystems:** Python (PyPI), npm, Cargo (crates.io), GitHub Actions, VS Code extensions (Open VSX), Go, Ruby (RubyGems), PHP (Packagist), and Swift. Python is the default.

**Tools:**
- `most_recent_not_vulnerable`: find the latest release of a package that is free of known vulnerabilities
- `is_vulnerable`: check whether a specific pinned version has known CVEs
- `lookup`: find available versions and their vulnerabilities for any package or requirement
- `list_ecosystems`: list the supported ecosystems, with each one's name format and examples


## Installation

The Fetter MCP server uses the HTTP transport and requires no local installation. Just register the remote URL with your MCP client.

### Claude Code

```bash
claude mcp add --transport http fetter https://mcp.fetter.io/mcp
```

### Codex

```bash
codex mcp add fetter --url https://mcp.fetter.io/mcp
```

### Other MCP Clients

For any other MCP-compatible client, provide the following remote server URL using the HTTP transport:

```
https://mcp.fetter.io/mcp
```


## Agent Usage

Once installed, the Fetter MCP tools are available to your AI agent during coding sessions. The agent can call them automatically when adding or auditing dependencies; no explicit tool invocation is required in your prompts.

**Example prompts**
- "Add the latest safe version of requests to requirements.txt"
- "Are there any known vulnerabilities in my current dependencies?"
- "What is the most recent version of lodash with no CVEs?"
- "Before pinning cryptography, check whether 42.0.5 is vulnerable"
- "Is `actions/download-artifact@v4.1.2` safe to use in this workflow?"

The agent selects the appropriate tool based on context:
- Adding a new package: `most_recent_not_vulnerable` to find a safe version
- Validating a specific pinned version: `is_vulnerable` for a definitive answer
- Auditing an existing specifier: `lookup` to see affected versions


## Ecosystems and Package Names

Every lookup tool takes an optional `ecosystem` parameter. When it is omitted, the ecosystem is `python`. Ecosystems can be named by their fetter name (`python`, `npm`, `cargo`, `gha`, `vscode`, `go`, `ruby`, `php`, `swift`) or by their OSV name (e.g. `PyPI`, `crates.io`, `RubyGems`), case-insensitively.

Python packages use [PEP 508](https://peps.python.org/pep-0508/) specifiers (`requests==2.31.0`, `numpy>=2.0`). Packages of other ecosystems use `name@requirement`, with the requirement in that ecosystem's native syntax:

| Ecosystem | Exact version | Requirement |
|---|---|---|
| `python` | `requests==2.31.0` | `requests>=2.30,<3` |
| `npm` | `lodash@4.17.15` | `lodash@>=4.17.15 <4.17.22` |
| `cargo` | `time@=0.1.43` | `serde@^1.0` |
| `gha` | `tj-actions/changed-files@v35` | `actions/download-artifact` (all tags) |
| `vscode` | `ms-python.python@2024.0.1` | `ms-python.python@>=2024.0.0` |
| `go` | `golang.org/x/net@v0.17.0` | `golang.org/x/net@>=v0.20.0 <v0.24.0` |
| `ruby` | `nokogiri@1.13.8` | `nokogiri@~> 1.16.0` |
| `php` | `guzzlehttp/guzzle@7.4.0` | `guzzlehttp/guzzle@~7.4.0` |
| `swift` | `github.com/sparkle-project/Sparkle@2.8.1` | `github.com/sparkle-project/Sparkle@>=2.6.0 <2.9.0` |

Every result includes the `ecosystem` it was looked up in. Each vulnerability carries its ID, summary, maximum CVSS score, severity (`Low`, `Medium`, `High`, `Critical`), and an OSV URL. Results are returned as `structuredContent`, with the same JSON also serialized as a text `content` block for clients that do not read structured content.


## `list_ecosystems`

List the supported ecosystems, the default ecosystem, and, for each, its registry, name format, and example names.

**Parameters:** none

**Example Response (abridged)**
```json
{
  "default": "python",
  "ecosystems": [
    {
      "name": "npm",
      "osv_name": "npm",
      "registry": "npm registry (registry.npmjs.org)",
      "name_format": "name@requirement with an npm semver range; scoped names allowed",
      "exact_example": "lodash@4.17.15",
      "range_example": "lodash@>=4.17.15 <4.17.22"
    }
  ]
}
```


## `most_recent_not_vulnerable`

Find the most recent version of a package that has no known vulnerabilities. Provide only a package name and the server will check the latest release. Useful when pinning a dependency to the latest clean release.

**Parameters**
- `name`: the package name, without a version (e.g. `"requests"`, `"lodash"`, `"actions/checkout"`). For ecosystems other than Python, an `@requirement` range may be given to search within.
- `ecosystem`: optional; defaults to `"python"`

**Example Request**
```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "id": 2,
  "params": {
    "name": "most_recent_not_vulnerable",
    "arguments": {
      "name": "lodash",
      "ecosystem": "npm"
    }
  }
}
```

**Example Response (`structuredContent`)**
```json
{
  "ecosystem": "npm",
  "package": "lodash",
  "version": "4.18.1",
  "vulnerabilities": [],
  "vulnerable": false
}
```


## `is_vulnerable`

Check if a specific package version has known vulnerabilities. Requires an exact version: `name==version` for Python, `name@version` for other ecosystems. (For Cargo, a bare version is treated as exact, so `time@0.1.43` and `time@=0.1.43` are equivalent here.)

**Parameters**
- `name`: the exact package version, e.g. `"requests==2.31.0"` or `"time@=0.1.43"`
- `ecosystem`: optional; defaults to `"python"`

**Example Request**
```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "id": 2,
  "params": {
    "name": "is_vulnerable",
    "arguments": {
      "name": "time@=0.1.43",
      "ecosystem": "cargo"
    }
  }
}
```

**Example Response (`structuredContent`)**
```json
{
  "ecosystem": "cargo",
  "package": "time",
  "version": "0.1.43",
  "vulnerabilities": [
    {
      "cvss_score": 6.2,
      "id": "GHSA-wcg3-cvx6-7396",
      "severity": "Medium",
      "summary": "Segmentation fault in time",
      "url": "https://osv.dev/vulnerability/GHSA-wcg3-cvx6-7396"
    },
    {
      "cvss_score": 6.2,
      "id": "RUSTSEC-2020-0071",
      "severity": "Medium",
      "summary": "Potential segfault in the time crate",
      "url": "https://osv.dev/vulnerability/RUSTSEC-2020-0071"
    }
  ],
  "vulnerable": true
}
```


## `lookup`

Look up a package by name and optional version requirement to find which versions are available and whether they have known vulnerabilities. Supports requirements such as `"requests"`, `"numpy>=2.0"`, `"lodash@>=4.17.15 <4.17.22"`, or `"actions/download-artifact"`.

**Parameters**
- `name`: the package name with an optional requirement
- `ecosystem`: optional; defaults to `"python"`
- `limit`: when the name is not an exact version, limit the number of recent versions checked
- `cvss_filter`: `"all"` (default) for all vulnerabilities, `"max"` for only the highest CVSS score per version, or a number (0–10) to keep only vulnerabilities at or above that score
- `retain_passing`: include versions with no known vulnerabilities in the results (default: false)

**Example Request**
```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "id": 2,
  "params": {
    "name": "lookup",
    "arguments": {
      "name": "actions/download-artifact@v4.1.2",
      "ecosystem": "gha"
    }
  }
}
```

**Example Response (`structuredContent`)**
```json
{
  "ecosystem": "gha",
  "package": "actions/download-artifact",
  "versions": [
    {
      "version": "v4.1.2",
      "vulnerabilities": [
        {
          "cvss_score": 8.6,
          "id": "GHSA-cxww-7g56-2vh6",
          "severity": "High",
          "summary": "@actions/download-artifact has an Arbitrary File Write via artifact extraction",
          "url": "https://osv.dev/vulnerability/GHSA-cxww-7g56-2vh6"
        }
      ],
      "vulnerable": true
    }
  ]
}
```

If some versions could not be checked against OSV, they are listed in an `unaudited` array; these are not known to be free of vulnerabilities.


## Self-Hosting

The server listens on port 8080 at `/mcp`. Environment variables:
- `TENANT_SECRET`: when set, requests must carry it in the `X-Fetter-MCP-Internal` header
- `MCP_ALLOWED_HOSTS`: comma-separated hostnames accepted in the `Host` header (DNS-rebinding protection); defaults to loopback and `mcp.fetter.io`. Use `*` to disable the check.
- `RUST_LOG`: log filter (default `info,fetter_mcp=debug`)

GitHub Actions and Swift lookups run `git ls-remote`, so `git` must be installed.
