# Fetter MCP

Fetter provides a remote [Model Context Protocol](https://modelcontextprotocol.io) (MCP) server at `https://mcp.fetter.io/mcp` that gives AI coding agents real-time access to Python package vulnerability data. Built on [fetter](https://github.com/fetter-io/fetter-rs), it queries PyPI and OSV to surface known CVEs, CVSS scores, and safe versions so your agent can make informed dependency decisions as it writes code.

**Tools:**
- `most_recent_not_vulnerable`: find the latest release of a package that is free of known vulnerabilities
- `is_vulnerable`: check whether a specific pinned version has known CVEs
- `lookup`: find available versions and their vulnerabilities for any package or specifier


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

**Example prompts:**
- "Add the latest safe version of requests to requirements.txt"
- "Are there any known vulnerabilities in my current dependencies?"
- "What is the most recent version of pillow with no CVEs?"
- "Before pinning cryptography, check whether 42.0.5 is vulnerable"

The agent selects the appropriate tool based on context:
- Adding a new package: `most_recent_not_vulnerable` to find a safe version
- Validating a specific pinned version: `is_vulnerable` for a definitive answer
- Auditing an existing specifier: `lookup` to see affected versions


## `most_recent_not_vulnerable`

Find the most recent version of a package that has no known vulnerabilities. Provide only a package name and the server will search recent releases for a safe version. Useful when pinning a dependency to the latest clean release.

**Parameters:**
- `package_name` — package name only (no version specifier), e.g. `"requests"`

```python
# Before adding a new dependency, find a safe version to pin
most_recent_not_vulnerable(package_name="pillow")

# Use the result to write a pinned requirement
most_recent_not_vulnerable(package_name="cryptography")
```


## `is_vulnerable`

Check if a specific package version has known vulnerabilities. Requires an exact version specifier. Returns vulnerability IDs, summaries, CVSS scores, severity ratings, and reference URLs.

**Parameters:**
- `dep_spec` — exact version specifier, e.g. `"requests==2.31.0"`

```python
# Check a specific version of requests
is_vulnerable(dep_spec="requests==2.31.0")

# Verify a pinned version before adding it to requirements.txt
is_vulnerable(dep_spec="numpy==1.24.0")
```


## `lookup`

Look up a package by name and optional version specifier to find which versions are available and whether they have known vulnerabilities. Supports specifiers such as `"requests"`, `"numpy>=2.0"`, or `"flask==3.0.0"`.

**Parameters:**
- `dep_specs` — package name or version specifier
- `cvss_threshold` — filter to vulnerabilities at or above this CVSS score (0–10)
- `max_observed_score` — return only the highest CVSS score per version rather than all individual vulnerabilities
- `count` — limit the number of recent versions checked
- `retain_passing` — include versions with no known vulnerabilities in the results

```python
# Check recent versions of requests for any vulnerabilities
lookup(dep_specs="requests")

# Check numpy 2.x versions, show only CVSS scores >= 7.0
lookup(dep_specs="numpy>=2.0", cvss_threshold=7.0)

# Get all versions of flask 3.0.0, including passing ones
lookup(dep_specs="flask==3.0.0", retain_passing=True)

# Check only the 5 most recent releases
lookup(dep_specs="pillow", count=5)
```
