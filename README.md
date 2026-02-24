# Fetter MCP

A Model Context Protocol (MCP) server that gives AI coding agents real-time access to Python package vulnerability data. Built on [fetter](https://github.com/fetter-io/fetter-rs), it queries PyPI and OSV to surface known CVEs, CVSS scores, and safe versions — so your agent can make informed dependency decisions as it writes code.

## Features

### `most_recent_not_vulnerable`
Find the most recent version of a package that has no known vulnerabilities. Provide only a package name (e.g., `"requests"`), and the server will search recent releases for a safe version.

### `is_vulnerable`
Check if a specific package version has known vulnerabilities. Requires an exact version specifier (e.g., `"requests==2.31.0"`).

- Returns vulnerability IDs, summaries, CVSS scores, severity ratings, and reference URLs


### `lookup`
Look up a package by name and (optionally) version specifier to find which versions are available and whether they have known vulnerabilities.

- Supports version specifiers: `"requests"`, `"numpy>=2.0"`, `"flask==3.0.0"`
- Filter results by CVSS score threshold, or show only the maximum observed score
- Limit the number of recent versions checked
- Optionally retain results for versions with no vulnerabilities



## Installation

### Claude Code

```bash
claude mcp add --transport http fetter https://mcp.fetter.io/mcp
```

### Codex

```bash
codex mcp add fetter --url https://mcp.fetter.io/mcp
```
