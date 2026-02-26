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

**Example prompts**
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

**Parameters**
- `package_name` — package name only (no version specifier), e.g. `"requests"`


**Example Request**
```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "id": 2,
  "params": {
    "name": "most_recent_not_vulnerable",
    "arguments": {
      "name": "cryptography"
    }
  }
}
```

**Example Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "content": [],
    "structuredContent": {
      "package": "cryptography",
      "version": "46.0.5",
      "vulnerabilities": [],
      "vulnerable": false
    },
    "isError": false
  }
}
```


## `is_vulnerable`

Check if a specific package version has known vulnerabilities. Requires an exact version specifier. Returns vulnerability IDs, summaries, CVSS scores, severity ratings, and reference URLs.

**Parameters**
- `dep_spec` — exact version specifier, e.g. `"requests==2.31.0"`

**Example Request**
```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "id": 2,
  "params": {
    "name": "is_vulnerable",
    "arguments": {
      "name": "requests==2.19.1"
    }
  }
}
```

**Example Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "content": [],
    "structuredContent": {
      "package": "requests",
      "version": "2.19.1",
      "vulnerabilities": [
        {
          "cvss_score": 5.3,
          "id": "GHSA-9hjg-9r4m-mvj7",
          "severity": "(Medium):",
          "summary": "Requests vulnerable to .netrc credentials leak via malicious URLs",
          "url": "https://osv.dev/vulnerability/GHSA-9hjg-9r4m-mvj7"
        },
        {
          "cvss_score": 5.6,
          "id": "GHSA-9wx4-h78v-vm56",
          "severity": "(Medium):",
          "summary": "Requests Session object does not verify requests after making first request with verify=False",
          "url": "https://osv.dev/vulnerability/GHSA-9wx4-h78v-vm56"
        },
        {
          "cvss_score": 6.1,
          "id": "GHSA-j8r2-6x86-q33q",
          "severity": "(Medium):",
          "summary": "Unintended leak of Proxy-Authorization header in requests",
          "url": "https://osv.dev/vulnerability/GHSA-j8r2-6x86-q33q"
        },
        {
          "cvss_score": 7.5,
          "id": "GHSA-x84v-xcm2-53pg",
          "severity": "(High):",
          "summary": "Insufficiently Protected Credentials in Requests",
          "url": "https://osv.dev/vulnerability/GHSA-x84v-xcm2-53pg"
        },
        {
          "cvss_score": null,
          "id": "PYSEC-2018-28",
          "severity": null,
          "summary": "",
          "url": "https://osv.dev/vulnerability/PYSEC-2018-28"
        },
        {
          "cvss_score": null,
          "id": "PYSEC-2023-74",
          "severity": null,
          "summary": "",
          "url": "https://osv.dev/vulnerability/PYSEC-2023-74"
        }
      ],
      "vulnerable": true
    },
    "isError": false
  }
}
```


## `lookup`

Look up a package by name and optional version specifier to find which versions are available and whether they have known vulnerabilities. Supports specifiers such as `"requests"`, `"numpy>=2.0"`, or `"flask==3.0.0"`.

**Parameters**
- `dep_specs` — package name or version specifier
- `cvss_threshold` — filter to vulnerabilities at or above this CVSS score (0–10)
- `max_observed_score` — return only the highest CVSS score per version rather than all individual vulnerabilities
- `count` — limit the number of recent versions checked
- `retain_passing` — include versions with no known vulnerabilities in the results


**Example Request**
```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "id": 2,
  "params": {
    "name": "lookup",
    "arguments": {
      "name": "requests>=2.32.0",
      "retain_passing": true
    }
  }
}
```

**Example Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "content": [],
    "structuredContent": {
      "package": "requests",
      "versions": [
        {
          "version": "2.32.0",
          "vulnerabilities": [
            {
              "cvss_score": 5.3,
              "id": "GHSA-9hjg-9r4m-mvj7",
              "severity": "(Medium):",
              "summary": "Requests vulnerable to .netrc credentials leak via malicious URLs",
              "url": "https://osv.dev/vulnerability/GHSA-9hjg-9r4m-mvj7"
            }
          ],
          "vulnerable": true
        },
        {
          "version": "2.32.1",
          "vulnerabilities": [
            {
              "cvss_score": 5.3,
              "id": "GHSA-9hjg-9r4m-mvj7",
              "severity": "(Medium):",
              "summary": "Requests vulnerable to .netrc credentials leak via malicious URLs",
              "url": "https://osv.dev/vulnerability/GHSA-9hjg-9r4m-mvj7"
            }
          ],
          "vulnerable": true
        },
        {
          "version": "2.32.2",
          "vulnerabilities": [
            {
              "cvss_score": 5.3,
              "id": "GHSA-9hjg-9r4m-mvj7",
              "severity": "(Medium):",
              "summary": "Requests vulnerable to .netrc credentials leak via malicious URLs",
              "url": "https://osv.dev/vulnerability/GHSA-9hjg-9r4m-mvj7"
            }
          ],
          "vulnerable": true
        },
        {
          "version": "2.32.3",
          "vulnerabilities": [
            {
              "cvss_score": 5.3,
              "id": "GHSA-9hjg-9r4m-mvj7",
              "severity": "(Medium):",
              "summary": "Requests vulnerable to .netrc credentials leak via malicious URLs",
              "url": "https://osv.dev/vulnerability/GHSA-9hjg-9r4m-mvj7"
            }
          ],
          "vulnerable": true
        },
        {
          "version": "2.32.4",
          "vulnerabilities": [],
          "vulnerable": false
        },
        {
          "version": "2.32.5",
          "vulnerabilities": [],
          "vulnerable": false
        }
      ]
    },
    "isError": false
  }
}
```
