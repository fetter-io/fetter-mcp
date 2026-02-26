#!/usr/bin/env python3
"""Check the deployed version of the Fetter MCP server."""

import json
import sys
import urllib.request

DEFAULT_URL = "https://mcp.fetter.io/mcp"


def get_version(base_url=DEFAULT_URL):
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "version-check", "version": "0.1.0"},
        },
    }
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    req = urllib.request.Request(
        base_url, data=json.dumps(body).encode(), headers=headers
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        content_type = resp.headers.get("Content-Type", "")
        raw = resp.read().decode()

        if "text/event-stream" in content_type:
            for line in raw.splitlines():
                line = line.strip()
                if line.startswith("data:"):
                    text = line[5:].strip()
                    if text:
                        return json.loads(text)
        else:
            return json.loads(raw)


# python3 /Users/ariza/_x/src/fetter-mcp/test_mcp_version.py http://localhost:8080/mcp

def main():
    url = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_URL
    try:
        result = get_version(url)
    except urllib.error.HTTPError as e:
        print(f"HTTP {e.code}: {e.reason}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"Connection failed: {e.reason}", file=sys.stderr)
        sys.exit(1)

    info = result.get("result", {}).get("serverInfo", {})
    name = info.get("name", "unknown")
    version = info.get("version", "unknown")
    protocol = result.get("result", {}).get("protocolVersion", "unknown")

    print(f"{name} v{version} (protocol {protocol})")
    print(f"  url: {url}")


if __name__ == "__main__":
    main()
