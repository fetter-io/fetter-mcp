#!/usr/bin/env python3
"""Minimal test client for the Fetter MCP server (Streamable HTTP transport)."""

import argparse
import json
import sys
import urllib.request

# BASE_URL = "http://localhost:8080/mcp"
BASE_URL = "https://mcp.fetter.io/mcp"

SESSION_ID = None
REQ_ID = 0


def next_id():
    global REQ_ID
    REQ_ID += 1
    return REQ_ID


def send(method, params=None, is_notification=False):
    """Send a JSON-RPC request and print the response."""
    global SESSION_ID
    body = {"jsonrpc": "2.0", "method": method}
    if not is_notification:
        body["id"] = next_id()
    if params:
        body["params"] = params

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if SESSION_ID:
        headers["Mcp-Session-Id"] = SESSION_ID

    data = json.dumps(body).encode()
    print(json.dumps(body, indent=2))

    req = urllib.request.Request(BASE_URL, data=data, headers=headers)

    try:
        with urllib.request.urlopen(req) as resp:
            # Check all header variations for session ID
            for key in ("Mcp-Session-Id", "mcp-session-id"):
                if sid := resp.headers.get(key):
                    SESSION_ID = sid
                    break

            content_type = resp.headers.get("Content-Type", "")
            raw = resp.read().decode()

            if not raw.strip():
                return

            if "text/event-stream" in content_type:
                for line in raw.splitlines():
                    line = line.strip()
                    if line.startswith("data:"):
                        text = line[5:].strip()
                        if text:
                            payload = json.loads(text)
                            print(json.dumps(payload, indent=2))
            else:
                payload = json.loads(raw)
                print(json.dumps(payload, indent=2))
    except urllib.error.HTTPError as e:
        body = e.read().decode() if e.fp else ""
        print(f"Error: {e.code} {e.reason} {body}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    print()


def init_session():
    """Initialize the MCP session and send the initialized notification."""
    send("initialize", {
        "protocolVersion": "2025-03-26",
        "capabilities": {},
        "clientInfo": {"name": "test-client", "version": "0.1.0"},
    })
    send("notifications/initialized", is_notification=True)


def call_tool(name, arguments):
    """Initialize session, list tools, and call the named tool."""
    init_session()
    # send("tools/list")
    send("tools/call", {"name": name, "arguments": arguments})


def cmd_lookup_name(args):
    arguments = {"name": args.name}
    if args.limit is not None:
        arguments["limit"] = args.limit
    if args.cvss_filter is not None:
        arguments["cvss_filter"] = args.cvss_filter
    if args.retain_passing:
        arguments["retain_passing"] = True
    call_tool("lookup", arguments)


def cmd_most_recent_not_vulnerable(args):
    call_tool("most_recent_not_vulnerable", {"name": args.name})


def cmd_is_vulnerable(args):
    call_tool("is_vulnerable", {"name": args.name})


def main():
    parser = argparse.ArgumentParser(description="Test client for the Fetter MCP server")
    sub = parser.add_subparsers(dest="command", required=True)

    # lookup
    p_lookup = sub.add_parser("lookup", help="Look up a package by name")
    p_lookup.add_argument("name", help="Package spec (e.g. 'requests', 'numpy>=2.0')")
    p_lookup.add_argument("--limit", type=int, default=None, help="Max versions to check")
    p_lookup.add_argument("--cvss_filter", default=None,
                          help="'all', 'max', or a threshold 0.0-10.0")
    p_lookup.add_argument("--retain_passing", action="store_true",
                          help="Include packages with no vulnerabilities")
    p_lookup.set_defaults(func=cmd_lookup_name)

    # most_recent_not_vulnerable
    p_safe = sub.add_parser("most_recent_not_vulnerable",
                            help="Find the most recent version without vulnerabilities")
    p_safe.add_argument("name", help="Package name (e.g. 'requests', 'numpy')")
    p_safe.set_defaults(func=cmd_most_recent_not_vulnerable)

    # is_vulnerable
    p_vuln = sub.add_parser("is_vulnerable",
                            help="Check if a specific version has vulnerabilities")
    p_vuln.add_argument("name", help="Exact package version (e.g. 'requests==2.31.0')")
    p_vuln.set_defaults(func=cmd_is_vulnerable)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
