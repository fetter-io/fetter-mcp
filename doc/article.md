

# Help You (or your Agent) Get the Right Python Version

# Give Yor Agents Tools to Avoid Old or Vulnerable Python Packages

Humans and agents can make the same mistakes: installing old or vulnerable versions of Python packages. 

Coding agents in particular can make surprising
choices, choosing versions representative of their training data regardless of age or vulnerabilities. Even if an agent picks a recent version it is unlikely to check for vulnerabilities. 

For agents, the Fetter MCP remote server provides tools to get the most recent version of a package without vulnerabilities. Additional tools permit checking which versions have vulnerabilities. 

For humans, the Fetter IO web application offers a Lookup interface to easily display all versions of a package, as well as any vulnerabilities associated with those packages. 

Both tools are buit in Ruse with fetter-rs core library, delivering excellent performance.


## Fetter MCP

```bash
claude mcp add --transport http fetter https://mcp.fetter.io/mcp
```

```bash
codex mcp add fetter --url https://mcp.fetter.io/mcp
```

## Fetter IO Lookup



## Conclusion









