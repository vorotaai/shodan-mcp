# Shodan MCP Server -- AI-Powered Internet Intelligence for Claude, Cursor & VS Code

**shodan-mcp** is a [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server that gives AI agents like Claude, Cursor, and GitHub Copilot direct access to [Shodan](https://www.shodan.io/) -- the world's search engine for internet-connected devices. Built by [Vorota AI](https://github.com/vorotaai).

20 tools for passive reconnaissance, vulnerability intelligence, DNS analysis, and device search -- all from your IDE. No packets sent to any target.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue)](https://github.com/vorotaai/shodan-mcp/blob/main/LICENSE)
[![Python versions](https://img.shields.io/badge/python-3.10%2B-blue)](https://github.com/vorotaai/shodan-mcp)
[![MCP Protocol](https://img.shields.io/badge/MCP-Compatible-blue)](https://modelcontextprotocol.io/)
[![Status](https://img.shields.io/badge/Status-Beta-orange)](https://github.com/vorotaai/shodan-mcp)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white)](https://github.com/vorotaai/shodan-mcp#installation)

---

## Quick Start

```bash
docker build -t shodan-mcp https://github.com/vorotaai/shodan-mcp.git
```

Add to your MCP client (Claude Desktop, Cursor, VS Code, etc.):

```json
{
  "mcpServers": {
    "shodan-mcp": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "-e", "SHODAN_API_KEY", "shodan-mcp"],
      "env": {
        "SHODAN_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

4 tools work **immediately with no API key** -- CVE lookup, CVE search, CPE search, and InternetDB. Get a Shodan API key at [account.shodan.io](https://account.shodan.io) to unlock all 20 tools.

---

## Available Tools

### Free Tools (No API Key Required)

| Tool | Description |
|------|-------------|
| `shodan-cve-lookup` | Look up any CVE -- CVSS v3 scores, EPSS exploit prediction, references, affected CPEs |
| `shodan-search-cves` | Search CVEs with filters -- CISA KEV catalog, EPSS sorting, date ranges |
| `shodan-search-cpes` | Search CPE identifiers by product name (e.g., "apache", "nginx") |
| `shodan-internetdb-lookup` | Fast free IP intelligence -- open ports, vulns, hostnames, CPEs, tags |

### Reconnaissance Tools (API Key Required)

| Tool | Description |
|------|-------------|
| `shodan-ip-lookup` | Full IP reconnaissance -- ports, services, banners, geolocation, vulns, ISP/org, ASN |
| `shodan-search` | Search Shodan's database of billions of devices with powerful query syntax |
| `shodan-search-count` | Count search results without consuming query credits |
| `shodan-dns-resolve` | Resolve hostnames to IP addresses |
| `shodan-dns-reverse` | Reverse DNS lookup for IP addresses |
| `shodan-domain-info` | Domain reconnaissance -- subdomains, DNS records, tags |
| `shodan-honeypot-score` | Detect if an IP is a honeypot (0.0 = real, 1.0 = honeypot) |

### Utility Tools (API Key Required)

| Tool | Description |
|------|-------------|
| `shodan-api-info` | Check API key usage -- plan type, remaining credits |
| `shodan-my-ip` | Get your external IP address as seen by Shodan |
| `shodan-account-profile` | Account membership, credits, display name |
| `shodan-list-facets` | List available search facets for query breakdowns |
| `shodan-list-filters` | List available search filters |
| `shodan-parse-query` | Analyze and debug search queries |
| `shodan-list-ports` | List port numbers Shodan crawlers scan |
| `shodan-list-protocols` | List protocols for on-demand scanning |
| `shodan-http-headers` | Show HTTP headers your client sends |

---

## Features

- **20 tools** covering IP recon, device search, CVE/CPE intelligence, DNS, domain analysis, and honeypot detection
- **4 free tools** that work with zero configuration -- no API key, no signup
- **Passive reconnaissance** -- all queries hit Shodan's pre-indexed database, no packets touch any target
- **Structured Pydantic output** -- every tool returns typed models, not raw JSON
- **Input validation** -- IP addresses, domains, CVE IDs, and queries are validated before any API call
- **API key protection** -- keys are never exposed in error messages or logs
- **Docker-first** -- single command to build and run
- **Works with all MCP clients** -- Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, Cline

---

## Example Prompts

Once connected, use natural language in your AI client:

- "What's my external IP address?"
- "What are the details of CVE-2021-44228?"
- "Search for CVEs related to Apache HTTP Server sorted by EPSS score"
- "Look up CPE identifiers for nginx"
- "Do a quick InternetDB lookup on my server's IP"
- "What DNS records exist for my company's domain?"
- "Resolve the hostname myapp.example.com to an IP address"
- "What search filters are available in Shodan?"
- "Check my Shodan API plan and remaining query credits"

---

## Installation

### Docker (recommended)

```bash
docker build -t shodan-mcp https://github.com/vorotaai/shodan-mcp.git
```

### Using uv

```bash
git clone https://github.com/vorotaai/shodan-mcp.git
cd shodan-mcp
uv sync --all-groups
shodan-mcp
```

### Using pip

```bash
git clone https://github.com/vorotaai/shodan-mcp.git
cd shodan-mcp
pip install .
shodan-mcp
```

---

## Usage with MCP Clients

shodan-mcp works with all major MCP clients: **Claude Desktop**, **Claude Code**, **Cursor**, **VS Code Copilot**, **Windsurf**, and **Cline**.

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "shodan-mcp": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "-e", "SHODAN_API_KEY", "shodan-mcp"],
      "env": {
        "SHODAN_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

### Claude Code

```bash
claude mcp add shodan-mcp -e SHODAN_API_KEY=your-api-key-here -- docker run --rm -i -e SHODAN_API_KEY shodan-mcp
```

### Cursor

Add to `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "shodan-mcp": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "-e", "SHODAN_API_KEY", "shodan-mcp"],
      "env": {
        "SHODAN_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

### VS Code / VS Code Insiders

Add to `.vscode/mcp.json`:

```json
{
  "servers": {
    "shodan-mcp": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "-e", "SHODAN_API_KEY", "shodan-mcp"],
      "env": {
        "SHODAN_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

### Windsurf / Cline

Use the same configuration as Claude Desktop. Refer to your client's documentation for the config file location.

---

## Recommended Workflow

1. **Free quick scan** -- Use `shodan-internetdb-lookup` for instant IP intelligence (no key needed)
2. **Vulnerability research** -- Use `shodan-cve-lookup` and `shodan-search-cves` to research CVEs (free)
3. **Deep reconnaissance** -- Use `shodan-ip-lookup` for full host details (API key)
4. **Discover exposed hosts** -- Use `shodan-search` and `shodan-search-count` to find and quantify targets
5. **DNS intelligence** -- Use `shodan-dns-resolve`, `shodan-dns-reverse`, and `shodan-domain-info`
6. **Filter honeypots** -- Use `shodan-honeypot-score` to identify deceptive hosts

---

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SHODAN_API_KEY` | (none) | Shodan API key. Required for 16 tools, not needed for 4 free tools. Get one at [account.shodan.io](https://account.shodan.io). |
| `FASTMCP_LOG_LEVEL` | `WARNING` | Logging level (DEBUG, INFO, WARNING, ERROR) |

---

## Security

**Authorization is required.** While Shodan queries are passive, you must still ensure:

- You have explicit authorization to investigate any target
- You comply with all applicable laws and organizational policies
- You use this tool only for legitimate security research, authorized assessments, or defensive operations

### Safety Measures

- **Input validation** -- IPs, domains, CVE IDs, hostnames, and queries are validated before any API call
- **Injection prevention** -- Forbidden characters (`;`, `|`, `&`, `$`, `` ` ``, etc.) are blocked
- **No shell execution** -- All HTTP requests use `httpx` with structured parameters
- **API key protection** -- Keys are passed via environment variables and stripped from error messages
- **Passive by design** -- No packets are sent to any target

---

## FAQ

### Do I need a Shodan API key?

Not to get started. 4 tools work immediately with no key: `shodan-cve-lookup`, `shodan-search-cves`, `shodan-search-cpes`, and `shodan-internetdb-lookup`. A free Shodan API key unlocks the remaining 16 tools -- get one at [account.shodan.io](https://account.shodan.io).

### What MCP clients are supported?

Claude Desktop, Claude Code, Cursor, VS Code (GitHub Copilot), Windsurf, and Cline -- any client supporting MCP stdio transport.

### Is it safe?

Yes. All queries are passive (no packets to targets), inputs are validated, and API keys are never exposed in error messages.

### How is this different from the Shodan website?

shodan-mcp integrates Shodan directly into your AI workflow. Your AI agent queries Shodan, interprets results, correlates findings, and makes recommendations -- all in a single conversation from your IDE.

---

## Contributing

```bash
git clone https://github.com/vorotaai/shodan-mcp.git
cd shodan-mcp
uv sync --all-groups
uv run pytest
```

Please open an issue or pull request on [GitHub](https://github.com/vorotaai/shodan-mcp).

---

## License

[Apache License 2.0](https://github.com/vorotaai/shodan-mcp/blob/main/LICENSE) -- Copyright (c) Vorota AI
