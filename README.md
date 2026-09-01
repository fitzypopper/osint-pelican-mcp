# Pelican — OSINT MCP Server

A **general-purpose open-source intelligence (OSINT) MCP server** for AI agents.
Local-first: run it on your own machine, connect any [Model Context
Protocol](https://modelcontextprotocol.io) client (OpenCode, Hermes, Claude,
Cursor, Cline, etc.), and give your agent one tool surface for broad public-data
lookups.

## 🦚 Why "Pelican"?

[Pelicans](https://en.wikipedia.org/wiki/Pelican) scan the shoreline for fish —
symbolising an OSINT server that scans public data sources for intelligence.
Short, distinctive, and animal-themed (like many MCP servers in this space).

## ⚡ Quick start

### Install

```bash
# Using uv (recommended)
uv venv && uv pip install -e ".[dev]"

# Or using pip
pip install pelican[dev]

# Or via uvx (one-shot)
uvx pelican-mcp
```

### Run the MCP server

```bash
# stdio (default — local AI agents)
pelican-mcp

# HTTP / streamable-http (remote agents)
pelican-mcp --transport http          # default port 8000
# or with bearer token auth:
OSINT_MCP_AUTH_TOKEN=$(openssl rand -hex 24) pelican-mcp --transport http
```

### Add to your MCP client config

**OpenCode** (`opencode.json`):

```json
{
  "mcpServers": {
    "pelican": {
      "type": "stdio",
      "command": ["uv", "run", "pelican-mcp"]
    }
  }
}
```

**Claude Code**:

```bash
claude mcp add pelican -- uv run pelican-mcp
```

### CLI (no MCP client needed)

```bash
pelican-mcp-cli whois_domain '{"domain": "example.com"}'
pelican-mcp-cli osint_domain_recon '{"domain": "example.com"}'
pelican-mcp-cli --list-tools
```

## 📦 What Pelican does

**32 MCP tools** across three coverage tiers:

| Tier | Tools (selected) |
|---|---|
| **Domain/Infra** | `dns_lookup`, `whois_domain`, `crtsh_search`, `geoip`, `bgp_asn`, `wayback_urls`, `email_security`, `hackertarget_hostsearch` |
| **Identity/Social** | `github_user_info`, `github_user_repos`, `reddit_user`, `keybase_lookup`, `username_enumerate`, `gravatar_lookup`, `email_permutations`, `domain_email_search` |
| **Threat/Breach** | `check_password_breach`, `shodan_internetdb`, `search_darkweb`, `cisa_kev_catalog`, `otx_search_pulses`, `osint_domain_recon`, `osint_ip_recon`, `osint_list_sources` |

**Aggregate tools:**
- `osint_list_sources` — shows all sources and which API keys are configured
- `osint_domain_recon` — all-in-one free domain recon (DNS + WHOIS + crt.sh + hosts + email security + geoip), correlated
- `osint_ip_recon` — all-in-one free IP recon (geoip + RDAP + BGP + Shodan InternetDB), correlated

## 🔑 API keys (all optional)

Most tools work with **zero config**. Add only the keys for sources you want to unlock:

| Variable | Unlocks | Cost |
|---|---|---|
| `HIBP_API_KEY` | breached-account lookups | ~$4.50/mo |
| `OTX_API_KEY` | OTX pulses + indicator enrichment | free |
| `SHODAN_API_KEY` | Shodan search/host tools | free tier |
| `GITHUB_TOKEN` | higher GitHub rate limit | free |

Copy `.env.example` to `.env` and add only the keys you need:

```bash
cp .env.example .env
# then edit .env with your keys
```

Keys are read into `SecretStr` and never logged.

## 🛠️ Architecture

```
pelican/
├── pelican/              pelican package (v2 compatibility shim: pelican -> osint_mcp_server)
│   ├── __init__.py       legacy import shim
│   ├── config.py         env/.env settings, source status
│   ├── net.py            shared async HTTP/DNS helpers, bounded concurrency
│   ├── server.py         FastMCP entry point, tool registration, transports
│   ├── cli.py            direct tool invocation (no MCP client)
│   └── tools/
│       ├── __init__.py
│       ├── domain.py     DNS, RDAP, crt.sh, geoip, BGP, wayback, email security
│       ├── social.py     GitHub, Reddit, Keybase, username, email, gravatar
│       ├── threat.py     HIBP, Ahmia, Shodan InternetDB, CISA KEV, OTX
│       └── suite.py      source listing + aggregate recon tools
└── tests/                unit tests (5 passing)
```

Every source is an independent module and every tool is **read-only** — nothing
here writes to any target. Tools are annotated with FastMCP
`readOnlyHint` / `idempotentHint` / `openWorldHint` so capable clients can
see at a glance that these are safe, repeatable, read-only operations.

## 💡 Credits & attribution

This project is a **from-scratch Python implementation** that borrows ideas,
tool-shapes, source-selection, and endpoint patterns from several excellent
MIT-licensed projects. Thanks to their authors:

| Project | What we borrowed | License |
|---|---|---|
| [badchars/osint-mcp-server](https://github.com/badchars/osint-mcp-server) | free no-key infra sources (DNS, RDAP, crt.sh, geoip, BGP, wayback, HackerTarget, email security), `osint_list_sources` and `osint_domain_recon` aggregate design | MIT |
| [CloudWaddie/osint-mcp](https://github.com/CloudWaddie/osint-mcp) | identity/social tool set & endpoint/field patterns (GitHub, Reddit, Keybase, username enumeration, email permutation, Gravatar, HIBP) | MIT |
| [frishtik/osint-tools-mcp-server](https://github.com/frishtik/osint-tools-mcp-server) | concept of wrapping OSINT tools, ethical-use framing | MIT |
| [pete-builds/mcp-threatintel](https://github.com/pete-builds/mcp-threatintel) | HIBP k-anonymity password check, Ahmia dark-web search, CISA KEV, explicit FastMCP read-only annotations | MIT |
| [Abraar02/threatwatch-mcp](https://github.com/Abraar02/threatwatch-mcp) / [Vorota-ai/shodan-mcp](https://github.com/vorotaai/shodan-mcp) | always-free Shodan InternetDB tool | MIT |

The licensing sections of these works are reproduced in full below.

## 📄 License

MIT. See [LICENSE](LICENSE).

The three MIT license texts from the credited upstream projects are reproduced
in this repository under `docs/THIRD_PARTY_LICENSES.md` as required by their
MIT terms, so attribution survives this derived work's every redistribution.

## 🛣️ Roadmap (brainstorm separately)

- [ ] Shodan / VirusTotal / Hunter source implementations (keys already plumbed)
- [ ] Optional CLI-tool wrappers (Sherlock / Maigret / Holehe) when installed
- [ ] Local SQLite cache + background poller for threat feeds (like mcp-threatintel)
- [ ] Publish to PyPI

---

*Pelican — one interface, many sources. For authorized open-source intelligence
research only.*