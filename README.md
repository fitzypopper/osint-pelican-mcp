# osint-mcp-server

A **general-purpose open-source intelligence (OSINT) MCP server** for AI agents.
Local-first: run it on your own machine, connect any [Model Context
Protocol](https://modelcontextprotocol.io) client (OpenCode, Hermes, Claude,
Cursor, Cline, etc.), and give your agent one tool surface for broad public-data
lookups.

Zero-config default: most tools work with **no API keys**. Optional keys unlock
higher-rate / premium sources (HIBP, OTX, Shodan, VirusTotal, Hunter, GitHub).

```
AI Agent (local or cloud LLM)
    ↓  MCP (stdio or streamable-http)
osint-mcp-server
    ├── Domain/Infra   DNS, WHOIS/RDAP, crt.sh, GeoIP, BGP, Wayback, HackerTarget, email security
    ├── Identity/Social GitHub, Reddit, Keybase, username enumeration, email permutation, Gravatar
    └── Threat/Breach  HIBP (k-anonymity + breaches), Ahmia dark-web, Shodan InternetDB, CISA KEV, OTX
```

---

## Quick start

```bash
uvx --from git+https://github.com/<you>/osint-mcp-server osint-mcp
```

Or, from a checkout:

```bash
git clone https://github.com/<you>/osint-mcp-server
cd osint-mcp-server
uv venv && uv pip install -e .
osint-mcp            # stdio transport (default)
```

Then add it to your client config. **OpenCode** (`opencode.json`):

```json
{
  "mcpServers": {
    "osint": {
      "type": "stdio",
      "command": ["uv", "run", "osint-mcp"]
    }
  }
}
```

**Claude Code**:

```bash
claude mcp add osint -- uv run osint-mcp
```

To run over HTTP instead of stdio:

```bash
OSINT_MCP_TRANSPORT=http osint-mcp        # streamable-http on default port
# optionally require a bearer token:
OSINT_MCP_AUTH_TOKEN=$(openssl rand -hex 24) OSINT_MCP_TRANSPORT=http osint-mcp
```

### CLI (no MCP client needed)

```bash
osint-mcp-cli whois_domain '{"domain": "example.com"}'
osint-mcp-cli osint_domain_recon '{"domain": "example.com"}'
osint-mcp-cli --list-tools
```

---

## Tools

Call `osint_list_sources` from any agent to see the full, current source/tool
table. Resident tools below.

### Domain & infrastructure (all free, no key)

| Tool | Source |
|---|---|
| `dns_lookup` / `dns_lookup_all` | dnspython |
| `whois_domain` / `whois_ip` | RDAP via rdap.org |
| `crtsh_search` | crt.sh (cert transparency) |
| `hackertarget_hostsearch` | HackerTarget |
| `email_security` | SPF/DMARC/DKIM derived from DNS |
| `geoip` | ip-api.com |
| `bgp_asn` / `bgp_ip` | bgpview.io |
| `wayback_urls` | Wayback Machine CDX |

### Identity & social (free)

| Tool | Source |
|---|---|
| `github_user_info` / `github_user_repos` / `github_commit_emails` / `github_repo_commits` | GitHub API |
| `reddit_user` / `reddit_user_posts` | Reddit JSON API |
| `keybase_lookup` | Keybase API |
| `username_enumerate` | HTTP probing across ~20 platforms |
| `gravatar_lookup` | Gravatar (MD5 hash) |
| `email_permutations` | local pattern generation |
| `domain_email_search` | heuristic scrape |

### Threat & breach

| Tool | Source | Key? |
|---|---|---|
| `check_password_breach` | HIBP k-anonymity | free |
| `shodan_internetdb` | Shodan InternetDB | free |
| `search_darkweb` | Ahmia.fi .onion index | free |
| `cisa_kev_catalog` | CISA KEV | free |
| `check_email_breaches` | HIBP | `HIBP_API_KEY` |
| `otx_search_pulses` / `otx_indicator` | AlienVault OTX | `OTX_API_KEY` |

### Aggregate

| Tool | What it does |
|---|---|
| `osint_list_sources` | Show sources + which keys are configured |
| `osint_domain_recon` | All-in-one free domain recon, correlated |
| `osint_ip_recon` | All-in-one free IP recon, correlated |

---

## API keys (all optional)

Copy `.env.example` to `.env` (or export env vars / use `~/.config/osint-mcp/.env`)
and add only the keys for sources you want to unlock:

| Var | Unlocks | Cost |
|---|---|---|
| `HIBP_API_KEY` | breached-account lookups | ~$4.50/mo |
| `OTX_API_KEY` | OTX pulses + indicator enrichment | free |
| `SHODAN_API_KEY` | Shodan search/host tools | free tier |
| `VIRUSTOTAL_API_KEY` | (planned) reputation | free tier |
| `HUNTER_API_KEY` | (planned) email discovery | paid |
| `GITHUB_TOKEN` | higher GitHub rate limit | free |

Keys are read into `SecretStr` and never logged.

---

## Ethics & use

This tool collects **publicly available** information only. Use it for
authorized OSINT research, security assessments of systems you own or are
authorized to test, journalism, and fraud/abuse investigation. Respect each
source's terms of service and rate limits. You are responsible for complying
with applicable law.

---

## Architecture

```
src/osint_mcp_server/
├── server.py          FastMCP entry point, tool registration, transports
├── cli.py             direct tool invocation (no MCP client)
├── config.py          env/.env settings, source status
├── net.py             shared async HTTP/DNS helpers, bounded concurrency
└── tools/
    ├── __init__.py
    ├── domain.py      DNS, RDAP, crt.sh, geoip, BGP, wayback, email security
    ├── social.py      GitHub, Reddit, Keybase, username, email, gravatar
    ├── threat.py      HIBP, Ahmia, Shodan InternetDB, CISA KEV, OTX
    └── suite.py       source listing + aggregate recon tools
```

Every source is an independent module and every tool is **read-only** —
nothing here writes to any target. Tools are annotated with FastMCP
`readOnlyHint` / `idempotentHint` / `openWorldHint` so capable clients can
see at a glance that these are safe, repeatable, read-only operations.

---

## Credits & attribution

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

---

## License

MIT. See [LICENSE](LICENSE).

The three MIT license texts from the credited upstream projects are reproduced
in this repository under `docs/THIRD_PARTY_LICENSES.md` as required by their
MIT terms, so attribution survives this derived work's every redistribution.

---

## Roadmap (brainstorm separately)

- [ ] Shodan / VirusTotal / Hunter source implementations (keys already plumbed)
- [ ] Optional CLI-tool wrappers (Sherlock / Maigret / Holehe) when installed
- [ ] Local SQLite cache + background poller for threat feeds (like mcp-threatintel)
- [ ] Publish to GitHub and PyPI
