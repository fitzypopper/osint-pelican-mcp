"""FastMCP entry point for the OSINT MCP server.

Registers every OSINT tool from tools/ into a FastMCP instance and serves it
over stdio (local-first) and optionally streamable HTTP. Tool annotations
(readOnlyHint / idempotentHint / openWorldHint) follow the explicit style
introduced in pete-builds/mcp-threatintel (MIT): every tool here is read-only
and safe to repeat.
"""

from __future__ import annotations

import os
import sys

from fastmcp import FastMCP

from .config import config, load_env
from .tools import domain as domain_mod
from .tools import social as social_mod
from .tools import suite as suite_mod
from .tools import threat as threat_mod

READ_REMOTE = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": True,
}

mcp = FastMCP(
    "OSINT",
    instructions=(
        "You are a general-purpose open-source intelligence (OSINT) server. "
        "Agents can query public data: DNS/WHOIS/cert-transparency/geoip/BGP "
        "(free), social/identity (GitHub, Reddit, Keybase, username/email), "
        "and threat/breach sources. Only for authorized research."
    ),
)


# ============================================================
# Domain & infrastructure
# ============================================================


@mcp.tool(annotations=READ_REMOTE)
async def dns_lookup(host: str, record_type: str = "A") -> str:
    """Resolve DNS records for a hostname (A, AAAA, MX, TXT, NS, SOA, CNAME, CAA, SRV)."""
    return _s(await domain_mod.dns_lookup(host, record_type))


@mcp.tool(annotations=READ_REMOTE)
async def dns_lookup_all(host: str) -> str:
    """Resolve all common record types for a hostname at once."""
    return _s(await domain_mod.dns_lookup_all(host))


@mcp.tool(annotations=READ_REMOTE)
async def whois_domain(domain: str) -> str:
    """Domain registration data (registrar, dates, nameservers) via RDAP."""
    return _s(await domain_mod.whois_domain(domain))


@mcp.tool(annotations=READ_REMOTE)
async def whois_ip(ip: str) -> str:
    """IP network allocation data via RDAP (network name, CIDR, country)."""
    return _s(await domain_mod.whois_ip(ip))


@mcp.tool(annotations=READ_REMOTE)
async def crtsh_search(domain: str, limit: int = 100) -> str:
    """Discover subdomains via certificate transparency logs (crt.sh)."""
    return _s(await domain_mod.crtsh_search(domain, limit))


@mcp.tool(annotations=READ_REMOTE)
async def hackertarget_hostsearch(domain: str) -> str:
    """Find hosts/subdomains with resolved IPs via HackerTarget."""
    return _s(await domain_mod.hackertarget_hostsearch(domain))


@mcp.tool(annotations=READ_REMOTE)
async def email_security(domain: str) -> str:
    """Analyze a domain's SPF/DMARC/DKIM email-authentication and spoofing risk."""
    return _s(await domain_mod.email_security(domain))


@mcp.tool(annotations=READ_REMOTE)
async def geoip(ip: str) -> str:
    """IP geolocation: country, region, city, ISP, ASN, proxy/hosting flags."""
    return _s(await domain_mod.geoip_lookup(ip))


@mcp.tool(annotations=READ_REMOTE)
async def bgp_asn(asn: str) -> str:
    """ASN details and announced IPv4/IPv6 prefixes."""
    return _s(await domain_mod.bgp_asn(asn))


@mcp.tool(annotations=READ_REMOTE)
async def bgp_ip(ip: str) -> str:
    """IP to prefix/ASN routing lookup."""
    return _s(await domain_mod.bgp_ip(ip))


@mcp.tool(annotations=READ_REMOTE)
async def wayback_urls(domain: str, limit: int = 200) -> str:
    """Discover archived URLs for a domain via the Wayback Machine CDX API."""
    return _s(await domain_mod.wayback_urls(domain, limit))


# ============================================================
# Identity & social
# ============================================================


@mcp.tool(annotations=READ_REMOTE)
async def github_user_info(username: str) -> str:
    """Get public GitHub profile metadata for a user."""
    return _s(await social_mod.github_user_info(username))


@mcp.tool(annotations=READ_REMOTE)
async def github_user_repos(username: str) -> str:
    """List public GitHub repositories for a user."""
    return _s(await social_mod.github_user_repos(username))


@mcp.tool(annotations=READ_REMOTE)
async def github_commit_emails(username: str) -> str:
    """Extract email addresses from a user's public GitHub events."""
    return _s(await social_mod.github_commit_emails(username))


@mcp.tool(annotations=READ_REMOTE)
async def github_repo_commits(owner: str, repo: str) -> str:
    """Extract committer emails from a repo's recent commit history."""
    return _s(await social_mod.github_repo_commits(owner, repo))


@mcp.tool(annotations=READ_REMOTE)
async def reddit_user(username: str) -> str:
    """Get public Reddit profile metadata (account age, karma, mod status)."""
    return _s(await social_mod.reddit_user(username))


@mcp.tool(annotations=READ_REMOTE)
async def reddit_user_posts(username: str, limit: int = 25) -> str:
    """List a Reddit user's recent public posts."""
    return _s(await social_mod.reddit_user_posts(username, limit))


@mcp.tool(annotations=READ_REMOTE)
async def keybase_lookup(username: str) -> str:
    """Look up a Keybase user and their linked social accounts / public keys."""
    return _s(await social_mod.keybase_lookup(username))


@mcp.tool(annotations=READ_REMOTE)
async def username_enumerate(username: str) -> str:
    """Probe ~20 major platforms to see if a username is taken."""
    return _s(await social_mod.username_enumerate(username))


@mcp.tool(annotations=READ_REMOTE)
async def gravatar_lookup(email: str) -> str:
    """Look up the public Gravatar profile for an email address."""
    return _s(await social_mod.gravatar_lookup(email))


@mcp.tool(annotations=READ_REMOTE)
async def email_permutations(first_name: str, last_name: str, domain: str) -> str:
    """Generate common corporate email address permutations."""
    return _s(social_mod.email_permutations(first_name, last_name, domain))


@mcp.tool(annotations=READ_REMOTE)
async def domain_email_search(domain: str) -> str:
    """Heuristically scrape a domain's public pages for exposed emails."""
    return _s(await social_mod.domain_email_search(domain))


# ============================================================
# Threat & breach
# ============================================================


@mcp.tool(annotations=READ_REMOTE)
async def check_password_breach(password: str) -> str:
    """Check if a password appeared in a breach (k-anonymity; password never leaves the machine)."""
    return _s(await threat_mod.check_password_breach(password))


@mcp.tool(annotations=READ_REMOTE)
async def check_email_breaches(email: str) -> str:
    """Check an email against HaveIBeenPwned breaches (needs HIBP_API_KEY)."""
    return _s(await threat_mod.check_email_breaches(email))


@mcp.tool(annotations=READ_REMOTE)
async def search_darkweb(query: str, max_results: int = 20) -> str:
    """Search the dark web via Ahmia.fi (.onion index). Metadata only."""
    return _s(await threat_mod.search_darkweb(query, max_results))


@mcp.tool(annotations=READ_REMOTE)
async def shodan_internetdb(ip: str) -> str:
    """Free Shodan InternetDB lookup: open ports, hostnames, CVEs, tags."""
    return _s(await threat_mod.shodan_internetdb(ip))


@mcp.tool(annotations=READ_REMOTE)
async def cisa_kev_catalog() -> str:
    """Fetch the CISA Known Exploited Vulnerabilities catalog."""
    return _s(await threat_mod.cisa_kev_catalog())


@mcp.tool(annotations=READ_REMOTE)
async def otx_search_pulses(limit: int = 10) -> str:
    """Fetch recent AlienVault OTX threat pulses (needs OTX_API_KEY)."""
    return _s(await threat_mod.otx_search_pulses(limit))


@mcp.tool(annotations=READ_REMOTE)
async def otx_indicator(indicator: str, section: str = "general") -> str:
    """Enrich an indicator (IP/domain/URL/hash) via AlienVault OTX."""
    return _s(await threat_mod.otx_indicator(indicator, section))


# ============================================================
# Meta / aggregate
# ============================================================


@mcp.tool
async def osint_list_sources() -> str:
    """List all data sources, which are free, and which API keys are configured."""
    return _s(suite_mod.list_sources())


@mcp.tool(annotations=READ_REMOTE)
async def osint_domain_recon(domain: str) -> str:
    """All-in-one free reconnaissance for a domain (DNS, WHOIS, crt.sh, hosts, email security, geoip)."""
    return _s(await suite_mod.domain_recon(domain))


@mcp.tool(annotations=READ_REMOTE)
async def osint_ip_recon(ip: str) -> str:
    """All-in-one free reconnaissance for an IP (geo, rdap, bgp, shodan internetdb)."""
    return _s(await suite_mod.ip_recon(ip))


def _s(data) -> str:
    from .net import compact_json

    return compact_json(data)


def main() -> None:
    load_env()
    transport = os.environ.get("OSINT_MCP_TRANSPORT", "stdio").strip().lower()
    auth_token = config.auth_token
    if transport in ("http", "streamable-http", "sse"):
        if auth_token:
            mcp.run(transport="streamable-http", bearer_token=auth_token)
        else:
            mcp.run(transport="streamable-http")
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    sys.exit(main())
