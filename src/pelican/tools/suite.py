"""Meta / aggregate OSINT tools.

Borrowed from badchars/osint-mcp-server (MIT):
  * osint_list_sources — show all sources and which API keys are unlocked
  * osint_domain_recon — run the free passes (DNS + WHOIS + crt.sh +
    HackerTarget + email security + geoip) in parallel and correlate.
Adds an osint_ip_recon aggregate for IPs.
"""

from __future__ import annotations

from typing import Any

from ..config import config
from ..net import run_bounded
from . import domain as domain_mod
from .domain import (
    bgp_ip,
    crtsh_search,
    dns_lookup_all,
    email_security,
    hackertarget_hostsearch,
    whois_domain,
)
from .threat import shodan_internetdb


def list_sources() -> dict[str, Any]:
    """List all data sources, tool availability, and API-key status."""
    keys = config.source_status
    return {
        "server": "pelican",
        "sources": {
            "dns": {"free": True, "needs_key": False, "tools": ["dns_lookup", "dns_lookup_all"]},
            "whois_rdap": {"free": True, "needs_key": False, "tools": ["whois_domain", "whois_ip"]},
            "certificate_transparency": {"free": True, "needs_key": False, "tools": ["crtsh_search"]},
            "geoip": {"free": True, "needs_key": False, "tools": ["geoip"]},
            "bgp": {"free": True, "needs_key": False, "tools": ["bgp_asn", "bgp_ip"]},
            "wayback": {"free": True, "needs_key": False, "tools": ["wayback_urls"]},
            "hackertarget": {"free": True, "needs_key": False, "tools": ["hackertarget_hostsearch"]},
            "email_security": {"free": True, "needs_key": False, "tools": ["email_security"]},
            "github": {"free": True, "key_configured": keys["github"], "tools": ["github_user_info", "github_user_repos", "github_commit_emails", "github_repo_commits"]},
            "reddit": {"free": True, "needs_key": False, "tools": ["reddit_user", "reddit_user_posts"]},
            "keybase": {"free": True, "needs_key": False, "tools": ["keybase_lookup"]},
            "username_enum": {"free": True, "needs_key": False, "tools": ["username_enumerate"]},
            "gravatar": {"free": True, "needs_key": False, "tools": ["gravatar_lookup"]},
            "shodan_internetdb": {"free": True, "needs_key": False, "tools": ["shodan_internetdb"]},
            "ahmia_darkweb": {"free": True, "needs_key": False, "tools": ["search_darkweb"]},
            "hibp_password": {"free": True, "needs_key": False, "tools": ["check_password_breach"]},
            "cisa_kev": {"free": True, "needs_key": False, "tools": ["cisa_kev_catalog"]},
            "hibp_breaches": {"free": False, "key_configured": keys["hibp"], "tools": ["check_email_breaches"]},
            "otx": {"free": False, "key_configured": keys["otx"], "tools": ["otx_search_pulses", "otx_indicator"]},
        },
    }


async def domain_recon(domain: str) -> dict[str, Any]:
    """All-in-one reconnaissance for a domain using only free sources.

    Runs DNS, RDAP WHOIS, crt.sh, HackerTarget, email security, and GeoIP
    of the resolved A record in parallel, then correlates into a single
    intelligence snapshot. Modeled on badchars/osint-mcp-server's
    osint_domain_recon (MIT).

    Args:
        domain: the domain to investigate (e.g. "example.com").

    Returns:
        Correlated DNS/WHOIS/subdomain/email-security/infra summary.
    """
    # Parallel free passes
    results = await run_bounded(
        [
            dns_lookup_all(domain),
            whois_domain(domain),
            crtsh_search(domain, limit=50),
            hackertarget_hostsearch(domain),
            email_security(domain),
        ]
    )
    dns_res, whois_res, crt_res, ht_res, mail_res = results

    # Resolve a primary IP for the geoip + bgp pass
    primary_ip = None
    if dns_res and isinstance(dns_res, dict):
        a_records = dns_res.get("A") or []
        if a_records:
            first = a_records[0]
            primary_ip = first.get("value") if isinstance(first, dict) else None
    if not primary_ip and ht_res:
        hosts = ht_res.get("hosts") or []
        if hosts and hosts[0].get("ip"):
            primary_ip = hosts[0]["ip"]

    ip_extra = []
    if primary_ip:
        geo = await domain_mod.geoip_lookup(primary_ip)
        ip_extra.append(await bgp_ip(primary_ip))
        ip_extra.insert(0, geo)

    return {
        "domain": domain,
        "dns": dns_res,
        "whois": whois_res,
        "certificate_transparency": {
            "subdomain_count": crt_res.get("subdomain_count", 0) if isinstance(crt_res, dict) else 0,
            "subdomains": crt_res.get("subdomains", []) if isinstance(crt_res, dict) else [],
        },
        "hosts": ht_res,
        "email_security": mail_res,
        "primary_ip": primary_ip,
        "ip_intel": ip_extra if ip_extra else None,
    }


async def ip_recon(ip: str) -> dict[str, Any]:
    """All-in-one reconnaissance for an IP using only free sources.

    Runs GeoIP, RDAP IP, BGP routing, Shodan InternetDB, and reverse DNS in
    parallel and correlates them.

    Args:
        ip: the IP address to investigate.

    Returns:
        Correlated geo/alloc/BGP/open-port/hostname intelligence.
    """
    results = await run_bounded(
        [
            domain_mod.geoip_lookup(ip),
            domain_mod.whois_ip(ip),
            bgp_ip(ip),
            shodan_internetdb(ip),
        ]
    )
    geo, whois, bgp, shodan = results
    return {
        "ip": ip,
        "geo": geo,
        "rdap": whois,
        "bgp": bgp,
        "shodan_internetdb": shodan,
    }
