"""Threat intelligence & breach OSINT tools.

Blends concepts from:
  * pete-builds/mcp-threatintel (MIT) — HIBP k-anonymity password check,
    Ahmia dark-web search, CISA KEV catalog patterns.
  * CloudWaddie/osint-mcp (MIT) — HIBP breached-account lookup shape.
  * badchars/osint-mcp-server (MIT) — Shodan discipline (free tier).

Free / no-key sources: Ahmia dark-web, HIBP password (k-anonymity), Shodan
InternetDB, CISA KEV. Key-gated: HIBP breaches, OTX, Shodan search.
"""

from __future__ import annotations

import hashlib
from typing import Any

from ..config import config
from ..net import fetch_json, fetch_text

HIBP_HEADERS = {"User-Agent": "pelican/0.1.0", "hibp-api-key": config.hibp_api_key}


async def check_password_breach(password: str) -> dict[str, Any]:
    """Check if a password has appeared in a known breach (k-anonymity).

    Only the first 5 characters of the SHA-1 hash leave the machine (HIBP
    range API). The full password never leaves this server. Borrowed from
    pete-builds/mcp-threatintel (MIT).

    Args:
        password: the password candidate to check.

    Returns:
        count (0 = not seen) and a hint for the full suffix lookup.
    """
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        body = await fetch_text(f"https://api.pwnedpasswords.com/range/{prefix}")
        count = 0
        for line in body.splitlines():
            if ":" in line and line.split(":")[0].upper() == suffix:
                count = int(line.split(":")[1].strip())
                break
        return {
            "sha1_prefix": prefix,
            "breach_count_seen": count,
            "exposed": count > 0,
            "note": "Only the first 5 chars of the SHA-1 hash were transmitted.",
        }
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}


async def check_email_breaches(email: str) -> dict[str, Any]:
    """Check an email address against HaveIBeenPwned (requires HIBP_API_KEY).

    Borrowed from CloudWaddie/osint-mcp (MIT).

    Args:
        email: email address to check.

    Returns:
        List of breaches the address appears in, or a config-error message.
    """
    if not config.hibp_api_key:
        return {
            "error": "HIBP_API_KEY not configured. Set it to use breach lookups."
        }
    try:
        data = await fetch_json(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
            headers=HIBP_HEADERS,
            params={"truncateResponse": "false"},
        )
        if data is None:
            return {"email": email, "breaches": []}
        breaches = [
            {
                "name": b.get("Name"),
                "title": b.get("Title"),
                "domain": b.get("Domain"),
                "breach_date": b.get("BreachDate"),
                "pwn_count": b.get("PwnCount"),
                "description": b.get("Description"),
                "data_classes": b.get("DataClasses"),
                "is_verified": b.get("IsVerified"),
                "is_sensitive": b.get("IsSensitive"),
                "is_spam_list": b.get("IsSpamList"),
            }
            for b in data
        ]
        return {"email": email, "count": len(breaches), "breaches": breaches}
    except Exception as exc:  # noqa: BLE001
        return {"email": email, "error": str(exc)}


async def search_darkweb(query: str, max_results: int = 20) -> dict[str, Any]:
    """Search the dark web via Ahmia.fi's index of .onion services.

    Borrowed from pete-builds/mcp-threatintel (MIT). You can't visit these
    URLs without Tor, but the metadata is useful for research.

    Args:
        query: search terms.
        max_results: max results to return (default 20).

    Returns:
        .onion URLs, titles and descriptions.
    """
    try:
        data = await fetch_json(
            "https://ahmia.fi/search/",
            params={"q": query},
            headers={"User-Agent": "pelican/0.1.0"},
        )
        results = []
        # Ahmia returns JSON when the client signals it accepts JSON.
        if isinstance(data, list):
            for item in data[: int(max_results)]:
                results.append({
                    "title": item.get("title"),
                    "url": item.get("url"),
                    "description": item.get("description"),
                })
            return {"query": query, "count": len(results), "results": results}
        return {"query": query, "count": 0, "results": []}
    except Exception as exc:  # noqa: BLE001
        return {"query": query, "error": str(exc)}


async def shodan_internetdb(ip: str) -> dict[str, Any]:
    """Free Shodan InternetDB lookup (no API key required).

    Returns open ports, hostnames, CVEs, and tags for an IP. Borrowed from
    the "always free" pattern in Abraar02/threatwatch-mcp and Vorota-ai/
    shodan-mcp.

    Args:
        ip: IP address.

    Returns:
        Open ports, hostnames, CVEs, tags.
    """
    try:
        data = await fetch_json(f"https://internetdb.shodan.io/{ip}")
        if "ports" not in data and "hostnames" not in data and "cpes" not in data:
            return {"ip": ip, "found": False, "detail": data}
        return {
            "ip": ip,
            "found": True,
            "ports": data.get("ports") or [],
            "hostnames": data.get("hostnames") or [],
            "cves": data.get("vulns") or [],
            "tags": data.get("tags") or [],
            "cpes": data.get("cpes") or [],
        }
    except Exception as exc:  # noqa: BLE001
        return {"ip": ip, "error": str(exc)}


async def cisa_kev_catalog() -> dict[str, Any]:
    """Fetch the CISA Known Exploited Vulnerabilities catalog.

    Borrowed from pete-builds/mcp-threatintel (MIT); also its own category in
    bob-reis/osint-mcp.

    Returns:
        List of known exploited vulnerabilities with vendor/product/dates.
    """
    try:
        data = await fetch_json("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
        vulns = data.get("vulnerabilities") or []
        return {
            "catalog_version": data.get("catalogVersion"),
            "catalog_date": data.get("dateReleased"),
            "count": len(vulns),
            "vulnerabilities": vulns,
        }
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}


async def otx_search_pulses(limit: int = 10) -> dict[str, Any]:
    """Fetch recent AlienVault OTX community threat pulses (requires OTX_API_KEY).

    Args:
        limit: max pulses (default 10).

    Returns:
        Recent OTX pulses with name, author, description, tags.
    """
    if not config.otx_api_key:
        return {"error": "OTX_API_KEY not configured."}
    try:
        data = await fetch_json(
            "https://otx.alienvault.com/api/v1/pulses/subscribed",
            headers={"X-OTX-API-KEY": config.otx_api_key},
            params={"limit": limit},
        )
        pulses = data.get("results") or []
        return {
            "count": len(pulses),
            "pulses": [
                {
                    "id": p.get("id"),
                    "name": p.get("name"),
                    "author": (p.get("author") or {}).get("username"),
                    "description": p.get("description"),
                    "tags": [t.get("name") for t in p.get("tags") or []],
                    "created": p.get("created"),
                }
                for p in pulses
            ],
        }
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}


async def otx_indicator(indicator: str, section: str = "general") -> dict[str, Any]:
    """Look up an indicator (IP/domain/hostname/URL/file-hash) in OTX.

    Args:
        indicator: the indicator to enrich.
        section: OTX section, e.g. general, reputation, geo, malware, url_list.

    Returns:
        OTX enrichment for that section.
    """
    if not config.otx_api_key:
        return {"error": "OTX_API_KEY not configured."}
    try:
        data = await fetch_json(
            f"https://otx.alienvault.com/api/v1/indicators/IPv4/{indicator}/{section}"
            if "." in indicator and indicator.replace(".", "").isdigit() is False
            else f"https://otx.alienvault.com/api/v1/indicators/{_otx_type(indicator)}/{indicator}/{section}",
            headers={"X-OTX-API-KEY": config.otx_api_key},
        )
        return data if isinstance(data, dict) else {"data": data}
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}


def _otx_type(indicator: str) -> str:
    if "." in indicator and not indicator.replace(".", "").isdigit():
        return "domain"
    if indicator.replace(".", "").isdigit():
        return "IPv4"
    if ":" in indicator or indicator.startswith("http"):
        return "url"
    if len(indicator) in (32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in indicator):
        return "file"
    return "domain"
