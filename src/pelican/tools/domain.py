"""Domain, DNS, WHOIS/RDAP, certificate transparency and email security tools.

Free, no-API-key sources. Tool set and categorization borrow heavily from
badchars/osint-mcp-server (MIT).

Endpoints / techniques:
  * DNS resolution: dnspython (node:dns in the TS original)
  * RDAP: https://rdap.org + IANA bootstrap for domains/IPs
  * crt.sh CT logs: https://crt.sh/?q=%25.<domain>&output=json
  * GeoIP: ip-api.com (see net.geoip_lookup)
  * BGP/ASN: https://api.bgpview.io
  * Wayback: http://web.archive.org/cdx/search/cdx
  * HackerTarget hostsearch: https://api.hackertarget.com/hostsearch
  * Email security: derive SPF/DMARC/DKIM from DNS TXT records
"""

from __future__ import annotations

import re
from typing import Any

import dns.asyncresolver
import dns.resolver

from ..net import (  # noqa: F401  (re-exported for suite/server)
    fetch_json,
    fetch_text,
    geoip_lookup,
)

TYPE_MAP = {
    "A": "A",
    "AAAA": "AAAA",
    "MX": "MX",
    "NS": "NS",
    "SOA": "SOA",
    "CNAME": "CNAME",
    "SRV": "SRV",
    "TXT": "TXT",
    "PTR": "PTR",
    "CAA": "CAA",
}


async def dns_lookup(host: str, record_type: str = "A") -> dict[str, Any]:
    """Look up DNS records for a hostname.

    Args:
        host: hostname/domain to resolve (e.g. "example.com").
        record_type: record type: A, AAAA, MX, TXT, NS, SOA, CNAME, CAA, SRV.
            Default "A".

    Returns:
        Structured list of records with TTL and values.
    """
    rtype = TYPE_MAP.get(record_type.upper(), record_type.upper())
    resolver = dns.asyncresolver.Resolver()
    records: list[dict[str, Any]] = []
    try:
        answers = await resolver.resolve(host, rtype)
        for rdata in answers:
            entry: dict[str, Any] = {"ttl": answers.ttl, "value": rdata.to_text()}
            if rtype == "MX":
                entry["preference"] = getattr(rdata, "preference", None)
                entry["exchange"] = rdata.to_text().split(" ", 1)[-1]
            elif rtype == "SOA":
                entry["mname"] = getattr(rdata, "mname", None)
                entry["rname"] = getattr(rdata, "rname", None)
            records.append(entry)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        pass
    except Exception as exc:  # noqa: BLE001
        return {"host": host, "type": rtype, "error": str(exc)}
    return {"host": host, "type": rtype, "count": len(records), "records": records}


async def dns_lookup_all(host: str) -> dict[str, Any]:
    """Resolve every common record type for a host at once.

    A convenience aggregate mirroring osint_domain_recon's DNS pass.
    """
    results: dict[str, Any] = {"host": host}
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "CAA", "SOA"):
        res = await dns_lookup(host, rtype)
        if res.get("records"):
            results[rtype] = res["records"]
    return results


async def whois_domain(domain: str) -> dict[str, Any]:
    """Domain registration data via RDAP (no API key).

    Args:
        domain: domain to look up (e.g. "example.com").

    Returns:
        Registrar, dates, nameservers, status, and registrant contacts if public.
    """
    try:
        data = await fetch_json(f"https://rdap.org/domain/{domain}")
        return _normalize_rdap_domain(data)
    except Exception as exc:  # noqa: BLE001
        return {"domain": domain, "error": str(exc)}


def _normalize_rdap_domain(data: dict) -> dict[str, Any]:
    status = [s for s in (data.get("status") or [])]
    nameservers = [ns.get("ldhName") for ns in (data.get("nameservers") or []) if ns.get("ldhName")]
    events = {e.get("eventAction"): e.get("eventDate") for e in (data.get("events") or [])}
    entities = []
    for ent in data.get("entities") or []:
        roles = ent.get("roles") or []
        if any(r in roles for r in ("registrant", "administrative", "technical")):
            vcard = ent.get("vcardArray", [])
            handle = None
            if len(vcard) > 1:
                for item in vcard[1]:
                    if item[0] == "fn":
                        handle = item[3]
            entities.append({
                "role": roles,
                "handle": ent.get("handle"),
                "name": handle,
                "country": _find_vcard(ent, "adr"),
            })
    return {
        "domain": data.get("ldhName"),
        "status": status,
        "registrar": data.get("entities", [{}])[0].get("handle") if data.get("entities") else None,
        "nameservers": nameservers,
        "created": events.get("registration"),
        "expires": events.get("expiration"),
        "updated": events.get("last changed"),
        "entities": entities,
        "raw_events": events,
    }


def _find_vcard(entity: dict, field: str) -> Any:
    vcard = entity.get("vcardArray", [])
    if len(vcard) < 2:
        return None
    for item in vcard[1]:
        if item[0] == field:
            return item[3]
    return None


async def whois_ip(ip: str) -> dict[str, Any]:
    """IP network allocation data via RDAP (no API key).

    Args:
        ip: IP address to look up.

    Returns:
        Network name, CIDR, country, and responsible entities.
    """
    try:
        resp = await fetch_json(f"https://rdap.org/ip/{ip}")
        events = {e.get("eventAction"): e.get("eventDate") for e in (resp.get("events") or [])}
        entities = [
            {
                "handle": e.get("handle"),
                "roles": e.get("roles") or [],
                "name": _find_vcard(e, "fn"),
            }
            for e in (resp.get("entities") or [])
        ]
        return {
            "ip": ip,
            "handle": resp.get("handle"),
            "startAddress": resp.get("startAddress"),
            "endAddress": resp.get("endAddress"),
            "cidr": resp.get("cidr0_cidrs") or resp.get("ipVersion"),
            "country": resp.get("country"),
            "name": resp.get("name"),
            "type": resp.get("type"),
            "events": events,
            "entities": entities,
        }
    except Exception as exc:  # noqa: BLE001
        return {"ip": ip, "error": str(exc)}


async def crtsh_search(domain: str, limit: int = 100) -> dict[str, Any]:
    """Search certificate transparency logs via crt.sh for subdomains.

    Args:
        domain: base domain (e.g. "example.com").
        limit: max results to return (default 100).

    Returns:
        Deduplicated list of subdomains plus raw certificate matches.
    """
    try:
        data = await fetch_json(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            timeout=30,
        )
        if not isinstance(data, list):
            return {"domain": domain, "error": "unexpected response from crt.sh"}
        subdomains: set[str] = set()
        rows = []
        for item in data[: int(limit)]:
            name = item.get("name_value", "")
            for part in name.splitlines():
                part = part.strip().lower()
                if part and part not in subdomains:
                    subdomains.add(part)
            rows.append({
                "name": item.get("common_name"),
                "issuer": item.get("issuer_name"),
                "not_before": item.get("not_before"),
                "not_after": item.get("not_after"),
            })
        return {
            "domain": domain,
            "subdomain_count": len(subdomains),
            "subdomains": sorted(subdomains)[: int(limit)],
            "certificates": rows,
        }
    except Exception as exc:  # noqa: BLE001
        return {"domain": domain, "error": str(exc) or f"crt.sh request failed (HTTP {getattr(exc, 'response', None) and exc.response.status_code})"}


async def hackertarget_hostsearch(domain: str) -> dict[str, Any]:
    """Find hosts/subdomains with resolved IPs via HackerTarget (free).

    Borrowed from badchars/osint-mcp-server (MIT).
    """
    try:
        text = await fetch_text(f"https://api.hackertarget.com/hostsearch/?q={domain}")
        hosts = []
        for line in text.strip().splitlines():
            if "," in line:
                host, ip = line.split(",", 1)
                hosts.append({"host": host, "ip": ip})
        return {"domain": domain, "count": len(hosts), "hosts": hosts}
    except Exception as exc:  # noqa: BLE001
        return {"domain": domain, "error": str(exc)}


async def email_security(domain: str) -> dict[str, Any]:
    """Analyze a domain's SPF/DMARC/DKIM email-authentication posture.

    Adapted from badchars/osint-mcp-server (MIT). Computes a spoofing risk
    assessment from the DNS records an attacker would check.
    """
    spf = await _gather_txt(domain)
    dmarc = await _gather_txt(f"_dmarc.{domain}")
    dkim_selector = None
    # common selectors, cheap probe (many domains use a single selector)
    for selector in ("default", "google", "selector1", "k1", "dkim", "mail", "s1", "s2"):
        rec = await _gather_txt(f"{selector}._domainkey.{domain}")
        if any("v=DKIM1" in r for r in rec):
            dkim_selector = selector
            break

    spf_policy = _spf_policy(spf)
    dmarc_policy = _dmarc_policy(dmarc)

    risk = "unknown"
    if spf_policy and dmarc_policy:
        if dmarc_policy == "reject" or (dmarc_policy == "quarantine" and spf_policy == "hardfail"):
            risk = "low"
        elif dmarc_policy == "none":
            risk = "high"
        else:
            risk = "medium"

    return {
        "domain": domain,
        "spf": {"records": spf, "policy": spf_policy},
        "dmarc": {"records": dmarc, "policy": dmarc_policy},
        "dkim": {"selector": dkim_selector, "found": dkim_selector is not None},
        "spoofing_risk": risk,
        "recommendations": _recommendations(spf_policy, dmarc_policy, dkim_selector),
    }


async def _gather_txt(target: str) -> list[str]:
    resolver = dns.asyncresolver.Resolver()
    try:
        answers = await resolver.resolve(target, "TXT")
        return [str(rdata).strip('"') for rdata in answers]
    except Exception:  # noqa: BLE001
        return []


def _spf_policy(txts: list[str]) -> str | None:
    for rec in txts:
        if rec.startswith("v=spf1"):
            if re.search(r"\s\-all\s*$", rec):
                return "hardfail"
            if re.search(r"\s\~all\s*$", rec):
                return "softfail"
            if re.search(r"\s\+all\s*$", rec):
                return "passall"
            return "weak"
    return None


def _dmarc_policy(txts: list[str]) -> str | None:
    for rec in txts:
        if rec.startswith("v=DMARC1"):
            m = re.search(r"p=(none|quarantine|reject)", rec)
            return m.group(1) if m else None
    return None


def _recommendations(spf: str | None, dmarc: str | None, dkim: str | None) -> list[str]:
    recs = []
    if spf and spf in ("softfail", "weak"):
        recs.append("Upgrade SPF to a hard fail (-all) to prevent spoofing.")
    if dmarc == "none":
        recs.append("Enforce DMARC policy (p=quarantine, then p=reject) to block spoofed mail.")
    if not dkim:
        recs.append("Configure DKIM signing to improve deliverability and anti-spoofing.")
    recs.append("Adopt DMARC reporting (rua=) to monitor alignment.")
    return recs


async def bgp_asn(asn: str) -> dict[str, Any]:
    """ASN details and announced prefixes via bgpview.io (free)."""
    try:
        data = await fetch_json(f"https://api.bgpview.io/asn/{asn}")
        # IPv4/IPv6 prefixes live at /asn/{asn}/prefixes; pull details + a prefix summary
        prefixes = await fetch_json(f"https://api.bgpview.io/asn/{asn}/prefixes")
        return {
            "asn": asn,
            "data": data.get("data") or data,
            "ipv4_prefixes": prefixes.get("data", {}).get("ipv4_prefixes") or [],
            "ipv6_prefixes": prefixes.get("data", {}).get("ipv6_prefixes") or [],
        }
    except Exception as exc:  # noqa: BLE001
        return {"asn": asn, "error": str(exc)}


async def bgp_ip(ip: str) -> dict[str, Any]:
    """IP -> prefix/ASN routing lookup via bgpview.io (free)."""
    try:
        data = await fetch_json(f"https://api.bgpview.io/ip/{ip}")
        return {"ip": ip, "data": data.get("data") or data}
    except Exception as exc:  # noqa: BLE001
        return {"ip": ip, "error": str(exc)}


async def wayback_urls(domain: str, limit: int = 200) -> dict[str, Any]:
    """Discover archived URLs for a domain via the Wayback CDX API (free).

    Borrowed from badchars/osint-mcp-server (MIT). Great for finding old
    endpoints, hidden paths, and removed content.
    """
    try:
        data = await fetch_json(
            "http://web.archive.org/cdx/search/cdx",
            params={
                "url": f"{domain}/*",
                "output": "json",
                "fl": "original,timestamp,statuscode,mimetype",
                "collapse": "urlkey",
                "limit": limit,
            },
            timeout=30,
        )
        if not isinstance(data, list) or len(data) < 2:
            return {"domain": domain, "count": 0, "urls": []}
        headers = data[0]
        urls = []
        for row in data[1:]:
            urls.append(dict(zip(headers, row)))
        return {"domain": domain, "count": len(urls), "urls": urls}
    except Exception as exc:  # noqa: BLE001
        return {"domain": domain, "error": str(exc)}
