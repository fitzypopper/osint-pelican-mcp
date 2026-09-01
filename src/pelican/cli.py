"""Minimal CLI to invoke OSINT tools directly without an MCP client.

Mirrors the `pelican --tool <name> '<json-args>'` pattern from
badchars/osint-mcp-server (MIT). Useful for scripting, cron, and CI.
"""

from __future__ import annotations

import asyncio
import json
import sys


async def _run(name: str, args: dict) -> str:
    from .net import compact_json
    from .tools import domain as domain_mod
    from .tools import social as social_mod
    from .tools import suite as suite_mod
    from .tools import threat as threat_mod

    # Meta (call the raw suite functions directly -> dict -> compact_json once)
    meta_tools = {
        "osint_list_sources": lambda: suite_mod.list_sources(),
        "osint_domain_recon": lambda: suite_mod.domain_recon(args.get("domain", "")),
        "osint_ip_recon": lambda: suite_mod.ip_recon(args.get("ip", "")),
    }
    if name in meta_tools:
        try:
            res = meta_tools[name]()
            if asyncio.iscoroutine(res):
                res = await res
            return compact_json(res)
        except Exception as exc:  # noqa: BLE001
            return compact_json({"tool": name, "error": str(exc)})

    # Domain
    domain_tools = {
        "dns_lookup": lambda: domain_mod.dns_lookup(args.get("host", ""), args.get("record_type", "A")),
        "dns_lookup_all": lambda: domain_mod.dns_lookup_all(args.get("host", "")),
        "whois_domain": lambda: domain_mod.whois_domain(args.get("domain", "")),
        "whois_ip": lambda: domain_mod.whois_ip(args.get("ip", "")),
        "crtsh_search": lambda: domain_mod.crtsh_search(args.get("domain", ""), args.get("limit", 100)),
        "hackertarget_hostsearch": lambda: domain_mod.hackertarget_hostsearch(args.get("domain", "")),
        "email_security": lambda: domain_mod.email_security(args.get("domain", "")),
        "geoip": lambda: domain_mod.geoip_lookup(args.get("ip", "")),
        "bgp_asn": lambda: domain_mod.bgp_asn(args.get("asn", "")),
        "bgp_ip": lambda: domain_mod.bgp_ip(args.get("ip", "")),
        "wayback_urls": lambda: domain_mod.wayback_urls(args.get("domain", ""), args.get("limit", 200)),
    }
    # Social
    social_tools = {
        "github_user_info": lambda: social_mod.github_user_info(args.get("username", "")),
        "github_user_repos": lambda: social_mod.github_user_repos(args.get("username", "")),
        "github_commit_emails": lambda: social_mod.github_commit_emails(args.get("username", "")),
        "github_repo_commits": lambda: social_mod.github_repo_commits(args.get("owner", ""), args.get("repo", "")),
        "reddit_user": lambda: social_mod.reddit_user(args.get("username", "")),
        "reddit_user_posts": lambda: social_mod.reddit_user_posts(args.get("username", ""), args.get("limit", 25)),
        "keybase_lookup": lambda: social_mod.keybase_lookup(args.get("username", "")),
        "username_enumerate": lambda: social_mod.username_enumerate(args.get("username", "")),
        "gravatar_lookup": lambda: social_mod.gravatar_lookup(args.get("email", "")),
        "email_permutations": lambda: asyncio.to_thread(
            social_mod.email_permutations,
            args.get("first_name", ""), args.get("last_name", ""), args.get("domain", ""),
        ),
        "domain_email_search": lambda: social_mod.domain_email_search(args.get("domain", "")),
    }
    # Threat
    threat_tools = {
        "check_password_breach": lambda: threat_mod.check_password_breach(args.get("password", "")),
        "check_email_breaches": lambda: threat_mod.check_email_breaches(args.get("email", "")),
        "search_darkweb": lambda: threat_mod.search_darkweb(args.get("query", ""), args.get("max_results", 20)),
        "shodan_internetdb": lambda: threat_mod.shodan_internetdb(args.get("ip", "")),
        "cisa_kev_catalog": lambda: threat_mod.cisa_kev_catalog(),
        "otx_search_pulses": lambda: threat_mod.otx_search_pulses(args.get("limit", 10)),
        "otx_indicator": lambda: threat_mod.otx_indicator(args.get("indicator", ""), args.get("section", "general")),
    }

    target = domain_tools.get(name) or social_tools.get(name) or threat_tools.get(name)
    if target is None:
        return json.dumps({"error": f"Unknown tool: {name}"}, indent=2)
    try:
        res = await target()
        return compact_json(res)
    except Exception as exc:  # noqa: BLE001
        return compact_json({"tool": name, "error": str(exc)})


def main() -> int:
    args = sys.argv[1:]
    if not args:
        print(
            "usage: pelican-cli <tool> ['{\"arg\": \"value\"}']\n"
            "       pelican-cli --list-tools",
            file=sys.stderr,
        )
        return 2
    if args[0] == "--list-tools":
        print("\n".join(_ALL_TOOLS))
        return 0
    name = args[0]
    payload = {}
    if len(args) > 1:
        try:
            payload = json.loads(args[1])
        except json.JSONDecodeError as exc:
            print(f"Invalid JSON args: {exc}", file=sys.stderr)
            return 2
    result = asyncio.run(_run(name, payload))
    print(result)
    return 0


_ALL_TOOLS = [
    "dns_lookup", "dns_lookup_all", "whois_domain", "whois_ip", "crtsh_search",
    "hackertarget_hostsearch", "email_security", "geoip", "bgp_asn", "bgp_ip",
    "wayback_urls", "github_user_info", "github_user_repos", "github_commit_emails",
    "github_repo_commits", "reddit_user", "reddit_user_posts", "keybase_lookup",
    "username_enumerate", "gravatar_lookup", "email_permutations", "domain_email_search",
    "check_password_breach", "check_email_breaches", "search_darkweb", "shodan_internetdb",
    "cisa_kev_catalog", "otx_search_pulses", "otx_indicator", "osint_list_sources",
    "osint_domain_recon", "osint_ip_recon",
]


if __name__ == "__main__":
    sys.exit(main())
