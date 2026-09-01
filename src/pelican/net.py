"""Shared async HTTP + DNS helpers.

A thin wrapper around httpx plus a convenience geoip fetch (borrowing the
"free source, no API key" design ethos from badchars/osint-mcp-server,
MIT). All calls carry a descriptive User-Agent and honor the global
timeout in config.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Mapping

import httpx

from .config import USER_AGENT, config


async def fetch_json(
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    params: Mapping[str, Any] | None = None,
    timeout: float | None = None,
) -> Any:
    """GET a URL and parse the response body as JSON. Raises httpx.HTTPError."""
    async with httpx.AsyncClient(
        timeout=timeout or config.http_timeout,
        headers={"User-Agent": USER_AGENT, **(headers or {})},
        follow_redirects=True,
    ) as client:
        resp = await client.get(url, params=params)
        resp.raise_for_status()
        return resp.json()


async def fetch_text(
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    params: Mapping[str, Any] | None = None,
    timeout: float | None = None,
) -> str:
    """GET a URL and return the raw text body."""
    async with httpx.AsyncClient(
        timeout=timeout or config.http_timeout,
        headers={"User-Agent": USER_AGENT, **(headers or {})},
        follow_redirects=True,
    ) as client:
        resp = await client.get(url, params=params)
        resp.raise_for_status()
        return resp.text


async def fetch_json_bounded(
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    params: Mapping[str, Any] | None = None,
    timeout: float | None = None,
) -> Any:
    """Like fetch_json but returns a friendly dict on failure instead of raising.

    Used when a single bad source must not bring down a multi-source tool.
    """
    try:
        return await fetch_json(url, headers=headers, params=params, timeout=timeout)
    except Exception as exc:  # noqa: BLE001 - we report, we don't re-raise
        return {"_error": str(exc)}


async def geoip_lookup(ip: str) -> dict[str, Any]:
    """Free GeoIP lookup via ip-api.com (no API key).

    Adapted from the GeoIP source pattern in badchars/osint-mcp-server (MIT).
    The non-commercial JSON endpoint needs no key and is accurate enough for
    OSINT enrichment.
    """
    try:
        data = await fetch_json(f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,lat,lon,timezone,isp,org,as,asname,query,proxy,hosting,mobile")
        return data if isinstance(data, dict) else {"query": ip, "error": "unexpected response"}
    except Exception as exc:  # noqa: BLE001
        return {"query": ip, "error": str(exc)}


async def run_bounded(coros: list[Any], limit: int | None = None) -> list[Any]:
    """Run many coroutines with an optional concurrency cap, preserving order.

    Borrowed pattern from CloudWaddie/osint-mcp (MIT) which batches parallel
    username checks to avoid being rate-limited/blocked by targets. Results
    are returned in submission order via asyncio.gather (an individual
    failure becomes None so one bad source never drops the rest).
    """
    limit = limit or config.max_concurrency
    sem = asyncio.Semaphore(limit)

    async def one(coro: Any) -> Any:
        async with sem:
            try:
                return await coro
            except Exception:  # noqa: BLE001
                return None

    return list(await asyncio.gather(*(one(c) for c in coros)))


def compact_json(obj: Any) -> str:
    """Pretty JSON for MCP text responses (drops None-heavy noise gracefully)."""
    return json.dumps(obj, indent=2, ensure_ascii=False, default=str)
