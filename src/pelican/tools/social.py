"""Identity & social-media OSINT tools.

Borrowed from CloudWaddie/osint-mcp (MIT) — this fills the people/social gap
that infra-focused servers omit. Endpoint patterns, field selection and tool
shapes follow that project; adapted from TypeScript to Python FastMCP.

Sources:
  * GitHub API (public) — profile, repos, commit emails
  * Reddit JSON API (public) — profile + submitted posts
  * Keybase lookup API
  * Gravatar profile from an email hash (MD5)
  * username enumeration across ~20 platforms via HTTP probing
  * email permutation patterns
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from ..config import config
from ..net import fetch_json, fetch_text, run_bounded

GITHUB_HEADERS = {
    "Accept": "application/vnd.github.v3+json",
    "User-Agent": "pelican",
}
if config.github_token:
    GITHUB_HEADERS["Authorization"] = f"token {config.github_token}"

REDDIT_HEADERS = {"User-Agent": "pelican/0.1.0"}

USERNAME_PLATFORMS = [
    ("Twitter", "https://twitter.com/{}"),
    ("Facebook", "https://www.facebook.com/{}"),
    ("Instagram", "https://www.instagram.com/{}/"),
    ("Reddit", "https://www.reddit.com/user/{}"),
    ("YouTube", "https://www.youtube.com/@{}"),
    ("Pinterest", "https://www.pinterest.com/{}/"),
    ("GitHub", "https://www.github.com/{}"),
    ("Medium", "https://medium.com/@{}"),
    ("Dev.to", "https://dev.to/{}"),
    ("Keybase", "https://keybase.io/{}"),
    ("Steam", "https://steamcommunity.com/id/{}"),
    ("Twitch", "https://www.twitch.tv/{}"),
    ("SoundCloud", "https://soundcloud.com/{}"),
    ("GitLab", "https://gitlab.com/{}"),
    ("About.me", "https://about.me/{}"),
    ("SlideShare", "https://www.slideshare.net/{}"),
    ("WordPress", "https://{}.wordpress.com/"),
    ("Blogger", "https://{}.blogspot.com/"),
    ("Linktree", "https://linktr.ee/{}"),
    ("Venmo", "https://venmo.com/{}"),
]


async def github_user_info(username: str) -> dict[str, Any]:
    """Get public GitHub profile metadata for a user.

    Args:
        username: GitHub username.

    Returns:
        Profile fields: name, bio, location, followers, repos, created date, etc.
    """
    try:
        data = await fetch_json(
            f"https://api.github.com/users/{username}", headers=GITHUB_HEADERS
        )
        if "login" not in data:
            return {"username": username, "found": False}
        return {
            "found": True,
            "username": data.get("login"),
            "name": data.get("name"),
            "bio": data.get("bio"),
            "company": data.get("company"),
            "location": data.get("location"),
            "blog": data.get("blog"),
            "email": data.get("email"),
            "followers": data.get("followers"),
            "following": data.get("following"),
            "public_repos": data.get("public_repos"),
            "created_at": data.get("created_at"),
            "profile_url": data.get("html_url"),
        }
    except Exception as exc:  # noqa: BLE001
        code = getattr(getattr(exc, "response", None), "status_code", None)
        if code in (404,):
            return {"username": username, "found": False}
        return {"username": username, "error": str(exc)}


async def github_user_repos(username: str) -> dict[str, Any]:
    """List public repositories for a GitHub user.

    Args:
        username: GitHub username.

    Returns:
        Repo name, description, language, stars, fork status, updated date.
    """
    try:
        data = await fetch_json(
            f"https://api.github.com/users/{username}/repos",
            headers=GITHUB_HEADERS,
            params={"per_page": 100, "sort": "updated"},
        )
        repos = [
            {
                "name": r.get("name"),
                "description": r.get("description"),
                "language": r.get("language"),
                "stargazers_count": r.get("stargazers_count"),
                "forks_count": r.get("forks_count"),
                "fork": r.get("fork"),
                "updated_at": r.get("updated_at"),
                "url": r.get("html_url"),
            }
            for r in data
        ]
        return {"username": username, "count": len(repos), "repos": repos}
    except Exception as exc:  # noqa: BLE001
        return {"username": username, "error": str(exc)}


async def github_commit_emails(username: str) -> dict[str, Any]:
    """Extract emails from a user's public GitHub events.

    Args:
        username: GitHub username.

    Returns:
        Deduplicated list of non-noreply email addresses.
    """
    try:
        events = await fetch_json(
            f"https://api.github.com/users/{username}/events/public",
            headers=GITHUB_HEADERS,
        )
        emails: set[str] = set()
        for event in events:
            if event.get("type") == "PushEvent":
                for commit in (event.get("payload") or {}).get("commits") or []:
                    author = commit.get("author") or {}
                    if author.get("email") and "noreply" not in author["email"]:
                        emails.add(author["email"])
        return {"username": username, "count": len(emails), "emails": sorted(emails)}
    except Exception as exc:  # noqa: BLE001
        return {"username": username, "error": str(exc)}


async def github_repo_commits(owner: str, repo: str) -> dict[str, Any]:
    """Extract committer emails from a repo's recent commit history.

    Args:
        owner: repo owner (user or org).
        repo: repository name.

    Returns:
        Deduplicated list of non-noreply emails.
    """
    try:
        commits = await fetch_json(
            f"https://api.github.com/repos/{owner}/{repo}/commits",
            headers=GITHUB_HEADERS,
            params={"per_page": 50},
        )
        emails: set[str] = set()
        for c in commits:
            for field in ("author", "committer"):
                person = (c.get("commit") or {}).get(field) or {}
                if person.get("email") and "noreply" not in person["email"]:
                    emails.add(person["email"])
        return {"repo": f"{owner}/{repo}", "count": len(emails), "emails": sorted(emails)}
    except Exception as exc:  # noqa: BLE001
        return {"repo": f"{owner}/{repo}", "error": str(exc)}


async def reddit_user(username: str) -> dict[str, Any]:
    """Get public Reddit profile metadata.

    Args:
        username: Reddit username (without u/).

    Returns:
        Account age, karma breakdown, mod status, publicly set description.
    """
    try:
        data = await fetch_json(
            f"https://www.reddit.com/user/{username}/about.json",
            headers=REDDIT_HEADERS,
        )
        if "data" not in data:
            return {"username": username, "found": False}
        user = data["data"]
        return {
            "found": True,
            "username": user.get("name") or data.get("name"),
            "id": user.get("id"),
            "created_utc": user.get("created_utc"),
            "karma_total": user.get("total_karma"),
            "karma_link": user.get("link_karma"),
            "karma_comment": user.get("comment_karma"),
            "is_mod": user.get("is_mod"),
            "has_verified_email": user.get("has_verified_email"),
            "description": user.get("public_description"),
        }
    except Exception as exc:  # noqa: BLE001
        code = getattr(getattr(exc, "response", None), "status_code", None)
        if code in (403,):
            return {"username": username, "error": "Reddit blocked the request (403). Reddit now requires authentication for this endpoint."}
        if code in (404,):
            return {"username": username, "found": False}
        return {"username": username, "error": str(exc)}


async def reddit_user_posts(username: str, limit: int = 25) -> dict[str, Any]:
    """List a Reddit user's recent public posts.

    Args:
        username: Reddit username.
        limit: max posts (default 25).

    Returns:
        Post title, subreddit, permalink, created date, score.
    """
    try:
        data = await fetch_json(
            f"https://www.reddit.com/user/{username}/submitted.json",
            headers=REDDIT_HEADERS,
            params={"limit": limit},
        )
        children = (data.get("data") or {}).get("children") or []
        posts = [
            {
                "title": p["data"].get("title"),
                "subreddit": p["data"].get("subreddit"),
                "url": f"https://reddit.com{ p['data'].get('permalink') }",
                "created_utc": p["data"].get("created_utc"),
                "score": p["data"].get("score"),
            }
            for p in children
        ]
        return {"username": username, "count": len(posts), "posts": posts}
    except Exception as exc:  # noqa: BLE001
        return {"username": username, "error": str(exc)}


async def keybase_lookup(username: str) -> dict[str, Any]:
    """Look up a Keybase user and their linked social accounts / public keys.

    Args:
        username: Keybase username.

    Returns:
        Profile info plus linked account proofs (Twitter, GitHub, etc.) and keys.
    """
    try:
        data = await fetch_json(
            "https://keybase.io/_/api/1.0/user/lookup.json",
            params={"usernames": username},
        )
        them = data.get("them") or []
        user = them[0] if them and isinstance(them[0], dict) else None
        if user is None:
            return {"username": username, "found": False}
        proofs = []
        for p in (user.get("proofs_summary") or {}).get("all") or []:
            proofs.append({
                "type": p.get("proof_type"),
                "username": p.get("nametag"),
                "url": p.get("service_url"),
                "state": p.get("state"),
            })
        profile = user.get("profile") or {}
        return {
            "found": True,
            "id": user.get("id"),
            "username": (user.get("basics") or {}).get("username"),
            "full_name": profile.get("full_name"),
            "location": profile.get("location"),
            "bio": profile.get("bio"),
            "linked_accounts": proofs,
            "public_keys": user.get("public_keys"),
        }
    except Exception as exc:  # noqa: BLE001
        return {"username": username, "error": str(exc)}


async def username_enumerate(username: str) -> dict[str, Any]:
    """Probe ~20 major platforms to see if a username is taken.

    Borrowed from CloudWaddie/osint-mcp (MIT) username search. Uses small
    parallel batches with a timeout to avoid being rate-limited. A 200
    response is treated as "found"; non-200/errors are treated as not found.

    Args:
        username: the username/handle to search.

    Returns:
        List of platforms where the username appears to exist with URLs.
    """
    import httpx

    found: list[dict[str, str]] = []

    async def check(platform: str, template: str) -> None:
        url = template.format(username)
        try:
            async with httpx.AsyncClient(
                timeout=6.0,
                follow_redirects=False,
                headers={
                    "User-Agent": (
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/91.0.4472.124 Safari/537.36"
                    )
                },
            ) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    found.append({"platform": platform, "url": url})
        except Exception:  # noqa: BLE001
            pass

    # Concurrency limit of 5, batched like the TS original.
    batch_size = 5
    for i in range(0, len(USERNAME_PLATFORMS), batch_size):
        batch = USERNAME_PLATFORMS[i : i + batch_size]
        await run_bounded([check(*p) for p in batch], limit=batch_size)

    return {
        "username": username,
        "total_found": len(found),
        "found": found,
        "platforms_checked": len(USERNAME_PLATFORMS),
    }


def email_permutations(first_name: str, last_name: str, domain: str) -> dict[str, Any]:
    """Generate common corporate email address permutations.

    Borrowed from CloudWaddie/osint-mcp (MIT) email permutation patterns.

    Args:
        first_name: person's first name.
        last_name: person's last name.
        domain: corporate domain (e.g. "acme.com").

    Returns:
        Deduplicated list of possible email addresses.
    """
    fn = first_name.lower().strip()
    ln = last_name.lower().strip()
    if not fn or not ln:
        return {"error": "first_name and last_name are required"}
    fi, li = fn[0], ln[0]
    d = domain.lower().strip()
    patterns = [
        f"{fn}@{d}", f"{ln}@{d}", f"{fn}.{ln}@{d}", f"{fn}{ln}@{d}",
        f"{fi}{ln}@{d}", f"{fi}.{ln}@{d}", f"{fn}{li}@{d}", f"{fn}.{li}@{d}",
        f"{fi}{li}@{d}", f"{fi}.{li}@{d}", f"{ln}.{fn}@{d}", f"{ln}{fn}@{d}",
        f"{ln}{fi}@{d}", f"{ln}.{fi}@{d}", f"{fn}-{ln}@{d}", f"{fi}-{ln}@{d}",
        f"{fn}-{li}@{d}", f"{fi}-{li}@{d}", f"{fn}_{ln}@{d}", f"{fi}_{ln}@{d}",
        f"{fn}_{li}@{d}", f"{fi}_{li}@{d}",
    ]
    return {"domain": d, "count": len(set(patterns)), "permutations": sorted(set(patterns))}


def _email_md5(email: str) -> str:
    return hashlib.md5(email.strip().lower().encode()).hexdigest()


async def gravatar_lookup(email: str) -> dict[str, Any]:
    """Look up the public Gravatar profile associated with an email address.

    Borrowed from CloudWaddie/osint-mcp (MIT) email_social_check concept.
    Hashes the email with MD5 (Gravatar's scheme) and queries the profile API.

    Args:
        email: the email address to look up.

    Returns:
        Display name, preferred username, profile URL, location and links.
    """
    digest = _email_md5(email)
    try:
        data = await fetch_json(
            f"https://gravatar.com/{digest}.json",
            headers={"User-Agent": "pelican/0.1.0"},
        )
        entry = (data.get("entry") or [{}])[0]
        if not entry:
            return {"email": email, "found": False}
        name = entry.get("displayName") or entry.get("preferredUsername")
        return {
            "email": email,
            "found": True,
            "display_name": name,
            "profile_url": entry.get("profileUrl"),
            "location": entry.get("currentLocation"),
            "about": entry.get("aboutMe"),
            "accounts": entry.get("accounts") or [],
        }
    except Exception as exc:  # noqa: BLE001
        return {"email": email, "found": False, "detail": str(exc)}


EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")


async def domain_email_search(domain: str) -> dict[str, Any]:
    """Heuristic: scrape a domain's public pages for exposed email addresses.

    Borrowed from CloudWaddie/osint-mcp (MIT) domain email search which pulls
    HackerTarget hostsearch output and regexes out emails.

    Args:
        domain: the domain to scan.

    Returns:
        Deduplicated list of emails found and where they were seen.
    """
    from .domain import hackertarget_hostsearch

    emails: set[str] = set()
    origins: dict[str, list[str]] = {}
    try:
        res = await hackertarget_hostsearch(domain)
        for host in res.get("hosts") or []:
            url = f"http://{host['host']}"
            try:
                body = await fetch_text(url, timeout=8.0)
                for m in EMAIL_RE.findall(body):
                    emails.add(m)
                    origins.setdefault(m, []).append(host["host"])
                    if len(origins[m]) > 5:
                        origins[m] = origins[m][:5]
            except Exception:  # noqa: BLE001
                continue
    except Exception:  # noqa: BLE001
        pass
    return {
        "domain": domain,
        "count": len(emails),
        "emails": sorted(emails),
        "sources": origins,
    }
