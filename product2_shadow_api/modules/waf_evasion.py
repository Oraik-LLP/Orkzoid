"""
waf_evasion.py — WAF / Rate-Limit Evasion Utilities
=====================================================
Provides:
  - A pool of realistic browser User-Agent strings (Chrome, Safari, Firefox, Edge)
  - Random delay injection between requests
  - A session factory that rotates UA per request via a Transport Adapter hook

All HTTP-making modules (discoverer, auditor) should use `create_evasion_session()`
instead of building a bare `requests.Session()`.
"""

import random
import time
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from rich.console import Console

console = Console()

# ─── User-Agent Pool ──────────────────────────────────────────────
# Realistic, recent browser UAs across multiple OS/browser combos
USER_AGENT_POOL = [
    # Chrome — Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",

    # Chrome — macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",

    # Chrome — Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",

    # Safari — macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.3 Safari/605.1.15",

    # Safari — iPhone
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",

    # Firefox — Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",

    # Firefox — macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125.0",

    # Firefox — Linux
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",

    # Edge — Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
]

# Common Accept headers matched to typical browser behavior
ACCEPT_HEADERS_POOL = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "application/json, text/plain, */*",
]

ACCEPT_LANGUAGE_POOL = [
    "en-US,en;q=0.9",
    "en-US,en;q=0.9,es;q=0.8",
    "en-GB,en;q=0.9,en-US;q=0.8",
    "en-US,en;q=0.5",
]


def get_random_user_agent() -> str:
    """Return a random User-Agent string from the pool."""
    return random.choice(USER_AGENT_POOL)


def get_random_headers() -> dict:
    """Return a full set of realistic, randomized browser headers."""
    return {
        "User-Agent": get_random_user_agent(),
        "Accept": random.choice(ACCEPT_HEADERS_POOL),
        "Accept-Language": random.choice(ACCEPT_LANGUAGE_POOL),
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": random.choice(["document", "empty"]),
        "Sec-Fetch-Mode": random.choice(["navigate", "cors", "no-cors"]),
        "Sec-Fetch-Site": random.choice(["none", "same-origin", "cross-site"]),
    }


def random_delay(min_seconds: float = 0.3, max_seconds: float = 1.5) -> None:
    """
    Sleep for a random duration between min_seconds and max_seconds.
    Adds jitter so request timing doesn't look automated.
    """
    delay = random.uniform(min_seconds, max_seconds)
    time.sleep(delay)


class RotatingUserAgentAdapter(HTTPAdapter):
    """
    Requests Transport Adapter that injects a fresh, random
    User-Agent header on every outgoing request.
    """

    def send(self, request, *args, **kwargs):
        # Rotate User-Agent on every single request
        request.headers["User-Agent"] = get_random_user_agent()
        # Also rotate Accept-Language for extra fingerprint diversity
        request.headers["Accept-Language"] = random.choice(ACCEPT_LANGUAGE_POOL)
        return super().send(request, *args, **kwargs)


def create_evasion_session() -> requests.Session:
    """
    Build a requests.Session pre-configured for WAF evasion:
      - Realistic initial headers
      - Auto-rotating User-Agent per request (via adapter)
      - Automatic retries on 429 / 503

    Usage:
        session = create_evasion_session()
        resp = session.get("https://target.com/api/v1/users")
    """
    session = requests.Session()

    # Set realistic default headers
    session.headers.update(get_random_headers())

    # Mount the rotating-UA adapter for both http and https
    adapter = RotatingUserAgentAdapter(
        max_retries=requests.adapters.Retry(
            total=3,
            backoff_factor=1.0,
            status_forcelist=[429, 503],
            allowed_methods=["GET", "HEAD", "OPTIONS"],
        )
    )
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    return session
