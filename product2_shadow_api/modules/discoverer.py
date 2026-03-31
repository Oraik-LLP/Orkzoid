"""
discoverer.py — API Endpoint Discovery Module
===============================================
Discovers API endpoints through multiple techniques:
  - Wordlist brute-force (common API paths)
  - HTML/JS bundle crawling (regex for fetch/axios/XHR calls)
  - Wayback Machine CDX API (historical URL discovery)
  - DNS subdomain enumeration
  - Deep JS route extraction (framework-specific patterns, source maps, webpack chunks)

WAF Evasion:
  - Rotates User-Agent headers per request (Chrome/Safari/Firefox/Edge)
  - Injects random delays between requests to avoid rate-limit bans
"""

import re
import os
import time
import random
import requests
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

import dns.resolver
import dns.exception
from bs4 import BeautifulSoup
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich.panel import Panel

from modules.waf_evasion import create_evasion_session, random_delay, get_random_user_agent

console = Console()

# Regex patterns for extracting API endpoints from JS/HTML
JS_ENDPOINT_PATTERNS = [
    # fetch() calls
    r"""fetch\s*\(\s*['"`]([^'"`\s]+)['"`]""",
    # axios calls
    r"""axios\.\w+\s*\(\s*['"`]([^'"`\s]+)['"`]""",
    # XMLHttpRequest.open()
    r"""\.open\s*\(\s*['"`]\w+['"`]\s*,\s*['"`]([^'"`\s]+)['"`]""",
    # jQuery AJAX
    r"""\$\.(ajax|get|post)\s*\(\s*['"`]([^'"`\s]+)['"`]""",
    # URL patterns in strings that look like API paths
    r"""['"`](\/api\/[^'"`\s]+)['"`]""",
    r"""['"`](\/v\d+\/[^'"`\s]+)['"`]""",
    r"""['"`](\/graphql[^'"`\s]*)['"`]""",
    # Common REST patterns
    r"""['"`](\/rest\/[^'"`\s]+)['"`]""",
    r"""['"`](\/admin\/[^'"`\s]+)['"`]""",
]

# Wayback Machine CDX API
WAYBACK_CDX_API = "https://web.archive.org/cdx/search/cdx"

# Common subdomains to enumerate
SUBDOMAIN_WORDLIST = [
    "api", "api2", "api3", "dev", "dev-api", "staging", "staging-api",
    "test", "test-api", "beta", "beta-api", "internal", "admin",
    "dashboard", "portal", "app", "mobile", "m", "gateway",
    "auth", "login", "sso", "oauth", "graphql", "ws", "websocket",
    "cdn", "static", "assets", "media", "docs", "swagger",
    "v1", "v2", "v3", "sandbox", "demo", "preview",
]


# ─── Deep JS Route Extraction Patterns ───────────────────────────
# Framework-specific patterns to extract API routes from JS bundles
DEEP_JS_ROUTE_PATTERNS = [
    # React Router / Next.js route definitions
    r"""path\s*:\s*['"`](\/[^'"`\s]{2,})['"`]""",
    # Vue Router route definitions
    r"""(?:path|redirect)\s*:\s*['"`](\/[^'"`\s]{2,})['"`]""",
    # Express-style route handlers
    r"""(?:router|app)\.(?:get|post|put|patch|delete|all)\s*\(\s*['"`](\/[^'"`\s]{2,})['"`]""",
    # Angular HttpClient
    r"""(?:http|this\.http)\.(?:get|post|put|delete|patch)\s*[<(]\s*['"`]([^'"`\s]{2,})['"`]""",
    # Template literal URLs with base path
    r"""\$\{[^}]*\}(\/api\/[^`\s]{2,})""",
    r"""\$\{[^}]*\}(\/v\d+\/[^`\s]{2,})""",
    # Webpack chunk/module references pointing to API paths
    r"""__webpack_require__\s*\(\s*['"]([^'"]+\/api[^'"]*)['"]\)""",
    # Generic URL path assignment patterns
    r"""(?:url|endpoint|baseUrl|apiUrl|API_URL|BASE_URL|apiBase|baseAPI)\s*[:=]\s*['"`]([^'"`\s]{2,})['"`]""",
    # String concatenation building API paths
    r"""['"`](\/[a-zA-Z0-9_\-]+(?:\/[a-zA-Z0-9_\-:]+){2,})['"`]""",
    # GraphQL operation names and endpoints
    r"""(?:mutation|query|subscription)\s+([A-Z][a-zA-Z]+)""",
    # API gateway / proxy routes
    r"""(?:proxy|gateway|redirect)\s*[:=]\s*['"`]([^'"`\s]+)['"`]""",
]

# File extensions to deep-crawl for route info
JS_CRAWL_EXTENSIONS = (
    ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx",
    ".js.map", ".chunk.js", ".bundle.js",
)


class APIDiscoverer:
    """
    Discovers API endpoints on a target domain using
    multiple discovery techniques.

    WAF Evasion:
      - Uses rotating User-Agent headers (Chrome, Safari, Firefox, Edge)
      - Adds random delays between requests to avoid rate-limit bans
    """

    def __init__(self, timeout: int = 5, wordlist_path: str | None = None):
        self.timeout = timeout

        # Use evasion-aware session with rotating User-Agent
        self.session = create_evasion_session()
        self.discovered_endpoints = []
        self.subdomains = []

        # Load wordlist
        if wordlist_path and os.path.isfile(wordlist_path):
            self.wordlist = self._load_wordlist(wordlist_path)
        else:
            # Use default wordlist
            default_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                "..", "wordlists", "api_paths.txt"
            )
            if os.path.isfile(default_path):
                self.wordlist = self._load_wordlist(default_path)
            else:
                self.wordlist = self._get_builtin_wordlist()

    def _load_wordlist(self, path: str) -> list[str]:
        """Load API paths from a wordlist file."""
        try:
            with open(path, "r", encoding="utf-8") as f:
                paths = [
                    line.strip()
                    for line in f
                    if line.strip() and not line.startswith("#")
                ]
            console.print(f"[green]✓ Loaded {len(paths)} paths from wordlist[/green]")
            return paths
        except Exception as e:
            console.print(f"[yellow]⚠ Failed to load wordlist: {e}[/yellow]")
            return self._get_builtin_wordlist()

    def _get_builtin_wordlist(self) -> list[str]:
        """Return a built-in minimal wordlist as fallback."""
        return [
            "/api", "/api/v1", "/api/v2", "/api/v3",
            "/graphql", "/admin", "/admin/api",
            "/rest", "/rest/v1", "/swagger", "/docs",
            "/health", "/status", "/metrics",
            "/.env", "/config", "/debug",
        ]

    def discover(self, target: str) -> list[dict]:
        """
        Run all discovery techniques against the target domain.

        Args:
            target: Target domain (e.g., 'example.com')

        Returns:
            List of discovered endpoint dictionaries.
        """
        self.discovered_endpoints = []

        # Normalize target
        if not target.startswith(("http://", "https://")):
            base_url = f"https://{target}"
        else:
            base_url = target
            target = urlparse(target).netloc

        console.print(
            Panel(
                f"[bold cyan]🔍 Discovering API endpoints on:[/bold cyan] [white]{target}[/white]\n"
                f"[dim]Timeout: {self.timeout}s | Wordlist: {len(self.wordlist)} paths[/dim]\n"
                f"[dim green]🛡 WAF Evasion: User-Agent rotation + random delays active[/dim green]",
                title="[bold green]API Discovery[/bold green]",
                border_style="green",
            )
        )

        # ─── Technique 1: Wordlist Brute-Force ───────────────────────
        console.rule("[dim]Technique 1: Wordlist Brute-Force[/dim]")
        self._wordlist_bruteforce(base_url)

        # ─── Technique 2: HTML/JS Crawling ───────────────────────────
        console.rule("[dim]Technique 2: HTML/JS Bundle Crawling[/dim]")
        self._crawl_js_bundles(base_url)

        # ─── Technique 3: Wayback Machine ────────────────────────────
        console.rule("[dim]Technique 3: Wayback Machine Historical URLs[/dim]")
        self._wayback_discovery(target)

        # ─── Technique 4: DNS Subdomain Enumeration ──────────────────
        console.rule("[dim]Technique 4: DNS Subdomain Enumeration[/dim]")
        self._dns_enumeration(target)

        # ─── Technique 5: Deep JS Route Extraction ───────────────────
        console.rule("[dim]Technique 5: Deep JS Route Extraction (beyond wordlist)[/dim]")
        self._deep_js_route_extraction(base_url)

        # Deduplicate results
        self._deduplicate()

        # Display results
        self._display_results()

        return self.discovered_endpoints

    def _wordlist_bruteforce(self, base_url: str):
        """Brute-force common API paths from the wordlist."""
        found = 0

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("[cyan]Brute-forcing paths...", total=len(self.wordlist))

            # Use thread pool for concurrent requests (limited to avoid WAF triggers)
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = {}
                for path in self.wordlist:
                    url = urljoin(base_url, path)
                    future = executor.submit(self._probe_url, url)
                    futures[future] = path

                for future in as_completed(futures):
                    path = futures[future]
                    progress.update(task, advance=1)

                    result = future.result()
                    if result:
                        self.discovered_endpoints.append(result)
                        found += 1
                        progress.update(
                            task,
                            description=f"[green]Found: {path} ({result['status_code']})",
                        )

        console.print(f"[green]✓ Wordlist scan found {found} endpoint(s)[/green]")

    def _probe_url(self, url: str) -> dict | None:
        """
        Probe a single URL and return info if it responds.
        Returns None for dead endpoints (404, connection errors).
        """
        try:
            # Random delay to avoid triggering WAF/rate-limits on target
            random_delay(min_seconds=0.3, max_seconds=1.2)
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=False)

            # Consider valid responses: anything that isn't 404 or connection failure
            if resp.status_code != 404:
                content_type = resp.headers.get("Content-Type", "unknown")
                return {
                    "url": url,
                    "path": urlparse(url).path,
                    "status_code": resp.status_code,
                    "content_type": content_type,
                    "content_length": len(resp.content),
                    "discovery_method": "wordlist",
                    "headers": dict(resp.headers),
                    "response_snippet": resp.text[:500] if resp.text else "",
                }
        except requests.RequestException:
            pass

        return None

    def _crawl_js_bundles(self, base_url: str):
        """Crawl page HTML and JS bundles for API endpoint references."""
        found = 0

        try:
            # First, get the main page
            resp = self.session.get(base_url, timeout=self.timeout)
            if resp.status_code != 200:
                console.print(f"[yellow]⚠ Main page returned {resp.status_code}[/yellow]")
                return

            soup = BeautifulSoup(resp.text, "lxml")

            # Extract endpoints from inline scripts and HTML
            endpoints_from_html = self._extract_endpoints_from_text(resp.text, base_url)
            found += len(endpoints_from_html)

            # Find all JS sources
            script_tags = soup.find_all("script", src=True)
            js_urls = [urljoin(base_url, tag["src"]) for tag in script_tags]

            # Also look for common JS bundle patterns
            for link in soup.find_all("link", href=True):
                href = link["href"]
                if href.endswith((".js", ".mjs")):
                    js_urls.append(urljoin(base_url, href))

            console.print(f"[dim]Found {len(js_urls)} JS file(s) to analyze[/dim]")

            # Download and scan each JS file
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TimeElapsedColumn(),
                console=console,
            ) as progress:
                task = progress.add_task("[cyan]Scanning JS bundles...", total=len(js_urls))

                for js_url in js_urls:
                    try:
                        # Random delay between JS fetches to avoid WAF triggers
                        random_delay(min_seconds=0.2, max_seconds=0.8)
                        js_resp = self.session.get(js_url, timeout=self.timeout)
                        if js_resp.status_code == 200:
                            endpoints = self._extract_endpoints_from_text(js_resp.text, base_url)
                            found += len(endpoints)
                    except requests.RequestException:
                        pass

                    progress.update(task, advance=1)

        except requests.RequestException as e:
            console.print(f"[yellow]⚠ Failed to crawl {base_url}: {e}[/yellow]")

        console.print(f"[green]✓ JS crawling found {found} endpoint reference(s)[/green]")

    def _extract_endpoints_from_text(self, text: str, base_url: str) -> list[dict]:
        """Extract API endpoints from text using regex patterns."""
        found = []
        seen_paths = set()

        for pattern in JS_ENDPOINT_PATTERNS:
            matches = re.findall(pattern, text)
            for match in matches:
                # Handle tuple matches from multi-group patterns
                path = match[-1] if isinstance(match, tuple) else match

                # Clean and validate the path
                path = path.strip()
                if not path or path in seen_paths:
                    continue
                if len(path) < 2 or len(path) > 200:
                    continue

                seen_paths.add(path)

                # Build full URL
                if path.startswith(("http://", "https://")):
                    url = path
                else:
                    url = urljoin(base_url, path)

                endpoint = {
                    "url": url,
                    "path": path,
                    "status_code": None,  # Not probed yet
                    "content_type": "unknown",
                    "content_length": 0,
                    "discovery_method": "js_crawl",
                    "headers": {},
                    "response_snippet": "",
                }
                self.discovered_endpoints.append(endpoint)
                found.append(endpoint)

        return found

    def _wayback_discovery(self, domain: str):
        """Query Wayback Machine CDX API for historical API-related URLs."""
        found = 0

        try:
            params = {
                "url": f"*.{domain}/*",
                "output": "json",
                "fl": "original,statuscode,mimetype",
                "filter": "statuscode:200",
                "limit": 500,
                "collapse": "urlkey",
            }

            console.print("[dim]Querying Wayback Machine CDX API...[/dim]")
            resp = self.session.get(WAYBACK_CDX_API, params=params, timeout=self.timeout * 3)

            if resp.status_code != 200:
                console.print(f"[yellow]⚠ Wayback API returned {resp.status_code}. Skipping.[/yellow]")
                return

            data = resp.json()
            if not data or len(data) < 2:
                console.print("[yellow]⚠ No historical URLs found in Wayback Machine.[/yellow]")
                return

            # First row is headers, rest are data
            headers = data[0]
            rows = data[1:]

            # Filter for API-like paths
            api_patterns = [
                "/api/", "/v1/", "/v2/", "/v3/", "/rest/",
                "/graphql", "/admin/", "/auth/", "/oauth/",
                "/swagger", "/openapi", "/.env", "/config",
                "/debug/", "/internal/", "/health", "/status",
            ]

            for row in rows:
                if len(row) < 3:
                    continue

                url = row[0]
                parsed = urlparse(url)
                path = parsed.path.lower()

                # Check if the URL looks like an API endpoint
                if any(p in path for p in api_patterns):
                    endpoint = {
                        "url": url,
                        "path": parsed.path,
                        "status_code": None,
                        "content_type": row[2] if len(row) > 2 else "unknown",
                        "content_length": 0,
                        "discovery_method": "wayback",
                        "headers": {},
                        "response_snippet": "",
                    }
                    self.discovered_endpoints.append(endpoint)
                    found += 1

        except requests.RequestException as e:
            console.print(f"[yellow]⚠ Wayback Machine unreachable: {e}. Skipping (offline mode).[/yellow]")
        except (ValueError, KeyError):
            console.print("[yellow]⚠ Failed to parse Wayback response.[/yellow]")

        console.print(f"[green]✓ Wayback Machine found {found} historical API endpoint(s)[/green]")

    def _dns_enumeration(self, domain: str):
        """Enumerate subdomains via DNS queries."""
        found = 0

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task(
                "[cyan]Enumerating subdomains...",
                total=len(SUBDOMAIN_WORDLIST),
            )

            for subdomain in SUBDOMAIN_WORDLIST:
                fqdn = f"{subdomain}.{domain}"
                try:
                    answers = dns.resolver.resolve(fqdn, "A")
                    if answers:
                        ips = [str(rdata) for rdata in answers]
                        self.subdomains.append({
                            "subdomain": fqdn,
                            "ips": ips,
                        })
                        found += 1

                        # Add as discovered endpoint
                        endpoint = {
                            "url": f"https://{fqdn}",
                            "path": "/",
                            "status_code": None,
                            "content_type": "subdomain",
                            "content_length": 0,
                            "discovery_method": "dns",
                            "headers": {},
                            "response_snippet": f"Resolved to: {', '.join(ips)}",
                        }
                        self.discovered_endpoints.append(endpoint)

                        progress.update(
                            task,
                            description=f"[green]Found: {fqdn} → {', '.join(ips)}",
                        )

                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                    pass
                except dns.exception.Timeout:
                    pass
                except Exception:
                    pass

                progress.update(task, advance=1)

        console.print(f"[green]✓ DNS enumeration found {found} subdomain(s)[/green]")

    # ─── Technique 5: Deep JS Route Extraction ────────────────────
    def _deep_js_route_extraction(self, base_url: str):
        """
        Go beyond the wordlist: dynamically crawl the site's JavaScript
        files to extract hidden API routes that aren't in standard
        dictionaries.

        This technique:
          1. Fetches the main page and extracts ALL linked JS resources
          2. Follows webpack chunk manifests and source maps
          3. Applies framework-specific regex (React Router, Vue Router,
             Express, Angular) to extract route definitions
          4. Mines generic path-like strings for undocumented endpoints
          5. Optionally probes discovered routes to verify they're live
        """
        found = 0
        js_urls_to_scan = set()
        seen_js = set()

        try:
            # Step 1: Fetch main page and collect all JS/asset URLs
            random_delay(min_seconds=0.3, max_seconds=1.0)
            resp = self.session.get(base_url, timeout=self.timeout)
            if resp.status_code != 200:
                console.print(f"[yellow]⚠ Main page returned {resp.status_code}, skipping deep JS extraction[/yellow]")
                return

            soup = BeautifulSoup(resp.text, "lxml")

            # Collect <script src="..."> tags
            for tag in soup.find_all("script", src=True):
                js_url = urljoin(base_url, tag["src"])
                js_urls_to_scan.add(js_url)

            # Collect <link href="...js"> (preloads, modulepreloads)
            for link in soup.find_all("link", href=True):
                href = link["href"]
                if any(href.endswith(ext) for ext in JS_CRAWL_EXTENSIONS):
                    js_urls_to_scan.add(urljoin(base_url, href))

            # Look for webpack chunk manifest patterns in inline scripts
            for script in soup.find_all("script", src=False):
                if script.string:
                    # Extract dynamically-imported chunk URLs
                    chunk_pattern = r"""['"`]([^'"`]*(?:chunk|bundle|vendor|main|app)[^'"`]*\.(?:js|mjs))['"`]"""
                    chunks = re.findall(chunk_pattern, script.string, re.IGNORECASE)
                    for chunk_path in chunks:
                        if chunk_path.startswith(("http://", "https://")):
                            js_urls_to_scan.add(chunk_path)
                        else:
                            js_urls_to_scan.add(urljoin(base_url, chunk_path))

            console.print(f"[dim]Collected {len(js_urls_to_scan)} JS resource(s) for deep analysis[/dim]")

            if not js_urls_to_scan:
                console.print("[yellow]⚠ No JS files found for deep route extraction.[/yellow]")
                return

            # Step 2: Download and deeply analyze each JS file
            extracted_routes = set()

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TimeElapsedColumn(),
                console=console,
            ) as progress:
                task = progress.add_task(
                    "[cyan]Deep-scanning JS for hidden routes...",
                    total=len(js_urls_to_scan),
                )

                for js_url in js_urls_to_scan:
                    if js_url in seen_js:
                        progress.update(task, advance=1)
                        continue
                    seen_js.add(js_url)

                    try:
                        random_delay(min_seconds=0.3, max_seconds=1.0)
                        js_resp = self.session.get(js_url, timeout=self.timeout)

                        if js_resp.status_code == 200:
                            js_text = js_resp.text

                            # Apply deep extraction patterns
                            routes = self._extract_deep_routes(js_text)
                            extracted_routes.update(routes)

                            # Check for source map reference and follow it
                            sourcemap_url = self._find_sourcemap_url(js_text, js_url)
                            if sourcemap_url and sourcemap_url not in seen_js:
                                seen_js.add(sourcemap_url)
                                try:
                                    random_delay(min_seconds=0.2, max_seconds=0.7)
                                    map_resp = self.session.get(sourcemap_url, timeout=self.timeout)
                                    if map_resp.status_code == 200:
                                        map_routes = self._extract_deep_routes(map_resp.text)
                                        extracted_routes.update(map_routes)
                                        progress.update(
                                            task,
                                            description=f"[yellow]📦 Source map: +{len(map_routes)} routes",
                                        )
                                except requests.RequestException:
                                    pass

                            # Look for additional chunk URLs referenced in this JS
                            more_chunks = re.findall(
                                r"""['"`]([./]*(?:static|assets|chunks?|js)/[^'"`\s]+\.(?:js|mjs))['"`]""",
                                js_text,
                            )
                            for chunk_path in more_chunks[:20]:  # Limit to avoid rabbit holes
                                chunk_url = urljoin(js_url, chunk_path)
                                if chunk_url not in seen_js:
                                    js_urls_to_scan.add(chunk_url)

                    except requests.RequestException:
                        pass

                    progress.update(task, advance=1)

            # Step 3: Filter and add discovered routes as endpoints
            already_known = {ep["path"].lower().rstrip("/") for ep in self.discovered_endpoints}

            for route in extracted_routes:
                route_normalized = route.lower().rstrip("/")
                if route_normalized in already_known:
                    continue

                # Build full URL
                if route.startswith(("http://", "https://")):
                    url = route
                else:
                    url = urljoin(base_url, route)

                endpoint = {
                    "url": url,
                    "path": route,
                    "status_code": None,
                    "content_type": "unknown",
                    "content_length": 0,
                    "discovery_method": "deep_js",
                    "headers": {},
                    "response_snippet": "",
                }
                self.discovered_endpoints.append(endpoint)
                already_known.add(route_normalized)
                found += 1

            # Step 4: Optionally probe the newly discovered routes
            if found > 0:
                console.print(f"[dim]Probing {found} newly extracted route(s)...[/dim]")
                deep_endpoints = [
                    ep for ep in self.discovered_endpoints
                    if ep["discovery_method"] == "deep_js" and ep["status_code"] is None
                ]
                probed = 0
                for ep in deep_endpoints[:50]:  # Limit probing to top 50
                    probe_result = self._probe_url(ep["url"])
                    if probe_result:
                        ep.update(probe_result)
                        ep["discovery_method"] = "deep_js"  # Preserve method
                        probed += 1
                console.print(f"[dim]  {probed}/{len(deep_endpoints)} routes responded[/dim]")

        except requests.RequestException as e:
            console.print(f"[yellow]⚠ Deep JS extraction failed: {e}[/yellow]")

        console.print(f"[green]✓ Deep JS route extraction found {found} hidden route(s)[/green]")

    def _extract_deep_routes(self, text: str) -> set[str]:
        """
        Apply all deep JS route patterns to extract API paths from
        JavaScript source text.
        """
        routes = set()

        for pattern in DEEP_JS_ROUTE_PATTERNS:
            try:
                matches = re.findall(pattern, text, re.IGNORECASE)
                for match in matches:
                    path = match[-1] if isinstance(match, tuple) else match
                    path = path.strip()

                    # Validate: must look like a real path
                    if not path or len(path) < 2 or len(path) > 200:
                        continue

                    # Skip obvious non-paths (JS variables, CSS, etc.)
                    if any(x in path for x in [
                        ".css", ".png", ".jpg", ".svg", ".gif", ".ico",
                        ".woff", ".ttf", ".eot",
                        "node_modules", "webpack", "__proto__",
                        "function", "return", "const ", "var ",
                    ]):
                        continue

                    # Must start with / or be a full URL
                    if path.startswith("/"):
                        routes.add(path)
                    elif path.startswith(("http://", "https://")):
                        parsed = urlparse(path)
                        if parsed.path and len(parsed.path) > 1:
                            routes.add(parsed.path)

            except re.error:
                continue

        return routes

    def _find_sourcemap_url(self, js_text: str, js_url: str) -> str | None:
        """
        Look for a sourceMappingURL comment in JS content and resolve
        it to an absolute URL.
        """
        # //# sourceMappingURL=filename.js.map
        match = re.search(r"//[#@]\s*sourceMappingURL\s*=\s*(\S+)", js_text)
        if match:
            map_ref = match.group(1)
            if map_ref.startswith(("http://", "https://")):
                return map_ref
            elif map_ref.startswith("data:"):
                return None  # Inline source map, skip
            else:
                return urljoin(js_url, map_ref)
        return None

    def _deduplicate(self):
        """Remove duplicate endpoints based on URL."""
        seen = set()
        unique = []
        for ep in self.discovered_endpoints:
            url_normalized = ep["url"].rstrip("/").lower()
            if url_normalized not in seen:
                seen.add(url_normalized)
                unique.append(ep)
        self.discovered_endpoints = unique

    def _display_results(self):
        """Display all discovered endpoints in a rich table."""
        if not self.discovered_endpoints:
            console.print("[yellow]⚠ No endpoints discovered.[/yellow]")
            return

        table = Table(
            title=f"🔍 Discovered Endpoints ({len(self.discovered_endpoints)} total)",
            border_style="green",
            show_lines=True,
        )
        table.add_column("#", style="dim", justify="right", width=4)
        table.add_column("Method", style="magenta", width=10)
        table.add_column("URL", style="cyan", max_width=60)
        table.add_column("Status", justify="center", width=8)
        table.add_column("Content-Type", style="dim", max_width=25)

        # Group by discovery method
        method_colors = {
            "wordlist": "green",
            "js_crawl": "yellow",
            "wayback": "blue",
            "dns": "magenta",
            "deep_js": "bright_red",
        }

        for idx, ep in enumerate(self.discovered_endpoints[:100], 1):  # Show top 100
            method = ep["discovery_method"]
            method_color = method_colors.get(method, "white")

            status = str(ep.get("status_code", "—"))
            if ep.get("status_code"):
                if ep["status_code"] < 300:
                    status = f"[green]{status}[/green]"
                elif ep["status_code"] < 400:
                    status = f"[yellow]{status}[/yellow]"
                else:
                    status = f"[red]{status}[/red]"

            table.add_row(
                str(idx),
                f"[{method_color}]{method}[/{method_color}]",
                ep["url"],
                status,
                ep.get("content_type", "unknown")[:25],
            )

        console.print(table)

        # Summary by method
        method_counts = {}
        for ep in self.discovered_endpoints:
            m = ep["discovery_method"]
            method_counts[m] = method_counts.get(m, 0) + 1

        summary_parts = [f"[bold]{m}:[/bold] {c}" for m, c in sorted(method_counts.items())]
        console.print(f"\n[bold]Discovery breakdown:[/bold] {' | '.join(summary_parts)}\n")
