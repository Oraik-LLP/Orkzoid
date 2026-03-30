"""
discoverer.py — API Endpoint Discovery Module
===============================================
Discovers API endpoints through multiple techniques:
  - Wordlist brute-force (common API paths)
  - HTML/JS bundle crawling (regex for fetch/axios/XHR calls)
  - Wayback Machine CDX API (historical URL discovery)
  - DNS subdomain enumeration
"""

import re
import os
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


class APIDiscoverer:
    """
    Discovers API endpoints on a target domain using
    multiple discovery techniques.
    """

    def __init__(self, timeout: int = 5, wordlist_path: str | None = None):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/json,*/*",
        })
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
                f"[dim]Timeout: {self.timeout}s | Wordlist: {len(self.wordlist)} paths[/dim]",
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

            # Use thread pool for concurrent requests
            with ThreadPoolExecutor(max_workers=10) as executor:
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
