"""
auditor.py — API Security Auditor Module
==========================================
Audits discovered API endpoints for common security issues:
  - TLS/HTTPS enforcement
  - Authentication requirements (401/403 vs 200 on unauthenticated requests)
  - Rate limiting (X-RateLimit, Retry-After headers)
  - Sensitive data exposure (emails, API keys, tokens, PII patterns)

WAF Evasion:
  - Rotates User-Agent headers per request (Chrome/Safari/Firefox/Edge)
  - Injects random delays between requests to avoid rate-limit bans
"""

import re
import requests
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich.panel import Panel

from modules.waf_evasion import create_evasion_session, random_delay

console = Console()

# ─── Sensitive Data Patterns ──────────────────────────────────────
# Regex patterns to detect sensitive information in API responses
SENSITIVE_PATTERNS = {
    "email": {
        "pattern": r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
        "severity": "MEDIUM",
        "description": "Email address exposed",
    },
    "api_key": {
        "pattern": r"""(?:api[_\-]?key|apikey|api[_\-]?secret|api[_\-]?token)\s*[:=]\s*['"]?([a-zA-Z0-9\-_]{16,})['"]?""",
        "severity": "CRITICAL",
        "description": "API key/secret exposed",
    },
    "aws_key": {
        "pattern": r"(?:AKIA|ASIA)[A-Z0-9]{16}",
        "severity": "CRITICAL",
        "description": "AWS Access Key ID exposed",
    },
    "jwt_token": {
        "pattern": r"eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+",
        "severity": "HIGH",
        "description": "JWT token exposed",
    },
    "private_key": {
        "pattern": r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
        "severity": "CRITICAL",
        "description": "Private key exposed",
    },
    "password_field": {
        "pattern": r"""(?:password|passwd|pwd|secret)\s*[:=]\s*['"]?([^'"\s]{4,})['"]?""",
        "severity": "CRITICAL",
        "description": "Password/secret value exposed",
    },
    "credit_card": {
        "pattern": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
        "severity": "CRITICAL",
        "description": "Credit card number exposed",
    },
    "ssn": {
        "pattern": r"\b\d{3}-\d{2}-\d{4}\b",
        "severity": "CRITICAL",
        "description": "Possible SSN exposed",
    },
    "phone_number": {
        "pattern": r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
        "severity": "MEDIUM",
        "description": "Phone number exposed",
    },
    "ipv4_internal": {
        "pattern": r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
        "severity": "LOW",
        "description": "Internal IP address exposed",
    },
    "bearer_token": {
        "pattern": r"""(?:Bearer|bearer)\s+[a-zA-Z0-9\-_\.]+""",
        "severity": "HIGH",
        "description": "Bearer token exposed",
    },
    "github_token": {
        "pattern": r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}",
        "severity": "CRITICAL",
        "description": "GitHub token exposed",
    },
}

# Rate limit related headers to check
RATE_LIMIT_HEADERS = [
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "x-rate-limit-limit",
    "x-rate-limit-remaining",
    "x-rate-limit-reset",
    "retry-after",
    "ratelimit-limit",
    "ratelimit-remaining",
    "ratelimit-reset",
]


class APIAuditor:
    """
    Audits discovered API endpoints for security misconfigurations.
    """

    def __init__(self, timeout: int = 5):
        self.timeout = timeout

        # Use evasion-aware session with rotating User-Agent
        self.session = create_evasion_session()
        self.audit_results = []

    def audit(self, endpoints: list[dict]) -> list[dict]:
        """
        Audit all discovered endpoints for security issues.

        Args:
            endpoints: List of endpoint dicts from APIDiscoverer.discover()

        Returns:
            List of audit result dictionaries.
        """
        self.audit_results = []

        # Filter to only probe-able endpoints (skip DNS-only results)
        probe_endpoints = [
            ep for ep in endpoints
            if ep["url"].startswith(("http://", "https://"))
            and ep["discovery_method"] != "dns"
        ]

        if not probe_endpoints:
            console.print("[yellow]⚠ No endpoints to audit.[/yellow]")
            return self.audit_results

        console.print(
            Panel(
                f"[bold cyan]Auditing {len(probe_endpoints)} endpoint(s) for security issues[/bold cyan]\n"
                f"[dim]Checks: TLS, Auth, Rate-Limiting, Data Exposure[/dim]\n"
                f"[dim yellow]Note: TLS cert verification is disabled for scanning (verify=False)[/dim yellow]\n"
                f"[dim green]🛡 WAF Evasion: User-Agent rotation + random delays active[/dim green]",
                title="[bold red]Security Audit[/bold red]",
                border_style="red",
            )
        )

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("[cyan]Auditing endpoints...", total=len(probe_endpoints))

            # Use thread pool for concurrent auditing
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = {}
                for ep in probe_endpoints:
                    future = executor.submit(self._audit_endpoint, ep)
                    futures[future] = ep

                for future in as_completed(futures):
                    ep = futures[future]
                    try:
                        result = future.result()
                        if result:
                            self.audit_results.append(result)
                    except Exception as e:
                        console.print(f"[dim red]  ✗ Error auditing {ep['url']}: {e}[/dim red]")

                    progress.update(task, advance=1)

        # Display audit results
        self._display_results()

        return self.audit_results

    def _audit_endpoint(self, endpoint: dict) -> dict | None:
        """
        Perform all security checks on a single endpoint.
        Returns an audit result dictionary.
        """
        url = endpoint["url"]
        result = {
            "url": url,
            "path": endpoint.get("path", urlparse(url).path),
            "discovery_method": endpoint.get("discovery_method", "unknown"),
            "issues": [],
            "tls_enforced": None,
            "auth_required": None,
            "rate_limited": None,
            "sensitive_data": [],
            "status_code": None,
            "response_headers": {},
        }

        try:
            # Random delay to avoid triggering WAF/rate-limits
            random_delay(min_seconds=0.3, max_seconds=1.0)

            # Make an unauthenticated GET request
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=True, verify=False)
            result["status_code"] = resp.status_code
            result["response_headers"] = dict(resp.headers)

            # ─── Check 1: TLS/HTTPS Enforcement ──────────────────────
            self._check_tls(url, result)

            # ─── Check 2: Authentication ──────────────────────────────
            self._check_auth(resp, result)

            # ─── Check 3: Rate Limiting ───────────────────────────────
            self._check_rate_limit(resp, result)

            # ─── Check 4: Sensitive Data Exposure ─────────────────────
            self._check_sensitive_data(resp, result)

            # ─── Check 5: Security Headers ────────────────────────────
            self._check_security_headers(resp, result)

        except requests.exceptions.SSLError:
            result["issues"].append({
                "type": "TLS_ERROR",
                "severity": "HIGH",
                "description": "SSL/TLS certificate error — connection is not secure",
            })
            result["tls_enforced"] = False

        except requests.RequestException as e:
            result["issues"].append({
                "type": "CONNECTION_ERROR",
                "severity": "INFO",
                "description": f"Could not connect: {str(e)[:100]}",
            })

        return result

    def _check_tls(self, url: str, result: dict):
        """Check if HTTPS is enforced."""
        parsed = urlparse(url)

        if parsed.scheme == "https":
            result["tls_enforced"] = True
        else:
            result["tls_enforced"] = False
            result["issues"].append({
                "type": "NO_TLS",
                "severity": "HIGH",
                "description": "Endpoint served over HTTP without TLS encryption",
            })

        # Check if HTTP redirects to HTTPS
        if parsed.scheme == "http":
            try:
                http_url = url.replace("https://", "http://")
                resp = self.session.get(http_url, timeout=self.timeout, allow_redirects=False)
                if resp.status_code in (301, 302, 307, 308):
                    location = resp.headers.get("Location", "")
                    if location.startswith("https://"):
                        result["tls_enforced"] = True
                        # Remove the NO_TLS issue since it redirects
                        result["issues"] = [
                            i for i in result["issues"] if i["type"] != "NO_TLS"
                        ]
            except requests.RequestException:
                pass

    def _check_auth(self, resp: requests.Response, result: dict):
        """Check if authentication is required."""
        if resp.status_code in (401, 403):
            result["auth_required"] = True
        elif resp.status_code == 200:
            result["auth_required"] = False
            result["issues"].append({
                "type": "NO_AUTH",
                "severity": "MEDIUM",
                "description": "Endpoint returns 200 without authentication — data may be publicly accessible",
            })
        else:
            result["auth_required"] = None  # Indeterminate

    def _check_rate_limit(self, resp: requests.Response, result: dict):
        """Check for rate limiting headers."""
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        found_headers = {}
        for header in RATE_LIMIT_HEADERS:
            if header in headers_lower:
                found_headers[header] = headers_lower[header]

        if found_headers:
            result["rate_limited"] = True
        else:
            result["rate_limited"] = False
            result["issues"].append({
                "type": "NO_RATE_LIMIT",
                "severity": "MEDIUM",
                "description": "No rate limiting headers detected — vulnerable to brute-force/DoS",
            })

    def _check_sensitive_data(self, resp: requests.Response, result: dict):
        """Scan response body for sensitive data patterns."""
        if not resp.text:
            return

        body = resp.text[:50000]  # Limit scan to first 50KB

        for name, pattern_info in SENSITIVE_PATTERNS.items():
            matches = re.findall(pattern_info["pattern"], body, re.IGNORECASE)
            if matches:
                # Truncate matched values for safety
                sanitized_matches = [
                    m[:8] + "***" if len(m) > 8 else m[:4] + "***"
                    for m in (matches[:5] if isinstance(matches[0], str) else [str(m) for m in matches[:5]])
                ]

                result["sensitive_data"].append({
                    "type": name,
                    "severity": pattern_info["severity"],
                    "description": pattern_info["description"],
                    "count": len(matches),
                    "samples": sanitized_matches,
                })

                result["issues"].append({
                    "type": f"DATA_EXPOSURE_{name.upper()}",
                    "severity": pattern_info["severity"],
                    "description": f"{pattern_info['description']} ({len(matches)} occurrence(s))",
                })

    def _check_security_headers(self, resp: requests.Response, result: dict):
        """Check for missing security headers."""
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        required_headers = {
            "x-content-type-options": "Prevents MIME-type sniffing",
            "x-frame-options": "Prevents clickjacking attacks",
            "strict-transport-security": "Enforces HTTPS via HSTS",
            "x-xss-protection": "Enables XSS filtering",
            "content-security-policy": "Prevents XSS and injection attacks",
        }

        for header, description in required_headers.items():
            if header not in headers_lower:
                result["issues"].append({
                    "type": f"MISSING_HEADER_{header.upper().replace('-', '_')}",
                    "severity": "LOW",
                    "description": f"Missing {header} header — {description}",
                })

    def _display_results(self):
        """Display audit results in a rich table."""
        if not self.audit_results:
            console.print("[yellow]⚠ No audit results to display.[/yellow]")
            return

        # Summary table
        table = Table(
            title="🔒 Security Audit Results",
            border_style="red",
            show_lines=True,
        )
        table.add_column("#", style="dim", justify="right", width=4)
        table.add_column("Endpoint", style="cyan", max_width=50)
        table.add_column("Status", justify="center", width=8)
        table.add_column("TLS", justify="center", width=6)
        table.add_column("Auth", justify="center", width=6)
        table.add_column("Rate\nLimit", justify="center", width=6)
        table.add_column("Data\nIssues", justify="center", width=8)
        table.add_column("Total\nIssues", justify="center", width=8)

        for idx, result in enumerate(self.audit_results[:50], 1):
            # Format boolean checks as colored symbols
            tls = "[green]✓[/green]" if result["tls_enforced"] else "[red]✗[/red]" if result["tls_enforced"] is False else "[dim]?[/dim]"
            auth = "[green]✓[/green]" if result["auth_required"] else "[red]✗[/red]" if result["auth_required"] is False else "[dim]?[/dim]"
            rate = "[green]✓[/green]" if result["rate_limited"] else "[red]✗[/red]" if result["rate_limited"] is False else "[dim]?[/dim]"

            data_issues = len(result["sensitive_data"])
            data_text = f"[red]{data_issues}[/red]" if data_issues > 0 else "[green]0[/green]"

            total_issues = len(result["issues"])
            issues_color = "red" if total_issues >= 5 else "yellow" if total_issues >= 2 else "green"
            issues_text = f"[{issues_color}]{total_issues}[/{issues_color}]"

            status = str(result.get("status_code", "—"))

            table.add_row(
                str(idx),
                result["url"][:50],
                status,
                tls,
                auth,
                rate,
                data_text,
                issues_text,
            )

        console.print(table)

        # Statistics
        total_issues = sum(len(r["issues"]) for r in self.audit_results)
        critical = sum(1 for r in self.audit_results for i in r["issues"] if i["severity"] == "CRITICAL")
        high = sum(1 for r in self.audit_results for i in r["issues"] if i["severity"] == "HIGH")
        medium = sum(1 for r in self.audit_results for i in r["issues"] if i["severity"] == "MEDIUM")

        console.print(
            f"\n[bold]Audit summary:[/bold] {total_issues} issue(s) across {len(self.audit_results)} endpoint(s)\n"
            f"  [bold red]Critical: {critical}[/bold red] | "
            f"[red]High: {high}[/red] | "
            f"[yellow]Medium: {medium}[/yellow]\n"
        )
