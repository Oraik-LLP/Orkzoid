"""
cve_correlator.py — CVE Correlation Module
============================================
Queries the NVD (National Vulnerability Database) API v2.0
to match discovered services and versions to known CVEs.
Gracefully handles offline scenarios.
"""

import requests
import time
from typing import Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich.panel import Panel

console = Console()

# NVD API v2.0 base URL
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Rate limit: NVD allows ~5 requests per 30 seconds without API key
NVD_RATE_LIMIT_DELAY = 6.5  # seconds between requests


class CVECorrelator:
    """
    Correlates discovered services/versions with known CVEs
    using the NVD API v2.0.
    """

    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Oraik-ThreatIntel/1.0",
            "Accept": "application/json",
        })
        self.cve_results = []
        self._online = True

    def correlate(self, services: list[dict]) -> list[dict]:
        """
        For each discovered service, query NVD for matching CVEs.

        Args:
            services: List of service dicts from ReconScanner.get_service_list()
                      Each dict has: host, port, name, product, version, cpe

        Returns:
            List of dicts, each containing the service info + matched CVEs.
        """
        self.cve_results = []

        if not services:
            console.print("[yellow]⚠ No services to correlate with CVEs.[/yellow]")
            return self.cve_results

        console.print(
            Panel(
                f"[bold cyan]🔗 Correlating {len(services)} service(s) with NVD CVE database[/bold cyan]\n"
                f"[dim]API: {NVD_API_BASE}[/dim]",
                title="[bold magenta]CVE Correlation[/bold magenta]",
                border_style="magenta",
            )
        )

        # Check connectivity first
        self._check_online()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("[cyan]Querying NVD...", total=len(services))

            for svc in services:
                cves = self._fetch_cves_for_service(svc)

                result = {
                    **svc,
                    "cves": cves,
                    "cve_count": len(cves),
                }
                self.cve_results.append(result)

                progress.update(
                    task,
                    advance=1,
                    description=f"[cyan]Queried: {svc['product'] or svc['name']} {svc['version']}",
                )

        # Display summary
        self._display_summary()

        return self.cve_results

    def _check_online(self):
        """Check if NVD API is reachable."""
        try:
            resp = self.session.get(NVD_API_BASE, timeout=self.timeout, params={"resultsPerPage": 1})
            if resp.status_code == 200:
                self._online = True
                console.print("[green]✓ NVD API is reachable.[/green]")
            else:
                self._online = False
                console.print(f"[yellow]⚠ NVD returned status {resp.status_code}. Working offline.[/yellow]")
        except requests.RequestException:
            self._online = False
            console.print("[yellow]⚠ Cannot reach NVD API. Skipping CVE correlation (offline mode).[/yellow]")

    def _fetch_cves_for_service(self, service: dict) -> list[dict]:
        """
        Fetch CVEs for a single service from NVD.

        Uses CPE matching if available, otherwise falls back to keyword search.
        """
        if not self._online:
            return []

        cves = []

        try:
            # Strategy 1: CPE-based lookup (most accurate)
            if service.get("cpe"):
                cves = self._query_by_cpe(service["cpe"])

            # Strategy 2: Keyword-based search (fallback)
            if not cves and (service.get("product") or service.get("name")):
                keyword = service.get("product") or service.get("name")
                version = service.get("version", "")
                if version:
                    keyword = f"{keyword} {version}"
                cves = self._query_by_keyword(keyword)

            # Respect rate limit
            time.sleep(NVD_RATE_LIMIT_DELAY)

        except Exception as e:
            console.print(f"[dim red]  ✗ Error fetching CVEs for {service.get('product', 'unknown')}: {e}[/dim red]")

        return cves

    def _query_by_cpe(self, cpe_string: str) -> list[dict]:
        """Query NVD by CPE name."""
        params = {
            "cpeName": cpe_string,
            "resultsPerPage": 20,
        }

        try:
            resp = self.session.get(NVD_API_BASE, params=params, timeout=self.timeout)
            if resp.status_code == 200:
                return self._parse_nvd_response(resp.json())
            elif resp.status_code == 403:
                console.print("[dim yellow]  ⚠ Rate limited by NVD. Waiting...[/dim yellow]")
                time.sleep(30)
                return []
        except requests.RequestException:
            return []

        return []

    def _query_by_keyword(self, keyword: str) -> list[dict]:
        """Query NVD by keyword search."""
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": 10,
        }

        try:
            resp = self.session.get(NVD_API_BASE, params=params, timeout=self.timeout)
            if resp.status_code == 200:
                return self._parse_nvd_response(resp.json())
            elif resp.status_code == 403:
                console.print("[dim yellow]  ⚠ Rate limited by NVD. Waiting...[/dim yellow]")
                time.sleep(30)
                return []
        except requests.RequestException:
            return []

        return []

    def _parse_nvd_response(self, data: dict) -> list[dict]:
        """
        Parse the NVD API v2.0 JSON response into a clean list of CVEs.
        """
        cves = []
        vulnerabilities = data.get("vulnerabilities", [])

        for vuln in vulnerabilities:
            cve_data = vuln.get("cve", {})
            cve_id = cve_data.get("id", "UNKNOWN")

            # Extract description (English preferred)
            descriptions = cve_data.get("descriptions", [])
            description = "No description available."
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", description)
                    break

            # Extract CVSS score (try v3.1 first, then v3.0, then v2.0)
            metrics = cve_data.get("metrics", {})
            cvss_score = 0.0
            cvss_severity = "UNKNOWN"
            cvss_vector = ""

            # Try CVSS v3.1
            cvss_v31 = metrics.get("cvssMetricV31", [])
            if cvss_v31:
                primary = cvss_v31[0].get("cvssData", {})
                cvss_score = primary.get("baseScore", 0.0)
                cvss_severity = primary.get("baseSeverity", "UNKNOWN")
                cvss_vector = primary.get("vectorString", "")
            else:
                # Try CVSS v3.0
                cvss_v30 = metrics.get("cvssMetricV30", [])
                if cvss_v30:
                    primary = cvss_v30[0].get("cvssData", {})
                    cvss_score = primary.get("baseScore", 0.0)
                    cvss_severity = primary.get("baseSeverity", "UNKNOWN")
                    cvss_vector = primary.get("vectorString", "")
                else:
                    # Try CVSS v2.0
                    cvss_v2 = metrics.get("cvssMetricV2", [])
                    if cvss_v2:
                        primary = cvss_v2[0].get("cvssData", {})
                        cvss_score = primary.get("baseScore", 0.0)
                        cvss_severity = primary.get("baseSeverity", "UNKNOWN")
                        cvss_vector = primary.get("vectorString", "")

            # Extract references
            references = [
                ref.get("url", "")
                for ref in cve_data.get("references", [])[:5]  # Limit to 5 refs
            ]

            # Extract published date
            published = cve_data.get("published", "N/A")

            cves.append({
                "id": cve_id,
                "description": description[:300],  # Truncate long descriptions
                "cvss_score": cvss_score,
                "cvss_severity": cvss_severity,
                "cvss_vector": cvss_vector,
                "references": references,
                "published": published,
            })

        return cves

    def _display_summary(self):
        """Display a summary table of CVE correlation results."""
        table = Table(
            title="🔗 CVE Correlation Summary",
            border_style="magenta",
            show_lines=True,
        )
        table.add_column("Host", style="bold white")
        table.add_column("Port", justify="right", style="cyan")
        table.add_column("Service", style="green")
        table.add_column("Version", style="yellow")
        table.add_column("CVEs Found", justify="center", style="bold red")

        for result in self.cve_results:
            cve_text = str(result["cve_count"])
            if result["cve_count"] > 0:
                cve_text = f"[bold red]{result['cve_count']}[/bold red]"
            else:
                cve_text = f"[green]0[/green]"

            table.add_row(
                result["host"],
                str(result["port"]),
                result["product"] or result["name"],
                result["version"] or "N/A",
                cve_text,
            )

        console.print(table)

        total_cves = sum(r["cve_count"] for r in self.cve_results)
        console.print(
            f"\n[bold]Total CVEs found:[/bold] [bold red]{total_cves}[/bold red] "
            f"across [bold]{len(self.cve_results)}[/bold] service(s)\n"
        )
