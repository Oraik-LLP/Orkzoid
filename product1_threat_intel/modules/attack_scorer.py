"""
attack_scorer.py — Attack Vector Scoring Module
=================================================
Scores and ranks discovered vulnerabilities by CVSS severity.
Categorizes findings into Critical, High, Medium, Low, and Info tiers.
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

console = Console()

# Severity thresholds based on CVSS v3.x scoring
SEVERITY_THRESHOLDS = {
    "CRITICAL": (9.0, 10.0),
    "HIGH": (7.0, 8.9),
    "MEDIUM": (4.0, 6.9),
    "LOW": (0.1, 3.9),
    "INFO": (0.0, 0.0),
}

# Color mapping for severity levels
SEVERITY_COLORS = {
    "CRITICAL": "bold white on red",
    "HIGH": "bold red",
    "MEDIUM": "bold yellow",
    "LOW": "bold blue",
    "INFO": "dim white",
    "UNKNOWN": "dim white",
}

# Risk emoji mapping
SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "INFO": "⚪",
    "UNKNOWN": "⚪",
}


class AttackScorer:
    """
    Scores and ranks attack vectors based on CVSS scores,
    producing a prioritized list of vulnerabilities.
    """

    def __init__(self):
        self.scored_results = []
        self.statistics = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
        }

    def score(self, cve_results: list[dict]) -> list[dict]:
        """
        Score and rank all CVE findings by severity.

        Args:
            cve_results: Output from CVECorrelator.correlate()

        Returns:
            Sorted list of scored findings (highest severity first).
        """
        self.scored_results = []
        self.statistics = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

        console.print(
            Panel(
                "[bold cyan]📊 Scoring and ranking attack vectors by severity[/bold cyan]",
                title="[bold yellow]Attack Scoring[/bold yellow]",
                border_style="yellow",
            )
        )

        for service_result in cve_results:
            for cve in service_result.get("cves", []):
                severity = self._classify_severity(cve["cvss_score"])
                self.statistics[severity] = self.statistics.get(severity, 0) + 1

                scored_entry = {
                    "host": service_result["host"],
                    "port": service_result["port"],
                    "service": service_result["product"] or service_result["name"],
                    "version": service_result["version"],
                    "cve_id": cve["id"],
                    "description": cve["description"],
                    "cvss_score": cve["cvss_score"],
                    "cvss_severity": severity,
                    "cvss_vector": cve.get("cvss_vector", ""),
                    "references": cve.get("references", []),
                    "published": cve.get("published", "N/A"),
                    "risk_rating": self._calculate_risk_rating(cve, service_result),
                }
                self.scored_results.append(scored_entry)

        # Sort by CVSS score descending (critical first)
        self.scored_results.sort(key=lambda x: x["cvss_score"], reverse=True)

        # Display the scored results
        self._display_scored_results()
        self._display_statistics()

        return self.scored_results

    def _classify_severity(self, cvss_score: float) -> str:
        """Classify a CVSS score into a severity level."""
        if cvss_score >= 9.0:
            return "CRITICAL"
        elif cvss_score >= 7.0:
            return "HIGH"
        elif cvss_score >= 4.0:
            return "MEDIUM"
        elif cvss_score > 0.0:
            return "LOW"
        else:
            return "INFO"

    def _calculate_risk_rating(self, cve: dict, service: dict) -> str:
        """
        Calculate a contextual risk rating considering factors beyond CVSS.
        Factors: CVSS score, service exposure (port), network accessibility.
        """
        score = cve["cvss_score"]

        # Bonus risk for commonly exploited ports
        high_risk_ports = {21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443}
        if service.get("port") in high_risk_ports:
            score = min(score + 0.5, 10.0)

        # Bonus for services with known version (more targetable)
        if service.get("version"):
            score = min(score + 0.3, 10.0)

        if score >= 9.0:
            return "IMMEDIATE ACTION REQUIRED"
        elif score >= 7.0:
            return "HIGH PRIORITY"
        elif score >= 4.0:
            return "MODERATE PRIORITY"
        elif score > 0.0:
            return "LOW PRIORITY"
        else:
            return "INFORMATIONAL"

    def _display_scored_results(self):
        """Display scored vulnerabilities in a rich table."""
        if not self.scored_results:
            console.print("[yellow]⚠ No vulnerabilities to score.[/yellow]")
            return

        table = Table(
            title="📊 Attack Vector Rankings (Highest Severity First)",
            border_style="yellow",
            show_lines=True,
        )
        table.add_column("#", style="dim", justify="right", width=4)
        table.add_column("Severity", justify="center", width=12)
        table.add_column("CVSS", justify="center", width=6)
        table.add_column("CVE ID", style="bold white", width=18)
        table.add_column("Host:Port", style="cyan", width=22)
        table.add_column("Service", style="green", width=20)
        table.add_column("Risk Rating", width=26)

        for idx, entry in enumerate(self.scored_results[:50], 1):  # Show top 50
            severity = entry["cvss_severity"]
            color = SEVERITY_COLORS.get(severity, "white")
            emoji = SEVERITY_EMOJI.get(severity, "⚪")

            severity_text = Text(f"{emoji} {severity}", style=color)

            # Color code the CVSS score
            cvss_text = f"[{color}]{entry['cvss_score']:.1f}[/{color}]"

            # Color code the risk rating
            risk = entry["risk_rating"]
            if "IMMEDIATE" in risk:
                risk_text = f"[bold red]{risk}[/bold red]"
            elif "HIGH" in risk:
                risk_text = f"[red]{risk}[/red]"
            elif "MODERATE" in risk:
                risk_text = f"[yellow]{risk}[/yellow]"
            else:
                risk_text = f"[blue]{risk}[/blue]"

            table.add_row(
                str(idx),
                severity_text,
                cvss_text,
                entry["cve_id"],
                f"{entry['host']}:{entry['port']}",
                f"{entry['service']} {entry['version']}".strip(),
                risk_text,
            )

        console.print(table)

    def _display_statistics(self):
        """Display severity distribution statistics."""
        total = sum(self.statistics.values())
        if total == 0:
            return

        console.print(
            Panel(
                f"[bold red]🔴 Critical:[/bold red] {self.statistics['CRITICAL']}\n"
                f"[bold red]🟠 High:[/bold red]     {self.statistics['HIGH']}\n"
                f"[bold yellow]🟡 Medium:[/bold yellow]   {self.statistics['MEDIUM']}\n"
                f"[bold blue]🔵 Low:[/bold blue]      {self.statistics['LOW']}\n"
                f"[dim]⚪ Info:[/dim]     {self.statistics['INFO']}\n"
                f"\n[bold]Total findings: {total}[/bold]",
                title="[bold]Severity Distribution[/bold]",
                border_style="yellow",
            )
        )

    def get_critical_findings(self) -> list[dict]:
        """Return only CRITICAL and HIGH severity findings."""
        return [
            f for f in self.scored_results
            if f["cvss_severity"] in ("CRITICAL", "HIGH")
        ]
