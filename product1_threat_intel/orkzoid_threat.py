#!/usr/bin/env python3
"""
orkzoid_threat.py — Orkzoid Proactive Threat Intelligence & Automated Incident Response
=====================================================================================
Main entry point for Product 1.

Scans targets for open ports/services, correlates with NVD CVEs,
scores attack vectors, and generates remediation playbooks.

Usage:
    python orkzoid_threat.py --target <IP or CIDR> [--output report.md] [--timeout 5]
"""

import argparse
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
import colorama

from modules.recon import ReconScanner
from modules.cve_correlator import CVECorrelator
from modules.attack_scorer import AttackScorer
from modules.playbook import PlaybookGenerator

# Initialize colorama for Windows compatibility
colorama.init()

console = Console()

BANNER = r"""
   ____             _ __      _____ __                    __
  / __ \_________ _(_) /__   /_  _// /_  ________  ____ _/ /_
 / / / / ___/ __ `/ / //_/    / / / __ \/ ___/ _ \/ __ `/ __/
/ /_/ / /  / /_/ / / ,<      / / / / / / /  /  __/ /_/ / /_
\____/_/   \__,_/_/_/|_|    /_/ /_/ /_/_/   \___/\__,_/\__/

    Proactive Threat Intelligence & Automated Incident Response
                        v1.0.0
"""


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="orkzoid_threat",
        description="Orkzoid Threat Intelligence — Scan targets, correlate CVEs, generate remediation playbooks.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python orkzoid_threat.py --target 192.168.1.1
  python orkzoid_threat.py --target 10.0.0.0/24 --timeout 10
  python orkzoid_threat.py --target 192.168.1.1 --output my_report
        """,
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Target IP address or CIDR range to scan (e.g., 192.168.1.1 or 10.0.0.0/24)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output report filename (without extension). Default: auto-generated with timestamp.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=5,
        help="Network operation timeout in seconds (default: 5)",
    )

    return parser.parse_args()


def main():
    """Main execution flow for Orkzoid Threat Intelligence."""
    args = parse_args()

    # Display banner
    console.print(Panel(
        Text(BANNER, style="bold cyan"),
        border_style="bright_cyan",
        padding=(0, 2),
    ))

    console.print(f"[bold white]Target:[/bold white]  [cyan]{args.target}[/cyan]")
    console.print(f"[bold white]Timeout:[/bold white] [cyan]{args.timeout}s[/cyan]")
    if args.output:
        console.print(f"[bold white]Output:[/bold white]  [cyan]{args.output}[/cyan]")
    console.print()

    # Resolve reports directory relative to this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    reports_dir = os.path.join(script_dir, "reports")

    # ─── Phase 1: Reconnaissance ──────────────────────────────────────
    console.rule("[bold green]Phase 1: Network Reconnaissance[/bold green]")
    scanner = ReconScanner(timeout=args.timeout)
    scan_results = scanner.scan(args.target)

    if not scan_results:
        console.print("[bold red]✗ No scan results. Exiting.[/bold red]")
        sys.exit(1)

    services = scanner.get_service_list()
    if not services:
        console.print("[yellow]⚠ No open services detected. No CVEs to correlate.[/yellow]")
        console.print("[dim]The scan completed but no open ports with identifiable services were found.[/dim]")

    # ─── Phase 2: CVE Correlation ─────────────────────────────────────
    console.rule("[bold magenta]Phase 2: CVE Correlation[/bold magenta]")
    correlator = CVECorrelator(timeout=args.timeout)
    cve_results = correlator.correlate(services)

    # ─── Phase 3: Attack Scoring ──────────────────────────────────────
    console.rule("[bold yellow]Phase 3: Attack Vector Scoring[/bold yellow]")
    scorer = AttackScorer()
    scored_findings = scorer.score(cve_results)

    # ─── Phase 4: Playbook Generation ─────────────────────────────────
    console.rule("[bold blue]Phase 4: Remediation Playbook[/bold blue]")
    generator = PlaybookGenerator(output_dir=reports_dir)
    md_path, json_path = generator.generate(
        scored_findings=scored_findings,
        target=args.target,
        output_filename=args.output,
    )

    # ─── Summary ──────────────────────────────────────────────────────
    console.print()
    console.print(
        Panel(
            f"[bold green]✓ Scan complete![/bold green]\n\n"
            f"[bold white]Hosts scanned:[/bold white]   {len(scan_results)}\n"
            f"[bold white]Services found:[/bold white]  {len(services)}\n"
            f"[bold white]CVEs matched:[/bold white]    {sum(r['cve_count'] for r in cve_results)}\n"
            f"[bold white]Findings scored:[/bold white] {len(scored_findings)}\n\n"
            f"[bold white]Reports:[/bold white]\n"
            f"  📄 Markdown: [cyan]{md_path}[/cyan]\n"
            f"  📊 JSON:     [cyan]{json_path}[/cyan]",
            title="[bold bright_cyan]Orkzoid Threat Intelligence — Complete[/bold bright_cyan]",
            border_style="bright_green",
            padding=(1, 2),
        )
    )


if __name__ == "__main__":
    main()
