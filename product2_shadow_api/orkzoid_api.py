#!/usr/bin/env python3
"""
orkzoid_api.py — Orkzoid Shadow API Attack Surface Management
==========================================================
Main entry point for Product 2.

Discovers undocumented API endpoints, audits for security issues,
diffs against OpenAPI specs, and generates kill-list reports.

Usage:
    python orkzoid_api.py --target <domain> [--spec openapi.json] [--output report.md] [--timeout 5]
"""

import argparse
import sys
import os
import urllib3

# Suppress InsecureRequestWarning for unverified HTTPS
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
import colorama

from modules.discoverer import APIDiscoverer
from modules.auditor import APIAuditor
from modules.shadow_detector import ShadowDetector
from modules.kill_report import KillReportGenerator

# Initialize colorama for Windows compatibility
colorama.init()

console = Console()

BANNER = r"""
   ____             _ __       ___    ____  ____
  / __ \_________ _(_) /__    /   |  / __ \/  _/
 / / / / ___/ __ `/ / //_/   / /| | / /_/ // /
/ /_/ / /  / /_/ / / ,<     / ___ |/ ____// /
\____/_/   \__,_/_/_/|_|   /_/  |_/_/   /___/

      Shadow API Attack Surface Management
                   v1.0.0
"""


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="orkzoid_api",
        description="Orkzoid Shadow API Scanner — Discover, audit, and report undocumented APIs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python orkzoid_api.py --target example.com
  python orkzoid_api.py --target example.com --spec openapi.json
  python orkzoid_api.py --target example.com --timeout 3 --output api_report
        """,
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Target domain to scan (e.g., example.com)",
    )
    parser.add_argument(
        "--spec",
        default=None,
        help="Path to OpenAPI/Swagger JSON spec file for shadow API detection",
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
    """Main execution flow for Orkzoid Shadow API Scanner."""
    args = parse_args()

    # Display banner
    console.print(Panel(
        Text(BANNER, style="bold cyan"),
        border_style="bright_cyan",
        padding=(0, 2),
    ))

    console.print(f"[bold white]Target:[/bold white]  [cyan]{args.target}[/cyan]")
    console.print(f"[bold white]Timeout:[/bold white] [cyan]{args.timeout}s[/cyan]")
    if args.spec:
        console.print(f"[bold white]Spec:[/bold white]    [cyan]{args.spec}[/cyan]")
    if args.output:
        console.print(f"[bold white]Output:[/bold white]  [cyan]{args.output}[/cyan]")
    console.print()

    # Resolve paths relative to this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    reports_dir = os.path.join(script_dir, "reports")
    wordlist_path = os.path.join(script_dir, "wordlists", "api_paths.txt")

    # ─── Phase 1: API Endpoint Discovery ──────────────────────────────
    console.rule("[bold green]Phase 1: API Endpoint Discovery[/bold green]")
    discoverer = APIDiscoverer(timeout=args.timeout, wordlist_path=wordlist_path)
    endpoints = discoverer.discover(args.target)

    if not endpoints:
        console.print("[bold yellow]⚠ No endpoints discovered. Report will be minimal.[/bold yellow]")

    # ─── Phase 2: Security Audit ──────────────────────────────────────
    console.rule("[bold red]Phase 2: Security Audit[/bold red]")
    auditor = APIAuditor(timeout=args.timeout)
    audit_results = auditor.audit(endpoints)

    # ─── Phase 3: Shadow API Detection ────────────────────────────────
    console.rule("[bold magenta]Phase 3: Shadow API Detection[/bold magenta]")
    detector = ShadowDetector()
    shadow_apis = []
    documented_apis = []

    if args.spec:
        if detector.load_spec(args.spec):
            shadow_apis, documented_apis = detector.detect(endpoints)
        else:
            console.print("[yellow]⚠ Skipping shadow detection (spec load failed).[/yellow]")
            shadow_apis = endpoints
    else:
        console.print("[dim]No --spec provided. Skipping OpenAPI diff.[/dim]")
        console.print("[dim]Use --spec <file.json> to enable shadow API detection.[/dim]")
        shadow_apis = []

    # ─── Phase 4: Kill-List Report ────────────────────────────────────
    console.rule("[bold red]Phase 4: Kill-List Report Generation[/bold red]")
    reporter = KillReportGenerator(output_dir=reports_dir)
    md_path, json_path = reporter.generate(
        audit_results=audit_results,
        shadow_apis=shadow_apis,
        target=args.target,
        output_filename=args.output,
    )

    # ─── Summary ──────────────────────────────────────────────────────
    console.print()
    console.print(
        Panel(
            f"[bold green]✓ Scan complete![/bold green]\n\n"
            f"[bold white]Endpoints discovered:[/bold white]  {len(endpoints)}\n"
            f"[bold white]Endpoints audited:[/bold white]    {len(audit_results)}\n"
            f"[bold white]Shadow APIs found:[/bold white]    {len(shadow_apis)}\n"
            f"[bold white]Documented APIs:[/bold white]      {len(documented_apis)}\n\n"
            f"[bold white]Reports:[/bold white]\n"
            f"  📄 Markdown: [cyan]{md_path}[/cyan]\n"
            f"  📊 JSON:     [cyan]{json_path}[/cyan]",
            title="[bold bright_cyan]Orkzoid Shadow API Scanner — Complete[/bold bright_cyan]",
            border_style="bright_green",
            padding=(1, 2),
        )
    )


if __name__ == "__main__":
    main()
