#!/usr/bin/env python3
"""
orkzoid.py — Unified Orkzoid Security Platform CLI
====================================================
Single entry point for both Orkzoid products.

Usage:
    python orkzoid.py --mode threat --target <IP or CIDR>
    python orkzoid.py --mode api    --target <domain> [--spec openapi.json]
"""

import argparse
import subprocess
import sys
import os
import importlib


BANNER = r"""
   ____       __                  _     __
  / __ \_____/ /_____  ____  ____(_)___/ /
 / / / / ___/ //_/_  / / __ \/ / / __  /
/ /_/ / /  / ,<   / /_/ /_/ / / / /_/ /
\____/_/  /_/|_| /___/\____/_/_/\__,_/

       Autonomous Security Platform v1.0.0
"""


def check_dependencies():
    """Check that core dependencies are installed."""
    required = {
        "rich": "rich",
        "requests": "requests",
        "colorama": "colorama",
    }
    missing = []
    for module, pip_name in required.items():
        try:
            importlib.import_module(module)
        except ImportError:
            missing.append(pip_name)
    if missing:
        print(f"\n[!] Missing dependencies: {', '.join(missing)}")
        print(f"    Run: pip install -r requirements.txt\n")
        sys.exit(1)


def main():
    check_dependencies()

    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    import colorama
    colorama.init()

    console = Console()

    parser = argparse.ArgumentParser(
        prog="orkzoid",
        description="Orkzoid — Unified Security Platform CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  threat    Proactive Threat Intelligence & Incident Response (nmap + NVD CVEs)
  api       Shadow API Attack Surface Management (discovery + audit)

Examples:
  python orkzoid.py --mode threat --target 192.168.1.1
  python orkzoid.py --mode threat --target 10.0.0.0/24 --api-key YOUR_NVD_KEY
  python orkzoid.py --mode api --target example.com --spec openapi.json
        """,
    )
    parser.add_argument(
        "--mode",
        required=True,
        choices=["threat", "api"],
        help="Product mode: 'threat' for Threat Intelligence, 'api' for Shadow API Scanner",
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Target IP/CIDR (threat mode) or domain (api mode)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output report filename (without extension)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=5,
        help="Network operation timeout in seconds (default: 5)",
    )
    parser.add_argument(
        "--api-key",
        default=None,
        help="NVD API key for faster CVE lookups (threat mode only)",
    )
    parser.add_argument(
        "--spec",
        default=None,
        help="OpenAPI/Swagger spec file path (api mode only)",
    )

    args = parser.parse_args()

    # Display banner
    console.print(Panel(
        Text(BANNER, style="bold cyan"),
        border_style="bright_cyan",
        padding=(0, 2),
    ))

    # Build the command for the appropriate product script
    script_dir = os.path.dirname(os.path.abspath(__file__))

    if args.mode == "threat":
        script = os.path.join(script_dir, "product1_threat_intel", "orkzoid_threat.py")
        cmd = [sys.executable, script, "--target", args.target, "--timeout", str(args.timeout)]
        if args.output:
            cmd.extend(["--output", args.output])
        if args.api_key:
            cmd.extend(["--api-key", args.api_key])
        console.print("[bold green]>> Launching Threat Intelligence module...[/bold green]\n")

    elif args.mode == "api":
        script = os.path.join(script_dir, "product2_shadow_api", "orkzoid_api.py")
        cmd = [sys.executable, script, "--target", args.target, "--timeout", str(args.timeout)]
        if args.output:
            cmd.extend(["--output", args.output])
        if args.spec:
            cmd.extend(["--spec", args.spec])
        console.print("[bold green]>> Launching Shadow API Scanner module...[/bold green]\n")

    # Execute the product script (inherit stdout/stderr for live output)
    try:
        result = subprocess.run(cmd)
        sys.exit(result.returncode)
    except FileNotFoundError:
        console.print(f"[bold red]Error: Script not found at {script}[/bold red]")
        sys.exit(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user.[/yellow]")
        sys.exit(130)


if __name__ == "__main__":
    main()
