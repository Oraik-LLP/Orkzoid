"""
recon.py — Network Reconnaissance Module
=========================================
Uses python-nmap to perform port scanning, service detection,
and OS fingerprinting on target IPs or CIDR ranges.
"""

import os
import sys
import platform
import nmap
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich.panel import Panel
from typing import Optional

console = Console()


class ReconScanner:
    """
    Wraps python-nmap to perform network reconnaissance.
    Detects open ports, running services, and their versions.
    """

    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self.scanner = nmap.PortScanner()
        self.results = []

    @staticmethod
    def _is_privileged() -> bool:
        """Check if the current user has root/admin privileges."""
        if platform.system() == "Windows":
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                return False
        else:
            return os.geteuid() == 0

    def scan(self, target: str) -> list[dict]:
        """
        Perform an nmap scan on the given target (IP or CIDR).

        Args:
            target: IP address or CIDR range to scan (e.g., '192.168.1.1' or '10.0.0.0/24')

        Returns:
            List of dictionaries containing host/port/service information.
        """
        self.results = []

        # Check privileges and select scan type accordingly
        privileged = self._is_privileged()
        if privileged:
            # Full SYN scan + scripts (requires root/admin)
            nmap_args = f"-sV -sC -T4 --host-timeout {self.timeout * 20}s"
            scan_mode = "Privileged (SYN + Scripts)"
        else:
            # Fallback to TCP connect scan (no root needed)
            nmap_args = f"-sT -sV -T4 --host-timeout {self.timeout * 20}s"
            scan_mode = "Unprivileged (TCP Connect)"
            console.print(
                "[yellow]⚠ Not running as root/admin. Using TCP connect scan (-sT) instead of SYN scan.[/yellow]\n"
                "[dim]  For full results (SYN scan + NSE scripts), run with: sudo python orkzoid_threat.py ...[/dim]"
            )

        console.print(
            Panel(
                f"[bold cyan]Scanning target:[/bold cyan] [white]{target}[/white]\n"
                f"[dim]Timeout: {self.timeout}s | Mode: {scan_mode}[/dim]",
                title="[bold green]Orkzoid Recon[/bold green]",
                border_style="green",
            )
        )

        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TimeElapsedColumn(),
                console=console,
            ) as progress:
                task = progress.add_task("[cyan]Running nmap scan...", total=None)

                self.scanner.scan(hosts=target, arguments=nmap_args)

                progress.update(task, description="[green]Scan complete!", completed=True)

        except nmap.PortScannerError as e:
            console.print(f"[bold red]✗ Nmap error:[/bold red] {e}")
            console.print("[yellow]⚠ Make sure nmap is installed on your system.[/yellow]")
            return self.results
        except Exception as e:
            console.print(f"[bold red]✗ Unexpected error during scan:[/bold red] {e}")
            return self.results

        # Parse scan results
        self._parse_results()

        # Display results table
        self._display_results()

        return self.results

    def _parse_results(self):
        """Parse raw nmap results into structured dictionaries."""
        for host in self.scanner.all_hosts():
            host_info = {
                "host": host,
                "hostname": self.scanner[host].hostname() or "N/A",
                "state": self.scanner[host].state(),
                "services": [],
            }

            for proto in self.scanner[host].all_protocols():
                ports = sorted(self.scanner[host][proto].keys())
                for port in ports:
                    service_data = self.scanner[host][proto][port]
                    service = {
                        "port": port,
                        "protocol": proto,
                        "state": service_data.get("state", "unknown"),
                        "name": service_data.get("name", "unknown"),
                        "product": service_data.get("product", ""),
                        "version": service_data.get("version", ""),
                        "extrainfo": service_data.get("extrainfo", ""),
                        "cpe": service_data.get("cpe", ""),
                    }
                    host_info["services"].append(service)

            self.results.append(host_info)

    def _display_results(self):
        """Display scan results as a rich table."""
        if not self.results:
            console.print("[yellow]⚠ No hosts responded to the scan.[/yellow]")
            return

        for host_data in self.results:
            table = Table(
                title=f"🖥  Host: {host_data['host']} ({host_data['hostname']}) — [{host_data['state']}]",
                border_style="cyan",
                show_lines=True,
            )
            table.add_column("Port", style="bold white", justify="right")
            table.add_column("Proto", style="dim")
            table.add_column("State", style="bold")
            table.add_column("Service", style="cyan")
            table.add_column("Product", style="green")
            table.add_column("Version", style="yellow")
            table.add_column("CPE", style="dim")

            for svc in host_data["services"]:
                # Color-code the state
                state_color = "green" if svc["state"] == "open" else "red"
                state_text = f"[{state_color}]{svc['state']}[/{state_color}]"

                table.add_row(
                    str(svc["port"]),
                    svc["protocol"],
                    state_text,
                    svc["name"],
                    svc["product"],
                    svc["version"],
                    svc["cpe"],
                )

            console.print(table)

        total_services = sum(len(h["services"]) for h in self.results)
        open_services = sum(
            1
            for h in self.results
            for s in h["services"]
            if s["state"] == "open"
        )
        console.print(
            f"\n[bold green]✓[/bold green] Found [bold]{len(self.results)}[/bold] host(s), "
            f"[bold]{total_services}[/bold] service(s) ([bold green]{open_services}[/bold green] open)\n"
        )

    def get_service_list(self) -> list[dict]:
        """
        Return a flat list of services with host info for CVE correlation.

        Returns:
            List of dicts with keys: host, port, name, product, version, cpe
        """
        services = []
        for host_data in self.results:
            for svc in host_data["services"]:
                if svc["state"] == "open" and (svc["product"] or svc["name"]):
                    services.append(
                        {
                            "host": host_data["host"],
                            "port": svc["port"],
                            "name": svc["name"],
                            "product": svc["product"],
                            "version": svc["version"],
                            "cpe": svc["cpe"],
                        }
                    )
        return services
