"""
shadow_detector.py — Shadow API Detection Module
==================================================
Diffs discovered API endpoints against a provided OpenAPI/Swagger
specification to identify undocumented "shadow" APIs.
"""

import json
import re
from urllib.parse import urlparse
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


class ShadowDetector:
    """Compares discovered endpoints against OpenAPI spec to find shadow APIs."""

    def __init__(self):
        self.spec_paths = set()
        self.shadow_apis = []
        self.documented_apis = []
        self.spec_data = {}

    def load_spec(self, spec_path: str) -> bool:
        """Load and parse an OpenAPI/Swagger specification file."""
        try:
            with open(spec_path, "r", encoding="utf-8") as f:
                self.spec_data = json.load(f)
            self._extract_spec_paths()
            console.print(
                Panel(
                    f"[bold cyan]Loaded OpenAPI spec:[/bold cyan] {spec_path}\n"
                    f"[dim]Title: {self.spec_data.get('info', {}).get('title', 'N/A')}[/dim]\n"
                    f"[dim]Documented paths: {len(self.spec_paths)}[/dim]",
                    title="[bold blue]OpenAPI Spec[/bold blue]",
                    border_style="blue",
                )
            )
            return True
        except FileNotFoundError:
            console.print(f"[red]✗ Spec file not found: {spec_path}[/red]")
            return False
        except json.JSONDecodeError as e:
            console.print(f"[red]✗ Invalid JSON in spec: {e}[/red]")
            return False

    def _extract_spec_paths(self):
        """Extract all documented paths from the OpenAPI spec."""
        self.spec_paths = set()
        paths = self.spec_data.get("paths", {})
        base_path = self.spec_data.get("basePath", "")
        for path in paths:
            normalized = self._normalize_path(path)
            self.spec_paths.add(normalized)
            if base_path and base_path != "/":
                self.spec_paths.add(f"{base_path.rstrip('/')}{normalized}")
        # Check servers (OpenAPI 3.x)
        for server in self.spec_data.get("servers", []):
            parsed = urlparse(server.get("url", ""))
            if parsed.path and parsed.path != "/":
                for path in list(self.spec_paths):
                    self.spec_paths.add(f"{parsed.path.rstrip('/')}{path}")

    def _normalize_path(self, path: str) -> str:
        """Normalize path: replace params with {*}, lowercase, strip trailing /."""
        normalized = re.sub(r"\{[^}]+\}", "{*}", path)
        return (normalized.rstrip("/") or "/").lower()

    def detect(self, endpoints: list[dict]) -> tuple[list[dict], list[dict]]:
        """Compare discovered endpoints against the loaded spec."""
        self.shadow_apis = []
        self.documented_apis = []

        if not self.spec_paths:
            self.shadow_apis = [{**ep, "shadow_reason": "No spec loaded"} for ep in endpoints]
            self._display_results()
            return self.shadow_apis, self.documented_apis

        console.print(
            Panel(
                f"[bold cyan]👻 Comparing {len(endpoints)} endpoint(s) "
                f"against {len(self.spec_paths)} documented path(s)[/bold cyan]",
                title="[bold magenta]Shadow API Detection[/bold magenta]",
                border_style="magenta",
            )
        )

        for endpoint in endpoints:
            path = endpoint.get("path", urlparse(endpoint["url"]).path)
            normalized = self._normalize_path(path)
            if self._matches_spec(normalized):
                self.documented_apis.append({**endpoint, "documented": True})
            else:
                closest = self._find_closest_match(normalized)
                self.shadow_apis.append({
                    **endpoint, "documented": False,
                    "shadow_reason": "Not found in OpenAPI specification",
                    "closest_match": closest,
                })

        self._display_results()
        return self.shadow_apis, self.documented_apis

    def _matches_spec(self, normalized_path: str) -> bool:
        """Check if a normalized path matches any spec path."""
        if normalized_path in self.spec_paths:
            return True
        for spec_path in self.spec_paths:
            pattern = re.escape(spec_path).replace(r"\{\*\}", r"[^/]+")
            if re.fullmatch(pattern, normalized_path):
                return True
        return False

    def _find_closest_match(self, path: str) -> str:
        """Find closest matching spec path via prefix matching."""
        best_match, best_score = "", 0
        for spec_path in self.spec_paths:
            common = sum(1 for a, b in zip(path, spec_path) if a == b)
            if common > best_score:
                best_score, best_match = common, spec_path
        return best_match if best_score > 3 else "No close match"

    def _display_results(self):
        """Display shadow API detection results."""
        if self.shadow_apis:
            table = Table(title=f"👻 Shadow APIs ({len(self.shadow_apis)} undocumented)", border_style="red", show_lines=True)
            table.add_column("#", style="dim", justify="right", width=4)
            table.add_column("Endpoint", style="bold red", max_width=50)
            table.add_column("Status", justify="center", width=8)
            table.add_column("Discovery", style="magenta", width=10)
            table.add_column("Closest Match", style="dim", max_width=35)
            for idx, api in enumerate(self.shadow_apis[:50], 1):
                table.add_row(str(idx), api.get("path", api["url"]), str(api.get("status_code", "—")),
                              api.get("discovery_method", "unknown"), api.get("closest_match", "—"))
            console.print(table)

        if self.documented_apis:
            console.print(f"[green]✓ {len(self.documented_apis)} endpoint(s) match the OpenAPI spec[/green]")

        total = len(self.shadow_apis) + len(self.documented_apis)
        if total > 0:
            pct = (len(self.shadow_apis) / total) * 100
            console.print(f"\n[bold]Shadow coverage:[/bold] [red]{len(self.shadow_apis)}[/red] undocumented "
                          f"/ [green]{len(self.documented_apis)}[/green] documented ([bold red]{pct:.1f}%[/bold red] shadow)\n")
