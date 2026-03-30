"""
kill_report.py — Kill-List Report Generator
=============================================
Generates comprehensive kill-list reports with:
  - Dangerous endpoint flagging
  - Firewall rules (nginx and iptables format)
  - GDPR/DPDP compliance risk flags
  - JSON and Markdown output
"""

import json
import os
from datetime import datetime, timezone
from urllib.parse import urlparse
from rich.console import Console
from rich.panel import Panel

console = Console()

# Dangerous endpoint patterns that should be flagged
DANGEROUS_PATTERNS = {
    "admin_panel": {
        "paths": ["/admin", "/administrator", "/wp-admin", "/dashboard", "/cpanel"],
        "risk": "Administrative interface exposed",
        "severity": "CRITICAL",
    },
    "debug_endpoints": {
        "paths": ["/debug", "/_debug", "/trace", "/profiler", "/phpinfo"],
        "risk": "Debug/profiling endpoint exposed",
        "severity": "CRITICAL",
    },
    "config_leak": {
        "paths": ["/.env", "/config", "/.git", "/.svn", "/wp-config.php", "/.htaccess"],
        "risk": "Configuration/source file exposed",
        "severity": "CRITICAL",
    },
    "database_interfaces": {
        "paths": ["/phpmyadmin", "/adminer", "/pgadmin", "/mongodb"],
        "risk": "Database management interface exposed",
        "severity": "CRITICAL",
    },
    "graphql": {
        "paths": ["/graphql", "/graphiql"],
        "risk": "GraphQL endpoint (introspection may leak schema)",
        "severity": "HIGH",
    },
    "api_docs": {
        "paths": ["/swagger", "/api-docs", "/openapi", "/swagger-ui"],
        "risk": "API documentation publicly accessible",
        "severity": "MEDIUM",
    },
    "health_metrics": {
        "paths": ["/health", "/metrics", "/status", "/info", "/actuator"],
        "risk": "Infrastructure monitoring endpoint exposed",
        "severity": "MEDIUM",
    },
    "file_upload": {
        "paths": ["/upload", "/file-upload", "/attachments"],
        "risk": "File upload endpoint (potential for RCE)",
        "severity": "HIGH",
    },
    "auth_endpoints": {
        "paths": ["/login", "/signup", "/register", "/forgot-password", "/reset-password"],
        "risk": "Authentication endpoint (brute-force target)",
        "severity": "MEDIUM",
    },
}


class KillReportGenerator:
    """Generates kill-list reports with firewall rules and risk flags."""

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def generate(self, audit_results: list[dict], shadow_apis: list[dict],
                 target: str, output_filename: str | None = None) -> tuple[str, str]:
        """
        Generate kill-list reports in Markdown and JSON.

        Args:
            audit_results: Output from APIAuditor.audit()
            shadow_apis: Shadow APIs from ShadowDetector.detect()
            target: Original target domain
            output_filename: Optional output filename (without extension)

        Returns:
            Tuple of (markdown_path, json_path)
        """
        if not output_filename:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            output_filename = f"oraik_api_report_{timestamp}"

        md_path = os.path.join(self.output_dir, f"{output_filename}.md")
        json_path = os.path.join(self.output_dir, f"{output_filename}.json")

        console.print(
            Panel(
                f"[bold cyan]📝 Generating kill-list report[/bold cyan]\n"
                f"[dim]Target: {target} | Audit: {len(audit_results)} | Shadow: {len(shadow_apis)}[/dim]",
                title="[bold red]Kill Report[/bold red]",
                border_style="red",
            )
        )

        # Identify dangerous endpoints
        dangerous = self._flag_dangerous(audit_results, shadow_apis)

        # Generate GDPR/DPDP risk flags
        gdpr_risks = self._assess_gdpr_risks(audit_results)

        # Generate firewall rules
        nginx_rules = self._generate_nginx_rules(dangerous, shadow_apis)
        iptables_rules = self._generate_iptables_rules(target)

        # Write Markdown
        md = self._build_markdown(target, audit_results, shadow_apis, dangerous, gdpr_risks, nginx_rules, iptables_rules)
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md)

        # Write JSON
        json_data = self._build_json(target, audit_results, shadow_apis, dangerous, gdpr_risks, nginx_rules, iptables_rules)
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(json_data, f, indent=2, default=str)

        console.print(f"[bold green]✓[/bold green] Markdown report: [cyan]{md_path}[/cyan]")
        console.print(f"[bold green]✓[/bold green] JSON report:     [cyan]{json_path}[/cyan]")
        return md_path, json_path

    def _flag_dangerous(self, audit_results: list[dict], shadow_apis: list[dict]) -> list[dict]:
        """Flag endpoints matching dangerous patterns."""
        dangerous = []
        all_endpoints = audit_results + shadow_apis

        for ep in all_endpoints:
            path = ep.get("path", urlparse(ep.get("url", "")).path).lower()
            for category, info in DANGEROUS_PATTERNS.items():
                if any(p in path for p in info["paths"]):
                    dangerous.append({
                        "url": ep.get("url", ""),
                        "path": path,
                        "category": category,
                        "risk": info["risk"],
                        "severity": info["severity"],
                        "status_code": ep.get("status_code"),
                        "is_shadow": ep.get("documented") is False,
                    })
                    break
        return dangerous

    def _assess_gdpr_risks(self, audit_results: list[dict]) -> list[dict]:
        """Assess GDPR/DPDP compliance risks from audit results."""
        risks = []
        for result in audit_results:
            for data in result.get("sensitive_data", []):
                if data["type"] in ("email", "phone_number", "ssn", "credit_card"):
                    risks.append({
                        "url": result["url"],
                        "data_type": data["type"],
                        "severity": data["severity"],
                        "description": data["description"],
                        "count": data.get("count", 0),
                        "regulation": "GDPR Art. 5/32" if data["type"] in ("email", "phone_number", "ssn") else "PCI-DSS",
                        "risk": f"Personal data ({data['type']}) exposed without proper access controls",
                    })
            # No-auth endpoint with 200 response
            if result.get("auth_required") is False and result.get("status_code") == 200:
                risks.append({
                    "url": result["url"],
                    "data_type": "unauthenticated_access",
                    "severity": "HIGH",
                    "description": "API endpoint accessible without authentication",
                    "regulation": "GDPR Art. 32 / DPDP Sec. 8",
                    "risk": "Potential unauthorized access to personal data",
                })
        return risks

    def _generate_nginx_rules(self, dangerous: list[dict], shadow_apis: list[dict]) -> str:
        """Generate nginx deny rules for dangerous and shadow endpoints."""
        lines = ["# Oraik — Auto-generated nginx deny rules", f"# Generated: {datetime.now(timezone.utc).isoformat()}", ""]
        paths_blocked = set()

        for ep in dangerous:
            path = ep.get("path", "")
            if path and path not in paths_blocked:
                lines.append(f"# Block: {ep.get('risk', 'Dangerous endpoint')}")
                lines.append(f"location ~* ^{path} {{")
                lines.append("    deny all;")
                lines.append("    return 403;")
                lines.append("}")
                lines.append("")
                paths_blocked.add(path)

        for ep in shadow_apis[:20]:
            path = ep.get("path", "")
            if path and path not in paths_blocked:
                lines.append(f"# Block shadow API: {path}")
                lines.append(f"location = {path} {{")
                lines.append("    deny all;")
                lines.append("    return 404;")
                lines.append("}")
                lines.append("")
                paths_blocked.add(path)

        return "\n".join(lines)

    def _generate_iptables_rules(self, target: str) -> str:
        """Generate basic iptables rules for rate limiting and blocking."""
        return "\n".join([
            "# Oraik — Auto-generated iptables rules",
            f"# Target: {target}",
            f"# Generated: {datetime.now(timezone.utc).isoformat()}",
            "",
            "# Rate limit incoming HTTP/HTTPS connections",
            "iptables -A INPUT -p tcp --dport 80 -m connlimit --connlimit-above 50 -j DROP",
            "iptables -A INPUT -p tcp --dport 443 -m connlimit --connlimit-above 50 -j DROP",
            "",
            "# Rate limit new connections (prevent brute-force)",
            "iptables -A INPUT -p tcp --dport 80 -m state --state NEW -m recent --set",
            "iptables -A INPUT -p tcp --dport 80 -m state --state NEW -m recent --update --seconds 60 --hitcount 20 -j DROP",
            "iptables -A INPUT -p tcp --dport 443 -m state --state NEW -m recent --set",
            "iptables -A INPUT -p tcp --dport 443 -m state --state NEW -m recent --update --seconds 60 --hitcount 20 -j DROP",
            "",
            "# Log and drop suspicious traffic",
            "iptables -A INPUT -p tcp --dport 80 -j LOG --log-prefix 'ORAIK_HTTP: '",
            "iptables -A INPUT -p tcp --dport 443 -j LOG --log-prefix 'ORAIK_HTTPS: '",
        ])

    def _build_markdown(self, target, audit_results, shadow_apis, dangerous, gdpr_risks, nginx_rules, iptables_rules) -> str:
        """Build the full Markdown report."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        lines = [
            "# 🛡️ Oraik Shadow API Attack Surface Report", "",
            f"**Target:** `{target}`  ",
            f"**Generated:** {now}  ",
            f"**Endpoints Audited:** {len(audit_results)}  ",
            f"**Shadow APIs Found:** {len(shadow_apis)}  ",
            f"**Dangerous Endpoints:** {len(dangerous)}  ", "", "---", "",
        ]

        # Executive Summary
        total_issues = sum(len(r.get("issues", [])) for r in audit_results)
        critical = sum(1 for r in audit_results for i in r.get("issues", []) if i.get("severity") == "CRITICAL")
        high = sum(1 for r in audit_results for i in r.get("issues", []) if i.get("severity") == "HIGH")
        lines.extend([
            "## 📋 Executive Summary", "",
            f"| Metric | Value |", f"|--------|-------|",
            f"| Endpoints audited | {len(audit_results)} |",
            f"| Shadow APIs | {len(shadow_apis)} |",
            f"| Dangerous endpoints | {len(dangerous)} |",
            f"| Total security issues | {total_issues} |",
            f"| Critical issues | {critical} |",
            f"| High issues | {high} |",
            f"| GDPR/DPDP risks | {len(gdpr_risks)} |", "", "---", "",
        ])

        # Dangerous Endpoints (Kill List)
        if dangerous:
            lines.extend(["## 🔴 Kill List — Dangerous Endpoints", ""])
            for idx, ep in enumerate(dangerous, 1):
                sev_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(ep["severity"], "⚪")
                lines.extend([
                    f"### {idx}. {sev_emoji} {ep['path']}", "",
                    f"| Field | Value |", f"|-------|-------|",
                    f"| URL | `{ep['url']}` |",
                    f"| Category | {ep['category']} |",
                    f"| Risk | {ep['risk']} |",
                    f"| Severity | {ep['severity']} |",
                    f"| Shadow API | {'Yes' if ep.get('is_shadow') else 'No'} |", "",
                ])

        # Shadow APIs
        if shadow_apis:
            lines.extend(["## 👻 Shadow APIs (Undocumented)", ""])
            lines.append("| # | Path | Status | Discovery Method |")
            lines.append("|---|------|--------|-----------------|")
            for idx, api in enumerate(shadow_apis[:30], 1):
                lines.append(f"| {idx} | `{api.get('path', api.get('url', ''))}` | {api.get('status_code', '—')} | {api.get('discovery_method', '—')} |")
            lines.extend(["", "---", ""])

        # GDPR/DPDP Risks
        if gdpr_risks:
            lines.extend(["## ⚖️ GDPR / DPDP Compliance Risks", ""])
            for idx, risk in enumerate(gdpr_risks, 1):
                lines.extend([
                    f"### {idx}. {risk['data_type']} — {risk['url']}", "",
                    f"- **Regulation:** {risk['regulation']}",
                    f"- **Risk:** {risk['risk']}",
                    f"- **Severity:** {risk['severity']}", "",
                ])

        # Firewall Rules
        lines.extend([
            "## 🔥 Recommended Firewall Rules", "",
            "### Nginx Deny Rules", "", "```nginx", nginx_rules, "```", "",
            "### iptables Rules", "", "```bash", iptables_rules, "```", "",
            "---", "",
            "*Report generated by Oraik Shadow API Attack Surface Management*", "",
        ])

        return "\n".join(lines)

    def _build_json(self, target, audit_results, shadow_apis, dangerous, gdpr_risks, nginx_rules, iptables_rules) -> dict:
        """Build structured JSON report."""
        return {
            "report": {
                "tool": "Oraik Shadow API Scanner",
                "version": "1.0.0",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "target": target,
            },
            "summary": {
                "endpoints_audited": len(audit_results),
                "shadow_apis": len(shadow_apis),
                "dangerous_endpoints": len(dangerous),
                "total_issues": sum(len(r.get("issues", [])) for r in audit_results),
                "gdpr_risks": len(gdpr_risks),
            },
            "dangerous_endpoints": dangerous,
            "shadow_apis": [{"url": a.get("url"), "path": a.get("path"), "method": a.get("discovery_method")} for a in shadow_apis],
            "gdpr_risks": gdpr_risks,
            "audit_details": [
                {
                    "url": r["url"], "status_code": r.get("status_code"),
                    "tls_enforced": r.get("tls_enforced"),
                    "auth_required": r.get("auth_required"),
                    "rate_limited": r.get("rate_limited"),
                    "issues": r.get("issues", []),
                    "sensitive_data": r.get("sensitive_data", []),
                } for r in audit_results
            ],
            "firewall_rules": {"nginx": nginx_rules, "iptables": iptables_rules},
        }
