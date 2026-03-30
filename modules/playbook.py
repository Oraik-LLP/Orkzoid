"""
playbook.py — Remediation Playbook Generator
==============================================
Generates detailed Markdown and JSON remediation playbooks
based on scored vulnerability findings.
"""

import json
import os
from datetime import datetime, timezone
from rich.console import Console
from rich.panel import Panel

console = Console()

# Remediation templates for common services
REMEDIATION_DB = {
    "apache": {
        "update_cmd": "sudo apt update && sudo apt install --only-upgrade apache2",
        "hardening": [
            "Disable directory listing: `Options -Indexes` in httpd.conf",
            "Hide server version: `ServerTokens Prod` and `ServerSignature Off`",
            "Enable mod_security: `sudo a2enmod security2`",
            "Enable mod_headers: Add `Header always set X-Content-Type-Options nosniff`",
            "Restrict HTTP methods: Allow only GET, POST, HEAD",
        ],
        "config_fixes": [
            "Set `Timeout 60` to prevent slowloris attacks",
            "Configure `MaxClients` based on available RAM",
            "Enable HTTPS with strong ciphers (TLS 1.2+)",
        ],
    },
    "nginx": {
        "update_cmd": "sudo apt update && sudo apt install --only-upgrade nginx",
        "hardening": [
            "Hide server version: `server_tokens off;` in nginx.conf",
            "Add security headers in server block",
            "Limit request body size: `client_max_body_size 1m;`",
            "Rate limit connections: Use `limit_req_zone` directive",
            "Disable unused HTTP methods",
        ],
        "config_fixes": [
            "Enable HTTPS with `ssl_protocols TLSv1.2 TLSv1.3;`",
            "Set `ssl_ciphers HIGH:!aNULL:!MD5;`",
            "Add `add_header X-Frame-Options DENY;`",
        ],
    },
    "openssh": {
        "update_cmd": "sudo apt update && sudo apt install --only-upgrade openssh-server",
        "hardening": [
            "Disable root login: `PermitRootLogin no` in sshd_config",
            "Use key-based auth only: `PasswordAuthentication no`",
            "Change default port: `Port 2222` (or any non-standard port)",
            "Limit login attempts: `MaxAuthTries 3`",
            "Use AllowUsers/AllowGroups to restrict access",
            "Enable 2FA: Install libpam-google-authenticator",
        ],
        "config_fixes": [
            "Set `LoginGraceTime 30`",
            "Set `ClientAliveInterval 300` and `ClientAliveCountMax 2`",
            "Disable X11 forwarding: `X11Forwarding no`",
        ],
    },
    "mysql": {
        "update_cmd": "sudo apt update && sudo apt install --only-upgrade mysql-server",
        "hardening": [
            "Run `mysql_secure_installation`",
            "Bind to localhost: `bind-address = 127.0.0.1` in my.cnf",
            "Remove anonymous users and test databases",
            "Set strong password policy",
            "Enable audit logging",
        ],
        "config_fixes": [
            "Set `local-infile=0` to prevent local file reads",
            "Set `skip-symbolic-links` to prevent symlink attacks",
            "Enable SSL for remote connections",
        ],
    },
    "postgresql": {
        "update_cmd": "sudo apt update && sudo apt install --only-upgrade postgresql",
        "hardening": [
            "Configure pg_hba.conf: Use `scram-sha-256` instead of `trust` or `md5`",
            "Bind to localhost: `listen_addresses = 'localhost'` in postgresql.conf",
            "Enable SSL: `ssl = on` in postgresql.conf",
            "Set `log_connections = on` and `log_disconnections = on`",
            "Restrict superuser access",
        ],
        "config_fixes": [
            "Set connection limits per user/database",
            "Enable row-level security policies where applicable",
        ],
    },
    "default": {
        "update_cmd": "Update the service to the latest stable version using your package manager",
        "hardening": [
            "Follow vendor-specific hardening guides",
            "Restrict network access with firewall rules",
            "Enable logging and monitoring",
            "Apply principle of least privilege",
            "Regularly audit configurations",
        ],
        "config_fixes": [
            "Review and apply CIS benchmarks for this service",
            "Enable TLS/SSL where applicable",
            "Disable unnecessary features and modules",
        ],
    },
}


class PlaybookGenerator:
    """
    Generates remediation playbooks in Markdown and JSON formats
    from scored vulnerability findings.
    """

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def generate(
        self,
        scored_findings: list[dict],
        target: str,
        output_filename: str | None = None,
    ) -> tuple[str, str]:
        """
        Generate remediation playbooks in both Markdown and JSON.

        Args:
            scored_findings: Output from AttackScorer.score()
            target: Original scan target
            output_filename: Optional output filename (without extension)

        Returns:
            Tuple of (markdown_path, json_path)
        """
        if not output_filename:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            output_filename = f"oraik_threat_report_{timestamp}"

        md_path = os.path.join(self.output_dir, f"{output_filename}.md")
        json_path = os.path.join(self.output_dir, f"{output_filename}.json")

        console.print(
            Panel(
                f"[bold cyan]📝 Generating remediation playbook[/bold cyan]\n"
                f"[dim]Target: {target}[/dim]\n"
                f"[dim]Findings: {len(scored_findings)}[/dim]",
                title="[bold blue]Playbook Generator[/bold blue]",
                border_style="blue",
            )
        )

        # Generate Markdown report
        md_content = self._generate_markdown(scored_findings, target)
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md_content)

        # Generate JSON report
        json_content = self._generate_json(scored_findings, target)
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(json_content, f, indent=2, default=str)

        console.print(f"[bold green]✓[/bold green] Markdown report saved: [cyan]{md_path}[/cyan]")
        console.print(f"[bold green]✓[/bold green] JSON report saved:     [cyan]{json_path}[/cyan]")

        return md_path, json_path

    def _generate_markdown(self, findings: list[dict], target: str) -> str:
        """Generate a comprehensive Markdown remediation playbook."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        lines = [
            f"# 🛡️ Oraik Threat Intelligence Report",
            f"",
            f"**Target:** `{target}`  ",
            f"**Generated:** {now}  ",
            f"**Total Findings:** {len(findings)}  ",
            f"",
            f"---",
            f"",
        ]

        # Executive Summary
        lines.extend(self._generate_executive_summary(findings))

        # Group findings by severity
        severity_groups = {}
        for finding in findings:
            sev = finding.get("cvss_severity", "UNKNOWN")
            severity_groups.setdefault(sev, []).append(finding)

        # Detailed findings by severity
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        severity_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}

        for severity in severity_order:
            group = severity_groups.get(severity, [])
            if not group:
                continue

            emoji = severity_emoji.get(severity, "⚪")
            lines.append(f"## {emoji} {severity} Severity Findings ({len(group)})")
            lines.append("")

            for idx, finding in enumerate(group, 1):
                lines.extend(self._generate_finding_section(finding, idx))

        # Appendix: Hardening checklist
        lines.extend(self._generate_hardening_checklist(findings))

        return "\n".join(lines)

    def _generate_executive_summary(self, findings: list[dict]) -> list[str]:
        """Generate an executive summary section."""
        stats = {}
        for f in findings:
            sev = f.get("cvss_severity", "UNKNOWN")
            stats[sev] = stats.get(sev, 0) + 1

        lines = [
            "## 📋 Executive Summary",
            "",
            "| Severity | Count |",
            "|----------|-------|",
        ]

        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = stats.get(sev, 0)
            if count > 0:
                lines.append(f"| {sev} | {count} |")

        lines.extend([
            "",
            f"**Total vulnerabilities:** {len(findings)}",
            "",
            "---",
            "",
        ])

        return lines

    def _generate_finding_section(self, finding: dict, idx: int) -> list[str]:
        """Generate a detailed section for a single finding."""
        service_name = (finding.get("service", "") or "unknown").lower()
        remediation = self._get_remediation(service_name)

        lines = [
            f"### {idx}. {finding['cve_id']}",
            "",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| **CVSS Score** | {finding['cvss_score']:.1f} |",
            f"| **Severity** | {finding['cvss_severity']} |",
            f"| **Host** | `{finding['host']}:{finding['port']}` |",
            f"| **Service** | {finding['service']} {finding.get('version', '')} |",
            f"| **Risk Rating** | {finding['risk_rating']} |",
            f"| **Published** | {finding.get('published', 'N/A')} |",
            "",
            f"**Description:**  ",
            f"{finding['description']}",
            "",
        ]

        # CVSS Vector (if available)
        if finding.get("cvss_vector"):
            lines.extend([
                f"**CVSS Vector:**  ",
                f"`{finding['cvss_vector']}`",
                "",
            ])

        # Remediation steps
        lines.extend([
            f"#### 🔧 Remediation Steps",
            "",
            f"**1. Update/Patch:**",
            f"```bash",
            f"{remediation['update_cmd']}",
            f"```",
            "",
            f"**2. Hardening Measures:**",
        ])

        for step in remediation["hardening"]:
            lines.append(f"- {step}")

        lines.append("")
        lines.append("**3. Configuration Fixes:**")

        for fix in remediation["config_fixes"]:
            lines.append(f"- {fix}")

        # References
        if finding.get("references"):
            lines.extend(["", "**References:**"])
            for ref in finding["references"]:
                lines.append(f"- [{ref}]({ref})")

        lines.extend(["", "---", ""])

        return lines

    def _generate_hardening_checklist(self, findings: list[dict]) -> list[str]:
        """Generate a general hardening checklist appendix."""
        lines = [
            "## ✅ General Hardening Checklist",
            "",
            "- [ ] Update all services to latest stable versions",
            "- [ ] Apply all critical and high CVE patches",
            "- [ ] Enable firewall rules (iptables/nftables/ufw)",
            "- [ ] Configure fail2ban for brute-force protection",
            "- [ ] Enable TLS 1.2+ on all services",
            "- [ ] Disable unnecessary services and ports",
            "- [ ] Implement network segmentation",
            "- [ ] Set up centralized logging (syslog/ELK)",
            "- [ ] Configure intrusion detection (Snort/Suricata)",
            "- [ ] Schedule regular vulnerability scans",
            "- [ ] Review and rotate credentials",
            "- [ ] Apply CIS benchmarks for all running services",
            "",
            "---",
            "",
            "*Report generated by [Oraik](https://github.com/oraik) Threat Intelligence Platform*",
            "",
        ]

        return lines

    def _get_remediation(self, service_name: str) -> dict:
        """
        Look up remediation steps for a given service.
        Falls back to generic advice if service isn't recognized.
        """
        service_lower = service_name.lower().strip()

        for key in REMEDIATION_DB:
            if key in service_lower:
                return REMEDIATION_DB[key]

        return REMEDIATION_DB["default"]

    def _generate_json(self, findings: list[dict], target: str) -> dict:
        """Generate a structured JSON report."""
        return {
            "report": {
                "tool": "Oraik Threat Intelligence",
                "version": "1.0.0",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "target": target,
            },
            "summary": {
                "total_findings": len(findings),
                "critical": sum(1 for f in findings if f.get("cvss_severity") == "CRITICAL"),
                "high": sum(1 for f in findings if f.get("cvss_severity") == "HIGH"),
                "medium": sum(1 for f in findings if f.get("cvss_severity") == "MEDIUM"),
                "low": sum(1 for f in findings if f.get("cvss_severity") == "LOW"),
                "info": sum(1 for f in findings if f.get("cvss_severity") == "INFO"),
            },
            "findings": [
                {
                    "cve_id": f["cve_id"],
                    "cvss_score": f["cvss_score"],
                    "cvss_severity": f["cvss_severity"],
                    "cvss_vector": f.get("cvss_vector", ""),
                    "host": f["host"],
                    "port": f["port"],
                    "service": f["service"],
                    "version": f.get("version", ""),
                    "description": f["description"],
                    "risk_rating": f["risk_rating"],
                    "published": f.get("published", ""),
                    "references": f.get("references", []),
                    "remediation": self._get_remediation((f.get("service", "") or "").lower()),
                }
                for f in findings
            ],
        }
