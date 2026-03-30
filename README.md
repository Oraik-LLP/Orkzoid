<p align="center">
  <img src="orkzoid.png" alt="Orkzoid" width="200">
</p>

# Orkzoid — Autonomous Security Platform

> **Proactive Threat Intelligence & Shadow API Attack Surface Management**

Orkzoid is a Python-based autonomous security platform consisting of two products designed for offensive security professionals, bug bounty hunters, and DevSecOps teams.

---

## Products

### Product 1 — Proactive Threat Intelligence & Automated Incident Response

Scans targets for open ports, correlates discovered services with known CVEs from NVD, scores attack vectors by severity, and generates remediation playbooks.

```bash
python product1_threat_intel/orkzoid_threat.py --target 192.168.1.0/24 --output report.md
```

**Features:**
- Network reconnaissance via `nmap` (port scanning, service/version detection)
- CVE correlation using NVD API v2.0
- CVSS-based attack vector scoring and ranking (Critical → Low)
- Automated remediation playbook generation (per-CVE patches, hardening commands)
- Rich terminal UI with progress bars and color-coded severity
- JSON + Markdown report generation

---

### Product 2 — Shadow API Attack Surface Management

Discovers undocumented API endpoints, audits them for security misconfigurations, diffs against OpenAPI specs, and generates firewall kill-lists.

```bash
python product2_shadow_api/orkzoid_api.py --target example.com --spec openapi.json --output report.md
```

**Features:**
- API endpoint discovery via:
  - Wordlist brute-force (200+ common API paths)
  - HTML/JS bundle crawling (fetch/axios/XHR regex extraction)
  - Wayback Machine CDX API for historical URLs
  - DNS subdomain enumeration
- Endpoint security auditing:
  - TLS/HTTPS enforcement
  - Authentication checks (401/403 vs 200)
  - Rate limiting detection (X-RateLimit, Retry-After headers)
  - Sensitive data exposure scanning (emails, API keys, tokens, PII)
- OpenAPI/Swagger spec diffing → shadow API detection
- Kill-list report with nginx/iptables firewall rules
- GDPR/DPDP risk flagging
- Rich terminal UI with tables and progress bars

---

## Installation

### Prerequisites
- Python 3.10+
- `nmap` installed on the system (for Product 1)

### Setup

```bash
# Clone or navigate to the project
cd Orkzoid

# Install dependencies
pip install -r requirements.txt
```

---

## Usage

### Unified CLI (Recommended)

```bash
# Threat Intelligence scan
python orkzoid.py --mode threat --target 192.168.1.1

# Shadow API scan
python orkzoid.py --mode api --target example.com --spec openapi.json

# With NVD API key for faster CVE lookups
python orkzoid.py --mode threat --target 10.0.0.0/24 --api-key YOUR_KEY
```

### Direct Product Scripts

```bash
# Product 1 — Threat Intelligence
python product1_threat_intel/orkzoid_threat.py --target 10.0.0.1
python product1_threat_intel/orkzoid_threat.py --target 192.168.1.0/24 --timeout 10 --api-key YOUR_KEY

# Product 2 — Shadow API Scanner
python product2_shadow_api/orkzoid_api.py --target example.com
python product2_shadow_api/orkzoid_api.py --target example.com --spec openapi.json --output api_report
```

### Common Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--mode` | `threat` or `api` (unified CLI only) | *Required* |
| `--target` | Target IP, CIDR, or domain | *Required* |
| `--timeout` | Network operation timeout (seconds) | `5` |
| `--output` | Output report filename | Auto-generated |
| `--api-key` | NVD API key for faster CVE lookups (threat mode) | `None` |
| `--spec` | OpenAPI/Swagger spec file (api mode only) | `None` |

> **Note:** Product 1 (Threat Intel) uses nmap. For full SYN scan + NSE scripts, run with `sudo`/admin. Without root, it automatically falls back to TCP connect scan.

---

## Project Structure

```
Orkzoid/
├── README.md
├── requirements.txt
├── product1_threat_intel/
│   ├── orkzoid_threat.py       # Main entry point
│   ├── modules/
│   │   ├── recon.py          # nmap scanning, service detection
│   │   ├── cve_correlator.py # Fetch CVEs from NVD API, match to services
│   │   ├── attack_scorer.py  # Score & rank attack vectors by severity
│   │   └── playbook.py       # Generate remediation playbooks per finding
│   └── reports/              # Auto-generated JSON + Markdown reports
└── product2_shadow_api/
    ├── orkzoid_api.py          # Main entry point
    ├── modules/
    │   ├── discoverer.py     # Crawl JS bundles, Wayback, wordlist brute-force
    │   ├── auditor.py        # Check auth, TLS, rate-limiting, data exposure
    │   ├── shadow_detector.py# Diff discovered endpoints vs OpenAPI/Swagger spec
    │   └── kill_report.py    # Flag dangerous APIs, generate firewall rules
    ├── wordlists/            # Common API path wordlists
    └── reports/              # Auto-generated JSON + Markdown reports
```

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `requests` | HTTP requests for API calls and endpoint probing |
| `python-nmap` | Python wrapper for nmap network scanner |
| `rich` | Terminal UI (tables, progress bars, panels) |
| `colorama` | Cross-platform colored terminal output |
| `dnspython` | DNS queries and subdomain enumeration |
| `beautifulsoup4` | HTML/JS parsing for endpoint extraction |
| `lxml` | Fast XML/HTML parser backend |

---

## Legal Disclaimer

**Orkzoid is intended for authorized security testing only.** Always obtain proper authorization before scanning any target. Unauthorized scanning of networks and APIs may violate local, state, and federal laws. The authors are not responsible for misuse of this tool.

---

## License

MIT License — See [LICENSE](LICENSE) for details.
