# Securing the Software Supply Chain

A multi-ecosystem security analysis tool for detecting vulnerabilities and supply chain threats in Python, Node.js, and Java projects. Combines real-time vulnerability intelligence with adaptive threat detection to give you accurate, actionable risk assessments.

[![CI](https://github.com/skishu0413/Securing-the-Software-Supply-Chain/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/skishu0413/Securing-the-Software-Supply-Chain/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

## What it does

- Scans dependency files (`requirements.txt`, `package-lock.json`, `pom.xml`) for known vulnerabilities
- Queries both **OSV** and **NVD** databases, deduplicates results, and enriches with CVSS scores
- Detects supply chain threats — typosquatting, dependency confusion, abandoned packages, poor metadata
- Scores each vulnerable package on a 0–100 risk scale using a 6-component methodology
- Outputs results to the terminal, JSON, or CSV

---

## Supported ecosystems

| Ecosystem | Input file |
|-----------|-----------|
| Python    | `requirements.txt` / any pip requirements file |
| Node.js   | `package-lock.json` |
| Java      | `pom.xml` |

---

## Installation

**Requirements:** Python 3.9+, internet access

```bash
git clone https://github.com/skishu0413/Securing-the-Software-Supply-Chain.git
cd Securing-the-Software-Supply-Chain
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
```

---

## Quick start

```bash
# Python project
python3 src/main.py requirements.txt --type pypi

# Node.js project
python3 src/main.py package-lock.json --type npm

# Java Maven project
python3 src/main.py pom.xml --type maven
```

### Using the sample test files

```bash
python3 src/main.py test_files/comprehensive_requirements.txt --type pypi
python3 src/main.py test_files/package-lock.json --type npm
python3 src/main.py test_files/pom.xml --type maven
```

---

## Output formats

```bash
# Default terminal output
python3 src/main.py requirements.txt --type pypi

# JSON export
python3 src/main.py requirements.txt --type pypi --format json --output report.json

# CSV export
python3 src/main.py requirements.txt --type pypi --format csv --output report

# Verbose risk breakdown per package
python3 src/main.py requirements.txt --type pypi --verbose-risk

# Show the risk scoring methodology
python3 src/main.py --show-methodology
```

---

## Sample output

```
--- Vulnerability Report ---

📦 Dependency: cryptography@1.9.0
   Overall Severity: CRITICAL | Risk Score: 100/100
   📈 Risk Breakdown → Severity:32 | Exploit:20 | Exposure:9 | Volume:9 | Patch:0 | Credibility:4
   💡 Recommendation: Upgrade to version 41.0.0 or later
   Vulnerabilities:
     - ID: CVE-2020-36242 | SOURCE: NVD | Advisory: https://nvd.nist.gov/vuln/detail/CVE-2020-36242
     - ID: CVE-2023-0286  | SOURCE: NVD, OSV | Advisory: https://osv.dev/vulnerability/GHSA-3ww4-gg4f-jr7f

📊 Risk Summary:
   🔴 Critical : 3 packages (Score ≥ 85)
   🟠 High     : 5 packages (Score 65–84)
   🟡 Medium   : 4 packages (Score 35–64)
   🟢 Low      : 2 packages (Score < 35)
   📈 Total vulnerable dependencies: 14
```

```
--- Suspicious Package Report ---

 - Typosquatting (2 packages):
   📦 requuests: 94% similar to 'requests'
   📦 flasks: 91% similar to 'flask'

 - Dependency Confusion (1 package):
   📦 internal-auth: Package not found on public pypi registry.

 - Abnormal Update Frequency (3 packages):
   📦 pip-requirements-parser: Not updated since 2022 (abandoned).

Total suspicious dependencies found: 6
```

---

## Risk scoring

Each vulnerable package receives a score from 0 to 100 based on six weighted components:

```
Score = Base Severity (35%) + Exploit Pressure (25%) + Exposure Context (15%)
      + Volume (10%) + Patch Gap (10%) + Credibility (5%)
```

| Component | Weight | What it measures |
|-----------|--------|-----------------|
| Base Severity | 35% | CVSS score, severity distribution, age of CVE |
| Exploit Pressure | 25% | CISA KEV status, EPSS score, attack vector |
| Exposure Context | 15% | Package type (network lib, parser, crypto, etc.) |
| Volume | 10% | Number of vulnerabilities, log-scaled |
| Patch Gap | 10% | Whether a fix is available |
| Credibility | 5% | Source reputation and reference quality |

Weights are fully configurable in `src/config.yaml`.

---

## Supply chain threat detection

The scanner checks every package for:

- **Typosquatting** — fuzzy name similarity against known popular packages
- **Dependency confusion** — package exists internally but not on the public registry
- **Abandoned packages** — no updates in 2+ years
- **Poor metadata** — missing description, no homepage, no author
- **Unusual versioning** — abnormally high or non-PEP 440 version strings

Detection thresholds adapt over time as the scanner learns from each scan.

---

## Performance

NVD imposes a rate limit of 5 requests/30 seconds without an API key. For large dependency lists this adds up. A free API key raises the limit to 50 requests/30 seconds and cuts scan times significantly.

```bash
# Get a free key at: https://nvd.nist.gov/developers/request-an-api-key
export NVD_API_KEY="your-api-key-here"
```

The scanner also maintains a persistent disk cache (`cache/`) with 24–72 hour TTLs so packages seen in previous scans don't require a network round-trip.

Approximate scan times:

| Project size | Without API key | With API key |
|-------------|----------------|--------------|
| < 20 deps   | 30–60s         | 10–20s       |
| 20–100 deps | 2–5 min        | 30–90s       |
| 100+ deps   | 5–15 min       | 1–3 min      |

---

## Configuration

All settings live in `src/config.yaml`. Key options:

```yaml
# NVD rate limiting
nvd:
  request_delay_without_key: 6.0   # seconds between requests (no key)
  request_delay_with_key: 0.6      # seconds between requests (with key)
  min_cvss_score: 3.0              # ignore CVEs below this threshold

# Risk score weights (must sum to 100)
risk_weights:
  base_severity: 35
  exploit_pressure: 25
  exposure_context: 15
  volume: 10
  patch_gap: 10
  credibility: 5

# Vulnerability age boosts
risk_scoring:
  very_recent_vuln_days: 30   # CVEs newer than this get a score boost
  very_recent_boost: 0.2      # +20%
```

---

## Running tests

```bash
pytest tests/ -v
```

Tests cover parsers, the risk scorer, and the NVD checker using property-based testing (Hypothesis) alongside standard unit tests. CI runs on Python 3.9 and 3.11 on every push and pull request.

---

## Project structure

```
.
├── src/
│   ├── main.py                        # CLI entry point and scan orchestration
│   ├── config.py / config.yaml        # Configuration
│   ├── dependency_parser/             # Parsers for requirements.txt, package-lock.json, pom.xml
│   ├── vulnerability_checker/         # OSV and NVD API integration
│   ├── risk_scorer/                   # 6-component risk scoring engine
│   ├── suspicious_package_detector/   # Supply chain threat detection
│   └── threat_analysis/               # Adaptive learning and pattern detection
├── tests/                             # Unit and property-based tests
├── test_files/                        # Sample dependency files for manual testing
├── cache/                             # Runtime API cache (not committed to git)
├── requirements-dev.txt               # Python dependencies
├── pyproject.toml                     # Project metadata
└── .github/workflows/ci.yml           # CI pipeline
```

---

## Troubleshooting

**Scan is very slow**
Set `NVD_API_KEY` — see [Performance](#performance) above.

**Rate limit warnings from NVD**
Normal without an API key. The scanner backs off automatically. Set the key to avoid this entirely.

**`WARNING: Malformed CVSS vector` messages**
These are silently skipped CVSS v4.0 vectors that the `cvss` library doesn't yet support. Scores for those CVEs come from the NVD numeric `baseScore` field instead. No data is lost.

**Package shows as suspicious but is legitimate**
The adaptive detector improves with each scan. If a false positive persists, raise an issue.

---

## License

MIT
