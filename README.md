# SecurePipe

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Latest tag](https://img.shields.io/github/v/tag/ismailarici/securepipe)](https://github.com/ismailarici/securepipe/tags)
[![Example pipeline](https://github.com/ismailarici/secureapp-v2/actions/workflows/pipeline.yml/badge.svg)](https://github.com/ismailarici/secureapp-v2/actions/workflows/pipeline.yml)

A plug-and-play DevSecOps pipeline that runs in under 5 minutes and produces audit-ready security reports.

Run it locally against any codebase. Scan an entire org's services with one command. Wire it into GitHub Actions for continuous scanning.

---

## Who this is for

- **Engineering teams without a dedicated security engineer** who need automated scanning before an audit
- **Startups preparing for SOC 2 or ISO 27001** who want evidence without hiring a consultant
- **Platform teams** rolling out a security baseline across multiple repos
- **Solo developers** who want the same coverage a well-staffed security team would run

It is not for teams that already have Snyk or Semgrep Pro and are happy with them. If your existing tooling works, keep it. SecurePipe is for teams that want serious coverage without per-seat licensing costs.

---

## What problem it solves

Most teams know they should run SAST, SCA, and container scanning. In practice, each tool has a different setup, different output format, and different CI configuration. A week of work turns into months of drift.

SecurePipe standardises all of it into a single command. One output. One report. Formats that auditors can open without explanation.

---

## Quick start (local)

Prerequisites: Docker and Python 3.

```bash
git clone https://github.com/ismailarici/securepipe.git
cd securepipe
./securepipe scan --target ./sample-apps/python
```

That runs SAST, SCA, and container scanning against the included vulnerable sample app and writes `reports/security-report.html`. DAST is skipped unless `--url` is provided.

Open the report:

```bash
open reports/security-report.html   # macOS
xdg-open reports/security-report.html  # Linux
```

To scan your own code:

```bash
./securepipe scan --target /path/to/your/app
```

To include DAST (requires a running app):

```bash
./securepipe scan --target ./your-app --url http://localhost:3000
```

---

## CLI reference

```
./securepipe scan [--target <path>] [--url <url>] [--openapi <spec>] [--auth-header "Header: Value"] [--output-dir <path>]
./securepipe org-scan [--config <securepipe-org.yml>]
./securepipe report
./securepipe clean
```

| Command | What it does |
|---------|-------------|
| `scan` | Runs SAST, SCA, SBOM (Java), container scan, and optionally DAST. Writes `reports/security-report.html` |
| `org-scan` | Scans multiple repos defined in a YAML config, writes per-repo reports and an aggregated `org-summary.html` |
| `report` | Re-generates the HTML report from existing raw results without re-running scans |
| `clean` | Deletes the `reports/` directory and removes the temporary Docker image |

### Scan flags

| Flag | Description |
|------|-------------|
| `--target <path>` | Directory to scan (default: current directory) |
| `--url <url>` | Run ZAP baseline DAST against a live URL |
| `--openapi <spec>` | Run ZAP API scan using an OpenAPI YAML or JSON spec |
| `--auth-header "Header: Value"` | Inject an auth header into every ZAP request (e.g. `"Authorization: Bearer token"`) |
| `--output-dir <path>` | Write reports to a custom directory (used internally by `org-scan`) |

### Environment variables

| Variable | Description |
|----------|-------------|
| `NVDAPIKEY` | NVD API key for OWASP Dependency-Check. Free to obtain at nvd.nist.gov/developers/request-an-api-key. Without it, the first Java scan is very slow due to NVD rate limits. |

---

## Security stack

| Stage | Tool | Languages | Why |
|-------|------|-----------|-----|
| SAST | Semgrep | Python, Node.js, Java | Fast, accurate, 1000+ rules, runs in Docker with zero config |
| SCA | pip-audit | Python | Official CVE detection for Python packages |
| SCA | npm audit | Node.js | CVE detection for npm packages |
| SCA | OWASP Dependency-Check | Java | CVE detection for Maven/Gradle dependencies |
| SBOM | Syft | Java | Full software bill of materials in SPDX format |
| Container scan | Trivy | All | Scans both Dockerfile images and filesystem; covers OS packages and language deps |
| DAST (baseline) | OWASP ZAP | All | Runtime scan for injection, missing headers, broken access |
| DAST (API) | OWASP ZAP api-scan | All | OpenAPI-driven scan that tests every defined endpoint |

Language detection is automatic — SecurePipe reads `pom.xml`/`build.gradle` for Java, `requirements.txt` for Python, `package.json` for Node.js.

TruffleHog (secret scanning across git history) runs in the GitHub Actions pipeline, not the local CLI, because it needs the full git history to be effective.

---

## Multi-repo scanning

To scan multiple services and get a unified org-level report:

```bash
./securepipe org-scan --config securepipe-org.yml
```

Create a `securepipe-org.yml` config:

```yaml
repos:
  - name: python-api
    path: ./repos/python-api

  - name: node-frontend
    path: ./repos/node-frontend
    url: http://localhost:3000        # optional: enables DAST

  - name: java-service
    path: ./repos/java-service
```

This produces:

```
reports/
├── org-summary.html          ← aggregated view across all repos
├── python-api/
│   ├── security-report.html  ← per-service report (for auditors)
│   └── raw/                  ← raw JSON from each tool
├── node-frontend/
│   ├── security-report.html
│   └── raw/
└── java-service/
    ├── security-report.html
    └── raw/
```

`org-summary.html` shows total findings, severity breakdown, and a per-repo status table. Each repo name links to its individual report. Both the summary and individual reports are self-contained HTML — no server required to open them.

**For audits:** submit the individual `security-report.html` per service plus `org-summary.html` as the executive summary. The `raw/` folders contain the machine-readable JSON for deeper review.

If one repo fails, scanning continues for the remaining repos.

An example config is at `examples/securepipe-org.yml`.

---

## DAST — OpenAPI and authenticated scanning

### OpenAPI-driven scan

Pass an OpenAPI spec to ensure every defined endpoint is tested:

```bash
./securepipe scan --target ./api --openapi ./openapi.yaml
```

Supports both YAML and JSON specs. SecurePipe passes the spec to ZAP's `api-scan` mode, which imports the endpoint list and actively probes each one.

### Authenticated DAST

Add an auth header to every ZAP request:

```bash
./securepipe scan --url http://localhost:3000 --auth-header "Authorization: Bearer $TOKEN"
```

The header value is never logged. To avoid the token appearing in your shell history, pass it via an environment variable:

```bash
./securepipe scan --url http://localhost:3000 --auth-header "Authorization: Bearer $(cat .token)"
```

---

## Java support

SecurePipe detects Java projects automatically via `pom.xml` or `build.gradle` and runs:

- **Semgrep** with `--config auto` (includes Java rules for injection, XXE, insecure deserialization)
- **OWASP Dependency-Check** — Docker-based CVE scan of Maven/Gradle dependencies
- **Syft** — generates SBOM in SPDX JSON format
- **Trivy** — container scan if a Dockerfile is present, filesystem scan otherwise

**First run note:** OWASP Dependency-Check downloads the NVD vulnerability database on first use. This takes several minutes without an API key and is much faster with one. Get a free key at [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key) and set `export NVDAPIKEY=your-key`. The database is cached at `~/.dependency-check/data/` so subsequent runs are fast.

---

## Sample apps

Three deliberately vulnerable sample apps are included for demo scans:

| App | Path | Seeded issues |
|-----|------|---------------|
| Python (Flask) | `sample-apps/python/` | SQL injection, command injection, insecure deserialization, hardcoded credentials, debug mode, old deps |
| Node.js (Express) | `sample-apps/node/` | Command injection, XSS, prototype pollution, hardcoded secrets, old deps (lodash 4.17.20, axios 0.21.1) |
| Java | `sample-apps/java/` | SQL injection, command injection, insecure deserialization, hardcoded credentials, log4j 2.14.1, jackson-databind 2.12.3 |

Run `./securepipe org-scan --config examples/securepipe-org.yml` to scan all three at once.

---

## Report

Each scan produces a self-contained HTML report with:

- Summary counts by severity (Critical, High, Medium, Low)
- Per-tool finding count
- Findings table sorted by severity — tool, file, line, description
- Recommendations with priority ranking
- Compliance mapping table (SOC 2, ISO 27001)

Raw JSON outputs are saved in `reports/raw/` alongside the HTML for auditor inspection.

---

## Compliance mapping

| Control | Tools | What it satisfies |
|---------|-------|------------------|
| SOC 2 — CC6.6 | Semgrep, pip-audit, OWASP-DC, Trivy | Logical access controls, vulnerability identification evidence |
| SOC 2 — CC7.1 | Semgrep, Trivy, ZAP | Detection and monitoring of security threats |
| ISO 27001 — A.12.6.1 | All tools | Technical vulnerability management — documented scan, findings, remediation |
| ISO 27001 — A.14.2.3 | Semgrep, ZAP | Application security testing after environment changes |

### Audit evidence

Every scan produces:

| Artifact | Location | Use |
|----------|----------|-----|
| HTML report | `reports/security-report.html` | Evidence package for auditors |
| Org summary | `reports/org-summary.html` | Executive summary across all services |
| Semgrep JSON | `reports/raw/semgrep.json` | Source code vulnerability detail |
| SCA JSON | `reports/raw/sca.json` | Dependency CVE inventory (pip-audit, npm-audit, or OWASP-DC) |
| SBOM JSON | `reports/raw/sbom.json` | Software bill of materials (Java only) |
| Trivy JSON | `reports/raw/trivy.json` | Container vulnerability inventory |
| ZAP JSON | `reports/raw/zap.json` | Runtime security findings |

All reports are timestamped and self-contained — no external dependencies to open them. Auditors can inspect the raw JSON files to verify tool versions and finding details.

To demonstrate compliance: run `./securepipe scan` before each release, store the `reports/` folder in a private evidence repository, and reference it in your control documentation.

---

## Architecture

```
./securepipe scan
│
├── run_sast()      → docker run returntocorp/semgrep      → raw/semgrep.json
├── run_sca()       → pip-audit / npm-audit / OWASP-DC     → raw/sca.json
│                     (auto-detected from project files)
├── run_sbom()      → docker run anchore/syft (Java only)  → raw/sbom.json
├── run_container() → docker run aquasec/trivy             → raw/trivy.json
│                     (image scan if Dockerfile, fs scan otherwise)
└── run_dast()      → docker run ghcr.io/zaproxy/zaproxy   → raw/zap.json
                      (skipped unless --url or --openapi provided)
                            │
                     scripts/generate-report.py
                            │
                     reports/security-report.html

./securepipe org-scan
│
├── scripts/org-scan.py
│     └── calls ./securepipe scan --output-dir reports/<repo> per repo
│
└── scripts/generate-org-report.py
      └── reads reports/*/raw/*.json → reports/org-summary.html
```

Each scanner runs in its own Docker container. Nothing is installed on the host. Org scan runs repos sequentially and continues if one fails.

---

## GitHub Actions pipeline

For CI, connect your repo to the reusable pipeline in one file:

```yaml
name: Security Pipeline

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  security-pipeline:
    uses: ismailarici/securepipe/.github/workflows/reusable-security-pipeline.yml@main
    with:
      app-language: python
      image-name: your-app-name
      app-port: "5000"
      fail-severity: HIGH
      aws-region: us-east-1
    secrets:
      AWS_ACCOUNT_ID: ${{ secrets.AWS_ACCOUNT_ID }}
      AWS_ROLE_ARN: ${{ secrets.AWS_ROLE_ARN }}
```

The GitHub Actions pipeline adds:

- **TruffleHog** — verified secret scanning across the entire git history
- **Bandit** — Python-specific SAST with SARIF output to the Security tab
- **Checkov** — Terraform and Dockerfile IaC misconfigurations
- **Syft** — SBOM generation in SPDX format
- **DefectDojo** integration — persistent finding management (optional)
- **Multi-cloud support** — AWS ECR, Azure ACR, and GCP Artifact Registry

See [docs/onboarding.md](docs/onboarding.md) for the full setup guide including AWS OIDC provisioning.

---

## Why not X?

### GitHub Advanced Security

GHAS is excellent if you are already paying for GitHub Enterprise. It covers secrets, code scanning, and Dependabot. It does not do container scanning or DAST. It requires per-seat licensing on private repos. SecurePipe runs the same scanners free, locally, on any repository.

### Snyk

Snyk has deeper SCA intelligence and a strong developer experience. It costs money at meaningful scale, requires an account, and phones home on every scan. SecurePipe is local-first — no account, no telemetry, no internet required after pulling Docker images.

### Manual toolchain

Running each tool manually means different output formats, different CI configs, and no unified report. The setup cost is non-trivial, and it falls apart when team members change. SecurePipe is one command, one output, no maintenance.

---

## Repository structure

```
securepipe/
├── securepipe                               # CLI entry point
├── scripts/
│   ├── generate-report.py                  # per-repo JSON → HTML report
│   ├── generate-org-report.py              # multi-repo → org-summary.html
│   └── org-scan.py                         # multi-repo scan orchestrator
├── .github/
│   └── workflows/
│       └── reusable-security-pipeline.yml  # GitHub Actions reusable pipeline
├── sample-apps/
│   ├── python/                             # vulnerable Flask app
│   ├── node/                               # vulnerable Express app
│   └── java/                              # vulnerable Java app (log4j, jackson-databind)
├── examples/
│   └── securepipe-org.yml                  # example org-scan config
├── terraform/                              # AWS OIDC + ECR provisioning
├── .semgrep/
│   └── custom-rules.yml                    # org-specific rules
├── .zap/
│   └── rules.tsv                           # ZAP passive rule overrides
├── docs/
│   ├── onboarding.md                       # CI setup guide
│   └── defect-dojo-setup.md                # DefectDojo deployment
├── setup.sh                                # generates caller workflow for CI
├── reports/                                # gitignored scan output
└── Makefile
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Validate YAML before committing (`make validate`). Test end to end against a real caller.

## Security

Report vulnerabilities via [GitHub Security Advisories](https://github.com/ismailarici/securepipe/security/advisories/new). See [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE).
