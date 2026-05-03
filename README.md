# SecurePipe

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Latest tag](https://img.shields.io/github/v/tag/ismailarici/securepipe)](https://github.com/ismailarici/securepipe/tags)
[![Example pipeline](https://github.com/ismailarici/secureapp-v2/actions/workflows/pipeline.yml/badge.svg)](https://github.com/ismailarici/secureapp-v2/actions/workflows/pipeline.yml)

A plug-and-play DevSecOps pipeline that runs in under 5 minutes and produces audit-ready security reports.

Run it locally against any codebase. Wire it into GitHub Actions for continuous scanning. Either way, one command is all it takes.

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

That runs four scans against the included vulnerable sample app and writes `reports/security-report.html`.

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
./securepipe scan [--target <path>] [--url <http://host:port>]
./securepipe report
./securepipe clean
```

| Command | What it does |
|---------|-------------|
| `scan` | Runs all four scanners, writes raw results to `reports/raw/`, generates `reports/security-report.html` |
| `report` | Re-generates the HTML report from existing raw results without re-running scans |
| `clean` | Deletes the `reports/` directory and removes the temporary Docker image |

---

## Security stack

| Stage | Tool | Why |
|-------|------|-----|
| SAST | Semgrep | Fast, accurate, 1000+ rules out of the box, runs in Docker with zero config |
| SCA | pip-audit / npm-audit | Official package-level CVE detection for Python and Node, auto-detected from project files |
| Container scan | Trivy | Scans both filesystem and Docker images, covers OS packages and language deps |
| DAST | OWASP ZAP baseline | Runtime scan for injection, missing headers, broken access — catches what static analysis misses |

TruffleHog (secret scanning across git history) runs in the GitHub Actions pipeline, not in the local CLI, because it needs the full git history to be effective. Wire up the Actions pipeline to get secret scanning on every push.

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

## Sample app

`sample-apps/python/` contains a deliberately vulnerable Flask app with seeded issues:

- SQL injection (unsanitised query string in database lookup)
- OS command injection (`shell=True` with user input)
- Insecure deserialization (`pickle.loads` on raw POST body)
- Hardcoded credentials (AWS key and database password in source)
- `debug=True` in production
- Vulnerable dependency versions (Flask 2.0.1, requests 2.27.1, Werkzeug 2.0.3)

Run `./securepipe scan --target ./sample-apps/python` to see all of them flagged.

---

## Report

The HTML report includes:

- Summary counts by severity (Critical, High, Medium, Low)
- Per-tool finding count
- Sortable findings table with tool, severity, file, line, and description
- Recommendations with priority ranking
- Compliance mapping table (SOC 2, ISO 27001)

Raw JSON outputs are saved in `reports/raw/` alongside the HTML for auditor inspection.

---

## Compliance mapping

| Control | Tools | What it satisfies |
|---------|-------|------------------|
| SOC 2 — CC6.6 | Semgrep, pip-audit, Trivy | Logical access controls, vulnerability identification evidence |
| SOC 2 — CC7.1 | Semgrep, Trivy, ZAP | Detection and monitoring of security threats |
| ISO 27001 — A.12.6.1 | All tools | Technical vulnerability management — documented scan, findings, remediation |
| ISO 27001 — A.14.2.3 | Semgrep, ZAP | Application security testing after environment changes |

### Audit evidence

Every scan produces:

| Artifact | Location | Use |
|----------|----------|-----|
| HTML report | `reports/security-report.html` | Evidence package for auditors |
| Semgrep JSON | `reports/raw/semgrep.json` | Source code vulnerability detail |
| SCA JSON | `reports/raw/sca.json` | Dependency CVE inventory |
| Trivy JSON | `reports/raw/trivy.json` | Container vulnerability inventory |
| ZAP JSON | `reports/raw/zap.json` | Runtime security findings |

Auditors can verify the scan ran, what version of each tool was used (Docker image tags), and what the findings were. The HTML report is timestamped and self-contained — no external dependencies to open it.

To demonstrate compliance: run `./securepipe scan` before each release, commit the report to a private evidence repository, and reference it in your control documentation.

---

## Architecture

```
securepipe (bash CLI)
│
├── run_sast()      → docker run returntocorp/semgrep  → reports/raw/semgrep.json
├── run_sca()       → docker run python:3.12-slim       → reports/raw/sca.json
│                     (pip-audit, auto-detected)
├── run_container() → docker run aquasec/trivy          → reports/raw/trivy.json
│                     (builds image from Dockerfile first if present)
└── run_dast()      → docker run ghcr.io/zaproxy/zaproxy → reports/raw/zap.json
                      (skipped unless --url is provided)
                            │
                     scripts/generate-report.py
                            │
                     reports/security-report.html
```

Each scanner runs in its own Docker container. No tool is installed on the host machine. Scan results are written to `reports/raw/` as JSON, then aggregated into a single HTML report.

Image sharing for the container scan: if a Dockerfile is found in the target directory, SecurePipe builds a local Docker image, passes it to Trivy, then removes it on `./securepipe clean`. If no Dockerfile is found, Trivy runs a filesystem scan instead.

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
│   └── generate-report.py                  # aggregates raw JSON → HTML
├── .github/
│   └── workflows/
│       └── reusable-security-pipeline.yml  # GitHub Actions reusable pipeline
├── sample-apps/
│   └── python/                             # vulnerable Flask app for demo scans
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

## Java support

Java is supported in the GitHub Actions pipeline (Semgrep with Java rules, Checkov for IaC). OWASP Dependency Check for Java dependencies is on the roadmap. The local CLI scanner currently covers Python and Node.js SCA; Java SCA via the CLI is not included because `dependency-check` has significant startup overhead in Docker. If you need Java SCA in CI, the Actions pipeline handles it via Semgrep.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Validate YAML before committing (`make validate`). Test end to end against a real caller.

## Security

Report vulnerabilities via [GitHub Security Advisories](https://github.com/ismailarici/securepipe/security/advisories/new). See [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE).
