# SecurePipe

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Latest tag](https://img.shields.io/github/v/tag/ismailarici/securepipe)](https://github.com/ismailarici/securepipe/tags)

A DevSecOps toolkit that runs a full security pipeline against any codebase with a single command. Two components: a local CLI and a reusable GitHub Actions pipeline.

Run the CLI locally to audit any app before a release. Use the GitHub Actions pipeline for continuous scanning on every push. Both produce the same coverage.

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

## What to expect on first run

SecurePipe pulls Docker images on demand. On a fresh machine:

- Semgrep, pip-audit, Trivy, and ZAP together are roughly 2–3 GB of images
- Pulling them takes several minutes depending on your connection
- **OWASP Dependency-Check (Java only)** downloads the NVD vulnerability database on first run — this takes 10–30 minutes without an API key; subsequent runs use the cached database at `~/.dependency-check/data/`

Subsequent scans are significantly faster because Docker layer caching means images are not re-downloaded. A Python or Node project with warm cache typically finishes in 3–5 minutes for SAST + SCA + container scan. DAST (ZAP) adds 2–5 minutes on top.

---

## Quick start (CLI)

**Prerequisites:** Docker and Python 3.

```bash
git clone https://github.com/ismailarici/securepipe.git
cd securepipe
./securepipe scan --target ./sample-apps/python
```

This runs SAST, SCA, dependency usage mapping, and container scanning against the included vulnerable Python sample app and writes `reports/security-report.html`. DAST is skipped unless `--url` is provided.

Open the report:

```bash
open reports/security-report.html       # macOS
xdg-open reports/security-report.html  # Linux
```

To scan your own code:

```bash
./securepipe scan --target /path/to/your/app
```

To include DAST (requires a live running app):

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
| `scan` | Runs SAST, SCA, dependency usage mapping, SBOM (Java), container scan, and optionally DAST. Writes `reports/security-report.html` |
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
| `NVDAPIKEY` | NVD API key for OWASP Dependency-Check (Java). Free at nvd.nist.gov/developers/request-an-api-key. Without it, the first Java scan is slow due to NVD rate limits. |

---

## Security stack

### CLI

| Stage | Tool | Languages | Notes |
|-------|------|-----------|-------|
| SAST | Semgrep | Python, Node.js, Java | 1000+ rules via `--config auto`; runs in Docker with zero config |
| SCA | pip-audit | Python | CVE detection against `requirements.txt` |
| SCA | npm audit | Node.js | CVE detection for npm packages |
| SCA | OWASP Dependency-Check | Java | CVE detection for Maven/Gradle; first run downloads the NVD database |
| Dep mapping | find-imports | Python, Node.js, Java | Maps each vulnerable package to the source files that import it; marks transitive deps and their parent chain |
| SBOM | Syft | Java | Full software bill of materials |
| Container scan | Trivy | All | Image scan if Dockerfile present; filesystem scan otherwise |
| DAST (baseline) | OWASP ZAP | All | Runtime scan for injection, missing headers, broken access |
| DAST (API) | OWASP ZAP api-scan | All | OpenAPI-driven scan that tests every defined endpoint |

Language detection is automatic — SecurePipe reads `pom.xml`/`build.gradle` for Java, `requirements.txt` for Python, `package.json` for Node.js.

### GitHub Actions pipeline

The reusable pipeline runs on every push or pull request and adds tools that benefit from the CI environment:

| Stage | Tool | Notes |
|-------|------|-------|
| Secrets | TruffleHog | Verified secrets across full git history; most effective with the complete commit log |
| SAST | Semgrep | OWASP Top 10 + secrets + Docker rulesets + custom `.semgrep/` rules |
| SAST | Bandit | Python-specific; outputs SARIF to the GitHub Security tab |
| SCA | pip-audit | Python dependency CVEs |
| SCA | npm audit | Node.js dependency CVEs |
| SBOM | Syft | All languages; SPDX JSON format |
| Container scan | Trivy | Image-level CVEs; configurable fail severity |
| IaC scan | Checkov | Terraform and Dockerfile misconfigurations |
| DAST | OWASP ZAP | Baseline scan against the built container |
| Findings management | DefectDojo | Optional; imports all SARIF results into a persistent DefectDojo instance |

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

The header value is never logged. To avoid the token appearing in shell history:

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

**First run note:** OWASP Dependency-Check downloads the NVD vulnerability database on first use. Without an API key this can take 10–30 minutes due to NVD rate limits. Get a free key at [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key) and set `export NVDAPIKEY=your-key`. The database is cached at `~/.dependency-check/data/` so subsequent runs are fast.

---

## Sample apps

Three deliberately vulnerable sample apps are included for testing:

| App | Path | Seeded issues |
|-----|------|---------------|
| Python (Flask) | `sample-apps/python/` | SQL injection, command injection, insecure deserialization, unsafe YAML load (CVE-2020-14343), hardcoded credentials, debug mode |
| Node.js (Express) | `sample-apps/node/` | Command injection, XSS, prototype pollution, hardcoded secrets, old deps (lodash 4.17.20, axios 0.21.1) |
| Java | `sample-apps/java/` | SQL injection, command injection, insecure deserialization, hardcoded credentials, log4j 2.14.1, jackson-databind 2.12.3 |

Run `./securepipe org-scan --config examples/securepipe-org.yml` to scan all three at once.

---

## Report

Each scan produces a self-contained HTML report with:

- Summary counts by severity (Critical, High, Medium, Low, Info)
- Per-tool finding count
- Findings table sorted by severity — file/line, fix summary, detected-by tool list
- **Dependency usage mapping** — for each vulnerable package, shows which source files import it (direct) or which parent package pulls it in (transitive)
- **CVE deduplication** — the same CVE detected by multiple tools (e.g. Trivy and pip-audit both find PyYAML) is shown as a single finding with all sources listed
- Expandable detail panel per finding with full description and remediation guidance
- Compliance mapping (SOC 2, ISO 27001)

Raw JSON outputs are saved in `reports/raw/` alongside the HTML.

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
| SCA JSON | `reports/raw/sca.json` | Dependency CVE inventory |
| Imports JSON | `reports/raw/imports.json` | Package→source file usage map |
| SBOM JSON | `reports/raw/sbom.json` | Software bill of materials (Java only) |
| Trivy JSON | `reports/raw/trivy.json` | Container vulnerability inventory |
| ZAP JSON | `reports/raw/zap.json` | Runtime security findings |

All reports are self-contained HTML — no external dependencies to open them. Auditors can inspect the raw JSON files to verify tool versions and finding details.

---

## Architecture

```
./securepipe scan
│
├── run_sast()         → docker run returntocorp/semgrep        → raw/semgrep.json
├── run_sca()          → pip-audit / npm-audit / OWASP-DC       → raw/sca.json
│                        (auto-detected from project files)        raw/dep-tree.json
├── run_imports()      → scripts/find-imports.py                → raw/imports.json
├── run_sbom()         → docker run anchore/syft (Java only)    → raw/sbom.json
├── run_container()    → docker run aquasec/trivy               → raw/trivy.json
│                        (image scan if Dockerfile, fs otherwise)
└── run_dast()         → docker run ghcr.io/zaproxy/zaproxy     → raw/zap.json
                         (skipped unless --url or --openapi given)
                               │
                        scripts/normalize.py
                          CVE deduplication, dep chain tracing,
                          dependency usage enrichment
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

### Internal scripts

| Script | Role |
|--------|------|
| `scripts/normalize.py` | Canonical finding schema; deduplicates CVEs across tools; enriches SCA findings with source file usage |
| `scripts/find-imports.py` | Scans .py/.js/.ts/.jsx/.tsx/.java source files for import statements; writes `imports.json` |
| `scripts/generate-report.py` | Converts normalised findings to `security-report.html` |
| `scripts/generate-org-report.py` | Aggregates per-repo reports into `org-summary.html` |
| `scripts/org-scan.py` | Orchestrates multi-repo scanning |

---

## GitHub Actions pipeline

For CI, add one file to your repo:

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
      app-language: python           # python | node | java
      image-name: your-app-name
      app-port: "5000"
      fail-severity: HIGH            # CRITICAL | HIGH | MEDIUM
      cloud-provider: aws            # aws | azure | gcp
      aws-region: us-east-1
    secrets:
      AWS_ACCOUNT_ID: ${{ secrets.AWS_ACCOUNT_ID }}
      AWS_ROLE_ARN: ${{ secrets.AWS_ROLE_ARN }}
```

**Prerequisites for the CI pipeline:**

- Your application must have a `Dockerfile` at `app/Dockerfile` and dependencies at `app/requirements.txt` (Python) or `app/package.json` (Node)
- Cloud credentials provisioned via OIDC (see [docs/onboarding.md](docs/onboarding.md))
- For DefectDojo integration: a running DefectDojo instance and a `DEFECTDOJO_TOKEN` secret

The pipeline uploads SARIF results to the GitHub Security tab by default. For private repos without GitHub Advanced Security, set `reporting-mode: artifacts` to download SARIF files as workflow artifacts instead.

See [docs/onboarding.md](docs/onboarding.md) for the full setup guide including AWS/Azure/GCP OIDC provisioning and DefectDojo deployment.

---

## Why not X?

### GitHub Advanced Security

GHAS is the right choice if you are already paying for GitHub Enterprise. It covers secrets, code scanning, and Dependabot well. It does not do DAST or aggregate multi-repo reporting. It requires per-seat licensing on private repos. SecurePipe runs the same scanners free, locally or in CI, on any repository.

### Snyk

Snyk has deeper SCA intelligence and a polished developer experience. It costs money at meaningful scale, requires an account, and sends scan data to Snyk's servers. SecurePipe is local-first — no account, no telemetry, no internet required after pulling Docker images.

### Manual toolchain

Running each tool manually means different output formats, different CI configs, and no unified report. The setup cost is non-trivial and it degrades as the team changes. SecurePipe is one command, one output, no per-tool maintenance.

---

## Repository structure

```
securepipe/
├── securepipe                               # CLI entry point (bash)
├── scripts/
│   ├── normalize.py                        # canonical finding schema + CVE dedup + dep enrichment
│   ├── find-imports.py                     # source file import scanner
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
│   └── custom-rules.yml                    # org-specific Semgrep rules
├── .zap/
│   └── rules.tsv                           # ZAP passive rule overrides
├── docs/
│   ├── onboarding.md                       # CI setup guide
│   └── defect-dojo-setup.md                # DefectDojo deployment
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
