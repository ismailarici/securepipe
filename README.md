# SecurePipe

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Latest tag](https://img.shields.io/github/v/tag/ismailarici/securepipe)](https://github.com/ismailarici/securepipe/tags)
[![Example pipeline](https://github.com/ismailarici/secureapp-v2/actions/workflows/pipeline.yml/badge.svg)](https://github.com/ismailarici/secureapp-v2/actions/workflows/pipeline.yml)

A reusable GitHub Actions security pipeline. One caller file in your app repo triggers a full
10-stage scan — secrets, SAST, dependency CVEs, container vulnerabilities, IaC misconfigurations,
SBOM generation, and DAST. All findings land in the GitHub Security tab or your DefectDojo instance.

---

## Who is this for

Teams that want serious security coverage without maintaining pipeline code in every repo.

SecurePipe is a single reusable workflow. Your app repos contain one caller file (~20 lines) that
references it. When you need to update a scanner, change a rule, or fix a step, you do it once
here and every connected repo picks it up automatically.

It works for:

- **Small teams** shipping fast who want automated scanning without a dedicated security engineer
- **Platform engineers** who want a standard security baseline rolled out across all app repos in an org
- **Solo developers** who want the same tooling a well-staffed security team would use

It is not for teams that already have a commercial SAST/SCA product they are happy with. If you
have Snyk or Semgrep Pro and it is working, stay with it. SecurePipe is for teams that want
solid open source coverage wired up correctly.

---

## What it runs

| Stage | Tool | Catches |
|-------|------|---------|
| Secrets gate | TruffleHog | Live credentials in code and full git history |
| Python SAST | Bandit | Python-specific security antipatterns |
| Multi-language SAST | Semgrep | OWASP Top 10, injection, misconfigs, custom rules |
| Python dependencies | pip-audit | CVEs in Python packages |
| Node.js dependencies | npm-audit | CVEs in npm packages |
| IaC | Checkov | Terraform and Dockerfile misconfigurations |
| Image build + SBOM | Syft | Full software bill of materials in SPDX format |
| Container scan | Trivy | OS and library CVEs in your Docker image |
| DAST | OWASP ZAP | Runtime issues — injection, missing headers, broken access control |
| Findings import | DefectDojo | Persistent finding management across all repos (optional) |

TruffleHog runs first and blocks everything else if it finds a live credential. Trivy is the
hard severity gate — it fails the build at your configured threshold. Everything else reports
findings without blocking, so a noisy first scan does not break your CI.

---

## How to connect your app

### Quickstart (30 minutes)

Run the setup script to generate a pre-filled caller workflow and the exact secrets you need to add:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/ismailarici/securepipe/main/setup.sh) \
  --org your-org \
  --repo your-app-repo \
  --language python
```

Or clone this repo and run it locally:

```bash
git clone https://github.com/ismailarici/securepipe.git
cd securepipe
bash setup.sh --org your-org --repo your-app-repo --language python
```

For a full walkthrough including AWS OIDC setup and troubleshooting, see [docs/onboarding.md](docs/onboarding.md).

### Manual setup

**Step 1 — Provision AWS infrastructure (skip if you already have ECR + OIDC role)**

```bash
cd terraform/
terraform init
terraform apply -var="github_org=your-org" -var="github_repo=your-app-repo"
```

This creates an ECR repository, a GitHub Actions OIDC provider, and a scoped IAM role.
Copy the `role_arn` and `aws_account_id` outputs — you need them as secrets.

**Step 2 — Add secrets to your app repo**

Settings → Secrets and variables → Actions:

| Secret | Value |
|--------|-------|
| `AWS_ACCOUNT_ID` | Your 12-digit AWS account ID |
| `AWS_ROLE_ARN` | `arn:aws:iam::ACCOUNT_ID:role/ROLE_NAME` |

**Step 3 — Create the caller workflow**

Create `.github/workflows/pipeline.yml` in your app repo:

```yaml
name: Security Pipeline

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  workflow_dispatch:

jobs:
  security-pipeline:
    name: Run Security Pipeline
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

**Step 4 — Enable Actions write permissions**

Settings → Actions → General → Workflow permissions → Read and write permissions.

Push the file and watch the Actions tab.

---

## Configuration

### Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `app-language` | Yes | — | `python`, `node`, or `java` |
| `image-name` | Yes | — | Docker image name (matches your ECR repo name) |
| `app-port` | No | `5000` | Port your app exposes |
| `fail-severity` | No | `HIGH` | Trivy severity that fails the build (`CRITICAL`, `HIGH`, `MEDIUM`) |
| `aws-region` | No | `us-east-1` | AWS region for ECR |
| `cloud-provider` | No | `aws` | Registry provider: `aws`, `azure`, or `gcp` |
| `registry-url` | No | `""` | Registry hostname for Azure/GCP (AWS is derived automatically) |
| `reporting-mode` | No | `sarif` | `sarif` uploads to GitHub Security tab; `artifacts` uploads SARIF as downloadable files (for private repos without GHAS) |
| `defectdojo-url` | No | `""` | Base URL of your DefectDojo instance. When set, all findings are imported after scanning. |

### Secrets

| Secret | When required |
|--------|--------------|
| `AWS_ACCOUNT_ID` | `cloud-provider: aws` |
| `AWS_ROLE_ARN` | `cloud-provider: aws` |
| `AZURE_CLIENT_ID` | `cloud-provider: azure` |
| `AZURE_TENANT_ID` | `cloud-provider: azure` |
| `AZURE_SUBSCRIPTION_ID` | `cloud-provider: azure` |
| `GCP_WORKLOAD_IDENTITY_PROVIDER` | `cloud-provider: gcp` |
| `GCP_SERVICE_ACCOUNT` | `cloud-provider: gcp` |
| `DEFECTDOJO_TOKEN` | `defectdojo-url` is set |
| `SEMGREP_APP_TOKEN` | Optional — enables Semgrep cloud features |

---

## Multi-cloud support

The pipeline pushes your image to the registry of your chosen cloud provider. All three use
short-lived OIDC credentials — no long-lived keys stored anywhere.

| Provider | Registry | Auth |
|----------|----------|------|
| AWS (default) | Amazon ECR | OIDC via `aws-actions/configure-aws-credentials` |
| Azure | Azure Container Registry | Federated credentials via `azure/login` |
| GCP | Google Artifact Registry | Workload Identity Federation via `google-github-actions/auth` |

For Azure and GCP setup, see [docs/onboarding.md](docs/onboarding.md).

---

## DefectDojo integration

When `defectdojo-url` is set, the pipeline imports all SARIF findings into DefectDojo after
every run. It creates a product (named after your repo) and a new engagement per run. The
`close_old_findings` flag means resolved issues are automatically marked mitigated.

```yaml
    with:
      defectdojo-url: https://defectdojo.yourdomain.com
    secrets:
      DEFECTDOJO_TOKEN: ${{ secrets.DEFECTDOJO_TOKEN }}
```

For DefectDojo deployment and setup, see [docs/defect-dojo-setup.md](docs/defect-dojo-setup.md).

---

## Private repo support

GitHub Advanced Security (GHAS) is required to upload SARIF to the Security tab on private
repos. If your repo is private and you do not have GHAS, set `reporting-mode: artifacts`.
All SARIF files are uploaded as downloadable run artifacts with 30-day retention instead.
The pipeline summary table still prints to the Actions run page regardless of mode.

```yaml
    with:
      reporting-mode: artifacts
```

---

## How it compares to commercial tools

| Capability | SecurePipe | Snyk | Semgrep Pro | Wiz |
|------------|-----------|------|-------------|-----|
| Secrets scanning | TruffleHog (verified) | Yes | Yes | No |
| SAST | Bandit + Semgrep OSS | Yes | Yes (more rules) | No |
| Dependency CVEs | pip-audit / npm-audit | Yes (deeper) | Yes | No |
| Container scanning | Trivy | Yes | No | Yes |
| IaC scanning | Checkov | Partial | Yes | Yes |
| DAST | OWASP ZAP | No | No | No |
| SBOM | Syft (SPDX) | Yes | No | Partial |
| Cloud runtime | No | No | No | Yes |
| Cost | Free | Freemium / paid | Freemium / paid | Paid |
| Self-hosted | Yes | Partial | Partial | No |
| Customisable rules | Yes (.semgrep/) | Limited | Yes | Limited |

The short version: SecurePipe covers more of the pipeline than any single commercial tool at
zero cost. The trade-offs are rule depth (Semgrep Pro has a larger rule set), ecosystem
integrations (Snyk has tighter package manager support), and cloud runtime visibility (only
Wiz covers that). If runtime security and deep SCA are your top priorities, evaluate those
tools on their own merits. For CI pipeline scanning with no per-seat cost, SecurePipe covers
the full surface area.

---

## Architecture

SecurePipe uses the GitHub Actions `workflow_call` pattern. Your app repo contains one caller
file. All scanner logic, tool versions, and step definitions live here. You update once and
every connected repo picks it up.

```
App repo (caller)                    SecurePipe (callee)
─────────────────                    ──────────────────────────────────────
.github/workflows/                   .github/workflows/
  pipeline.yml        calls →          reusable-security-pipeline.yml
  │
  └── passes inputs:
        app-language, image-name
        app-port, fail-severity
        aws-region, cloud-provider
        registry-url, reporting-mode
        defectdojo-url
```

**Job execution order:**

```
[TruffleHog] ← secrets gate, blocks all other jobs if it fails
      │
      ├── [Bandit]       Python only
      ├── [Semgrep]      all languages
      ├── [pip-audit]    Python only
      ├── [npm-audit]    Node.js only
      ├── [Checkov]      all languages
      └── [Build + SBOM] ─── [Trivy]
                         └── [ZAP]
                               │
                         [DefectDojo import]  if defectdojo-url is set
                               │
                         [Pipeline summary]
```

Image sharing between jobs uses GitHub Actions artifacts. The image built in `build-and-sbom`
is exported as a tar, uploaded with 1-day retention, and loaded by Trivy and ZAP in their
own runners.

---

## Language support

| | TruffleHog | Semgrep | Checkov | Bandit | pip-audit | npm-audit |
|-|:---:|:---:|:---:|:---:|:---:|:---:|
| Python | ✓ | ✓ | ✓ | ✓ | ✓ | — |
| Node.js | ✓ | ✓ | ✓ | — | — | ✓ |
| Java | ✓ | ✓ | ✓ | — | — | — |

Language-specific jobs are automatically skipped — no configuration needed.

---

## Custom Semgrep rules

Add `.yml` rule files to `.semgrep/` and they run on every scan alongside the community packs.
Three rules are included by default:

| Rule | Catches |
|------|---------|
| `hardcoded-aws-access-key` | AWS Access Key IDs hardcoded in source |
| `flask-debug-mode-enabled` | Flask `debug=True` in production |
| `npm-unsafe-perm` | `--unsafe-perm` in npm scripts |

---

## Repository structure

```
securepipe/
├── .github/
│   ├── workflows/
│   │   └── reusable-security-pipeline.yml
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.yml
│   │   └── feature_request.yml
│   └── PULL_REQUEST_TEMPLATE.md
├── sample-apps/
│   └── python/                  minimal Flask app for end-to-end testing
├── terraform/
│   ├── main.tf                  OIDC provider, ECR repo, IAM role
│   ├── variables.tf
│   ├── outputs.tf
│   └── README.md
├── .semgrep/
│   └── custom-rules.yml
├── .zap/
│   └── rules.tsv
├── docs/
│   ├── onboarding.md            AWS setup, rollout sequence, troubleshooting
│   └── defect-dojo-setup.md     DefectDojo on EC2, API token, import setup
├── setup.sh                     generates caller workflow + prints required secrets
├── Makefile                     make validate, make lint, make test
├── USE_THIS_TEMPLATE.md         first 30 minutes after clicking Use this template
├── CONTRIBUTING.md
├── SECURITY.md
└── LICENSE
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The short version: validate YAML before every commit
(`make validate`), test end to end against a real caller, one logical change per commit.

## Security

Report vulnerabilities via [GitHub Security Advisories](https://github.com/ismailarici/securepipe/security/advisories/new).
Do not open public issues for security findings. See [SECURITY.md](SECURITY.md) for the full policy.

## License

MIT — see [LICENSE](LICENSE).
