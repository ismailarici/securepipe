# securepipe

A reusable, language-configurable security pipeline for GitHub Actions. Connect any app in under 5 minutes and get a full 9-stage security scan automatically — secrets detection, SAST, dependency scanning, container scanning, IaC scanning, SBOM generation, and DAST.

---

## What it does

Every time your app pushes to main or opens a pull request, this pipeline runs automatically:

| Stage                       | Tool         | What it catches                                                             |
| --------------------------- | ------------ | --------------------------------------------------------------------------- |
| Secrets scanning            | TruffleHog   | Live credentials in code and git history                                    |
| Python SAST                 | Bandit       | Python-specific security antipatterns                                       |
| Multi-language SAST         | Semgrep      | OWASP Top 10, injection, misconfigurations, custom rules                    |
| Python dependency scanning  | pip-audit    | Known CVEs in Python dependencies                                           |
| Node.js dependency scanning | npm-audit    | Known CVEs in npm packages                                                  |
| SBOM generation             | Syft         | Full inventory of every component in your container                         |
| Container scanning          | Trivy        | OS and library vulnerabilities in your Docker image                         |
| IaC scanning                | Checkov      | Terraform and Dockerfile misconfigurations                                  |
| DAST                        | OWASP ZAP    | Runtime vulnerabilities — injection, missing headers, broken access control |
| Reporting                   | GitHub SARIF | All findings in the GitHub Security tab                                     |

All findings appear in your repository's Security tab. No external dashboard required.

---

## How to connect your app

### Prerequisites

- Your app has a `Dockerfile` at `app/Dockerfile`
- Your app has a `requirements.txt` at `app/requirements.txt` (Python apps) or `package.json` at `app/package.json` (Node.js apps)
- You have an AWS account with an ECR repository and an IAM role configured for GitHub Actions OIDC

### Step 1 — Add secrets to your app repo

Go to your app repo → Settings → Secrets and variables → Actions and add:

| Secret           | Value                               |
| ---------------- | ----------------------------------- |
| `AWS_ACCOUNT_ID` | Your 12-digit AWS account ID        |
| `AWS_ROLE_ARN`   | ARN of your GitHub Actions IAM role |

### Step 2 — Create the caller workflow

Create `.github/workflows/pipeline.yml` in your app repo with the following content:

```yaml
name: Security Pipeline

on:
  push:
    branches:
      - main
  pull_request:
    branches:
      - main
  workflow_dispatch:

jobs:
  security-pipeline:
    name: Run Security Pipeline
    uses: ismailarici/securepipe/.github/workflows/reusable-security-pipeline.yml@v1.0.0
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

### Step 3 — Push and watch it run

Push the file to your repo. Go to the Actions tab and watch the pipeline run.

That's it.

---

## Configuration inputs

| Input           | Required | Default     | Description                                                        |
| --------------- | -------- | ----------- | ------------------------------------------------------------------ |
| `app-language`  | Yes      | —           | Programming language (`python`, `node`, `java`)                    |
| `image-name`    | Yes      | —           | Docker image name to build and scan                                |
| `app-port`      | No       | `5000`      | Port your app exposes                                              |
| `fail-severity` | No       | `HIGH`      | Trivy severity that fails the build (`CRITICAL`, `HIGH`, `MEDIUM`) |
| `aws-region`    | No       | `us-east-1` | AWS region for ECR                                                 |

---

## Pipeline architecture

The pipeline uses the GitHub Actions reusable workflow pattern. Your app repo contains a single caller file that references this pipeline repo. All security logic lives here — your app repo has no pipeline code at all.

```
App repo (caller)                    Pipeline repo (callee)
─────────────────                    ──────────────────────
.github/workflows/                   .github/workflows/
  pipeline.yml          calls →        reusable-security-pipeline.yml
  │
  └── passes inputs:
        app-language
        image-name
        app-port
        fail-severity
        aws-region
```

### Job execution order

TruffleHog runs first as the secrets gate. If a live credential is found, the pipeline stops immediately.

After TruffleHog passes, these jobs run in parallel:

- Bandit (Python only)
- Semgrep (all languages)
- pip-audit (Python only)
- npm-audit (Node.js only)
- Checkov (all languages)
- Build image and generate SBOM

After the image is built, Trivy and OWASP ZAP run against it.

Trivy is the hard gate. If it finds a vulnerability at or above your configured severity threshold, the pipeline fails. ZAP findings are reported but do not block the build — DAST results require human triage.

The pipeline summary job runs last and prints a status table of every stage to the Actions run page.

---

## Language support

| Language | TruffleHog | Semgrep | Checkov | Bandit | pip-audit | npm-audit |
| -------- | ---------- | ------- | ------- | ------ | --------- | --------- |
| Python   | ✅         | ✅      | ✅      | ✅     | ✅        | —         |
| Node.js  | ✅         | ✅      | ✅      | —      | —         | ✅        |
| Java     | ✅         | ✅      | ✅      | —      | —         | —         |

Language-specific tools are automatically skipped for non-matching apps. No configuration needed.

---

## Custom Semgrep rules

The `.semgrep/` directory contains custom rules that run alongside the community rule packs:

| Rule                       | What it catches                                    |
| -------------------------- | -------------------------------------------------- |
| `hardcoded-aws-access-key` | AWS Access Key IDs hardcoded in any language       |
| `flask-debug-mode-enabled` | Flask apps running with `debug=True` in production |
| `npm-unsafe-perm`          | Use of `--unsafe-perm` flag in npm scripts         |

To add your own rules, place `.yml` rule files in the `.semgrep/` directory of this repo. They will run automatically on every scan.

---

## Viewing findings

All findings are uploaded to the GitHub Security tab in SARIF format.

To view them:

1. Go to your app repo on GitHub
2. Click the **Security** tab
3. Click **Code scanning alerts**

Each finding includes the tool that found it, the file and line number, severity, and a link to the relevant CWE or CVE.

---

## Requirements

- GitHub repository with Actions enabled
- Docker-based application with a `Dockerfile` at `app/Dockerfile`
- AWS account with:
  - An ECR repository for your image
  - An IAM role configured for GitHub Actions OIDC authentication
  - The role must have ECR push permissions for your repository

---

## Sample app

A minimal Flask app is included at `sample-apps/python/` to verify the pipeline works end to end. It has no intentional vulnerabilities and exists only to prove the pipeline runs against something it did not hardcode.

---

## Project structure

```
securepipe/
├── .github/
│   └── workflows/
│       └── reusable-security-pipeline.yml   ← the pipeline
├── sample-apps/
│   └── python/
│       ├── app.py
│       ├── requirements.txt
│       └── Dockerfile
├── .semgrep/
│   └── custom-rules.yml                     ← custom Semgrep rules
├── docs/
│   └── onboarding.md                        ← detailed onboarding guide
└── README.md
```
