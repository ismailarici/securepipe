# First 30 minutes with SecurePipe

You just clicked "Use this template." Here is exactly what to do next.

---

## What you have

A copy of the SecurePipe pipeline repository. This repo contains one file that matters right now:

```
.github/workflows/reusable-security-pipeline.yml
```

This is the pipeline. Your application repos will call it using GitHub Actions'
`workflow_call` pattern. Your app repos contain no pipeline logic — just a single
caller file that points here.

---

## Step 1 — Set up AWS (15 minutes)

The pipeline needs two AWS resources. If you already have them, skip to Step 2.

**Create an ECR repository** for each app you plan to scan.

**Create an OIDC identity provider** in IAM (once per AWS account):
- Provider URL: `https://token.actions.githubusercontent.com`
- Audience: `sts.amazonaws.com`

**Create an IAM role** with a trust policy scoped to your GitHub org and repo:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::YOUR_ACCOUNT_ID:oidc-provider/token.actions.githubusercontent.com"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
      },
      "StringLike": {
        "token.actions.githubusercontent.com:sub": "repo:YOUR_ORG/YOUR_APP_REPO:*"
      }
    }
  }]
}
```

Attach a policy with ECR push permissions for your repository.

Note the role ARN — you will need it in Step 2.

For a fully automated setup, run `setup.sh` or use the Terraform module at `terraform/`.
See `docs/onboarding.md` for the full walkthrough.

---

## Step 2 — Connect your first app (5 minutes)

In your **application repo**, create `.github/workflows/pipeline.yml`:

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
    uses: YOUR_ORG/securepipe/.github/workflows/reusable-security-pipeline.yml@main
    with:
      app-language: python        # python | node | java
      image-name: your-app-name   # matches your ECR repo name
      app-port: "5000"
      fail-severity: HIGH
      aws-region: us-east-1
    secrets:
      AWS_ACCOUNT_ID: ${{ secrets.AWS_ACCOUNT_ID }}
      AWS_ROLE_ARN: ${{ secrets.AWS_ROLE_ARN }}
```

Replace `YOUR_ORG/securepipe` with your actual org and repo name.

Add two secrets to your app repo (Settings → Secrets and variables → Actions):

| Secret | Value |
|--------|-------|
| `AWS_ACCOUNT_ID` | Your 12-digit AWS account ID |
| `AWS_ROLE_ARN` | The role ARN from Step 1 |

---

## Step 3 — Enable Actions permissions (1 minute)

In your app repo: Settings → Actions → General → Workflow permissions → **Read and write permissions**.

This is required for SARIF upload to the Security tab.

---

## Step 4 — Push and verify

Commit `pipeline.yml` and push. Go to the Actions tab in your app repo.

The pipeline runs in this order:

1. **TruffleHog** — secrets gate. Stops everything if a live credential is found.
2. In parallel: Bandit, Semgrep, pip-audit or npm-audit, Checkov, image build + SBOM
3. After image is built: Trivy, OWASP ZAP
4. Summary table printed to the run page

First run takes 3–5 minutes. Findings appear in the Security tab under Code scanning alerts.

---

## What to do with findings

**Week 1:** Set `fail-severity: CRITICAL`. Let findings accumulate. Do not suppress anything yet.

**Week 2–3:** Triage. Real findings get tickets. False positives get inline suppressions
(`# nosec` for Python, `// nosemgrep` for others).

**Week 4+:** Lower to `fail-severity: HIGH`. Add branch protection to require the pipeline
to pass before merging.

---

## Need help?

- `docs/onboarding.md` — detailed AWS setup, troubleshooting, rollout sequence
- `setup.sh --help` — automated setup script
- [Open an issue](https://github.com/ismailarici/securepipe/issues) if something is broken
