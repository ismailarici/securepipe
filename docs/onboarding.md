# Onboarding Guide — securepipe

This guide walks you through connecting your app to the reusable security pipeline from scratch. You should be running scans within 30 minutes.

---

## What you need before you start

- A GitHub repository with your application code
- A Dockerfile at `app/Dockerfile` in your repo
- An AWS account
- Admin access to your GitHub repo settings

If you do not have a Dockerfile yet, see the section at the bottom of this guide.

---

## Step 1 — Set up AWS prerequisites

The pipeline needs two AWS resources: an ECR repository to store your Docker image, and an IAM role that GitHub Actions can assume via OIDC.

### 1a — Create an ECR repository

1. Log into the AWS console
2. Go to ECR and click Create repository
3. Set visibility to Private
4. Set image tag mutability to Immutable
5. Name it after your application (for example: my-app)
6. Click Create repository
7. Note the repository URI — you will need it later

### 1b — Set up GitHub Actions OIDC authentication

This allows GitHub Actions to authenticate with AWS without storing long-lived credentials anywhere.

First, create the OIDC provider in AWS (only needed once per AWS account):

1. Go to IAM → Identity providers → Add provider
2. Provider type: OpenID Connect
3. Provider URL: https://token.actions.githubusercontent.com
4. Audience: sts.amazonaws.com
5. Click Add provider

Next, create the IAM role:

1. Go to IAM → Roles → Create role
2. Trusted entity type: Web identity
3. Identity provider: token.actions.githubusercontent.com
4. Audience: sts.amazonaws.com
5. Click Next
6. Attach a policy with these permissions (create a custom inline policy):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["ecr:GetAuthorizationToken"],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "ecr:BatchCheckLayerAvailability",
        "ecr:GetDownloadUrlForLayer",
        "ecr:BatchGetImage",
        "ecr:PutImage",
        "ecr:InitiateLayerUpload",
        "ecr:UploadLayerPart",
        "ecr:CompleteLayerUpload"
      ],
      "Resource": "arn:aws:ecr:us-east-1:YOUR_ACCOUNT_ID:repository/YOUR_REPO_NAME"
    }
  ]
}
```

7. Name the role (for example: github-actions-my-app)
8. After creating the role, go to the Trust relationships tab and edit the trust policy to restrict it to your specific repo:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
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
          "token.actions.githubusercontent.com:sub": "repo:YOUR_GITHUB_ORG/YOUR_REPO_NAME:*"
        }
      }
    }
  ]
}
```

Replace YOUR_ACCOUNT_ID, YOUR_GITHUB_ORG, and YOUR_REPO_NAME with your actual values.

9. Note the role ARN — it looks like: arn:aws:iam::123456789012:role/github-actions-my-app

---

## Step 2 — Add secrets to your GitHub repo

1. Go to your app repo on GitHub
2. Click Settings → Secrets and variables → Actions
3. Click New repository secret and add:

| Secret name    | Value                        |
| -------------- | ---------------------------- |
| AWS_ACCOUNT_ID | Your 12-digit AWS account ID |
| AWS_ROLE_ARN   | The role ARN from Step 1b    |

---

## Step 3 — Create the caller workflow

Create a file at `.github/workflows/pipeline.yml` in your app repo with this content:

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

Replace the values in the `with` block:

| Input         | What to put                                                     |
| ------------- | --------------------------------------------------------------- |
| app-language  | python, node, or java                                           |
| image-name    | Your ECR repository name                                        |
| app-port      | The port your app listens on                                    |
| fail-severity | CRITICAL to start (less disruptive), HIGH when ready to enforce |
| aws-region    | The AWS region where your ECR repo lives                        |

---

## Step 4 — Enable GitHub Actions permissions

1. Go to your app repo → Settings → Actions → General
2. Under Workflow permissions, select Read and write permissions
3. Click Save

---

## Step 5 — Push and verify

Commit and push the `pipeline.yml` file to your repo. Go to the Actions tab and you should see the pipeline start running automatically.

The first run takes 3-5 minutes. Subsequent runs are faster because Trivy caches its vulnerability database.

---

## Viewing your findings

Once the pipeline runs, go to your repo's Security tab and click Code scanning alerts. You will see findings grouped by tool — TruffleHog, Bandit, Semgrep, Trivy, and others depending on your language.

Each finding shows:

- Which tool detected it
- The file and line number
- Severity level
- A link to the relevant CWE or CVE

---

## Recommended rollout sequence

If you are connecting an existing codebase that has never been scanned before, start permissive and tighten over time:

**Week 1 — Reporting only**
Set fail-severity to CRITICAL. The pipeline runs and reports findings but only blocks on the most severe issues. Use this time to triage what gets flagged.

**Week 2-3 — Triage findings**
Review Code scanning alerts. For false positives, add suppression comments (# nosec for Python, // nosec for others). For real findings, create tickets.

**Week 4+ — Enforce gates**
Lower fail-severity to HIGH. The pipeline now blocks PRs that introduce HIGH or CRITICAL vulnerabilities. Branch protection rules can be added to require the pipeline to pass before merging.

---

## If you do not have a Dockerfile yet

Your app needs a Dockerfile for the container scanning and DAST stages to run. Here is a minimal production-ready Dockerfile for a Python Flask app:

```dockerfile
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

RUN adduser --disabled-password --gecos "" appuser
USER appuser

EXPOSE 5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]
```

For Node.js apps:

```dockerfile
FROM node:20-slim

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY . .

RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser
USER appuser

EXPOSE 3000

CMD ["node", "server.js"]
```

Place the Dockerfile at `app/Dockerfile` in your repo.

---

## Troubleshooting

**Pipeline fails immediately on TruffleHog**
TruffleHog found a verified live secret in your git history. Check the job logs for the specific finding. Rotate the credential immediately, then use git filter-branch or BFG Repo Cleaner to remove it from history.

**Trivy fails with HIGH severity findings**
Your Docker image contains vulnerabilities. Check the Security tab for details. Update your base image or the affected dependencies. If the vulnerability has no fix available, Trivy will skip it automatically (ignore-unfixed is enabled).

**Semgrep blocks a PR with a false positive**
Add a comment on the line above the flagged code:

- Python: `# nosec B104`
- JavaScript/TypeScript: `// nosemgrep`

**Pipeline fails with permissions error**
Check that your IAM role trust policy includes your repo name exactly. The sub field in the condition must match `repo:YOUR_ORG/YOUR_REPO:*`.

**ZAP reports findings but pipeline still passes**
This is correct behaviour. ZAP findings are reported to the Security tab but do not block the build. DAST findings require human triage before enforcement.

---

## Getting help

Open an issue at github.com/ismailarici/securepipe with:

- Your app language
- The failing job name
- The error message from the job logs

---

## Azure setup

Use this section if `cloud-provider: azure` is set in your caller workflow.

### Prerequisites

- An Azure subscription
- Azure CLI installed locally (`az`)
- An Azure Container Registry (ACR) instance

### Step 1 — Create an ACR repository

```bash
az acr create \
  --resource-group your-resource-group \
  --name yourregistryname \
  --sku Basic
```

Note the login server — it will be `yourregistryname.azurecr.io`. This is your `registry-url` input.

### Step 2 — Register a GitHub app registration for OIDC

```bash
# Create the app registration
az ad app create --display-name "securepipe-your-app-repo"

# Note the appId from the output — this is your AZURE_CLIENT_ID
APP_ID=<appId from above>

# Create a service principal for the app registration
az ad sp create --id $APP_ID

# Assign AcrPush role scoped to your registry
az role assignment create \
  --assignee $APP_ID \
  --role AcrPush \
  --scope $(az acr show --name yourregistryname --query id -o tsv)
```

### Step 3 — Add federated credentials (OIDC)

```bash
az ad app federated-credential create \
  --id $APP_ID \
  --parameters '{
    "name": "github-actions",
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:YOUR_ORG/YOUR_REPO:ref:refs/heads/main",
    "audiences": ["api://AzureADTokenExchange"]
  }'
```

Replace `YOUR_ORG/YOUR_REPO` with your actual values. Add a second federated credential with `subject` set to `repo:YOUR_ORG/YOUR_REPO:pull_request` if you want the pipeline to run on PRs.

### Step 4 — Add secrets to your app repo

| Secret | Value |
|--------|-------|
| `AZURE_CLIENT_ID` | App registration client ID (`appId`) |
| `AZURE_TENANT_ID` | `az account show --query tenantId -o tsv` |
| `AZURE_SUBSCRIPTION_ID` | `az account show --query id -o tsv` |

### Step 5 — Update your caller workflow

```yaml
    with:
      cloud-provider: azure
      registry-url: yourregistryname.azurecr.io
    secrets:
      AZURE_CLIENT_ID: ${{ secrets.AZURE_CLIENT_ID }}
      AZURE_TENANT_ID: ${{ secrets.AZURE_TENANT_ID }}
      AZURE_SUBSCRIPTION_ID: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
```

---

## GCP setup

Use this section if `cloud-provider: gcp` is set in your caller workflow.

### Prerequisites

- A GCP project with billing enabled
- `gcloud` CLI installed locally
- Google Artifact Registry API enabled: `gcloud services enable artifactregistry.googleapis.com`

### Step 1 — Create a GAR repository

```bash
gcloud artifacts repositories create your-repo-name \
  --repository-format=docker \
  --location=us-central1 \
  --project=your-project-id
```

Your `registry-url` input will be `us-central1-docker.pkg.dev/your-project-id/your-repo-name`.

### Step 2 — Create a service account

```bash
gcloud iam service-accounts create securepipe-runner \
  --display-name "SecurePipe GitHub Actions" \
  --project your-project-id

# Grant Artifact Registry write access
gcloud artifacts repositories add-iam-policy-binding your-repo-name \
  --location=us-central1 \
  --member="serviceAccount:securepipe-runner@your-project-id.iam.gserviceaccount.com" \
  --role="roles/artifactregistry.writer" \
  --project=your-project-id
```

### Step 3 — Configure Workload Identity Federation

```bash
# Create the pool
gcloud iam workload-identity-pools create "github-pool" \
  --location="global" \
  --project=your-project-id

# Create the provider
gcloud iam workload-identity-pools providers create-oidc "github-provider" \
  --location="global" \
  --workload-identity-pool="github-pool" \
  --issuer-uri="https://token.actions.githubusercontent.com" \
  --attribute-mapping="google.subject=assertion.sub,attribute.repository=assertion.repository" \
  --project=your-project-id

# Allow the specific repo to impersonate the service account
gcloud iam service-accounts add-iam-policy-binding \
  securepipe-runner@your-project-id.iam.gserviceaccount.com \
  --role="roles/iam.workloadIdentityUser" \
  --member="principalSet://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/github-pool/attribute.repository/YOUR_ORG/YOUR_REPO" \
  --project=your-project-id
```

Get your project number: `gcloud projects describe your-project-id --format='value(projectNumber)'`

### Step 4 — Add secrets to your app repo

| Secret | Value |
|--------|-------|
| `GCP_WORKLOAD_IDENTITY_PROVIDER` | `projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/github-pool/providers/github-provider` |
| `GCP_SERVICE_ACCOUNT` | `securepipe-runner@your-project-id.iam.gserviceaccount.com` |

### Step 5 — Update your caller workflow

```yaml
    with:
      cloud-provider: gcp
      registry-url: us-central1-docker.pkg.dev/your-project-id/your-repo-name
    secrets:
      GCP_WORKLOAD_IDENTITY_PROVIDER: ${{ secrets.GCP_WORKLOAD_IDENTITY_PROVIDER }}
      GCP_SERVICE_ACCOUNT: ${{ secrets.GCP_SERVICE_ACCOUNT }}
```
