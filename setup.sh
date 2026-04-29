#!/usr/bin/env bash
set -euo pipefail

# Generates a caller workflow file and prints the secrets a team needs to add.
# Optionally provisions AWS infrastructure via Terraform.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Options:
  --org        GitHub org or username that owns the app repo  (required)
  --repo       App repository name                            (required)
  --language   python | node | java                           (required)
  --port       Port the app exposes                           (default: 5000)
  --cloud      aws | azure | gcp                              (default: aws)
  --region     Cloud region                                   (default: us-east-1)
  --provision  Run terraform init + apply to create AWS infra (flag, no value)
  --help       Show this message

Examples:
  $(basename "$0") --org acme --repo payments-api --language python
  $(basename "$0") --org acme --repo frontend --language node --port 3000
  $(basename "$0") --org acme --repo api --language python --provision
EOF
}

# ── defaults ──────────────────────────────────────────────────────────────────
ORG=""
REPO=""
LANGUAGE=""
PORT="5000"
CLOUD="aws"
REGION="us-east-1"
PROVISION=false

# ── argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --org)       ORG="$2";      shift 2 ;;
    --repo)      REPO="$2";     shift 2 ;;
    --language)  LANGUAGE="$2"; shift 2 ;;
    --port)      PORT="$2";     shift 2 ;;
    --cloud)     CLOUD="$2";    shift 2 ;;
    --region)    REGION="$2";   shift 2 ;;
    --provision) PROVISION=true; shift ;;
    --help)      usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

# ── validation ────────────────────────────────────────────────────────────────
errors=()
[[ -z "$ORG"      ]] && errors+=("--org is required")
[[ -z "$REPO"     ]] && errors+=("--repo is required")
[[ -z "$LANGUAGE" ]] && errors+=("--language is required")

if [[ -n "$LANGUAGE" ]] && [[ "$LANGUAGE" != "python" && "$LANGUAGE" != "node" && "$LANGUAGE" != "java" ]]; then
  errors+=("--language must be python, node, or java (got: $LANGUAGE)")
fi

if [[ "$CLOUD" != "aws" && "$CLOUD" != "azure" && "$CLOUD" != "gcp" ]]; then
  errors+=("--cloud must be aws, azure, or gcp (got: $CLOUD)")
fi

if [[ ${#errors[@]} -gt 0 ]]; then
  echo "Errors:" >&2
  for e in "${errors[@]}"; do echo "  $e" >&2; done
  echo "" >&2
  usage
  exit 1
fi

# ── derive the pipeline org from this script's git remote ────────────────────
PIPELINE_ORG="ismailarici"
if git -C "$SCRIPT_DIR" remote get-url origin &>/dev/null; then
  remote=$(git -C "$SCRIPT_DIR" remote get-url origin)
  # handles both https://github.com/org/repo and git@github.com:org/repo
  PIPELINE_ORG=$(echo "$remote" | sed -E 's|.*github\.com[:/]([^/]+)/.*|\1|')
fi
PIPELINE_REPO="securepipe"

# ── build caller workflow content ─────────────────────────────────────────────
WORKFLOW_REF="main"

build_caller_workflow() {
  local secrets_block=""
  if [[ "$CLOUD" == "aws" ]]; then
    secrets_block="    secrets:
      AWS_ACCOUNT_ID: \${{ secrets.AWS_ACCOUNT_ID }}
      AWS_ROLE_ARN: \${{ secrets.AWS_ROLE_ARN }}
      SEMGREP_APP_TOKEN: \${{ secrets.SEMGREP_APP_TOKEN }}"
  elif [[ "$CLOUD" == "azure" ]]; then
    secrets_block="    secrets:
      AZURE_CLIENT_ID: \${{ secrets.AZURE_CLIENT_ID }}
      AZURE_TENANT_ID: \${{ secrets.AZURE_TENANT_ID }}
      AZURE_SUBSCRIPTION_ID: \${{ secrets.AZURE_SUBSCRIPTION_ID }}
      SEMGREP_APP_TOKEN: \${{ secrets.SEMGREP_APP_TOKEN }}"
  elif [[ "$CLOUD" == "gcp" ]]; then
    secrets_block="    secrets:
      GCP_PROJECT_ID: \${{ secrets.GCP_PROJECT_ID }}
      GCP_WORKLOAD_IDENTITY_PROVIDER: \${{ secrets.GCP_WORKLOAD_IDENTITY_PROVIDER }}
      GCP_SERVICE_ACCOUNT: \${{ secrets.GCP_SERVICE_ACCOUNT }}
      SEMGREP_APP_TOKEN: \${{ secrets.SEMGREP_APP_TOKEN }}"
  fi

  cat <<WORKFLOW
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
    uses: ${PIPELINE_ORG}/${PIPELINE_REPO}/.github/workflows/reusable-security-pipeline.yml@${WORKFLOW_REF}
    with:
      app-language: ${LANGUAGE}
      image-name: ${REPO}
      app-port: "${PORT}"
      fail-severity: HIGH
      aws-region: ${REGION}
      cloud-provider: ${CLOUD}
${secrets_block}
WORKFLOW
}

# ── print caller workflow ──────────────────────────────────────────────────────
OUTPUT_FILE=".github/workflows/pipeline.yml"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  SecurePipe setup — ${ORG}/${REPO}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Step 1 — Create this file in your app repo:"
echo ""
echo "  ${OUTPUT_FILE}"
echo ""
echo "────────────────────────────────────────────────────────────────────────"
build_caller_workflow
echo "────────────────────────────────────────────────────────────────────────"
echo ""

# ── print required secrets ────────────────────────────────────────────────────
echo "Step 2 — Add these secrets to ${ORG}/${REPO}:"
echo "  (Settings → Secrets and variables → Actions → New repository secret)"
echo ""

if [[ "$CLOUD" == "aws" ]]; then
  cat <<SECRETS
  AWS_ACCOUNT_ID          Your 12-digit AWS account ID
  AWS_ROLE_ARN            arn:aws:iam::ACCOUNT_ID:role/ROLE_NAME
  SEMGREP_APP_TOKEN       Optional — leave blank to skip Semgrep cloud features

SECRETS
elif [[ "$CLOUD" == "azure" ]]; then
  cat <<SECRETS
  AZURE_CLIENT_ID              App registration client ID (for federated OIDC)
  AZURE_TENANT_ID              Azure AD tenant ID
  AZURE_SUBSCRIPTION_ID        Subscription ID
  SEMGREP_APP_TOKEN            Optional — leave blank to skip Semgrep cloud features

SECRETS
elif [[ "$CLOUD" == "gcp" ]]; then
  cat <<SECRETS
  GCP_PROJECT_ID                    Your GCP project ID
  GCP_WORKLOAD_IDENTITY_PROVIDER    projects/PROJECT_NUM/locations/global/workloadIdentityPools/POOL/providers/PROVIDER
  GCP_SERVICE_ACCOUNT               service-account@project.iam.gserviceaccount.com
  SEMGREP_APP_TOKEN                 Optional — leave blank to skip Semgrep cloud features

SECRETS
fi

# ── Actions permissions reminder ──────────────────────────────────────────────
echo "Step 3 — Enable Actions write permissions in ${ORG}/${REPO}:"
echo "  Settings → Actions → General → Workflow permissions → Read and write permissions"
echo ""

# ── Terraform provisioning ────────────────────────────────────────────────────
if [[ "$PROVISION" == "true" ]]; then
  if [[ "$CLOUD" != "aws" ]]; then
    echo "Note: --provision currently supports AWS only. Skipping Terraform for ${CLOUD}."
    echo ""
  else
    TF_DIR="$SCRIPT_DIR/terraform"
    if [[ ! -d "$TF_DIR" ]]; then
      echo "Error: terraform/ directory not found at $TF_DIR" >&2
      exit 1
    fi

    echo "Step 4 — Provisioning AWS infrastructure via Terraform..."
    echo "  Directory: $TF_DIR"
    echo ""

    pushd "$TF_DIR" > /dev/null
    terraform init
    terraform apply \
      -var="github_org=${ORG}" \
      -var="github_repo=${REPO}" \
      -var="aws_region=${REGION}" \
      -var="ecr_repo_name=${REPO}"
    popd > /dev/null

    echo ""
    echo "Infrastructure provisioned. Copy the role_arn output above into AWS_ROLE_ARN."
  fi
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Done. Push pipeline.yml to ${ORG}/${REPO} and watch the Actions tab."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
