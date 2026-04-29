# SecurePipe Terraform Module

Provisions the AWS infrastructure required to run SecurePipe against an app repository:

- **GitHub OIDC provider** — allows GitHub Actions to authenticate with AWS without long-lived credentials
- **ECR repository** — stores the Docker image built during the pipeline run
- **IAM role** — scoped to the specific GitHub repo, with push-only ECR permissions

---

## Prerequisites

- Terraform >= 1.3
- AWS CLI configured with credentials that have IAM and ECR write permissions
- The app repository must exist on GitHub before you apply

---

## Usage

### First time for this AWS account

```bash
cd terraform/

terraform init

terraform apply \
  -var="github_org=your-org" \
  -var="github_repo=your-app-repo"
```

Terraform will create the OIDC provider, ECR repository, and IAM role, then print the outputs you need.

### If the OIDC provider already exists

The GitHub OIDC provider is created once per AWS account. If you have already run this module
for a different repo (or set it up manually), import the existing provider before applying:

```bash
terraform import aws_iam_openid_connect_provider.github \
  https://token.actions.githubusercontent.com

terraform apply \
  -var="github_org=your-org" \
  -var="github_repo=your-app-repo"
```

---

## Inputs

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `github_org` | Yes | — | GitHub org or username |
| `github_repo` | Yes | — | App repository name |
| `aws_region` | No | `us-east-1` | AWS region |
| `ecr_repo_name` | No | same as `github_repo` | ECR repository name |
| `role_name` | No | `securepipe-{github_repo}` | IAM role name |

---

## Outputs

After `terraform apply`, copy these values into your app repo secrets:

| Output | Secret name | Where |
|--------|-------------|-------|
| `aws_account_id` | `AWS_ACCOUNT_ID` | App repo → Settings → Secrets |
| `role_arn` | `AWS_ROLE_ARN` | App repo → Settings → Secrets |
| `ecr_repository_url` | Use as `image-name` input | Caller workflow |

---

## What gets created

```
aws_iam_openid_connect_provider.github   (once per account)
aws_ecr_repository.app
aws_ecr_lifecycle_policy.app             (keeps last 20 images)
aws_iam_role.github_actions
aws_iam_role_policy.ecr_push
```

The IAM role trust policy is scoped to `repo:ORG/REPO:*` — only workflows in
that specific repository can assume it.

---

## Destroying

```bash
terraform destroy \
  -var="github_org=your-org" \
  -var="github_repo=your-app-repo"
```

This will delete the ECR repository and all images in it. The OIDC provider will
also be destroyed — if other roles in the account depend on it, remove it from
state first:

```bash
terraform state rm aws_iam_openid_connect_provider.github
terraform destroy -var="github_org=your-org" -var="github_repo=your-app-repo"
```
