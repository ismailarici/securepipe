# DefectDojo Setup Guide

DefectDojo is an open source vulnerability management platform. SecurePipe can import all scan
findings into DefectDojo automatically after every pipeline run, giving you a persistent,
searchable record of findings across all your repositories and releases.

---

## What gets created

Every pipeline run creates one **engagement** under a **product** in DefectDojo. The product
is named after your GitHub repository. The engagement is named `SecurePipe {short-sha}` and
contains all findings from that run across all scanners.

---

## Option 1 — Deploy DefectDojo on EC2 (recommended for teams)

### Prerequisites

- An EC2 instance (t3.medium minimum — DefectDojo is a Django app with Celery workers)
- Amazon Linux 2023 or Ubuntu 22.04
- Security group: inbound port 80 or 443 from your runner IPs (or 0.0.0.0/0 if public)
- Outbound port 443 for pip installs during setup

### Step 1 — Launch the instance

```bash
# From your local machine
aws ec2 run-instances \
  --image-id ami-0c02fb55956c7d316 \
  --instance-type t3.medium \
  --key-name your-key-pair \
  --security-group-ids sg-xxxxxxxxxx \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=defectdojo}]'
```

Or use the AWS console. Note the public IP or DNS — this becomes your `defectdojo-url`.

### Step 2 — Install DefectDojo

SSH into the instance and run the official Docker Compose installation:

```bash
sudo yum install -y git docker
sudo systemctl enable --now docker
sudo usermod -aG docker ec2-user

# Re-login for group change to take effect
exit && ssh ...

git clone https://github.com/DefectDojo/django-DefectDojo.git
cd django-DefectDojo

# Generate secrets
./dc-build.sh

# Start all services
docker compose up -d

# Wait for initialisation (takes 2-3 minutes on first run)
docker compose logs -f initializer
```

When you see `Admin password: ...` in the initializer logs, DefectDojo is ready.

### Step 3 — Get the admin password

```bash
docker compose logs initializer 2>&1 | grep "Admin password"
```

Log in at `http://YOUR_EC2_IP/` with username `admin` and the password above.

### Step 4 — Create an API token

1. Log into DefectDojo
2. Go to your profile (top right) → **API v2 Key**
3. Copy the token

This is your `DEFECTDOJO_TOKEN` secret.

### Step 5 — Optionally set up HTTPS

Use an Application Load Balancer with an ACM certificate in front of the EC2 instance, or
install Caddy on the instance for automatic Let's Encrypt:

```bash
sudo yum install -y caddy

cat > /etc/caddy/Caddyfile << EOF
defectdojo.yourdomain.com {
    reverse_proxy localhost:80
}
EOF

sudo systemctl enable --now caddy
```

---

## Option 2 — DefectDojo Cloud

DefectDojo offers a hosted SaaS version at defectdojo.com. If you use DefectDojo Cloud:

1. Log in and go to your profile → API v2 Key
2. Your `defectdojo-url` is `https://app.defectdojo.com` (or your org subdomain)
3. Your `DEFECTDOJO_TOKEN` is the key from step 1

---

## Connecting SecurePipe to DefectDojo

### Step 1 — Add the secret to your app repo

In your app repo → Settings → Secrets and variables → Actions → New repository secret:

| Secret | Value |
|--------|-------|
| `DEFECTDOJO_TOKEN` | The API token from DefectDojo |

### Step 2 — Update the caller workflow

Add `defectdojo-url` to the `with:` block and the token to `secrets:`:

```yaml
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
      defectdojo-url: https://defectdojo.yourdomain.com
    secrets:
      AWS_ACCOUNT_ID: ${{ secrets.AWS_ACCOUNT_ID }}
      AWS_ROLE_ARN: ${{ secrets.AWS_ROLE_ARN }}
      DEFECTDOJO_TOKEN: ${{ secrets.DEFECTDOJO_TOKEN }}
```

### Step 3 — Push and verify

After the next pipeline run, log into DefectDojo and go to **Products**. You will see a product
named after your repository with one engagement per pipeline run. Each engagement contains the
findings from all scanners.

---

## What the import does

1. Looks up the product by repository name. Creates it if it does not exist.
2. Creates a new engagement named `SecurePipe {short-sha}` with today's date.
3. Downloads all SARIF files generated during the run.
4. Uploads each SARIF file to the engagement via the DefectDojo `/api/v2/import-scan/` endpoint.
5. Marks new findings active, closes findings from previous runs that are no longer present.

The `close_old_findings: true` flag means DefectDojo will automatically mark a finding as
mitigated if it does not appear in the latest scan. This keeps your finding list accurate
without manual triage of resolved issues.

---

## Troubleshooting

**DefectDojo Import job fails with 401**
The `DEFECTDOJO_TOKEN` secret is incorrect or has been revoked. Generate a new token from
your DefectDojo profile page.

**DefectDojo Import job fails with connection refused**
The EC2 instance is not reachable from GitHub Actions runners. Check the security group
inbound rules. GitHub Actions runners use a range of IPs — the simplest fix for an internal
deployment is to allow 0.0.0.0/0 on port 443, or use a public ALB.

**No findings appear in DefectDojo despite the job succeeding**
The SARIF files were empty (no findings). This is correct behaviour — an empty SARIF is a
valid scan result with zero issues.

**Product was created with the wrong name**
The product name is derived from the last segment of `github.repository` (e.g. `org/my-app`
becomes `my-app`). If you have multiple repos with the same name, use DefectDojo's product
type feature to organise them.
