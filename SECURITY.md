# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| `main`  | Yes       |
| `v1.x`  | Yes       |

Older tags are not patched. Pin to `main` or the latest tag.

---

## Reporting a vulnerability

**Do not open a public issue for security vulnerabilities.**

Report privately via GitHub's security advisory system:
[https://github.com/ismailarici/securepipe/security/advisories/new](https://github.com/ismailarici/securepipe/security/advisories/new)

Include:

- A description of the vulnerability and its impact
- Steps to reproduce or a proof-of-concept
- The pipeline version or commit SHA affected
- Whether you believe it is exploitable in a default configuration

---

## What to report

Things that belong here:

- A pipeline step that introduces a supply chain risk (e.g. a `curl | bash` from an untrusted source)
- A misconfiguration in the OIDC trust policy that allows credential escalation
- An injection vulnerability in how inputs are passed to scanner commands
- A workflow step that leaks secrets to logs

Things that do not belong here:

- Vulnerabilities found *by* the pipeline in a sample app — those are intentional test cases
- GitHub Actions platform vulnerabilities — report those to GitHub
- Scanner tool vulnerabilities (Trivy, Semgrep, etc.) — report those to the respective projects

---

## Response timeline

| Event | Target |
|-------|--------|
| Acknowledgement | Within 48 hours |
| Initial assessment | Within 5 business days |
| Fix or mitigation | Depends on severity — critical issues within 7 days |
| Public disclosure | After fix is available, coordinated with reporter |

---

## Scope

This policy covers the pipeline workflow at `.github/workflows/reusable-security-pipeline.yml`,
the Terraform module at `terraform/`, and the setup script at `setup.sh`.

The sample app at `sample-apps/` is intentionally minimal and may contain findings
flagged by the pipeline — that is expected behaviour, not a vulnerability.
