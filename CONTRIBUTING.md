# Contributing to SecurePipe

Thanks for taking the time to contribute. This document covers the full process
from reporting a bug to getting a pull request merged.

---

## Ways to contribute

- **Bug reports** — something behaves differently than documented
- **Feature requests** — a scanner, output format, or integration that would make this useful for more teams
- **Pull requests** — fixes, new stages, documentation improvements
- **Testing** — running the pipeline against your own apps and reporting what breaks

---

## Reporting bugs

Use the [bug report template](https://github.com/ismailarici/securepipe/issues/new?template=bug_report.yml).

Before filing, check whether the issue is already reported. Include:

- The pipeline version (`@v1.0.0`, `@main`, etc.)
- The `app-language` input value
- The full error output from the failing job
- Whether the issue reproduces on the sample app in `sample-apps/python/`

The sample app is the baseline. If it fails there, it is definitively a pipeline bug.
If it only fails on your app, include your Dockerfile and dependency file (redact secrets).

---

## Requesting features

Use the [feature request template](https://github.com/ismailarici/securepipe/issues/new?template=feature_request.yml).

Describe the security problem you are trying to solve, not just the tool you want added.
A request like "add Snyk" with no context is hard to evaluate. A request like
"pip-audit misses transitive dependencies in monorepos structured as X — Snyk handles
this because Y" gives enough to make a decision.

---

## Pull requests

### Before you start

For non-trivial changes, open an issue first. This avoids spending time on a PR
that conflicts with planned work or a design decision already made.

For small fixes (documentation, broken step names, missing `if: always()` on an upload
step), go straight to a PR.

### Setup

```bash
git clone https://github.com/ismailarici/securepipe.git
cd securepipe
```

No build step. The pipeline is YAML — edit, validate, test.

### Validation

Always validate the workflow YAML before committing:

```bash
make validate
```

This runs `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/reusable-security-pipeline.yml'))"`.
A YAML parse error means the pipeline will fail to load on GitHub — this is a hard block.

To test end to end, point a caller workflow at your fork's branch:

```yaml
uses: YOUR_FORK/securepipe/.github/workflows/reusable-security-pipeline.yml@YOUR_BRANCH
```

### Code standards

- Every job must have a `name:` field
- Every step must have a `name:` field
- No hardcoded values — use inputs
- `|| true` on scanner runs so findings do not skip SARIF upload
- `if: always()` on all upload steps
- Comments explain *why*, not *what*
- OIDC authentication only — no long-lived credentials
- Images tagged with git SHA, never `latest`

### Commit messages

Lowercase imperative, no period:

```
add trivy scan for java apps
fix missing if: always() on bandit upload step
update semgrep to scan .semgrep/ directory from pipeline repo
```

Not:

```
Fixed bug
Updated file
WIP
```

One logical change per commit.

### PR checklist

The PR template will prompt you through this. The two hard requirements are:
YAML validates and the pipeline passes on a real run.

---

## What will not be merged

- New scanners without a documented rationale for why existing coverage is insufficient
- Hardcoded credentials or region values of any kind
- Changes that break existing callers without a migration path
- `latest` image tags
- Long-lived AWS credentials replacing OIDC

---

## Questions

Open a [discussion](https://github.com/ismailarici/securepipe/discussions) or file an issue.
