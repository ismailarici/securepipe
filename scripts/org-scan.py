#!/usr/bin/env python3
"""Orchestrates multi-repo scanning from securepipe-org.yml."""

import argparse
import subprocess
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    subprocess.run(
        [sys.executable, "-m", "pip", "install", "pyyaml", "-q"],
        check=True, capture_output=True,
    )
    import yaml


def scan_repo(securepipe, repo, output_dir):
    name = repo.get("name", "unknown")
    path = repo.get("path", ".")
    url = repo.get("url", "")
    openapi = repo.get("openapi", "")
    auth_header = repo.get("auth_header", "")

    cmd = [
        securepipe, "scan",
        "--target", str(Path(path).resolve()),
        "--output-dir", str(output_dir),
    ]
    if url:
        cmd += ["--url", url]
    if openapi:
        cmd += ["--openapi", str(Path(openapi).resolve())]
    if auth_header:
        cmd += ["--auth-header", auth_header]

    print(f"\n\033[1;34m[org-scan]\033[0m Scanning \033[1m{name}\033[0m ...", flush=True)
    print(f"           target: {path}", flush=True)

    try:
        result = subprocess.run(cmd, timeout=600)
        if result.returncode == 0:
            print(f"\033[1;32m[✓]\033[0m {name} complete")
        else:
            print(f"\033[1;33m[!]\033[0m {name} finished with warnings")
        return True
    except subprocess.TimeoutExpired:
        print(f"\033[1;31m[✗]\033[0m {name} timed out after 10 minutes")
        return False
    except Exception as e:
        print(f"\033[1;31m[✗]\033[0m {name} failed: {e}")
        return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--securepipe", required=True)
    args = parser.parse_args()

    with open(args.config) as f:
        config = yaml.safe_load(f)

    repos = config.get("repos", [])
    if not repos:
        print("No repos defined in config.")
        sys.exit(1)

    script_dir = Path(args.securepipe).parent
    reports_base = script_dir / "reports"

    print(f"\n\033[1;35m━━━ Org Scan — {len(repos)} repo(s) ━━━\033[0m", flush=True)

    results = []
    for repo in repos:
        name = repo.get("name", "unknown")
        output_dir = reports_base / name
        output_dir.mkdir(parents=True, exist_ok=True)
        success = scan_repo(args.securepipe, repo, output_dir)
        results.append({"name": name, "success": success})

    successful = sum(1 for r in results if r["success"])
    print(f"\n\033[1;35m━━━ Generating Org Summary ({successful}/{len(results)} repos) ━━━\033[0m")

    summary_script = script_dir / "scripts" / "generate-org-report.py"
    subprocess.run([
        sys.executable, str(summary_script),
        "--reports-dir", str(reports_base),
        "--output", str(reports_base / "org-summary.html"),
    ])

    print(f"\n\033[1;32m━━━ Org scan complete ━━━\033[0m")
    print(f"\033[1;34m[org-scan]\033[0m Summary: {reports_base}/org-summary.html")
    print(f"\033[1;34m[org-scan]\033[0m Open with: open \"{reports_base}/org-summary.html\"")


if __name__ == "__main__":
    main()
