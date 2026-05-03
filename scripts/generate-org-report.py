#!/usr/bin/env python3
"""Generates org-level summary HTML from per-repo scan results."""

import argparse
import importlib.util
import json
from pathlib import Path
from datetime import datetime, timezone


def load_parsers():
    spec = importlib.util.spec_from_file_location(
        "generate_report", Path(__file__).parent / "generate-report.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {}


def get_repo_findings(raw_dir, parsers):
    findings = []
    if (raw_dir / "semgrep.json").exists():
        findings += parsers.parse_semgrep(load_json(raw_dir / "semgrep.json"))
    if (raw_dir / "sca.json").exists():
        sca = load_json(raw_dir / "sca.json")
        deps = sca.get("dependencies", [])
        if deps and "vulns" in (deps[0] if deps else {}):
            findings += parsers.parse_pip_audit(sca)
        elif deps and "vulnerabilities" in (deps[0] if deps else {}):
            findings += parsers.parse_dependency_check(sca)
        elif "vulnerabilities" in sca:
            findings += parsers.parse_npm_audit(sca)
    if (raw_dir / "trivy.json").exists():
        findings += parsers.parse_trivy(load_json(raw_dir / "trivy.json"))
    if (raw_dir / "zap.json").exists():
        findings += parsers.parse_zap(load_json(raw_dir / "zap.json"))
    return findings


def build_org_html(repo_data, generated_at):
    total = sum(r["total"] for r in repo_data)
    total_critical = sum(r["critical"] for r in repo_data)
    total_high = sum(r["high"] for r in repo_data)
    total_medium = sum(r["medium"] for r in repo_data)

    repo_rows = ""
    for r in sorted(repo_data, key=lambda x: -(x["critical"] * 1000 + x["high"] * 100 + x["medium"])):
        link = f'<a href="{r["name"]}/security-report.html" style="color:#2563eb;text-decoration:none;font-weight:600">{r["name"]}</a>'
        if r["critical"] > 0:
            status, status_color = "CRITICAL", "#dc2626"
        elif r["high"] > 0:
            status, status_color = "HIGH", "#ea580c"
        elif r["medium"] > 0:
            status, status_color = "MEDIUM", "#ca8a04"
        else:
            status, status_color = "CLEAN", "#16a34a"

        def cell(n):
            return f'<td style="text-align:center">{n if n > 0 else "—"}</td>'

        repo_rows += f"""
        <tr>
          <td>{link}</td>
          <td style="color:{status_color};font-weight:600">{status}</td>
          {cell(r['critical'])}
          {cell(r['high'])}
          {cell(r['medium'])}
          {cell(r['low'])}
          <td style="text-align:center;font-weight:600">{r['total']}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SecurePipe — Org Security Summary</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f9fafb; color: #111827; }}
  .header {{ background: #111827; color: #fff; padding: 32px 48px; }}
  .header h1 {{ font-size: 24px; font-weight: 700; margin-bottom: 4px; }}
  .header p {{ font-size: 14px; color: #9ca3af; }}
  .content {{ max-width: 1100px; margin: 32px auto; padding: 0 24px; }}
  .stats {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 16px; margin-bottom: 24px; }}
  .stat {{ background: #fff; border: 1px solid #e5e7eb; border-radius: 8px; padding: 20px; text-align: center; }}
  .stat .num {{ font-size: 32px; font-weight: 700; }}
  .stat .label {{ font-size: 12px; color: #6b7280; margin-top: 4px; }}
  .repos .num {{ color: #374151; }}
  .critical .num {{ color: #dc2626; }}
  .high .num {{ color: #ea580c; }}
  .medium .num {{ color: #ca8a04; }}
  .total .num {{ color: #374151; }}
  .card {{ background: #fff; border: 1px solid #e5e7eb; border-radius: 8px; padding: 24px; margin-bottom: 24px; }}
  .card h2 {{ font-size: 16px; font-weight: 600; margin-bottom: 16px; color: #374151; border-bottom: 1px solid #f3f4f6; padding-bottom: 12px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{ text-align: left; padding: 10px 12px; background: #f9fafb; border-bottom: 2px solid #e5e7eb; font-weight: 600; }}
  td {{ padding: 10px 12px; border-bottom: 1px solid #f3f4f6; }}
  tr:hover td {{ background: #f9fafb; }}
  .footer {{ text-align: center; padding: 24px; font-size: 12px; color: #9ca3af; }}
</style>
</head>
<body>
<div class="header">
  <h1>SecurePipe — Org Security Summary</h1>
  <p>Generated: {generated_at} &nbsp;|&nbsp; {len(repo_data)} repos &nbsp;|&nbsp; {total} total findings</p>
</div>
<div class="content">
  <div class="stats">
    <div class="stat repos"><div class="num">{len(repo_data)}</div><div class="label">Repos scanned</div></div>
    <div class="stat critical"><div class="num">{total_critical}</div><div class="label">Critical</div></div>
    <div class="stat high"><div class="num">{total_high}</div><div class="label">High</div></div>
    <div class="stat medium"><div class="num">{total_medium}</div><div class="label">Medium</div></div>
    <div class="stat total"><div class="num">{total}</div><div class="label">Total findings</div></div>
  </div>

  <div class="card">
    <h2>Repos — Security Status</h2>
    <table>
      <thead>
        <tr>
          <th>Repo</th><th>Status</th>
          <th style="text-align:center">Critical</th>
          <th style="text-align:center">High</th>
          <th style="text-align:center">Medium</th>
          <th style="text-align:center">Low</th>
          <th style="text-align:center">Total</th>
        </tr>
      </thead>
      <tbody>{repo_rows}</tbody>
    </table>
  </div>

  <div class="card">
    <h2>Compliance Note</h2>
    <p style="font-size:13px;color:#374151;line-height:1.6">
      This org summary represents a point-in-time security scan across {len(repo_data)} service(s).
      Each repo link opens the detailed per-service report. Store this page and the per-repo reports
      as evidence for SOC 2 CC6.6 / ISO 27001 A.12.6.1 audits. Raw findings (JSON) are in each
      repo's <code>raw/</code> folder for auditor inspection.
    </p>
  </div>
</div>
<div class="footer">SecurePipe &mdash; github.com/ismailarici/securepipe</div>
</body>
</html>"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--reports-dir", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    parsers = load_parsers()
    reports_dir = Path(args.reports_dir)

    repo_data = []
    for repo_dir in sorted(reports_dir.iterdir()):
        raw_dir = repo_dir / "raw"
        if not repo_dir.is_dir() or not raw_dir.exists():
            continue
        findings = get_repo_findings(raw_dir, parsers)
        repo_data.append({
            "name": repo_dir.name,
            "total": len(findings),
            "critical": len([f for f in findings if f["severity"] == "CRITICAL"]),
            "high": len([f for f in findings if f["severity"] == "HIGH"]),
            "medium": len([f for f in findings if f["severity"] == "MEDIUM"]),
            "low": len([f for f in findings if f["severity"] in ("LOW", "INFO", "UNKNOWN")]),
        })

    if not repo_data:
        print("No repo scan data found in reports directory.")
        return

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    html = build_org_html(repo_data, generated_at)

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w") as f:
        f.write(html)
    print(f"Org summary written: {args.output} ({len(repo_data)} repos, {sum(r['total'] for r in repo_data)} findings)")


if __name__ == "__main__":
    main()
