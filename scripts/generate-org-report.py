#!/usr/bin/env python3
"""Generates org-level summary HTML from per-repo scan results."""

import argparse
import html
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import normalize

e = html.escape

SEVERITY_COLOR = {
    "CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#ca8a04",
    "LOW": "#2563eb", "INFO": "#6b7280", "UNKNOWN": "#6b7280",
}


def build_org_html(repo_data, generated_at):
    total          = sum(r["total"] for r in repo_data)
    total_critical = sum(r["critical"] for r in repo_data)
    total_high     = sum(r["high"] for r in repo_data)
    total_medium   = sum(r["medium"] for r in repo_data)

    repo_rows = ""
    for r in sorted(repo_data, key=lambda x: -(x["critical"] * 1000 + x["high"] * 100 + x["medium"])):
        link = (f'<a href="{e(r["name"])}/security-report.html" '
                f'style="color:#2563eb;text-decoration:none;font-weight:600">{e(r["name"])}</a>')

        if r["critical"] > 0:
            status, sc = "CRITICAL", "#dc2626"
        elif r["high"] > 0:
            status, sc = "HIGH", "#ea580c"
        elif r["medium"] > 0:
            status, sc = "MEDIUM", "#ca8a04"
        else:
            status, sc = "CLEAN", "#16a34a"

        def _cell(n):
            return f'<td style="text-align:center">{n if n > 0 else "&#8212;"}</td>'

        repo_rows += (
            f'<tr><td>{link}</td>'
            f'<td style="color:{sc};font-weight:600">{status}</td>'
            f'{_cell(r["critical"])}{_cell(r["high"])}{_cell(r["medium"])}{_cell(r["low"])}'
            f'<td style="text-align:center;font-weight:600">{r["total"]}</td></tr>\n'
        )

    return (
        _ORG_HEAD
        + f'<div class="header"><h1>SecurePipe &mdash; Org Security Summary</h1>'
          f'<p>Generated: {e(generated_at)} &nbsp;|&nbsp; {len(repo_data)} repos '
          f'&nbsp;|&nbsp; {total} total findings</p></div>\n'
        + '<div class="content">\n'
        + f'<div class="stats">'
          f'<div class="stat repos"><div class="num">{len(repo_data)}</div><div class="label">Repos scanned</div></div>'
          f'<div class="stat critical"><div class="num">{total_critical}</div><div class="label">Critical</div></div>'
          f'<div class="stat high"><div class="num">{total_high}</div><div class="label">High</div></div>'
          f'<div class="stat medium"><div class="num">{total_medium}</div><div class="label">Medium</div></div>'
          f'<div class="stat total"><div class="num">{total}</div><div class="label">Total findings</div></div>'
          f'</div>\n'
        + f'<div class="card"><h2>Repos — Security Status</h2>'
          f'<table><thead><tr>'
          f'<th>Repo</th><th>Status</th>'
          f'<th style="text-align:center">Critical</th>'
          f'<th style="text-align:center">High</th>'
          f'<th style="text-align:center">Medium</th>'
          f'<th style="text-align:center">Low</th>'
          f'<th style="text-align:center">Total</th>'
          f'</tr></thead><tbody>{repo_rows}</tbody></table></div>\n'
        + f'<div class="card"><h2>Compliance Note</h2>'
          f'<p style="font-size:13px;color:#374151;line-height:1.6">'
          f'This org summary represents a point-in-time security scan across {len(repo_data)} service(s). '
          f'Each repo link opens the detailed per-service report. Store this page and the per-repo reports '
          f'as evidence for SOC 2 CC6.6 / ISO 27001 A.12.6.1 audits. Raw findings (JSON) are in each '
          f"repo's <code>raw/</code> folder for auditor inspection.</p></div>\n"
        + '</div>\n'
        + '<div class="footer">SecurePipe &mdash; github.com/ismailarici/securepipe</div>\n'
        + '</body></html>\n'
    )


_ORG_HEAD = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SecurePipe — Org Security Summary</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f9fafb; color: #111827; }
  .header { background: #111827; color: #fff; padding: 32px 48px; }
  .header h1 { font-size: 24px; font-weight: 700; margin-bottom: 4px; }
  .header p { font-size: 14px; color: #9ca3af; }
  .content { max-width: 1100px; margin: 32px auto; padding: 0 24px; }
  .stats { display: grid; grid-template-columns: repeat(5, 1fr); gap: 16px; margin-bottom: 24px; }
  .stat { background: #fff; border: 1px solid #e5e7eb; border-radius: 8px; padding: 20px; text-align: center; }
  .stat .num { font-size: 32px; font-weight: 700; }
  .stat .label { font-size: 12px; color: #6b7280; margin-top: 4px; }
  .repos .num { color: #374151; }
  .critical .num { color: #dc2626; }
  .high .num { color: #ea580c; }
  .medium .num { color: #ca8a04; }
  .total .num { color: #374151; }
  .card { background: #fff; border: 1px solid #e5e7eb; border-radius: 8px; padding: 24px; margin-bottom: 24px; }
  .card h2 { font-size: 16px; font-weight: 600; margin-bottom: 16px; color: #374151; border-bottom: 1px solid #f3f4f6; padding-bottom: 12px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; padding: 10px 12px; background: #f9fafb; border-bottom: 2px solid #e5e7eb; font-weight: 600; }
  td { padding: 10px 12px; border-bottom: 1px solid #f3f4f6; }
  tr:hover td { background: #f9fafb; }
  .footer { text-align: center; padding: 24px; font-size: 12px; color: #9ca3af; }
  @media (max-width: 768px) { .stats { grid-template-columns: repeat(2, 1fr); } }
</style>
</head>
<body>
"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--reports-dir", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    reports_dir = Path(args.reports_dir)
    repo_data = []

    for repo_dir in sorted(reports_dir.iterdir()):
        raw_dir = repo_dir / "raw"
        if not repo_dir.is_dir() or not raw_dir.exists():
            continue
        findings = normalize.load_findings(raw_dir)
        repo_data.append({
            "name": repo_dir.name,
            "total": len(findings),
            "critical": len([f for f in findings if f["severity"] == "CRITICAL"]),
            "high":     len([f for f in findings if f["severity"] == "HIGH"]),
            "medium":   len([f for f in findings if f["severity"] == "MEDIUM"]),
            "low":      len([f for f in findings if f["severity"] in ("LOW", "INFO", "UNKNOWN")]),
        })

    if not repo_data:
        print("No repo scan data found in reports directory.")
        return

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    html_out = build_org_html(repo_data, generated_at)

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w") as f:
        f.write(html_out)
    total = sum(r["total"] for r in repo_data)
    print(f"Org summary written: {args.output} ({len(repo_data)} repos, {total} findings)")


if __name__ == "__main__":
    main()
