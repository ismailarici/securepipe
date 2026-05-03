#!/usr/bin/env python3
"""Aggregates scan results from reports/raw/ into a single HTML report."""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path


def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {}


def parse_semgrep(data):
    findings = []
    for r in data.get("results", []):
        findings.append({
            "tool": "Semgrep",
            "severity": r.get("extra", {}).get("severity", "INFO").upper(),
            "title": r.get("check_id", "unknown"),
            "file": r.get("path", ""),
            "line": r.get("start", {}).get("line", ""),
            "message": r.get("extra", {}).get("message", ""),
        })
    return findings


def parse_pip_audit(data):
    findings = []
    for dep in data.get("dependencies", []):
        for vuln in dep.get("vulns", []):
            findings.append({
                "tool": "pip-audit",
                "severity": "HIGH",
                "title": vuln.get("id", "CVE-unknown"),
                "file": dep.get("name", "") + "@" + dep.get("version", ""),
                "line": "",
                "message": vuln.get("description", ""),
            })
    return findings


def parse_npm_audit(data):
    findings = []
    for name, vuln in data.get("vulnerabilities", {}).items():
        findings.append({
            "tool": "npm-audit",
            "severity": vuln.get("severity", "unknown").upper(),
            "title": name,
            "file": name + "@" + str(vuln.get("range", "")),
            "line": "",
            "message": vuln.get("title", ""),
        })
    return findings


def parse_trivy(data):
    findings = []
    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities") or []:
            findings.append({
                "tool": "Trivy",
                "severity": vuln.get("Severity", "UNKNOWN"),
                "title": vuln.get("VulnerabilityID", ""),
                "file": vuln.get("PkgName", "") + "@" + vuln.get("InstalledVersion", ""),
                "line": "",
                "message": vuln.get("Description", vuln.get("Title", "")),
            })
    return findings


def parse_dependency_check(data):
    findings = []
    for dep in data.get("dependencies", []):
        for vuln in dep.get("vulnerabilities", []):
            findings.append({
                "tool": "OWASP-DC",
                "severity": vuln.get("severity", "UNKNOWN").upper(),
                "title": vuln.get("name", "CVE-unknown"),
                "file": dep.get("fileName", ""),
                "line": "",
                "message": (vuln.get("description", "") or "")[:200],
            })
    return findings


def parse_zap(data):
    findings = []
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            risk = alert.get("riskdesc", "").split(" ")[0].upper()
            findings.append({
                "tool": "ZAP",
                "severity": risk,
                "title": alert.get("alert", ""),
                "file": alert.get("uri", ""),
                "line": "",
                "message": alert.get("desc", ""),
            })
    return findings


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5}
SEVERITY_COLOR = {
    "CRITICAL": "#dc2626",
    "HIGH": "#ea580c",
    "MEDIUM": "#ca8a04",
    "LOW": "#2563eb",
    "INFO": "#6b7280",
    "UNKNOWN": "#6b7280",
}


def severity_badge(s):
    color = SEVERITY_COLOR.get(s, "#6b7280")
    return f'<span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600">{s}</span>'


def build_html(findings, generated_at):
    critical = [f for f in findings if f["severity"] == "CRITICAL"]
    high = [f for f in findings if f["severity"] == "HIGH"]
    medium = [f for f in findings if f["severity"] == "MEDIUM"]
    low = [f for f in findings if f["severity"] in ("LOW", "INFO", "UNKNOWN")]

    tools = sorted(set(f["tool"] for f in findings))
    tool_counts = {t: len([f for f in findings if f["tool"] == t]) for t in tools}

    rows = ""
    for f in sorted(findings, key=lambda x: SEVERITY_ORDER.get(x["severity"], 5)):
        loc = f["file"]
        if f["line"]:
            loc += f":{f['line']}"
        msg = (f["message"] or "")[:200]
        rows += f"""
        <tr>
          <td>{severity_badge(f['severity'])}</td>
          <td><code style="font-size:12px">{f['tool']}</code></td>
          <td style="font-size:13px">{f['title']}</td>
          <td style="font-size:12px;color:#6b7280">{loc}</td>
          <td style="font-size:12px">{msg}</td>
        </tr>"""

    tool_summary = ""
    for t, c in tool_counts.items():
        tool_summary += f'<div style="display:inline-block;margin:4px 8px 4px 0;padding:4px 12px;background:#f3f4f6;border-radius:6px;font-size:13px"><strong>{t}</strong> — {c} finding{"s" if c != 1 else ""}</div>'

    compliance_rows = """
    <tr><td>SOC 2 — CC6.6</td><td>Semgrep, pip-audit, npm-audit, Trivy</td><td>Logical access controls and vulnerability management evidence</td></tr>
    <tr><td>SOC 2 — CC7.1</td><td>Semgrep, Trivy, ZAP</td><td>Detection and monitoring of security threats</td></tr>
    <tr><td>ISO 27001 — A.12.6.1</td><td>All tools</td><td>Management of technical vulnerabilities — full audit trail</td></tr>
    <tr><td>ISO 27001 — A.14.2.3</td><td>Semgrep, ZAP</td><td>Technical review of application security after OS changes</td></tr>
    """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SecurePipe Security Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f9fafb; color: #111827; }}
  .header {{ background: #111827; color: #fff; padding: 32px 48px; }}
  .header h1 {{ font-size: 24px; font-weight: 700; margin-bottom: 4px; }}
  .header p {{ font-size: 14px; color: #9ca3af; }}
  .content {{ max-width: 1200px; margin: 32px auto; padding: 0 24px; }}
  .card {{ background: #fff; border: 1px solid #e5e7eb; border-radius: 8px; padding: 24px; margin-bottom: 24px; }}
  .card h2 {{ font-size: 16px; font-weight: 600; margin-bottom: 16px; color: #374151; border-bottom: 1px solid #f3f4f6; padding-bottom: 12px; }}
  .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }}
  .stat {{ background: #fff; border: 1px solid #e5e7eb; border-radius: 8px; padding: 20px; text-align: center; }}
  .stat .num {{ font-size: 36px; font-weight: 700; }}
  .stat .label {{ font-size: 13px; color: #6b7280; margin-top: 4px; }}
  .critical .num {{ color: #dc2626; }}
  .high .num {{ color: #ea580c; }}
  .medium .num {{ color: #ca8a04; }}
  .low .num {{ color: #2563eb; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{ text-align: left; padding: 10px 12px; background: #f9fafb; border-bottom: 2px solid #e5e7eb; font-weight: 600; color: #374151; }}
  td {{ padding: 10px 12px; border-bottom: 1px solid #f3f4f6; vertical-align: top; }}
  tr:hover td {{ background: #f9fafb; }}
  .badge-ok {{ background: #16a34a; color: #fff; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }}
  .footer {{ text-align: center; padding: 24px; font-size: 12px; color: #9ca3af; }}
</style>
</head>
<body>
<div class="header">
  <h1>SecurePipe Security Report</h1>
  <p>Generated: {generated_at} &nbsp;|&nbsp; Total findings: {len(findings)}</p>
</div>
<div class="content">

  <div class="stats">
    <div class="stat critical"><div class="num">{len(critical)}</div><div class="label">Critical</div></div>
    <div class="stat high"><div class="num">{len(high)}</div><div class="label">High</div></div>
    <div class="stat medium"><div class="num">{len(medium)}</div><div class="label">Medium</div></div>
    <div class="stat low"><div class="num">{len(low)}</div><div class="label">Low / Info</div></div>
  </div>

  <div class="card">
    <h2>Tool Summary</h2>
    {tool_summary if tool_summary else '<p style="color:#6b7280;font-size:13px">No findings from any tool.</p>'}
  </div>

  <div class="card">
    <h2>All Findings</h2>
    {'<table><thead><tr><th>Severity</th><th>Tool</th><th>Finding</th><th>Location</th><th>Description</th></tr></thead><tbody>' + rows + '</tbody></table>' if findings else '<p style="color:#6b7280;font-size:13px">No findings detected.</p>'}
  </div>

  <div class="card">
    <h2>Recommendations</h2>
    <table>
      <thead><tr><th>Priority</th><th>Action</th></tr></thead>
      <tbody>
        {'<tr><td>' + severity_badge('CRITICAL') + '</td><td>Address ' + str(len(critical)) + ' critical finding(s) before next deployment</td></tr>' if critical else ''}
        {'<tr><td>' + severity_badge('HIGH') + '</td><td>Review and remediate ' + str(len(high)) + ' high severity finding(s) within 7 days</td></tr>' if high else ''}
        {'<tr><td>' + severity_badge('MEDIUM') + '</td><td>Schedule remediation of ' + str(len(medium)) + ' medium finding(s) within 30 days</td></tr>' if medium else ''}
        <tr><td><span class="badge-ok">ACTION</span></td><td>Store this report as audit evidence for SOC 2 CC6.6 / ISO 27001 A.12.6.1</td></tr>
        <tr><td><span class="badge-ok">ACTION</span></td><td>Run <code>./securepipe scan</code> on every pull request</td></tr>
      </tbody>
    </table>
  </div>

  <div class="card">
    <h2>Compliance Mapping</h2>
    <table>
      <thead><tr><th>Control</th><th>Tools</th><th>Evidence</th></tr></thead>
      <tbody>{compliance_rows}</tbody>
    </table>
    <p style="margin-top:16px;font-size:13px;color:#6b7280">
      <strong>Audit use:</strong> This report is timestamped and self-contained.
      Attach it to your SOC 2 evidence collection or ISO 27001 Statement of Applicability review.
      Raw tool outputs are in <code>reports/raw/</code> for auditor inspection.
    </p>
  </div>

</div>
<div class="footer">SecurePipe &mdash; open source DevSecOps pipeline &mdash; github.com/ismailarici/securepipe</div>
</body>
</html>"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw-dir", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    raw = Path(args.raw_dir)
    findings = []

    if (raw / "semgrep.json").exists():
        findings += parse_semgrep(load_json(raw / "semgrep.json"))
    if (raw / "sca.json").exists():
        sca = load_json(raw / "sca.json")
        deps = sca.get("dependencies", [])
        if deps and "vulns" in (deps[0] if deps else {}):
            findings += parse_pip_audit(sca)
        elif deps and "vulnerabilities" in (deps[0] if deps else {}):
            findings += parse_dependency_check(sca)
        elif "vulnerabilities" in sca:
            findings += parse_npm_audit(sca)
    if (raw / "trivy.json").exists():
        findings += parse_trivy(load_json(raw / "trivy.json"))
    if (raw / "zap.json").exists():
        findings += parse_zap(load_json(raw / "zap.json"))

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    html = build_html(findings, generated_at)

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w") as f:
        f.write(html)

    print(f"Report written: {args.output} ({len(findings)} total findings)")


if __name__ == "__main__":
    main()
