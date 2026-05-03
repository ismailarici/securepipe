#!/usr/bin/env python3
"""Aggregates scan results from reports/raw/ into a detailed HTML report."""

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
CATEGORY_COLOR = {
    "SAST": "#7c3aed", "SCA": "#0369a1", "CONTAINER": "#0f766e", "DAST": "#b45309",
}


def _badge(text, color):
    return (f'<span style="background:{color};color:#fff;padding:2px 7px;'
            f'border-radius:4px;font-size:11px;font-weight:600;white-space:nowrap">'
            f'{e(text)}</span>')


def _sev_badge(s):
    return _badge(s, SEVERITY_COLOR.get(s, "#6b7280"))


def _cat_badge(s):
    return _badge(s, CATEGORY_COLOR.get(s, "#6b7280"))


def _location(f):
    cat = f.get("category", "")
    if cat == "SAST":
        path = f.get("file", "")
        parts = Path(path).parts
        short = "/".join(parts[-2:]) if len(parts) >= 2 else path
        line = f.get("line")
        return e(f"{short}:{line}" if line else short)
    if cat == "SCA":
        pkg = f.get("package", "")
        ver = f.get("version", "")
        file_ref = f.get("file", "")
        pkg_str = f"{pkg}@{ver}" if ver else pkg
        if file_ref:
            return (f'{e(pkg_str)}<br>'
                    f'<span style="font-size:11px;color:#9ca3af;font-family:monospace">{e(file_ref)}</span>')
        return e(pkg_str)
    if cat == "CONTAINER":
        pkg = f.get("package", "")
        ver = f.get("version", "")
        target = f.get("container_target", "")
        pkg_str = f"{pkg}@{ver}" if ver else pkg
        if target:
            return (f'{e(pkg_str)}<br>'
                    f'<span style="font-size:11px;color:#9ca3af;font-family:monospace">{e(target)}</span>')
        return e(pkg_str)
    if cat == "DAST":
        method = f.get("method", "")
        ep = f.get("endpoint", "")
        return e((f"{method} {ep}" if method else ep)[:80])
    return ""


def _tool_label(f):
    sources = f.get("sources")
    if sources and len(sources) > 1:
        return e(" + ".join(sources))
    return e(f.get("tool", ""))


def _detail_panel(f):
    parts = []

    desc = f.get("description", "")
    if desc:
        parts.append(f'<div class="dl"><div class="dt">Description</div>'
                     f'<div class="dd">{e(desc)}</div></div>')

    cat = f.get("category", "")

    if cat == "SAST":
        file_path = f.get("file", "")
        line = f.get("line")
        if file_path:
            loc = f"{file_path}:{line}" if line else file_path
            parts.append(f'<div class="dl"><div class="dt">Location</div>'
                         f'<div class="dd"><code>{e(loc)}</code></div></div>')
        snippet = f.get("code_snippet", "")
        if snippet:
            parts.append(f'<div class="dl"><div class="dt">Code</div>'
                         f'<div class="dd"><pre class="snippet">{e(snippet)}</pre></div></div>')

    if cat in ("SCA", "CONTAINER"):
        pkg = f.get("package", "")
        ver = f.get("version", "")
        fixed = f.get("fixed_version", "")
        if pkg:
            ver_str = f"{pkg}@{ver}" if ver else pkg
            parts.append(f'<div class="dl"><div class="dt">Package</div>'
                         f'<div class="dd"><code>{e(ver_str)}</code></div></div>')
        if fixed:
            parts.append(f'<div class="dl"><div class="dt">Fix version</div>'
                         f'<div class="dd"><code style="color:#16a34a;font-weight:600">{e(fixed)}</code></div></div>')
        dep_path = f.get("dependency_path", [])
        if dep_path:
            parts.append(f'<div class="dl"><div class="dt">Dep path</div>'
                         f'<div class="dd"><code>{e(" → ".join(dep_path))}</code></div></div>')
        if cat == "CONTAINER":
            target = f.get("container_target", "")
            ct = f.get("container_type", "")
            if target:
                type_note = f' <small style="color:#6b7280">({e(ct)})</small>' if ct else ""
                parts.append(f'<div class="dl"><div class="dt">Target</div>'
                             f'<div class="dd"><code>{e(target)}</code>{type_note}</div></div>')
        file_ref = f.get("file", "")
        if file_ref:
            parts.append(f'<div class="dl"><div class="dt">File</div>'
                         f'<div class="dd"><code>{e(file_ref)}</code></div></div>')

    if cat == "DAST":
        ep = f.get("endpoint", "")
        method = f.get("method", "")
        param = f.get("parameter", "")
        evidence = f.get("evidence", "")
        if ep:
            ep_str = f"{method} {ep}" if method else ep
            parts.append(f'<div class="dl"><div class="dt">Endpoint</div>'
                         f'<div class="dd"><code>{e(ep_str)}</code></div></div>')
        if param:
            parts.append(f'<div class="dl"><div class="dt">Parameter</div>'
                         f'<div class="dd"><code>{e(param)}</code></div></div>')
        if evidence:
            parts.append(f'<div class="dl"><div class="dt">Evidence</div>'
                         f'<div class="dd"><code>{e(evidence)}</code></div></div>')

    fix = f.get("fix", "")
    if fix:
        parts.append(f'<div class="dl"><div class="dt">Fix</div>'
                     f'<div class="dd fix-text">{e(fix)}</div></div>')

    rule_id = f.get("rule_id", "")
    if rule_id:
        parts.append(f'<div class="dl"><div class="dt">Rule</div>'
                     f'<div class="dd"><code style="font-size:11px;color:#6b7280">{e(rule_id)}</code></div></div>')

    cve = f.get("cve", "")
    if cve and cve != "CVE-unknown":
        parts.append(f'<div class="dl"><div class="dt">CVE / ID</div>'
                     f'<div class="dd"><code>{e(cve)}</code></div></div>')

    sources = f.get("sources", [])
    if sources and len(sources) > 1:
        parts.append(f'<div class="dl"><div class="dt">Found by</div>'
                     f'<div class="dd">{e(", ".join(sources))}</div></div>')

    refs = f.get("references", [])
    if refs:
        links = " ".join(
            f'<a href="{e(r)}" target="_blank" rel="noopener">'
            f'{e(r[:70])}{"…" if len(r) > 70 else ""}</a>'
            for r in refs if r
        )
        parts.append(f'<div class="dl"><div class="dt">References</div>'
                     f'<div class="dd ref-links">{links}</div></div>')

    return "\n".join(parts)


def _compliance_rows(findings):
    sast_tools = {f["tool"] for f in findings if f["category"] == "SAST"}
    sca_tools  = {f["tool"] for f in findings if f["category"] == "SCA"}
    cont_tools = {f["tool"] for f in findings if f["category"] == "CONTAINER"}
    dast_tools = {f["tool"] for f in findings if f["category"] == "DAST"}
    all_tools  = sast_tools | sca_tools | cont_tools | dast_tools

    def _tools_cell(s):
        return e(", ".join(sorted(s))) if s else '<span style="color:#9ca3af">—</span>'

    def _status(s):
        if s:
            return '<span style="color:#16a34a;font-weight:600">&#10003; Evidence captured</span>'
        return '<span style="color:#9ca3af">No data</span>'

    cc66 = sast_tools | sca_tools | cont_tools
    cc71 = sast_tools | cont_tools | dast_tools

    rows = [
        ("SOC 2 — CC6.6", cc66,
         "Vulnerability identification across SAST, SCA, and container scanning"),
        ("SOC 2 — CC7.1", cc71,
         "Detection and monitoring of security threats in code and runtime"),
        ("ISO 27001 — A.12.6.1", all_tools,
         "Technical vulnerability management — full audit trail of identified issues"),
        ("ISO 27001 — A.14.2.3", sast_tools | dast_tools,
         "Technical review of application security after environment changes"),
    ]
    html_rows = ""
    for control, tool_set, scope in rows:
        html_rows += (f"<tr><td>{e(control)}</td><td>{_tools_cell(tool_set)}</td>"
                      f"<td>{e(scope)}</td><td>{_status(tool_set)}</td></tr>\n")
    return html_rows


def build_html(findings, generated_at):
    findings = sorted(
        findings,
        key=lambda x: (normalize.SEVERITY_ORDER.get(x["severity"], 5), x.get("title", ""))
    )

    critical = [f for f in findings if f["severity"] == "CRITICAL"]
    high     = [f for f in findings if f["severity"] == "HIGH"]
    medium   = [f for f in findings if f["severity"] == "MEDIUM"]
    low      = [f for f in findings if f["severity"] in ("LOW", "INFO", "UNKNOWN")]

    tools = sorted(set(f["tool"] for f in findings))
    tool_counts = {t: len([f for f in findings if f["tool"] == t or t in f.get("sources", [])]) for t in tools}

    tool_summary = "".join(
        f'<div class="tool-pill"><strong>{e(t)}</strong> &mdash; {c} finding{"s" if c != 1 else ""}</div>'
        for t, c in tool_counts.items()
    ) if tool_counts else '<p class="empty-msg">No findings from any tool.</p>'

    severities = sorted(set(f["severity"] for f in findings), key=lambda s: normalize.SEVERITY_ORDER.get(s, 5))
    categories = sorted(set(f["category"] for f in findings))
    all_tools_list = sorted(set(f["tool"] for f in findings))

    sev_opts  = '<option value="">All severities</option>' + "".join(f'<option value="{e(s)}">{e(s)}</option>' for s in severities)
    cat_opts  = '<option value="">All categories</option>' + "".join(f'<option value="{e(c)}">{e(c)}</option>' for c in categories)
    tool_opts = '<option value="">All tools</option>' + "".join(f'<option value="{e(t)}">{e(t)}</option>' for t in all_tools_list)

    rows_html = ""
    for f in findings:
        loc = _location(f)
        fix_raw = f.get("fix") or ""
        fix_short = e(fix_raw[:72] + ("…" if len(fix_raw) > 72 else ""))
        search_text = e(" ".join(filter(None, [
            f.get("title", ""), f.get("file", ""), f.get("package", ""),
            f.get("endpoint", ""), (f.get("description", "") or "")[:100],
            f.get("cve", ""),
        ])).lower())
        rows_html += (
            f'<tr class="finding-row" data-sev="{e(f["severity"])}" '
            f'data-cat="{e(f["category"])}" data-tool="{e(f["tool"])}" data-text="{search_text}">'
            f'<td>{_sev_badge(f["severity"])}</td>'
            f'<td>{_cat_badge(f["category"])}</td>'
            f'<td style="font-size:12px;color:#374151">{_tool_label(f)}</td>'
            f'<td style="font-size:13px;font-weight:500">{e(f.get("title",""))}</td>'
            f'<td style="font-size:12px;color:#6b7280;font-family:monospace">{loc}</td>'
            f'<td style="font-size:12px;color:#374151">{fix_short}</td>'
            f'<td class="expand-arrow" style="text-align:center;font-size:16px;'
            f'color:#9ca3af;user-select:none;width:28px">&#8250;</td></tr>\n'
            f'<tr class="detail-row" style="display:none"><td colspan="7">'
            f'<div class="detail-panel">{_detail_panel(f)}</div></td></tr>\n'
        )

    if not findings:
        rows_html = '<tr><td colspan="7" class="empty-msg">No findings detected.</td></tr>'

    reco_rows = ""
    if critical:
        reco_rows += f'<tr><td>{_sev_badge("CRITICAL")}</td><td>Address {len(critical)} critical finding(s) immediately — do not deploy until resolved</td></tr>'
    if high:
        reco_rows += f'<tr><td>{_sev_badge("HIGH")}</td><td>Remediate {len(high)} high severity finding(s) within 7 days</td></tr>'
    if medium:
        reco_rows += f'<tr><td>{_sev_badge("MEDIUM")}</td><td>Schedule remediation of {len(medium)} medium finding(s) within 30 days</td></tr>'
    reco_rows += ('<tr><td><span class="badge-ok">ACTION</span></td>'
                  '<td>Store this report as audit evidence for SOC 2 CC6.6 / ISO 27001 A.12.6.1</td></tr>')
    reco_rows += ('<tr><td><span class="badge-ok">ACTION</span></td>'
                  '<td>Run <code>./securepipe scan</code> on every pull request</td></tr>')

    compliance_rows = _compliance_rows(findings)

    # Assemble — static CSS/JS kept as plain strings to avoid brace-escaping issues
    return (
        _HTML_HEAD
        + f'<div class="header"><h1>SecurePipe Security Report</h1>'
          f'<p>Generated: {e(generated_at)} &nbsp;|&nbsp; Total findings: {len(findings)}</p></div>\n'
        + '<div class="content">\n'
        + f'<div class="stats">'
          f'<div class="stat critical"><div class="num">{len(critical)}</div><div class="label">Critical</div></div>'
          f'<div class="stat high"><div class="num">{len(high)}</div><div class="label">High</div></div>'
          f'<div class="stat medium"><div class="num">{len(medium)}</div><div class="label">Medium</div></div>'
          f'<div class="stat low"><div class="num">{len(low)}</div><div class="label">Low / Info</div></div>'
          f'</div>\n'
        + f'<div class="card"><h2>Tool Summary</h2>{tool_summary}</div>\n'
        + f'<div class="card"><h2>Findings</h2>'
          f'<div class="filters">'
          f'<select id="f-sev">{sev_opts}</select>'
          f'<select id="f-cat">{cat_opts}</select>'
          f'<select id="f-tool">{tool_opts}</select>'
          f'<input id="f-q" type="search" placeholder="Search findings…">'
          f'<span id="visible-count">{len(findings)} finding{"s" if len(findings) != 1 else ""}</span>'
          f'</div>'
          f'<table><thead><tr>'
          f'<th>Severity</th><th>Category</th><th>Tool</th>'
          f'<th>Finding</th><th>Package / Path</th><th>Fix Summary</th><th></th>'
          f'</tr></thead><tbody id="findings-tbody">'
          f'{rows_html}'
          f'</tbody></table></div>\n'
        + f'<div class="card"><h2>Recommendations</h2>'
          f'<table><thead><tr><th>Priority</th><th>Action</th></tr></thead>'
          f'<tbody>{reco_rows}</tbody></table></div>\n'
        + f'<div class="card"><h2>Compliance Mapping</h2>'
          f'<table><thead><tr><th>Control</th><th>Tools</th><th>Scope</th><th>Status</th></tr></thead>'
          f'<tbody>{compliance_rows}</tbody></table>'
          f'<p style="margin-top:16px;font-size:13px;color:#6b7280">'
          f'<strong>Audit use:</strong> This report is timestamped and self-contained. '
          f'Attach it to your SOC 2 evidence collection or ISO 27001 Statement of Applicability review. '
          f'Raw tool outputs are in <code>reports/raw/</code> for auditor inspection.</p></div>\n'
        + '</div>\n'
        + '<div class="footer">SecurePipe &mdash; open source DevSecOps pipeline &mdash; github.com/ismailarici/securepipe</div>\n'
        + _HTML_TAIL
    )


_HTML_HEAD = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SecurePipe Security Report</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f9fafb; color: #111827; }
  .header { background: #111827; color: #fff; padding: 32px 48px; }
  .header h1 { font-size: 24px; font-weight: 700; margin-bottom: 4px; }
  .header p { font-size: 14px; color: #9ca3af; }
  .content { max-width: 1280px; margin: 32px auto; padding: 0 24px; }
  .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }
  .stat { background: #fff; border: 1px solid #e5e7eb; border-radius: 8px; padding: 20px; text-align: center; }
  .stat .num { font-size: 36px; font-weight: 700; }
  .stat .label { font-size: 13px; color: #6b7280; margin-top: 4px; }
  .critical .num { color: #dc2626; }
  .high .num { color: #ea580c; }
  .medium .num { color: #ca8a04; }
  .low .num { color: #2563eb; }
  .card { background: #fff; border: 1px solid #e5e7eb; border-radius: 8px; padding: 24px; margin-bottom: 24px; }
  .card h2 { font-size: 16px; font-weight: 600; margin-bottom: 16px; color: #374151; border-bottom: 1px solid #f3f4f6; padding-bottom: 12px; }
  .tool-pill { display: inline-block; margin: 4px 8px 4px 0; padding: 4px 12px; background: #f3f4f6; border-radius: 6px; font-size: 13px; }
  .filters { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; margin-bottom: 16px; }
  .filters select { padding: 7px 10px; border: 1px solid #d1d5db; border-radius: 6px; font-size: 13px; background: #fff; cursor: pointer; }
  .filters input { padding: 7px 10px; border: 1px solid #d1d5db; border-radius: 6px; font-size: 13px; flex: 1; min-width: 180px; }
  #visible-count { font-size: 13px; color: #6b7280; margin-left: auto; white-space: nowrap; padding-left: 8px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; padding: 10px 12px; background: #f9fafb; border-bottom: 2px solid #e5e7eb; font-weight: 600; color: #374151; white-space: nowrap; }
  td { padding: 10px 12px; border-bottom: 1px solid #f3f4f6; vertical-align: top; }
  tr.finding-row { cursor: pointer; }
  tr.finding-row:hover td { background: #f0f9ff; }
  tr.finding-row.active td { background: #eff6ff; }
  .detail-row > td { padding: 0; border-bottom: 2px solid #3b82f6; }
  .detail-panel { background: #f8fafc; border-left: 3px solid #3b82f6; padding: 16px 20px 16px 24px; }
  .dl { display: flex; gap: 12px; margin-bottom: 10px; font-size: 13px; }
  .dl:last-child { margin-bottom: 0; }
  .dt { min-width: 120px; font-weight: 600; color: #374151; flex-shrink: 0; padding-top: 1px; }
  .dd { color: #1f2937; line-height: 1.55; word-break: break-word; }
  .fix-text { color: #065f46; font-weight: 500; background: #f0fdf4; padding: 6px 10px; border-radius: 4px; }
  pre.snippet { background: #1e1e1e; color: #d4d4d4; padding: 10px 14px; border-radius: 6px; font-size: 12px; overflow-x: auto; white-space: pre; margin-top: 4px; }
  .ref-links a { color: #2563eb; font-size: 12px; display: block; word-break: break-all; text-decoration: none; }
  .ref-links a:hover { text-decoration: underline; }
  .badge-ok { background: #16a34a; color: #fff; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }
  .empty-msg { color: #6b7280; font-size: 13px; padding: 24px; text-align: center; }
  .footer { text-align: center; padding: 24px; font-size: 12px; color: #9ca3af; }
  @media (max-width: 768px) { .stats { grid-template-columns: repeat(2, 1fr); } .header { padding: 24px; } }
</style>
</head>
<body>
"""

_HTML_TAIL = """
<script>
(function () {
  var rows = document.querySelectorAll('tr.finding-row');

  rows.forEach(function (row) {
    row.addEventListener('click', function () {
      var detail = row.nextElementSibling;
      if (detail && detail.classList.contains('detail-row')) {
        var open = detail.style.display !== 'none';
        detail.style.display = open ? 'none' : 'table-row';
        row.classList.toggle('active', !open);
        var arrow = row.querySelector('.expand-arrow');
        if (arrow) arrow.innerHTML = open ? '&#8250;' : '&#8964;';
      }
    });
  });

  function countVisible() {
    var n = 0;
    document.querySelectorAll('tr.finding-row').forEach(function (r) {
      if (r.style.display !== 'none') n++;
    });
    var el = document.getElementById('visible-count');
    if (el) el.textContent = n + ' finding' + (n !== 1 ? 's' : '');
  }

  function applyFilters() {
    var sev  = document.getElementById('f-sev').value;
    var cat  = document.getElementById('f-cat').value;
    var tool = document.getElementById('f-tool').value;
    var q    = document.getElementById('f-q').value.toLowerCase();

    document.querySelectorAll('tr.finding-row').forEach(function (row) {
      var detail = row.nextElementSibling;
      var match = (!sev  || row.dataset.sev  === sev)  &&
                  (!cat  || row.dataset.cat  === cat)  &&
                  (!tool || row.dataset.tool === tool) &&
                  (!q    || row.dataset.text.indexOf(q) !== -1);
      row.style.display = match ? '' : 'none';
      if (detail && detail.classList.contains('detail-row')) {
        detail.style.display = 'none';
        row.classList.remove('active');
        var arrow = row.querySelector('.expand-arrow');
        if (arrow) arrow.innerHTML = '&#8250;';
      }
    });
    countVisible();
  }

  ['f-sev', 'f-cat', 'f-tool', 'f-q'].forEach(function (id) {
    var el = document.getElementById(id);
    if (el) el.addEventListener('input', applyFilters);
  });
}());
</script>
</body>
</html>
"""


def main():
    parser = argparse.ArgumentParser(description="Generate HTML security report from raw scan JSON.")
    parser.add_argument("--raw-dir", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    findings = normalize.load_findings(args.raw_dir)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    html_out = build_html(findings, generated_at)

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w") as f:
        f.write(html_out)
    print(f"Report written: {args.output} ({len(findings)} total findings)")


if __name__ == "__main__":
    main()
