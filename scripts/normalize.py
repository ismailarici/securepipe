#!/usr/bin/env python3
"""Normalises raw scanner outputs into a unified Finding schema."""

import hashlib
import json
import re
from pathlib import Path

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5}

_SEMGREP_SEV = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "INFO"}
_ZAP_SEV = {
    "CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM",
    "LOW": "LOW", "INFO": "INFO", "INFORMATIONAL": "INFO",
}

_SAST_FIX = {
    "sql": "Use parameterized queries or an ORM. Never concatenate user input into SQL strings.",
    "sqli": "Use parameterized queries or an ORM. Never concatenate user input into SQL strings.",
    "command": "Avoid shell=True / Runtime.exec with user input. Use an allowlist or subprocess with an argument list.",
    "exec": "Avoid shell=True / Runtime.exec with user input. Use an allowlist or subprocess with an argument list.",
    "injection": "Validate and sanitize all user input before use in system calls.",
    "pickle": "Never deserialize untrusted data with pickle/ObjectInputStream. Use JSON or a safe serialization format.",
    "deserializ": "Never deserialize untrusted data from untrusted sources. Validate class allowlists if necessary.",
    "hardcoded": "Move credentials to environment variables or a secrets manager. Never commit secrets to source control.",
    "secret": "Move credentials to environment variables or a secrets manager. Never commit secrets to source control.",
    "credential": "Move credentials to environment variables or a secrets manager.",
    "password": "Move passwords to environment variables. Use a secrets manager in production.",
    "xss": "Escape all user-supplied output before rendering in HTML. Use a templating engine with auto-escaping.",
    "debug": "Disable debug mode in production environments. Set DEBUG=False or equivalent.",
    "xxe": "Disable external entity processing in XML parsers. Set FEATURE_SECURE_PROCESSING.",
    "ssrf": "Validate and restrict URLs to an allowlist of safe destinations. Block internal network ranges.",
    "traversal": "Validate and normalize file paths to prevent directory traversal attacks.",
    "path": "Validate and normalize file paths. Use realpath and confirm the path is within an allowed base directory.",
}


def _norm_sev(s):
    s = (s or "UNKNOWN").upper().strip()
    return s if s in SEVERITY_ORDER else "UNKNOWN"


def _uid(*parts):
    return hashlib.sha1("|".join(str(p) for p in parts).encode()).hexdigest()[:12]


def _load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {}


def _sast_fix(rule_id):
    rule = rule_id.lower()
    for keyword, hint in _SAST_FIX.items():
        if keyword in rule:
            return hint
    return "Review the flagged code and apply security best practices for this vulnerability class."


# ── SAST ──────────────────────────────────────────────────────────────────────

def parse_semgrep(data):
    findings = []
    for r in data.get("results", []):
        raw_sev = r.get("extra", {}).get("severity", "INFO").upper()
        severity = _SEMGREP_SEV.get(raw_sev, _norm_sev(raw_sev))
        rule_id = r.get("check_id", "unknown")
        file_path = r.get("path", "")
        line = r.get("start", {}).get("line")
        message = (r.get("extra", {}).get("message") or "").strip()
        snippet = (r.get("extra", {}).get("lines") or "").strip()
        refs = (r.get("extra", {}).get("metadata") or {}).get("references", [])
        findings.append({
            "id": _uid("semgrep", rule_id, file_path, str(line)),
            "title": rule_id.split(".")[-1].replace("-", " ").title(),
            "rule_id": rule_id,
            "description": message,
            "severity": severity,
            "category": "SAST",
            "tool": "semgrep",
            "file": file_path,
            "line": line,
            "code_snippet": snippet,
            "fix": _sast_fix(rule_id),
            "references": [r for r in refs if isinstance(r, str)][:3],
        })
    return findings


# ── SCA ───────────────────────────────────────────────────────────────────────

def parse_pip_audit(data):
    findings = []
    for dep in data.get("dependencies", []):
        pkg = dep.get("name", "")
        ver = dep.get("version", "")
        for vuln in dep.get("vulns", []):
            cve = vuln.get("id", "CVE-unknown")
            fix_versions = vuln.get("fix_versions", [])
            fixed = fix_versions[0] if fix_versions else None
            fix_str = (f"Upgrade {pkg} to {fixed}" if fixed
                       else f"Upgrade {pkg} — check PyPI for the latest safe version")
            findings.append({
                "id": _uid("pip-audit", cve, pkg),
                "title": cve,
                "description": (vuln.get("description") or "").strip(),
                "severity": "HIGH",
                "category": "SCA",
                "tool": "pip-audit",
                "file": "requirements.txt",
                "package": pkg,
                "version": ver,
                "fixed_version": fixed,
                "cve": cve,
                "fix": fix_str,
                "references": ([f"https://osv.dev/vulnerability/{cve}"]
                               if (cve.startswith("CVE") or cve.startswith("PYSEC")) else []),
            })
    return findings


def parse_npm_audit(data):
    findings = []
    for name, vuln in data.get("vulnerabilities", {}).items():
        sev = _norm_sev(vuln.get("severity", "UNKNOWN"))
        via = vuln.get("via", [])
        cve = None
        desc = ""
        for v in via:
            if isinstance(v, dict):
                cve = v.get("cve") or v.get("name") or ""
                desc = (v.get("title") or v.get("name") or "").strip()
                break
        dep_path = [v for v in via if isinstance(v, str)]
        fix_available = vuln.get("fixAvailable")
        if isinstance(fix_available, dict):
            fn = fix_available.get("name", name)
            fv = fix_available.get("version", "")
            fix_str = f"Run `npm install {fn}@{fv}` or `npm audit fix --force`"
        elif fix_available is True:
            fix_str = "Run `npm audit fix` to apply available patches"
        else:
            fix_str = "No automatic fix available — review manually or pin to a safe version"
        findings.append({
            "id": _uid("npm-audit", name, vuln.get("range", "")),
            "title": vuln.get("title") or name,
            "description": desc or vuln.get("title") or "",
            "severity": sev,
            "category": "SCA",
            "tool": "npm-audit",
            "file": "package.json",
            "package": name,
            "version": vuln.get("range", ""),
            "cve": cve,
            "dependency_path": dep_path,
            "fix": fix_str,
            "references": ([f"https://osv.dev/vulnerability/{cve}"]
                           if cve and cve.startswith("CVE") else []),
        })
    return findings


def parse_dependency_check(data):
    findings = []
    for dep in data.get("dependencies", []):
        file_name = dep.get("fileName", "")
        for vuln in dep.get("vulnerabilities", []):
            sev = _norm_sev(vuln.get("severity", "UNKNOWN"))
            cve = vuln.get("name", "CVE-unknown")
            desc = (vuln.get("description") or "")[:400].strip()
            pkg_name = file_name.split("/")[-1].split("\\")[-1]
            findings.append({
                "id": _uid("owasp-dc", cve, file_name),
                "title": cve,
                "description": desc,
                "severity": sev,
                "category": "SCA",
                "tool": "owasp-dc",
                "file": file_name,
                "package": pkg_name,
                "cve": cve,
                "fix": (f"Upgrade the library file {pkg_name} to a patched version. "
                        f"Check the vendor advisory for {cve}."),
                "references": ([f"https://nvd.nist.gov/vuln/detail/{cve}"]
                               if cve.startswith("CVE") else []),
            })
    return findings


# ── Container ─────────────────────────────────────────────────────────────────

def parse_trivy(data):
    findings = []
    for result in data.get("Results", []):
        target = result.get("Target", "")
        result_type = result.get("Type", "")
        for vuln in result.get("Vulnerabilities") or []:
            cve = vuln.get("VulnerabilityID", "")
            pkg = vuln.get("PkgName", "")
            installed = vuln.get("InstalledVersion", "")
            fixed = vuln.get("FixedVersion", "") or None
            sev = _norm_sev(vuln.get("Severity", "UNKNOWN"))
            desc = (vuln.get("Description") or vuln.get("Title") or "")[:400].strip()
            refs = [r for r in vuln.get("References", [])
                    if "cve.mitre" in r or "nvd.nist" in r or "github.com/advisories" in r][:2]
            fix_str = (f"Upgrade {pkg} to {fixed}" if fixed
                       else f"No fix released yet for {pkg}@{installed} — monitor the upstream advisory")
            findings.append({
                "id": _uid("trivy", cve, pkg, installed),
                "title": cve or pkg,
                "description": desc,
                "severity": sev,
                "category": "CONTAINER",
                "tool": "trivy",
                "package": pkg,
                "version": installed,
                "fixed_version": fixed,
                "cve": cve,
                "container_target": target,
                "container_type": result_type,
                "fix": fix_str,
                "references": refs,
            })
    return findings


# ── DAST ──────────────────────────────────────────────────────────────────────

def parse_zap(data):
    findings = []
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            risk_word = alert.get("riskdesc", "").split(" ")[0].upper()
            sev = _ZAP_SEV.get(risk_word, _norm_sev(risk_word))
            solution = (alert.get("solution") or "").strip()
            cwe = alert.get("cweid", "")
            refs = []
            if cwe:
                refs.append(f"https://cwe.mitre.org/data/definitions/{cwe}.html")
            for url in re.findall(r'https?://\S+', alert.get("reference", "")):
                refs.append(url.rstrip(">,.)"))
            findings.append({
                "id": _uid("zap", alert.get("alert", ""), alert.get("uri", "")),
                "title": alert.get("alert", ""),
                "description": (alert.get("desc") or "").strip(),
                "severity": sev,
                "category": "DAST",
                "tool": "zap",
                "endpoint": alert.get("uri", ""),
                "method": (alert.get("method") or "").upper(),
                "parameter": alert.get("param", ""),
                "evidence": (alert.get("evidence") or "")[:200],
                "fix": solution or "Apply the recommended fix from the ZAP alert documentation.",
                "references": refs[:3],
            })
    return findings


# ── Deduplication ─────────────────────────────────────────────────────────────

def deduplicate(findings):
    """Merge findings with the same CVE + package detected by multiple tools."""
    seen = {}
    result = []
    for f in findings:
        cve = f.get("cve")
        pkg = f.get("package")
        if cve and cve not in ("CVE-unknown", "") and pkg:
            key = f"{cve}|{pkg}"
            if key in seen:
                existing = seen[key]
                sources = existing.get("sources", [existing["tool"]])
                if f["tool"] not in sources:
                    sources.append(f["tool"])
                existing["sources"] = sources
                if SEVERITY_ORDER.get(f["severity"], 5) < SEVERITY_ORDER.get(existing["severity"], 5):
                    existing["severity"] = f["severity"]
                if not existing.get("fixed_version") and f.get("fixed_version"):
                    existing["fixed_version"] = f["fixed_version"]
                    existing["fix"] = f["fix"]
                continue
            f = dict(f)
            f["sources"] = [f["tool"]]
            seen[key] = f
        result.append(f)
    return result


# ── Public loader ─────────────────────────────────────────────────────────────

def load_findings(raw_dir):
    """Load and normalize all scan results from a raw output directory."""
    raw_dir = Path(raw_dir)
    findings = []

    if (raw_dir / "semgrep.json").exists():
        findings += parse_semgrep(_load_json(raw_dir / "semgrep.json"))

    if (raw_dir / "sca.json").exists():
        sca = _load_json(raw_dir / "sca.json")
        deps = sca.get("dependencies", [])
        if deps and "vulns" in (deps[0] if deps else {}):
            findings += parse_pip_audit(sca)
        elif deps and "vulnerabilities" in (deps[0] if deps else {}):
            findings += parse_dependency_check(sca)
        elif "vulnerabilities" in sca:
            findings += parse_npm_audit(sca)

    if (raw_dir / "trivy.json").exists():
        findings += parse_trivy(_load_json(raw_dir / "trivy.json"))

    if (raw_dir / "zap.json").exists():
        findings += parse_zap(_load_json(raw_dir / "zap.json"))

    return deduplicate(findings)
