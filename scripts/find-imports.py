#!/usr/bin/env python3
"""Scans source files for package import statements and writes imports.json."""

import argparse
import json
import re
from pathlib import Path

# Packages whose import name differs from their PyPI name
_PY_ALIASES = {
    "pillow": ["pil", "image"],
    "pyyaml": ["yaml"],
    "scikit-learn": ["sklearn"],
    "beautifulsoup4": ["bs4"],
    "opencv-python": ["cv2"],
    "python-dateutil": ["dateutil"],
    "typing-extensions": ["typing_extensions"],
    "markupsafe": ["markupsafe"],
}

# Java: map common artifact names to their import package prefix
_JAVA_JAR_TO_IMPORT = {
    "log4j":          "org.apache.logging.log4j",
    "jackson":        "com.fasterxml.jackson",
    "spring":         "org.springframework",
    "hibernate":      "org.hibernate",
    "guava":          "com.google.common",
    "commons-lang":   "org.apache.commons.lang",
    "commons-io":     "org.apache.commons.io",
    "junit":          "org.junit",
    "slf4j":          "org.slf4j",
    "logback":        "ch.qos.logback",
    "netty":          "io.netty",
    "tomcat":         "org.apache.catalina",
    "httpclient":     "org.apache.http",
    "okhttp":         "okhttp3",
    "gson":           "com.google.gson",
    "snakeyaml":      "org.yaml.snakeyaml",
    "xstream":        "com.thoughtworks.xstream",
}

_SKIP_DIRS = {"node_modules", ".venv", "venv", ".git", "__pycache__", ".next", "build", "dist", "target"}

MAX_PER_PKG = 6


def _should_skip(path):
    return any(part in _SKIP_DIRS for part in path.parts)


def _rel(path, base):
    try:
        return str(path.relative_to(base))
    except ValueError:
        return str(path)


def scan_python(source_dir):
    results = {}
    pat = re.compile(r'^\s*(?:import|from)\s+([\w][\w.]*)', re.MULTILINE)
    for f in Path(source_dir).rglob("*.py"):
        if _should_skip(f.relative_to(source_dir)):
            continue
        try:
            content = f.read_text(errors="replace")
        except Exception:
            continue
        rel = _rel(f, source_dir)
        for m in pat.finditer(content):
            top = m.group(1).split(".")[0].lower()
            line = content[: m.start()].count("\n") + 1
            results.setdefault(top, []).append({"file": rel, "line": line})
    # Apply aliases: map canonical PyPI name → import name
    for pkg, aliases in _PY_ALIASES.items():
        for alias in aliases:
            if alias in results and pkg not in results:
                results[pkg] = results[alias]
    return results


def scan_node(source_dir):
    results = {}
    pat = re.compile(r'(?:require\s*\(\s*[\'"]|from\s+[\'"])([@\w][\w./\-@]*)[\'"]')
    for ext in ("*.js", "*.ts", "*.jsx", "*.tsx", "*.mjs", "*.cjs"):
        for f in Path(source_dir).rglob(ext):
            if _should_skip(f.relative_to(source_dir)):
                continue
            try:
                content = f.read_text(errors="replace")
            except Exception:
                continue
            rel = _rel(f, source_dir)
            for m in pat.finditer(content):
                pkg = m.group(1)
                if pkg.startswith("@"):
                    pkg = "/".join(pkg.split("/")[:2])
                else:
                    pkg = pkg.split("/")[0]
                if pkg.startswith(".") or not pkg:
                    continue
                line = content[: m.start()].count("\n") + 1
                results.setdefault(pkg.lower(), []).append({"file": rel, "line": line})
    return results


def scan_java(source_dir):
    """Map jar artifact names to the Java source files that import them."""
    # First, collect all import statements from Java source files
    import_pat = re.compile(r'^\s*import\s+([\w.]+);', re.MULTILINE)
    all_imports = {}  # prefix → [{file, line}]
    for f in Path(source_dir).rglob("*.java"):
        if _should_skip(f.relative_to(source_dir)):
            continue
        try:
            content = f.read_text(errors="replace")
        except Exception:
            continue
        rel = _rel(f, source_dir)
        for m in import_pat.finditer(content):
            pkg = m.group(1).lower()
            line = content[: m.start()].count("\n") + 1
            all_imports.setdefault(pkg, []).append({"file": rel, "line": line})

    # Build result keyed by artifact name
    results = {}
    for artifact, import_prefix in _JAVA_JAR_TO_IMPORT.items():
        prefix_lower = import_prefix.lower()
        matches = []
        for imp_key, locs in all_imports.items():
            if imp_key.startswith(prefix_lower):
                matches.extend(locs)
        if matches:
            results[artifact.lower()] = matches[:MAX_PER_PKG]
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-dir", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    source = Path(args.source_dir)
    results = {}
    results.update(scan_python(source))
    results.update(scan_node(source))
    results.update(scan_java(source))

    # Cap entries per package
    results = {k: v[:MAX_PER_PKG] for k, v in results.items()}

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(results, f)
    print(f"Imports map: {args.output} ({len(results)} packages)")


if __name__ == "__main__":
    main()
