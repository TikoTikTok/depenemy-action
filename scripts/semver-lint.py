#!/usr/bin/env python3
"""
semver-lint.py — Scan package.json for unsafe SemVer specifiers (A-1).

Reads package.json from CWD (or path provided as $1).
Outputs ALERT findings for every dep using ^, ~, *, or latest.
Exits 0 always (ALERT, not BLOCK — see Plan.md §Blocking Philosophy).

Usage:
    python semver-lint.py [package.json]
    python semver-lint.py package.json --output-json findings.json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

UNSAFE_PATTERN = re.compile(r"[\^~*]|^latest$|^$")

DEP_SECTIONS = [
    "dependencies",
    "devDependencies",
    "peerDependencies",
    "optionalDependencies",
]


def lint(manifest_path: Path) -> list[dict]:
    findings = []
    try:
        data = json.loads(manifest_path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        print(f"[semver-lint] ERROR reading {manifest_path}: {exc}", file=sys.stderr)
        return findings

    for section in DEP_SECTIONS:
        deps = data.get(section, {})
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            if not isinstance(spec, str):
                continue
            if spec.startswith("workspace:") or spec.startswith("file:"):
                continue  # monorepo refs — not a registry range
            if UNSAFE_PATTERN.search(spec.strip()):
                findings.append(
                    {
                        "verdict": "ALERT",
                        "rule": "A-1",
                        "check": "SemVer",
                        "package": name,
                        "spec": spec,
                        "section": section,
                        "reason": (
                            f"`{spec}` is a range specifier. "
                            "`npm ci` installs the lockfile-pinned version regardless, "
                            "but `npm install` would resolve to the latest matching version."
                        ),
                        "data_source": str(manifest_path),
                    }
                )
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan package.json for unsafe SemVer specifiers")
    parser.add_argument("manifest", nargs="?", default="package.json")
    parser.add_argument("--output-json", metavar="FILE", help="Write findings JSON to file")
    parser.add_argument("--quiet", action="store_true", help="Suppress stdout output")
    args = parser.parse_args()

    manifest = Path(args.manifest)
    if not manifest.exists():
        print(f"[semver-lint] {manifest} not found", file=sys.stderr)
        return 1

    findings = lint(manifest)

    if not args.quiet:
        if findings:
            print(f"[A-1 SemVer] {len(findings)} unsafe specifier(s) found:")
            for f in findings:
                print(f"  ALERT  {f['package']:<40}  {f['spec']:<16}  ({f['section']})")
        else:
            print("[A-1 SemVer] PASS — all dependencies use exact pins")

    if args.output_json:
        Path(args.output_json).write_text(json.dumps(findings, indent=2))

    return 0  # always 0 — ALERT tier never blocks


if __name__ == "__main__":
    sys.exit(main())
