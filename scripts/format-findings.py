#!/usr/bin/env python3
"""Format lockfile-diff.py JSON findings for GitHub Step Summary."""
import json
import sys

findings_path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/lockfile-findings.json"
try:
    findings = json.load(open(findings_path))
except (FileNotFoundError, json.JSONDecodeError):
    findings = []

blocks = [f for f in findings if f.get("verdict") == "BLOCK"]
alerts = [f for f in findings if f.get("verdict") == "ALERT"]

if blocks:
    print("## :no_entry: BLOCK — This PR should NOT be merged")
    print()
    print("| Rule | Package | Reason | Data Source |")
    print("|------|---------|--------|-------------|")
    for f in blocks:
        print(f"| `{f['rule']}` | `{f['package']}` | {f['reason']} | {f.get('data_source', '')} |")
    print()

if alerts:
    print("## :warning: ALERT — Review recommended")
    print()
    print("| Rule | Package | Reason | Data Source |")
    print("|------|---------|--------|-------------|")
    for f in alerts:
        print(f"| `{f['rule']}` | `{f['package']}` | {f['reason']} | {f.get('data_source', '')} |")
    print()

if not blocks and not alerts:
    print("## :white_check_mark: PASS — No supply chain issues detected")
