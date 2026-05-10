#!/usr/bin/env python3
"""
lockfile-diff.py — Extract NEW_PACKAGES from package-lock.json diff and check
install script flags (B-3, A-15) and scope/registry/injection signals (B-5, B-8, B-10).

Workflow:
  1. git diff origin/<BASE> -- package-lock.json to find added packages
  2. For each NEW_PACKAGE: check hasInstallScript, resolved URL, _integrity
  3. Emit BLOCK for B-3 (new dep + install script), B-5 (scope confusion),
     B-8 (bad registry), B-10 (lockfile injection)
  4. Emit ALERT for A-15 (existing dep gained install script)

Exit code:
  0 — no BLOCK findings (ALERTs allowed)
  1 — at least one BLOCK finding

Usage:
    python lockfile-diff.py [--base origin/main] [--lockfile package-lock.json]
                            [--scopes internal-scopes.json]
                            [--registries approved-registries.json]
                            [--output-json findings.json]
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

DEFAULT_APPROVED_REGISTRIES = ["registry.npmjs.org"]


def run_git_diff(base: str, lockfile: str) -> str:
    try:
        result = subprocess.run(
            ["git", "diff", f"origin/{base}", "--", lockfile],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout
    except subprocess.CalledProcessError as exc:
        print(f"[lockfile-diff] git diff failed: {exc.stderr}", file=sys.stderr)
        return ""


def parse_new_packages_from_diff(diff_text: str) -> set[str]:
    """Parse added package entries from a unified diff of package-lock.json."""
    new_packages: set[str] = set()
    current_pkg: str | None = None
    in_added_block = False

    for line in diff_text.splitlines():
        if line.startswith("+") and '"node_modules/' in line:
            pkg_name = line.split('"node_modules/')[1].split('"')[0]
            current_pkg = pkg_name
            in_added_block = True
        elif line.startswith("-") and '"node_modules/' in line:
            in_added_block = False
            current_pkg = None

        # A newly added resolved line confirms the package is truly new
        if in_added_block and line.startswith('+') and '"version"' in line:
            if current_pkg:
                new_packages.add(current_pkg)

    return new_packages


def read_lockfile(lockfile_path: Path) -> dict:
    try:
        return json.loads(lockfile_path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        print(f"[lockfile-diff] ERROR reading {lockfile_path}: {exc}", file=sys.stderr)
        return {}


def get_workspace_packages(manifest_path: Path) -> set[str]:
    """Read workspaces list from package.json for allowlisting file: protocols."""
    try:
        data = json.loads(manifest_path.read_text())
        workspaces = data.get("workspaces", [])
        if isinstance(workspaces, dict):
            workspaces = workspaces.get("packages", [])
        return set(workspaces)
    except (json.JSONDecodeError, OSError):
        return set()


def check_packages(
    lockfile_data: dict,
    new_packages: set[str],
    approved_registries: list[str],
    internal_scopes: list[str],
    workspaces: set[str],
) -> list[dict]:
    findings = []
    packages = lockfile_data.get("packages", {})
    # Also check all packages for registry/injection issues (not just new ones)
    all_pkg_entries = {
        k.removeprefix("node_modules/"): v
        for k, v in packages.items()
        if k.startswith("node_modules/") and isinstance(v, dict)
    }

    for name, info in all_pkg_entries.items():
        resolved = info.get("resolved", "")
        integrity = info.get("integrity", "")
        has_install_script = info.get("hasInstallScript", False)
        is_new = name in new_packages

        # B-8 Bad Registry — all packages
        if resolved:
            try:
                host = urlparse(resolved).netloc
                if host and not any(
                    host == r or host.endswith("." + r) for r in approved_registries
                ):
                    findings.append({
                        "verdict": "BLOCK",
                        "rule": "B-8",
                        "check": "BadRegistry",
                        "package": name,
                        "resolved": resolved,
                        "reason": f"Resolved from `{host}` which is not in approved-registries.json",
                        "data_source": "package-lock.json resolved field",
                    })
            except Exception:
                pass

        # B-10 LockfileInjection — all prod packages not in workspaces
        if resolved and name not in workspaces:
            # 1. Suspicious protocols
            for proto in ("file:", "git+", "git:", "github:"):
                if resolved.startswith(proto):
                    findings.append({
                        "verdict": "BLOCK",
                        "rule": "B-10",
                        "check": "LockfileInjection",
                        "package": name,
                        "resolved": resolved,
                        "reason": (
                            f"Non-registry protocol `{proto}` on a production dep. "
                            "Add to `workspaces` if this is intentional."
                        ),
                        "data_source": "package-lock.json resolved field",
                    })
                    break
            else:
                # 2. Package name NOT in resolved URL path — tarball swapped to different pkg
                try:
                    path = urlparse(resolved).path.lower().replace("%2f", "/")
                    expected = name.lower().lstrip("@")
                    if resolved and expected not in path:
                        findings.append({
                            "verdict": "BLOCK",
                            "rule": "B-10",
                            "check": "LockfileInjection",
                            "package": name,
                            "resolved": resolved,
                            "reason": (
                                f"Resolved URL `{resolved[:80]}` does not contain "
                                f"the package name `{name}` in its path. "
                                "Tarball may have been swapped to point at a different package."
                            ),
                            "data_source": "package-lock.json resolved field",
                        })
                except Exception:
                    pass

        # B-5 Scope Confusion — all packages with internal scopes
        if name.startswith("@"):
            scope = name.split("/")[0]
            if scope in internal_scopes:
                # Check if resolution is NOT from the org's own registry
                host = urlparse(resolved).netloc if resolved else ""
                if not any(host == r or host.endswith("." + r) for r in approved_registries):
                    findings.append({
                        "verdict": "BLOCK",
                        "rule": "B-5",
                        "check": "ScopeConfusion",
                        "package": name,
                        "resolved": resolved or "(no resolved URL)",
                        "reason": (
                            f"Scope `{scope}` is in internal-scopes.json but package is "
                            "resolved from the public registry, not the org's private registry."
                        ),
                        "data_source": "internal-scopes.json + package-lock.json resolved",
                    })

        if not is_new:
            # A-15 — Existing dep now has hasInstallScript (version bump introduced hook)
            if has_install_script:
                findings.append({
                    "verdict": "ALERT",
                    "rule": "A-15",
                    "check": "NewInstallScript",
                    "package": name,
                    "reason": (
                        "This previously-trusted package now has a `postinstall`/`preinstall` "
                        "script in the updated version. Confirm the hook is intentional."
                    ),
                    "data_source": "package-lock.json hasInstallScript field",
                })
        else:
            # B-3 candidate — NEW dep with install script (depenemy S001 must also confirm)
            if has_install_script:
                findings.append({
                    "verdict": "BLOCK",
                    "rule": "B-3",
                    "check": "InstallScript",
                    "package": name,
                    "reason": (
                        "New dependency has `hasInstallScript: true` in lockfile. "
                        "Runs code automatically on `npm install`. "
                        "Requires depenemy S001 confirmation to finalise BLOCK."
                    ),
                    "data_source": "package-lock.json hasInstallScript field (+ depenemy S001)",
                })

    return findings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="main", help="Base branch (default: main)")
    parser.add_argument("--lockfile", default="package-lock.json")
    parser.add_argument("--manifest", default="package.json")
    parser.add_argument(
        "--registries",
        default=None,
        help="Path to approved-registries.json",
    )
    parser.add_argument("--scopes", default=None, help="Path to internal-scopes.json")
    parser.add_argument("--output-json", metavar="FILE", help="Write findings JSON to file")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument(
        "--no-fail",
        action="store_true",
        help="Always exit 0 even when BLOCK findings are present (report-only mode)",
    )
    args = parser.parse_args()

    lockfile_path = Path(args.lockfile)
    if not lockfile_path.exists():
        print(f"[lockfile-diff] {lockfile_path} not found", file=sys.stderr)
        return 1

    approved_registries: list[str] = DEFAULT_APPROVED_REGISTRIES
    if args.registries and Path(args.registries).exists():
        approved_registries = json.loads(Path(args.registries).read_text())

    internal_scopes: list[str] = []
    if args.scopes and Path(args.scopes).exists():
        internal_scopes = json.loads(Path(args.scopes).read_text())

    workspaces = get_workspace_packages(Path(args.manifest))
    lockfile_data = read_lockfile(lockfile_path)
    diff_text = run_git_diff(args.base, args.lockfile)
    new_packages = parse_new_packages_from_diff(diff_text)

    if not args.quiet:
        print(f"[lockfile-diff] {len(new_packages)} new package(s) detected in this PR")

    findings = check_packages(
        lockfile_data, new_packages, approved_registries, internal_scopes, workspaces
    )

    # Write NEW_PACKAGES to a file for downstream jobs (J2, J3, J4)
    Path("new-packages.json").write_text(json.dumps(sorted(new_packages), indent=2))

    blocks = [f for f in findings if f["verdict"] == "BLOCK"]
    alerts = [f for f in findings if f["verdict"] == "ALERT"]

    if not args.quiet:
        for f in findings:
            icon = "🚫" if f["verdict"] == "BLOCK" else "⚠️"
            print(f"  {icon} [{f['rule']}] {f['package']}: {f['reason']}")
        if not findings:
            print("[lockfile-diff] PASS — no lockfile issues found")

    if args.output_json:
        Path(args.output_json).write_text(json.dumps(findings, indent=2))

    return 0 if args.no_fail else (1 if blocks else 0)


if __name__ == "__main__":
    sys.exit(main())
