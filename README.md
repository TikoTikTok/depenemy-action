# depenemy Supply Chain Scanner

> **GitHub Action** · Scans npm dependencies for supply chain attacks using the [depenemy](https://github.com/TikoTikTok/depenemy) engine.

[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-depenemy-blue?logo=github)](https://github.com/marketplace/actions/depenemy-supply-chain-scanner)

---

## What it checks

| Rule | Severity | Description |
|------|----------|-------------|
| **B001** | warning | Unsafe SemVer specifier (`^`, `~`, `*`, `latest`) in `package.json` |
| **B002** | error | Completely unpinned version (wildcard `*` / `latest` in lockfile) |
| **B005** | error | Lockfile integrity hash mismatch (tampered package) |
| **B006** | error | Package resolved from a non-approved registry |
| **B007** | error | Lockfile injection via non-registry protocol (`file:`, `git+`, `http:`) |
| **R007** | error | Known CVE in the resolved version (via OSV) |
| **R009** | warning | Suspected typosquatting (edit-distance ≤ 1 from popular packages) |
| **R010** | error | Version published very recently (active attack window) |
| **S001** | error | Package has `preinstall`/`postinstall` scripts (arbitrary code on install) |
| **S004** | warning | Dependency confusion risk (internal-looking scope on public registry) |
| **S005** | error | Package flagged as malicious in OSV or public advisories |
| **S007** | warning | Ghost repository (claimed source repo has no real activity) |
| **S008** | warning | Publisher bulk-published many packages in a short window |
| **S009** | warning | Publisher npm identity has no matching GitHub account |
| **C001** | error | Composite score: 4+ independent risk signals → confirmed attacker pattern |

All findings are emitted as **SARIF** and appear in the GitHub **Security → Code Scanning** tab.

---

## Quick start

```yaml
# .github/workflows/supply-chain.yml
name: Supply Chain Security
on:
  pull_request:
    paths: ["package.json", "package-lock.json"]
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  depenemy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run depenemy
        id: scan
        uses: TikoTikTok/depenemy-action@v1
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.scan.outputs.sarif-file }}
          category: depenemy
```

---

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `approved-registries` | No | `registry.npmjs.org` | Comma-separated list of approved registry hostnames. Packages resolved from any other host are **blocked** (B006). |
| `fail-on` | No | `error` | Minimum severity that fails the job: `error` \| `warning` \| `info` \| `never` |
| `paths` | No | `.` | Space-separated paths to scan |
| `config` | No | — | Path to a `.depenemy.yml` file (overrides `approved-registries`) |
| `token` | No | `${{ github.token }}` | GitHub token for author/publisher reputation lookups |
| `no-fail` | No | `false` | **Deprecated** — use `fail-on: never` instead |

## Outputs

| Output | Description |
|--------|-------------|
| `findings-count` | Total findings across all severity levels |
| `errors-count` | Error-severity findings (the ones that block) |
| `sarif-file` | Absolute path to `depenemy.sarif` in the workspace |

---

## Advanced: private registries

```yaml
- uses: TikoTikTok/depenemy-action@v1
  with:
    approved-registries: "registry.npmjs.org,npm.mycompany.internal"
    fail-on: error
```

## Advanced: custom rule config

Create `.depenemy.yml` in your repository root:

```yaml
approved_registries:
  - registry.npmjs.org
  - npm.mycompany.internal

rules:
  B001: warning   # range specifier is warning (not error)
  B006: error     # bad registry always blocks
  S005: error     # known malicious always blocks

thresholds:
  min_author_account_age_days: 180
  composite_score_threshold: 3   # tighten composite score
```

Then reference it in the action:

```yaml
- uses: TikoTikTok/depenemy-action@v1
  with:
    config: .depenemy.yml
```

## Report-only mode (never block PRs)

```yaml
- uses: TikoTikTok/depenemy-action@v1
  with:
    fail-on: never   # findings still appear in Code Scanning, job always passes
```

---

## Architecture

This action is a **thin Docker wrapper** around the [depenemy](https://github.com/TikoTikTok/depenemy) Python engine:

```
depenemy-action (Docker)
  └── entrypoint.sh
        ├── gen-config.py  →  generates .depenemy-action.yml from inputs
        └── depenemy scan  →  parses manifests, fetches metadata, runs rules
              ├── NpmParser  (reads package.json + package-lock.json)
              ├── B001–B007  (behavioral rules)
              ├── R001–R010  (reputation rules)
              ├── S001–S009  (supply chain rules)
              └── SARIF reporter  (writes depenemy.sarif)
```

The Docker image installs depenemy from the fork at build time, ensuring full rule coverage including supply chain checks not yet merged upstream.

---

## Contributing / PR to upstream

The supply chain rules in this action (B006, B007, S004–S009, C001) are implemented in
[TikoTikTok/depenemy](https://github.com/TikoTikTok/depenemy) and are candidates for
upstream contribution. See the fork's `CONTRIBUTING.md` for details on how to propose rules.

## License

MIT
