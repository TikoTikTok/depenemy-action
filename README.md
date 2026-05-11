# depenemy-action

GitHub Action for [depenemy](https://github.com/W3OSC/depenemy) — scans your dependencies for supply chain risks, behavioral issues, and reputation red flags.

Results appear automatically in your **Security → Code Scanning** tab on every push and pull request.

---

## Usage

Create `.github/workflows/supply-chain.yml` in your repository:

```yaml
name: Supply Chain Security
on:
  pull_request:
    paths: ["package.json", "package-lock.json", "**/package.json"]
  push:
    branches: [main, master]

permissions:
  contents: read
  security-events: write

jobs:
  depenemy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run depenemy
        id: scan
        uses: W3OSC/depenemy-action@v1
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
          fail-on: error
          approved-registries: "registry.npmjs.org"

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.scan.outputs.sarif-file }}
          category: depenemy
```

---

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `token` | GitHub token for author and contributor lookups (unlocks R001, R006) | No | `${{ github.token }}` |
| `paths` | Space-separated paths to scan | No | `.` |
| `fail-on` | Minimum severity to fail the action (`error`, `warning`, `info`, `never`) | No | `error` |
| `output-sarif` | Path to write SARIF output file | No | `depenemy.sarif` |
| `config` | Path to `.depenemy.yml` config file (overrides `approved-registries`) | No | — |
| `ecosystems` | Comma-separated ecosystems to scan (`npm,pypi,cargo`) | No | auto-detect |
| `upload-sarif` | Automatically upload SARIF to GitHub Code Scanning | No | `false` |
| `approved-registries` | Comma-separated approved npm registry hostnames — packages from any other host trigger B006 | No | `registry.npmjs.org` |

## Outputs

| Output | Description |
|--------|-------------|
| `sarif-file` | Path to the generated SARIF file |
| `findings-count` | Total number of findings |
| `errors-count` | Number of error-level findings |

---

## What it detects

### Behavioral (lockfile integrity)

| ID | Name | Description | Severity |
|----|------|-------------|----------|
| B001 | Range specifier | Version uses `^`, `~`, `>=`, `*` | Warning |
| B002 | No version pinned | No version specified at all | Error |
| B003 | Lagging version | Pinned version significantly behind latest | Warning |
| B004 | Lockfile missing | No adjacent lockfile found | Error |
| B005 | Hash mismatch | Lockfile integrity hash doesn't match resolved tarball | Error |
| B006 | Unapproved registry | Package resolved from non-approved registry host | Error |
| B007 | Lockfile injection | Package in lockfile but absent from `package.json` | Error |

### Reputation signals

| ID | Name | Description | Severity |
|----|------|-------------|----------|
| R001 | Young author account | GitHub account < 12 months old | Warning |
| R002 | New package | Published < 6 months ago | Warning |
| R003 | Low weekly downloads | < 1,000 weekly downloads | Warning |
| R004 | Low total downloads | < 10,000 total downloads | Warning |
| R005 | No updates in 2+ years | Last publish > 2 years ago | Warning |
| R006 | Few contributors | < 5 GitHub contributors | Warning |
| R007 | Known vulnerable version | Below a known security patch (OSV/CVE) | Error |
| R008 | Deprecated package | Officially marked as deprecated | Warning |
| R009 | Typosquatting suspected | Name suspiciously close to a popular package | Warning |
| R010 | Recently published version | Version published < 7 days ago | Error |

### Supply chain risks

| ID | Name | Description | Severity |
|----|------|-------------|----------|
| S001 | Install scripts | Runs code at install time | Error |
| S002 | No source repository | No GitHub/GitLab link in metadata | Warning |
| S003 | Archived repository | Source repo archived or deleted | Warning |
| S004 | Dependency confusion | Private package name found on public registry | Warning |
| S005 | Known malicious package | Recorded history of malicious activity | Error |
| S006 | Missing provenance | No npm provenance attestation | Warning |
| S007 | Ghost repository | npm points to non-existent GitHub repo | Error |
| S008 | Bulk publish | Account published unusually many packages in short window | Warning |
| S009 | Identity mismatch | npm author name/email doesn't match GitHub account | Warning |

### Composite score

| ID | Name | Description | Severity |
|----|------|-------------|----------|
| C001 | Composite attacker score | Weighted combination of S/B signals exceeds threshold | Error |

---

## Supported ecosystems

- npm / Node.js
- Python
- Rust
- Solidity

---

## License

MIT - see [LICENSE](https://github.com/W3OSC/depenemy/blob/main/LICENSE)
