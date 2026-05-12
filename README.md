# depenemy-action

GitHub Action for [depenemy](https://github.com/W3OSC/depenemy) — scans your dependencies for supply chain risks, reputation red flags, and behavioral issues.

Results appear automatically in your **Security > Code Scanning** tab on every push and pull request.

---

## Quick start

```yaml
# .github/workflows/supply-chain.yml
name: Supply Chain Security
on:
  pull_request:
    paths: ["package.json", "package-lock.json", "**/package.json", "**/package-lock.json"]
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
          approved-registries: "registry.npmjs.org"
          fail-on: error
          token: ${{ secrets.GITHUB_TOKEN }}
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.scan.outputs.sarif-file }}
          category: depenemy
```

> **Note:** `upload-sarif` defaults to `false` — GitHub Advanced Security (GHAS) is required for SARIF upload. Use the explicit `github/codeql-action/upload-sarif` step above, or set `upload-sarif: 'true'` if GHAS is enabled on your repo.

---

## Action variants

### Composite action (default) — any runner

```yaml
- uses: W3OSC/depenemy-action@v1
  with:
    approved-registries: "registry.npmjs.org"
    fail-on: error
```

Installs depenemy from PyPI at runtime. Works on Linux, macOS, and Windows runners.

### Docker action — fully isolated

```yaml
- uses: W3OSC/depenemy-action/action@v1
  with:
    approved-registries: "registry.npmjs.org"
    fail-on: error
```

Builds depenemy from the repo source inside a Docker container. Requires a Linux runner. Use this for reproducible, hermetic builds.

---

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `approved-registries` | Comma-separated list of approved npm registry hostnames. Packages resolved from any other host trigger rule B006 (BLOCK). | No | `registry.npmjs.org` |
| `token` | GitHub token for author and contributor lookups (unlocks R001, R006, S007–S009) | No | `${{ github.token }}` |
| `paths` | Space-separated paths to scan | No | `.` |
| `fail-on` | Minimum severity to fail the action (`error`, `warning`, `info`, `never`) | No | `error` |
| `output-sarif` | Path to write SARIF output file | No | `depenemy.sarif` |
| `config` | Path to `.depenemy.yml` config file. When provided, `approved-registries` is ignored. | No | — |
| `ecosystems` | Comma-separated ecosystems to scan (`npm,pypi,cargo`) | No | auto-detect |
| `upload-sarif` | Automatically upload SARIF to GitHub Code Scanning (requires GHAS) | No | `false` |

## Outputs

| Output | Description |
|--------|-------------|
| `sarif-file` | Path to the generated SARIF file |
| `findings-count` | Total number of findings |
| `errors-count` | Number of error-level findings |

---

## What it detects

### Behavioral (lockfile integrity)

| ID | Name | Severity |
|----|------|----------|
| B001 | Range specifier | Warning |
| B002 | No version pinned | Error |
| B003 | Lagging version | Warning |
| **B005** | **Lockfile integrity hash mismatch** (tampered tarball) | **Error** |
| **B006** | **Package from unapproved registry** | **Error** |
| **B007** | **Lockfile resolved URL injection** | **Error** |

### Reputation

| ID | Name | Severity |
|----|------|----------|
| R001 | Young author account | Warning |
| R002 | New package | Warning |
| R003 | Low weekly downloads | Warning |
| R004 | Low total downloads | Warning |
| R005 | No updates in 2+ years | Warning |
| R006 | Few contributors | Warning |
| R007 | Known vulnerable version | Error |
| R008 | Deprecated package | Warning |
| R009 | Typosquatting suspected | Warning |
| R010 | Recently published version | Error |

### Supply chain

| ID | Name | Severity |
|----|------|----------|
| S001 | Install scripts | Error |
| S002 | No source repository | Warning |
| S003 | Archived repository | Warning |
| S004 | Dependency confusion | Warning |
| S005 | Known malicious package | Error |
| **S006** | **Missing provenance attestation** | **Warning** |
| **S007** | **Ghost repository** (facade repo) | **Warning** |
| **S008** | **Bulk publish burst** | **Warning** |
| **S009** | **Publisher/GitHub identity mismatch** | **Warning** |

### Composite

| ID | Name | Severity |
|----|------|----------|
| **C001** | **Composite supply-chain risk score** (≥4 signals) | **Error** |

---

## Approved registries

The `approved-registries` input controls which npm registry hostnames are trusted. Any package whose `resolved` URL in `package-lock.json` points to a different host triggers **B006** (ERROR) and blocks the build.

```yaml
# Single registry (default)
approved-registries: "registry.npmjs.org"

# Multiple registries (comma-separated)
approved-registries: "registry.npmjs.org, npm.pkg.github.com"

# JSON array
approved-registries: '["registry.npmjs.org", "artifactory.mycompany.com"]'
```

When using a private Artifactory/Nexus/Verdaccio proxy, add its hostname to `approved-registries` so internal packages are not incorrectly flagged.

---

## Supported ecosystems

- **npm** / Node.js (full rule set including B005–B007, S006–S009, C001)
- Python
- Rust

---

## License

MIT — see [LICENSE](LICENSE)
