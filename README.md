# depenemy — npm Supply Chain Scanner

[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-depenemy-blue?logo=github)](https://github.com/marketplace/actions/depenemy-npm-supply-chain-scanner)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

> Detect npm supply chain attacks before they merge. Integrates in one step.

**depenemy** scans your `package-lock.json` and `package.json` on every PR for:

| Check | Rule | Severity |
|-------|------|----------|
| Package from unapproved registry | B-8 | 🚫 BLOCK |
| Internal scope resolved from public registry | B-5 | 🚫 BLOCK |
| Lockfile integrity field tampered | B-10 | 🚫 BLOCK |
| Unsafe SemVer specifiers (`^`, `~`, `*`, `latest`) | A-1 | ⚠️ ALERT |
| Package gained install script | A-15 | ⚠️ ALERT |
| Suspicious publisher metadata | S-* | ⚠️ ALERT |

---

## Usage

```yaml
# .github/workflows/supply-chain.yml
name: Supply Chain Security

on:
  pull_request:
    paths:
      - 'package-lock.json'
      - 'package.json'

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: TikoTikTok/depenemy-action@v1
        with:
          lockfile: package-lock.json
          manifest: package.json
          approved-registries: '["registry.npmjs.org"]'
          internal-scopes: '["@myorg"]'
```

### Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `lockfile` | Path to `package-lock.json` | `package-lock.json` |
| `manifest` | Path to `package.json` | `package.json` |
| `approved-registries` | JSON array of allowed registry hostnames | `["registry.npmjs.org"]` |
| `internal-scopes` | JSON array of scopes that must NOT resolve from public registries | `[]` |
| `no-fail` | `true` = report-only, never blocks PR | `false` |
| `semver-lint` | `false` = skip semver check | `true` |

### Outputs

| Output | Description |
|--------|-------------|
| `result` | `PASS` / `ALERT` / `BLOCK` |
| `blocks` | Number of BLOCK-level findings |
| `alerts` | Number of ALERT-level findings |

### Use the result in later steps

```yaml
      - uses: TikoTikTok/depenemy-action@v1
        id: scan
        with:
          approved-registries: '["registry.npmjs.org"]'

      - name: Post comment on BLOCK
        if: steps.scan.outputs.result == 'BLOCK'
        uses: actions/github-script@v7
        with:
          script: |
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: '🚫 **depenemy blocked this PR** — supply chain issue detected. See the Actions summary for details.'
            })
```

### Report-only mode (ALERTs, never blocks)

```yaml
      - uses: TikoTikTok/depenemy-action@v1
        with:
          no-fail: 'true'
```

---

## How it works

depenemy runs inside a Docker container — no dependencies needed on your runner.

1. **Semver Lint** — scans `package.json` for range specifiers that allow silent dependency drift
2. **Lockfile Diff** — parses `package-lock.json` and checks every resolved URL against your approved registry list; flags internal scopes resolving from public CDNs; detects tampered integrity hashes

BLOCK findings exit 1 (blocks the PR). ALERT findings are informational.

---

## License

MIT
