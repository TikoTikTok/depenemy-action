#!/bin/sh
set -e

LOCKFILE="${1:-package-lock.json}"
MANIFEST="${2:-package.json}"
APPROVED_REGISTRIES="${3:-[\"registry.npmjs.org\"]}"
INTERNAL_SCOPES="${4:-[]}"
NO_FAIL="${5:-false}"
RUN_SEMVER="${6:-true}"

WORKDIR="${GITHUB_WORKSPACE:-/github/workspace}"
FINDINGS_JSON="/tmp/depenemy-findings.json"
SEMVER_JSON="/tmp/depenemy-semver.json"

cd "$WORKDIR"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  depenemy — npm Supply Chain Scanner"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Lockfile  : $LOCKFILE"
echo "  Manifest  : $MANIFEST"
echo "  Registries: $APPROVED_REGISTRIES"
echo "  Scopes    : $INTERNAL_SCOPES"
echo "  No-fail   : $NO_FAIL"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Write config files from inputs
echo "$APPROVED_REGISTRIES" > /tmp/approved-registries.json
echo "$INTERNAL_SCOPES"     > /tmp/internal-scopes.json

BLOCK_COUNT=0
ALERT_COUNT=0

# ── Semver Lint ──────────────────────────────────────────
if [ "$RUN_SEMVER" = "true" ] && [ -f "$MANIFEST" ]; then
    echo "[ semver-lint ] Scanning $MANIFEST ..."
    python /scripts/semver-lint.py "$MANIFEST" --output-json "$SEMVER_JSON" || true
    SEMVER_ALERTS=$(python -c "import json,sys; d=json.load(open('$SEMVER_JSON')); print(len(d))" 2>/dev/null || echo 0)
    ALERT_COUNT=$((ALERT_COUNT + SEMVER_ALERTS))
    echo "[ semver-lint ] Found $SEMVER_ALERTS ALERT(s)"
fi

# ── Lockfile Diff ─────────────────────────────────────────
if [ -f "$LOCKFILE" ]; then
    echo "[ lockfile-diff ] Scanning $LOCKFILE ..."

    NO_FAIL_FLAG=""
    if [ "$NO_FAIL" = "true" ]; then
        NO_FAIL_FLAG="--no-fail"
    fi

    python /scripts/lockfile-diff.py \
        --lockfile "$LOCKFILE" \
        --registries /tmp/approved-registries.json \
        --scopes /tmp/internal-scopes.json \
        --output-json "$FINDINGS_JSON" \
        $NO_FAIL_FLAG
    EXIT_CODE=$?

    BLOCKS=$(python -c "
import json, sys
try:
    data = json.load(open('$FINDINGS_JSON'))
    findings = data.get('findings', data) if isinstance(data, dict) else data
    print(sum(1 for f in findings if f.get('verdict') == 'BLOCK'))
except: print(0)
" 2>/dev/null || echo 0)
    ALERTS=$(python -c "
import json, sys
try:
    data = json.load(open('$FINDINGS_JSON'))
    findings = data.get('findings', data) if isinstance(data, dict) else data
    print(sum(1 for f in findings if f.get('verdict') == 'ALERT'))
except: print(0)
" 2>/dev/null || echo 0)

    BLOCK_COUNT=$((BLOCK_COUNT + BLOCKS))
    ALERT_COUNT=$((ALERT_COUNT + ALERTS))
    echo "[ lockfile-diff ] Found $BLOCKS BLOCK(s), $ALERTS ALERT(s)"
else
    echo "[ lockfile-diff ] Skipping — $LOCKFILE not found"
    EXIT_CODE=0
fi

# ── Step Summary ─────────────────────────────────────────
if [ -n "$GITHUB_STEP_SUMMARY" ]; then
    echo "## 🔍 depenemy Supply Chain Scan" >> "$GITHUB_STEP_SUMMARY"
    echo "" >> "$GITHUB_STEP_SUMMARY"
    if [ -f "$SEMVER_JSON" ]; then
        echo "### Semver Lint" >> "$GITHUB_STEP_SUMMARY"
        python /scripts/format-findings.py --input "$SEMVER_JSON" >> "$GITHUB_STEP_SUMMARY" 2>/dev/null || true
    fi
    if [ -f "$FINDINGS_JSON" ]; then
        echo "### Lockfile Diff" >> "$GITHUB_STEP_SUMMARY"
        python /scripts/format-findings.py --input "$FINDINGS_JSON" >> "$GITHUB_STEP_SUMMARY" 2>/dev/null || true
    fi
fi

# ── Set outputs ───────────────────────────────────────────
if [ -n "$GITHUB_OUTPUT" ]; then
    echo "blocks=$BLOCK_COUNT" >> "$GITHUB_OUTPUT"
    echo "alerts=$ALERT_COUNT" >> "$GITHUB_OUTPUT"
    if [ "$BLOCK_COUNT" -gt 0 ]; then
        echo "result=BLOCK" >> "$GITHUB_OUTPUT"
    elif [ "$ALERT_COUNT" -gt 0 ]; then
        echo "result=ALERT" >> "$GITHUB_OUTPUT"
    else
        echo "result=PASS" >> "$GITHUB_OUTPUT"
    fi
fi

# ── Final verdict ─────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if [ "$BLOCK_COUNT" -gt 0 ]; then
    echo "  🚫 RESULT: BLOCK — $BLOCK_COUNT critical finding(s)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    if [ "$NO_FAIL" != "true" ]; then
        exit 1
    fi
elif [ "$ALERT_COUNT" -gt 0 ]; then
    echo "  ⚠️  RESULT: ALERT — $ALERT_COUNT warning(s) (non-blocking)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
else
    echo "  ✅ RESULT: PASS — no findings"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
fi
