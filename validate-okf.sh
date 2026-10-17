#!/usr/bin/env bash
# validate-okf.sh — Enforces Google OKF conformance in CI
set -euo pipefail

BUNDLE_DIR="${1:-./shieldpulse-okf}"
ERRORS=0

echo "Validating OKF bundle in: $BUNDLE_DIR"

# 1. Verify root index.md exists
if [[ ! -f "$BUNDLE_DIR/index.md" ]]; then
  echo "[FAIL] Missing root index.md"
  exit 1
fi

# 2. Verify every non-reserved .md file contains 'type:' in YAML frontmatter
while IFS= read -r -d '' file; do
  if ! awk 'NR==1 && /^---$/ {in_fm=1; next} in_fm && /^---$/ {exit} in_fm && /^type:[[:space:]]*[^[:space:]]+/ {found=1} END {exit !found}' "$file"; then
    echo "[FAIL] Missing required 'type' frontmatter field in: $file"
    ERRORS=$((ERRORS + 1))
  fi
done < <(find "$BUNDLE_DIR" -name "*.md" ! -name "index.md" ! -name "log.md" -print0)

# 3. Verify every .md file has balanced code fences and resolvable relative links
while IFS= read -r -d '' file; do
  fences=$(grep -c '^[[:space:]]*```' "$file" || true)
  if (( fences % 2 != 0 )); then
    echo "[FAIL] Unclosed code fence in: $file"
    ERRORS=$((ERRORS + 1))
  fi

  dir=$(dirname "$file")
  while IFS= read -r target; do
    target="${target#](}"
    target="${target%)}"
    target="${target%%#*}"
    [[ -z "$target" || "$target" =~ ^[a-zA-Z][a-zA-Z0-9+.-]*: ]] && continue
    if [[ ! -e "$dir/$target" ]]; then
      echo "[FAIL] Broken link in $file -> $target"
      ERRORS=$((ERRORS + 1))
    fi
  done < <(grep -oE '\]\([^)[:space:]]+\)' "$file" || true)
done < <(find "$BUNDLE_DIR" -name "*.md" -print0)

if [[ $ERRORS -gt 0 ]]; then
  echo "OKF Validation failed with $ERRORS error(s)."
  exit 1
fi

echo "[PASS] All OKF concept files are conformant; fences and links are valid."

