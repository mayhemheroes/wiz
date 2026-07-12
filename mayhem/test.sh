#!/usr/bin/env bash
#
# mayhem/test.sh — RUN wiz's own functional test suite (built by mayhem/build.sh at bin/wiz).
#
# tests/wiztests.py compiles each tests/{block,failure}/*.wiz with wiz and asserts the emitted
# machine-code bytes match the `// BLOCK <addr> <bytes>` annotations (known-answer tests) and that
# `// ERROR` cases fail as expected. It is a behavioral oracle: a wiz that is patched to a no-op /
# exit(0) emits no/incorrect bytes and FAILS here.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

WIZ_BIN="$SRC/bin/wiz"
if [ ! -x "$WIZ_BIN" ]; then
  echo "test.sh: $WIZ_BIN missing — build.sh must produce the normal wiz build" >&2
  emit_ctrf "wiztests" 0 1 0
  exit 1
fi

mkdir -p "$SRC/bin/test-tmp"
out="$(mktemp)"
set +e
bash tests/wiztests.sh -w "$WIZ_BIN" -b "$SRC/bin/test-tmp" tests/block tests/failure 2>&1 | tee "$out"
rc=${PIPESTATUS[0]}
set -e

passed="$(grep -oE '[0-9]+ tests passed' "$out" | grep -oE '^[0-9]+' | tail -1)"
passed="${passed:-0}"

# Per-file failure triage: wiztests.py prints "tests/<dir>/<file>.wiz:" headers followed by
# " PASSED"/" FAILED". Failures listed in mayhem/known-upstream-test-failures.txt are upstream-tip
# regressions (identical under clang and g++) and are counted as "other"; anything else is a real
# failure. A neutered (exit-0/no-op) wiz fails EVERY block test, far beyond the known list.
failing_files="$(awk '/^tests\//{split($0,a,":"); cur=a[1]} /^ FAILED$/{print cur}' "$out" | sort -u)"
known=0; new=0
while IFS= read -r f; do
  [ -n "$f" ] || continue
  if grep -qxF "$f" "$SRC/mayhem/known-upstream-test-failures.txt"; then
    known=$((known+1))
  else
    echo "test.sh: UNEXPECTED failure in $f" >&2
    new=$((new+1))
  fi
done <<< "$failing_files"

# Guard against a silent no-op run (e.g. suite never executed): zero results is a failure,
# not a vacuous green.
if [ "$passed" -eq 0 ] && [ "$known" -eq 0 ] && [ "$new" -eq 0 ]; then
  echo "test.sh: suite reported no results (rc=$rc)" >&2
  emit_ctrf "wiztests" 0 1 0
  exit 1
fi

emit_ctrf "wiztests" "$passed" "$new" 0 0 "$known"
