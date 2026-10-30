#!/usr/bin/env bash
#
# mayhem/test.sh — RUN vifm's own unit-test suites (stic; built by mayhem/build.sh with normal flags).
# Each suite must print stic's "ALL TESTS PASSED" summary; the run counts come from that summary, so
# a neutered binary (prints nothing, exits 0) is a failure, not a pass.
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

SUITES="abbrevs autocmds cmds commands completion keys options parsing text_buffer variables
        ioeta ionotif iop ior colmgr column_view viewcolumns_parser
        bmarks escape fileops filetype filter lua menus misc undo utils"

# stic's make-based sandbox layout expects to be run from tests/ with a terminal-less environment.
unset TERM STY TMUX DISPLAY WAYLAND_DISPLAY
export UBSAN_OPTIONS=halt_on_error=1
cd tests

passed=0; failed=0; skipped=0
for s in $SUITES; do
  bin="bin/$s"
  if [ ! -x "$bin" ]; then
    echo "missing test runner $bin (mayhem/build.sh should have built it)" >&2
    failed=$((failed + 1)); continue
  fi
  out=$("$bin" -s 2>&1); rc=$?
  summary=$(printf '%s\n' "$out" | grep -E '[0-9]+ checks? :: [0-9]+ run tests? :: [0-9]+ skipped tests?' | tail -n1)
  if [ $rc -eq 0 ] && printf '%s\n' "$out" | grep -q 'ALL TESTS PASSED' && [ -n "$summary" ]; then
    run=$(printf '%s' "$summary" | sed -E 's/.*checks? :: ([0-9]+) run tests? ::.*/\1/')
    skip=$(printf '%s' "$summary" | sed -E 's/.*run tests? :: ([0-9]+) skipped.*/\1/')
    passed=$((passed + run)); skipped=$((skipped + skip))
    echo "suite $s: ok ($run run, $skip skipped)"
  else
    echo "suite $s: FAILED (rc=$rc)" >&2
    printf '%s\n' "$out" | tail -n 40 >&2
    failed=$((failed + 1))
  fi
done

# Known-answer floor: the suites together exercise well over a thousand cases.
if [ "$failed" -eq 0 ] && [ "$passed" -lt 1000 ]; then
  echo "only $passed tests ran; expected >= 1000" >&2
  failed=1
fi

emit_ctrf "stic" "$passed" "$failed" "$skipped"
