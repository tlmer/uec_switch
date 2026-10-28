#!/bin/sh
# S8: summarize the PASS/FAIL criteria lines from a run.sh log directory.
# Usage: tools/coverage_report.sh [logdir] [outfile]
cd "$(dirname "$0")/.." || exit 1
dir=${1:-build}
out=${2:-$dir/coverage_report.txt}
pass=$(grep -h ' PASS' "$dir"/tb_switch_*.log 2>/dev/null | wc -l)
fail=$(grep -h ' FAIL' "$dir"/tb_switch_*.log 2>/dev/null | wc -l)
{
  echo "SW_COVERAGE pass_lines=$pass fail_lines=$fail"
  echo "SW_COVERAGE modules:"
  for f in "$dir"/tb_switch_*.log; do
    [ -f "$f" ] || continue
    p=$(grep -c ' PASS' "$f" 2>/dev/null || true)
    x=$(grep -c ' FAIL' "$f" 2>/dev/null || true)
    echo "SW_COVERAGE $(basename "$f" .log) pass=$p fail=$x"
  done
  echo "SW_COVERAGE criteria:"
  grep -h ' PASS' "$dir"/tb_switch_*.log 2>/dev/null | sed 's/^/SW_COVERAGE   /'
  if [ "$fail" -eq 0 ]; then
    echo "SW_COVERAGE PASS"
  else
    echo "SW_COVERAGE FAIL"
  fi
} > "$out"
cat "$out"
[ "$fail" -eq 0 ]
