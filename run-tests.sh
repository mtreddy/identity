#!/usr/bin/env bash
# run-tests.sh — run every mechanism's test.py in its own venv.
#
#   ./run-tests.sh                 # all mechanisms with a test.py
#   ./run-tests.sh 09-* 16-totp    # only the named directories
#
# Each mechanism is self-contained, so we create a per-dir .venv, install its
# requirements, and run its test.py (which starts the app and asserts).
set -u
ROOT="$(cd "$(dirname "$0")" && pwd)"

if [ "$#" -gt 0 ]; then
  dirs=("$@")
else
  dirs=()
  for d in "$ROOT"/[0-9][0-9]-*/; do dirs+=("$(basename "$d")"); done
fi

pass=0 fail=0 skip=0
failed_list=()
for d in "${dirs[@]}"; do
  d="${d%/}"
  if [ ! -f "$ROOT/$d/test.py" ]; then
    echo "SKIP  $d  (no test.py)"; skip=$((skip+1)); continue
  fi
  echo "──────── $d ────────"
  (
    cd "$ROOT/$d" || exit 1
    python3 -m venv .venv >/dev/null 2>&1
    ./.venv/bin/pip install -q -r requirements.txt >/dev/null 2>&1
    ./.venv/bin/python test.py
  )
  if [ $? -eq 0 ]; then pass=$((pass+1)); else fail=$((fail+1)); failed_list+=("$d"); fi
  echo
done

echo "════════════════════════════════════════"
echo "passed: $pass   failed: $fail   skipped: $skip"
if [ "$fail" -gt 0 ]; then
  echo "FAILED: ${failed_list[*]}"
  exit 1
fi
