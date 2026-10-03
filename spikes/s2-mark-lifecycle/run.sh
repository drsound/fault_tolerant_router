#!/usr/bin/env bash
# Run every S2 test; exit status is non-zero if any check failed.
cd "$(dirname "$0")" || exit 1
rc=0
for t in $(ls t[0-9]*-*.sh | sort -V); do
  echo "######## $t"
  bash "$t" || rc=1
done
exit $rc
