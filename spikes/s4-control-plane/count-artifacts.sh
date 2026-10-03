#!/bin/sh
# Count FTR-tagged (protocol 249) rules and routes per family.
IP=${IP:-ip}
for f in 4 6; do
  r=$($IP -$f rule show | grep -c "proto 249")
  t=$($IP -$f route show table all proto 249 2>/dev/null | grep -c .)
  printf 'IPv%s rules=%s routes=%s  ' "$f" "$r" "$t"
done
echo
