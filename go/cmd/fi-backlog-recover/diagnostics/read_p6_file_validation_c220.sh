#!/bin/sh
# FI P6 FileObservation validation accounting failure — read-only evidence.
# Run as root@c220. Prints source snippets only; no SQL, no mutations.
set -eu
[ "$(id -un)" = root ] && [ "$(hostname -s)" = c220 ] ||
  { echo "FI P6 DIAG STOP: root@c220 required" >&2; exit 1; }
jexec -U jwood fi-dev sh -s <<'FI_P6_SEED'
set -eu
base=/home/jwood/fi-window-bench-w512-20261115T153532Z/optimized-source/go/internal/recordingest
[ -d "$base" ] || {
  echo "FI P6 DIAG STOP: original W512 seed source absent" >&2
  exit 1
}
echo "=== ORIGINAL SEED FILE VALIDATION ASSERTION AND CONTEXT ==="
found=0
for f in "$base"/*.go; do
  [ -f "$f" ] || continue
  places=$(grep -nF "FileObservation validation count mismatch" "$f" | cut -d: -f1 || :)
  [ -n "$places" ] || continue
  found=1
  for n in $places; do
    case "$n" in *[!0-9]*|"") exit 1;; esac
    a=$((n>30?n-30:1))
    b=$((n+24))
    printf "FILE=%s LINES=%s..%s\n" "$f" "$a" "$b"
    sed -n "${a},${b}{=;p;}" "$f" | sed "N;s/\n/ /"
  done
done
[ "$found" = 1 ] || echo "FI P6 DIAG: error not in original seed; inspect clone below"
echo "=== FILE VALIDATION / REUSE COUNTER REFERENCES ==="
grep -RnEi "validated\.observation|[Ff]ile.*[Vv]alidat|[Vv]alidat.*[Ff]ile|[Rr]eused.*[Vv]alidat|[Vv]alidat.*[Rr]eused" "$base" 2>/dev/null | head -n 140 || :
echo "FI P6 READ-ONLY FILE VALIDATION DIAGNOSTIC COMPLETE"
FI_P6_SEED
