#!/bin/sh
# FI P10: original accepted P6 native family buffers with five concurrent
# SQL writers. C220 disposable PostgreSQL clone only. No P7 code or bridge.
set -eu
umask 077
fail() { printf 'FI P10 STOP: %s\n' "$*" >&2; exit 1; }
[ "$(id -un)" = root ] && [ "$(hostname -s)" = c220 ] &&
[ "$#" -eq 2 ] || fail 'usage: sh controller preflight|p10 20261115T153532Z'
case "$1" in preflight|p10) mode=$1;;*)fail 'unknown mode';;esac
[ "$2" = 20261115T153532Z ] || fail 'only accepted signed W512 seed'
repo=/home/jwood/fi-w512-c220-stage
sourcepin=6c9b2646bf1aed4969e18f0e61cb91bb914d941f
runnerpin=f0d52fe6c4af14bde9bac5840ee73429767e7bd3
runnerpath=go/cmd/fi-backlog-recover/run_private_p10_native_p6_c220_host.sh
jexec -U jwood fi-dev git -C "$repo" cat-file -e "$sourcepin^{commit}" ||
  fail 'native P6 signed source pin unavailable'
jexec -U jwood fi-dev git -C "$repo" cat-file -e "$runnerpin^{commit}" ||
  fail 'native P6 runner pin unavailable'
p5=/var/tmp/fi-window-chunks-family-p3-20261116T123717Z
p6=/var/tmp/fi-window-chunks-family-p3-20261116T230127Z
[ -s "$p5/SUMMARY.txt" ] && [ -s "$p6/SUMMARY.txt" ] ||
  fail 'P5/P6 accepted baseline missing'
grep -Fxq 'FI C220 W512 PERSISTENT P5 TWO-WINDOW ACCEPTED windows=2 new_records=997434 elapsed=3m57.995s min_workers=2 max_workers=16 max_slots=80 credits=32 writer=1 authoritative=0 accepted=0' "$p5/SUMMARY.txt" ||
  fail 'P5 signed performance baseline changed'
grep -Fxq 'FI C220 W512 ATOMIC FAMILY P6 TWO-WINDOW ACCEPTED windows=2 new_records=997434 elapsed=4m7.626s min_workers=2 max_workers=16 max_slots=80 credits=32 writer=1 authoritative=0 accepted=0' "$p6/SUMMARY.txt" ||
  fail 'P6 accepted source/relational performance baseline changed'
runroot=/var/tmp/fi-p10-p6-native-$(date -u '+%Y%m%dT%H%M%SZ')
[ ! -e "$runroot" ] && [ ! -L "$runroot" ] || fail 'private P10 output path collision'
mkdir -m 0700 "$runroot"
runner="$runroot/pinned-p10-p6.sh"
jexec -U jwood fi-dev git -C "$repo" show "$runnerpin:$runnerpath" > "$runner" ||
  fail 'pinned P6-native runner missing'
chmod 0700 "$runner"
sh -n "$runner" || fail 'P10 P6-native runner shell syntax invalid'
grep -Fxq "sourcecommit=$sourcepin" "$runner" &&
grep -Fq 'go127 test -race' "$runner" &&
grep -Fq 'TestPrivateP10' "$runner" &&
grep -Fq 'private_p10_direct.go' "$runner" &&
grep -Fq 'FI P10 NATIVE P6 DIRECT SOURCE PASS p7_bridge=none source_stage=none' "$runner" &&
grep -Fq 'FI P10 P6 FIVE SQL PASS' "$runner" &&
grep -Fq 'FI C220 P10 DIRECT P6 FIVE SQL ACCEPTED' "$runner" ||
  fail 'native P6 SQL or signed record acceptance scripts mismatched'
export FI_W512_P6_FAMILY_SQL=1
export FI_W512_P5_PERSISTENT=1
export FI_W512_P3_DYNAMIC_MIN=2
export FI_W512_P3_DYNAMIC_MAX=16
unset FI_W512_P7_SQL_WRITERS FI_W512_P8_REUSE FI_W512_P9_DIRECT_STREAM
unset FI_W512_P3_SECURITY_WORKERS FI_W512_P3_GENERAL_WORKERS
sh "$runner" preflight "$2" ||
  fail 'original P6 seed/source preflight rejected'
printf 'FI P10 NATIVE P6 PREFLIGHT PASS source=%s runner=%s postgres_started=false\n' "$sourcepin" "$runnerpin"
[ "$mode" = preflight ] && exit 0
log="$runroot/P10.console.txt"
status="$runroot/P10.exit"
( if sh "$runner" family "$2";then printf '0\n' > "$status";else printf '1\n' > "$status";fi ) 2>&1 | tee "$log"
[ -s "$status" ] && [ "$(cat "$status")" = 0 ] ||
  fail 'native P6 five-writer Go build, signed stream, relational or clone acceptance failed'
receipt=$(grep '^FI W512 PILOT FINISHED exit=0 outputs=' "$log" | tail -n 1)
[ -n "$receipt" ] || fail 'P10 private SQL shutdown receipt missing'
out=$(printf '%s\n' "$receipt" | sed -n 's/.* outputs=\([^ ]*\) private_clone=.*/\1/p')
case "$out" in /var/tmp/fi-window-chunks-family-p3-*) :;;
 *) fail 'untrusted P10 private SQL output location';;esac
grep -Fq 'FI C220 P10 DIRECT P6 FIVE SQL ACCEPTED windows=2 records=997434 ' "$out/SUMMARY.txt" ||
  fail 'native five-writer direct benchmark acceptance missing'
for f in P10_READ.txt P10_BACKENDS.txt P10_FAMILIES.txt RESULT.txt WINDOWS.txt;do
  [ -s "$out/clone-w512-2g/$f" ] || fail "P10 metrics missing $f"
  cp "$out/clone-w512-2g/$f" "$runroot/$f"
done
elapsed=$(sed -n 's/.*committed_window_time=\([^ ]*\).*/\1/p' "$runroot/RESULT.txt")
seconds=$(awk -v t="$elapsed" 'BEGIN{
 n=split(t,a,"m");if(n!=2)exit 1
 sub(/s$/,"",a[2]);if(a[1]<0||a[2]<0)exit 1
 printf "%.3f",a[1]*60+a[2]
}') || fail 'invalid P10 committed elapsed'
rate=$(awk -v t="$seconds" 'BEGIN{if(t<=0)exit 1;printf "%.2f",997434/t}') ||
  fail 'invalid native P6 five-SQL throughput'
{
  printf 'version\twriters\trecords\tseconds\trecords_per_second\n'
  printf 'P5_persistent\t1\t997434\t237.995\t4190.99\n'
  printf 'P6_accepted\t1\t997434\t247.626\t4027.99\n'
  printf 'P7_additional_staging\t5\t997434\t461.391\t2161.80\n'
  printf 'P8_additional_staging\t5\t997434\t420.021\t2374.72\n'
  printf 'P10_P6_native_direct\t5\t997434\t%s\t%s\n' "$seconds" "$rate"
} > "$runroot/COMPARISON.tsv"
cat "$runroot/COMPARISON.tsv"
printf 'FI P10 NATIVE P6 FIVE SQL PRIVATE ACCEPTED windows=2 records=997434 writers=5 source_staging=none authoritative=0 accepted=0 output=%s\n' "$runroot"
