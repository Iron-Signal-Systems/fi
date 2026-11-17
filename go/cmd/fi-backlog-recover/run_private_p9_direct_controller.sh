#!/bin/sh
# FI P9 direct signed five-family stream. Independent C220 clone ONLY.
# Modes preflight, tests or p9. Real SoR/Accepted is forbidden.
set -eu
umask 077
fail(){ printf 'FI P9 STOP: %s\n' "$*" >&2; exit 1; }
[ "$(id -un)" = root ] && [ "$(hostname -s)" = c220 ] &&
[ "$#" -eq 2 ] || fail 'usage: sh controller preflight|tests|p9 20261115T153532Z'
case "$1" in preflight|tests|p9) mode=$1;;*) fail 'invalid P9 mode';;esac
[ "$2" = 20261115T153532Z ] || fail 'only authenticated W512 original seed allowed'
repo=/home/jwood/fi-w512-c220-stage
sourcepin=5acbf0ae6cdea1f9ee66cc936ef4016a729ae6ea
testrunnerpin=c42dc77c954b7d3e8e9003807d6eff9a5d4adfbc
runnerpin=f5fa1df9213b5ebfd133f926c716d3748ccde714
testpath=go/cmd/fi-backlog-recover/run_private_p9_direct_compile_c220_host.sh
runpath=go/cmd/fi-backlog-recover/run_private_p9_direct_c220_host.sh
for pin in "$sourcepin" "$testrunnerpin" "$runnerpin";do
  jexec -U jwood fi-dev git -C "$repo" cat-file -e "$pin^{commit}" ||
    fail "pinned source not in fi-dev repository: $pin"
done
p5=/var/tmp/fi-window-chunks-family-p3-20261116T123717Z
p6=/var/tmp/fi-window-chunks-family-p3-20261116T230127Z
[ -s "$p5/SUMMARY.txt" ] && [ -s "$p6/SUMMARY.txt" ] ||
  fail 'accepted P5 and P6 baseline absent'
grep -Fxq 'FI C220 W512 PERSISTENT P5 TWO-WINDOW ACCEPTED windows=2 new_records=997434 elapsed=3m57.995s min_workers=2 max_workers=16 max_slots=80 credits=32 writer=1 authoritative=0 accepted=0' "$p5/SUMMARY.txt" ||
  fail 'accepted P5 performance control changed'
grep -Fxq 'FI C220 W512 ATOMIC FAMILY P6 TWO-WINDOW ACCEPTED windows=2 new_records=997434 elapsed=4m7.626s min_workers=2 max_workers=16 max_slots=80 credits=32 writer=1 authoritative=0 accepted=0' "$p6/SUMMARY.txt" ||
  fail 'accepted P6 performance control changed'
runroot=/var/tmp/fi-w512-direct-p9-$(date -u '+%Y%m%dT%H%M%SZ')
[ ! -e "$runroot" ] && [ ! -L "$runroot" ] || fail 'output collision'
mkdir -m 0700 "$runroot"
tests="$runroot/pinned-p9-tests.sh"
runner="$runroot/pinned-p9-pilot.sh"
jexec -U jwood fi-dev git -C "$repo" show "$testrunnerpin:$testpath" > "$tests" ||
  fail 'pinned P9 tests missing'
jexec -U jwood fi-dev git -C "$repo" show "$runnerpin:$runpath" > "$runner" ||
  fail 'pinned P9 pilot missing'
chmod 0700 "$tests" "$runner"
sh -n "$tests" && sh -n "$runner" || fail 'pinned POSIX shell syntax invalid'
grep -Fxq "sourcepin=$sourcepin" "$tests" &&
grep -Fxq "sourcecommit=$sourcepin" "$runner" ||
  fail 'P9 source pin mismatch'
grep -Fq 'TestPrivateP[789]' "$tests" &&
grep -Fq 'go127 test -race' "$tests" &&
grep -Fq 'FI P9 DIRECT MULTIWINDOW COMMIT PASS' "$runner" &&
grep -Fq 'source_receipt_writes=0 artifact_receipt_writes=0' "$runner" &&
grep -Fq 'FI P9 DIRECT SECURITY PARTITION PASS' "$runner" &&
grep -Fq 'fi_p9_typed_shadow_generation_fkey' "$runner" &&
grep -Fq 'FI C220 P9 DIRECT FIVE WRITER TWO-WINDOW ACCEPTED' "$runner" ||
  fail 'P9 direct signed-stream/test/SQL handoff gates missing'
export FI_W512_P7_SQL_WRITERS=5
export FI_W512_P6_FAMILY_SQL=1
export FI_W512_P5_PERSISTENT=1
export FI_W512_P3_DYNAMIC_MIN=2
export FI_W512_P3_DYNAMIC_MAX=16
unset FI_W512_P3_SECURITY_WORKERS FI_W512_P3_GENERAL_WORKERS
sh "$runner" preflight "$2" || fail 'source/cache/storage preflight failed'
printf 'FI P9 PINNED PREFLIGHT PASS source=%s tests=%s runner=%s postgres_started=false\n' \
  "$sourcepin" "$testrunnerpin" "$runnerpin"
[ "$mode" = preflight ] && exit 0
sh "$tests" tests || fail 'P9 direct Go unit or race regression failed before PostgreSQL'
echo 'FI P9 NO-SQL UNIT/RACE PASS postgres_started=false'
[ "$mode" = tests ] && exit 0
log="$runroot/P9.console.txt"
status="$runroot/P9.exit"
( if sh "$runner" family "$2"; then echo 0 > "$status"; else echo 1 > "$status"; fi ) 2>&1 | tee "$log"
[ -s "$status" ] && [ "$(cat "$status")" = 0 ] ||
  fail 'P9 direct clone or signed/relational acceptance failed'
receipt=$(grep '^FI W512 PILOT FINISHED exit=0 outputs=' "$log" | tail -n 1)
[ -n "$receipt" ] || fail 'P9 private PostgreSQL shutdown receipt absent'
out=$(printf '%s\n' "$receipt" | sed -n 's/.* outputs=\([^ ]*\) private_clone=.*/\1/p')
case "$out" in /var/tmp/fi-window-chunks-family-p3-*) :;; *) fail 'untrusted private SQL metrics location';;esac
summary="$out/SUMMARY.txt"
grep -Fq 'FI C220 P9 DIRECT FIVE WRITER TWO-WINDOW ACCEPTED windows=2 records=997434 ' "$summary" ||
  fail 'P9 direct pilot did not meet acceptance'
for item in P9_READ.txt P9_FAMILIES.txt P9_COMMIT.txt RESULT.txt WINDOWS.txt;do
  [ -s "$out/clone-w512-2g/$item" ] || fail "P9 result missing: $item"
  cp "$out/clone-w512-2g/$item" "$runroot/$item"
done
elapsed=$(sed -n 's/.*committed_window_time=\([^ ]*\).*/\1/p' "$runroot/RESULT.txt")
secs=$(awk -v e="$elapsed" 'BEGIN{
  n=split(e,a,"m");if(n!=2)exit 1
  sub(/s$/,"",a[2]);if(a[1]<0||a[2]<0)exit 1
  printf "%.3f",a[1]*60+a[2]
}') || fail 'bad P9 elapsed time'
rps=$(awk -v s="$secs" 'BEGIN{if(s<=0)exit 1;printf "%.3f",997434/s}') ||
  fail 'bad P9 rate'
{
 printf 'experiment\twriters\trecords\tseconds\trecords_per_sec\n'
 printf 'P5_persistent\t1\t997434\t237.995\t4190.987\n'
 printf 'P6_single_writer\t1\t997434\t247.626\t4027.986\n'
 printf 'P7_five_writers\t5\t997434\t461.391\t2161.798\n'
 printf 'P8_five_writers\t5\t997434\t420.021\t2374.724\n'
 printf 'P9_direct_stream\t5\t997434\t%s\t%s\n' "$secs" "$rps"
} > "$runroot/P5_P6_P7_P8_P9_COMPARISON.tsv"
echo '===== MATCHED TWO-WINDOW DIRECT STREAM PERFORMANCE ====='
cat "$runroot/P5_P6_P7_P8_P9_COMPARISON.tsv"
echo '===== DIRECT SIGNED RECORD STREAM ====='
cat "$runroot/P9_READ.txt" "$runroot/P9_FAMILIES.txt" "$runroot/P9_COMMIT.txt"
printf 'FI C220 P9 DIRECT STREAM PRIVATE ACCEPTED windows=2 records=997434 writers=5 new_staging=none authoritative=0 accepted=0 output=%s\n' "$runroot"
