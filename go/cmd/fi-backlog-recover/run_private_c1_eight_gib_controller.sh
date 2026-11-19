#!/bin/sh
# FI C1 clone-only signed 8GiB group A/B (2GiB vs 4GiB), adaptive shared SQL.
# C220 disposable PostgreSQL clone only. No P7 code or bridge.
set -eu
umask 077
fail() { printf 'FI C1 STOP: %s\n' "$*" >&2; exit 1; }
[ "$(id -un)" = root ] && [ "$(hostname -s)" = c220 ] &&
[ "$#" -eq 2 ] || fail 'usage: sh controller preflight|compile|c1|inject-file 20261115T153532Z'
case "$1" in preflight|compile|c1|inject-file) mode=$1;;*)fail 'unknown mode';;esac
[ "$2" = 20261115T153532Z ] || fail 'only pinned signed W512 seed'
repo=/home/jwood/fi-w512-c220-stage
sourcepin=1ca8d7b8992f50ad5b70ec41e416237b1b6513f3
runnerpin=5868fb01944397853089b6bceffcc137a22fe5df
runnerpath=go/cmd/fi-backlog-recover/run_private_c1_eight_gib_c220_host.sh
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
runroot=/var/tmp/fi-c1-eight-gib-$(date -u '+%Y%m%dT%H%M%SZ')
[ ! -e "$runroot" ] && [ ! -L "$runroot" ] || fail 'private C1 output path collision'
mkdir -m 0700 "$runroot"
runner="$runroot/pinned-c1-p6.sh"
jexec -U jwood fi-dev git -C "$repo" show "$runnerpin:$runnerpath" > "$runner" ||
  fail 'pinned P6-native runner missing'
chmod 0700 "$runner"
sh -n "$runner" || fail 'C1 P6-native runner shell syntax invalid'
grep -Fxq "sourcecommit=$sourcepin" "$runner" &&
grep -Fq 'go127 test -race' "$runner" &&
grep -Fq 'TestPrivateC1' "$runner" &&
grep -Fq 'private_c1_direct.go' "$runner" &&
grep -Fq 'FI C1 CLEAN START PASS' "$runner" &&
grep -Fq 'C1_CONTINUOUS_FAMILIES.txt' "$runner" &&
grep -Fq 'C1_SECURITY_COPY.txt' "$runner" &&
grep -Fq 'FI C1 NATIVE P6 DIRECT SOURCE PASS p7_bridge=none source_stage=none' "$runner" &&
grep -Fq 'FI C1 P6 SHARED SQL PASS' "$runner" &&
grep -Fq 'FI C1 EIGHT GIB SIGNED PLAN' "$runner" &&
grep -Fq 'C1_PLAN.txt' "$runner" &&
grep -Fq 'C1_POOL.txt' "$runner" &&
grep -Fq 'FI C1 SHARED SQL POOL' "$runner" &&
grep -Fq 'FI C220 C1 EIGHT GIB DEV PASS' "$runner" ||
  fail 'native P6 SQL or signed record acceptance scripts mismatched'
sqlmax=${FI_W512_C1_SQL_WORKERS_MAX:-12}
case "$sqlmax" in [1-9]|1[0-6]) ;; *) fail 'SQL worker maximum must be 1..16';; esac
group=${FI_C1_8G_GROUP_GIB:-}
case "$group" in 2|4) : ;; *) fail 'set FI_C1_8G_GROUP_GIB=2 or 4';; esac
export FI_C1_8G_GROUP_GIB="$group"
export FI_W512_C1_SQL_WORKERS_MAX="$sqlmax"
export FI_W512_P6_FAMILY_SQL=1
export FI_W512_P5_PERSISTENT=1
export FI_W512_P3_DYNAMIC_MIN=2
export FI_W512_P3_DYNAMIC_MAX=16
unset FI_W512_P7_SQL_WRITERS FI_W512_P8_REUSE FI_W512_P9_DIRECT_STREAM
unset FI_W512_P3_SECURITY_WORKERS FI_W512_P3_GENERAL_WORKERS
sh "$runner" preflight "$2" ||
  fail 'original P6 seed/source preflight rejected'
printf 'FI C1 NATIVE P6 PREFLIGHT PASS source=%s runner=%s postgres_started=false\n' "$sourcepin" "$runnerpin"
[ "$mode" = preflight ] && exit 0
if [ "$mode" = compile ]; then
  compilelog="$runroot/C1.compile.txt"
  if ! sh "$runner" compile "$2" > "$compilelog" 2>&1; then
    tail -n 100 "$compilelog" >&2 || :
    fail 'C1 private Go and race tests failed; no database started'
  fi
  cat "$compilelog"
  grep -Fxq 'FI C1 C220 PRIVATE GO/RACE GATE PASS original_seed_unchanged=true postgres_started=false' "$compilelog" ||
    fail 'C1 no-database compile receipt missing'
  echo 'FI C1 C220 GO/RACE COMPILE PASS original_seed_unchanged=true postgres_started=false'
  exit 0
fi
log="$runroot/C1.console.txt"
status="$runroot/C1.exit"
runner_mode=family
[ "$mode" != inject-file ] || runner_mode=inject-file
( if sh "$runner" "$runner_mode" "$2";then printf '0\n' > "$status";else printf '1\n' > "$status";fi ) 2>&1 | tee "$log"
[ -s "$status" ] && [ "$(cat "$status")" = 0 ] ||
  fail 'native P6 adaptive SQL build, signed stream, relational or clone checks failed'
if [ "$mode" = inject-file ]; then
  grep -Fq 'FI C1 DEVELOPMENT FAILURE CONTAINMENT PASS ' "$log" ||
    fail 'C1 injected File failure did not prove missing typed checkpoint'
  grep -Fq 'dirty_clone_discard_required=true authoritative=0 published=0' "$log" ||
    fail 'C1 failed dirty clone quarantine proof'
  grep -Fq 'FI W512 PILOT FINISHED exit=0 ' "$log" ||
    fail 'C1 injected File clone was not cleanly shut down'
  printf 'FI C1 DEVELOPMENT FAILURE/RESTART GUARD PASS file_postcommit_failure=true typed_marker_not_advanced=true dirty_clone_discard_required=true\n'
  exit 0
fi
receipt=$(grep '^FI W512 PILOT FINISHED exit=0 outputs=' "$log" | tail -n 1)
[ -n "$receipt" ] || fail 'C1 private SQL shutdown receipt missing'
out=$(printf '%s\n' "$receipt" | sed -n 's/.* outputs=\([^ ]*\) private_clone=.*/\1/p')
case "$out" in /var/tmp/fi-window-chunks-family-p3-*) :;;
 *) fail 'untrusted C1 private SQL output location';;esac
grep -Fq "FI C220 C1 EIGHT GIB DEV PASS groups=" "$out/SUMMARY.txt" ||
  fail 'native shared-SQL benchmark acceptance missing'
for f in C1_READ.txt C1_BACKENDS.txt C1_FAMILIES.txt C1_PLAN.txt C1_PREP.txt C1_P5_LANES.txt C1_SQL_PROFILE.txt C1_SECURITY_COPY.txt C1_CONTINUOUS_FAMILIES.txt C1_POOL.txt RESULT.txt WINDOWS.txt;do
  [ -s "$out/clone-w512-2g/$f" ] || fail "C1 metrics missing $f"
  cp "$out/clone-w512-2g/$f" "$runroot/$f"
done
# C1 is an unreleased DEVELOPMENT implementation, not a competition
# between historical performance experiments. The only success criteria
# here are signed data, five-family relational correctness and clean SQL
# shutdown. The historical P5/P6 receipts above only pin the original input.
cat "$runroot/C1_PLAN.txt"
cat "$runroot/C1_FAMILIES.txt"
cat "$runroot/C1_CONTINUOUS_FAMILIES.txt"
cat "$runroot/C1_POOL.txt"
elapsed=$(sed -n 's/.*committed_window_time=\([^ ]*\).*/\1/p' "$runroot/RESULT.txt")
seconds=$(awk -v t="$elapsed" 'BEGIN{
  n=split(t,a,"m");if(n!=2)exit 1
  sub(/s$/,"",a[2]);if(a[1]<0||a[2]<0)exit 1
  printf "%.3f",a[1]*60+a[2]
}') || fail 'C1 reported an invalid duration'
records=$(sed -n 's/.* new_records=\\([0-9]*\\) .*/\\1/p' "$runroot/C1_PLAN.txt")
bytes=$(sed -n 's/.* new_source_bytes=\\([0-9]*\\) .*/\\1/p' "$runroot/C1_PLAN.txt")
lastbatch=$(sed -n 's/.* last_batch=\\([0-9]*\\) .*/\\1/p' "$runroot/C1_PLAN.txt")
[ -n "$records" ] && [ -n "$bytes" ] && [ -n "$lastbatch" ] || fail 'signed 8GiB counts missing'
rate=$(awk -v t="$seconds" -v r="$records" 'BEGIN{if(t<=0||r<=0)exit 1;printf "%.2f",r/t}') ||
  fail 'C1 reported an invalid throughput'
printf 'FI C1 EIGHT GIB THROUGHPUT records=%s source_bytes=%s group_gib=%s elapsed_seconds=%s records_per_second=%s shared_sql_workers_max=%s last_batch=%s\n' "$records" "$bytes" "$group" "$seconds" "$rate" "$sqlmax" "$lastbatch"
printf 'FI C1 EIGHT GIB INTEGRATION PASS group_gib=%s records=%s source_bytes=%s last_batch=%s sql_families=5 shared_sql_workers_max=%s source_parent_writers=1 seed_unchanged=true clean_start=true source_staging=none authoritative=0 published=0 output=%s\n' "$group" "$records" "$bytes" "$lastbatch" "$sqlmax" "$runroot"
