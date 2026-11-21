#!/bin/sh
# FI C1 full signed 4GiB grouped backlog with adaptive shared SQL and final private proof.
# C220 disposable PostgreSQL clone only. No P7 code or bridge.
set -eu
umask 077
fail() { printf 'FI C1 STOP: %s\n' "$*" >&2; exit 1; }
[ "$(id -un)" = root ] && [ "$(hostname -s)" = c220 ] &&
[ "$#" -eq 2 ] || fail 'usage: sh controller preflight|compile|prefix8|c1 20261115T153532Z'
case "$1" in preflight|compile|c1|prefix8) mode=$1;;*)fail 'unknown mode';;esac
[ "$2" = 20261115T153532Z ] || fail 'only pinned signed W512 seed'
# Stage 2 is only meaningful after the Stage 1 full 8GB/4MB run passes.
# Fail closed on a missing or mismatched complete private-replay receipt.
prior=${FI_C1_WAL8_BASELINE_REPORT:-}
case "$prior" in
  /var/tmp/fi-c1-pgwal8.*) ;;
  *) fail 'set FI_C1_WAL8_BASELINE_REPORT to the successful Stage 1 report directory' ;;
esac
[ -d "$prior" ] && [ ! -L "$prior" ] && [ -s "$prior/run.log" ] ||
  fail 'Stage 1 8GB/4MB full-run log is missing'
grep -Fxq 'FI C1 POSTGRES WAL A/B CANDIDATE max_wal_size=8GB wal_buffers=4MB original_full_run=1GB_4MB proof=clone_only' "$prior/run.log" &&
grep -Fxq 'FI C1 FULL GROUPED RELATIONAL PROOF PASS windows=16 signed_batches=8399 records=15140785 bytes=65205192753 typed_markers=16 source_parent_rows=15140785 authoritative=0 accepted=0 artifact_source_markers=seed_only proof=private_clone_only' "$prior/run.log" &&
grep -Fq 'FI C1 FULL BACKLOG INTEGRATION PASS group_gib=4 groups=15 records=14647307 source_bytes=63081148153 last_batch=8399 signed_batches=8399' "$prior/run.log" ||
  fail 'Stage 1 8GB/4MB full source/relational acceptance receipt not verified'
# Compare this P5 implementation against the completed 8GB/16MB run,
# not against the earlier 4MB WAL-buffer experiment.
prior16=${FI_C1_WAL16_BASELINE_REPORT:-}
case "$prior16" in /var/tmp/fi-c1-pgwal16.*) ;; *)
  fail 'set FI_C1_WAL16_BASELINE_REPORT to the successful 8GB/16MB report directory' ;;
esac
[ -d "$prior16" ] && [ ! -L "$prior16" ] && [ -s "$prior16/run.log" ] ||
  fail '8GB/16MB full-run comparator log is missing'
grep -Fxq 'FI C1 POSTGRES WAL BUFFER A/B CANDIDATE max_wal_size=8GB wal_buffers=16MB comparator=8GB_4MB proof=clone_only' "$prior16/run.log" &&
grep -Fxq 'FI C1 FULL GROUPED RELATIONAL PROOF PASS windows=16 signed_batches=8399 records=15140785 bytes=65205192753 typed_markers=16 source_parent_rows=15140785 authoritative=0 accepted=0 artifact_source_markers=seed_only proof=private_clone_only' "$prior16/run.log" &&
grep -Fq 'FI C1 FULL BACKLOG INTEGRATION PASS group_gib=4 groups=15 records=14647307 source_bytes=63081148153 last_batch=8399 signed_batches=8399' "$prior16/run.log" ||
  fail '8GB/16MB complete signed/relational comparator proof missing'
repo=/home/jwood/fi-w512-c220-stage
sourcepin=e2839176f11413c1f9dcd31186756a60e48f9563
runnerpin=39ea99725fe92eb92f1509ebad90955dcc398f2d
runnerpath=go/cmd/fi-backlog-recover/run_private_c1_full_backlog_4g_c220_host.sh
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
if [ "$mode" = prefix8 ];then
  runroot=/var/tmp/fi-c1-async-prefix8-$(date -u '+%Y%m%dT%H%M%SZ')
else
  runroot=/var/tmp/fi-c1-full-backlog-4g-$(date -u '+%Y%m%dT%H%M%SZ')
fi
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
grep -Fq 'private_c1_backpressure_test.go' "$runner" &&
grep -Fq 'private_c1_continuous_signed_stream.go' "$runner" &&
grep -Fq 'private_c1_continuous_signed_stream_test.go' "$runner" &&
grep -Fq 'private_c1_async_verify.go' "$runner" &&
grep -Fq 'private_c1_async_verify_test.go' "$runner" &&
grep -Fq 'private_c1_process_verify.go' "$runner" &&
grep -Fq 'private_c1_process_verify_test.go' "$runner" &&
grep -Fq 'go/cmd/fi-c1-verifier/main.go' "$runner" &&
grep -Fq 'C1 B PID must differ from ingestion A PID' "$runner" &&
grep -Fq 'FI C1 B HOST EXECUTABLE PREFLIGHT PASS' "$runner" &&
grep -Fq 'fi-c1-verifier.c220' "$runner" &&
grep -Fq 'private_c1_commit_ready.go' "$runner" &&
grep -Fq 'private_c1_commit_ready_test.go' "$runner" &&
grep -Fq 'private_c1_sparse_age_test.go' "$runner" &&
grep -Fq 'C1 added sparse-family SQL handoffs to schedule B' "$runner" &&
grep -Fq 'C1_COMMIT_READY.txt' "$runner" &&
grep -Fq 'C1_SQL_DRAIN.txt' "$runner" &&
grep -Fq 'C1 read-only B proof incomplete or incorrectly reported' "$runner" &&
grep -Fq 'C1_ASYNC_VERIFY.txt' "$runner" &&
grep -Fq 'C1_B_GROUPS.txt' "$runner" &&
grep -Fq 'C1_B_FINAL.txt' "$runner" &&
grep -Fq 'final_generation_proof=B' "$runner" &&
grep -Fq 'FIRST GO TEST/RACE/BUILD FAILURES' "$runner" &&
grep -Fq 'FI C1 P5 TEST CONTRACT PASS' "$runner" &&
grep -Fq 'C1_STREAM.txt' "$runner" &&
grep -Fq 'TestPrivateC1' "$runner" &&
grep -Fq 'FI C1 FULL BACKLOG SIGNED PLAN' "$runner" &&
grep -Fq 'C1_PLAN.txt' "$runner" &&
grep -Fq 'C1_POOL.txt' "$runner" &&
grep -Fq 'max_wal_size=8GB' "$runner" &&
grep -Fq 'wal_buffers=16MB' "$runner" &&
grep -Fq 'checkpointer_after.jsonl' "$runner" &&
grep -Fq 'tables_after.jsonl' "$runner" &&
grep -Fq 'FI C1 SHARED SQL POOL' "$runner" &&
grep -Fq 'FI C220 C1 DEV PASS prefix8=' "$runner" ||
  fail 'native P6 SQL or signed record acceptance scripts mismatched'
sqlmax=${FI_W512_C1_SQL_WORKERS_MAX:-32}
case "$sqlmax" in [1-9]|1[0-9]|2[0-9]|3[0-2]) ;; *) fail 'SQL worker maximum must be 1..32';; esac
group=4
export FI_C1_FULL_BACKLOG_GROUP_GIB=4
export FI_W512_C1_SQL_WORKERS_MAX="$sqlmax"
export FI_C1_PG_MAX_WAL_SIZE=8GB
export FI_C1_PG_WAL_BUFFERS=16MB
export FI_W512_P6_FAMILY_SQL=1
export FI_W512_P5_PERSISTENT=1
export FI_C1_DEV_ASYNC_VERIFY=1
if [ "$mode" = prefix8 ];then export FI_C1_DEV_PREFIX8=1;else export FI_C1_DEV_PREFIX8=0;fi
export FI_W512_P3_DYNAMIC_MIN=2
export FI_W512_P3_DYNAMIC_MAX=32
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
# Performance evidence is mandatory for the clone-only C1 experiment.
# Start the original read-only C220 telemetry BEFORE the PostgreSQL clone
# starts, then finalize it automatically even if the benchmark fails.
telemetry_script="$runroot/pinned-c1-resource-telemetry.sh"
jexec -U jwood fi-dev git -C "$repo" show \
  "$runnerpin:go/cmd/fi-backlog-recover/run_private_c1_resource_telemetry_c220.sh" \
  > "$telemetry_script" || fail 'pinned C220 resource telemetry source missing'
chmod 0700 "$telemetry_script"
sh -n "$telemetry_script" || fail 'resource telemetry shell syntax invalid'
telemetry_dir=/var/tmp/fi-c1-resources-$(date -u '+%Y%m%dT%H%M%SZ')-async
[ ! -e "$telemetry_dir" ] || fail 'resource telemetry destination already exists'
monitorpid=
finish_monitor(){
  [ -n "$monitorpid" ] || return 0
  kill -TERM "$monitorpid" 2>/dev/null || :
  wait "$monitorpid" 2>/dev/null || :
  monitorpid=
  [ -s "$telemetry_dir/host_after.txt" ] &&
  [ -s "$telemetry_dir/host_5s.txt" ] &&
  [ -s "$telemetry_dir/processes_5s.txt" ] ||
    fail 'C1 telemetry shutdown snapshots incomplete'
  tar -C /var/tmp -czf "$runroot/C1.telemetry.tar.gz" \
    "$(basename "$telemetry_dir")" ||
    fail 'C1 automated telemetry archive creation failed'
  tar -tzf "$runroot/C1.telemetry.tar.gz" >/dev/null ||
    fail 'C1 automated telemetry archive integrity failed'
  printf 'FI C1 AUTOMATED TELEMETRY CAPTURED path=%s samples=host_5s,processes_5s,zpool,disks\n' \
    "$runroot/C1.telemetry.tar.gz"
}
trap 'finish_monitor' 0
trap 'exit 130' 2
trap 'exit 143' 15
sh "$telemetry_script" "$telemetry_dir" > "$runroot/C1.telemetry.log" 2>&1 &
monitorpid=$!
ready=0
i=0
while [ "$i" -lt 25 ];do
  if [ -s "$telemetry_dir/host_5s.txt" ] &&
     [ -s "$telemetry_dir/processes_5s.txt" ];then
    ready=1
    break
  fi
  kill -0 "$monitorpid" 2>/dev/null ||
    fail 'C1 telemetry process stopped before startup'
  i=$((i+1))
  sleep 1
done
[ "$ready" = 1 ] || fail 'C1 mandatory telemetry failed startup readiness'
printf 'FI C1 AUTOMATED TELEMETRY READY path=%s before_ingest=true\n' "$telemetry_dir"
log="$runroot/C1.console.txt"
status="$runroot/C1.exit"
runner_mode=family
[ "$mode" != inject-file ] || runner_mode=inject-file
( if sh "$runner" "$runner_mode" "$2";then printf '0\n' > "$status";else printf '1\n' > "$status";fi ) 2>&1 | tee "$log"
kill -0 "$monitorpid" 2>/dev/null ||
  fail 'C1 mandatory telemetry died during the benchmark'
[ -s "$status" ] && [ "$(cat "$status")" = 0 ] ||
  fail 'native P6 adaptive SQL build, signed stream, relational or clone checks failed'
finish_monitor
trap - 0 2 15
receipt=$(grep '^FI W512 PILOT FINISHED exit=0 outputs=' "$log" | tail -n 1)
[ -n "$receipt" ] || fail 'C1 private SQL shutdown receipt missing'
out=$(printf '%s\n' "$receipt" | sed -n 's/.* outputs=\([^ ]*\) private_clone=.*/\1/p')
case "$out" in /var/tmp/fi-window-chunks-family-p3-*) :;;
 *) fail 'untrusted C1 private SQL output location';;esac
grep -Fq "FI C220 C1 DEV PASS prefix8=$FI_C1_DEV_PREFIX8 groups=" "$out/SUMMARY.txt" ||
  fail 'native shared-SQL benchmark acceptance missing'
for f in C1_READ.txt C1_BACKENDS.txt C1_FAMILIES.txt C1_PLAN.txt C1_FULL_PROOF.txt C1_COMPLETE.txt C1_PREP.txt C1_STREAM.txt C1_B_GROUPS.txt C1_B_FINAL.txt C1_COMMIT_READY.txt C1_ASYNC_VERIFY.txt C1_SQL_DRAIN.txt C1_P5_LANES.txt C1_SQL_PROFILE.txt C1_SECURITY_COPY.txt C1_CONTINUOUS_FAMILIES.txt C1_POOL.txt RESULT.txt WINDOWS.txt;do
  [ -s "$out/clone-w512-2g/$f" ] || fail "C1 metrics missing $f"
  cp "$out/clone-w512-2g/$f" "$runroot/$f"
done
# C1 is an unreleased DEVELOPMENT implementation, not a competition
# between historical performance experiments. The only success criteria
# here are signed data, five-family relational correctness and clean SQL
# shutdown. The historical P5/P6 receipts above only pin the original input.
cat "$runroot/C1_PLAN.txt"
cat "$runroot/C1_FULL_PROOF.txt"
cat "$runroot/C1_COMPLETE.txt"
cat "$runroot/C1_FAMILIES.txt"
cat "$runroot/C1_STREAM.txt"
cat "$runroot/C1_COMMIT_READY.txt"
cat "$runroot/C1_ASYNC_VERIFY.txt"
cat "$runroot/C1_SQL_DRAIN.txt"
cat "$runroot/C1_CONTINUOUS_FAMILIES.txt"
cat "$runroot/C1_POOL.txt"
wall_duration=$(sed -n 's/.* duration=\([^ ]*\).*/\1/p' "$runroot/RESULT.txt")
elapsed=$(sed -n 's/^FI C1 P6 SQL DRAIN elapsed=\([^ ]*\) .*/\1/p' "$runroot/C1_SQL_DRAIN.txt")
[ -n "$elapsed" ] || fail 'C1 ingestion SQL drain duration missing'
seconds=$(awk -v t="$elapsed" 'BEGIN {
  h=0;m=0
  if(index(t,"h")){n=split(t,a,"h");if(n!=2)exit 1;h=a[1]+0;t=a[2]}
  if(index(t,"m")){n=split(t,a,"m");if(n!=2)exit 1;m=a[1]+0;t=a[2]}
  sub(/s$/,"",t)
  if(h<0||m<0||t+0<0)exit 1
  printf "%.3f",h*3600+m*60+t
}') || fail 'C1 full reported an invalid duration'
plan_field() {
  awk -v want="$1" '
    /^FI C1 (FULL BACKLOG|EIGHT GIB) SIGNED PLAN / {
      for(i=1;i<=NF;i++) {
        n=split($i,p,"=")
        if(n==2 && p[1]==want && p[2]~/^[0-9]+$/) {
          print p[2];found=1;exit
        }
      }
    }
    END {if(!found)exit 1}
  ' "$runroot/C1_PLAN.txt"
}
records=$(plan_field new_records) || fail 'signed backlog record count missing'
bytes=$(plan_field new_source_bytes) || fail 'signed backlog byte count missing'
lastbatch=$(plan_field last_batch) || fail 'signed end batch missing'
groups=$(plan_field new_windows) || fail 'signed 4GiB group count missing'
if [ "$mode" = prefix8 ];then
  [ "$groups" = 2 ] && [ "$lastbatch" -lt 8399 ] &&
  [ "$bytes" -ge 8522825728 ] && [ "$bytes" -le 8589934592 ] ||
    fail '8GiB prefix contains wrong signed range'
  grep -Fq "groups=2 windows=3 source_records=$((493478+records)) new_records=$records source_bytes=$bytes signed_batches=$lastbatch full_generation=false" "$runroot/C1_FULL_PROOF.txt" ||
    fail '8GiB signed prefix-only proof incorrect'
else
  signed_batches=$(plan_field signed_batches) || fail 'complete signed batch count missing'
  [ "$lastbatch" = "$signed_batches" ] && [ "$groups" -gt 2 ] ||
    fail 'complete signed generation missing'
fi
# Only P5/P6 committed ingest seconds are the divisor. B verification
# and operating-system cleanup belong to separate, non-throughput clocks.
rate=$(awk -v t="$seconds" -v r="$records" 'BEGIN{if(t<=0||r<=0)exit 1;printf "%.2f",r/t}') ||
  fail 'C1 reported invalid throughput'
if [ "$mode" = prefix8 ];then
  printf 'FI C1 ASYNC 8G PREFIX THROUGHPUT records=%s source_bytes=%s group_gib=4 groups=2 ingest_seconds=%s records_per_second=%s verification_excluded=true full_generation=false\n' "$records" "$bytes" "$seconds" "$rate"
  printf 'FI C1 COMMIT-READY 8G PREFIX TEST PASS groups=2 records=%s source_bytes=%s receiver_custody_sha=true one_shot_relational_proofs=true verifier_timing_independent=true original_relational_rescans=removed all_sql_acked=true authoritative=0 accepted=0 published=0 telemetry=complete output=%s\n' "$records" "$bytes" "$runroot"
else
  printf 'FI C1 FULL BACKLOG THROUGHPUT records=%s source_bytes=%s group_gib=4 groups=%s ingest_seconds=%s records_per_second=%s verification_excluded=true shared_sql_workers_max=%s last_batch=%s\n' "$records" "$bytes" "$groups" "$seconds" "$rate" "$sqlmax" "$lastbatch"
  printf 'FI C1 ASYNC RELATIONAL VERIFIER CANDIDATE max_wal_size=8GB wal_buffers=16MB comparator=continuous_p5_previous_run read_only=true final_marker_unchanged=true proof=clone_only\n'
  printf 'FI C1 FULL BACKLOG INTEGRATION PASS group_gib=4 groups=%s records=%s source_bytes=%s last_batch=%s signed_batches=%s shared_sql_workers_max=%s source_parent_writers=1 seed_unchanged=true clean_start=true typed_full=true artifact_source_markers=seed_only private_clone_only=true authoritative=0 published=0 output=%s\n' "$groups" "$records" "$bytes" "$lastbatch" "$signed_batches" "$sqlmax" "$runroot"
fi
