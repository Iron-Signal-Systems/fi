#!/bin/sh
# FI W512 C220 P5: persistent priority-fill 2..16 prep workers/family per W512 window.
# Private PostgreSQL ONLY, same signed seed and unchanged H16 SQL writer.
set -eu
umask 077
fail(){ printf 'FI C220 PERSISTENT P5 STOP: %s\n' "$*" >&2; exit 1; }
[ "$(id -un)" = root ] && [ "$(hostname -s)" = c220 ] &&
[ "$#" -eq 2 ] || fail 'usage: sh controller preflight|persistent 20261115T153532Z'
case "$1" in preflight|persistent) mode=$1 ;; *) fail 'unknown persistent P5 mode' ;; esac
[ "$2" = 20261115T153532Z ] || fail 'signed W512 source seed mismatch'
# Freeze the accepted P4 comparison input, not just a printed number.
control=/var/tmp/fi-window-chunks-family-p3-20261116T115151Z
controlbundle="$control/fi-w512-family-p3-pilot2-20261116T115151Z.tar.gz"
controlsha=9bbbba5dd9376eefb75c98a3bd5f6f878f7bbb0e3b25966195b0647a47a9923e
[ -s "$controlbundle" ] && [ -s "$control/SUMMARY.txt" ] &&
[ "$(sha256 -q "$controlbundle")" = "$controlsha" ] ||
  fail 'accepted P4 baseline metrics bundle missing or SHA256 differs'
grep -Fxq 'FI W512 SIGNED READBACK PASS batches=431 byte_identical=true manifests_identical=true' "$control/SUMMARY.txt" ||
  fail 'accepted P4 source signature/readback receipt absent'
grep -Fxq 'FI C220 W512 DYNAMIC P4 TWO-WINDOW ACCEPTED windows=2 new_records=997434 elapsed=4m0.984s min_workers=2 max_workers=16 max_slots=80 credits=32 writer=1 authoritative=0 accepted=0' "$control/SUMMARY.txt" ||
  fail 'accepted P4 SQL/typed/batch baseline receipt differs'
repo=/home/jwood/fi-w512-c220-stage
sourcepin=9ba8c9ea309747d9203424aa340bb72000108c32
runnerpin=21e6d6bf32964d61bb51835cd18cb28941d8fb1c
rpath=go/cmd/fi-backlog-recover/run_private_family_w512_c220_p3_host.sh
jexec -U jwood fi-dev git -C "$repo" cat-file -e "$sourcepin^{commit}" ||
  fail 'private dynamic source pin not in the C220 staging object database'
jexec -U jwood fi-dev git -C "$repo" cat-file -e "$runnerpin^{commit}" ||
  fail 'private dynamic runner pin not in the C220 staging object database'
outroot=/var/tmp/fi-w512-persistent-p5-$(date -u '+%Y%m%dT%H%M%SZ')
[ ! -e "$outroot" ] && [ ! -L "$outroot" ] || fail 'output directory collision'
mkdir -m 0700 "$outroot" || fail 'cannot allocate output'
runner="$outroot/pinned-family-p5.sh"
jexec -U jwood fi-dev git -C "$repo" show "$runnerpin:$rpath" > "$runner" ||
  fail 'cannot stage pinned runner'
chmod 0700 "$runner"
sh -n "$runner" || fail 'runner syntax failure'
grep -Fxq "sourcecommit=$sourcepin" "$runner" ||
  fail 'P5 runner does not match source pin'
grep -Fxq 'port=55983' "$runner" || fail 'only accepted relay port 55983 allowed'
grep -Fq 'FI W512 SIGNED READBACK PASS' "$runner" ||
  fail 'mandatory signed byte-identical readback missing'
grep -Fq 'P5_WINDOW_LANES.tsv' "$runner" &&
grep -Fq 'FAMILY_DYNAMIC_SUMMARY.tsv' "$runner" ||
  fail 'per-window persistent family pool report missing'
grep -Fq 'go127 test -race' "$runner" ||
  fail 'persistent worker race regression test must run before PostgreSQL'
export FI_W512_P3_DYNAMIC_MIN=2
export FI_W512_P3_DYNAMIC_MAX=16
export FI_W512_P5_PERSISTENT=1
unset FI_W512_P3_SECURITY_WORKERS FI_W512_P3_GENERAL_WORKERS
echo '===== P5 READ-ONLY SIGNED SOURCE + PERSISTENT REPORT PREFLIGHT ====='
sh "$runner" preflight "$2" ||
  fail 'read-only P5 preflight or pinned AWK fixture failed'
if [ "$mode" = preflight ]; then
  echo 'FI C220 PERSISTENT P5 PREFLIGHT ACCEPTED min_per_family=2 max_per_family=16 max_slots=80 inflight=32 sql_writers=1 no_database_started=true'
  exit 0
fi
log="$outroot/DYNAMIC.console.txt"
status="$outroot/DYNAMIC.exit"
echo '===== P5 TWO-WINDOW PRIVATE W512 REPLAY ====='
( if sh "$runner" family "$2"; then printf '0\n' > "$status"; else
    printf '1\n' > "$status"; fi ) 2>&1 | tee "$log"
[ -s "$status" ] && [ "$(cat "$status")" = 0 ] ||
  fail 'P5 did not pass SQL, Go race, telemetry, or signed readback gates'
receipt=$(grep '^FI W512 PILOT FINISHED exit=0 outputs=' "$log" | tail -n 1)
[ -n "$receipt" ] || fail 'private PostgreSQL did not shut down cleanly'
output=$(printf '%s\n' "$receipt" |
  sed -n 's/.* outputs=\([^ ]*\) private_clone=.*/\1/p')
case "$output" in /var/tmp/fi-window-chunks-family-p3-*) : ;;
  *) fail 'unexpected private clone results root' ;; esac
[ -s "$output/SUMMARY.txt" ] || fail 'SQL acceptance summary missing'
grep -Fq 'FI W512 SIGNED READBACK PASS batches=431 byte_identical=true manifests_identical=true' "$output/SUMMARY.txt" ||
  fail '431 exact signed batch identities not accepted'
grep -Fq 'FI W512 P5 DYNAMIC BATCH ACCOUNTING PASS batches=431 families=5 min=2 max=16 slots=80' "$output/SUMMARY.txt" ||
  fail 'five independent dynamic family receipts not accepted'
grep -Fq 'FI W512 P5 PERSISTENT WINDOWS PASS windows=2 signed_records=997434 persistent_across_batches=true window_pools_closed=true' "$output/SUMMARY.txt" ||
  fail 'two persistent window pools not accepted'
grep -Fq 'FI W512 FAMILY BREAKDOWN PASS windows=2 signed_batches=431 families=5 workers=80 records=997434' "$output/SUMMARY.txt" ||
  fail 'record and per-worker accounting mismatch'
accepted=$(grep '^FI C220 W512 PERSISTENT P5 TWO-WINDOW ACCEPTED ' "$output/SUMMARY.txt" | tail -n 1)
[ -n "$accepted" ] || fail 'P5 SQL and signed descriptor gates not accepted'
printf '%s\n' "$accepted" |
  grep -Fq 'windows=2 new_records=997434 ' ||
  fail 'P5 record count incorrect'
printf '%s\n' "$accepted" |
  grep -Fq 'min_workers=2 max_workers=16 max_slots=80 credits=32 writer=1 authoritative=0 accepted=0' ||
  fail 'P5 source/SQL isolation incorrect'
elapsed=$(printf '%s\n' "$accepted" |
  sed -n 's/.* elapsed=\([^ ]*\) min_workers=.*/\1/p')
seconds=$(awk -v elapsed="$elapsed" 'BEGIN{
  parts=split(elapsed,a,"m"); if(parts!=2)exit 1
  sub(/s$/,"",a[2])
  if(a[1]<0 || a[2]<0)exit 1
  printf "%.3f",a[1]*60+a[2]
}') || fail 'P5 elapsed parse invalid'
rps=$(awk -v sec="$seconds" 'BEGIN{
  if(sec<=0)exit 1
  printf "%.3f",997434/sec
}') || fail 'P5 throughput invalid'
[ -s "$output/clone-w512-2g/P5_WINDOW_LANES.tsv" ] ||
  fail 'P5 per-window worker pool breakdown missing'
[ -s "$output/clone-w512-2g/FAMILY_DYNAMIC_SUMMARY.tsv" ] ||
  fail 'P5 dynamic family summaries missing'
[ -s "$output/clone-w512-2g/FAMILY_LANE_SUMMARY.tsv" ] ||
  fail 'P5 signed family counts missing'
[ -s "$output/clone-w512-2g/FAMILY_WORKER_SUMMARY.tsv" ] ||
  fail 'P5 individual worker summaries missing'
comparison="$outroot/COMPARISON.tsv"
printf 'experiment\tsecurity_workers\tgeneral_workers\tcredits\trecords\tseconds\trecords_per_sec\n' > "$comparison"
printf 'A8_fixed\t8\t8\t32\t997434\t246.481\t4046.697\n' >> "$comparison"
printf 'P4_dynamic_2to16\t2_to_16\t2_to_16_each_family\t32\t997434\t240.984\t4139.005\n' >> "$comparison"
printf 'P5_window_persistent\t2_to_16\t2_to_16_each_family\t32\t997434\t%s\t%s\n' \
  "$seconds" "$rps" >> "$comparison"
cp "$output/clone-w512-2g/P5_WINDOW_LANES.tsv" "$outroot/P5_WINDOW_LANES.tsv"
cp "$output/clone-w512-2g/FAMILY_DYNAMIC_SUMMARY.tsv" "$outroot/FAMILY_DYNAMIC_SUMMARY.tsv"
cp "$output/clone-w512-2g/FAMILY_LANE_SUMMARY.tsv" "$outroot/FAMILY_LANE_SUMMARY.tsv"
cp "$output/clone-w512-2g/FAMILY_WORKER_SUMMARY.tsv" "$outroot/FAMILY_WORKER_SUMMARY.tsv"
printf '%s\n' "$output" > "$outroot/PRIVATE_OUTPUT_PATH"
echo '===== P5 VS ACCEPTED P4 AND A8 ====='
cat "$comparison"
echo '===== P5 PER-FAMILY PERSISTENT WORKER ACTIVITY ====='
cat "$outroot/FAMILY_DYNAMIC_SUMMARY.tsv"
printf 'FI C220 PERSISTENT P5 PRIVATE ACCEPTED windows=2 records=997434 signed_batches=431 family_lanes=5 min=2 max=16 writer=1 output=%s\n' "$outroot"
