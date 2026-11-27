#!/bin/sh
# FI W512 C220: accepted A8 versus 8 Security + four workers per other family.
# 32 global in-flight records, one SQL writer, same authenticated W512 seed.
# Every benchmark write targets the existing runner's isolated private clone.
set -eu
umask 077
fail(){ printf 'FI W512 GENERAL FOUR STOP: %s\n' "$*" >&2; exit 1; }
[ "$(id -un)" = root ] && [ "$(hostname -s)" = c220 ] && [ "$#" -eq 2 ] ||
  fail 'usage: sh script preflight|baseline 20261115T153532Z'
case "$1" in preflight|baseline) mode=$1;; *) fail 'invalid mode';; esac
[ "$2" = 20261115T153532Z ] || fail 'wrong accepted signed W512 seed'
repo=/home/jwood/fi-w512-c220-stage
sourcepin=4d80ce2ce03e73dbff7c8637a5226a6a18a12311
runnerpin=7a0702f94bac17810a2495ca1948c47e26f17249
rpath=go/cmd/fi-backlog-recover/run_private_family_w512_c220_p3_host.sh
control=/var/tmp/fi-window-chunks-family-p3-20261116T104459Z
controlbundle="$control/fi-w512-family-p3-pilot2-20261116T104459Z.tar.gz"
controlhash=e25589dd23cbd50514b613cee35ff37760f818eb32942a884d0dee83583a8895
[ -s "$controlbundle" ] && [ -s "$control/clone-w512-2g/FAMILY_LANE_SUMMARY.tsv" ] ||
  fail 'accepted A8 reference bundle or family metrics missing'
[ "$(sha256 -q "$controlbundle")" = "$controlhash" ] ||
  fail 'accepted A8 metrics bundle SHA differs'
grep -Fq 'FI W512 SIGNED READBACK PASS batches=431 byte_identical=true manifests_identical=true' "$control/SUMMARY.txt" ||
  fail 'accepted A8 signed readback receipt missing'
grep -Fq 'FI C220 W512 SECURITY SWEEP TWO-WINDOW ACCEPTED windows=2 new_records=997434 elapsed=4m6.481s family_workers=16 security_workers=8 general_workers=8 credits=32 writer=1 authoritative=0 accepted=0' "$control/SUMMARY.txt" ||
  fail 'accepted A8 SQL acceptance receipt missing'
jexec -U jwood fi-dev git -C "$repo" cat-file -e "$sourcepin^{commit}" ||
  fail 'pinned candidate source unavailable'
jexec -U jwood fi-dev git -C "$repo" cat-file -e "$runnerpin^{commit}" ||
  fail 'pinned candidate host runner unavailable'
outroot=/var/tmp/fi-w512-general-four-$(date -u '+%Y%m%dT%H%M%SZ')
[ ! -e "$outroot" ] && [ ! -L "$outroot" ] || fail 'output already exists'
mkdir -m 0700 "$outroot"
runner="$outroot/c220-pinned-runner.sh"
jexec -U jwood fi-dev git -C "$repo" show "$runnerpin:$rpath" > "$runner" ||
  fail 'pinned benchmark runner unavailable'
chmod 0700 "$runner"
sh -n "$runner" || fail 'runner syntax'
grep -Fxq "sourcecommit=$sourcepin" "$runner" || fail 'runner source pin inconsistent'
grep -Fxq "port=55983" "$runner" || fail 'relay port incompatible'
grep -Fq 'FI W512 SIGNED READBACK PASS' "$runner" ||
  fail 'signed readback gate unexpectedly absent'
grep -Fq 'FAMILY_WORKER_SUMMARY.tsv' "$runner" ||
  fail 'family-level metrics unexpectedly absent'
export FI_W512_P3_SECURITY_WORKERS=8
export FI_W512_P3_GENERAL_WORKERS=16
sh "$runner" preflight "$2" || fail '4-each source/fixture/shell preflight failed'
if [ "$mode" = preflight ]; then
  printf 'FI W512 GENERAL FOUR PREFLIGHT PASS security=8 file=4 coverage=4 usn=4 other=4 total=24 credits=32 writer=1 control=A8 no_database_started=true\n'
  exit 0
fi
log="$outroot/BASELINE.console.txt"
status="$outroot/BASELINE.exit"
# Preserve original process status across the display pipe.
( if sh "$runner" family "$2"; then echo 0 > "$status"; else echo 1 > "$status"; fi ) 2>&1 | tee "$log"
[ -s "$status" ] && [ "$(cat "$status")" = 0 ] ||
  fail 'new clone benchmark did not pass all original gates'
receipt=$(grep '^FI W512 PILOT FINISHED exit=0 outputs=' "$log" | tail -n 1)
[ -n "$receipt" ] || fail 'new clone did not shut down cleanly'
output=$(printf '%s\n' "$receipt" |
  sed -n 's/.* outputs=\([^ ]*\) private_clone=.*/\1/p')
case "$output" in /var/tmp/fi-window-chunks-family-p3-*) :;;
  *) fail 'unrecognized private clone output';;
esac
[ -s "$output/SUMMARY.txt" ] || fail 'new private SQL acceptance summary missing'
grep -Fq 'FI W512 SIGNED READBACK PASS batches=431 byte_identical=true manifests_identical=true' "$output/SUMMARY.txt" ||
  fail 'new signed readback failed'
grep -Fq 'FI W512 FAMILY BREAKDOWN PASS windows=2 signed_batches=431 families=5 workers=24 records=997434' "$output/SUMMARY.txt" ||
  fail 'new family breakdown incomplete'
accepted=$(grep '^FI C220 W512 GENERAL FOUR TWO-WINDOW ACCEPTED ' "$output/SUMMARY.txt" | tail -n 1)
[ -n "$accepted" ] || fail 'new SQL acceptance absent'
printf '%s\n' "$accepted" |
  grep -Fq 'windows=2 new_records=997434 ' ||
  fail 'new SQL accepted incorrect record count'
printf '%s\n' "$accepted" |
  grep -Fq 'family_workers=24 security_workers=8 general_workers=16 credits=32 writer=1 authoritative=0 accepted=0' ||
  fail 'new accepted topology or clone isolation incorrect'
elapsed=$(printf '%s\n' "$accepted" |
  sed -n 's/.* elapsed=\([^ ]*\) family_workers=.*/\1/p')
secs=$(awk -v elapsed="$elapsed" 'BEGIN{
  parts=split(elapsed,a,"m"); if(parts!=2)exit 1
  sub(/s$/,"",a[2]); if(a[1]<0 || a[2]<0)exit 1
  printf "%.3f",a[1]*60+a[2]
}') || fail 'new timing unavailable'
rps=$(awk -v seconds="$secs" 'BEGIN{
  if(seconds<=0)exit 1
  printf "%.3f",997434/seconds
}') || fail 'new throughput invalid'
cmp="$outroot/COMPARISON.tsv"
printf 'run\tsecurity_workers\tfile_workers\tcoverage_workers\tusn_workers\tother_workers\tinflight\twriter\trecords\telapsed_seconds\trecords_per_second\n' > "$cmp"
printf 'A8\t8\t2\t2\t2\t2\t32\t1\t997434\t246.481\t4046.697\n' >> "$cmp"
printf 'G4\t8\t4\t4\t4\t4\t32\t1\t997434\t%s\t%s\n' "$secs" "$rps" >> "$cmp"
family="$outroot/FAMILY_COMPARISON.tsv"
printf 'run\tfamily\tworkers\trecords\tbytes\tprepare_worker_seconds\tinput_wait_worker_seconds\toutput_wait_worker_seconds\tpeak_queue_depth\n' > "$family"
for label in A8 G4; do
  if [ "$label" = A8 ]; then folder="$control"; else folder="$output"; fi
  [ -s "$folder/clone-w512-2g/FAMILY_LANE_SUMMARY.tsv" ] ||
    fail "$label family summary unavailable"
  awk -v label="$label" 'NR>1{print label "\t" $0}' \
    "$folder/clone-w512-2g/FAMILY_LANE_SUMMARY.tsv" >> "$family"
done
printf '%s\n' "$output" > "$outroot/NEW_PRIVATE_OUTPUT.txt"
echo '===== MATCHED A8 VS FOUR-EACH COMPARISON ====='
cat "$cmp"
echo '===== ALL FIVE FAMILY BREAKDOWNS ====='
cat "$family"
printf 'FI C220 GENERAL FOUR BASELINE ACCEPTED windows=2 records=997434 signed_batches=431 source_unchanged=true authoritative=0 accepted=0 output=%s\n' "$outroot"
