#!/bin/sh
# FI P6 W512: independent relational-family SQL, matched signed P5 control.
# Run ONLY root@c220. Private clone; NEVER SoR or Accepted publication.
set -eu
umask 077
fail(){ printf 'FI P6 W512 STOP: %s\n' "$*" >&2; exit 1; }
[ "$(id -un)" = root ] && [ "$(hostname -s)" = c220 ] &&
[ "$#" -eq 2 ] || fail 'usage: sh controller preflight|p6 20261115T153532Z'
case "$1" in preflight|p6) mode=$1;; *) fail 'unsupported mode';; esac
[ "$2" = 20261115T153532Z ] || fail 'unexpected signed W512 seed'
control=/var/tmp/fi-window-chunks-family-p3-20261116T123717Z
archive="$control/fi-w512-family-p3-pilot2-20261116T123717Z.tar.gz"
sha=7f8f1fadfe8bc48529dfffc654fd08fd06aed5ac767d480a52bf99d2f52e184a
[ -s "$archive" ] && [ -s "$control/SUMMARY.txt" ] &&
[ "$(sha256 -q "$archive")" = "$sha" ] ||
    fail 'accepted P5 signed comparison archive absent or SHA256 changed'
grep -Fxq 'FI W512 SIGNED READBACK PASS batches=431 byte_identical=true manifests_identical=true' "$control/SUMMARY.txt" ||
    fail 'P5 signed bytes and manifests receipt missing'
grep -Fxq 'FI C220 W512 PERSISTENT P5 TWO-WINDOW ACCEPTED windows=2 new_records=997434 elapsed=3m57.995s min_workers=2 max_workers=16 max_slots=80 credits=32 writer=1 authoritative=0 accepted=0' "$control/SUMMARY.txt" ||
    fail 'P5 typed SQL acceptance receipt changed'
repo=/home/jwood/fi-w512-c220-stage
sourcepin=5309fcf6c99f27cfcd23602de8abd3c5c06d0c30
runnerpin=22f8a7cc150fcc156d257b461dccce5abeba9017
runner_path=go/cmd/fi-backlog-recover/run_private_family_w512_c220_p3_host.sh
jexec -U jwood fi-dev git -C "$repo" cat-file -e "$sourcepin^{commit}" ||
    fail 'pinned 8-module P6 source unavailable'
jexec -U jwood fi-dev git -C "$repo" cat-file -e "$runnerpin^{commit}" ||
    fail 'pinned P6 W512 host runner unavailable'
root=/var/tmp/fi-w512-atomic-p6-$(date -u '+%Y%m%dT%H%M%SZ')
[ ! -e "$root" ] && [ ! -L "$root" ] ||
    fail 'P6 output root already exists'
mkdir -m 0700 "$root"
runner="$root/pinned-p6-w512-runner.sh"
jexec -U jwood fi-dev git -C "$repo" show "$runnerpin:$runner_path" > "$runner" ||
    fail 'pinned host runner extraction failed'
chmod 0700 "$runner"
sh -n "$runner" || fail 'host runner shell syntax invalid'
grep -Fxq "sourcecommit=$sourcepin" "$runner" ||
    fail 'P6 runner source and controller pins do not match'
grep -Fq 'FI P6 FULL RELATIONAL GRAPH PASS' "$runner" &&
grep -Fq 'P6_FAMILY_HANDOFFS.txt' "$runner" &&
grep -Fq 'go127 test -race' "$runner" &&
grep -Fq 'FI W512 SIGNED READBACK PASS' "$runner" ||
    fail 'SQL FK, 5-family, Go race or signed gates not present'
grep -Fxq 'port=55983' "$runner" || fail 'unexpected PostgreSQL relay port'
export FI_W512_P5_PERSISTENT=1
export FI_W512_P6_FAMILY_SQL=1
export FI_W512_P3_DYNAMIC_MIN=2
export FI_W512_P3_DYNAMIC_MAX=16
unset FI_W512_P3_SECURITY_WORKERS FI_W512_P3_GENERAL_WORKERS
sh "$runner" preflight "$2" ||
    fail 'read-only signed source, patcher or reporter preflight failed'
if [ "$mode" = preflight ]; then
    printf 'FI C220 P6 PREFLIGHT PASS source_pin=%s sql_modules=5 writer=1 seed_unchanged=true no_postgres_started=true\n' "$sourcepin"
    exit 0
fi
log="$root/P6.console.txt"
status="$root/P6.exit"
( if sh "$runner" family "$2";then printf '0\n' > "$status";else
    printf '1\n' > "$status";fi ) 2>&1 | tee "$log"
[ -s "$status" ] && [ "$(cat "$status")" = 0 ] ||
    fail 'P6 failed source/SQL/Go race/relational family or signed readback acceptance'
receipt=$(grep '^FI W512 PILOT FINISHED exit=0 outputs=' "$log" | tail -n 1)
[ -n "$receipt" ] || fail 'P6 SQL clone did not terminate cleanly'
output=$(printf '%s\n' "$receipt" |
    sed -n 's/.* outputs=\([^ ]*\) private_clone=.*/\1/p')
case "$output" in /var/tmp/fi-window-chunks-family-p3-*) :;;
    *) fail 'unexpected clone output path';;
esac
summary="$output/SUMMARY.txt"
[ -s "$summary" ] || fail 'P6 typed SQL summary missing'
grep -Fxq 'FI W512 SIGNED READBACK PASS batches=431 byte_identical=true manifests_identical=true' "$summary" ||
    fail 'P6 signed payload/manifest readback not byte-identical'
grep -Fxq 'FI W512 P6 ATOMIC FAMILY HANDOFFS PASS windows=2 families=5 records=997434 source_ledger=ordered sql_writers=1' "$summary" ||
    fail 'P6 source ledger and all five SQL families not accepted'
grep -Fxq 'FI P6 FULL RELATIONAL GRAPH PASS supported_kinds=13 missing_typed=0 unvalidated_fks=0' "$summary" ||
    fail 'P6 complete typed relational parent/FK graph not accepted'
grep -Fxq 'FI W512 P5 PERSISTENT WINDOWS PASS windows=2 signed_records=997434 persistent_across_batches=true window_pools_closed=true' "$summary" ||
    fail 'P5 persistent preparation engines failed inside P6'
accepted=$(grep '^FI C220 W512 ATOMIC FAMILY P6 TWO-WINDOW ACCEPTED ' "$summary" | tail -n 1)
[ -n "$accepted" ] || fail 'P6 SQL atomic-window acceptance missing'
printf '%s\n' "$accepted" |
  grep -Fq 'windows=2 new_records=997434 ' ||
    fail 'P6 new record count mismatch'
printf '%s\n' "$accepted" |
  grep -Fq 'min_workers=2 max_workers=16 max_slots=80 credits=32 writer=1 authoritative=0 accepted=0' ||
    fail 'P6 wrong pool isolation or writer count'
elapsed=$(printf '%s\n' "$accepted" |
    sed -n 's/.* elapsed=\([^ ]*\) min_workers=.*/\1/p')
secs=$(awk -v elapsed="$elapsed" 'BEGIN{
    parts=split(elapsed,a,"m"); if(parts!=2)exit 1
    sub(/s$/,"",a[2]); if(a[1]<0 || a[2]<0)exit 1
    printf "%.3f",a[1]*60+a[2]
}') || fail 'P6 timing malformed'
rps=$(awk -v sec="$secs" 'BEGIN{
    if(sec<=0)exit 1
    printf "%.3f",997434/sec
}') || fail 'P6 throughput malformed'
for file in P6_SOURCE_LEDGER.txt P6_FAMILY_HANDOFFS.txt P6_WINDOWS.txt \
    P5_WINDOW_LANES.tsv FAMILY_DYNAMIC_SUMMARY.tsv FAMILY_LANE_SUMMARY.tsv \
    FAMILY_WORKER_SUMMARY.tsv W512_CHECKPOINTS.tsv; do
    [ -s "$output/clone-w512-2g/$file" ] ||
        fail "P6 required audit evidence missing: $file"
    cp "$output/clone-w512-2g/$file" "$root/$file"
done
printf '%s\n' "$output" > "$root/PRIVATE_OUTPUT_PATH"
{
    printf 'experiment\trecords\tseconds\trecords_per_sec\twriter\tfamily_modules\n'
    printf 'P5_accepted\t997434\t237.995\t4190.987\t1\toriginal\n'
    printf 'P6_atomic_family_sql\t997434\t%s\t%s\t1\t5\n' "$secs" "$rps"
} > "$root/COMPARISON.tsv"
echo '===== SAME SIGNED W512 WINDOWS: P5 vs P6 ====='
cat "$root/COMPARISON.tsv"
echo '===== P6 SQL FAMILY HANDOFF RECEIPTS ====='
cat "$root/P6_FAMILY_HANDOFFS.txt"
printf 'FI C220 P6 PRIVATE ACCEPTED windows=2 signed_batches=431 records=997434 writer=1 source_unchanged=true output=%s\n' "$root"
