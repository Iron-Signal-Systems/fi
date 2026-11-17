#!/bin/sh
# FI P7 private C220 five-real-PostgreSQL-writer control.
# NO authoritative or Accepted SQL writes. Failed attempts discarded.
# Mode: preflight | tests | p7. No database started by preflight/tests.
set -eu
umask 077
fail(){ printf 'FI P7 FIVE SQL STOP: %s\n' "$*" >&2; exit 1; }
[ "$(id -un)" = root ] && [ "$(hostname -s)" = c220 ] &&
[ "$#" -eq 2 ] ||
    fail 'usage root@c220: sh controller preflight|tests|p8 20261115T153532Z'
case "$1" in preflight|tests|p8) mode=$1;;*) fail 'unsupported mode';;esac
[ "$2" = 20261115T153532Z ] ||
    fail 'only the previously accepted signed W512 seed is allowed'
repo=/home/jwood/fi-w512-c220-stage
sourcepin=fa63946a468428ce32b3799490764b0744eff469
testrunnerpin=486a1251ade3386a845bfff1c2254d7d62e41684
runnerpin=d9cce7cb07e9b2bce778e8c71f15d8fabcef6915
testpath=go/cmd/fi-backlog-recover/run_private_p7_five_sql_compile_c220_host.sh
runpath=go/cmd/fi-backlog-recover/run_private_five_sql_w512_c220_host.sh
p5=/var/tmp/fi-window-chunks-family-p3-20261116T123717Z
p5archive="$p5/fi-w512-family-p3-pilot2-20261116T123717Z.tar.gz"
p5sha=7f8f1fadfe8bc48529dfffc654fd08fd06aed5ac767d480a52bf99d2f52e184a
p6=/var/tmp/fi-window-chunks-family-p3-20261116T230127Z
p6archive="$p6/fi-w512-family-p3-pilot2-20261116T230127Z.tar.gz"
p6sha=f8b28076c610f26bab85959db17d3ce3dae4d30753dfed622764f8da20edaa91
[ -s "$p5archive" ] && [ "$(sha256 -q "$p5archive")" = "$p5sha" ] &&
[ -s "$p6archive" ] && [ "$(sha256 -q "$p6archive")" = "$p6sha" ] ||
    fail 'accepted P5 or P6 metrics archive absent/changed'
[ -s "$p5/SUMMARY.txt" ] && [ -s "$p6/SUMMARY.txt" ] ||
    fail 'accepted P5/P6 SQL acceptance summaries absent'
grep -Fxq 'FI C220 W512 PERSISTENT P5 TWO-WINDOW ACCEPTED windows=2 new_records=997434 elapsed=3m57.995s min_workers=2 max_workers=16 max_slots=80 credits=32 writer=1 authoritative=0 accepted=0' "$p5/SUMMARY.txt" ||
    fail 'P5 baseline changed'
grep -Fxq 'FI C220 W512 ATOMIC FAMILY P6 TWO-WINDOW ACCEPTED windows=2 new_records=997434 elapsed=4m7.626s min_workers=2 max_workers=16 max_slots=80 credits=32 writer=1 authoritative=0 accepted=0' "$p6/SUMMARY.txt" ||
    fail 'P6 baseline changed'
for p in "$p5" "$p6"; do
    grep -Fxq 'FI W512 SIGNED READBACK PASS batches=431 byte_identical=true manifests_identical=true' "$p/SUMMARY.txt" ||
        fail "control $p lost signed custody readback"
done
for pin in "$sourcepin" "$testrunnerpin" "$runnerpin";do
    jexec -U jwood fi-dev git -C "$repo" cat-file -e "$pin^{commit}" ||
        fail "pinned source/test/runner unavailable $pin"
done
runroot=/var/tmp/fi-w512-five-sql-p7-$(date -u '+%Y%m%dT%H%M%SZ')
[ ! -e "$runroot" ] && [ ! -L "$runroot" ] ||
    fail 'private P7 control output already exists'
mkdir -m 0700 "$runroot"
testscript="$runroot/pinned-p7-go-race-tests.sh"
runner="$runroot/pinned-p7-five-w512.sh"
jexec -U jwood fi-dev git -C "$repo" show "$testrunnerpin:$testpath" > "$testscript" ||
    fail 'exact pinned P7 Go/race tests missing'
jexec -U jwood fi-dev git -C "$repo" show "$runnerpin:$runpath" > "$runner" ||
    fail 'exact pinned P7 W512 SQL runner missing'
chmod 0700 "$testscript" "$runner"
sh -n "$testscript" && sh -n "$runner" ||
    fail 'pinned P7 test or SQL runner is not valid POSIX shell'
grep -Fxq "sourcepin=$sourcepin" "$testscript" &&
grep -Fxq "sourcecommit=$sourcepin" "$runner" ||
    fail 'P7 source pin disagrees across C220 runners'
grep -Fq 'go127 test -race' "$testscript" &&
grep -Fq 'TestPrivateP[78]' "$testscript" &&
grep -Fq 'FI P8 SAME-PROCESS ARTIFACT REUSE PASS' "$runner" &&
grep -Fq 'FI W512 P7 SIGNED CANONICAL SHA PASS' "$runner" &&
grep -Fq 'sha_once_shortcut=disabled' "$runner" &&
grep -Fq 'FI W512 P7 SOURCE CHECKPOINT CHAIN PASS' "$runner" &&
grep -Fq 'P7_SOURCE_CHAIN.txt' "$runner" &&
grep -Fq 'FI W512 P7 PHYSICAL SIGNED STAGE PASS' "$runner" &&
grep -Fq 'P7_MATERIALIZED_WINDOWS.txt' "$runner" &&
grep -Fq 'FI W512 P7 REAL FIVE PG WRITERS PASS' "$runner" &&
grep -Fq 'SELECT rolname FROM pg_catalog.pg_roles WHERE rolsuper AND rolcanlogin' "$runner" &&
grep -Fq 'FI P7 PRIVATE CLONE SETTINGS ACCESS PASS' "$runner" &&
grep -Fq 'GRANT pg_read_all_settings TO fi_ingest' "$runner" &&
grep -Fq 'clone_ingest_path' "$runner" &&
grep -Fq 'FI P7 VERIFIED NATIVE FILE SOURCE AND BULK REUSE PASS' "$runner" &&
grep -Fq 'FI P6 FULL RELATIONAL GRAPH PASS' "$runner" &&
grep -Fq 'FI W512 SIGNED READBACK PASS' "$runner" ||
    fail 'required Go, 5 SQL writer, relational/FK, File, or signature gates missing'
grep -Fxq 'port=55983' "$runner" || fail 'unexpected P7 relay port'
export FI_W512_P7_SQL_WRITERS=5
export FI_W512_P6_FAMILY_SQL=1
export FI_W512_P5_PERSISTENT=1
export FI_W512_P3_DYNAMIC_MIN=2
export FI_W512_P3_DYNAMIC_MAX=16
unset FI_W512_P3_SECURITY_WORKERS FI_W512_P3_GENERAL_WORKERS
sh "$runner" preflight "$2" ||
    fail 'P7 source/authentication/patcher preflight failed'
printf 'FI C220 P7 PINNED PREFLIGHT PASS source=%s runner=%s tests=%s signed_seed_unchanged=true postgres_started=false\n' "$sourcepin" "$runnerpin" "$testrunnerpin"
[ "$mode" = preflight ] && exit 0
# Go tests run only in an isolated private Go copy. Do NOT allocate a
# new PostgreSQL clone if compile/race/unit tests do not all pass.
sh "$testscript" tests ||
    fail 'P7 five writer Go compiler, race or signed P6 regression tests failed'
printf 'FI C220 P7 NO-SQL UNIT/RACE GATE PASS postgres_started=false\n'
[ "$mode" = tests ] && exit 0
log="$runroot/P7.console.txt"
status="$runroot/P7.exit"
( if sh "$runner" family "$2";then
    printf '0\n' > "$status"
  else
    printf '1\n' > "$status"
  fi ) 2>&1 | tee "$log"
[ -s "$status" ] && [ "$(cat "$status")" = 0 ] ||
    fail 'P7 W512 five-writer SQL, relational or signed acceptance failed'
receipt=$(grep '^FI W512 PILOT FINISHED exit=0 outputs=' "$log" | tail -n 1)
[ -n "$receipt" ] || fail 'P7 no clean SQL clone shutdown receipt'
out=$(printf '%s\n' "$receipt" |
    sed -n 's/.* outputs=\([^ ]*\) private_clone=.*/\1/p')
case "$out" in /var/tmp/fi-window-chunks-family-p3-*) :;;
    *) fail 'P7 clone output path not in private experiment namespace';;
esac
summary="$out/SUMMARY.txt"
[ -s "$summary" ] || fail 'P7 SQL run summary missing'
for expected in \
    'FI P8 SAME-PROCESS ARTIFACT REUSE PASS windows=2 signed_batches=431 records=997434 full_data_rehashes_avoided=8 historical_sql_source_scan=retained original_sha=retained' \
    'FI W512 P7 SIGNED CANONICAL SHA PASS windows=2 signed_batches=431 sha_once_shortcut=disabled canonical_sha256=every_batch original_manifest=unchanged' \
    'FI W512 P7 SOURCE CHECKPOINT CHAIN PASS windows=2 artifact_markers=2 source_markers=2 signed_batches=431 records=997434' \
    'FI W512 P7 PHYSICAL SIGNED STAGE PASS windows=2 signed_batches=431 records=997434 original_cache_unchanged=true' \
    'FI W512 SIGNED READBACK PASS batches=431 byte_identical=true manifests_identical=true' \
    'FI P6 FULL RELATIONAL GRAPH PASS supported_kinds=13 missing_typed=0 unvalidated_fks=0' \
    'FI W512 P7 FIVE SQL FAMILY HANDOFFS PASS windows=2 families=5 records=997434 source_ledger=durable sql_writers=5' \
    'FI W512 P7 REAL FIVE PG WRITERS PASS windows=2 independent_backends=5 per_window_family_receipts=10 records=997434 typed_marker=atomic' \
    'FI P7 VERIFIED NATIVE FILE SOURCE AND BULK REUSE PASS windows=2 validated=104830 reused=104830 sql_writers=5' \
    'FI W512 P5 PERSISTENT WINDOWS PASS windows=2 signed_records=997434 persistent_across_batches=true window_pools_closed=true'
do
    grep -Fxq "$expected" "$summary" ||
        fail "P7 required SQL, FK, source or signed proof missing: $expected"
done
accepted=$(grep '^FI C220 W512 FIVE WRITER P7 TWO-WINDOW ACCEPTED ' "$summary" | tail -n 1)
[ -n "$accepted" ] ||
    fail 'five SQL writers did not produce the accepted private W512 receipt'
printf '%s\n' "$accepted" |
    grep -Fq 'windows=2 new_records=997434 ' ||
    fail 'P7 original signed records mismatch'
printf '%s\n' "$accepted" |
    grep -Fq 'min_workers=2 max_workers=16 max_slots=80 credits=32 writer=5 authoritative=0 accepted=0' ||
    fail 'P7 five SQL writers or SoR isolation failed'
for file in P7_MATERIALIZED_WINDOWS.txt P8_REUSED.txt P7_SOURCE_CHAIN.txt P7_SQL_FAMILIES.txt P7_PUBLISHED.txt P6_FILE_VALIDATION.txt \
    P6_FAMILY_HANDOFFS.txt STAGES.txt WINDOWS.txt SIGNED_BATCHES.txt P5_WINDOW_LANES.tsv \
    FAMILY_DYNAMIC_SUMMARY.tsv FAMILY_LANE_SUMMARY.tsv W512_CHECKPOINTS.tsv
do
    [ -s "$out/clone-w512-2g/$file" ] ||
        fail "missing P7 source, PostgreSQL or five-family metrics: $file"
    cp "$out/clone-w512-2g/$file" "$runroot/$file"
done
elapsed=$(printf '%s\n' "$accepted" |
    sed -n 's/.* elapsed=\([^ ]*\) min_workers=.*/\1/p')
secs=$(awk -v elapsed="$elapsed" 'BEGIN{
    parts=split(elapsed,a,"m");if(parts!=2)exit 1
    sub(/s$/,"",a[2]);if(a[1]<0||a[2]<0)exit 1
    printf "%.3f",a[1]*60+a[2]
}') || fail 'invalid P7 elapsed time'
rps=$(awk -v sec="$secs" 'BEGIN{if(sec<=0)exit 1;printf "%.3f",997434/sec}') ||
    fail 'invalid P7 throughput'
{
    printf 'experiment\twriters\trecords\tseconds\trecords_per_sec\n'
    printf 'P5_persistent\t1\t997434\t237.995\t4190.987\n'
    printf 'P6_single_writer\t1\t997434\t247.626\t4027.986\n'
    printf 'P7_five_writers\t5\t997434\t461.391\t2161.798\n'
    printf 'P8_artifact_evidence\t5\t997434\t%s\t%s\n' "$secs" "$rps"
} > "$runroot/P5_P6_P7_P8_COMPARISON.tsv"
printf '%s\n' "$out" > "$runroot/PRIVATE_SQL_OUTPUT_PATH"
echo '===== MATCHED P5 / P6 / P7 / P8 TWO-WINDOW RESULTS ====='
cat "$runroot/P5_P6_P7_P8_COMPARISON.tsv"
echo '===== P8 PER-WINDOW PHASE TIMING ====='
cat "$runroot/STAGES.txt" "$runroot/WINDOWS.txt"
echo '===== P7 FIVE ACTUAL POSTGRESQL FAMILY WRITERS ====='
cat "$runroot/P7_SQL_FAMILIES.txt"
printf 'FI C220 P8 FIVE PG SQL PRIVATE ACCEPTED windows=2 source_batches=431 records=997434 writers=5 authoritative=0 accepted=0 output=%s\n' "$runroot"
