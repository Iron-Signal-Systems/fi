#!/bin/sh
# Copyright (c) 2026 John Joseph Wood. All rights reserved.
# One C220 REAL receiver -> fi-sor C1 run: signed backfill, canonical SQL,
# independent original FIGT B, one Accepted. No reset or service activation.
set -eu
umask 077
fail(){ echo "FI C1 REAL END-TO-END STOP: $*" >&2;exit 1; }
if [ "$#" -eq 1 ]&&[ "$1" = --selftest ];then
  echo 'FI C1 REAL END-TO-END SELFTEST PASS sql_reset_prohibited=true services_unmodified=true'
  exit 0
fi
[ "$#" -eq 2 ] || fail 'usage: --audit|--run FULL_40_HEX_COMMIT'
mode=$1
pin=$2
case "$mode" in --audit|--run) ;; *) fail 'invalid mode';; esac
case "$pin" in *[!0123456789abcdef]*|'') fail 'invalid exact SHA';; esac
[ "${#pin}" -eq 40 ] || fail 'exact 40-character commit required'
[ "$(id -u)" -eq 0 ]&&[ "$(uname -s)" = FreeBSD ]&&
[ "$(hostname -s)" = c220 ] || fail 'root@c220 FreeBSD required'
repo=/home/jwood/fi-c1-two-process-2a449f1a
branch=dev/c1-sor-single-jail-20261124
stage_path=go/cmd/fi-backlog-recover/diagnostics/fi_c1_c220_exact_receiver_cache_backfill.sh
real_path=go/cmd/fi-backlog-recover/diagnostics/fi_c1_c220_direct_canonical_real_generation.sh
for jail in fi-dev fi-receiver fi-sor;do
  jls -j "$jail" >/dev/null 2>&1 || fail "required $jail jail missing"
done
if jls -j fi-ingest >/dev/null 2>&1;then
  fail 'retired fi-ingest jail is running'
fi
jexec -U jwood fi-dev git -C "$repo" fetch origin \
  "refs/heads/$branch:refs/remotes/origin/$branch" ||
  fail 'exact development branch fetch failed'
[ "$(jexec -U jwood fi-dev git -C "$repo" rev-parse "refs/remotes/origin/$branch")" = "$pin" ] ||
  fail 'branch head changed; never run a stale binary'
tmp=$(mktemp -d /root/fi-c1-end-to-end.XXXXXXXX) ||
  fail 'cannot create exact pinned script workspace'
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
jexec -U jwood fi-dev git -C "$repo" show "$pin:$stage_path" > "$tmp/stage"
jexec -U jwood fi-dev git -C "$repo" show "$pin:$real_path" > "$tmp/real"
[ -s "$tmp/stage" ]&&[ -s "$tmp/real" ]||
  fail 'exact-commit receiver/SoR physical scripts absent'
sh -n "$tmp/stage"
sh -n "$tmp/real"
echo "FI_C1_REAL_RUN_PIN=$pin"
echo '===== REAL SQL AND ORIGINAL SIGNED CUSTODY READ-ONLY AUDIT ====='
sh "$tmp/real" --audit "$pin" ||
  fail 'real PostgreSQL/signed-custody prestate did not pass'
if [ "$mode" = --audit ];then
  echo 'FI C1 REAL END-TO-END AUDIT PASS read_only=true postgres_untouched=true'
  exit 0
fi
echo '===== EXACT NATIVE FREEBSD RECEIVER + C1 SOR STAGING ====='
sh "$tmp/stage" --stage "$pin" ||
  fail 'exact FreeBSD build/stage failed; canonical remains untouched'
echo '===== ORIGINAL FIGT COMPLETE RECEIVER-AUTHENTICATED CACHE BACKFILL ====='
sh "$tmp/stage" --backfill "$pin" ||
  fail 'full signed transfer not authenticated; real SQL not started'
echo '===== REAL FI CANONICAL C1 SOURCEPARENT + FAMILIES + ORIGINAL B ====='
sh "$tmp/real" --run "$pin" ||
  fail 'canonical run failed; preserve evidence, never reset or blindly retry'
echo '===== COMPLETE CANONICAL SIGNED BATCH/ROW/JOURNAL READBACK ====='
result=$(jexec -U postgres fi-sor psql -X -w -v ON_ERROR_STOP=1 -At \
 -h /var/db/fi/sor/run -p 5432 -d fi -c "
SELECT g.record_count::text||'|'||g.batch_count::text||'|'||
  (SELECT count(*) FROM fi.source_batch b
   WHERE b.recorded_generation_id=g.recorded_generation_id)::text||'|'||
  (SELECT count(*) FROM fi.source_record r
   JOIN fi.source_batch b USING(source_batch_id)
   WHERE b.recorded_generation_id=g.recorded_generation_id)::text
FROM fi.recorded_generation g
WHERE g.source_id='iss-fs-22a.iss.local'
 AND g.generation_id='20261030T000032.061323100Z-3e38b2210771462c'") ||
 fail 'read-only canonical batch/row totals unavailable'
accepted=$(jexec -U postgres fi-sor psql -X -w -v ON_ERROR_STOP=1 -At \
 -h /var/db/fi/sor/run -p 5432 -d fi -c "
SELECT count(*) FROM fi.ingest_journal j
JOIN fi.recorded_generation g
 ON g.source_id=j.source_id AND g.generation_id=j.generation_id
WHERE g.source_id='iss-fs-22a.iss.local'
 AND g.generation_id='20261030T000032.061323100Z-3e38b2210771462c'
 AND j.outcome='Accepted' AND j.transfer_sha256=g.transfer_sha256
 AND j.records_committed=g.record_count") ||
 fail 'read-only original transfer Accepted journal unavailable'
[ "$result" = '15140785|8399|8399|15140785' ] &&
[ "$accepted" = 1 ] ||
 fail "incorrect real canonical coverage: $result exact_accepted=$accepted"
echo 'FI C1 FULL REAL RUN ACCEPTED PASS source_records=15140785 signed_batches=8399 receiver_signed_custody_authenticated=true B_commit_ready_relational_verified=true accepted_journal=1 no_reset=true services_unmodified=true'
