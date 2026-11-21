#!/bin/sh
# C220 C1 full signed-backlog replay in continuous 4GiB reporting groups.
# Inherits accepted C220 H16 P2 clone, signed-source, readback and SQL gates.
# All signed-source/SQL gates preserved. No live ingest; private PG only.
# Test ONLY against an OFFLINE COPY of the validated private W512 seed.
# No W128 checkpoint, canonical SoR write or Accepted publication.
set -eu
umask 077
fail(){ printf 'FI W512 PILOT STOP: %s\n' "$*" >&2; exit 1; }
[ "$(id -un)" = root ] && [ "$(hostname -s)" = c220 ] && [ "$#" -eq 2 ] ||
    fail 'usage on root@c220: sh runner preflight|compile|family|inject-file YYYYMMDDTHHMMSSZ'
case "$1" in
  preflight|compile|family) mode=$1 ;;
  *) fail 'mode must be preflight, compile or family' ;;
esac
# P6: 5 separate SoR relational ingestion modules, same P5 preparers.
[ "${FI_W512_P6_FAMILY_SQL:-}" = 1 ] ||
    fail 'P6 requires explicit isolated SQL family redesign gate'
[ "${FI_W512_P5_PERSISTENT:-}" = 1 ] || fail 'P5 persistent worker mode must be explicitly enabled'
[ "${FI_C1_DEV_ASYNC_VERIFY:-}" = 1 ] ||
    fail 'C1 independent read-only verifier must be explicitly enabled for this clone experiment'
[ "${FI_W512_P3_DYNAMIC_MIN:-}" = 2 ] &&
[ "${FI_W512_P3_DYNAMIC_MAX:-}" = 32 ] ||
    fail 'C1 persistent P5 priority-fill requires min=2 max=32'
[ -z "${FI_W512_P3_SECURITY_WORKERS:-}" ] &&
[ -z "${FI_W512_P3_GENERAL_WORKERS:-}" ] ||
    fail 'P4 dynamic mode cannot mix with fixed worker controls'
security_workers=16
general_workers=64
general_each=16
family_workers=80  # historical P3/P4 report fixture slots; C1 P5 capacity is 5x32
sqlmax=${FI_W512_C1_SQL_WORKERS_MAX:-32}
case "$sqlmax" in
  [1-9]|1[0-9]|2[0-9]|3[0-2]) ;;
  *) fail 'C1 SQL worker maximum must be an integer between 1 and 32' ;;
esac
group=4
# Controlled Stage 2 PostgreSQL WAL-buffer A/B: 8GB max_wal_size FIXED.
# Compare separately against the proven Stage 1 8GB/4MB candidate.
# Change ONLY clone wal_buffers to 16MB; preserve all durability settings.
pg_max_wal=8GB
pg_wal_buffers=16MB
[ "${FI_C1_PG_MAX_WAL_SIZE:-8GB}" = "$pg_max_wal" ] ||
    fail 'this experimental runner requires exactly max_wal_size=8GB'
[ "${FI_C1_PG_WAL_BUFFERS:-16MB}" = "$pg_wal_buffers" ] ||
    fail 'Stage 2 WAL buffer candidate requires exactly 16MB'
[ "${FI_C1_FULL_BACKLOG_GROUP_GIB:-4}" = 4 ] ||
  fail 'C1 full signed backlog requires 4GiB groups'
prefix8=${FI_C1_DEV_PREFIX8:-0}
case "$prefix8" in 0|1) ;; *) fail 'FI_C1_DEV_PREFIX8 must be 0 or 1' ;; esac
# Same three Security changes as the measured 8GiB candidate.
# Full-backlog selection requires a separate opt-in and a complete clone.
security8=${FI_C1_SECURITY_8G_EXPERIMENT:-0}
fullcandidate=${FI_C1_SECURITY_FULL_BACKLOG_CANDIDATE:-0}
case "$security8" in 0|1) ;; *) fail 'FI_C1_SECURITY_8G_EXPERIMENT must be 0 or 1';; esac
case "$fullcandidate" in 0|1) ;; *) fail 'FI_C1_SECURITY_FULL_BACKLOG_CANDIDATE must be 0 or 1';; esac
if [ "$security8" = 1 ];then
  if [ "$prefix8" = 1 ];then
    [ "$fullcandidate" = 0 ] ||
      fail 'full-backlog candidate flag is forbidden in prefix8 mode'
  else
    [ "$fullcandidate" = 1 ] ||
      fail 'full-backlog Security candidate requires explicit opt-in'
  fi
else
  [ "$fullcandidate" = 0 ] ||
    fail 'full-backlog candidate opt-in without Security candidate'
fi
sourceprof=${FI_C1_SOURCE_PROFILE_8G:-0}
case "$sourceprof" in 0|1) ;; *) fail 'FI_C1_SOURCE_PROFILE_8G must be 0 or 1';; esac
if [ "$sourceprof" = 1 ] && { [ "$prefix8" != 1 ] || [ "$security8" != 1 ]; };then
  fail 'SourceParent profiling is limited to the optimized 8GiB private clone'
fi
# Do not leak performance switches into generic compile/race tests.
unset FI_C1_SECURITY_8G_EXPERIMENT FI_C1_SECURITY_FULL_BACKLOG_CANDIDATE FI_C1_SOURCE_PROFILE_8G
stop=0
if [ "$prefix8" = 1 ];then stop=2;fi

seedstamp=$2
case "$seedstamp" in
  ????????T??????Z) ;;
  *) fail 'seed timestamp must be YYYYMMDDTHHMMSSZ' ;;
esac
if jexec fi-ingest service fi_ingest_worker onestatus >/dev/null 2>&1; then
  fail 'live FI-ingest service running; private benchmark forbidden'
fi
if jexec fi-ingest ps -axww -o command | grep -q '[f]i-ingest-worker'; then
  fail 'live FI-ingest process running; private benchmark forbidden'
fi
seed=/home/jwood/fi-window-bench-w512-$seedstamp
seedout=/var/tmp/fi-window-chunks-h16-w512-seed-$seedstamp
cache=/fast/jails/roots/fi-dev/home/jwood/fi-w512-c220-verified-cache
seedhash=ff58478b40ca35f1f6cc5e52aa0300de6371ed58243c41f34e4f20ad6d61a319
name=clone-w512-2g
stamp=$(date -u '+%Y%m%dT%H%M%SZ')
root=/home/jwood/fi-window-bench-w512-family-p3-$stamp
out=/var/tmp/fi-window-chunks-family-p3-$stamp
# Clone-only artifact bytes must share the verified cache's ZFS filesystem.
# Keep /var/tmp only for timing, logs and AF_UNIX PostgreSQL relay sockets.
# The private signed output is a separate fresh 0700 directory on the CACHE dataset.
private_parent=/fast/jails/roots/fi-dev/home/jwood
private_root="$private_parent/fi-w512-family-clone-p3-$stamp"
# Use the relay-allowed port proven by the accepted C220 header-first P2 run.
port=55983
# Source commit is pinned before this runner was created; never build from moving HEAD.
sourcecommit=35bf436452aa8c009648ada40e3d2dbf47ca4542
jailroot=$(jls -j fi-dev path) || fail 'fi-dev missing'
devjid=$(jls -j fi-dev jid) || fail 'fi-dev JID missing'
sorjid=$(jls -j fi-sor jid) || fail 'fi-sor JID missing'
[ "$devjid" != "$sorjid" ] || fail 'SoR and dev jails match'
# NEVER connect to or interrogate authoritative SoR PostgreSQL.
existing=$(ps -axww -o pid,jid,user,rss,command | awk -v jid="$devjid" '
$2==jid && $5=="/usr/local/bin/postgres" && $6=="-D" {n++} END{print n+0}')
[ "$existing" = 0 ] || fail 'existing dev PostgreSQL postmaster; pilot not started'
[ -d "$jailroot$seed/$name/data" ] && [ ! -e "$jailroot$root" ] && [ ! -e "$out" ] ||
    fail 'W512 seed unavailable or new pilot path collides'
[ -d "$cache" ] && [ ! -L "$cache" ] || fail 'previous receiver-admitted verified cache missing'
[ -s "$seedout/fi-w512-private-seed-$seedstamp.tar.gz" ] ||
    fail 'C220 signed private seed metrics bundle missing'
[ "$(sha256 -q "$seedout/fi-w512-private-seed-$seedstamp.tar.gz")" = \
    "52d45162719f56b26fa9cda739e746bfd7da488cfabd839c9b9f311196cd40cf" ] ||
    fail 'C220 accepted seed evidence bundle SHA changed'
[ "$(sha256 -q "$jailroot$seed/fi-optfield-recover")" = \
  "$(cat "$jailroot$seed/recover.sha256")" ] ||
    fail 'C220 pinned seed executable SHA mismatch'
[ "$(sha256 -q "$jailroot$seed/fi-optfield-relay")" = \
  "$(cat "$jailroot$seed/relay.sha256")" ] ||
    fail 'C220 pinned seed SQL relay SHA mismatch'
[ "$(cat "$seedout/$name/W512_SEED_CHECKPOINT.tsv")" = "0|493478|$seedhash" ] ||
    fail 'W512 accepted seed descriptor changed'
grep -Fq 'FI W512/2G FRESH SIGNED SEED ACCEPTED windows=1 typed_records=493478 fields=6194967 authoritative=0 accepted=0' "$seedout/SUMMARY.txt" ||
    fail 'W512 accepted seed record gate missing'
jexec -U jwood fi-dev pg_ctl -D "$seed/$name/data" status >/dev/null 2>&1 &&
    fail 'W512 seed PostgreSQL must be stopped'
# The private seed contains millions of field rows. Require filesystem room
# for the apparent offline copy plus at least 8 GiB for replay WAL/index growth.
# This is intentionally conservative and runs before creating any destination.
seed_kib=$(jexec -U jwood fi-dev du -Aks "$seed/$name/data" | awk '{print $1}') ||
    fail 'cannot determine private seed apparent size'
free_kib=$(jexec -U jwood fi-dev df -Pk "$seed" | awk 'END{print $4}') ||
    fail 'cannot determine available private storage'
case "$seed_kib:$free_kib" in *[!0-9:]*|:*) fail 'invalid storage preflight figures';; esac
need_kib=$((seed_kib+268435456))
[ "$seed_kib" -gt 0 ] && [ "$free_kib" -gt "$need_kib" ] ||
    fail "insufficient space for private seed copy and 256GiB headroom (need_kib=$need_kib free_kib=$free_kib)"
printf 'FI C220 W512 P2 STORAGE PREFLIGHT PASS seed_apparent_kib=%s available_kib=%s required_kib=%s\n' "$seed_kib" "$free_kib" "$need_kib"
socket="$root/$name/socket/.s.PGSQL.$port"
rsocket="$out/pg-$name/.s.PGSQL.$port"
[ "$(printf %s "$socket" | wc -c)" -le 103 ] &&
[ "$(printf %s "$rsocket" | wc -c)" -le 103 ] || fail 'socket length exceeds FreeBSD limit'
case "$out" in /var/tmp/fi-window-chunks-*) ;; *) fail 'relay path allowlist mismatch';; esac
[ "$jailroot" = /fast/jails/roots/fi-dev ] ||
  fail 'wrong development jail filesystem'
[ -d "$cache" ] && [ ! -L "$cache" ] &&
[ "$(find "$cache" -type f -name 'batch-*.data' | wc -l | tr -d ' ')" = 8399 ] &&
[ "$(find "$cache" -type f -name verified.json | wc -l | tr -d ' ')" = 1 ] ||
  fail 'original authenticated receiver-admitted cache incomplete'
[ -d "$private_parent" ] && [ ! -L "$private_parent" ] ||
  fail 'trusted fast SSD private-artifact parent missing or symlink'
[ ! -e "$private_root" ] && [ ! -L "$private_root" ] ||
  fail 'private signed artifacts collide with a prior test: '"$private_root"
# deferredFileStat requires independent inodes on an IDENTICAL st_dev;
# compare filesystem IDs, not merely zpool names or capacity.
cache_dev=$(stat -f %d "$cache") || fail 'cannot stat signed cache filesystem'
dest_dev=$(stat -f %d "$private_parent") || fail 'cannot stat private artifact filesystem'
[ "$cache_dev" = "$dest_dev" ] ||
  fail "clone-only cache/output filesystem mismatch: cache_dev=$cache_dev dest_dev=$dest_dev"
[ "$(sysctl -n vfs.zfs.bclone_enabled)" = 1 ] ||
  fail 'ZFS block cloning disabled on C220 host'
clone_feature=$(zpool get -H -o value feature@block_cloning fast) ||
  fail 'cannot inspect fast ZFS block cloning feature'
case "$clone_feature" in active|enabled) :;; *)
  fail "fast ZFS block cloning feature unavailable: $clone_feature";; esac
[ "$(df -Pk "$private_parent" | awk 'END {print $4}')" -gt 268435456 ] ||
  fail 'fast full-backlog private artifacts need at least 256 GiB available'
printf 'FI C220 CLONE FS PREFLIGHT PASS cache_dev=%s destination_dev=%s zfs_pool=fast bclone_enabled=1 feature=%s root=%s\n' \
 "$cache_dev" "$dest_dev" "$clone_feature" "$private_root"
[ "$(df -Pk /var/tmp | awk 'END {print $4}')" -gt 8388608 ] ||
  fail 'host /var/tmp needs at least 8 GiB spare'
echo '===== VERIFY HOST C220 RECEIVER TRUST PATHS (PRIVATE BASELINE ONLY) ====='
for trustinput in \
  /work/fi-c220-20261114/ingest-config/pki/trust/fi-root-ca.crt.pem \
  /work/fi-c220-20261114/ingest-config/pki/trust/fi-batch-signing-ca.crt.pem \
  /work/fi-c220-20261114/config/receiver/pki/trust/fi-batch-signing-ca.crl.pem \
  /work/fi-c220-20261114/ingest-config/sources/iss-fs-22a.iss.local.conf
do
  [ -f "$trustinput" ] && [ -r "$trustinput" ] && [ ! -L "$trustinput" ] ||
    fail "historical FI trust input missing/unreadable: $trustinput"
done
openssl crl -in /work/fi-c220-20261114/config/receiver/pki/trust/fi-batch-signing-ca.crl.pem -noout -nextupdate ||
  fail 'cannot parse current C220 CRL'
[ -f "$jailroot$seed/optimized-source/go/internal/recordingest/generation_trust.go" ] ||
  fail 'pinned W512 original seed source missing; cannot rebuild path-only private copy'
echo 'FI C220 HISTORICAL TRUST PATH PREFLIGHT PASS C220-host-inputs=present no-host-trust-install=true'
# Local Git object database MUST contain the pinned experimental commit.
# User may safely fetch that branch before running; no network access is
# required during the private benchmark itself.
staged_git="$jailroot/home/jwood/fi-w512-c220-stage"
[ -d "$staged_git/.git" ] || fail 'C220 staging repository missing; do not use a fallback checkout'
jexec -U jwood fi-dev git -C /home/jwood/fi-w512-c220-stage cat-file -e "$sourcecommit^{commit}" 2>/dev/null ||
  fail "missing pinned family P3 commit $sourcecommit; fetch experiment/fi-family-processors-w512-20261115 into C220 staging checkout"
for asset in \
  go/internal/recordingest/security_bulk_profiles.go \
  go/internal/recordingest/security_field_profile_dual.go \
  go/internal/recordingest/security_field_profile_dual_test.go \
  go/internal/recordingest/private_canonical_spool_dispatch.go \
  go/internal/recordingest/private_canonical_spool_dispatch_test.go \
  go/cmd/fi-backlog-recover/testdata/header-first/private_header_first_p2.go \
  go/cmd/fi-backlog-recover/testdata/header-first/private_header_first_p2_test.go \
  go/cmd/fi-backlog-recover/testdata/family-p3/private_family_preparation_p3.go \
  go/cmd/fi-backlog-recover/testdata/family-p3/private_family_preparation_p3_test.go \
  go/cmd/fi-backlog-recover/testdata/family-p3/private_family_dynamic_p4.go \
  go/cmd/fi-backlog-recover/testdata/family-p3/private_family_dynamic_p4_test.go \
  go/cmd/fi-backlog-recover/testdata/family-p3/private_family_persistent_p5.go \
  go/cmd/fi-backlog-recover/testdata/family-p3/private_family_persistent_p5_test.go \
  go/cmd/fi-backlog-recover/testdata/family-p6/private_p6_family_buffers.go \
  go/cmd/fi-backlog-recover/testdata/family-p6/private_p6_family_buffers_test.go \
  go/cmd/fi-backlog-recover/testdata/family-p6/private_p6_file_proof_test.go \
  go/cmd/fi-backlog-recover/testdata/family-p6/private_p6_sql_coordinator.go \
  go/cmd/fi-backlog-recover/testdata/family-p6/private_p6_sql_security.go \
  go/cmd/fi-backlog-recover/testdata/family-p6/private_p6_sql_ntfs.go \
  go/cmd/fi-backlog-recover/testdata/family-p6/private_p6_sql_coverage.go \
  go/cmd/fi-backlog-recover/testdata/family-p6/private_p6_sql_usn.go \
  go/cmd/fi-backlog-recover/testdata/family-p6/private_p6_sql_other.go \
  go/cmd/fi-backlog-recover/patchers/security_sweep_c220/private_family_dynamic_summary.awk \
  go/cmd/fi-backlog-recover/patchers/security_sweep_c220/private_family_persistent_p5_summary.awk \
  go/cmd/fi-backlog-recover/patchers/family_p3_c220/main.go \
  go/cmd/fi-backlog-recover/testdata/c1/private_c1_family_buffers.go \
  go/cmd/fi-backlog-recover/testdata/c1/private_c1_five_sql.go \
  go/cmd/fi-backlog-recover/testdata/c1/private_c1_source_profile.go \
  go/cmd/fi-backlog-recover/testdata/c1/private_c1_source_profile_test.go \
  go/cmd/fi-backlog-recover/testdata/c1/private_c1_direct.go \
  go/cmd/fi-backlog-recover/testdata/c1/private_c1_direct_test.go \
  go/cmd/fi-backlog-recover/testdata/c1/private_c1_continuous_signed_stream.go \
  go/cmd/fi-backlog-recover/testdata/c1/private_c1_continuous_signed_stream_test.go \
  go/cmd/fi-backlog-recover/testdata/c1/private_c1_async_verify.go \
  go/cmd/fi-backlog-recover/testdata/c1/private_c1_async_verify_test.go \
  go/cmd/fi-backlog-recover/testdata/c1/private_c1_process_verify.go \
  go/cmd/fi-backlog-recover/testdata/c1/private_c1_process_verify_test.go \
  go/cmd/fi-c1-verifier/main.go \
  go/cmd/fi-backlog-recover/testdata/c1/private_c1_commit_ready.go \
  go/cmd/fi-backlog-recover/testdata/c1/private_c1_commit_ready_test.go \
  go/cmd/fi-backlog-recover/testdata/c1/private_c1_sparse_age_test.go \
  go/cmd/fi-backlog-recover/testdata/c1/private_c1_prefix8_proof.go \
  go/cmd/fi-backlog-recover/testdata/c1/private_c1_prefix8_proof_test.go \
  go/cmd/fi-backlog-recover/testdata/c1/private_c1_modules.go \
  go/cmd/fi-backlog-recover/testdata/c1/private_c1_cached_recovery.go \
  go/cmd/fi-backlog-recover/testdata/c1/private_c1_correctness_test.go \
  go/cmd/fi-backlog-recover/testdata/c1/private_c1_backpressure_test.go \
  go/cmd/fi-backlog-recover/testdata/c1/private_c1_eight_gib_group.go \
  go/cmd/fi-backlog-recover/testdata/c1/private_c1_eight_gib_group_test.go \
  go/cmd/fi-backlog-recover/testdata/c1/private_c1_full_backlog.go \
  go/cmd/fi-backlog-recover/testdata/c1/private_c1_full_backlog_test.go
do
  jexec -U jwood fi-dev git -C /home/jwood/fi-w512-c220-stage cat-file -e "$sourcecommit:$asset" 2>/dev/null ||
    fail "missing pinned experimental source asset $asset"
done
echo "FI FAMILY P6 SOURCE PREFLIGHT PASS commit=$sourcecommit assets=51 clone_only=true p5_min=2 p5_max=32 sql_workers_max=$sqlmax sql_modules=5"
# Compile the EXACT pinned patcher before allocating a private PostgreSQL clone.
# This checks syntax in both preflight and benchmark modes, without switching
# the staging Git checkout or modifying the historical source.
jexec -U jwood fi-dev sh -s "$sourcecommit" "$seed" <<'HF_GO_SYNTAX'
set -eu
umask 077
tmp=$(mktemp -d /tmp/fi-hf-patcher-preflight.XXXXXX) || exit 1
trap 'rm -rf "$tmp"' 0
git -C /home/jwood/fi-w512-c220-stage show \
  "$1:go/cmd/fi-backlog-recover/patchers/family_p3_c220/main.go" \
  > "$tmp/main.go" || exit 1
GOTOOLCHAIN=local GO111MODULE=off go127 test "$tmp/main.go" >/dev/null || exit 1
for f in private_canonical_spool_dispatch.go private_canonical_spool_dispatch_test.go; do
  git -C /home/jwood/fi-w512-c220-stage show \
    "$1:go/internal/recordingest/$f" > "$tmp/$f" || exit 1
done
GOTOOLCHAIN=local GO111MODULE=off go127 test -count=1 \
  "$tmp/private_canonical_spool_dispatch.go" \
  "$tmp/private_canonical_spool_dispatch_test.go" >/dev/null || exit 1
# Original C220 seed is examined ONLY in memory. The patcher checks all
# ordered source anchors and reports the precise mismatching source fragment.
# Fail in preflight, before allocating any disposable DB or overlay.
GOTOOLCHAIN=local GO111MODULE=off go127 run "$tmp/main.go" \
  audit "$2/optimized-source" || exit 1
HF_GO_SYNTAX
echo 'FI FAMILY P3 PATCHER COMPILE PREFLIGHT PASS pinned=true source_tree_unchanged=true'
echo 'FI FAMILY P3 DISPATCH TEST PREFLIGHT PASS fixture=present standalone_tests=passed'
echo 'FI FAMILY P3 ORIGINAL SOURCE ANCHOR AUDIT PASS seed_unchanged=true'
# Validate the EXACT report program under this source commit BEFORE
# repeating an expensive W512 replay. Also prevents zero-activity families
# from disappearing in the final comparison.
report_tmp=$(mktemp -d /var/tmp/fi-w512-family-report.XXXXXX) ||
    fail 'cannot allocate private AWK preflight directory'
report_awk="$report_tmp/private_family_worker_summary.awk"
report_fixture="$report_tmp/fixture.tsv"
dynamic_awk="$report_tmp/private_family_dynamic_summary.awk"
dynamic_fixture="$report_tmp/dynamic_fixture.tsv"
dynamic_output="$report_tmp/dynamic_output.tsv"
p5_report="$report_tmp/p5_window_report.awk"
p5_fixture="$report_tmp/p5_fixture.txt"
p5_output="$report_tmp/p5_output.tsv"
report_clear(){
    rm -f "$report_awk" "$report_fixture" "$dynamic_awk" "$dynamic_fixture" "$dynamic_output" \
      "$p5_report" "$p5_fixture" "$p5_output"
    rmdir "$report_tmp" 2>/dev/null || :
}
trap report_clear 0
jexec -U jwood fi-dev git -C /home/jwood/fi-w512-c220-stage show \
  "$sourcecommit:go/cmd/fi-backlog-recover/patchers/security_sweep_c220/private_family_worker_summary.awk" \
    > "$report_awk" || fail 'pinned family worker report unavailable'
chmod 0600 "$report_awk"
jexec -U jwood fi-dev git -C /home/jwood/fi-w512-c220-stage show \
  "$sourcecommit:go/cmd/fi-backlog-recover/patchers/security_sweep_c220/private_family_dynamic_summary.awk" \
    > "$dynamic_awk" || fail 'pinned dynamic scale-out report unavailable'
chmod 0600 "$dynamic_awk"
jexec -U jwood fi-dev git -C /home/jwood/fi-w512-c220-stage show \
  "$sourcecommit:go/cmd/fi-backlog-recover/patchers/security_sweep_c220/private_family_persistent_p5_summary.awk" \
  > "$p5_report" || fail 'pinned P5 window report unavailable'
chmod 0600 "$p5_report"
cat > "$p5_fixture" <<'P5_FIXTURE'
FI P5 PERSISTENT WINDOW FAMILY window=1 family=0 spawned=16 scale_ups=14 peak_busy=16 max_queue=20 processed=499052 complete=true
FI P5 PERSISTENT WINDOW FAMILY window=1 family=1 spawned=2 scale_ups=0 peak_busy=0 max_queue=0 processed=0 complete=true
FI P5 PERSISTENT WINDOW FAMILY window=1 family=2 spawned=2 scale_ups=0 peak_busy=0 max_queue=0 processed=0 complete=true
FI P5 PERSISTENT WINDOW FAMILY window=1 family=3 spawned=2 scale_ups=0 peak_busy=0 max_queue=0 processed=0 complete=true
FI P5 PERSISTENT WINDOW FAMILY window=1 family=4 spawned=2 scale_ups=0 peak_busy=0 max_queue=0 processed=0 complete=true
FI P5 PERSISTENT WINDOW FAMILY window=2 family=0 spawned=16 scale_ups=14 peak_busy=16 max_queue=20 processed=498382 complete=true
FI P5 PERSISTENT WINDOW FAMILY window=2 family=1 spawned=2 scale_ups=0 peak_busy=0 max_queue=0 processed=0 complete=true
FI P5 PERSISTENT WINDOW FAMILY window=2 family=2 spawned=2 scale_ups=0 peak_busy=0 max_queue=0 processed=0 complete=true
FI P5 PERSISTENT WINDOW FAMILY window=2 family=3 spawned=2 scale_ups=0 peak_busy=0 max_queue=0 processed=0 complete=true
FI P5 PERSISTENT WINDOW FAMILY window=2 family=4 spawned=2 scale_ups=0 peak_busy=0 max_queue=0 processed=0 complete=true
P5_FIXTURE
awk -v windows=2 -v first=1 -v records1=499052 -v records2=498382 \
  -f "$p5_report" "$p5_fixture" > "$p5_output" ||
    fail 'P5 pinned window-report smoke test failed'
[ "$(wc -l < "$p5_output" | tr -d ' ')" = 11 ] &&
grep -Fq "$(printf '1\tSecurity\t16\t14\t16\t20\t499052')" "$p5_output" ||
    fail 'P5 window-report fixture row mismatch'
printf 'FI P5 PERSISTENT REPORT PREFLIGHT PASS windows=2 families=5 signed_records=997434\n'
cat > "$dynamic_fixture" <<'DYNAMIC_FIXTURE'
FI FAMILY DYNAMIC LANE family=Security min=2 max=16 spawned=8 scale_ups=6 peak_busy=8 peak_pending=3 assigned=3 prepared=3 dispatched=3 complete=true
FI FAMILY DYNAMIC LANE family=File min=2 max=16 spawned=2 scale_ups=0 peak_busy=1 peak_pending=1 assigned=1 prepared=1 dispatched=1 complete=true
FI FAMILY DYNAMIC LANE family=Coverage min=2 max=16 spawned=2 scale_ups=0 peak_busy=0 peak_pending=0 assigned=0 prepared=0 dispatched=0 complete=true
FI FAMILY DYNAMIC LANE family=USNDependency min=2 max=16 spawned=2 scale_ups=0 peak_busy=0 peak_pending=0 assigned=0 prepared=0 dispatched=0 complete=true
FI FAMILY DYNAMIC LANE family=Other min=2 max=16 spawned=2 scale_ups=0 peak_busy=0 peak_pending=0 assigned=0 prepared=0 dispatched=0 complete=true
DYNAMIC_FIXTURE
awk -v batches=1 -f "$dynamic_awk" "$dynamic_fixture" > "$dynamic_output" ||
    fail 'pinned P4 dynamic lane reporter fixture failed'
[ "$(wc -l < "$dynamic_output" | tr -d ' ')" = 6 ] &&
grep -Fq "$(printf 'Security\t1\t3\t8\t8\t3\t6')" "$dynamic_output" ||
    fail 'P4 dynamic lane reporter fixture values incorrect'
printf 'FI FAMILY P4 DYNAMIC REPORT PREFLIGHT PASS families=5 zero_work=retained min=2 max=16\n'
awk -v sec="$security_workers" -v general="$general_workers" -f "$report_awk" > "$report_fixture" <<'FIXTURE' ||
    fail 'pinned per-worker AWK report compile/smoke test failed'
FI FAMILY P3 WORKER family=Security worker=0 records=3 bytes=300 prepare_ns=500000000 input_wait_ns=2000000000 output_wait_ns=0 complete=true
FI FAMILY P3 WORKER family=File worker=0 records=1 bytes=100 prepare_ns=7000000 input_wait_ns=0 output_wait_ns=0 complete=true
FIXTURE
awk -F '\t' -v sec="$security_workers" -v each="$general_each" -v total="$family_workers" '
    NR==1 {if($1!="family" || $2!="worker" || $3!="records")bad=1}
    NR>1 {
        if($1=="Security"){security++;if($2==0 && ($3!=3 || $4!=300))bad=1}
        else if($1=="File"){file++;if($2==0 && ($3!=1 || $4!=100))bad=1}
        else if($1=="Coverage")coverage++
        else if($1=="USNDependency")usn++
        else if($1=="Other")other++
        else bad=1
    }
    END{
        if(bad || NR!=total+1 || security!=sec ||
          file!=each || coverage!=each || usn!=each || other!=each)exit 1
    }' "$report_fixture" ||
    fail 'worker summary self-test incorrect counts or zero-work families'
printf 'FI FAMILY P4 WORKER SUMMARY PREFLIGHT PASS min=2 max=16 slots_per_family=16 max_slots=80 zero_work_families=retained\n'
printf 'FI C220 FAMILY P4 DYNAMIC PREFLIGHT PASS min_workers=2 max_workers=16 families=5 max_slots=80 credits=32 writer=1 start=1 windows=2 cache=authenticated live_ingest=stopped\n'
# Preserve pinned historical 16-slot P4 report fixtures above. The C1
# execution below uses five independently adaptive P5 2..32 pools (160
# available slots) plus ONE adaptive 1..32 PostgreSQL family SQL pool.
security_workers=32
general_workers=128
general_each=32
family_workers=160
printf 'FI C1 FULL ADAPTIVE CAPACITY PREFLIGHT PASS p5_lanes=5 p5_worker_min=2 p5_worker_max=32 p5_max_slots=160 sql_worker_min=1 sql_worker_max=%s ordered_parent=1 shared_sql=true credits=32\n' "$sqlmax"
if [ "$mode" = preflight ]; then
  echo 'FI C220 W512 P2 PREFLIGHT ONLY: no database started, no source changed'
  exit 0
fi
relaypid=
iostatpid=
vmstatpid=
dipmonpid=
cleanup(){
    code=$?
    trap - 0 1 2 15
    report_clear
    for pid in "$iostatpid" "$vmstatpid" "$dipmonpid" "$relaypid"; do
        [ -n "$pid" ] || continue
        kill -TERM "$pid" 2>/dev/null || :
        wait "$pid" 2>/dev/null || :
    done
    if [ -d "$jailroot$root/$name/data" ] &&
       jexec -U jwood fi-dev pg_ctl -D "$root/$name/data" status >/dev/null 2>&1; then
        jexec -U jwood fi-dev pg_ctl -D "$root/$name/data" -m fast -w -t 60 stop ||
            { echo 'WARNING: W512 pilot PostgreSQL failed to stop' >&2; code=1; }
    fi
    printf 'FI W512 PILOT FINISHED exit=%s outputs=%s private_clone=%s private_artifacts=%s original_seed_unchanged=true\n' "$code" "$out" "$root" "$private_root"
    exit "$code"
}
trap cleanup 0
trap 'exit 130' 2
trap 'exit 143' 15
jexec -U jwood fi-dev sh -s "$seed" "$root" "$name" "$port" "$sourcecommit" "$mode" "$sqlmax" "$group" "$stop" <<'JAIL'
set -eu
umask 077
seed=$1
root=$2
name=$3
port=$4
sourcecommit=$5
mode=$6
sqlmax=$7
group=$8
stop=$9
[ "$(id -un)" = jwood ] && [ "$(psql --version)" = 'psql (PostgreSQL) 18.6' ] || exit 1
[ ! -e "$root" ] && [ ! -e "$seed/$name/data/postmaster.pid" ] || exit 1
pg_ctl -D "$seed/$name/data" status >/dev/null 2>&1 && exit 1
mkdir -m 700 "$root" "$root/$name" "$root/$name/socket" || exit 1
# Validate seed version now, but do NOT copy its database until Go tests/build pass.
[ "$(cat "$seed/$name/data/PG_VERSION")" = 18 ] || exit 1
for f in fi-optfield-recover fi-optfield-relay recover.sha256 relay.sha256; do
    cp "$seed/$f" "$root/$f" || exit 1
done
[ "$(sha256 -q "$root/fi-optfield-recover")" = "$(cat "$root/recover.sha256")" ] || exit 1
[ "$(sha256 -q "$root/fi-optfield-relay")" = "$(cat "$root/relay.sha256")" ] || exit 1
# Build a PRIVATE benchmark-only source copy; never change the historical
# authenticated seed source, working Git checkout, or installed receiver trust.
src="$root/optimized-source"
cp -R "$seed/optimized-source" "$src" || exit 1
trustfile="$src/go/internal/recordingest/generation_trust.go"
expected=/home/jwood/fi-w512-c220-stage
[ -f "$trustfile" ] || exit 1
# Stage ONLY the pinned, new experimental files into this disposable archive.
for item in private_canonical_spool_dispatch.go private_canonical_spool_dispatch_test.go; do
  [ ! -e "$src/go/internal/recordingest/$item" ] || exit 1
  git -C "$expected" show "$sourcecommit:go/internal/recordingest/$item" \
    > "$src/go/internal/recordingest/$item" || exit 1
done
for item in private_header_first_p2.go private_header_first_p2_test.go; do
  [ ! -e "$src/go/internal/recordingest/$item" ] || exit 1
  git -C "$expected" show "$sourcecommit:go/cmd/fi-backlog-recover/testdata/header-first/$item" \
    > "$src/go/internal/recordingest/$item" || exit 1
done
for item in private_family_preparation_p3.go private_family_preparation_p3_test.go private_family_dynamic_p4.go private_family_dynamic_p4_test.go private_family_persistent_p5.go private_family_persistent_p5_test.go; do
  [ ! -e "$src/go/internal/recordingest/$item" ] || exit 1
  git -C "$expected" show "$sourcecommit:go/cmd/fi-backlog-recover/testdata/family-p3/$item" \
    > "$src/go/internal/recordingest/$item" || exit 1
done
for item in private_p6_family_buffers_test.go private_p6_file_proof_test.go private_p6_sql_coordinator.go private_p6_sql_security.go private_p6_sql_ntfs.go private_p6_sql_coverage.go private_p6_sql_usn.go private_p6_sql_other.go; do
  [ ! -e "$src/go/internal/recordingest/$item" ] || exit 1
  git -C "$expected" show "$sourcecommit:go/cmd/fi-backlog-recover/testdata/family-p6/$item" \
    > "$src/go/internal/recordingest/$item" || exit 1
done
# P6 patcher audits all P6 private assets before modifying the disposable
# source. Supply the C1-owned P6 buffer implementation BEFORE that audit,
# not after it. This is the accepted P6 buffer with only SQL ACK barriers.
[ ! -e "$src/go/internal/recordingest/private_p6_family_buffers.go" ] || exit 1
git -C "$expected" show "$sourcecommit:go/cmd/fi-backlog-recover/testdata/c1/private_c1_family_buffers.go" \
  > "$src/go/internal/recordingest/private_p6_family_buffers.go" || exit 1
[ -s "$src/go/internal/recordingest/private_p6_family_buffers.go" ] || exit 1
mkdir -p "$src/go/cmd/fi-backlog-recover/patchers/family_p3_c220" || exit 1
git -C "$expected" show "$sourcecommit:go/cmd/fi-backlog-recover/patchers/family_p3_c220/main.go" \
  > "$src/go/cmd/fi-backlog-recover/patchers/family_p3_c220/main.go" || exit 1
(cd "$src/go" &&
 GOTOOLCHAIN=local GOFLAGS=-mod=readonly go127 run \
   ./cmd/fi-backlog-recover/patchers/family_p3_c220 "$src"
) || exit 1
# C1 Security 8GiB COPY overlay: the P3/P6 patcher has ALREADY installed
# the ordered source-parent bypass and exact signed (batch,ordinal) FK reuse.
# Never overwrite security_bulk.go with a repository copy here: doing so
# would remove both audited P6 transformations.
#
# Replace only the three profile/field budget/test files in this private
# source tree, then widen EXACTLY the three existing private selection seams
# in the already-patched security_bulk.go. The ordinary source path remains
# identical because its new context switch is absent.
for item in security_bulk_profiles.go security_field_profile_dual.go security_field_profile_dual_test.go;do
  target="$src/go/internal/recordingest/$item"
  [ -f "$target" ] && [ ! -L "$target" ] || {
    echo "FI C1 STOP: source profile overlay target missing or unsafe $item" >&2
    exit 1
  }
  git -C "$expected" show "$sourcecommit:go/internal/recordingest/$item" \
    > "$target.c1" || exit 1
  [ -s "$target.c1" ] || exit 1
  mv "$target.c1" "$target" || exit 1
done
security_bulk="$src/go/internal/recordingest/security_bulk.go"
[ -f "$security_bulk" ] && [ ! -L "$security_bulk" ] &&
grep -Fq 'if privateP6SourceAlreadyInserted(ctx)' "$security_bulk" &&
grep -Fq 'ids := privateC1KnownSourceIDs(ctx)' "$security_bulk" ||
  { echo 'FI C1 STOP: existing P6 parent/FK Security optimizations not present' >&2; exit 1; }
[ "$(grep -Fc 'if usePrivateSinglePassSecurity(ctx) {' "$security_bulk")" = 3 ] ||
  { echo 'FI C1 STOP: expected exactly three original Security COPY selection seams' >&2; exit 1; }
sed 's/if usePrivateSinglePassSecurity(ctx) {/if usePrivateSinglePassSecurity(ctx) || securityC1COPYExperimentEnabled(ctx) {/' \
  "$security_bulk" > "$security_bulk.c1" || exit 1
[ "$(grep -Fc 'if usePrivateSinglePassSecurity(ctx) || securityC1COPYExperimentEnabled(ctx) {' "$security_bulk.c1")" = 3 ] &&
grep -Fq 'if privateP6SourceAlreadyInserted(ctx)' "$security_bulk.c1" &&
grep -Fq 'ids := privateC1KnownSourceIDs(ctx)' "$security_bulk.c1" ||
  { echo 'FI C1 STOP: Security COPY overlay changed P6 relational dependency behavior' >&2; exit 1; }
mv "$security_bulk.c1" "$security_bulk" || exit 1
echo 'FI C1 PRIVATE SECURITY COPY OVERLAY PASS source_parent_bypass=preserved signed_fk_reuse=preserved private_switches=3 context_isolated=true clone_only=true'

# Extend the accepted P6 coordinator directly. P6 buffers were already
# installed before the original P6 patcher's required asset audit.
for item in private_c1_five_sql.go private_c1_source_profile.go private_c1_source_profile_test.go private_c1_direct.go private_c1_direct_test.go private_c1_continuous_signed_stream.go private_c1_continuous_signed_stream_test.go private_c1_async_verify.go private_c1_async_verify_test.go private_c1_process_verify.go private_c1_process_verify_test.go private_c1_commit_ready.go private_c1_commit_ready_test.go private_c1_sparse_age_test.go private_c1_prefix8_proof.go private_c1_prefix8_proof_test.go private_c1_correctness_test.go private_c1_backpressure_test.go private_c1_modules.go private_c1_eight_gib_group.go private_c1_eight_gib_group_test.go private_c1_full_backlog.go private_c1_full_backlog_test.go; do
  [ ! -e "$src/go/internal/recordingest/$item" ] || exit 1
  git -C "$expected" show "$sourcecommit:go/cmd/fi-backlog-recover/testdata/c1/$item" \
    > "$src/go/internal/recordingest/$item" || exit 1
done
# C1's persistent P5 pool is 2..32. Historical P4 2..16 test fixtures
# are retained, but C1's own two signed-stream regression tests must use 32.
for test in private_c1_direct_test.go private_c1_continuous_signed_stream_test.go; do
  if grep -Fq 'FI_W512_P3_DYNAMIC_MAX","16"' "$src/go/internal/recordingest/$test"; then
    echo "FI C1 STOP: stale P5 max=16 configuration in $test" >&2
    exit 1
  fi
  grep -Fq 'FI_W512_P3_DYNAMIC_MAX","32"' "$src/go/internal/recordingest/$test" ||
    { echo "FI C1 STOP: expected P5 max=32 missing from $test" >&2; exit 1; }
done
echo 'FI C1 P5 TEST CONTRACT PASS continuous=true direct=true adaptive_worker_max=32'
mkdir -p "$src/go/cmd/fi-c1-verifier" || exit 1
[ ! -e "$src/go/cmd/fi-c1-verifier/main.go" ] || exit 1
git -C "$expected" show "$sourcecommit:go/cmd/fi-c1-verifier/main.go" \
  > "$src/go/cmd/fi-c1-verifier/main.go" || exit 1
grep -Fxq '//go:build fi_c1_private' "$src/go/cmd/fi-c1-verifier/main.go" ||
  { echo 'FI C1 STOP: verifier entry point is not isolated by the private build tag' >&2; exit 1; }
# The retired synchronous relational scans MUST NOT remain on the C1
# typed-marker path. The new verifier owns those exact checks and marker
# insertion is gated on every committed group proof.
if grep -Eq 'verifyBacklogShadowWindowCounts|verifyBacklogWindowProjectionCoverage|verifyGenerationProjectionCoverage' \
    "$src/go/internal/recordingest/private_c1_direct.go";then
  echo 'FI C1 STOP: old synchronous relational scans remain on marker path' >&2
  exit 1
fi
grep -Fq 'commitReady.FinishCommitted()' \
  "$src/go/internal/recordingest/private_c1_direct.go" &&
grep -Fq 'privateC1AsyncVerifyGroup' \
  "$src/go/internal/recordingest/private_c1_async_verify.go" &&
grep -Fq 'CommitFamily(rows)' \
  "$src/go/internal/recordingest/private_c1_five_sql.go" &&
grep -Fq 'CommitSource(rows)' \
  "$src/go/internal/recordingest/private_c1_five_sql.go" &&
grep -Fq 'commitReady.Seal' \
  "$src/go/internal/recordingest/private_c1_direct.go" &&
grep -Fq 'privateC1StartProcessVerify(ctx,dsn,pgdata' \
  "$src/go/internal/recordingest/private_c1_direct.go" &&
grep -Fq 'RunPrivateC1VerifyChild' \
  "$src/go/internal/recordingest/private_c1_process_verify.go" &&
grep -Fq 'privateC1AsyncVerifyGroup' \
  "$src/go/internal/recordingest/private_c1_process_verify.go" &&
grep -Fq 'os/exec' \
  "$src/go/internal/recordingest/private_c1_process_verify.go" &&
grep -Fq 'verifier.WaitGroups(ctx)' \
  "$src/go/internal/recordingest/private_c1_direct.go" &&
grep -Fq 'verifiedByB,e:=verifier.Finish(ctx)' \
  "$src/go/internal/recordingest/private_c1_direct.go" &&
grep -Fq 'privateC1VerifyCompleteGroupedReplay(ctx,conn,g,p.Descriptors)' \
  "$src/go/internal/recordingest/private_c1_process_verify.go" &&
grep -Fq 'privateC1VerifyEightGiBPrefix(ctx,conn,g,p.Descriptors,p.End)' \
  "$src/go/internal/recordingest/private_c1_process_verify.go" ||
  { echo 'FI C1 STOP: committed source/family readiness or independent verifier boundary missing' >&2; exit 1; }
if grep -Fq 'privateC1VerifyCompleteGroupedReplay(ctx,reader,g,ds)' \
  "$src/go/internal/recordingest/private_c1_direct.go"; then
  echo 'FI C1 STOP: A still owns the final relational generation proof' >&2
  exit 1
fi
if grep -Eq 'privateC1SparseMaxBatchLag|flushAgedSparse' \
  "$src/go/internal/recordingest/private_p6_family_buffers.go"; then
  echo 'FI C1 STOP: retired B-driven sparse-family flush still present' >&2
  exit 1
fi
echo 'FI C1 A/B SOURCE AUDIT PASS old_relational_scans=removed source_commit=tracked family_commit=tracked reader_seal=tracked verifier_independent=true verifier_os_process=separate final_generation_proof=B sparse_age_flush=removed no_group_flush=true'
# Historical C220 original is the only allowed cache entrypoint source.
cached="$src/go/internal/recordingest/backlog_verified_cache_recovery.go"
git -C "$expected" show "b01ff0d8cb6559797de052f34b18bd84a395dc4c:go/internal/recordingest/backlog_verified_cache_recovery.go" |
  cmp -s - "$cached" || { echo "FI C1: unexpected historical cached recovery source" >&2; exit 1; }
git -C "$expected" show "$sourcecommit:go/cmd/fi-backlog-recover/testdata/c1/private_c1_cached_recovery.go" \
  > "$cached" || exit 1
echo "FI C1 NATIVE P6 DIRECT SOURCE PASS p7_bridge=none source_stage=none"

# Full backlog uses original 0=unlimited controlled-stop handling.
# Do not change main_freebsd.go or widen its isolated benchmark stop gate.
# Pin the original resolver source exactly BEFORE replacing four filesystem
# path constants. Cryptographic signature, certificate and CRL logic is intact.
git -C "$expected" show b01ff0d8cb6559797de052f34b18bd84a395dc4c:go/internal/recordingest/generation_trust.go |
    cmp -s - "$trustfile" || {
    echo 'FI C220 PRIVATE TRUST PATCH STOP: historical resolver source differs' >&2
    exit 1
}
for anchor in \
  receivertrust.RootCAPath \
  receivertrust.BatchIssuerPath \
  receivertrust.BatchCRLPath \
  receivertrust.SourceRegistryPath
do
  [ "$(grep -Foc "$anchor" "$trustfile")" = 1 ] || {
    echo "FI C220 PRIVATE TRUST PATCH STOP: invalid source anchor $anchor" >&2
    exit 1
  }
done
# CERTIFICATES and ENROLLED SOURCE are the original C220 migration inputs.
# CRL is the currently valid receiver trust, matching the accepted cache gate.
sed \
  -e 's|receivertrust.RootCAPath|"/work/fi-c220-20261114/ingest-config/pki/trust/fi-root-ca.crt.pem"|' \
  -e 's|receivertrust.BatchIssuerPath|"/work/fi-c220-20261114/ingest-config/pki/trust/fi-batch-signing-ca.crt.pem"|' \
  -e 's|receivertrust.BatchCRLPath|"/work/fi-c220-20261114/config/receiver/pki/trust/fi-batch-signing-ca.crl.pem"|' \
  -e 's|receivertrust.SourceRegistryPath|"/work/fi-c220-20261114/ingest-config/sources"|' \
  "$trustfile" > "$trustfile.c220" || exit 1
# Verify four substitutions and no unresolved installed-trust path constants.
for pinned in \
  '/work/fi-c220-20261114/ingest-config/pki/trust/fi-root-ca.crt.pem' \
  '/work/fi-c220-20261114/ingest-config/pki/trust/fi-batch-signing-ca.crt.pem' \
  '/work/fi-c220-20261114/config/receiver/pki/trust/fi-batch-signing-ca.crl.pem' \
  '/work/fi-c220-20261114/ingest-config/sources'
do
  grep -Fq "$pinned" "$trustfile.c220" || exit 1
done
if grep -Eq 'receivertrust\\.(RootCAPath|BatchIssuerPath|BatchCRLPath|SourceRegistryPath)' "$trustfile.c220"; then
  echo 'FI C220 PRIVATE TRUST PATCH STOP: installed paths remain' >&2
  exit 1
fi
mv "$trustfile.c220" "$trustfile" || exit 1
(cd "$src/go" &&
 FI_W512_P6_FAMILY_SQL= FI_W512_P5_PERSISTENT= FI_W512_P3_DYNAMIC_MIN= FI_W512_P3_DYNAMIC_MAX= \
   GOTOOLCHAIN=local GOFLAGS=-mod=readonly go127 test \
   ./internal/recordingest -run '^(TestBacklogWindowsW512TwoGiB|TestPrivateParallelA|TestH16Combined|TestCanonicalDispatch|TestPrivateHeaderFirstP2|TestPrivateFamilyP3|TestPrivateSecuritySweep|TestPrivateDynamicP4|TestPrivateP5|TestPrivateP6|TestPrivateC1|TestC1Security8GiB)' -count=1 &&
 FI_W512_P6_FAMILY_SQL= FI_W512_P5_PERSISTENT= FI_W512_P3_DYNAMIC_MIN= FI_W512_P3_DYNAMIC_MAX= \
   GOTOOLCHAIN=local GOFLAGS=-mod=readonly go127 test -race \
   ./internal/recordingest -run '^(TestPrivateFamilyP3|TestPrivateSecuritySweep|TestPrivateDynamicP4|TestPrivateP5|TestPrivateP6|TestPrivateC1)' -count=1 &&
 GOTOOLCHAIN=local GOFLAGS=-mod=readonly go127 build \
   -o "$root/fi-optfield-recover.c220" ./cmd/fi-backlog-recover &&
 GOTOOLCHAIN=local GOFLAGS=-mod=readonly go127 build -tags fi_c1_private \
   -o "$root/fi-c1-verifier.c220" ./cmd/fi-c1-verifier
) > "$root/private-trust-path-build.log" 2>&1 || {
  echo "===== FIRST GO TEST/RACE/BUILD FAILURES =====" >&2
  grep -n -C 5 -E -- '--- FAIL:|^FAIL|panic:|fatal error:|WARNING: DATA RACE|build failed|^# ' \
    "$root/private-trust-path-build.log" | head -n 180 >&2 || :
  echo "===== BUILD LOG TAIL =====" >&2
  tail -n 40 "$root/private-trust-path-build.log" >&2
  echo 'FI C220 PRIVATE TRUST PATCH STOP: tests/build failed' >&2
  exit 1
}
[ -x "$root/fi-optfield-recover.c220" ] || exit 1
[ -x "$root/fi-c1-verifier.c220" ] || exit 1
mv "$root/fi-optfield-recover.c220" "$root/fi-optfield-recover" || exit 1
mv "$root/fi-c1-verifier.c220" "$root/fi-c1-verifier" || exit 1
sha256 -q "$root/fi-optfield-recover" > "$root/recover.sha256" || exit 1
sha256 -q "$root/fi-c1-verifier" > "$root/verifier.sha256" || exit 1
printf 'FI C220 PRIVATE TRUST PATH PATCH PASS source=pinned_b01ff0 benchmark_only=true compiler=go127 root_ca=migrated signing_ca=migrated crl=current_receiver source_registry=migrated\n'

# Compile-only acceptance uses the exact original C220 optimized seed.
# Tests/race/build complete before any PostgreSQL data copy or startup.
if [ "$mode" = compile ]; then
  echo 'FI C1 PRIVATE SOURCE GO/RACE COMPILE PASS original_seed=unchanged postgres_started=false'
  exit 0
fi
# All pinned overlay compilation and tests passed. Clone PostgreSQL only now.
cp -R "$seed/$name/data" "$root/$name/data" || exit 1
[ "$(cat "$root/$name/data/PG_VERSION")" = 18 ] || exit 1
echo 'FI FAMILY P3 POST-BUILD PRIVATE SEED COPY PASS'
pg_ctl -D "$root/$name/data" -l "$root/$name/postgres.log" \
  -o "-p $port -k $root/$name/socket -c listen_addresses= -c unix_socket_permissions=0700 -c max_wal_size=8GB -c wal_buffers=16MB" \
  -w start > "$root/$name/start.log" 2>&1 || { echo 'FI C1 CLONE STOP: PostgreSQL failed to start; inspect start.log and postgres.log in the private clone' >&2; exit 1; }
echo 'FI C1 PRIVATE POSTGRESQL START PASS'
# Verify the original private clone using existing owner and fi_ingest roles.
# Do not modify database roles, grants, revocations or ownership.
clone_sock="$root/$name/socket"
clone_data="$root/$name/data"
clone_ingest_dsn="host=$clone_sock port=$port user=fi_ingest dbname=fi sslmode=disable"
clone_admin=$(psql "$clone_ingest_dsn" -X -qAt -v ON_ERROR_STOP=1 \
  -c "SELECT rolname FROM pg_catalog.pg_roles WHERE rolsuper AND rolcanlogin AND rolname !~ '^pg_' ORDER BY rolname") || { echo 'FI C1 CLONE STOP: existing owner role discovery query failed' >&2; exit 1; }
[ -n "$clone_admin" ] &&
[ "$(printf '%s\n' "$clone_admin" | wc -l | tr -d '[:space:]')" = 1 ] &&
printf '%s\n' "$clone_admin" | grep -Eq '^[A-Za-z_][A-Za-z_0-9]*$' || { echo 'FI C1 CLONE STOP: existing PostgreSQL clone owner is missing or ambiguous' >&2; exit 1; }
clone_owner_dsn="host=$clone_sock port=$port user=$clone_admin dbname=fi sslmode=disable"
[ "$(psql "$clone_owner_dsn" -X -qAt -v ON_ERROR_STOP=1 -c "SELECT current_setting('data_directory')")" = "$clone_data" ] || { echo 'FI C1 CLONE STOP: verified PGDATA does not match disposable private clone' >&2; exit 1; }
[ "$(psql "$clone_owner_dsn" -X -qAt -v ON_ERROR_STOP=1 -c "SELECT current_user||'|'||(SELECT rolsuper::text FROM pg_roles WHERE rolname=current_user)||'|'||pg_is_in_recovery()::text")" = "$clone_admin|true|false" ] || { echo 'FI C1 CLONE STOP: existing clone owner identity or primary status differs' >&2; exit 1; }
echo 'FI C1 PRIVATE CLONE OWNER VERIFIED PASS'
psql "$clone_owner_dsn" -X -qAt -v ON_ERROR_STOP=1 -c \
  "CREATE TABLE fi_recovery_projection.windows_security_event_field_c1_default
     PARTITION OF fi_recovery_projection.windows_security_event_field DEFAULT;
   ALTER TABLE fi_recovery.typed_window
     DROP CONSTRAINT typed_window_receipt_sha256_window_index_fkey;
   ALTER TABLE fi_recovery.typed_window
     ADD CONSTRAINT typed_window_c1_shadow_fkey
     FOREIGN KEY (shadow_generation_id)
     REFERENCES fi_recovery_projection.recorded_generation(recorded_generation_id);" >/dev/null || { echo 'FI C1 CLONE STOP: private-only partition or typed marker DDL failed' >&2; exit 1; }
echo 'FI C1 PRIVATE CLONE STRUCTURE PASS'
# fi_ingest uses the original P6 role without new read-all-settings grants.
# PGDATA identity has already been verified through the clone owner above.
[ "$(psql "$clone_ingest_dsn" -X -qAt -v ON_ERROR_STOP=1 -c "SELECT current_user||'|'||pg_is_in_recovery()::text")" = "fi_ingest|false" ] || { echo 'FI C1 CLONE STOP: original fi_ingest role or primary status differs' >&2; exit 1; }
echo 'FI C1 ORIGINAL INGEST ROLE PASS permissions=unchanged'
echo 'FI C1 PRIVATE P6 SQL CLONE PASS physical_pgdata=verified shadow_fk=retained permissions=unchanged'
echo 'FI W512 PILOT OFFLINE SEED COPY PASS'
JAIL
if [ "$mode" = compile ]; then
  echo 'FI C1 C220 PRIVATE GO/RACE GATE PASS original_seed_unchanged=true postgres_started=false'
  exit 0
fi
mkdir -m 700 "$out" "$out/$name" "$private_root" ||
  fail 'private benchmark output initialization failed'
[ "$(stat -f %d "$private_root")" = "$(stat -f %d "$cache")" ] ||
  fail 'private signed artifact root differs from signed-cache filesystem'
[ "$(stat -f %Sp "$private_root")" = "drwx------" ] ||
  fail 'private artifact directory must be exactly 0700'
printf 'FI C220 CLONE-ONLY PRIVATE OUTPUT PASS cache_fs=fast private_fs=fast separate_inode_required=true original_cache=unchanged\n'
recover="$jailroot$root/fi-optfield-recover"
relay="$jailroot$root/fi-optfield-relay"
[ "$(sha256 -q "$recover")" = "$(cat "$jailroot$root/recover.sha256")" ] ||
    fail 'W512 recovery executable SHA mismatch'
[ "$(sha256 -q "$relay")" = "$(cat "$jailroot$root/relay.sha256")" ] ||
    fail 'W512 relay executable SHA mismatch'
"$relay" -cluster-root="$root" -output-root="$out" \
  -base-port="$port" -jail-binary="$root/fi-optfield-relay" > "$out/relay.log" 2>&1 &
relaypid=$!
tries=0
while ! grep -Fq "FI PG RELAY READY profile=$name port=$port" "$out/relay.log" 2>/dev/null; do
    kill -0 "$relaypid" 2>/dev/null || { tail -n 50 "$out/relay.log" >&2 || :; fail 'W512 relay exited'; }
    [ "$tries" -lt 30 ] || { tail -n 50 "$out/relay.log" >&2 || :; fail 'W512 relay startup timeout'; }
    tries=$((tries+1))
    sleep 1
done
sql(){
    jexec -U jwood fi-dev psql \
      "host=$root/$name/socket port=$port user=fi_ingest dbname=fi sslmode=disable" \
      -X -qAt -v ON_ERROR_STOP=1 -c "$1"
}
state=$(sql "SELECT count(*)::text||'|'||sum(committed_records)::text||'|'||
  min(window_index)::text||'|'||max(window_index)::text||'|'||
  min(encode(descriptor_sha256,'hex')) FROM fi_recovery.typed_window")
[ "$state" = "1|493478|0|0|$seedhash" ] || fail "private W512 seed SQL state invalid: $state"
[ "$(sql 'SELECT count(*) FROM fi_recovery.source_window')" = 1 ] &&
[ "$(sql 'SELECT count(*) FROM fi_recovery.verified_artifact_window')" = 1 ] &&
[ "$(sql 'SELECT count(*) FROM fi_recovery_projection.source_batch')" = 8399 ] &&
[ "$(sql 'SELECT count(*) FROM fi_recovery_projection.windows_security_event_field')" = 6194967 ] ||
    fail 'W512 copied seed schema, source metadata or field count invalid'
[ "$(sql 'SELECT count(*) FROM fi.recorded_generation')" = 0 ] &&
[ "$(sql "SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted'")" = 0 ] ||
    fail 'canonical or Accepted rows present in private seed'
[ "$(sql 'SHOW max_wal_size')" = "$pg_max_wal" ] &&
[ "$(sql 'SHOW wal_buffers')" = "$pg_wal_buffers" ] ||
    fail 'private PostgreSQL WAL experiment settings changed'
# Only the disposable clone may open up to 32 adaptive family SQL sessions
# alongside the ordered parent, B read-only session and normal control queries.
pg_connections=$(sql 'SHOW max_connections') ||
    fail 'private PostgreSQL connection limit unavailable'
case "$pg_connections" in ''|*[!0-9]*) fail 'invalid PostgreSQL max_connections' ;; esac
[ "$pg_connections" -ge 40 ] ||
    fail 'private PostgreSQL max_connections is insufficient for 32 adaptive SQL workers plus parent/B'
echo "FI C1 32 SQL CONNECTION PREFLIGHT PASS max_connections=$pg_connections sql_workers_max=$sqlmax ordered_parent=1 verifier_B=1"
for f in fsync synchronous_commit full_page_writes; do
    [ "$(sql "SHOW $f")" = on ] || fail "PostgreSQL durability $f disabled"
done
cat > "$out/RUN_MANIFEST.txt" <<EOF
FI C1 SIGNED BACKLOG 4GiB PRIVATE CLONE
c1_private_8g_prefix=$prefix8
family_p3_source_commit=$sourcecommit
c1_group_gib=$group
c1_source_target_gib=full_verified_generation
source_seed=$seed
seed_descriptor=$seedhash
seed_records=493478
signed_cache=$cache
window_profile=W512
window_records_max=unbounded_for_new_groups
window_source_bytes_max=$((group*1073741824))
seed_window_records_max=524288
seed_window_source_bytes_max=2147483648
start_window=1
windows=all_remaining_groups
c1_group_gib=$group
c1_source_target_gib=full_verified_generation
c1_source_comparison=entire_signed_receiver_cache
K32=32768
family_lanes=5
family_workers=$family_workers
security_workers=$security_workers
general_workers=$general_workers
file_workers=$general_each
coverage_workers=$general_each
usn_workers=$general_each
other_workers=$general_each
scheduler=priority_fill
worker_min=2
worker_max=32
per_family_dynamic=true
inflight_limit=32
pending_raw_bytes_max=268435456
sql_workers_min=1
sql_workers_max=$sqlmax
telemetry_period_seconds=1
telemetry_cpu_ticks=per_cpu
telemetry_postgres_activity_wait_event=true
telemetry_postgres_wal_counters=true
telemetry_postgres_checkpointer_counters=true
telemetry_postgres_io_counters=true
telemetry_disks=iostat_extended
pg_max_wal_size=$pg_max_wal
pg_wal_buffers=$pg_wal_buffers
pg_wal_experiment=wal_buffers_only_after_8gb_wal
sql_worker_assignment=shared_adaptive
private_only=true
private_signed_artifact_root=$private_root
clone_only_same_filesystem_required=true
host_relay_output_root=$out
authoritative_writes=forbidden
accepted_publication=forbidden
recover_sha256=$(sha256 -q "$recover")
benchmark_trust_path_adaptation=host_migrated_readonly_sources_only
benchmark_trust_source_base=b01ff0d8cb6559797de052f34b18bd84a395dc4c
benchmark_certificate_root=/work/fi-c220-20261114/ingest-config/pki/trust
benchmark_revocation_root=/work/fi-c220-20261114/config/receiver/pki/trust
benchmark_enrollment_root=/work/fi-c220-20261114/ingest-config/sources
EOF
stats(){
    phase=$1
    sql 'SELECT row_to_json(x)::text FROM (SELECT * FROM pg_stat_wal) x' > "$out/$name/wal_$phase.jsonl"
    sql 'SELECT row_to_json(x)::text FROM (SELECT * FROM pg_stat_checkpointer) x' > "$out/$name/checkpointer_$phase.jsonl"
    sql 'SELECT row_to_json(x)::text FROM (SELECT * FROM pg_stat_io) x' > "$out/$name/io_$phase.jsonl"
    sql "SELECT row_to_json(x)::text FROM (
      SELECT schemaname,relname,seq_scan,idx_scan,n_tup_ins,n_tup_upd,n_tup_del,
             n_tup_hot_upd,n_live_tup,n_dead_tup,n_ins_since_vacuum,
             vacuum_count,autovacuum_count,analyze_count,autoanalyze_count,
             total_vacuum_time,total_autovacuum_time,
             total_analyze_time,total_autoanalyze_time,
             last_vacuum,last_autovacuum,
             pg_relation_size(relid) AS table_heap_bytes,
             pg_indexes_size(relid) AS index_bytes,
             pg_total_relation_size(relid) AS total_bytes
      FROM pg_stat_user_tables
      WHERE schemaname IN ('fi_recovery_projection','fi_recovery')
      ORDER BY schemaname,relname
    ) x" > "$out/$name/tables_$phase.jsonl"
    sql "SELECT row_to_json(x)::text FROM (
      SELECT schemaname,relname,indexrelname,idx_scan,idx_tup_read,idx_tup_fetch
      FROM pg_stat_user_indexes
      WHERE schemaname IN ('fi_recovery_projection','fi_recovery')
      ORDER BY schemaname,relname,indexrelname
    ) x" > "$out/$name/indexes_$phase.jsonl"
    sql 'SELECT row_to_json(x)::text FROM (SELECT * FROM pg_stat_bgwriter) x' > "$out/$name/bgwriter_$phase.jsonl"
}
stats before || fail 'pre-run PostgreSQL stats unavailable'
# Automatic C1 pause telemetry: UTC-aligned one-second sampling.
# SELECT-only against disposable clone. No extra batch hashing/SQL handoffs.
iostat -x -w 1 > "$out/$name/iostat.txt" 2>&1 &
iostatpid=$!
vmstat -w 1 > "$out/$name/vmstat.txt" 2>&1 &
vmstatpid=$!
dip_sql=$(cat <<'C1_DIP_SQL'
SELECT json_build_object(
 'utc',to_char(clock_timestamp() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
 'source_parent',(SELECT row_to_json(p) FROM (
   SELECT pid,state,wait_event_type,wait_event,backend_xid::text AS backend_xid,
          backend_xmin::text AS backend_xmin,query_start,state_change
   FROM pg_stat_activity
   WHERE datname=current_database() AND backend_type='client backend'
     AND application_name='fi-c1-sourceparent-8g'
   ORDER BY pid LIMIT 1
 ) p),
 'activity',coalesce((SELECT json_agg(row_to_json(a)) FROM (
   SELECT backend_type,state,wait_event_type,wait_event,count(*) AS backends
   FROM pg_stat_activity
   WHERE datname=current_database() AND pid<>pg_backend_pid()
   GROUP BY backend_type,state,wait_event_type,wait_event
   ORDER BY backend_type,state,wait_event_type,wait_event
 ) a),'[]'::json),
 'wal',(SELECT row_to_json(w) FROM pg_stat_wal w),
 'checkpointer',(SELECT row_to_json(c) FROM pg_stat_checkpointer c),
 'io',coalesce((SELECT json_agg(row_to_json(i)) FROM pg_stat_io i),'[]'::json)
)::text
C1_DIP_SQL
)
# Prove the exact read-only wait/WAL/checkpointer/I/O sampler works before
# admitting any record. Otherwise a full replay could finish without enough
# evidence to investigate the observed CPU stalls.
sql "$dip_sql" > "$out/$name/dip_preflight.jsonl" ||
  fail 'C1 one-second PostgreSQL telemetry SQL unavailable before ingestion'
[ -s "$out/$name/dip_preflight.jsonl" ] &&
grep -Fq '"activity"' "$out/$name/dip_preflight.jsonl" &&
grep -Fq '"checkpointer"' "$out/$name/dip_preflight.jsonl" &&
grep -Fq '"source_parent"' "$out/$name/dip_preflight.jsonl" &&
grep -Fq '"io"' "$out/$name/dip_preflight.jsonl" ||
  fail 'C1 telemetry preflight missing SQL wait/checkpointer/io keys'
echo "FI C1 DIPS TELEMETRY PREFLIGHT PASS sampler=postgresql_activity_wal_checkpointer_io read_only=true before_ingestion=true"
: > "$out/$name/dip_sample_errors.txt"
(
 while :; do
   utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
   {
     printf 'UTC %s\n' "$utc"
     sysctl -n kern.cp_time 2>&1 || :
     sysctl -n kern.cp_times 2>&1 || :
   } >> "$out/$name/cpu_ticks_1s.txt"
   {
     printf 'UTC %s\n' "$utc"
     ps -ax -o pid,comm,pcpu,rss,state |
       awk 'NR==1 || $2 ~ /fi-optfield|postgres|fi-c1-verifier/' || :
   } >> "$out/$name/processes_1s.txt"
   if ! sql "$dip_sql" >> "$out/$name/postgres_waits_1s.jsonl" 2>> "$out/$name/dip_sample_errors.txt"; then
     printf 'UTC %s POSTGRES_SAMPLE_ERROR\n' "$utc" >> "$out/$name/dip_sample_errors.txt"
   fi
   sleep 1
 done
) > "$out/$name/dip_monitor.stderr" 2>&1 &
dipmonpid=$!
echo "FI C1 DIPS TELEMETRY START utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ') period=1s cpu_ticks=true pg_activity_waits=true wal=true checkpointer=true pg_io=true disk=true process=true readonly=true"
printf "FI FAMILY C1 SIGNED DIRECT START start_index=1 prefix8=$prefix8 group_gib=$group prep_lanes=5 prep_workers=2..32 sql_modules=5 source_ledger=ordered writer=shared_adaptive max_sql_workers=$sqlmax buffers=persistent_across_windows\n" | tee "$out/SUMMARY.txt"
export FI_W512_C1_P6_DIRECT=1
export FI_C1_DEV_ASYNC_VERIFY=1
export FI_C1_DEV_PROCESS_VERIFY=1
# A executes on the host. B was compiled inside fi-dev; use the existing
# jailroot mapping already verified by this runner, never the jail path alone.
verifier_host="$jailroot$root/fi-c1-verifier"
verifier_digest="$jailroot$root/verifier.sha256"
[ -x "$verifier_host" ] && [ -s "$verifier_digest" ] ||
  fail 'C1 B host-visible executable or digest absent'
expected_verifier_sha=$(cat "$verifier_digest") || fail 'C1 B digest unreadable'
actual_verifier_sha=$(sha256 -q "$verifier_host") || fail 'C1 B executable unreadable'
[ -n "$expected_verifier_sha" ] && [ "$actual_verifier_sha" = "$expected_verifier_sha" ] ||
  fail 'C1 independent B executable digest changed'
export FI_C1_DEV_VERIFIER_BIN="$verifier_host"
echo "FI C1 B HOST EXECUTABLE PREFLIGHT PASS host_path=$verifier_host sha256=$actual_verifier_sha"
export FI_W512_C1_SQL_WORKERS_MAX="$sqlmax"
# Restore candidate mode only for the actual private ingestion executable.
# All Go/race compile tests ran with the ordinary control defaults.
export FI_C1_SECURITY_8G_EXPERIMENT="$security8"
export FI_C1_SECURITY_FULL_BACKLOG_CANDIDATE="$fullcandidate"
export FI_C1_SOURCE_PROFILE_8G="$sourceprof"
if [ "$prefix8" = 1 ];then
  export FI_W512_C1_STOP_WINDOWS=2
  export FI_W512_C1_GROUP_GIB=4
  export FI_W512_C1_FULL_BACKLOG=0
  export FI_C1_DEV_PREFIX8=1
else
  unset FI_W512_C1_STOP_WINDOWS FI_C1_DEV_PREFIX8
  export FI_W512_C1_GROUP_GIB=4
  export FI_W512_C1_FULL_BACKLOG=1
fi
export FI_W512_C1_SQL_DSN="host=$out/pg-$name port=$port user=fi_ingest dbname=fi sslmode=disable"
export FI_W512_C1_EXPECTED_PGDATA="$root/$name/data"
# No injected failure in the full backlog throughput/correctness experiment.
unset FI_C1_DEV_FAIL_AFTER_FILE_SQL_COMMIT
if /usr/bin/time -l "$recover" \
  -private-w512-2g -private-hash-h16 \
  -private-mixed-family-buffers -private-dependency-buffers -private-parallel-prep-a \
  -source=iss-fs-22a.iss.local \
  -generation-id=20261030T000032.061323100Z-3e38b2210771462c \
  -postgres="host=$out/pg-$name port=$port user=fi_ingest dbname=fi sslmode=disable" \
  -custody-root=/work/fi-c220-20261114/custody/generation -recorded-root=/work/fi-c220-20261114/custody/recorded \
  -source-namespaces=false -private-root="$private_root" \
  -private-writes -private-field-partitions \
  -security-profile=P3 -file-profile=F3 -window-profile=W512 \
  -processing-chunk-records=32768 -continuous-private -start-window=1 \
  -max-windows=0 -max-runtime=0 -test-stop-after-windows=0 \
  -deferred-verified-clone -verified-cache-root="$cache" > "$out/$name/recover.log" 2>&1; then
    [ "$prefix8" = 0 ] || fail '8GiB prefix returned unexpected full-generation success'
else
    if [ "$prefix8" = 1 ] &&
       grep -Fq 'FI C1 PRIVATE 8G PREFIX PROOF PASS groups=2 windows=3 ' "$out/$name/recover.log" &&
       grep -Fq 'FI continuous private recovery: context canceled' "$out/$name/recover.log" &&
       ! grep -Fq 'FI REAL BACKLOG PRIVATE COMPLETE ' "$out/$name/recover.log";then
        echo 'FI C1 CONTROLLED PREFIX STOP PASS exact_two_4GiB_groups=true full_generation=false'
    else
        tail -n 100 "$out/$name/recover.log" >&2 || :
        fail 'C1 signed replay failed before controlled 8GiB prefix proof'
    fi
fi
for pid in "$iostatpid" "$vmstatpid" "$dipmonpid"; do
    kill -TERM "$pid" 2>/dev/null || :
    wait "$pid" 2>/dev/null || :
done
iostatpid=
vmstatpid=
dipmonpid=
stats after || fail 'postrun PostgreSQL stats unavailable'
[ -s "$out/$name/cpu_ticks_1s.txt" ] &&
[ -s "$out/$name/processes_1s.txt" ] &&
[ -s "$out/$name/postgres_waits_1s.jsonl" ] ||
  fail 'one-second CPU/SQL telemetry missing'
echo "FI C1 DIPS TELEMETRY PASS sample_period=1s CPU=true PostgreSQL_waits=true WAL=true checkpoints=true"
log="$out/$name/recover.log"
echo "FI C1 POSTGRES WAL BUFFERS EXPERIMENT PASS max_wal_size=$pg_max_wal wal_buffers=$pg_wal_buffers durability=on checkpoint_stats=before_after clone_only=true"
if [ "$prefix8" = 1 ];then
  grep '^FI C1 EIGHT GIB SIGNED PLAN ' "$log" > "$out/$name/C1_PLAN.txt" ||
    fail 'C1 8GiB exact signed prefix plan absent'
  [ "$(wc -l < "$out/$name/C1_PLAN.txt" | tr -d '[:space:]')" = 1 ] &&
  grep -Fq 'group_gib=4 new_windows=2 ' "$out/$name/C1_PLAN.txt" &&
  grep -Fq 'seed_unchanged=true identical_prefix=true' "$out/$name/C1_PLAN.txt" ||
    fail 'C1 8GiB signed prefix plan invalid'
else
  grep '^FI C1 FULL BACKLOG SIGNED PLAN ' "$log" > "$out/$name/C1_PLAN.txt" ||
    fail 'C1 full 4GiB signed receipt plan absent'
  [ "$(wc -l < "$out/$name/C1_PLAN.txt" | tr -d '[:space:]')" = 1 ] &&
  grep -Fq 'group_gib=4 ' "$out/$name/C1_PLAN.txt" &&
  grep -Fq 'seed_unchanged=true no_record_window_limit=true' "$out/$name/C1_PLAN.txt" ||
    fail 'C1 full signed generation plan invalid'
fi
plan_field() {
  awk -v want="$1" '
    /^FI C1 (FULL BACKLOG|EIGHT GIB) SIGNED PLAN / {
      for(i=1;i<=NF;i++){
        n=split($i,p,"=")
        if(n==2 && p[1]==want && p[2]~/^[0-9]+$/){print p[2];found=1;exit}
      }
    }
    END {if(!found)exit 1}
  ' "$out/$name/C1_PLAN.txt"
}
rows=$(plan_field new_records) || fail 'C1 signed record count missing'
bytes=$(plan_field new_source_bytes) || fail 'C1 signed bytes missing'
lastbatch=$(plan_field last_batch) || fail 'C1 signed end batch missing'
windows=$(plan_field new_windows) || fail 'C1 number of 4GiB groups missing'
if [ "$prefix8" = 1 ];then
  signed_batches=$lastbatch
  seeded=493478
  [ "$windows" = 2 ] && [ "$rows" -gt 1000000 ] &&
  [ "$bytes" -ge 8522825728 ] && [ "$bytes" -le 8589934592 ] &&
  [ "$lastbatch" -lt 8399 ] && [ "$lastbatch" -gt 205 ] ||
    fail 'C1 exact 8GiB signed prefix size or cutoff invalid'
else
  signed_batches=$(plan_field signed_batches) || fail 'C1 total signed batches missing'
  seeded=$(plan_field seeded_records) || fail 'C1 signed seed count missing'
  [ "$windows" -gt 2 ] && [ "$windows" -le 64 ] &&
  [ "$rows" -gt 10000000 ] && [ "$bytes" -gt 42949672960 ] &&
  [ "$lastbatch" = "$signed_batches" ] && [ "$seeded" = 493478 ] ||
    fail 'C1 full signed source size/cutoff guard failed'
fi
grep -Fxq "FI C1 CLEAN START PASS windows=1..$windows signed_parents_absent=true typed_markers_absent=true restart_requires_fresh_clone=true" "$log" ||
  fail 'C1 signed destination was not clean before replay'
if [ "$prefix8" = 1 ];then
  grep '^FI C1 PRIVATE 8G PREFIX PROOF PASS ' "$log" > "$out/$name/C1_FULL_PROOF.txt" ||
    fail 'C1 private 8GiB prefix-only SQL/marker proof missing'
  grep -Fq "groups=2 windows=3 source_records=$((seeded+rows)) new_records=$rows source_bytes=$bytes signed_batches=$signed_batches full_generation=false authoritative=0 accepted=0" "$out/$name/C1_FULL_PROOF.txt" ||
    fail 'C1 prefix relational proof differs from signed target'
  ! grep -q '^FI C1 FULL GROUPED RELATIONAL PROOF PASS ' "$log" ||
    fail 'C1 incomplete prefix falsely declared full-generation proof'
  ! grep -q '^FI REAL BACKLOG PRIVATE COMPLETE ' "$log" ||
    fail 'C1 prefix falsely declared complete signed generation'
  printf 'FI C1 PRIVATE PREFIX ONLY groups=2 full_generation=false\n' > "$out/$name/C1_COMPLETE.txt"
else
  grep '^FI C1 FULL GROUPED RELATIONAL PROOF PASS ' "$log" > "$out/$name/C1_FULL_PROOF.txt" ||
    fail 'C1 full clone relational verification proof absent'
  grep -Fq "windows=$((windows+1)) signed_batches=$signed_batches records=$((seeded+rows)) bytes=" "$out/$name/C1_FULL_PROOF.txt" &&
  grep -Fq 'authoritative=0 accepted=0 artifact_source_markers=seed_only proof=private_clone_only' "$out/$name/C1_FULL_PROOF.txt" ||
    fail 'C1 full clone proof totals/identity mismatched'
  grep '^FI REAL BACKLOG PRIVATE COMPLETE ' "$log" > "$out/$name/C1_COMPLETE.txt" ||
    fail 'C1 full private-generation completion missing'
  grep -Fq "windows=$((windows+1)) records=$((seeded+rows)) " "$out/$name/C1_COMPLETE.txt" ||
    fail 'C1 full receipt not complete'
fi
grep '^FI C1 P6 DIRECT READ ' "$log" > "$out/$name/C1_READ.txt" ||
  fail 'C1 full signed batch read receipts missing'
awk -v expected="$rows" -v expected_bytes="$bytes" -v groups="$windows" '
/^FI C1 P6 DIRECT READ /{
  delete x
  for(i=1;i<=NF;i++){split($i,a,"=");x[a[1]]=a[2]}
  w=x["window"]+0
  if(w<1||w>groups||seen[w]++||x["source_stage_rows"]!="0"||
     x["copied_artifacts"]!="0"||x["signed_batches"]<1)bad=1
  n+=x["records"]+0;b+=x["bytes"]+0;nb+=x["signed_batches"]+0
}
END{
  for(i=1;i<=groups;i++)if(seen[i]!=1)bad=1
  if(bad||n!=expected||b!=expected_bytes||nb<1)exit 1
}' "$out/$name/C1_READ.txt" || fail 'C1 full signed receipt total mismatch'
grep '^FI C1 P6 NATIVE SQL BACKENDS ' "$log" > "$out/$name/C1_BACKENDS.txt" ||
  fail 'C1 shared native P6 SQL pool missing'
[ "$(wc -l < "$out/$name/C1_BACKENDS.txt" | tr -d ' ')" = 1 ] &&
grep -Fq "shared_workers_initial=1 workers_max=$sqlmax distinct_pids=2 clone_only=true" "$out/$name/C1_BACKENDS.txt" ||
  fail 'C1 shared SQL worker pool did not start from one verified connection'
# The exact child executable must have started as a second OS process
# before A's continuous P5/P6 preparation and SQL admission began.
grep '^FI C1 B OS PROCESS SPAWN ' "$log" > "$out/$name/C1_B_SPAWN.txt" ||
  fail 'C1 B independent OS process was not spawned'
grep '^FI C1 B OS PROCESS START ' "$log" > "$out/$name/C1_B_PROCESS.txt" ||
  fail 'C1 B independent OS process did not establish read-only SQL'
[ "$(wc -l < "$out/$name/C1_B_SPAWN.txt" | tr -d '[:space:]')" = 1 ] &&
[ "$(wc -l < "$out/$name/C1_B_PROCESS.txt" | tr -d '[:space:]')" = 1 ] &&
grep -Fq 'read_only=true separate_os_process=true' "$out/$name/C1_B_PROCESS.txt" &&
grep -Fq 'controls_p6=false original_batch_sha_pass=none' "$out/$name/C1_B_SPAWN.txt" ||
  fail 'C1 B process isolation or no-extra-SHA proof missing'
awk '
/^FI C1 B OS PROCESS SPAWN / {
 for(i=1;i<=NF;i++){split($i,a,"=");if(a[1]=="pid")child=a[2];if(a[1]=="parent_pid")parent=a[2]}
}
/^FI C1 B OS PROCESS START /{
 for(i=1;i<=NF;i++){split($i,a,"=");if(a[1]=="pid")started=a[2]}
}
END{if(child==""||parent==""||started!=child||child==parent)exit 1}
' "$log" || fail 'C1 B PID must differ from ingestion A PID'
# B runs read-only against independently committed data, not on A's
# execution clock. No SQL capacity handoff or all-family flush may be
# introduced solely to make B finish while A is still ingesting.
grep '^FI C1 COMMIT READY ' "$log" > "$out/$name/C1_COMMIT_READY.txt" ||
  fail 'C1 durable SQL group-ready notifications missing'
[ "$(wc -l < "$out/$name/C1_COMMIT_READY.txt" | tr -d '[:space:]')" = "$windows" ] &&
grep -Fq 'custody_batch_sealed=true no_group_flush=true' "$out/$name/C1_COMMIT_READY.txt" ||
  fail 'C1 did not emit durable source+family and custody-bound group readiness'
# Age or verifier-driven handoffs are forbidden. An independent 30-second
# inactivity timer is a real Family Processing flush trigger, not a B command.
if grep '^FI P6 FAMILY ' "$log" | grep -Eq ' age=[1-9][0-9]* '; then
  fail 'C1 added sparse-family SQL handoffs to schedule B'
fi
grep '^FI C1 FAMILY PROCESSING INACTIVITY TIMER ' "$log" > "$out/$name/C1_IDLE_TIMER.txt" ||
  fail 'C1 independent 30-second inactivity timer never started'
[ "$(wc -l < "$out/$name/C1_IDLE_TIMER.txt" | tr -d '[:space:]')" = 1 ] &&
grep -Fq 'timeout=30s poll=1s per_family=true resets_on=received_record no_input_required=true owner=ordered_consumer no_batch_flush=true no_group_flush=true' "$out/$name/C1_IDLE_TIMER.txt" ||
  fail 'C1 30s inactivity timer is not single-owner or per-family'
grep '^FI C1 FAMILY PROCESSING IDLE FLUSH ' "$log" > "$out/$name/C1_IDLE_FLUSH.txt" || :
# A fully active run can legitimately have zero idle flushes. Preserve an
# empty evidence file rather than inventing a timer event.
if grep '^FI C1 FAMILY PROCESSING IDLE FLUSH ' "$log" |
  grep -Ev 'timeout=30s .*trigger=inactivity no_batch_flush=true no_group_flush=true verifier_independent=true'; then
  fail 'C1 unexpected idle-family trigger or timeout'
fi
grep '^FI C1 ASYNC VERIFY PASS ' "$log" > "$out/$name/C1_ASYNC_VERIFY.txt" ||
  fail 'C1 independent read-only group proofs missing'
[ "$(wc -l < "$out/$name/C1_ASYNC_VERIFY.txt" | tr -d '[:space:]')" = "$windows" ] &&
awk -v expected="$windows" '
{
 delete p
 for(i=1;i<=NF;i++){n=split($i,a,"=");if(n==2)p[a[1]]=a[2]}
 w=p["window"]+0
 if(w<1||w>expected||seen[w]++||p["attempts"]!="1"||
    p["read_only"]!="true"||p["independent_connection"]!="true"||
    p["commit_ready"]!="true"||p["separate_os_process"]!="true")bad=1
 if(p["phase"]!="during_ingest"&&p["phase"]!="after_drain")bad=1
}
END{
 for(i=1;i<=expected;i++)if(seen[i]!=1)bad=1
 if(bad)exit 1
}' "$out/$name/C1_ASYNC_VERIFY.txt" ||
  fail 'C1 read-only B proof incomplete or incorrectly reported'
grep -Fq "FI C1 ASYNC VERIFY COMPLETE groups=$windows during_ingest=" "$log" &&
grep -Fq 'original_relational_rescans=removed final_marker_gate=preserved separate_os_process=true' "$log" &&
! grep -Fq 'FI C1 ASYNC VERIFY FAIL ' "$log" ||
  fail 'C1 independent verifier proof completion missing'
grep '^FI C1 B GROUPS PROOF PASS ' "$log" > "$out/$name/C1_B_GROUPS.txt" ||
  fail 'B never acknowledged all original committed group proofs'
[ "$(wc -l < "$out/$name/C1_B_GROUPS.txt" | tr -d '[:space:]')" = 1 ] &&
grep -Fq "groups=$windows read_only=true no_p6_flush=true awaiting_final_marker=true" "$out/$name/C1_B_GROUPS.txt" ||
  fail 'B group proof receipt disagrees with original signed group count'
grep '^FI C1 B FINAL GENERATION VERIFY PASS ' "$log" > "$out/$name/C1_B_FINAL.txt" ||
  fail 'B final independent generation proof missing'
[ "$(wc -l < "$out/$name/C1_B_FINAL.txt" | tr -d '[:space:]')" = 1 ] &&
grep -Fq "mode=$( [ "$prefix8" = 1 ] && echo prefix || echo generation ) groups=$windows" "$out/$name/C1_B_FINAL.txt" &&
grep -Fq 'read_only=true separate_os_process=true' "$out/$name/C1_B_FINAL.txt" ||
  fail 'B final SQL proof mode or OS process identity invalid'
[ "$(grep -c '^FI C1 B FINAL RESULT ' "$log")" = 1 ] ||
  fail 'B final structured receipt missing or duplicated'
grep '^FI C1 PRE-INGEST SETUP ' "$log" > "$out/$name/C1_SETUP.txt" ||
  fail 'C1 independent pre-ingest startup timer missing'
grep '^FI C1 INGEST CLOCK START ' "$log" > "$out/$name/C1_INGEST_START.txt" ||
  fail 'C1 first-record P5/P6 ingest timer missing'
[ "$(wc -l < "$out/$name/C1_SETUP.txt" | tr -d '[:space:]')" = 1 ] &&
[ "$(wc -l < "$out/$name/C1_INGEST_START.txt" | tr -d '[:space:]')" = 1 ] &&
grep -Fq 'excluded_from_ingest_rate=true' "$out/$name/C1_SETUP.txt" &&
grep -Fq 'setup_excluded=true verifier_excluded=true' "$out/$name/C1_INGEST_START.txt" ||
  fail 'C1 startup/ingest timer separation contract failed'
grep '^FI C1 P6 SQL DRAIN ' "$log" > "$out/$name/C1_SQL_DRAIN.txt" ||
  fail 'C1 separate P6 SQL-drain performance receipt missing'
# C1 adds the original P5 five-family parallel Go preparation pool,
# retained across all signed batches and every 4GiB reporting window.
grep '^FI C1 P5 CONTINUOUS SIGNED STREAM PASS ' "$log" > "$out/$name/C1_STREAM.txt" ||
  fail 'C1 did not verify one continuous P5 preparation stream'
[ "$(wc -l < "$out/$name/C1_STREAM.txt" | tr -d '[:space:]')" = 1 ] &&
grep -Fq "batches=$((signed_batches-205)) sessions=1 records=$rows sealed_batches=$((signed_batches-205)) custody_sha256=receiver_verified per_batch_manifest=true exact_ordinals=true buffers=bounded" "$out/$name/C1_STREAM.txt" ||
  fail 'C1 continuous P5 custody-bound batch counts or one-session proof missing'
grep '^FI C1 P5 PREP COMPLETE ' "$log" > "$out/$name/C1_PREP.txt" ||
  fail 'C1 original P5 family preparation pool completion missing'
grep -Fq "records=$rows family_lanes=5 worker_min=2 worker_max=32 " "$out/$name/C1_PREP.txt" ||
  fail 'C1 P5 dynamic family preparation counts incorrect'
grep '^FI P5 PERSISTENT WINDOW FAMILY ' "$log" > "$out/$name/C1_P5_LANES.txt" ||
  fail 'C1 original P5 family worker summary absent'
[ "$(wc -l < "$out/$name/C1_P5_LANES.txt" | tr -d '[:space:]')" = 5 ] ||
  fail 'C1 did not retain all five original P5 preparation lanes'
grep '^FI C1 P6 CONTINUOUS FAMILY ' "$log" > "$out/$name/C1_CONTINUOUS_FAMILIES.txt" ||
  fail 'C1 P5/P6 sliding-ACK continuous family proof missing'
[ "$(wc -l < "$out/$name/C1_CONTINUOUS_FAMILIES.txt" | tr -d '[:space:]')" = 5 ] &&
grep -Fq "family=Security max_outstanding=$( [ "$sqlmax" -gt 4 ] && echo "$sqlmax" || echo 4) " "$out/$name/C1_CONTINUOUS_FAMILIES.txt" &&
grep -Fq "family=NTFSFile max_outstanding=$( [ "$sqlmax" -gt 4 ] && echo "$sqlmax" || echo 4) " "$out/$name/C1_CONTINUOUS_FAMILIES.txt" ||
  fail 'C1 continuous P6 family backpressure/report mismatch'
# The original source and File/NTFS relationships remain durable before
# USN SQL, but the main Preparation reader is no longer serialized behind
# every USN SQL ACK. Both queues are bounded and use the SAME SQL workers.
grep '^FI C1 ASYNC USN DISPATCH START ' "$log" > "$out/$name/C1_USN_ASYNC_START.txt" ||
  fail 'C1 asynchronous ordered USN dispatcher was not started'
grep '^FI C1 ASYNC USN DISPATCH COMPLETE ' "$log" > "$out/$name/C1_USN_ASYNC_COMPLETE.txt" ||
  fail 'C1 asynchronous ordered USN dispatcher did not complete'
[ "$(wc -l < "$out/$name/C1_USN_ASYNC_START.txt" | tr -d '[:space:]')" = 1 ] &&
[ "$(wc -l < "$out/$name/C1_USN_ASYNC_COMPLETE.txt" | tr -d '[:space:]')" = 1 ] &&
grep -Fq 'queue_max=64 ordered_SQL_commits=true file_dependencies=commit_fences shared_sql_workers=true extra_pg_connections=0' "$out/$name/C1_USN_ASYNC_START.txt" &&
grep -Fq 'queue_max=64 ' "$out/$name/C1_USN_ASYNC_COMPLETE.txt" &&
grep -Fq 'ordered_commit=true shared_sql=true' "$out/$name/C1_USN_ASYNC_COMPLETE.txt" &&
grep -Fq 'family=USNDependency max_outstanding=64 ' "$out/$name/C1_CONTINUOUS_FAMILIES.txt" ||
  fail 'C1 USN queue/ordering/family limits do not match async design'
awk '
  {
    delete x
    for(i=1;i<=NF;i++){n=split($i,p,"=");if(n==2)x[p[1]]=p[2]}
    if(x["peak_outstanding"]<1||x["peak_outstanding"]>64||
       x["committed_handoffs"]<1)exit 1
  }
' "$out/$name/C1_USN_ASYNC_COMPLETE.txt" ||
  fail 'C1 USN dispatcher did not commit or violated bounded backlog'
# Every USN buffer SQL ACK counted in the existing Family Processing
# receipt must also appear in the asynchronous dispatcher commit receipt.
usn_buffer_handoffs=$(awk '/^FI P6 FAMILY / && /family=USNDependency/ {
    for(i=1;i<=NF;i++){split($i,p,"=");if(p[1]=="handoffs"){print p[2];exit}}
}' "$log")
usn_async_commits=$(awk '{
    for(i=1;i<=NF;i++){split($i,p,"=");if(p[1]=="committed_handoffs"){print p[2];exit}}
}' "$out/$name/C1_USN_ASYNC_COMPLETE.txt")
[ -n "$usn_buffer_handoffs" ] && [ "$usn_buffer_handoffs" = "$usn_async_commits" ] ||
  fail 'C1 asynchronous USN commit count differs from real Family Processing SQL handoffs'
echo "FI C1 ASYNC USN COMMIT ACCOUNTING PASS handoffs=$usn_async_commits ordered=true file_fences=true bounded=true"

grep '^FI C1 SECURITY 8G PROFILE ' "$log" > "$out/$name/C1_SECURITY_8G_PROFILE.txt" ||
  fail 'C1 8GiB Security COPY profile selection was not reported'
[ "$(wc -l < "$out/$name/C1_SECURITY_8G_PROFILE.txt" | tr -d '[:space:]')" = 1 ] ||
  fail 'C1 Security 8GiB profile must have exactly one report'
if [ "$security8" = 1 ];then
  expect_full=false
  if [ "$prefix8" = 0 ];then
    [ "$fullcandidate" = 1 ] || fail 'missing full-backlog Security candidate selection'
    expect_full=true
  fi
  grep -Fq "mode=candidate security_rows=8192 security_bytes=33554432 sql_profile=P4 field_rows=65536 field_bytes=16777216 reusable_event=true reusable_scope=true separate_field_partitions=false full_backlog=$expect_full clone_only=true" "$out/$name/C1_SECURITY_8G_PROFILE.txt" ||
    fail 'C1 candidate did not retain the exact 8192/32MiB and 65536/16MiB Security profile'
else
  grep -Fq 'mode=control security_rows=4096 security_bytes=16777216 sql_profile=P3 field_rows=32768 field_bytes=8388608 reusable_event=false reusable_scope=false separate_field_partitions=false' "$out/$name/C1_SECURITY_8G_PROFILE.txt" ||
    fail 'C1 Security control profile unexpectedly changed'
fi
echo "FI C1 SECURITY 8G SELECTION PASS mode=$( [ "$security8" = 1 ] && echo candidate || echo control ) same_relational_schema=true signed_source_unchanged=true verification_required=true"
if [ "$security8" = 1 ] && [ "$prefix8" = 0 ];then
  echo 'FI C1 SECURITY FULL BACKLOG CANDIDATE PASS profile=8192_32MiB_65536_16MiB_reusable_row sourceparent=ordered verifier=B clone_only=true'
fi
grep '^FI C1 SOURCE PARENT STAGES ' "$log" > "$out/$name/C1_SOURCE_PARENT_STAGES.txt" ||
  fail 'C1 serial SourceParent COPY/commit breakdown was not recorded'
if [ "$sourceprof" = 1 ];then
  grep '^FI C1 SOURCE PARENT BACKEND ' "$log" > "$out/$name/C1_SOURCE_PARENT_BACKEND.txt" ||
    fail 'C1 SourceParent backend PID identity missing'
  grep '^FI C1 SOURCE PARENT COPY DETAIL ' "$log" > "$out/$name/C1_SOURCE_PARENT_COPY_DETAIL.txt" ||
    fail 'C1 SourceParent cursor/COPY diagnostic missing'
  [ "$(wc -l < "$out/$name/C1_SOURCE_PARENT_BACKEND.txt" | tr -d '[:space:]')" = 1 ] &&
  [ "$(wc -l < "$out/$name/C1_SOURCE_PARENT_COPY_DETAIL.txt" | tr -d '[:space:]')" = 1 ] &&
  grep -Fq 'phase_remainder_includes_pgx_encode_io_server=true one_parent_connection=true clone_only=true' "$out/$name/C1_SOURCE_PARENT_COPY_DETAIL.txt" ||
    fail 'C1 SourceParent diagnostic inconsistent or incomplete'
  grep -Fq '"source_parent"' "$out/$name/postgres_waits_1s.jsonl" ||
    fail 'C1 SourceParent wait samples missing'
else
  echo 'FI C1 SOURCE PARENT BACKEND profiler=off' > "$out/$name/C1_SOURCE_PARENT_BACKEND.txt"
  echo 'FI C1 SOURCE PARENT COPY DETAIL profiler=off' > "$out/$name/C1_SOURCE_PARENT_COPY_DETAIL.txt"
fi
[ "$(wc -l < "$out/$name/C1_SOURCE_PARENT_STAGES.txt" | tr -d '[:space:]')" = 1 ] &&
grep -Fq 'single_connection=true no_schema_change=true' "$out/$name/C1_SOURCE_PARENT_STAGES.txt" &&
grep -Eq 'copy=[0-9]' "$out/$name/C1_SOURCE_PARENT_STAGES.txt" &&
grep -Eq 'commit=[0-9]' "$out/$name/C1_SOURCE_PARENT_STAGES.txt" ||
  fail 'C1 ordered SourceParent stage breakdown incomplete'
grep '^FI C1 SQL PROFILE ' "$log" > "$out/$name/C1_SQL_PROFILE.txt" ||
  fail 'C1 per-family SQL performance and commit profile missing'
[ "$(wc -l < "$out/$name/C1_SQL_PROFILE.txt" | tr -d '[:space:]')" = 6 ] ||
  fail 'C1 did not report the source parent and five SQL family lanes'
grep '^FI C1 SECURITY COPY CALL PROFILE ' "$log" > "$out/$name/C1_SECURITY_COPY_CALLS.txt" ||
  fail 'C1 Security COPY per-call latency telemetry missing'
[ "$(wc -l < "$out/$name/C1_SECURITY_COPY_CALLS.txt" | tr -d '[:space:]')" = 1 ] &&
grep -Eq 'event_calls=[1-9][0-9]* ' "$out/$name/C1_SECURITY_COPY_CALLS.txt" &&
grep -Eq 'field_calls=[1-9][0-9]* ' "$out/$name/C1_SECURITY_COPY_CALLS.txt" &&
grep -Fq 'concurrent_time_sum=true' "$out/$name/C1_SECURITY_COPY_CALLS.txt" ||
  fail 'C1 Security field COPY call distribution incomplete'
if [ "$security8" = 1 ];then
  grep -Fq 'field_max_rows=65536 field_max_bytes=16777216 ' "$out/$name/C1_SECURITY_COPY_CALLS.txt" ||
    fail 'C1 Security candidate COPY reported incorrect 65536/16MiB actual field limits'
else
  grep -Fq 'field_max_rows=32768 field_max_bytes=8388608 ' "$out/$name/C1_SECURITY_COPY_CALLS.txt" ||
    fail 'C1 Security control COPY reported incorrect 32768/8MiB actual field limits'
fi
grep '^FI C1 SHARED SQL POOL ' "$log" > "$out/$name/C1_POOL.txt" ||
  fail 'C1 dynamic SQL worker pool metrics missing'
[ "$(wc -l < "$out/$name/C1_POOL.txt" | tr -d '[:space:]')" = 1 ] &&
grep -Fq "workers_min=1 workers_max=$sqlmax " "$out/$name/C1_POOL.txt" ||
  fail 'C1 SQL pool bounds differ from configured maximum'
awk -v cap="$sqlmax" '{
  for(i=1;i<=NF;i++){split($i,p,"=");x[p[1]]=p[2]}
  if(x["workers_peak"]<1||x["workers_peak"]>cap||x["workers_current"]<1||
     x["workers_current"]>cap||x["busy"]!=0)exit 1
  if(cap>1&&(x["workers_peak"]<2||x["security_sql_peak"]<2))exit 1
  if(x["security_sql_peak"]<1||x["security_sql_peak"]>cap||x["jobs_completed"]<5)exit 1
}' "$out/$name/C1_POOL.txt" || fail 'C1 adaptive SQL worker bound or scale-up proof missing'
# Expose the original P6 Security COPY counters once, without altering the
# C220 clone schema, SQL module, staging, or network/PG permissions.
grep '^FI C1 SECURITY COPY PROFILE ' "$log" > "$out/$name/C1_SECURITY_COPY.txt" ||
  fail 'C1 existing Security COPY timing counters not retained'
[ "$(wc -l < "$out/$name/C1_SECURITY_COPY.txt" | tr -d '[:space:]')" = 1 ] &&
grep -Eq 'events=[1-9][0-9]* ' "$out/$name/C1_SECURITY_COPY.txt" &&
grep -Eq 'fields=[1-9][0-9]* ' "$out/$name/C1_SECURITY_COPY.txt" ||
  fail 'C1 Security event/child COPY profiling count mismatch'
grep '^FI C1 P6 SHARED SQL PASS ' "$log" > "$out/$name/C1_FAMILIES.txt" ||
  fail 'C1 all five SQL worker handoffs missing'
grep -Fq "windows=$windows records=$rows bytes=$bytes " "$out/$name/C1_FAMILIES.txt" &&
grep -Fq "five_committed=$rows " "$out/$name/C1_FAMILIES.txt" &&
grep -Fq 'source_staging=none ' "$out/$name/C1_FAMILIES.txt" ||
  fail 'C1 P6 family/source completion incorrect'
[ "$(sql 'SELECT count(*) FROM fi_recovery.typed_window')" = "$((windows+1))" ] &&
[ "$(sql "SELECT coalesce(sum(committed_records),0) FROM fi_recovery.typed_window WHERE window_index BETWEEN 1 AND $windows")" = "$rows" ] &&
[ "$(sql 'SELECT count(*) FROM fi_recovery.source_window')" = 1 ] &&
[ "$(sql 'SELECT count(*) FROM fi_recovery.verified_artifact_window')" = 1 ] &&
[ "$(sql 'SELECT count(*) FROM fi_recovery.pending_source_record')" = 493478 ] &&
[ "$(sql 'SELECT count(*) FROM fi_recovery_projection.source_record')" = "$((493478+rows))" ] &&
[ "$(sql "SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted'")" = 0 ] &&
[ "$(sql 'SELECT count(*) FROM fi.recorded_generation')" = 0 ] ||
  fail 'C1 clone-only source stages/typed checkpoint/authoritative counts invalid'
[ "$(sql "SELECT count(*) FROM pg_constraint WHERE connamespace='fi_recovery_projection'::regnamespace AND contype='f' AND NOT convalidated")" = 0 ] ||
  fail 'C1 relational foreign keys not all validated'
grep '^FI C1 P6 SHARED SQL PASS ' "$log" > "$out/$name/RESULT.txt" ||
  fail 'C1 full SQL pipeline completion receipt missing'
grep '^FI REAL BACKLOG DURABLE ' "$log" > "$out/$name/WINDOWS.txt" ||
  fail 'C1 durable per-window reports absent'
elapsed=$(sed -n 's/.* duration=\([^ ]*\).*/\1/p' "$out/$name/RESULT.txt")
[ -n "$elapsed" ] || fail 'C1 benchmark elapsed time missing'
printf "FI C220 C1 DEV PASS prefix8=$prefix8 groups=$windows group_gib=4 records=$rows source_bytes=$bytes last_batch=$lastbatch signed_batches=$signed_batches elapsed=%s writer=adaptive_shared sql_workers_max=$sqlmax P5_prep=5x2_to_32 source_stage=none commit_ready=true original_relational_rescans=removed authoritative=0 accepted=0\n" "$elapsed" |
  tee -a "$out/SUMMARY.txt"
tar -C "$out" -czf "$out/fi-c1-full-backlog-4g-$stamp.tar.gz" RUN_MANIFEST.txt SUMMARY.txt relay.log \
  "$name/recover.log" "$name/C1_READ.txt" "$name/C1_BACKENDS.txt" \
  "$name/C1_FAMILIES.txt" "$name/C1_PLAN.txt" "$name/C1_FULL_PROOF.txt" "$name/C1_COMPLETE.txt" "$name/C1_PREP.txt" "$name/C1_STREAM.txt" "$name/C1_B_SPAWN.txt" "$name/C1_B_PROCESS.txt" "$name/C1_B_GROUPS.txt" "$name/C1_B_FINAL.txt" "$name/C1_COMMIT_READY.txt" "$name/C1_ASYNC_VERIFY.txt" "$name/C1_SQL_DRAIN.txt" "$name/C1_P5_LANES.txt" \
  "$name/C1_SETUP.txt" "$name/C1_INGEST_START.txt" \
  "$name/C1_IDLE_TIMER.txt" "$name/C1_IDLE_FLUSH.txt" \
  "$name/C1_SQL_PROFILE.txt" "$name/C1_SOURCE_PARENT_STAGES.txt" "$name/C1_SOURCE_PARENT_BACKEND.txt" "$name/C1_SOURCE_PARENT_COPY_DETAIL.txt" "$name/C1_SECURITY_8G_PROFILE.txt" "$name/C1_SECURITY_COPY.txt" "$name/C1_SECURITY_COPY_CALLS.txt" \
  "$name/C1_CONTINUOUS_FAMILIES.txt" "$name/C1_POOL.txt" \
  "$name/C1_USN_ASYNC_START.txt" "$name/C1_USN_ASYNC_COMPLETE.txt" \
  "$name/RESULT.txt" "$name/WINDOWS.txt" \
  "$name/wal_before.jsonl" "$name/wal_after.jsonl" \
  "$name/checkpointer_before.jsonl" "$name/checkpointer_after.jsonl" \
  "$name/io_before.jsonl" "$name/io_after.jsonl" \
  "$name/tables_before.jsonl" "$name/tables_after.jsonl" \
  "$name/indexes_before.jsonl" "$name/indexes_after.jsonl" \
  "$name/bgwriter_before.jsonl" "$name/bgwriter_after.jsonl" \
  "$name/iostat.txt" "$name/vmstat.txt" \
  "$name/cpu_ticks_1s.txt" "$name/processes_1s.txt" \
  "$name/postgres_waits_1s.jsonl" "$name/dip_preflight.jsonl" "$name/dip_sample_errors.txt" \
  "$name/dip_monitor.stderr" || fail 'C1 metrics bundle failed'
bundle="$out/fi-c1-full-backlog-4g-$stamp.tar.gz"
[ -s "$bundle" ] || fail 'C1 full-backlog 4GiB metrics bundle missing'
bundle_sha=$(sha256 -q "$bundle") || fail 'C1 full-backlog 4GiB metrics bundle SHA failed'
[ "${#bundle_sha}" -eq 64 ] || fail 'C1 full-backlog 4GiB metrics bundle SHA invalid'
printf 'FI C1 PRIVATE METRICS BUNDLE PASS path=%s sha256=%s\n' \
  "$bundle" "$bundle_sha"
