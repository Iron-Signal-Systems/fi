#!/bin/sh
# C220 W512 independent-family P3 private A/B, indices 1 and 2.
# Inherits accepted C220 H16 P2 clone, signed-source, readback and SQL gates.
# All signed-source/SQL gates preserved. No live ingest; private PG only.
# Test ONLY against an OFFLINE COPY of the validated private W512 seed.
# No W128 checkpoint, canonical SoR write or Accepted publication.
set -eu
umask 077
fail(){ printf 'FI W512 PILOT STOP: %s\n' "$*" >&2; exit 1; }
[ "$(id -un)" = root ] && [ "$(hostname -s)" = c220 ] && [ "$#" -eq 2 ] ||
    fail 'usage on root@c220: sh runner preflight|family YYYYMMDDTHHMMSSZ'
case "$1" in
  preflight|family) mode=$1 ;;
  *) fail 'mode must be preflight or family' ;;
esac
# P7: five real SQL family writers, source ledger and final marker.
[ "${FI_W512_P7_SQL_WRITERS:-}" = 5 ] || fail 'P7 five SQL writers must be explicitly enabled'
[ "${FI_W512_P6_FAMILY_SQL:-}" = 1 ] ||
    fail 'P6 requires explicit isolated SQL family redesign gate'
[ "${FI_W512_P5_PERSISTENT:-}" = 1 ] || fail 'P5 persistent worker mode must be explicitly enabled'
[ "${FI_W512_P3_DYNAMIC_MIN:-}" = 2 ] &&
[ "${FI_W512_P3_DYNAMIC_MAX:-}" = 16 ] ||
    fail 'P4 priority-fill requires min=2 max=16'
[ -z "${FI_W512_P3_SECURITY_WORKERS:-}" ] &&
[ -z "${FI_W512_P3_GENERAL_WORKERS:-}" ] ||
    fail 'P4 dynamic mode cannot mix with fixed worker controls'
security_workers=16
general_workers=64
general_each=16
family_workers=80  # reporting slots; 2..16 actual goroutines per lane

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
sourcecommit=34ad2e976d8a6ed44ec5ac063e13350c67153de8
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
need_kib=$((seed_kib+8388608))
[ "$seed_kib" -gt 0 ] && [ "$free_kib" -gt "$need_kib" ] ||
    fail "insufficient space for private seed copy and 8GiB headroom (need_kib=$need_kib free_kib=$free_kib)"
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
[ "$(df -Pk "$private_parent" | awk 'END {print $4}')" -gt 8388608 ] ||
  fail 'fast private artifacts need at least 8 GiB available'
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
  go/cmd/fi-backlog-recover/testdata/family-p7/private_p7_five_writer_handoff.go \
  go/cmd/fi-backlog-recover/testdata/family-p7/private_p7_five_writer_handoff_test.go \
  go/cmd/fi-backlog-recover/testdata/family-p7/private_p7_postgres_writers.go \
  go/cmd/fi-backlog-recover/testdata/family-p7/private_p7_atomic_publish.go \
  go/cmd/fi-backlog-recover/testdata/family-p7/private_p7_window_setup.go \
  go/cmd/fi-backlog-recover/testdata/family-p7/private_p7_window_session.go \
  go/cmd/fi-backlog-recover/testdata/family-p7/private_p7_typed_window.go \
  go/cmd/fi-backlog-recover/patchers/security_sweep_c220/private_family_dynamic_summary.awk \
  go/cmd/fi-backlog-recover/patchers/security_sweep_c220/private_family_persistent_p5_summary.awk \
  go/cmd/fi-backlog-recover/patchers/family_p3_c220/main.go \
  go/cmd/fi-backlog-recover/patchers/p7_parallel_bridge/main.go \
  go/cmd/fi-backlog-recover/patchers/p7_parallel_bridge/main_test.go \
  go/cmd/fi-backlog-recover/testdata/family-p7/private_p8_verified_outer.go \
  go/cmd/fi-backlog-recover/testdata/family-p7/private_p8_verified_outer_test.go \
  go/cmd/fi-backlog-recover/testdata/family-p9/private_p9_direct_stream.go \
  go/cmd/fi-backlog-recover/testdata/family-p9/private_p9_direct_stream_test.go \
  go/cmd/fi-backlog-recover/testdata/family-p9/private_p9_cached_recovery.go
do
  jexec -U jwood fi-dev git -C /home/jwood/fi-w512-c220-stage cat-file -e "$sourcecommit:$asset" 2>/dev/null ||
    fail "missing pinned experimental source asset $asset"
done
echo "FI FAMILY P7 SOURCE PREFLIGHT PASS commit=$sourcecommit assets=36 clone_only=true min=2 max=16 actual_sql_writers=5"
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
# Validate the P7 bridge itself before even opening a private PostgreSQL clone.
git -C /home/jwood/fi-w512-c220-stage show \
  "$1:go/cmd/fi-backlog-recover/patchers/p7_parallel_bridge/main.go" \
  > "$tmp/p7_bridge_main.go" || exit 1
git -C /home/jwood/fi-w512-c220-stage show \
  "$1:go/cmd/fi-backlog-recover/patchers/p7_parallel_bridge/main_test.go" \
  > "$tmp/p7_bridge_main_test.go" || exit 1
GOTOOLCHAIN=local GO111MODULE=off go127 test -count=1 \
  "$tmp/p7_bridge_main.go" "$tmp/p7_bridge_main_test.go" >/dev/null || exit 1
echo 'FI P7 AST BRIDGE NO-POSTGRES PREFLIGHT PASS'
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
if [ "$mode" = preflight ]; then
  echo 'FI C220 W512 P2 PREFLIGHT ONLY: no database started, no source changed'
  exit 0
fi
relaypid=
iostatpid=
vmstatpid=
cleanup(){
    code=$?
    trap - 0 1 2 15
    report_clear
    for pid in "$iostatpid" "$vmstatpid" "$relaypid"; do
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
jexec -U jwood fi-dev sh -s "$seed" "$root" "$name" "$port" "$sourcecommit" <<'JAIL'
set -eu
umask 077
seed=$1
root=$2
name=$3
port=$4
sourcecommit=$5
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
for item in private_p6_family_buffers.go private_p6_family_buffers_test.go private_p6_file_proof_test.go private_p6_sql_coordinator.go private_p6_sql_security.go private_p6_sql_ntfs.go private_p6_sql_coverage.go private_p6_sql_usn.go private_p6_sql_other.go; do
  [ ! -e "$src/go/internal/recordingest/$item" ] || exit 1
  git -C "$expected" show "$sourcecommit:go/cmd/fi-backlog-recover/testdata/family-p6/$item" \
    > "$src/go/internal/recordingest/$item" || exit 1
done
for item in private_p7_five_writer_handoff.go private_p7_five_writer_handoff_test.go private_p7_postgres_writers.go private_p7_atomic_publish.go private_p7_window_setup.go private_p7_window_session.go private_p7_typed_window.go; do
  [ ! -e "$src/go/internal/recordingest/$item" ] || exit 1
  git -C "$expected" show "$sourcecommit:go/cmd/fi-backlog-recover/testdata/family-p7/$item" \
    > "$src/go/internal/recordingest/$item" || exit 1
done
for item in private_p8_verified_outer.go private_p8_verified_outer_test.go; do
  [ ! -e "$src/go/internal/recordingest/$item" ] || exit 1
  git -C "$expected" show "$sourcecommit:go/cmd/fi-backlog-recover/testdata/family-p7/$item" \
    > "$src/go/internal/recordingest/$item" || exit 1
done
mkdir -p "$src/go/cmd/fi-backlog-recover/patchers/family_p3_c220" || exit 1
git -C "$expected" show "$sourcecommit:go/cmd/fi-backlog-recover/patchers/family_p3_c220/main.go" \
  > "$src/go/cmd/fi-backlog-recover/patchers/family_p3_c220/main.go" || exit 1
(cd "$src/go" &&
 GOTOOLCHAIN=local GOFLAGS=-mod=readonly go127 run \
   ./cmd/fi-backlog-recover/patchers/family_p3_c220 "$src"
) || exit 1
# The inherited Candidate A activation insists on the old K32 buffer,
# which P7 cannot own. Install an exact P7-only alternative after P3.
bridge="$src/go/cmd/fi-backlog-recover/patchers/p7_parallel_bridge"
mkdir -p "$bridge" || exit 1
git -C "$expected" show "$sourcecommit:go/cmd/fi-backlog-recover/patchers/p7_parallel_bridge/main.go" \
    > "$bridge/main.go" || exit 1
(cd "$src/go" &&
 GOTOOLCHAIN=local GOFLAGS=-mod=readonly go127 run \
   ./cmd/fi-backlog-recover/patchers/p7_parallel_bridge "$src"
) || exit 1
echo "FI FAMILY P8 COMMITTED ARTIFACT ENTRYPOINT READY source_commit=$sourcecommit"
# Install P9's pinned direct verified-cache entrypoint in this disposable
# optimized-source only. No changes to authenticated custody/receiver/SoR.
for item in private_p9_direct_stream.go private_p9_direct_stream_test.go; do
  [ ! -e "$src/go/internal/recordingest/$item" ] || exit 1
  git -C "$expected" show "$sourcecommit:go/cmd/fi-backlog-recover/testdata/family-p9/$item" \
    > "$src/go/internal/recordingest/$item" || exit 1
done
cached="$src/go/internal/recordingest/backlog_verified_cache_recovery.go"
git -C "$expected" show "$sourcecommit:go/internal/recordingest/backlog_verified_cache_recovery.go" |
  cmp -s - "$cached" || {
    echo 'FI P9 SOURCE STOP: original cached recovery tree changed; no unsafe patch' >&2;exit 1;
  }
git -C "$expected" show "$sourcecommit:go/cmd/fi-backlog-recover/testdata/family-p9/private_p9_cached_recovery.go" \
  > "$cached" || exit 1
echo 'FI P9 DIRECT CACHE ENTRYPOINT READY copied_windows=0 new_source_staging=none'
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
   ./internal/recordingest -run '^(TestBacklogWindowsW512TwoGiB|TestPrivateParallelA|TestH16Combined|TestCanonicalDispatch|TestPrivateHeaderFirstP2|TestPrivateFamilyP3|TestPrivateSecuritySweep|TestPrivateDynamicP4|TestPrivateP5|TestPrivateP6|TestPrivateP7|TestPrivateP9)' -count=1 &&
 FI_W512_P6_FAMILY_SQL= FI_W512_P5_PERSISTENT= FI_W512_P3_DYNAMIC_MIN= FI_W512_P3_DYNAMIC_MAX= \
   GOTOOLCHAIN=local GOFLAGS=-mod=readonly go127 test -race \
   ./internal/recordingest -run '^(TestPrivateFamilyP3|TestPrivateSecuritySweep|TestPrivateDynamicP4|TestPrivateP5|TestPrivateP6|TestPrivateP7|TestPrivateP9)' -count=1 &&
 GOTOOLCHAIN=local GOFLAGS=-mod=readonly go127 build \
   -o "$root/fi-optfield-recover.c220" ./cmd/fi-backlog-recover
) > "$root/private-trust-path-build.log" 2>&1 || {
  tail -n 60 "$root/private-trust-path-build.log" >&2
  echo 'FI C220 PRIVATE TRUST PATCH STOP: tests/build failed' >&2
  exit 1
}
[ -x "$root/fi-optfield-recover.c220" ] || exit 1
mv "$root/fi-optfield-recover.c220" "$root/fi-optfield-recover" || exit 1
sha256 -q "$root/fi-optfield-recover" > "$root/recover.sha256" || exit 1
printf 'FI C220 PRIVATE TRUST PATH PATCH PASS source=pinned_b01ff0 benchmark_only=true compiler=go127 root_ca=migrated signing_ca=migrated crl=current_receiver source_registry=migrated\n'

# All pinned overlay compilation and tests passed. Clone PostgreSQL only now.
cp -R "$seed/$name/data" "$root/$name/data" || exit 1
[ "$(cat "$root/$name/data/PG_VERSION")" = 18 ] || exit 1
echo 'FI FAMILY P3 POST-BUILD PRIVATE SEED COPY PASS'
pg_ctl -D "$root/$name/data" -l "$root/$name/postgres.log" \
  -o "-p $port -k $root/$name/socket -c listen_addresses= -c unix_socket_permissions=0700" \
  -w start > "$root/$name/start.log" 2>&1 || exit 1
# P7: The fi_ingest role cannot read PostgreSQL's restricted
# data_directory setting by default. It needs that setting to prove
# EVERY P7 writer is connected to this exact disposable private clone.
# Grant the narrowly scoped pg_read_all_settings role ONLY AFTER an
# existing LOCAL clone owner/superuser has independently verified PGDATA.
# NEVER use this bootstrap on the authoritative FI SoR or a remote socket.
clone_sock="$root/$name/socket"
clone_data="$root/$name/data"
clone_ingest_dsn="host=$clone_sock port=$port user=fi_ingest dbname=fi sslmode=disable"
[ -d "$clone_data" ] && [ -d "$clone_sock" ] &&
[ "$(cat "$clone_data/PG_VERSION")" = 18 ] &&
pg_ctl -D "$clone_data" status >/dev/null 2>&1 ||
    { echo 'FI P7 PRIVATE GRANT STOP: exact clone server not running' >&2; exit 1; }
# Unix account jwood is not a PostgreSQL role in this signed seed.
# Enumerate this PRIVATE CLONE's login-capable PG superuser through
# fi_ingest's read-only public pg_roles view; never guess an identity.
clone_admin=$(psql "$clone_ingest_dsn" -X -qAt -v ON_ERROR_STOP=1 \
    -c "SELECT rolname FROM pg_catalog.pg_roles WHERE rolsuper AND rolcanlogin AND rolname !~ '^pg_' ORDER BY rolname") ||
    { echo 'FI P7 PRIVATE GRANT STOP: cannot discover cloned PostgreSQL bootstrap roles' >&2; exit 1; }
[ -n "$clone_admin" ] &&
[ "$(printf '%s\n' "$clone_admin" | wc -l | tr -d '[:space:]')" = 1 ] &&
printf '%s\n' "$clone_admin" | grep -Eq '^[A-Za-z_][A-Za-z_0-9]*$' ||
    { echo 'FI P7 PRIVATE GRANT STOP: expected exactly one safe login-capable PostgreSQL superuser in clone' >&2; exit 1; }
clone_owner_dsn="host=$clone_sock port=$port user=$clone_admin dbname=fi sslmode=disable"
# Verify exact physical private PGDATA as the discovered SQL superuser
# BEFORE granting the limited settings-read privilege.
clone_path=$(psql "$clone_owner_dsn" -X -qAt -v ON_ERROR_STOP=1 \
    -c "SELECT current_setting('data_directory')" ) ||
    { echo 'FI P7 PRIVATE GRANT STOP: discovered clone superuser cannot read physical PGDATA' >&2; exit 1; }
[ "$clone_path" = "$clone_data" ] ||
    { echo 'FI P7 PRIVATE GRANT STOP: actual cluster data_directory differs from copied private PGDATA' >&2; exit 1; }
clone_owner=$(psql "$clone_owner_dsn" -X -qAt -v ON_ERROR_STOP=1 \
    -c "SELECT current_user||'|'||(SELECT rolsuper::text FROM pg_roles WHERE rolname=current_user)||'|'||pg_is_in_recovery()::text") ||
    { echo 'FI P7 PRIVATE GRANT STOP: clone SQL superuser identity not verified' >&2; exit 1; }
[ "$clone_owner" = "$clone_admin|true|false" ] ||
    { echo "FI P7 PRIVATE GRANT STOP: unsafe clone SQL superuser identity $clone_owner" >&2; exit 1; }
# The role grant exists only in THIS newly copied PostgreSQL cluster.
# pg_read_all_settings gives config READ access, not SQL superuser access.
psql "$clone_owner_dsn" -X -qAt -v ON_ERROR_STOP=1 \
    -c "GRANT pg_read_all_settings TO fi_ingest" >/dev/null ||
    { echo 'FI P7 PRIVATE GRANT STOP: read-only clone settings grant rejected' >&2; exit 1; }
clone_ingest_path=$(psql "$clone_ingest_dsn" -X -qAt -v ON_ERROR_STOP=1 \
    -c "SELECT current_setting('data_directory')") ||
    { echo 'FI P7 PRIVATE GRANT STOP: fi_ingest still cannot read clone data_directory' >&2; exit 1; }
[ "$clone_ingest_path" = "$clone_data" ] ||
    { echo 'FI P7 PRIVATE GRANT STOP: fi_ingest is not connected to expected disposable PostgreSQL clone' >&2; exit 1; }
printf 'FI P7 PRIVATE CLONE SETTINGS ACCESS PASS pgdata=%s role=fi_ingest config_read=pg_read_all_settings clone_only=true\n' "$clone_data"
# Clone-only DEFAULT Security-field partition eliminates artificial W512
# partition drains; original W0 partitions remain intact.
psql "$clone_owner_dsn" -X -qAt -v ON_ERROR_STOP=1 -c \
  "CREATE TABLE fi_recovery_projection.windows_security_event_field_continuous_default
     PARTITION OF fi_recovery_projection.windows_security_event_field DEFAULT;
   REVOKE ALL ON fi_recovery_projection.windows_security_event_field_continuous_default FROM PUBLIC;
   GRANT SELECT, INSERT ON fi_recovery_projection.windows_security_event_field_continuous_default TO fi_ingest;
   -- The historical typed-window FK only supports the old duplicate
   -- pending-source ledger. Replace it with the real shadow generation
   -- FK in THIS disposable PostgreSQL clone only. Preserve other FKs.
   ALTER TABLE fi_recovery.typed_window
     DROP CONSTRAINT typed_window_receipt_sha256_window_index_fkey;
   ALTER TABLE fi_recovery.typed_window
     ADD CONSTRAINT fi_p9_typed_shadow_generation_fkey
     FOREIGN KEY (shadow_generation_id)
     REFERENCES fi_recovery_projection.recorded_generation(recorded_generation_id);" >/dev/null ||
   { echo 'FI P9: cannot prepare clone-only direct Security partition' >&2;exit 1; }
echo 'FI P9 DIRECT SECURITY PARTITION PASS clone_only=true no_detached_window_tables=true'
echo 'FI W512 PILOT OFFLINE SEED COPY PASS'
JAIL
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
[ "$(sql 'SHOW max_wal_size')" = 1GB ] &&
[ "$(sql 'SHOW wal_buffers')" = 4MB ] || fail 'PostgreSQL WAL settings changed'
for f in fsync synchronous_commit full_page_writes; do
    [ "$(sql "SHOW $f")" = on ] || fail "PostgreSQL durability $f disabled"
done
cat > "$out/RUN_MANIFEST.txt" <<EOF
FI FAMILY P3 W512 PRIVATE TWO-WINDOW PILOT
family_p3_source_commit=$sourcecommit
source_seed=$seed
seed_descriptor=$seedhash
seed_records=493478
signed_cache=$cache
window_profile=W512
window_records_max=524288
window_source_bytes_max=2147483648
start_window=1
windows=2
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
worker_max=16
per_family_dynamic=true
inflight_limit=32
pending_raw_bytes_max=268435456
sql_writers=5
parent_ledger_connections=1
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
}
stats before || fail 'pre-run PostgreSQL stats unavailable'
iostat -x -w 5 > "$out/$name/iostat.txt" 2>&1 &
iostatpid=$!
vmstat -w 5 > "$out/$name/vmstat.txt" 2>&1 &
vmstatpid=$!
printf 'FI FAMILY P9 DIRECT PILOT START start_index=1 windows=2 sql_writers=5 parent_ledger=1 p5_persistent=stream dynamic_min=2 dynamic_max=16 credits=32 K32=32768\n' | tee "$out/SUMMARY.txt"
export FI_W512_P7_SQL_WRITERS=5
export FI_W512_P8_REUSE=
export FI_W512_P9_DIRECT_STREAM=1
export FI_W512_P9_STOP_WINDOWS=2
export FI_W512_P7_SQL_DSN="host=$out/pg-$name port=$port user=fi_ingest dbname=fi sslmode=disable"
export FI_W512_P7_EXPECTED_PGDATA="$root/$name/data"
if ! /usr/bin/time -l "$recover" \
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
  -max-windows=0 -max-runtime=0 -test-stop-after-windows=2 \
  -deferred-verified-clone -verified-cache-root="$cache" > "$out/$name/recover.log" 2>&1; then
    tail -n 100 "$out/$name/recover.log" >&2 || :
    fail 'W512 two-worker recovery rejected'
fi
for pid in "$iostatpid" "$vmstatpid"; do
    kill -TERM "$pid" 2>/dev/null || :
    wait "$pid" 2>/dev/null || :
done
iostatpid=
vmstatpid=
stats after || fail 'postrun PostgreSQL stats unavailable'
log="$out/$name/recover.log"
# The direct path never copies/stages signed window payloads a second time.
# It must not add P8 source/artifact markers or pending_source_record rows.
grep '^FI P9 DIRECT READ window=' "$log" > "$out/$name/P9_READ.txt" ||
    fail 'P9 direct signed stream receipt missing'
awk '/^FI P9 DIRECT READ window=/{
  delete v
  for(i=1;i<=NF;i++){split($i,a,"=");v[a[1]]=a[2]}
  w=v["window"]+0
  if(w<1||w>2||seen[w]++||v["pending_source_rows_added"]!="0"||
     v["artifact_copies"]!="0")bad=1
  if(w==1&&v["records"]!=499052)bad=1
  if(w==2&&v["records"]!=498382)bad=1
  rows+=v["records"]+0;batches+=v["signed_batches"]+0
}END{
 if(bad||seen[1]!=1||seen[2]!=1||rows!=997434||batches!=431)exit 1
}' "$out/$name/P9_READ.txt" || fail 'P9 original signed W512 records/batches inconsistent'
grep -Fqx 'FI P9 DIRECT SECURITY PARTITION PASS clone_only=true no_detached_window_tables=true' "$out/SUMMARY.txt" ||
    { :; } # SQL default partition was installed before the receiver ran
grep '^FI P9 DIRECT FIVE WRITERS PASS ' "$log" > "$out/$name/P9_FAMILIES.txt" ||
    fail 'P9 five real PostgreSQL writer receipt missing'
awk '/^FI P9 DIRECT FIVE WRITERS PASS /{
 delete v
 for(i=1;i<=NF;i++){split($i,a,"=");v[a[1]]=a[2]}
 if(v["records"]!=997434||v["sql_committed"]!=997434||v["peak_queued_bytes"]<=0||
    v["security"]+v["file"]+v["coverage"]+v["usn"]+v["other"]!=997434)bad=1
 n++
}END{if(n!=1||bad)exit 1}' "$out/$name/P9_FAMILIES.txt" ||
    fail 'P9 source vs family committed records mismatch'
grep '^FI P9 DIRECT MULTIWINDOW COMMIT PASS ' "$log" > "$out/$name/P9_COMMIT.txt" ||
    fail 'P9 no duplicate staging / final typed marker receipt missing'
grep -q 'start=1 windows=2 records=997434 .*staging_reads=0 source_receipt_writes=0 artifact_receipt_writes=0 capacities_cross_windows=true' \
    "$out/$name/P9_COMMIT.txt" || fail 'P9 direct cross-window buffer and no-staging contract missing'
[ "$(grep -c '^FI P7 FIVE SQL BACKENDS VERIFIED typed_writers=5 parent_ledger=1 unique_backend_pids=6 shadow_only=true$' "$log")" = 1 ] ||
    fail 'P9 expected one persistent set of five distinct SQL backends'
[ "$(sql 'SELECT count(*) FROM fi_recovery.typed_window')" = 3 ] &&
[ "$(sql 'SELECT coalesce(sum(committed_records),0) FROM fi_recovery.typed_window WHERE window_index BETWEEN 1 AND 2')" = 997434 ] &&
[ "$(sql 'SELECT count(*) FROM fi_recovery.source_window')" = 1 ] &&
[ "$(sql 'SELECT count(*) FROM fi_recovery.verified_artifact_window')" = 1 ] &&
[ "$(sql 'SELECT count(*) FROM fi_recovery.pending_source_record')" = 493478 ] &&
[ "$(sql 'SELECT count(*) FROM fi_recovery_projection.source_record')" = 1490912 ] &&
[ "$(sql "SELECT count(*) FROM fi.recorded_generation")" = 0 ] &&
[ "$(sql "SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted'")" = 0 ] ||
    fail 'P9 produced a duplicate staging row, changed seed or lost typed parent records'
[ "$(sql "SELECT count(*) FROM pg_constraint WHERE connamespace='fi_recovery_projection'::regnamespace AND contype='f' AND NOT convalidated")" = 0 ] ||
    fail 'P9 private SQL contains unvalidated foreign keys'
[ "$(sql "SELECT count(*) FROM pg_inherits i JOIN pg_class c ON c.oid=i.inhrelid WHERE i.inhparent='fi_recovery_projection.windows_security_event_field'::regclass AND c.relname='windows_security_event_field_continuous_default' AND pg_get_expr(c.relpartbound,c.oid)='DEFAULT'")" = 1 ] ||
    fail 'P9 Security default partition not installed in private clone'
grep '^FI PRIVATE EXACT WINDOW STOP start=1 windows=2 last=2 records=997434 ' "$log" > "$out/$name/RESULT.txt" ||
    fail 'P9 two-window durable completed-prefix receipt missing'
grep '^FI REAL BACKLOG DURABLE ' "$log" > "$out/$name/WINDOWS.txt" ||
    fail 'P9 durable per-window markers missing'
elapsed=$(sed -n 's/.*committed_window_time=\([^ ]*\).*/\1/p' "$out/$name/RESULT.txt")
[ -n "$elapsed" ] || fail 'P9 elapsed time missing'
printf 'FI C220 P9 DIRECT FIVE WRITER TWO-WINDOW ACCEPTED windows=2 records=997434 elapsed=%s sql_writers=5 staging=none source_receipts_added=0 artifact_receipts_added=0 authoritative=0 accepted=0\n' \
  "$elapsed" | tee -a "$out/SUMMARY.txt"
bundle="$out/fi-w512-p9-direct-$stamp.tar.gz"
tar -C "$out" -czf "$bundle" RUN_MANIFEST.txt SUMMARY.txt relay.log \
  "$name/recover.log" "$name/P9_READ.txt" "$name/P9_FAMILIES.txt" \
  "$name/P9_COMMIT.txt" "$name/RESULT.txt" "$name/WINDOWS.txt" \
  "$name/wal_before.jsonl" "$name/wal_after.jsonl" \
  "$name/io_before.jsonl" "$name/io_after.jsonl" \
  "$name/iostat.txt" "$name/vmstat.txt" || fail 'P9 metrics bundle failed'
echo "FI P9 METRICS BUNDLE PASS path=$bundle sha256=$(sha256 -q "$bundle")"
