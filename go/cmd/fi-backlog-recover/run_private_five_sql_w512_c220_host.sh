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
sourcecommit=546c6a1e1a12f30bb0f54c70809dee978afea5f3
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
  go/cmd/fi-backlog-recover/patchers/family_p3_c220/main.go
do
  jexec -U jwood fi-dev git -C /home/jwood/fi-w512-c220-stage cat-file -e "$sourcecommit:$asset" 2>/dev/null ||
    fail "missing pinned experimental source asset $asset"
done
echo "FI FAMILY P7 SOURCE PREFLIGHT PASS commit=$sourcecommit assets=29 clone_only=true min=2 max=16 actual_sql_writers=5"
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
mkdir -p "$src/go/cmd/fi-backlog-recover/patchers/family_p3_c220" || exit 1
git -C "$expected" show "$sourcecommit:go/cmd/fi-backlog-recover/patchers/family_p3_c220/main.go" \
  > "$src/go/cmd/fi-backlog-recover/patchers/family_p3_c220/main.go" || exit 1
(cd "$src/go" &&
 GOTOOLCHAIN=local GOFLAGS=-mod=readonly go127 run \
   ./cmd/fi-backlog-recover/patchers/family_p3_c220 "$src"
) || exit 1
echo "FI FAMILY P7 FIVE-SQL OVERLAY READY source_commit=$sourcecommit"
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
   ./internal/recordingest -run '^(TestBacklogWindowsW512TwoGiB|TestPrivateParallelA|TestH16Combined|TestCanonicalDispatch|TestPrivateHeaderFirstP2|TestPrivateFamilyP3|TestPrivateSecuritySweep|TestPrivateDynamicP4|TestPrivateP5|TestPrivateP6|TestPrivateP7)' -count=1 &&
 FI_W512_P6_FAMILY_SQL= FI_W512_P5_PERSISTENT= FI_W512_P3_DYNAMIC_MIN= FI_W512_P3_DYNAMIC_MAX= \
   GOTOOLCHAIN=local GOFLAGS=-mod=readonly go127 test -race \
   ./internal/recordingest -run '^(TestPrivateFamilyP3|TestPrivateSecuritySweep|TestPrivateDynamicP4|TestPrivateP5|TestPrivateP6|TestPrivateP7)' -count=1 &&
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
printf 'FI FAMILY P7 W512 PILOT START start_index=1 windows=2 sql_writers=5 parent_ledger=1 p5_persistent=window dynamic_min=2 dynamic_max=16 credits=32 K32=32768\n' | tee "$out/SUMMARY.txt"
export FI_W512_P7_SQL_WRITERS=5
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
# A deferred artifact marker is NOT evidence of physical signed data.
# Require exactly the two original, hash-verified, private W512 windows.
grep '^FI P7 PRIVATE MATERIALIZED WINDOW VERIFIED ' "$log" > "$out/$name/P7_MATERIALIZED_WINDOWS.txt" ||
    fail 'P7 physical source copy and hash proof missing'
awk '/^FI P7 PRIVATE MATERIALIZED WINDOW VERIFIED /{
    delete v
    for(i=1;i<=NF;i++){split($i,t,"=");v[t[1]]=t[2]}
    w=v["index"]+0
    if(w<1||w>2||seen[w]++||v["original_cache_unchanged"]!="true"||
       v["signed_batches"]+0<1||v["bytes"]+0<1)bad=1
    if(w==1&&v["records"]!=499052)bad=1
    if(w==2&&v["records"]!=498382)bad=1
    rows+=v["records"]+0;batches+=v["signed_batches"]+0;n++
}END{
    if(bad||n!=2||seen[1]!=1||seen[2]!=1||rows!=997434||batches!=431)exit 1
}' "$out/$name/P7_MATERIALIZED_WINDOWS.txt" ||
    fail 'P7 requires two physically verified W512 windows and all 431 signed batches'
printf 'FI W512 P7 PHYSICAL SIGNED STAGE PASS windows=2 signed_batches=431 records=997434 original_cache_unchanged=true\n' |
    tee -a "$out/SUMMARY.txt"
# Source of truth for P7 is a three-stage, strict ordered checkpoint:
# original SHA-verified physical files -> verified artifact DB checkpoint ->
# durable pending-source DB checkpoint -> five SQL writers.
# The fixture must never count a deferred placeholder as a completed source.
awk '/^FI P7 PRIVATE MATERIALIZED WINDOW VERIFIED /{
   delete a
   for(i=1;i<=NF;i++){split($i,x,"=");a[x[1]]=x[2]}
   w=a["index"]+0
   if(w<1||w>2||state[w]!=0)bad=1
   state[w]=1
}
/^FI P7 VERIFIED ARTIFACT CHECKPOINT COMMITTED /{
   delete a
   for(i=1;i<=NF;i++){split($i,x,"=");a[x[1]]=x[2]}
   w=a["index"]+0
   if(w<1||w>2||state[w]!=1||a["typed_marker"]!="absent"||
      a["source_rows"]!="pending")bad=1
   if(w==1&&(a["signed_batches"]!=216||a["records"]!=499052))bad=1
   if(w==2&&(a["signed_batches"]!=215||a["records"]!=498382))bad=1
   state[w]=2
}
/^FI P7 VERIFIED SOURCE CHECKPOINT COMMITTED /{
   delete a
   for(i=1;i<=NF;i++){split($i,x,"=");a[x[1]]=x[2]}
   w=a["index"]+0
   if(w<1||w>2||state[w]!=2||a["typed_marker"]!="absent"||
      a["artifact"]!="committed")bad=1
   if(w==1&&(a["signed_batches"]!=216||a["records"]!=499052))bad=1
   if(w==2&&(a["signed_batches"]!=215||a["records"]!=498382))bad=1
   state[w]=3
}
END{if(bad||state[1]!=3||state[2]!=3)exit 1}' "$log" ||
    fail 'P7 signed physical/artifact/source checkpoint chain incomplete or out of order'
grep -E '^FI P7 (VERIFIED ARTIFACT CHECKPOINT COMMITTED|VERIFIED SOURCE CHECKPOINT COMMITTED) ' \
    "$log" > "$out/$name/P7_SOURCE_CHAIN.txt" ||
    fail 'P7 durable artifact/source checkpoint receipts absent'
[ "$(wc -l < "$out/$name/P7_SOURCE_CHAIN.txt" | tr -d '[:space:]')" = 4 ] ||
    fail 'P7 expected two durable checkpoint receipts per signed window'
printf 'FI W512 P7 SOURCE CHECKPOINT CHAIN PASS windows=2 artifact_markers=2 source_markers=2 signed_batches=431 records=997434\n' |
    tee -a "$out/SUMMARY.txt"
[ "$(grep -c '^FI P7 FIVE SQL BACKENDS VERIFIED typed_writers=5 parent_ledger=1 unique_backend_pids=6 shadow_only=true$' "$log")" = 2 ] ||
    fail 'five distinct family SQL writer backend PIDs absent from W512 windows'
[ "$(grep -c '^FI REAL BACKLOG DURABLE ' "$log")" = 2 ] &&
[ "$(grep -c '^FI P7 PRIVATE STAGE PROFILE ' "$log")" = 2 ] &&
[ "$(grep -c '^FI P7 REAL TYPED WINDOW ' "$log")" = 2 ] &&
[ "$(grep -c '^FI P7 SIGNED BATCH VERIFIED window=' "$log")" = 2 ] ||
    fail 'W512 per-window instrumentation incomplete'
grep -q '^FI PRIVATE EXACT WINDOW STOP start=1 windows=2 last=2 records=' "$log" ||
    fail 'W512 exact two-window stop missing'
new=$(sql 'SELECT coalesce(sum(committed_records),0) FROM fi_recovery.typed_window WHERE window_index BETWEEN 1 AND 2')
case "$new" in ''|*[!0-9]*) fail 'invalid W512 new record count';; esac
[ "$new" = 997434 ] || fail "historical W512 2-window record invariant failed: $new != 997434"
total=$((493478+new))
integrity=$(sql "SELECT CASE WHEN
 (SELECT count(*) FROM fi_recovery.typed_window)=3
 AND (SELECT count(*) FROM fi_recovery.source_window)=3
 AND (SELECT count(*) FROM fi_recovery.verified_artifact_window)=3
 AND (SELECT count(*) FROM fi_recovery_projection.source_batch)=8399
 AND (SELECT count(*) FROM pg_inherits
   WHERE inhparent='fi_recovery_projection.windows_security_event_field'::regclass)=3
 AND (SELECT count(*) FROM fi_recovery.pending_source_record)=$total
 AND (SELECT count(*) FROM fi_recovery_projection.source_record)=$total
 AND (SELECT count(*) FROM fi_recovery_projection.windows_security_event_field)>6194967
 AND (SELECT count(*) FROM fi.recorded_generation)=0
 AND (SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted')=0
 AND NOT EXISTS(SELECT 1 FROM fi_recovery.typed_window t
  LEFT JOIN fi_recovery.source_window s USING(receipt_sha256,window_index)
  LEFT JOIN fi_recovery.verified_artifact_window a USING(receipt_sha256,window_index)
  WHERE s.window_index IS NULL OR a.window_index IS NULL
  OR t.descriptor_sha256 IS DISTINCT FROM s.descriptor_sha256
  OR t.descriptor_sha256 IS DISTINCT FROM a.descriptor_sha256)
 AND (SELECT encode(descriptor_sha256,'hex') FROM fi_recovery.typed_window WHERE window_index=0)='$seedhash'
 THEN 'PASS' ELSE 'FAIL' END")
[ "$integrity" = PASS ] || fail 'W512 SQL source/typed/artifact integrity failed'
# P6 additionally proves that ALL 13 relational record kinds have their
# canonical typed parent. This covers the full child-family dispatcher and
# not merely the number of FI source_record ledger entries.
missing_typed=$(sql "SELECT count(*) FROM fi_recovery_projection.source_record sr WHERE CASE sr.record_kind
 WHEN 'CollectorIdentity' THEN NOT EXISTS (SELECT 1 FROM fi_recovery_projection.collector_identity x WHERE x.source_record_id=sr.source_record_id)
 WHEN 'DirectoryPrincipalSnapshot' THEN NOT EXISTS (SELECT 1 FROM fi_recovery_projection.directory_principal_snapshot x WHERE x.source_record_id=sr.source_record_id)
 WHEN 'FileObservation' THEN NOT EXISTS (SELECT 1 FROM fi_recovery_projection.file_observation x WHERE x.source_record_id=sr.source_record_id)
 WHEN 'LocalPrincipalSnapshot' THEN NOT EXISTS (SELECT 1 FROM fi_recovery_projection.local_principal_snapshot x WHERE x.source_record_id=sr.source_record_id)
 WHEN 'NTFSCollectionError' THEN NOT EXISTS (SELECT 1 FROM fi_recovery_projection.ntfs_collection_error x WHERE x.source_record_id=sr.source_record_id)
 WHEN 'SMBShareSnapshot' THEN NOT EXISTS (SELECT 1 FROM fi_recovery_projection.smb_share_snapshot x WHERE x.source_record_id=sr.source_record_id)
 WHEN 'SupportingSourceCollectionError' THEN NOT EXISTS (SELECT 1 FROM fi_recovery_projection.supporting_source_collection_error x WHERE x.source_record_id=sr.source_record_id)
 WHEN 'USNContinuityGap' THEN NOT EXISTS (SELECT 1 FROM fi_recovery_projection.usn_continuity_gap x WHERE x.source_record_id=sr.source_record_id)
 WHEN 'USNObjectObservation' THEN NOT EXISTS (SELECT 1 FROM fi_recovery_projection.usn_object_observation x WHERE x.source_record_id=sr.source_record_id)
 WHEN 'USNReadBoundary' THEN NOT EXISTS (SELECT 1 FROM fi_recovery_projection.usn_read_boundary x WHERE x.source_record_id=sr.source_record_id)
 WHEN 'WindowsSecurityContinuityGap' THEN NOT EXISTS (SELECT 1 FROM fi_recovery_projection.windows_security_continuity_gap x WHERE x.source_record_id=sr.source_record_id)
 WHEN 'WindowsSecurityCoverage' THEN NOT EXISTS (SELECT 1 FROM fi_recovery_projection.windows_security_coverage x WHERE x.source_record_id=sr.source_record_id)
 WHEN 'WindowsSecurityEvent' THEN NOT EXISTS (SELECT 1 FROM fi_recovery_projection.windows_security_event x WHERE x.source_record_id=sr.source_record_id)
 ELSE true END") || fail 'P6 relational graph readback query failed'
[ "$missing_typed" = 0 ] || fail "P6 relational projection coverage missing typed parents=$missing_typed"
unvalidated_fks=$(sql "SELECT count(*) FROM pg_constraint WHERE connamespace='fi_recovery_projection'::regnamespace AND contype='f' AND NOT convalidated") ||
  fail 'P6 FK graph status inspection failed'
[ "$unvalidated_fks" = 0 ] || fail "P6 foreign keys are not fully validated=$unvalidated_fks"
printf 'FI P6 FULL RELATIONAL GRAPH PASS supported_kinds=13 missing_typed=0 unvalidated_fks=0\n' |
  tee -a "$out/SUMMARY.txt"
# Preserve original C220 optimized FileObservation source proof and bulk
# validated-source reuse. Unlike the first P6 failure, these receipts come
# from the original seeded validator AFTER actual typed SQL writes.
grep '^FI P7 FILE PROOF VERIFIED index=' "$log" > "$out/$name/P6_FILE_VALIDATION.txt" ||
    fail 'original optimized FileObservation validation receipts missing'
[ "$(wc -l < "$out/$name/P6_FILE_VALIDATION.txt" | tr -d ' ')" = 2 ] ||
    fail 'original FileObservation validation receipts missing for a W512 window'
awk '
/^FI P7 FILE PROOF VERIFIED / {
    delete kv
    for(i=1;i<=NF;i++){split($i,a,"=");kv[a[1]]=a[2]}
    win=kv["index"]+0
    if(win<1||win>2||seen[win]++||
       kv["source_validated"]<1||
       kv["bulk_reused"]!=kv["source_validated"]||
       kv["all_native"]!="true") bad=1
    source[win]=kv["source_validated"]+0
    reused[win]=kv["bulk_reused"]+0
}
END {
    if(bad||seen[1]!=1||seen[2]!=1||
       source[1]!=52519||source[2]!=52311||
       reused[1]!=52519||reused[2]!=52311||
       source[1]+source[2]!=104830)exit 1
}' "$out/$name/P6_FILE_VALIDATION.txt" ||
    fail 'P6 signed NTFS validation proof missing, reused more than validated, or count differs'
printf 'FI P7 VERIFIED NATIVE FILE SOURCE AND BULK REUSE PASS windows=2 validated=104830 reused=104830 sql_writers=5\n' |
    tee -a "$out/SUMMARY.txt"
sql "SELECT window_index::text || '|' || committed_records::text || '|' ||
    encode(descriptor_sha256,'hex')
    FROM fi_recovery.typed_window ORDER BY window_index" \
    > "$out/$name/W512_CHECKPOINTS.tsv" ||
  fail 'W512 C220 two-window checkpoint readback failed'
[ "$(cat "$out/$name/W512_CHECKPOINTS.tsv")" = \
"0|493478|$seedhash
1|499052|bd093cdd14ad195e440fcf411d3baefcda670bbeb11e0f4d8a1aca715519c92c
2|498382|3750b8827d8e89c4d02bfcbf7a345325fbdb80ec36832f6f5b06170b183894d9" ] ||
  fail 'C220 W512 immutable signed window checkpoint plan mismatch'
grep '^FI FAMILY P3 BLOCK DISPATCH ' "$log" > "$out/$name/FAMILY_DISPATCH.txt" ||
    fail 'family P3 block dispatcher proof missing'
grep '^FI PRIVATE PARALLEL PREP BATCH ' "$log" > "$out/$name/PARALLEL_PREP.txt" ||
    fail 'parallel batch proof absent'
prep=$(awk '/^FI PRIVATE PARALLEL PREP BATCH /{
 delete f
 for(i=1;i<=NF;i++){split($i,a,"=");f[a[1]]=a[2]}
 if(f["writers"]!=1||f["reorder_peak"]+0>31||seen[f["batch"]]++)bad=1
 rows+=f["records"]+0;n++
 }END{if(bad||n==0)exit 1;printf "%.0f",rows}' "$out/$name/PARALLEL_PREP.txt") ||
    fail 'W512 parallel preparation invariant failed'
[ "$prep" = "$new" ] || fail "W512 prepared rows $prep do not equal $new"
# P7 authenticates the complete window by source re-staging and by
# ingestSourceBatch's original signed batch hasher, not old P6 hash telemetry.
grep '^FI P7 SIGNED BATCH VERIFIED window=' "$log" > "$out/$name/SIGNED_BATCHES.txt" ||
    fail 'five-writer signed batch verifier receipts missing'
trusted=$(awk '/^FI P7 SIGNED BATCH VERIFIED /{
    delete v
    for(i=1;i<=NF;i++){split($i,a,"=");v[a[1]]=a[2]}
    w=v["window"]+0
    if(w<1||w>2||seen[w]++||v["manifest_sha_validated"]!="true"||
       v["record_sha_validated"]!="true")bad=1
    if(w==1&&v["records"]!=499052)bad=1
    if(w==2&&v["records"]!=498382)bad=1
    n+=v["batches"]+0
} END{
    if(bad||seen[1]!=1||seen[2]!=1||n!=431)exit 1
    print n
}' "$out/$name/SIGNED_BATCHES.txt") ||
    fail 'P7 signed windows SHA, record or signed batch totals invalid'
prepbatches=$(wc -l < "$out/$name/PARALLEL_PREP.txt" | tr -d ' ')
[ "$prepbatches" = 431 ] ||
    fail "W512 expected 431 signed preparation batches; observed $prepbatches"
[ "$(grep -Fc 'FI FAMILY P3 SCHEDULER lanes=5 mode=persistent priority_fill=true min_workers=2 max_workers=16 max_worker_slots=80 credits=32 max_pending_bytes=268435456 sql_writers=1 atomic_window=true' "$log")" = "$prepbatches" ] ||
    fail 'independent family worker topology proof missing'
grep '^FI FAMILY P3 BUDGET ' "$log" > "$out/$name/FAMILY_BUDGET.txt" ||
    fail 'private family admission budget proof missing'
[ "$(wc -l < "$out/$name/FAMILY_BUDGET.txt" | tr -d ' ')" = "$prepbatches" ] ||
    fail 'one memory-budget proof per signed batch is required'
awk '/^FI FAMILY P3 BUDGET /{
    delete f
    for(i=1;i<=NF;i++){split($i,a,"=");f[a[1]]=a[2]+0}
    if(f["peak_pending_bytes"]<0 || f["peak_pending_bytes"]>268435456 ||
       f["remaining_bytes"]!=0)bad=1
    n++
}END{if(bad||n!=431)exit 1}' "$out/$name/FAMILY_BUDGET.txt" ||
    fail 'family admission budget invariant failed'
# Real scale-out proof: each family has 2..16 spawned Go worker goroutines
# per signed batch. The 80 report slots are upper limits, not 80 active workers.
grep '^FI FAMILY DYNAMIC LANE ' "$log" > "$out/$name/FAMILY_DYNAMIC.txt" ||
    fail 'P4 lane scale-out receipts missing'
[ "$(wc -l < "$out/$name/FAMILY_DYNAMIC.txt" | tr -d ' ')" = "$((prepbatches*5))" ] ||
    fail 'P4 requires five lane receipts for each signed batch'
awk -v batches="$prepbatches" -f "$dynamic_awk" \
    "$out/$name/FAMILY_DYNAMIC.txt" > "$out/$name/FAMILY_DYNAMIC_SUMMARY.tsv" ||
    fail 'P4 dynamic spawn/queue/record accounting invalid'
printf 'FI W512 P5 DYNAMIC BATCH ACCOUNTING PASS batches=%s families=5 min=2 max=16 slots=80\n' "$prepbatches" |
    tee -a "$out/SUMMARY.txt"
# The five preparation pools persist across signed batches, but MUST
# be disposed at the SQL transaction boundary of each W512 typed window.
grep '^FI P5 PERSISTENT WINDOW START ' "$log" > "$out/$name/P5_WINDOW_START.txt" ||
    fail 'P5 typed-window pool start receipts missing'
grep '^FI P5 PERSISTENT WINDOW STOP ' "$log" > "$out/$name/P5_WINDOW_STOP.txt" ||
    fail 'P5 typed-window pool worker join receipts missing'
grep '^FI P5 PERSISTENT WINDOW FAMILY ' "$log" > "$out/$name/P5_WINDOW_LANES.txt" ||
    fail 'P5 per-window family pool breakdown missing'
[ "$(wc -l < "$out/$name/P5_WINDOW_START.txt" | tr -d ' ')" = 2 ] &&
[ "$(wc -l < "$out/$name/P5_WINDOW_STOP.txt" | tr -d ' ')" = 2 ] &&
[ "$(wc -l < "$out/$name/P5_WINDOW_LANES.txt" | tr -d ' ')" = 10 ] ||
    fail 'P5 requires exactly two pool lifetimes, ten per-window family proofs'
for window in 1 2; do
    grep -Fqx "FI P5 PERSISTENT WINDOW STOP window=$window families=5 joined=true" \
        "$out/$name/P5_WINDOW_STOP.txt" ||
        fail "P5 pool workers did not cleanly join at window $window"
done
awk -v windows=2 -v first=1 -v records1=499052 -v records2=498382 \
    -f "$p5_report" "$out/$name/P5_WINDOW_LANES.txt" \
    > "$out/$name/P5_WINDOW_LANES.tsv" ||
    fail 'P5 window family/worker reuse and signed-row accounting failed'
printf 'FI W512 P5 PERSISTENT WINDOWS PASS windows=2 signed_records=997434 persistent_across_batches=true window_pools_closed=true\n' |
    tee -a "$out/SUMMARY.txt"
# P6: require every relational module and source-copy ledger to complete.
# These receipts are logged inside the existing W512 transaction, before
# the final existing typed-window SQL commit and signed readback.
grep '^FI P6 SOURCE LEDGER window=' "$log" > "$out/$name/P6_SOURCE_LEDGER.txt" ||
    fail 'P6 ordered source ledger receipts missing'
grep '^FI P6 FAMILY window=' "$log" > "$out/$name/P6_FAMILY_HANDOFFS.txt" ||
    fail 'P6 five dedicated relational family receipts missing'
grep '^FI P6 WINDOW READY window=' "$log" > "$out/$name/P6_WINDOWS.txt" ||
    fail 'P6 atomic window source/typed completion receipts missing'
[ "$(wc -l < "$out/$name/P6_SOURCE_LEDGER.txt" | tr -d ' ')" = 2 ] &&
[ "$(wc -l < "$out/$name/P6_FAMILY_HANDOFFS.txt" | tr -d ' ')" = 10 ] &&
[ "$(wc -l < "$out/$name/P6_WINDOWS.txt" | tr -d ' ')" = 2 ] ||
    fail 'P6 must have two window ledgers and ten exact family handoffs'
awk '/^FI P6 FAMILY /{
    delete k
    for(i=1;i<=NF;i++){split($i,a,"=");k[a[1]]=a[2]}
    family=k["family"];win=k["window"]+0
    if(win<1||win>2||k["complete"]!="true"||
        k["rows"]<0||k["capacity"]<0||k["dependency"]<0||
        k["final"]<0||k["handoffs"]<0||
        k["handoffs"]!=k["capacity"]+k["dependency"]+k["final"]||
        k["peak_rows"]<0||k["peak_bytes"]<0||
        seen[win ":" family]++)bad=1
    records[win]+=k["rows"];total+=k["rows"];n++
}END {
    if(bad||n!=10||records[1]!=499052||records[2]!=498382||total!=997434)exit 1
    split("Security NTFSFile Coverage USNDependency Other",families," ")
    for(w=1;w<=2;w++)for(i=1;i<=5;i++)
        if(seen[w ":" families[i]]!=1)exit 1
}' "$out/$name/P6_FAMILY_HANDOFFS.txt" ||
    fail 'P6 source/child family handoffs or original signed totals mismatch'
grep -Fxq 'FI P6 WINDOW READY window=1 source=499052 typed=499052 families=5 sql_writers=5 atomic=true' "$out/$name/P6_WINDOWS.txt" &&
grep -Fxq 'FI P6 WINDOW READY window=2 source=498382 typed=498382 families=5 sql_writers=5 atomic=true' "$out/$name/P6_WINDOWS.txt" ||
    fail 'P6 SQL source-parent and typed child completion disagree'
printf 'FI W512 P7 FIVE SQL FAMILY HANDOFFS PASS windows=2 families=5 records=997434 source_ledger=durable sql_writers=5\n' |
    tee -a "$out/SUMMARY.txt"
# P7: Five ACTUAL relational PostgreSQL writer backends; five exact
# SQL commit reports per W512 window, not five modules on one connection.
grep '^FI P7 SQL FAMILY COMMITTED ' "$log" > "$out/$name/P7_SQL_FAMILIES.txt" ||
    fail 'five independent PostgreSQL family writer commit reports missing'
grep '^FI P7 FIVE-WRITER W512 PUBLISHED ' "$log" > "$out/$name/P7_PUBLISHED.txt" ||
    fail 'atomic typed W512 publication receipts missing'
[ "$(wc -l < "$out/$name/P7_SQL_FAMILIES.txt" | tr -d ' ')" = 10 ] &&
[ "$(wc -l < "$out/$name/P7_PUBLISHED.txt" | tr -d ' ')" = 2 ] ||
    fail 'five PostgreSQL family writer receipts missing for a window'
awk '/^FI P7 SQL FAMILY COMMITTED /{
    delete kv
    for(i=1;i<=NF;i++){split($i,a,"=");kv[a[1]]=a[2]}
    w=kv["window"]+0;f=kv["family"];pid=kv["pg_backend"]+0
    if(w<1||w>2||pid<1||kv["complete"]!="true"||
       kv["handoffs"]<0||kv["records"]<0||
       seen[w ":" f]++||pidSeen[w ":" pid]++)bad=1
    records[w]+=kv["records"];n++
}END{
    if(bad||n!=10||records[1]!=499052||records[2]!=498382)exit 1
    split("Security NTFSFile Coverage USNDependency Other",families," ")
    for(w=1;w<=2;w++)for(i=1;i<=5;i++)if(seen[w ":" families[i]]!=1)exit 1
}' "$out/$name/P7_SQL_FAMILIES.txt" ||
    fail 'P7 backend PID isolation, SQL receipts or source rows mismatch'
grep -Fq 'FI P7 FIVE-WRITER W512 PUBLISHED index=1 records=499052 ' "$out/$name/P7_PUBLISHED.txt" &&
grep -Fq 'FI P7 FIVE-WRITER W512 PUBLISHED index=2 records=498382 ' "$out/$name/P7_PUBLISHED.txt" &&
[ "$(grep -Fc 'family_writers=5 ' "$out/$name/P7_PUBLISHED.txt")" = 2 ] &&
[ "$(grep -Fc 'typed_marker=atomic accepted=0 authoritative=0' "$out/$name/P7_PUBLISHED.txt")" = 2 ] ||
    fail 'P7 five-writer atomic publication missing or authoritative'
printf 'FI W512 P7 REAL FIVE PG WRITERS PASS windows=2 independent_backends=5 per_window_family_receipts=10 records=997434 typed_marker=atomic\n' |
    tee -a "$out/SUMMARY.txt"
# Lane/worker receipts are printed only AFTER every prep worker has joined.
# Every signed batch must report five lanes (including zero-work lanes), all
# 8+Security workers individually, and complete source/prepare accounting.
grep '^FI FAMILY P3 TOTAL ' "$log" > "$out/$name/FAMILY_TOTALS.txt" ||
    fail 'family P3 completion totals absent'
grep '^FI FAMILY P3 LANE ' "$log" > "$out/$name/FAMILY_LANES.txt" ||
    fail 'family P3 lane telemetry absent'
grep '^FI FAMILY P3 WORKER ' "$log" > "$out/$name/FAMILY_WORKERS.txt" ||
    fail 'family P3 individual worker telemetry absent'
[ "$(wc -l < "$out/$name/FAMILY_TOTALS.txt" | tr -d ' ')" = "$prepbatches" ] &&
[ "$(wc -l < "$out/$name/FAMILY_LANES.txt" | tr -d ' ')" = "$((prepbatches*5))" ] &&
[ "$(wc -l < "$out/$name/FAMILY_WORKERS.txt" | tr -d ' ')" = "$((prepbatches*family_workers))" ] ||
    fail 'family P3 completion report missing or duplicate worker/lane entries'
awk -v expected="$new" -v sec="$security_workers" -v general="$general_workers" '/^FI FAMILY P3 TOTAL /{
    delete f
    for(i=1;i<=NF;i++){split($i,a,"=");f[a[1]]=a[2]}
    if(f["complete"]!="true" || f["prepared_records"]!=f["input_records"] ||
       f["security_workers"]!=sec || f["general_workers"]!=general ||
       f["inflight"]!=32 || f["sql_writers"]!=1) bad=1
    sum+=f["input_records"]; n++
}END{if(bad || n!=431 || sum!=expected)exit 1}' "$out/$name/FAMILY_TOTALS.txt" ||
    fail 'signed family source/prepared completion totals diverged'
awk -v sec="$security_workers" -v each="$general_each" '/^FI FAMILY P3 WORKER /{
    delete f
    for(i=1;i<=NF;i++){split($i,a,"=");f[a[1]]=a[2]}
    key=f["family"]
    w=f["worker"]+0
    if(f["complete"]!="true" || f["records"]<0 || f["bytes"]<0 ||
       f["prepare_ns"]<0 || f["input_wait_ns"]<0 || f["output_wait_ns"]<0 ||
       (key=="Security" && w>=sec) ||
       (key!="Security" && w>=each))bad=1
    wc[key]++; records[key]+=f["records"]; bytes[key]+=f["bytes"]
}
/^FI FAMILY P3 LANE /{
    delete f
    for(i=1;i<=NF;i++){split($i,a,"=");f[a[1]]=a[2]}
    key=f["family"]
    want=(key=="Security"?sec:each)
    if(key!="Security" && key!="File" && key!="Coverage" &&
       key!="USNDependency" && key!="Other")bad=1
    if(f["complete"]!="true" || f["workers"]!=want ||
       wc[key]!=want || records[key]!=f["prepared"] ||
       f["prepared"]!=f["dispatched"] || bytes[key]!=f["bytes"] ||
       f["max_queue_depth"]<0 || f["max_queue_depth"]>32)bad=1
    wc[key]=0; records[key]=0; bytes[key]=0; lanes++; seen[key]++
}END{
    if(bad || lanes!=2155 || seen["Security"]!=431 ||
       seen["File"]!=431 || seen["Coverage"]!=431 ||
       seen["USNDependency"]!=431 || seen["Other"]!=431)exit 1
}' "$log" ||
    fail 'per-family worker totals, exact counts or bounded queues invalid'
# Machine-readable family-wide summaries, ready for two-window and W3..W12
# cross-experiment comparisons. Wait columns are cumulative worker-seconds,
# NOT wall time or PostgreSQL wait_event measurements.
awk '/^FI FAMILY P3 LANE /{
    delete f
    for(i=1;i<=NF;i++){split($i,a,"=");f[a[1]]=a[2]}
    k=f["family"]; workers[k]=f["workers"]
    records[k]+=f["prepared"]; bytes[k]+=f["bytes"]
    pre[k]+=f["prepare_ns"]; iw[k]+=f["input_wait_ns"]
    ow[k]+=f["output_wait_ns"]
    if(f["max_queue_depth"]>peak[k])peak[k]=f["max_queue_depth"]
}END{
    print "family\tworkers\trecords\tbytes\tprepare_worker_seconds\tinput_wait_worker_seconds\toutput_wait_worker_seconds\tpeak_queue_depth"
    split("Security File Coverage USNDependency Other",a," ")
    for(i=1;i<=5;i++){k=a[i];printf "%s\t%d\t%.0f\t%.0f\t%.6f\t%.6f\t%.6f\t%d\n",
        k,workers[k],records[k],bytes[k],pre[k]/1e9,iw[k]/1e9,ow[k]/1e9,peak[k]}
}' "$out/$name/FAMILY_LANES.txt" > "$out/$name/FAMILY_LANE_SUMMARY.tsv" ||
    fail 'family lane summary failed'
awk -v sec="$security_workers" -v general="$general_workers" -f "$report_awk" \
    "$out/$name/FAMILY_WORKERS.txt" > "$out/$name/FAMILY_WORKER_SUMMARY.tsv" ||
    fail 'pinned family worker summary failed'
printf 'FI W512 FAMILY BREAKDOWN PASS windows=2 signed_batches=%s families=5 workers=%s records=%s\n' "$prepbatches" "$family_workers" "$new" |
    tee -a "$out/SUMMARY.txt"
awk '/^FI FAMILY P3 BLOCK DISPATCH /{
  delete f
  for(i=1;i<=NF;i++){split($i,a,"=");f[a[1]]=a[2]+0}
  if(f["security"]+f["file"]+f["coverage"]+f["usn"]+f["other"]!=f["records"])bad=1
  n++
}END{if(bad||n!=431)exit 1}' "$out/$name/FAMILY_DISPATCH.txt" ||
    fail 'W512 family classification count mismatch'
[ "$(wc -l < "$out/$name/FAMILY_DISPATCH.txt" | tr -d ' ')" = "$prepbatches" ] ||
    fail 'family P3 block dispatch batch count does not match signed preparation'
header_records=$(awk '/^FI FAMILY P3 BLOCK DISPATCH /{
  for(i=1;i<=NF;i++)if($i~/^records=/){split($i,a,"=");sum+=a[2]+0}
}END{printf "%.0f",sum}' "$out/$name/FAMILY_DISPATCH.txt")
[ "$header_records" = "$new" ] ||
    fail "family P3 dispatched $header_records records; expected $new"
[ "$trusted" = "$prepbatches" ] || fail 'W512 batch SHA reuse/parallel preparation counts disagree'
expected_batches=$(sql 'SELECT coalesce(sum(end_batch-start_batch),0)
 FROM fi_recovery.verified_artifact_window WHERE window_index BETWEEN 1 AND 2')
checked=0
for directory in "$private_root"/receipt-*/window-*; do
    [ -d "$directory" ] || fail 'private signed W512 batch directory absent'
    namespace=$(basename "$(dirname "$directory")")
    case "$namespace" in receipt-*) ;; *) fail 'signed receipt namespace invalid';; esac
    for file in "$directory"/batch-*.data; do
        [ -f "$file" ] || fail 'W512 signed batch payload absent'
        original="$cache/$namespace/$(basename "$file")"
        manifest=$(printf '%s\n' "$file" | sed 's/\.data$/.manifest/')
        original_manifest=$(printf '%s\n' "$original" | sed 's/\.data$/.manifest/')
        [ -f "$original" ] && [ -f "$manifest" ] && [ -f "$original_manifest" ] ||
            fail 'W512 signed readback artifact path missing'
        cmp -s "$file" "$original" || fail 'W512 payload changed from receiver-admitted cache'
        cmp -s "$manifest" "$original_manifest" ||
            fail 'W512 signed manifest changed from receiver-admitted cache'
        checked=$((checked+1))
    done
done
[ "$checked" = 431 ] && [ "$checked" = "$expected_batches" ] && [ "$checked" = "$trusted" ] ||
    fail 'W512 signed byte-identical readback count mismatch'
printf 'FI W512 SIGNED READBACK PASS batches=%s byte_identical=true manifests_identical=true\n' "$checked" |
    tee -a "$out/SUMMARY.txt"
grep '^FI REAL BACKLOG DURABLE ' "$log" > "$out/$name/WINDOWS.txt"
grep '^FI REAL TYPED WINDOW ' "$log" > "$out/$name/COPY_CALLS.txt" ||
    fail 'W512 SQL COPY telemetry absent'
grep '^FI P7 PRIVATE STAGE PROFILE ' "$log" > "$out/$name/STAGES.txt"
grep '^FI PRIVATE EXACT WINDOW STOP ' "$log" > "$out/$name/RESULT.txt"
elapsed=$(sed -n 's/.*committed_window_time=\([^ ]*\).*/\1/p' "$out/$name/RESULT.txt")
[ -n "$elapsed" ] || fail 'W512 elapsed time missing'
printf 'FI C220 W512 FIVE WRITER P7 TWO-WINDOW ACCEPTED windows=2 new_records=%s elapsed=%s min_workers=2 max_workers=16 max_slots=80 credits=32 writer=5 authoritative=0 accepted=0\n' \
    "$new" "$elapsed" | tee -a "$out/SUMMARY.txt"
bundle="$out/fi-w512-family-p3-pilot2-$stamp.tar.gz"
tar -C "$out" -czf "$bundle" RUN_MANIFEST.txt SUMMARY.txt relay.log \
  "$name/recover.log" "$name/RESULT.txt" "$name/WINDOWS.txt" \
  "$name/COPY_CALLS.txt" "$name/STAGES.txt" "$name/PARALLEL_PREP.txt" \
  "$name/P7_MATERIALIZED_WINDOWS.txt" "$name/P7_SOURCE_CHAIN.txt" "$name/SIGNED_BATCHES.txt" "$name/wal_before.jsonl" "$name/wal_after.jsonl" \
  "$name/checkpointer_before.jsonl" "$name/checkpointer_after.jsonl" \
  "$name/io_before.jsonl" "$name/io_after.jsonl" \
  "$name/FAMILY_DISPATCH.txt" "$name/FAMILY_BUDGET.txt" \
  "$name/FAMILY_TOTALS.txt" "$name/FAMILY_LANES.txt" "$name/FAMILY_WORKERS.txt" \
  "$name/FAMILY_DYNAMIC.txt" "$name/FAMILY_DYNAMIC_SUMMARY.tsv" \
  "$name/P5_WINDOW_START.txt" "$name/P5_WINDOW_STOP.txt" \
  "$name/P5_WINDOW_LANES.txt" "$name/P5_WINDOW_LANES.tsv" \
  "$name/P5_WINDOW_LANES.txt" "$name/P5_WINDOW_LANES.tsv" \
  "$name/P5_WINDOW_START.txt" "$name/P5_WINDOW_STOP.txt" \
  "$name/P6_SOURCE_LEDGER.txt" "$name/P6_FAMILY_HANDOFFS.txt" "$name/P6_WINDOWS.txt" \
  "$name/P6_FILE_VALIDATION.txt" "$name/P7_SQL_FAMILIES.txt" "$name/P7_PUBLISHED.txt" \
  "$name/FAMILY_LANE_SUMMARY.tsv" "$name/FAMILY_WORKER_SUMMARY.tsv" \
  "$name/iostat.txt" "$name/vmstat.txt" "$name/W512_CHECKPOINTS.tsv" ||
  fail 'W512 metrics bundle creation failed'
[ -s "$bundle" ] || fail 'W512 metrics bundle absent'
printf 'FI W512 PILOT METRICS BUNDLE PASS path=%s sha256=%s\n' "$bundle" "$(sha256 -q "$bundle")"