#!/bin/sh
# FI C1: exact signed Pending generation replay, followed by finite READY drain.
# Operator-triggered only; fail closed with no SQL/custody/READY truncation.
# The prior --ready-batch-size 1 attempt was WRONG: READY queue ordering does
# not select this Pending generation. Always use the explicit generation mode.
set -eu
umask 077

fail(){ echo "FI C1 EXACT RECOVERY STOP: $*" >&2; exit 1; }
[ "$#" -eq 1 ] && [ "$1" = "--resume-and-drain" ] ||
    fail "usage: sh script --resume-and-drain"
[ "$(uname -s)" = FreeBSD ] && [ "$(hostname -s)" = c220 ] &&
    [ "$(id -u)" -eq 0 ] || fail "C220 root only"

source=iss-fs-22a.iss.local
generation=20261030T000032.061323100Z-3e38b2210771462c
receipt_sha=29891703eea7bef6e21b84374c49193a9b1d58666665d418267e418e3414c7ed
marker=generation-67ef0182b7803049344fafb4a693c0fa559abc603a15a4157fc982548b249c38.record.json
recorded=/work/fi-c220-20261114/custody/recorded
ready=/work/fi-c220-20261114/custody/ready/iss-fs-22a.iss.local
sor_config=/fast/jails/roots/fi-sor/etc/rc.conf.d/fi_c1_sor
ingest_config=/fast/jails/roots/fi-ingest/etc/rc.conf.d/fi_c1_ingest
sustained=/root/fi-c1-sustained-20261123.sh
original_config=
changed=0
started=0
logdir=

sql(){
    jexec -U postgres fi-sor psql -X -w -At -v ON_ERROR_STOP=1 \
        -h /var/db/fi/sor/run -p 5432 -d fi -c "$1"
}
cleanup(){
    code=$?
    trap - EXIT HUP INT TERM
    if [ "$started" = 1 ]; then
        jexec fi-sor service fi_c1_sor onestop ||
            { echo "WARNING: SoR stop unsuccessful" >&2; code=1; }
    fi
    if [ "$changed" = 1 ]; then
        install -o root -g 4100 -m 0640 "$original_config" "$sor_config" ||
            { echo "WARNING: manual recovery mode reset needed" >&2; code=1; }
    fi
    if [ "$code" -ne 0 ]; then
        echo "===== EXACT SERVER REJECTION EVIDENCE ====="
        jexec fi-sor /bin/sh -c '
            for f in /var/log/daemon.log /var/log/messages; do
                [ -f "$f" ] || continue
                grep -E "FI C1 SOR (START REJECTED|SQL HANDOFF REJECTED|SESSION STOP)|FI C1 NATIVE B FAILED" "$f" |
                  tail -20 || :
            done
        ' || :
        echo "RECOVERY_LOGDIR=$logdir"
        echo "FAIL CLOSED: preserve signed custody, Pending SQL and READY markers" >&2
    fi
    exit "$code"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

echo "===== EXACT SIGNED PENDING RECOVERY PREFLIGHT ====="
[ -f "$recorded/$marker" ] && [ ! -L "$recorded/$marker" ] ||
    fail "original recorded receipt missing or unsafe"
[ "$(sha256 -q "$recorded/$marker")" = "$receipt_sha" ] ||
    fail "original signed receipt SHA differs"
[ -f "$ready/$marker" ] && [ ! -L "$ready/$marker" ] ||
    fail "interrupted generation READY marker not found"
grep -qx 'fi_c1_sor_enable="NO"' "$sor_config" ||
    fail "SoR boot service must remain disabled"
grep -qx 'fi_c1_ingest_enable="NO"' "$ingest_config" ||
    fail "ingest boot service must remain disabled"
grep -qx 'fi_c1_sor_reconcile_private_replay="NO"' "$sor_config" ||
    fail "replay state not initially disabled"
[ -f "$sustained" ] && [ ! -L "$sustained" ] ||
    fail "bounded sustained READY runner not staged"
sh -n "$sustained" || fail "sustained READY script syntax check failed"
for service in 'fi-sor fi_c1_sor' 'fi-ingest fi_c1_ingest' 'fi-ingest fi_ingest_worker'; do
    set -- $service
    if jexec "$1" service "$2" onestatus >/dev/null 2>&1; then
        fail "competing FI service $2 already running"
    fi
done
pending=$(sql "SELECT source_id||'|'||generation_id||'|'||state||'|'||
     record_count||'|'||batch_count FROM fi_c1_pending.generation_control")
[ "$pending" = "$source|$generation|Pending|15140785|8399" ] ||
    fail "Pending control is not the exact interrupted signed generation"
[ "$(sql "SELECT count(*) FROM fi_c1_pending.source_record")" = 334323 ] ||
    fail "committed SourceParent count differs from audited interrupted prefix"
[ "$(sql "SELECT count(*) FROM fi.recorded_generation
    WHERE source_id='$source' AND generation_id='$generation'")" = 0 ] ||
    fail "generation is already canonical"
[ "$(sql "SELECT has_database_privilege(
    'fi_c1_publisher','fi','TEMPORARY')")" = t ] ||
    fail "publisher TEMP privilege absent"
jexec -U fi-sor fi-sor /usr/local/libexec/fi-c1-sor-run --verify ||
    fail "installed fi-sor read-only preflight failed"

echo "===== SET REPLAY MODE ONLY FOR EXACT INTERRUPTED GENERATION ====="
logdir=$(mktemp -d /root/fi-c1-exact-recovery-20261123.XXXXXXXX)
echo "RECOVERY_LOGDIR=$logdir"
original_config=$(mktemp /root/fi-c1-rc-before-exact-replay.XXXXXXXX)
cp -p "$sor_config" "$original_config"
candidate=$(mktemp /root/fi-c1-rc-exact-replay.XXXXXXXX)
awk '
    $0=="fi_c1_sor_reconcile_private_replay=\"NO\"" {
        print "fi_c1_sor_reconcile_private_replay=\"YES\""; matched++; next
    }
    {print}
    END {if(matched!=1)exit 1}
' "$sor_config" >"$candidate"
changed=1
install -o root -g 4100 -m 0640 "$candidate" "$sor_config"
rm -f "$candidate"

canonical_before=$(sql "SELECT count(*) FROM fi.recorded_generation")
echo "CANONICAL_BEFORE=$canonical_before"

echo "===== START C1 SOR FOR SINGLE EXACT SIGNED REPLAY ====="
started=1
jexec fi-sor service fi_c1_sor onestart
listening=0
i=0
while [ "$i" -lt 15 ]; do
    if jexec fi-sor sockstat -4 -l -P tcp |
        grep -q '172.20.20.22:9443'; then
        listening=1;break
    fi
    i=$((i + 1))
    sleep 1
done
[ "$listening" = 1 ] || fail "C1 SoR mTLS listener unavailable"

echo "===== REPLAY EXACT 15,140,785-RECORD GENERATION ====="
echo "SIGNED_GENERATION=$generation"
echo "INGEST_LOG=$logdir/exact-generation.log"
# Crucial: -generation-id, not -ready-root/-ready-batch-size/-once.
# This worker does not retire READY markers in explicit generation mode.
if jexec -U fi-ingest fi-ingest /bin/sh -c '
    set -eu
    generation=$1
    . /etc/rc.conf.d/fi_c1_ingest
    [ "$fi_c1_ingest_enable" = NO ] && [ -z "$fi_c1_ingest_generation_id" ]
    set -- \
        -source-id iss-fs-22a.iss.local \
        -generation-id "$generation" \
        -custody-root "$fi_c1_ingest_custody_root" \
        -recorded-root "$fi_c1_ingest_recorded_root" \
        -shared-ram-dir "$fi_c1_ingest_shared_ram_dir" \
        -sor-address "$fi_c1_ingest_sor_address" \
        -sor-server-dns "$fi_c1_ingest_sor_dns" \
        -tls-cert "$fi_c1_ingest_tls_cert" \
        -tls-key "$fi_c1_ingest_tls_key" \
        -tls-ca "$fi_c1_ingest_tls_ca"
    case "$fi_c1_ingest_source_namespaces" in
        YES) set -- "$@" -source-namespaces ;;
        NO) ;;
        *) exit 1 ;;
    esac
    exec /usr/local/sbin/fi-c1-ingest-worker "$@"
' sh "$generation" >"$logdir/exact-generation.log" 2>&1; then
    :
else
    tail -60 "$logdir/exact-generation.log" >&2
    fail "exact signed replay failed; no continuation"
fi

grep -Fq "FI C1 CANONICAL ACCEPTED source=$source generation=$generation records=15140785" \
    "$logdir/exact-generation.log" ||
    fail "explicit signed generation did not report canonical acceptance"
[ "$(sql "SELECT count(*) FROM fi.recorded_generation")" -eq "$((canonical_before+1))" ] ||
    fail "canonical count did not increase exactly once"
[ "$(sql "SELECT count(*) FROM fi.ingest_journal WHERE
    source_id='$source' AND generation_id='$generation' AND outcome='Accepted'")" = 1 ] ||
    fail "exact canonical Accepted journal missing or duplicated"
[ "$(sql "SELECT
    (SELECT count(*) FROM fi_c1_pending.recorded_generation)+
    (SELECT count(*) FROM fi_c1_pending.generation_control)+
    (SELECT count(*) FROM fi_c1_pending.source_batch)+
    (SELECT count(*) FROM fi_c1_pending.source_record)")" = 0 ] ||
    fail "Pending not entirely retired"
[ -f "$ready/$marker" ] || fail "explicit mode unexpectedly changed READY marker"
echo "C1_EXACT_15M_CANONICAL_ACCEPTANCE=PASS"

echo "===== EXIT RECOVERY MODE AND RESTORE NO-REPLAY ====="
jexec fi-sor service fi_c1_sor onestop
started=0
install -o root -g 4100 -m 0640 "$original_config" "$sor_config"
changed=0
echo "REPLAY_DISABLED=true"

echo "===== FINITE TWO-SOURCE READY BACKLOG ACCEPTANCE ====="
# The first READY pass will reconcile/retire the already Accepted
# 15M generation marker without re-running its SQL.
sh "$sustained" --drain-signed-ready ||
    fail "subsequent bounded READY drain failed; no automatic retry"

echo "C1_EXACT_RECOVERY_AND_SUSTAINED_ACCEPTANCE=PASS"
echo "ORIGINAL_CUSTODY_PRESERVED=true CONTINUOUS_INGEST=false"
echo "RECOVERY_LOGDIR=$logdir"
