#!/bin/sh
# C220 real two-jail C1 sustained READY acceptance.
# Operator-triggered, finite snapshot of the two sources with signed READY work.
# No installer, source mutation, TCP/ACL changes, rc enable, or automatic replay.
# Failure preserves original custody and Pending for read-only reconciliation.
set -eu
umask 077

fail() { echo "FI C1 SUSTAINED STOP: $*" >&2; exit 1; }
[ "$#" -eq 1 ] && [ "$1" = "--drain-signed-ready" ] ||
    fail "usage: sh script --drain-signed-ready"
[ "$(uname -s)" = FreeBSD ] && [ "$(hostname -s)" = c220 ] &&
    [ "$(id -u)" -eq 0 ] || fail "physical C220 FreeBSD root required"

ready=/work/fi-c220-20261114/custody/ready
ingest_conf=/fast/jails/roots/fi-ingest/etc/rc.conf.d/fi_c1_ingest
sor_conf=/fast/jails/roots/fi-sor/etc/rc.conf.d/fi_c1_sor
gate=/fast/jails/roots/fi-dev/home/jwood/fi-c1-two-process-2a449f1a/go/cmd/fi-backlog-recover/diagnostics/fi_c1_c220_governed_deploy_gate.sh
sor_started=0
new_total=0
old_total=0
records_total=0
source_count=0

sql() {
    jexec -U postgres fi-sor psql -X -w -At -v ON_ERROR_STOP=1 \
        -h /var/db/fi/sor/run -p 5432 -d fi -c "$1"
}
marker_count() {
    if [ -d "$ready/$1" ]; then
        find "$ready/$1" -mindepth 1 -maxdepth 1 -type f -print |
            wc -l | tr -d ' '
    else
        printf '0\n'
    fi
}
cleanup() {
    rc=$?
    trap - EXIT HUP INT TERM
    if [ "$sor_started" -eq 1 ]; then
        echo "===== STOP C1 SOR ====="
        if ! jexec fi-sor service fi_c1_sor onestop; then
            echo "WARNING: manual C1 SoR service status review required" >&2
            [ "$rc" -ne 0 ] || rc=1
        fi
    fi
    if [ "$rc" -ne 0 ]; then
        echo "FI C1 SUSTAINED STOP: no automatic retry or Pending cleanup" >&2
        echo "FI C1 SUSTAINED LOGDIR=$logdir" >&2
    fi
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

echo "===== FULL C1 GOVERNED C220 READINESS ====="
[ -f "$gate" ] && [ ! -L "$gate" ] ||
    fail "existing read-only C220 gate missing"
sh "$gate" --ready
grep -qx 'fi_c1_sor_enable="NO"' "$sor_conf" ||
    fail "SoR rc must remain disabled"
grep -qx 'fi_c1_ingest_enable="NO"' "$ingest_conf" ||
    fail "ingest rc must remain disabled"
grep -qx 'fi_c1_sor_reconcile_private_replay="NO"' "$sor_conf" ||
    fail "replay must remain disabled"
if jexec fi-sor service fi_c1_sor onestatus >/dev/null 2>&1 ||
   jexec fi-ingest service fi_c1_ingest onestatus >/dev/null 2>&1; then
    fail "C1 worker already active"
fi
if jexec fi-ingest service fi_ingest_worker onestatus >/dev/null 2>&1; then
    fail "old FI worker already active"
fi
[ "$(sql "SELECT has_database_privilege('fi_c1_publisher','fi','TEMPORARY')")" = t ] ||
    fail "C1 canonical publisher lacks tested TEMP authority"
[ "$(sql "SELECT
    (SELECT count(*) FROM fi_c1_pending.recorded_generation)+
    (SELECT count(*) FROM fi_c1_pending.generation_control)+
    (SELECT count(*) FROM fi_c1_pending.source_batch)+
    (SELECT count(*) FROM fi_c1_pending.source_record)")" = 0 ] ||
    fail "unresolved Pending SQL exists"

echo "===== INVENTORY ORIGINAL SIGNED READY QUEUES ====="
work=0
for source in iss-fs-22a.iss.local iss-fs-22b.iss.local; do
    count=$(marker_count "$source")
    echo "SOURCE=$source READY=$count"
    [ "$count" -le 4096 ] || fail "unexpectedly large source queue"
    work=$((work + count))
done
[ "$work" -gt 0 ] || {
    echo "FI C1 SUSTAINED PASS no_signed_ready_work=true services_started=false"
    exit 0
}

logdir=$(mktemp -d /root/fi-c1-sustained-20261123.XXXXXXXX)
[ -d "$logdir" ] && [ ! -L "$logdir" ] || fail "unsafe audit directory"
echo "C1_LOGDIR=$logdir"
first=$(sql "SELECT (SELECT count(*) FROM fi.recorded_generation)::text
    ||'|'||(SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted')::text")
started_at=$(date +%s)
echo "CANONICAL_AND_ACCEPTED_BEFORE=$first"
echo "SIGNED_READY_SELECTED=$work"

echo "===== START EXISTING FI-SOR ONCE ====="
sor_started=1
jexec fi-sor service fi_c1_sor onestart
listening=0
i=0
while [ "$i" -lt 15 ]; do
    if jexec fi-sor sockstat -4 -l -P tcp |
        grep -q '172.20.20.22:9443'; then
        listening=1
        break
    fi
    i=$((i + 1))
    sleep 1
done
[ "$listening" -eq 1 ] || fail "existing private SoR listener did not start"

for source in iss-fs-22a.iss.local iss-fs-22b.iss.local; do
    count=$(marker_count "$source")
    [ "$count" -gt 0 ] || continue

    log="$logdir/$source.log"
    echo "===== SIGNED SOURCE PASS source=$source selected=$count ====="
    source_started_at=$(date +%s)

    # -once consumes the finite, bounded directory snapshot. A new receiver
    # marker appearing after the snapshot is not part of this operation.
    # The original source-specific queue is resolved by the Go READY code.
    if jexec -U fi-ingest fi-ingest /bin/sh -c '
        set -eu
        source_id=$1
        selected=$2
        . /etc/rc.conf.d/fi_c1_ingest

        test "$fi_c1_ingest_enable" = NO
        test -z "$fi_c1_ingest_generation_id"

        set -- \
            -source-id "$source_id" \
            -ready-root "$fi_c1_ingest_ready_root" \
            -ready-batch-size "$selected" \
            -once \
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
    ' sh "$source" "$count" > "$log" 2>&1; then
        :
    else
        echo "===== SOURCE FAILURE TAIL: $source =====" >&2
        tail -60 "$log" >&2
        fail "source run failed; committed prefix remains authoritative"
    fi

    new=$(grep -c "^FI C1 READY RETIRED source=$source " "$log" || :)
    old=$(grep -c "^FI C1 READY RECOVERED ACCEPTED source=$source " "$log" || :)
    finished=$((new + old))
    remaining=$(marker_count "$source")
    [ "$finished" -eq "$count" ] ||
        fail "source output does not prove every selected marker retired"
    [ "$remaining" -eq 0 ] ||
        fail "READY queue changed during finite pass; inspect receiver activity"
    [ "$(sql "SELECT
        (SELECT count(*) FROM fi_c1_pending.recorded_generation)+
        (SELECT count(*) FROM fi_c1_pending.generation_control)+
        (SELECT count(*) FROM fi_c1_pending.source_batch)+
        (SELECT count(*) FROM fi_c1_pending.source_record)")" = 0 ] ||
        fail "Pending must be empty after fully accepted source"

    records=$(awk '/^FI FAMILY P3 TOTAL / {
        for (i=1;i<=NF;i++) if ($i ~ /^input_records=/) {
            split($i,a,"="); total+=a[2]
        }
    } END {printf "%.0f\n",total+0}' "$log")

    elapsed=$(( $(date +%s) - source_started_at ))
    new_total=$((new_total + new))
    old_total=$((old_total + old))
    records_total=$((records_total + records))
    source_count=$((source_count + 1))
    echo "SOURCE_RESULT=$source new_canonical=$new previously_accepted=$old accepted_records=$records duration_seconds=$elapsed ready_remaining=$remaining"
done

echo "===== AUTHORITATIVE AFTER-READBACK ====="
last=$(sql "SELECT (SELECT count(*) FROM fi.recorded_generation)::text
    ||'|'||(SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted')::text")
expected_new=$new_total
before_gen=$(printf '%s\n' "$first" | cut -d '|' -f 1)
before_accept=$(printf '%s\n' "$first" | cut -d '|' -f 2)
after_gen=$(printf '%s\n' "$last" | cut -d '|' -f 1)
after_accept=$(printf '%s\n' "$last" | cut -d '|' -f 2)
[ "$after_gen" -eq "$((before_gen + expected_new))" ] ||
    fail "canonical generation delta disagrees with signed READY acknowledgments"
[ "$after_accept" -eq "$((before_accept + expected_new))" ] ||
    fail "Accepted journal delta disagrees with signed READY acknowledgments"

elapsed=$(( $(date +%s) - started_at ))
rate=$(awk -v records="$records_total" -v secs="$elapsed" \
    'BEGIN {if (secs>0) printf "%.1f",records/secs; else printf "n/a"}')
echo "CANONICAL_AND_ACCEPTED_BEFORE=$first"
echo "CANONICAL_AND_ACCEPTED_AFTER=$last"
echo "SOURCES_WITH_READY=$source_count"
echo "NEW_CANONICAL_GENERATIONS=$new_total"
echo "PREVIOUSLY_ACCEPTED_RECONCILED=$old_total"
echo "NEW_SIGNED_RECORDS=$records_total"
echo "ELAPSED_SECONDS=$elapsed"
echo "END_TO_END_RECORDS_PER_SECOND=$rate"
echo "ORIGINAL_SIGNED_CUSTODY_PRESERVED=true"
echo "UNRESOLVED_PENDING=0"
echo "CONTINUOUS_INGEST_NOT_ENABLED=true"
echo "C1_LOGDIR=$logdir"
echo "===== C1 SUSTAINED SIGNED READY ACCEPTANCE PASS ====="
