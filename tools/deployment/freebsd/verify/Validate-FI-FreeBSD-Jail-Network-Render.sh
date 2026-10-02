#!/bin/sh

PROGRAM=${0##*/}
VERIFY_DIR=$(CDPATH= cd "$(dirname "$0")" 2>/dev/null && pwd)
FREEBSD_DIR=$(CDPATH= cd "$VERIFY_DIR/.." 2>/dev/null && pwd)

BOOTSTRAP="$FREEBSD_DIR/fi-bootstrap.sh"
FIXTURE="$VERIFY_DIR/fixtures/fi-bootstrap.test.conf"

WORK_ROOT=""

fail()
{
    printf '[FAIL] %s\n' "$*" >&2

    if [ -n "$WORK_ROOT" ] && [ -d "$WORK_ROOT" ]; then
        rm -rf "$WORK_ROOT"
    fi

    exit 1
}

pass()
{
    printf '[PASS] %s\n' "$*"
}

cleanup()
{
    if [ -n "$WORK_ROOT" ] && [ -d "$WORK_ROOT" ]; then
        rm -rf "$WORK_ROOT"
    fi
}

require_line()
{
    expected_file=$1
    expected_line=$2
    description=$3

    grep -Fqx "$expected_line" "$expected_file" ||
        fail "$description"

    pass "$description"
}

reject_text()
{
    expected_file=$1
    rejected_text=$2
    description=$3

    if grep -Fq "$rejected_text" "$expected_file"; then
        fail "$description"
    fi

    pass "$description"
}

trap cleanup EXIT HUP INT TERM

[ -x "$BOOTSTRAP" ] ||
    fail "bootstrap is not executable: $BOOTSTRAP"

[ -f "$FIXTURE" ] ||
    fail "fixture not found: $FIXTURE"

WORK_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/fi-jail-network-render.XXXXXX") ||
    fail "unable to create test workspace"

PLAN="$WORK_ROOT/plan"

"$BOOTSTRAP" plan "$FIXTURE" "$PLAN" >/dev/null ||
    fail "unable to render production jail network plan"

RECEIVER="$PLAN/fi-receiver.conf"
INGEST="$PLAN/fi-ingest.conf"
SOR="$PLAN/fi-sor-db.conf"

for expected_file in "$RECEIVER" "$INGEST" "$SOR"
do
    [ -f "$expected_file" ] ||
        fail "rendered jail configuration is absent: $expected_file"

    if grep -Eq '@FI_[A-Z0-9_]+@' "$expected_file"; then
        fail "rendered jail configuration contains unresolved FI token: $expected_file"
    fi
done

pass "all three jail network templates render without unresolved FI tokens"

require_line \
    "$RECEIVER" \
    '    exec.prestart = "/usr/local/libexec/fi-vnet-pair create-receiver vtnet1 bridge30 epre0a epre0b jail:fi-receiver:external eprm0a eprm0b bridge10 jail:fi-receiver:mgmt eprw0a eprw0b bridge20 jail:fi-receiver:work";' \
    "receiver uses create-receiver with exact external bridge and epair inputs"

require_line \
    "$RECEIVER" \
    '    vnet.interface = "epre0b";' \
    "receiver receives external jail epair endpoint"

reject_text \
    "$RECEIVER" \
    '    vnet.interface = "vtnet1";' \
    "receiver does not receive dedicated physical external interface"

require_line \
    "$RECEIVER" \
    '    vnet.interface += "eprm0b";' \
    "receiver receives management jail endpoint"

require_line \
    "$RECEIVER" \
    '    vnet.interface += "eprw0b";' \
    "receiver receives workload jail endpoint"

require_line \
    "$RECEIVER" \
    '    exec.start = "/sbin/ifconfig epre0b inet 192.168.1.219/24 up";' \
    "receiver configures exact external address inside VNET"

require_line \
    "$RECEIVER" \
    '    exec.start += "/sbin/ifconfig eprm0b inet 10.77.10.20/24 up";' \
    "receiver configures exact management address"

require_line \
    "$RECEIVER" \
    '    exec.start += "/sbin/ifconfig eprw0b inet 10.77.20.20/24 up";' \
    "receiver configures exact workload address"

require_line \
    "$RECEIVER" \
    '    exec.start += "/sbin/route add default 192.168.1.1";' \
    "receiver default route uses external gateway"

require_line \
    "$RECEIVER" \
    '    exec.poststop = "/usr/local/libexec/fi-vnet-pair destroy-receiver vtnet1 bridge30 epre0a epre0b eprm0a eprm0b bridge10 eprw0a eprw0b bridge20";' \
    "receiver poststop destroys external, management, and workload attachments"

require_line \
    "$INGEST" \
    '    exec.prestart = "/usr/local/libexec/fi-vnet-pair create-dual epim0a epim0b bridge10 jail:fi-ingest:mgmt epiw0a epiw0b bridge20 jail:fi-ingest:work";' \
    "ingest uses exact dual-epair prestart"

require_line \
    "$INGEST" \
    '    exec.start = "/sbin/ifconfig epim0b inet 10.77.10.21/24 up";' \
    "ingest configures exact management address"

require_line \
    "$INGEST" \
    '    exec.start += "/sbin/ifconfig epiw0b inet 10.77.20.21/24 up";' \
    "ingest configures exact workload address"

require_line \
    "$INGEST" \
    '    exec.start += "/sbin/route add default 10.77.10.1";' \
    "ingest default route uses management gateway"

require_line \
    "$INGEST" \
    '    exec.poststop = "/usr/local/libexec/fi-vnet-pair destroy-dual epim0a epim0b bridge10 epiw0a epiw0b bridge20";' \
    "ingest poststop uses exact dual-epair cleanup"

require_line \
    "$SOR" \
    '    exec.prestart = "/usr/local/libexec/fi-vnet-pair create-dual epdm0a epdm0b bridge10 jail:fi-sor-db:mgmt epdw0a epdw0b bridge20 jail:fi-sor-db:work";' \
    "System of Record retains exact dual-epair prestart"

require_line \
    "$SOR" \
    '    exec.start += "/sbin/route add default 10.77.10.1";' \
    "System of Record default route uses management gateway"

require_line \
    "$SOR" \
    '    sysvmsg = new;' \
    "System of Record receives a private System V message namespace"

require_line \
    "$SOR" \
    '    sysvsem = new;' \
    "System of Record receives a private System V semaphore namespace"

require_line \
    "$SOR" \
    '    sysvshm = new;' \
    "System of Record receives a private System V shared-memory namespace"

reject_text \
    "$SOR" \
    "allow.sysvipc" \
    "System of Record does not receive deprecated allow.sysvipc"

for ipc_token in sysvmsg sysvsem sysvshm
do
    reject_text \
        "$SOR" \
        "    $ipc_token = inherit;" \
        "System of Record does not inherit System V IPC namespace: $ipc_token"
done

for ipc_token in sysvmsg sysvsem sysvshm
do
    reject_text \
        "$RECEIVER" \
        "$ipc_token" \
        "receiver does not receive PostgreSQL private IPC: $ipc_token"

    reject_text \
        "$INGEST" \
        "$ipc_token" \
        "ingest does not receive PostgreSQL private IPC: $ipc_token"
done

reject_text \
    "$INGEST" \
    "vtnet1" \
    "ingest does not receive receiver dedicated external interface"

reject_text \
    "$SOR" \
    "vtnet1" \
    "System of Record does not receive receiver dedicated external interface"

reject_text \
    "$RECEIVER" \
    "192.168.1.218" \
    "receiver template never references host administrative address"

receiver_vnet_count=$(grep -c '^[[:space:]]*vnet\.interface' "$RECEIVER")
ingest_vnet_count=$(grep -c '^[[:space:]]*vnet\.interface' "$INGEST")
sor_vnet_count=$(grep -c '^[[:space:]]*vnet\.interface' "$SOR")

[ "$receiver_vnet_count" -eq 3 ] ||
    fail "receiver must receive exactly three interfaces"

[ "$ingest_vnet_count" -eq 2 ] ||
    fail "ingest must receive exactly two interfaces"

[ "$sor_vnet_count" -eq 2 ] ||
    fail "System of Record must receive exactly two interfaces"

pass "rendered VNET interface counts are exact"

for expected_file in "$RECEIVER" "$INGEST" "$SOR"
do
    require_line \
        "$expected_file" \
        '    exec.start += "/bin/sh /etc/rc";' \
        "jail starts FreeBSD rc after network configuration: ${expected_file##*/}"

    require_line \
        "$expected_file" \
        '    exec.stop = "/bin/sh /etc/rc.shutdown jail";' \
        "jail uses controlled rc shutdown: ${expected_file##*/}"
done

pass "FI FreeBSD jail network render acceptance complete"
