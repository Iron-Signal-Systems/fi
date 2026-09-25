#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="fi-ingest-worker.service"
TARGET_BINARY="/opt/fi/bin/fi-ingest-worker"
TARGET_ENV="/etc/fi/fi-ingest-worker.env"
TARGET_UNIT="/etc/systemd/system/${SERVICE_NAME}"

usage() {
    cat <<'EOF'
Usage:
  sudo ./Install-FI-Ingest-Worker.sh \
    --binary /path/to/fi-ingest-worker \
    --source <authorized-source-id> \
    [--enable]

This installer:
  - verifies the fi-receiver service identity and existing custody access;
  - installs the worker binary atomically to /opt/fi/bin/fi-ingest-worker;
  - writes /etc/fi/fi-ingest-worker.env;
  - installs fi-ingest-worker.service;
  - runs systemd unit verification;
  - reloads systemd;
  - optionally enables the unit for boot.

It does NOT start, restart, or stop the service.
It does NOT stop a manually running ingest worker.
EOF
}

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

BINARY=""
SOURCE_ID=""
ENABLE=0

while (($# > 0)); do
    case "$1" in
        --binary)
            (($# >= 2)) || fail "--binary requires a value"
            BINARY="$2"
            shift 2
            ;;
        --source)
            (($# >= 2)) || fail "--source requires a value"
            SOURCE_ID="$2"
            shift 2
            ;;
        --enable)
            ENABLE=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            fail "unknown argument: $1"
            ;;
    esac
done

[[ "$(id -u)" -eq 0 ]] || fail "installer must run as root"
[[ -n "${BINARY}" ]] || fail "--binary is required"
[[ -n "${SOURCE_ID}" ]] || fail "--source is required"
[[ -f "${BINARY}" ]] || fail "worker binary does not exist: ${BINARY}"
[[ -x "${BINARY}" ]] || fail "worker binary is not executable: ${BINARY}"

if [[ ! "${SOURCE_ID}" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]*$ ]]; then
    fail "source ID contains unsupported characters"
fi

for command in \
    getent \
    install \
    runuser \
    sha256sum \
    stat \
    systemctl \
    systemd-analyze
do
    command -v "${command}" >/dev/null 2>&1 ||
        fail "required command not found: ${command}"
done

getent passwd fi-receiver >/dev/null ||
    fail "required service user fi-receiver does not exist"

getent group fi-receiver >/dev/null ||
    fail "required service group fi-receiver does not exist"

if systemctl is-active --quiet "${SERVICE_NAME}"; then
    fail "${SERVICE_NAME} is already active; stop it deliberately before replacing its installed runtime"
fi

for path in \
    /var/lib/fi/custody/generation \
    /var/lib/fi/custody/recorded \
    /var/lib/fi/custody/ready
do
    [[ -d "${path}" ]] || fail "required custody directory is missing: ${path}"
done

runuser -u fi-receiver -- test -r /var/lib/fi/custody/generation ||
    fail "fi-receiver cannot read generation custody root"

runuser -u fi-receiver -- test -x /var/lib/fi/custody/generation ||
    fail "fi-receiver cannot traverse generation custody root"

runuser -u fi-receiver -- test -r /var/lib/fi/custody/recorded ||
    fail "fi-receiver cannot read recorded receipt root"

runuser -u fi-receiver -- test -x /var/lib/fi/custody/recorded ||
    fail "fi-receiver cannot traverse recorded receipt root"

runuser -u fi-receiver -- test -r /var/lib/fi/custody/ready ||
    fail "fi-receiver cannot read READY root"

runuser -u fi-receiver -- test -w /var/lib/fi/custody/ready ||
    fail "fi-receiver cannot modify READY root"

runuser -u fi-receiver -- test -x /var/lib/fi/custody/ready ||
    fail "fi-receiver cannot traverse READY root"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UNIT_SOURCE="${SCRIPT_DIR}/fi-ingest-worker.service"

[[ -f "${UNIT_SOURCE}" ]] ||
    fail "unit file not found beside installer: ${UNIT_SOURCE}"

echo "===== INSTALL PRECHECK ====="
echo "source=${SOURCE_ID}"
echo "binary=${BINARY}"
sha256sum "${BINARY}"

install -d -o root -g root -m 0755 /opt/fi
install -d -o root -g root -m 0755 /opt/fi/bin
install -d -o root -g fi-receiver -m 0750 /etc/fi

BINARY_TMP="/opt/fi/bin/.fi-ingest-worker.new.$$"
ENV_TMP="/etc/fi/.fi-ingest-worker.env.new.$$"
UNIT_TMP="/etc/systemd/system/.fi-ingest-worker.service.new.$$"

cleanup() {
    rm -f "${BINARY_TMP}" "${ENV_TMP}" "${UNIT_TMP}"
}
trap cleanup EXIT

install -o root -g root -m 0755 "${BINARY}" "${BINARY_TMP}"

{
    printf 'FI_SOURCE_ID=%s\n' "${SOURCE_ID}"
} > "${ENV_TMP}"
chown root:fi-receiver "${ENV_TMP}"
chmod 0640 "${ENV_TMP}"

install -o root -g root -m 0644 "${UNIT_SOURCE}" "${UNIT_TMP}"

mv -f "${BINARY_TMP}" "${TARGET_BINARY}"
mv -f "${ENV_TMP}" "${TARGET_ENV}"
mv -f "${UNIT_TMP}" "${TARGET_UNIT}"

echo
echo "===== INSTALLED FILES ====="
stat -c '%U:%G %a %n' \
    "${TARGET_BINARY}" \
    "${TARGET_ENV}" \
    "${TARGET_UNIT}"

echo
echo "===== UNIT VERIFY ====="
systemd-analyze verify "${TARGET_UNIT}"

echo
echo "===== SYSTEMD RELOAD ====="
systemctl daemon-reload

if [[ "${ENABLE}" -eq 1 ]]; then
    echo
    echo "===== ENABLE FOR BOOT ====="
    systemctl enable "${SERVICE_NAME}"
fi

echo
echo "===== INSTALLED WORKER SHA256 ====="
sha256sum "${TARGET_BINARY}"

echo
echo "PASS: permanent FI ingest-worker package installed"
echo "PASS: service was not started or restarted"
echo "Next action is an explicit controlled cutover from the current manual worker."
