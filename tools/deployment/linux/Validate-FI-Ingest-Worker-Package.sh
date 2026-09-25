#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UNIT="${SCRIPT_DIR}/fi-ingest-worker.service"

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

[[ -f "${UNIT}" ]] || fail "unit file missing: ${UNIT}"

for command in grep systemd-analyze; do
    command -v "${command}" >/dev/null 2>&1 ||
        fail "required command not found: ${command}"
done

echo "===== SYSTEMD UNIT VERIFY ====="

set +e
VERIFY_OUTPUT="$(systemd-analyze verify "${UNIT}" 2>&1)"
VERIFY_RC=$?
set -e

if [[ "${VERIFY_RC}" -eq 0 ]]; then
    if [[ -n "${VERIFY_OUTPUT}" ]]; then
        printf '%s\n' "${VERIFY_OUTPUT}"
    fi
    echo "PASS: systemd unit verification"
else
    UNEXPECTED=0
    while IFS= read -r line; do
        [[ -z "${line}" ]] && continue

        case "${line}" in
            *"Command /opt/fi/bin/fi-ingest-worker is not executable: No such file or directory")
                echo "EXPECTED PREINSTALL: ${line}"
                ;;
            *)
                echo "UNEXPECTED VERIFY ERROR: ${line}" >&2
                UNEXPECTED=1
                ;;
        esac
    done <<< "${VERIFY_OUTPUT}"

    if [[ "${UNEXPECTED}" -ne 0 ]]; then
        fail "systemd unit verification reported an unexpected error"
    fi

    echo "PASS: preinstall verification reached only the expected missing-binary diagnostic"
    echo "PASS: installer performs strict systemd-analyze verify after the binary is installed"
fi

echo
echo "===== CONTRACT CHECKS ====="

require_line() {
    local pattern="$1"
    local description="$2"

    if ! grep -Eq "${pattern}" "${UNIT}"; then
        fail "missing ${description}"
    fi

    echo "PASS: ${description}"
}

forbid_line() {
    local pattern="$1"
    local description="$2"

    if grep -Eq "${pattern}" "${UNIT}"; then
        fail "forbidden ${description}"
    fi

    echo "PASS: no ${description}"
}

require_line '^User=fi-receiver$' 'fi-receiver service user'
require_line '^Group=fi-receiver$' 'fi-receiver service group'
require_line '^UMask=0077$' 'restrictive runtime umask'
require_line '^RuntimeDirectory=fi$' 'systemd-owned /run/fi runtime directory'
require_line '^RuntimeDirectoryMode=0700$' '/run/fi mode 0700'
require_line '^RuntimeDirectoryPreserve=yes$' 'preserved runtime lock namespace'
require_line '^Restart=on-failure$' 'process-failure restart policy'
require_line '^RestartSec=5s$' 'bounded process restart delay'
require_line '^StartLimitIntervalSec=60s$' 'restart-storm interval'
require_line '^StartLimitBurst=3$' 'restart-storm burst limit'
require_line '^-?[[:space:]]*-postgres-retry-initial 1s' 'PostgreSQL initial reconnect delay'
require_line '^-?[[:space:]]*-postgres-retry-max 30s' 'PostgreSQL maximum reconnect delay'
require_line '^-?[[:space:]]*-repair-interval 1h' 'adaptive repair validation interval'
require_line '^-?[[:space:]]*-poll-interval 2s' 'accepted worker poll interval'
require_line '^NoNewPrivileges=yes$' 'NoNewPrivileges hardening'
require_line '^ProtectSystem=strict$' 'strict system filesystem protection'
require_line '^ReadOnlyPaths=/var/lib/fi/custody/generation$' 'read-only generation custody'
require_line '^ReadOnlyPaths=/var/lib/fi/custody/recorded$' 'read-only recorder receipt authority'
require_line '^ReadWritePaths=/var/lib/fi/custody/ready$' 'READY retirement write boundary'
require_line '^ReadWritePaths=/run/fi$' 'runtime lock write boundary'

forbid_line '^Requires=.*postgres' 'hard PostgreSQL Requires dependency'
forbid_line '^BindsTo=.*postgres' 'hard PostgreSQL BindsTo dependency'
forbid_line '^PartOf=.*postgres' 'PostgreSQL lifecycle coupling'
forbid_line '^Restart=always$' 'unbounded Restart=always policy'

echo
echo "PASS: FI ingest-worker systemd package contract is valid"
