#!/bin/sh

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" 2>/dev/null && pwd)
BOOTSTRAP="$SCRIPT_DIR/../fi-bootstrap.sh"

[ -f "$BOOTSTRAP" ] || {
    printf '[FAIL] bootstrap not found: %s\n' "$BOOTSTRAP" >&2
    exit 1
}

awk '
    BEGIN {
        modes[1] = "apply-zfs"
        modes[2] = "preflight-jail-roots"
        modes[3] = "apply-jail-roots"
        modes[4] = "verify-jail-roots"
        modes[5] = "apply-identities"
        modes[6] = "apply-directories"
        modes[7] = "apply-devfs"
        modes[8] = "verify-devfs"
        modes[9] = "apply-host-files"
        modes[10] = "verify-host-files"
        modes[11] = "verify-zfs"
    }

    $0 == "    case \"$mode\" in" {
        mode_case++
        next
    }

    {
        label = $0
        sub(/^[[:space:]]*/, "", label)

        if (label !~ /^[A-Za-z0-9_-]+(\|[A-Za-z0-9_-]+)*\)$/) {
            next
        }

        sub(/\)$/, "", label)
        count = split(label, parts, /\|/)

        for (part = 1; part <= count; part++) {
            for (i = 1; i <= 11; i++) {
                if (parts[part] != modes[i]) {
                    continue
                }

                if (mode_case == 2) {
                    helper[modes[i]]++
                } else if (mode_case == 3) {
                    dispatch[modes[i]]++
                }
            }
        }
    }

    END {
        failed = 0

        if (mode_case != 3) {
            printf \
                "[FAIL] expected exactly three mode case blocks, observed %d\n", \
                mode_case > "/dev/stderr"
            failed = 1
        }

        for (i = 1; i <= 11; i++) {
            mode = modes[i]

            if (helper[mode] != 1 || dispatch[mode] != 1) {
                printf \
                    "[FAIL] bootstrap dispatch %s: helper=%d dispatch=%d\n", \
                    mode, helper[mode], dispatch[mode] > "/dev/stderr"
                failed = 1
            }
        }

        exit failed
    }
' "$BOOTSTRAP" || exit 1

printf '%s\n' \
    "[PASS] bootstrap helper-loading and final-dispatch structure is exact"
