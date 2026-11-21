#!/bin/sh
# CI-only: verify that C220 C1 read-only diagnostics use the actual
# installed FreeBSD jail name, not the logical fi-sor component label.
set -eu
root=go/cmd/fi-backlog-recover/diagnostics
for basename in \
    fi_c1_development_sor_preflight_c220.sh \
    fi_c1_populated_sor_readiness_c220.sh \
    fi_c1_crl_trust_readiness_c220.sh \
    fi_c1_sor_telemetry_discovery_c220.sh;do
    file="$root/$basename"
    sh -n "$file" || exit 1
    grep -F 'fi-sor-db' "$file" >/dev/null ||
        { echo "C1 C220 preflight missing real fi-sor-db jail name: $file" >&2; exit 1; }
    if grep -E '(jls -j fi-sor([[:space:]]|$)|jexec (.* )?fi-sor([[:space:]]|$)|for j in .* fi-sor;)' "$file";then
        echo "C1 C220 preflight used non-existent fi-sor jail: $file" >&2
        exit 1
    fi
done
echo "C1 C220 READ ONLY PREFLIGHT JAIL NAMES PASS real_jail=fi-sor-db"
