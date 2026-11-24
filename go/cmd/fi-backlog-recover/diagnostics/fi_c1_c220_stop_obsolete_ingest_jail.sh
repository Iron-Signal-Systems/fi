#!/bin/sh
# FreeBSD C220, explicitly selected SINGLE-JAIL C1 migration.
# --audit is read-only. --stop stops ONLY the obsolete fi-ingest jail.
# NEVER destroys a jail root, modifies ZFS, unmounts receiver custody,
# removes signed batches/receipts, changes SQL, or edits boot configuration.
set -eu
fail(){ echo "FI C1 OLD INGEST JAIL STOP: $*" >&2; exit 1; }
[ "$#" -eq 1 ] || fail 'usage: --audit | --stop'
case "$1" in --audit|--stop) mode=$1;; *) fail 'unknown mode';; esac
[ "$(uname -s)" = FreeBSD ] && [ "$(id -u)" = 0 ] ||
    fail 'must run as root on the physical FreeBSD C220'
[ -d /fast/jails/roots/fi-sor ] &&
[ -d /fast/jails/roots/fi-receiver ] &&
[ -d /work/fi-c220-20261114/custody/generation ] &&
[ -d /work/fi-c220-20261114/custody/recorded ] ||
    fail 'physical C220 original jail/custody paths differ; do not proceed'
echo "===== OBSOLETE FI-INGEST JAIL STATUS ====="
if jls -j fi-ingest >/dev/null 2>&1; then
    jls -j fi-ingest
    if jexec fi-ingest /usr/bin/pgrep -fl 'fi-c1-ingest-worker|fi-ingest-worker' 2>/dev/null;then
        fail 'an FI ingest worker is still running; do not interrupt signed work'
    fi
    if [ "$mode" = --stop ];then
        echo "===== STOP FI-INGEST JAIL (NO DESTROY) ====="
        service jail onestop fi-ingest ||
            fail 'FreeBSD jail rc stop failed; no alternate forced kill'
        if jls -j fi-ingest >/dev/null 2>&1;then
            fail 'fi-ingest jail remains running after stop'
        fi
        echo 'FI C1 OLD INGEST JAIL STOPPED original_custody_untouched=true jail_root_preserved=true'
    fi
else
    echo 'FI C1 OLD INGEST JAIL ALREADY STOPPED'
fi
echo "===== PERSISTENT BOOT CONFIG REFERENCES (READ-ONLY) ====="
for f in /etc/jail.conf /etc/jail.conf.d/*.conf /etc/rc.conf /etc/rc.conf.local /etc/fstab /etc/fstab.fi-ingest /etc/fstab.fi-sor;do
    [ -f "$f" ] || continue
    grep -n 'fi-ingest' "$f" | sed "s|^|$f:|" || :
done
echo "===== ORIGINAL RECEIVER SIGNED CUSTODY PRESENCE ====="
[ -d /work/fi-c220-20261114/custody/generation ] ||
    fail 'original generation custody missing after jail stop'
[ -d /work/fi-c220-20261114/custody/recorded ] ||
    fail 'original recorded receipts missing after jail stop'
echo "FI C1 SINGLE-JAIL LEGACY INGEST AUDIT COMPLETE mode=$mode custody_delete=false jail_root_delete=false postgres_writes=false"
