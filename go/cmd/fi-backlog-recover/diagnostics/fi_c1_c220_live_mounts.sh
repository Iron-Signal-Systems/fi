#!/bin/sh
# FI C1 physical C220: one-time LIVE mount into EXISTING running jails.
# Does NOT configure reboot persistence, change jail.conf/fstab, restart
# jails, touch PostgreSQL or start C1 workers.
set -eu
umask 077
fail(){ printf 'FI C1 LIVE MOUNT STOP: %s\n' "$*" >&2; exit 1; }
[ "$#" -eq 1 ] || fail 'usage: sh script --audit | --apply'
case "$1" in
--audit|--apply) mode=$1 ;;
*) fail 'expected --audit or --apply' ;;
esac
[ "$(id -un)" = root ] && [ "$(hostname -s)" = c220 ] ||
    fail 'must run as root on physical C220'
ingest=/fast/jails/roots/fi-ingest
sor=/fast/jails/roots/fi-sor
ram=/var/run/fi-c1-handoff
ingest_ram=$ingest/var/run/fi-c1-handoff
sor_ram=$sor/var/run/fi-c1-handoff
host_generation=/work/fi-c220-20261114/custody/generation
host_recorded=/work/fi-c220-20261114/custody/recorded
host_trust=/work/fi-c220-20261114/config/receiver/pki/trust
host_sources=/work/fi-c220-20261114/config/receiver/sources
sor_generation=$sor/var/db/fi/custody/generation
sor_recorded=$sor/var/db/fi/custody/recorded
sor_trust=$sor/usr/local/etc/fi/pki/trust
sor_sources=$sor/usr/local/etc/fi/sources

for name in fi-ingest fi-sor; do
    case "$name" in
    fi-ingest) root=$ingest ;;
    fi-sor) root=$sor ;;
    esac
    actual=$(jls -h jid name path | awk -v n="$name" '$2==n {print $3}')
    [ "$actual" = "$root" ] || fail "running $name jail is not at expected root"
    [ -d "$root" ] && [ ! -L "$root" ] || fail "unsafe $name jail root"
done
if jls -j fi-sor-db jid >/dev/null 2>&1; then
    fail 'ambiguous fi-sor-db jail also running'
fi
[ "$(jexec fi-ingest id -u fi-ingest)" = 4100 ] &&
[ "$(jexec fi-ingest id -g fi-ingest)" = 4100 ] ||
    fail 'fi-ingest service identity differs from tested C220 baseline'
[ "$(jexec fi-sor id -u fi-sor)" = 4100 ] &&
[ "$(jexec fi-sor id -g fi-sor)" = 4100 ] ||
    fail 'fi-sor service identity differs from tested C220 baseline'
[ "$(jexec fi-sor id -g postgres)" = 770 ] ||
    fail 'existing PostgreSQL service group differs from C220 baseline'
for source in "$host_generation" "$host_recorded" "$host_trust" "$host_sources"; do
    [ -d "$source" ] && [ ! -L "$source" ] ||
        fail "original signed receiver custody/trust source absent or unsafe: $source"
    [ "$(realpath "$source")" = "$source" ] ||
        fail "original receiver source resolves through unexpected path: $source"
done
for name in fi-ingest fi-sor; do
    file=/etc/jail.conf.d/$name.conf
    [ -f "$file" ] && [ ! -L "$file" ] ||
        fail "unexpected original C220 jail configuration: $file"
    if grep -Eq '^[[:space:]]*mount[.]fstab[[:space:]]*=' "$file"; then
        fail "C220 jail fstab already installed; audit before live staging: $file"
    fi
done
if jexec fi-ingest pgrep -f '/usr/local/sbin/fi-c1-ingest-worker' >/dev/null 2>&1; then
    fail 'C1 ingest worker already running'
fi
if jexec fi-sor pgrep -f '/usr/local/sbin/fi-c1-sor-worker' >/dev/null 2>&1; then
    fail 'C1 SoR worker already running'
fi
jexec -U postgres fi-sor pg_isready -h /var/db/fi/sor/run -p 5432 >/dev/null 2>&1 ||
    fail 'existing PostgreSQL SoR unavailable'

# No overlapping C1 mountpoint is permitted. This must start from
# unmounted host filesystem and jail folders seen in physical preflight.
for dest in "$ram" "$ingest_ram" "$sor_ram" \
    "$sor_generation" "$sor_recorded" "$sor_trust" "$sor_sources"; do
    if mount -p | awk -v p="$dest" '$2==p {found=1} END{exit !found}'; then
        fail "existing mount occupies C1 destination: $dest"
    fi
    if [ -L "$dest" ]; then
        fail "C1 destination is a symlink: $dest"
    fi
    if [ -e "$dest" ]; then
        [ -d "$dest" ] || fail "C1 destination is not a directory: $dest"
        [ -z "$(ls -A "$dest")" ] ||
            fail "C1 would cover nonempty destination: $dest"
    fi
done
[ "$(jexec -U postgres fi-sor psql -X -w -At -v ON_ERROR_STOP=1 \
    -h /var/db/fi/sor/run -p 5432 -d fi \
    -c "SELECT (to_regnamespace('fi_recovery_projection') IS NULL AND to_regnamespace('fi_recovery') IS NULL)::text")" = t ] ||
    fail 'C1 private development SQL stage must remain absent before live mount'

echo '===== FI C1 REAL C220 LIVE MOUNT PRECHECK PASS ====='
echo 'Host tmpfs: /var/run/fi-c1-handoff (4 GiB noexec nosuid UID:GID 4100:4100)'
echo 'fi-ingest: writable RAM; fi-sor: read-only RAM + signed custody/receipt/trust/registry'
echo 'Existing FI jail configs, PostgreSQL, receiver mounts and database unchanged.'
if [ "$mode" = --audit ]; then
    echo 'FI C1 LIVE MOUNT AUDIT COMPLETE read_only=true mount_changes=false'
    exit 0
fi
[ "$(printenv FI_C1_LIVE_MOUNTS_APPROVED 2>/dev/null || :)" = \
  ONLY_C1_TMPFS_AND_FIVE_SOR_RO_VIEWS ] ||
    fail 'exact C220 live-only mount authorization required'

# First live test deliberately does not persist across reboot.
# Check the canonical path after mkdir, before any mount.
ensure_mountpoint(){
    dest=$1
    install -d -o root -g wheel -m 0755 "$dest" ||
        fail "cannot create safe empty C1 destination: $dest"
    [ -d "$dest" ] && [ ! -L "$dest" ] &&
        [ "$(realpath "$dest")" = "$dest" ] &&
        [ -z "$(ls -A "$dest")" ] ||
        fail "C1 mountpoint changed or contains files: $dest"
}
for dest in "$ram" "$ingest_ram" "$sor_ram" \
    "$sor_generation" "$sor_recorded" "$sor_trust" "$sor_sources"; do
    ensure_mountpoint "$dest"
done

echo '===== MOUNT REAL C220 FI C1 LIVE TRANSPORT ====='
mount -t tmpfs -o 'size=4g,uid=4100,gid=4100,mode=0770,nosuid,noexec' \
    tmpfs "$ram" || fail 'host tmpfs mount failed; no jail restart'
mount -t nullfs -o rw "$ram" "$ingest_ram" ||
    fail 'fi-ingest producer RW RAM nullfs mount failed'
mount -t nullfs -o ro "$ram" "$sor_ram" ||
    fail 'fi-sor consumer RO RAM nullfs mount failed'
mount -t nullfs -o ro "$host_generation" "$sor_generation" ||
    fail 'fi-sor original signed generation RO mount failed'
mount -t nullfs -o ro "$host_recorded" "$sor_recorded" ||
    fail 'fi-sor original recorded receipt RO mount failed'
mount -t nullfs -o ro "$host_trust" "$sor_trust" ||
    fail 'fi-sor pinned receiver trust RO mount failed'
mount -t nullfs -o ro "$host_sources" "$sor_sources" ||
    fail 'fi-sor pinned source-registry RO mount failed'

echo '===== VERIFY EXACT LIVE MOUNTS (NATIVE STATFS ACCEPTANCE STILL REQUIRED) ====='
check_mount(){
    src=$1
    dest=$2
    typ=$3
    opt=$4
    mount -p | awk -v a="$src" -v b="$dest" -v t="$typ" -v o="$opt" \
      '$1==a && $2==b && $3==t {n=split($4,opts,","); for(i=1;i<=n;i++) if(opts[i]==o){ok=1}} END{exit !ok}' ||
        fail "C1 live mount source/type/mode mismatch at $dest"
    echo "C1_LIVE_MOUNT_OK=$dest mode=$opt"
}
check_mount tmpfs "$ram" tmpfs rw
check_mount "$ram" "$ingest_ram" nullfs rw
check_mount "$ram" "$sor_ram" nullfs ro
check_mount "$host_generation" "$sor_generation" nullfs ro
check_mount "$host_recorded" "$sor_recorded" nullfs ro
check_mount "$host_trust" "$sor_trust" nullfs ro
check_mount "$host_sources" "$sor_sources" nullfs ro
echo 'FI C1 C220 LIVE MOUNTS INSTALLED host_persistence=false jail_restarts=0 c1_services_started=false'
