#!/bin/sh
# FI C1 C220: READ-ONLY inventory for exact reboot-persistence planning.
# This enumerates ALL current host-managed nullfs mounts for fi-receiver,
# fi-ingest and fi-sor, not just the seven new C1 mounts. A reboot would
# otherwise lose the existing signed custody and PostgreSQL pgdata views.
# This script never edits mount.fstab, jail.conf, rc.d, rc.conf or fstab.
set -eu
fail(){ printf 'FI C1 C220 BOOT INVENTORY STOP: %s\n' "$*" >&2; exit 1; }
[ "$#" -eq 1 ] && [ "$1" = --audit ] ||
    fail 'usage: sh script --audit'
[ "$(id -un)" = root ] && [ "$(hostname -s)" = c220 ] ||
    fail 'must run as root on physical C220'

for name in fi-receiver fi-ingest fi-sor; do
    expected=/fast/jails/roots/$name
    actual=$(jls -h jid name path | awk -v n="$name" '$2==n {print $3}')
    [ "$actual" = "$expected" ] || fail "$name jail path changed: $actual"
    [ -d "$actual" ] && [ ! -L "$actual" ] || fail "unsafe jail root: $actual"
done

echo '===== C220 THREE EXISTING JAILS ====='
jls -h jid name path | awk '$2=="fi-receiver"||$2=="fi-ingest"||$2=="fi-sor"{print}'
echo '===== HOST MOUNTS INTO THOSE JAILS (EXACT LIVE INVENTORY) ====='
# FreeBSD devfs is mounted by the jail lifecycle, NOT a nullfs entry.
# Require the physical C220 baseline of six nullfs + one devfs per jail.
mount -p | awk '
$2 ~ /^\/fast\/jails\/roots\/fi-(receiver|ingest|sor)\// {
    print
    n=split($2,parts,"/")
    jail=parts[5]
    if (jail!="fi-receiver" && jail!="fi-ingest" && jail!="fi-sor") bad=1
    if ($3=="nullfs") {
        if ($1=="" || ($4!="rw" && $4!="ro")) bad=1
        nullfs[jail]++
        nullfs_total++
    } else if ($3=="devfs") {
        if ($1!="devfs" || $2!="/fast/jails/roots/" jail "/dev" || $4!="rw") bad=1
        devfs[jail]++
        devfs_total++
    } else {
        bad=1
    }
}
END{
    printf "C1_EXISTING_FI_JAIL_MOUNT_COUNT=%d\n",nullfs_total+devfs_total
    printf "C1_EXISTING_FI_NULLFS_MOUNT_COUNT=%d\n",nullfs_total
    printf "C1_EXISTING_FI_DEVFS_MOUNT_COUNT=%d\n",devfs_total
    for (i=1;i<=3;i++) {
        jail=(i==1?"fi-receiver":i==2?"fi-ingest":"fi-sor")
        printf "C1_EXISTING_FI_JAIL_MOUNT_TYPES=%s nullfs=%d devfs=%d\n",jail,nullfs[jail],devfs[jail]
        if (nullfs[jail]!=6 || devfs[jail]!=1) bad=1
    }
    if (nullfs_total!=18 || devfs_total!=3 || bad) exit 1
}
' || fail 'unexpected original/C1 nullfs or devfs mount inventory; do not plan reboot yet'

echo '===== CANDIDATE JAIL NULLFS FSTAB FILES (devfs EXCLUDED; NOT WRITTEN) ====='
# Preserve every currently mounted PostgreSQL, custody, receiver,
# runtime config and C1 RAM nullfs view in their current source/target
# order. Never assume only the seven C1 additions need persistence.
for name in fi-receiver fi-ingest fi-sor; do
    root=/fast/jails/roots/$name
    printf 'C1_PROPOSED_FSTAB=/etc/jail.fstab.d/fi-c1-%s.fstab\n' "$name"
    mount -p | awk -v prefix="$root/" '
    index($2,prefix)==1 {
        if ($3=="devfs") {
            # devfs belongs to jail.conf mount.devfs, NEVER the fstab.
            if ($1!="devfs" || $2!=prefix "dev" || $4!="rw") bad=1
            devfs++
            next
        }
        if ($3!="nullfs" || $1=="" || ($4!="rw" && $4!="ro")) {
            bad=1
            next
        }
        print $1, $2, "nullfs", $4, "0 0"
        count++
    }
    END{
        printf "C1_PROPOSED_NULLFS_COUNT=%d C1_EXISTING_DEVFS_EXCLUDED=%d\\n",count,devfs > "/dev/stderr"
        if (count!=6 || devfs!=1 || bad) exit 1
    }
    ' || fail "cannot derive complete original + C1 fstab for $name"
done
echo '===== PROPOSED HOST FSTAB RAM ENTRY (NOT WRITTEN) ====='
echo 'tmpfs /var/run/fi-c1-handoff tmpfs rw,noauto,nosuid,noexec,size=4g,uid=4100,gid=4100,mode=0770 0 0'
echo '===== PROPOSED BOOT RC ORDER (NOT WRITTEN) ====='
echo 'fi_c1_ram: REQUIRE FILESYSTEMS; BEFORE jail; enabled only AFTER original jail mount persistence review'
echo 'Reboot persistence must not replace any original receiver, ingest or PostgreSQL mount.'

echo '===== HOST VOLATILE RAM MOUNT ====='
mount -p | awk '
$2=="/var/run/fi-c1-handoff" {
    print
    count++
    if ($3!="tmpfs") bad=1
}
END{if (count!=1 || bad) exit 1}
' || fail 'host tmpfs missing or changed'

echo '===== EXISTING JAIL CONFIGURATION MOUNT/STARTUP DIRECTIVES ====='
for name in fi-receiver fi-ingest fi-sor; do
    conf=/etc/jail.conf.d/$name.conf
    [ -f "$conf" ] && [ ! -L "$conf" ] ||
        fail "missing or unsafe physical jail config: $conf"
    printf '%s\n' "JAIL_CONF=$conf"
    if grep -nE '^[[:space:]]*(mount[.]fstab|mount[.]devfs|mount[.]procfs|exec[.]prestart|exec[.]poststart|exec[.]start|exec[.]stop|exec[.]poststop)[[:space:]]*=' "$conf"; then
        :
    else
        printf '%s\n' 'C1_JAIL_STARTUP_MOUNT_DIRECTIVES=NONE'
    fi
done

echo '===== EXISTING HOST FSTAB RAM TARGETS ====='
[ -f /etc/fstab ] && [ ! -L /etc/fstab ] ||
    fail 'system /etc/fstab missing or unsafe'
awk '
$0 ~ /^[[:space:]]*#/ {next}
NF>=2 && ($2=="/var/run/fi-c1-handoff" ||
           $2 ~ /^\/fast\/jails\/roots\/fi-(receiver|ingest|sor)\//) {
    print
    count++
}
END{printf "C1_BOOT_FSTAB_RELATED_EXISTING_LINES=%d\n",count}
' /etc/fstab

echo '===== HOST BOOT SERVICE AND ORDERING REFERENCES ====='
for path in \
    /usr/local/etc/rc.d/fi_c1_ram \
    /etc/rc.conf.d/fi_c1_ram \
    /etc/rc.conf.d/jail \
    /etc/rc.conf.d/zfs; do
    if [ -e "$path" ]; then
        [ -f "$path" ] && [ ! -L "$path" ] ||
            fail "unsafe boot configuration path: $path"
        stat -f 'C1_BOOT_FILE|%N|mode=%Sp|uid=%u|gid=%g|bytes=%z' "$path"
        if [ "$path" = /usr/local/etc/rc.d/fi_c1_ram ]; then
            grep -E '^# (PROVIDE|REQUIRE|BEFORE):' "$path" || :
        fi
    else
        printf 'C1_BOOT_FILE_ABSENT=%s\n' "$path"
    fi
done
if command -v rcorder >/dev/null 2>&1; then
    echo '===== BOOT ORDER: LIVE HOST RC FILES (FILTERED) ====='
    rcorder /etc/rc.d/* /usr/local/etc/rc.d/* 2>/dev/null |
        grep -E '/(zfs|mountcritlocal|mountcritremote|mountlate|jail|fi_c1_ram)$' || :
fi

echo '===== PRESERVE ORIGINAL ACCEPTED SOR ====='
jexec -U postgres fi-sor psql -X -w -At -v ON_ERROR_STOP=1 \
  -h /var/db/fi/sor/run -p 5432 -d fi <<'SQL'
BEGIN TRANSACTION READ ONLY;
SELECT 'C1_CANONICAL_GENERATIONS='||count(*) FROM fi.recorded_generation;
SELECT 'C1_PRIVATE_STAGE_ABSENT='||
    (to_regnamespace('fi_recovery_projection') IS NULL AND
     to_regnamespace('fi_recovery') IS NULL)::text;
COMMIT;
SQL

echo 'FI C1 C220 BOOT MOUNT INVENTORY COMPLETE read_only=true'
echo 'C1_BOOT_MOUNT_INSTALLATION=NOT_APPLIED'
echo 'C1_JAIL_RESTART=NOT_AUTHORIZED'
