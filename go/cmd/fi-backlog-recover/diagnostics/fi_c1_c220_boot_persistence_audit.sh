#!/bin/sh
# C220 C1 reboot/restart persistence prerequisite.
# READ ONLY. Captures COMPLETE original FI nullfs mount inventory
# before any permanent fstab is installed. PostgreSQL PGDATA and
# receiver custody are currently independently mounted.
set -eu
fail(){ printf 'FI C1 C220 BOOT AUDIT STOP: %s\n' "$*" >&2; exit 1; }
[ "$#" -eq 1 ] && [ "$1" = --audit ] ||
    fail 'usage: sh script --audit'
[ "$(id -un)" = root ] && [ "$(hostname -s)" = c220 ] ||
    fail 'physical C220 root required'
for pair in 'fi-sor /fast/jails/roots/fi-sor' \
            'fi-ingest /fast/jails/roots/fi-ingest' \
            'fi-receiver /fast/jails/roots/fi-receiver'; do
    name=$(printf '%s\n' "$pair" | awk '{print $1}')
    root=$(printf '%s\n' "$pair" | awk '{print $2}')
    actual=$(jls -h jid name path | awk -v j="$name" '$2==j {print $3}')
    [ "$actual" = "$root" ] ||
        fail "running original FI jail root unexpected: $name"
done
if jls -j fi-sor-db jid >/dev/null 2>&1; then
    fail 'physical C220 fi-sor-db duplicate jail exists'
fi
echo '===== RUNNING FI JAILS AND ROOTS ====='
jls -h jid name path |
    awk '$2=="fi-sor" || $2=="fi-ingest" || $2=="fi-receiver" || $2=="fi-dev" {print}'
echo '===== ALL EXISTING FI NULLFS AND TMPFS HOST MOUNTS ====='
# Do not abbreviate: losing original custody or PGDATA on restart is
# unacceptable. This reads mount table but never changes it.
mount -p | awk '$2=="/var/run/fi-c1-handoff" ||
    $2 ~ /^\/fast\/jails\/roots\/fi-(sor|ingest|receiver|dev)\// {
    print
}' || fail 'cannot list live FI mounts'
echo '===== EXISTING FI JAIL CONF MOUNT/STARTUP HOOKS ====='
for name in fi-sor fi-ingest fi-receiver fi-dev; do
    file=/etc/jail.conf.d/$name.conf
    printf 'JAIL_CONFIG=%s\n' "$file"
    if [ ! -f "$file" ]; then
        echo 'JAIL_CONFIG_ABSENT'
        continue
    fi
    [ ! -L "$file" ] || fail "symlinked jail config: $file"
    # Display only mount and startup references.
    grep -nE '(mount[.]fstab|mount[.]devfs|mount[.]fdescfs|exec[.]prestart|exec[.]poststart|exec[.]prestop|exec[.]poststop|path[[:space:]]*=|depend[[:space:]]*=)' "$file" || :
done
echo '===== HOST FILESYSTEM / JAIL STARTUP CONFIG ====='
for file in /etc/fstab /etc/rc.conf /etc/rc.conf.d/jail \
            /etc/rc.conf.d/fi_c1_ram; do
    if [ -f "$file" ]; then
        printf 'CONFIG_PRESENT=%s\n' "$file"
        if [ "$file" = /etc/fstab ]; then
            grep -vE '^[[:space:]]*(#|$)' "$file" || :
        else
            grep -nE '^[[:space:]]*(jail_enable|jail_list|jail_parallel_start|fi_c1_ram_enable|mountd_enable)=' "$file" || :
        fi
    else
        printf 'CONFIG_ABSENT=%s\n' "$file"
    fi
done
echo '===== EXISTING FI FSTAB FILES ====='
for file in \
    /etc/jail.fstab.d/fi-ingest.fstab \
    /etc/jail.fstab.d/fi-sor.fstab \
    /etc/jail.fstab.d/fi-receiver.fstab \
    /etc/jail.fstab.d/fi-c1-fi-ingest.fstab \
    /etc/jail.fstab.d/fi-c1-fi-sor.fstab; do
    if [ -e "$file" ]; then
        [ -f "$file" ] && [ ! -L "$file" ] ||
            fail "unexpected fstab target: $file"
        printf 'JAIL_FSTAB_PRESENT=%s\n' "$file"
        grep -vE '^[[:space:]]*(#|$)' "$file" || :
    else
        printf 'JAIL_FSTAB_ABSENT=%s\n' "$file"
    fi
done
echo '===== EXISTING BOOT MOUNT PROVIDER FILE PATHS (NO CONTENT) ====='
for dir in /usr/local/etc/rc.d /usr/local/sbin /usr/local/libexec \
           /etc/rc.d /etc/rc.conf.d; do
    if [ -d "$dir" ]; then
        grep -RIlE 'fi-c220-20261114|/fast/data/fi/sor/pgdata|/work/fi-c220-20261114/custody|fi-c1-handoff' \
            "$dir" 2>/dev/null || :
    fi
done
echo '===== C1 LIVE ONLY FLAG ====='
echo 'C1_HOST_RAM_REBOOT_PERSISTENT=UNVERIFIED'
echo 'C1_EXISTING_FI_PGDATA_CUSTODY_RESTART_PERSISTENCE=UNVERIFIED'
echo 'C1_JAIL_RESTART_ALLOWED=false'
echo 'FI C1 C220 BOOT PERSISTENCE AUDIT COMPLETE read_only=true no_restart=true'
