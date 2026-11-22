#!/bin/sh
# Read-only C220 boot configuration acceptance. Run after the guarded
# persistent installer, before ANY jail restart or reboot.
set -eu
fail(){ echo "FI C1 C220 BOOT VERIFY STOP: $*" >&2; exit 1; }
[ "$#" = 1 ] && [ "$1" = --verify ] ||
    fail 'usage: sh script --verify'
[ "$(id -un)" = root ] && [ "$(hostname -s)" = c220 ] ||
    fail 'physical C220 root required'
persist=/var/tmp/fi_c1_c220_persist_boot.sh
[ -f "$persist" ] && [ ! -L "$persist" ] ||
    fail 'exact C220 persistent installer source missing'
sh "$persist" --audit ||
    fail 'original 18 live nullfs mounts or boot candidate configuration changed'
for jail in fi-receiver fi-ingest fi-sor; do
    fstab=/etc/jail.fstab.d/fi-c1-$jail.fstab
    jailconf=/etc/jail.conf.d/$jail.conf
    [ -f "$fstab" ] && [ ! -L "$fstab" ] ||
        fail "missing installed jail fstab $fstab"
    [ "$(awk '$3=="nullfs" {n++} END{print n+0}' "$fstab")" = 6 ] ||
        fail "jail fstab has wrong nullfs count: $jail"
    [ "$(grep -Ec '^[[:space:]]*mount[.]fstab[[:space:]]*=' "$jailconf")" = 1 ] ||
        fail "jail.conf does not reference exactly one mount.fstab: $jail"
    [ "$(grep -Ec '^[[:space:]]*mount[.]devfs[[:space:]]*;' "$jailconf")" = 1 ] ||
        fail "original jail devfs no longer configured: $jail"
done
[ -f /etc/jail.conf ] && [ ! -L /etc/jail.conf ] ||
    fail 'original aggregate jail.conf missing or unsafe'
# -e is the read-only FreeBSD jail parameter exhibition operation.
# It parses the entire aggregate jail configuration; unlike -c/-m/-r,
# it does not create, modify, restart or remove a jail.
jail_parameters=$(jail -f /etc/jail.conf -e '|') ||
    fail 'actual FreeBSD jail configuration failed parse/read-only exhibition'
# The effective aggregate config must include the exact fstab for ALL
# three running FI jails; merely validating individual fragment files
# would not detect a missing include in the host jail.conf.
for jailname in fi-receiver fi-ingest fi-sor; do
    printf '%s\n' "$jail_parameters" | grep -F \
      "/etc/jail.fstab.d/fi-c1-$jailname.fstab" >/dev/null ||
        fail "effective jail config omits persistent nullfs mounts for $jailname"
done
[ -f /usr/local/etc/rc.d/fi_c1_ram ] &&
[ -f /etc/rc.conf.d/fi_c1_ram ] &&
[ "$(cat /etc/rc.conf.d/fi_c1_ram)" = 'fi_c1_ram_enable="YES"' ] ||
    fail 'host C1 RAM prerequisite service is not installed/enabled'

# Native rcorder must place the C1 RAM source AFTER the ZFS/FILESYSTEMS
# milestones and BEFORE any automatic jail startup.
ordered=$(rcorder /etc/rc.d/* /usr/local/etc/rc.d/*) ||
    fail 'native rcorder rejected host startup dependencies'
line_number(){
    printf '%s\n' "$ordered" | awk -v p="$1" '$0==p {print NR}'
}
zfs=$(line_number /etc/rc.d/zfs)
fs=$(line_number /etc/rc.d/mountcritlocal)
ram=$(line_number /usr/local/etc/rc.d/fi_c1_ram)
jail=$(line_number /etc/rc.d/jail)
[ -n "$zfs" ] && [ -n "$fs" ] && [ -n "$ram" ] && [ -n "$jail" ] ||
    fail 'zfs/filesystems/C1 RAM/jail order lacks one or more required rc scripts'
[ "$zfs" -lt "$ram" ] && [ "$fs" -lt "$ram" ] && [ "$ram" -lt "$jail" ] ||
    fail "invalid startup order zfs=$zfs fs=$fs ram=$ram jail=$jail"
printf 'C1_C220_RCORDER_PASS zfs=%s filesystems=%s c1_ram=%s jail=%s\n' \
    "$zfs" "$fs" "$ram" "$jail"
echo 'FI C1 C220 BOOT CONFIG VERIFIED live_mounts_unchanged=true original_pgdata_preserved=true original_custody_preserved=true'
echo 'FI C1 REBOOT/RESTART NOT AUTHORIZED until controlled restart/recovery test and C1 canonical ingestion acceptance'
