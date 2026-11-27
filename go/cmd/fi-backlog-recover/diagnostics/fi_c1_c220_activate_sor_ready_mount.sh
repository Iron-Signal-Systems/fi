#!/bin/sh
# FI C1 physical FreeBSD C220. Retire the stopped obsolete fi-ingest
# from the host jail boot list, add ONLY the original receiver READY
# scheduling nullfs mount (RW) to fi-sor and its existing persistent
# jail fstab. Never removes signed custody, changes PG, or starts C1.
# --audit is read-only. --apply requires strict current-state matching.
set -eu
umask 077
fail(){ printf 'FI C1 SOR READY MOUNT STOP: %s\n' "$*" >&2; exit 1; }
# Exercise the EXACT mount-options matcher in CI and on C220 before audit.
# A malformed awk expression must never masquerade as a failed custody check.
mount_options_match() {
    awk -v source="$1" -v target="$2" -v access="$3" '
        $2 == target {
            count++
            n = split($4, options, ",")
            for (i = 1; i <= n; i++) {
                if ($1 == source && $3 == "nullfs" && options[i] == access) {
                    matched++
                }
            }
        }
        END { exit !(count == 1 && matched == 1) }
    '
}
check_mount() {
    mount -p | mount_options_match "$1" "$2" "$3"
}
selftest_mount_matcher() {
    good_ro="/work/custody /fast/jails/roots/fi-sor/custody nullfs ro,nosuid 0 0"
    good_rw="/work/ready /fast/jails/roots/fi-sor/ready nullfs rw 0 0"
    printf '%s\n' "$good_ro" |
        mount_options_match /work/custody /fast/jails/roots/fi-sor/custody ro ||
        fail 'RO match failed in synthetic mount fixture'
    printf '%s\n' "$good_rw" |
        mount_options_match /work/ready /fast/jails/roots/fi-sor/ready rw ||
        fail 'RW match failed in synthetic mount fixture'
    if printf '%s\n' "$good_ro" |
        mount_options_match /work/custody /fast/jails/roots/fi-sor/custody rw; then
        fail 'RW was incorrectly authorized on RO custody fixture'
    fi
    if printf '%s\n' "$good_rw" |
        mount_options_match /work/wrong /fast/jails/roots/fi-sor/ready rw; then
        fail 'foreign original receiver READY source was accepted'
    fi
    if printf '%s\n%s\n' "$good_ro" "$good_ro" |
        mount_options_match /work/custody /fast/jails/roots/fi-sor/custody ro; then
        fail 'duplicate mount rows were accepted'
    fi
    printf 'FI C1 SOR READY MOUNT MATCHER SELFTEST PASS ro=true rw=true rejects_bad_access=true rejects_foreign_source=true rejects_duplicate=true\\n'
}
[ "$#" -eq 1 ] || fail 'usage: --selftest | --audit | --apply'
case "$1" in
    --selftest) selftest_mount_matcher; exit 0 ;;
    --audit|--apply) mode=$1 ;;
    *) fail 'unknown action' ;;
esac
[ "$(id -u)" -eq 0 ] && [ "$(uname -s)" = FreeBSD ] &&
    [ "$(hostname -s)" = c220 ] ||
    fail 'physical C220 FreeBSD host root required'

sor=/fast/jails/roots/fi-sor
receiver=/fast/jails/roots/fi-receiver
host_root=/work/fi-c220-20261114
src=$host_root/custody/ready
dst=$sor/var/db/fi/custody/ready
gen=$host_root/custody/generation
recorded=$host_root/custody/recorded
fstab=/etc/jail.fstab.d/fi-c1-fi-sor.fstab
jailconf=/etc/jail.conf.d/fi-sor.conf
rc=/etc/rc.conf
ready_line="$src $dst nullfs rw 0 0"
cache_src=$host_root/custody/verified-cache
cache_line="$cache_src $sor/var/db/fi/verified-cache nullfs ro 0 0"
[ -d "$cache_src" ] && [ ! -L "$cache_src" ] ||
    fail 'receiver-owned verified cache source missing'
check_mount "$cache_src" "$receiver/var/db/fi/verified-cache" rw ||
    fail 'receiver authenticated batch cache must be mounted RW'
check_mount "$cache_src" "$sor/var/db/fi/verified-cache" ro ||
    fail 'fi-sor authenticated batch cache must be mounted RO'


[ -d "$sor" ] && [ -d "$receiver" ] &&
    [ -d "$src" ] && [ ! -L "$src" ] &&
    [ -d "$gen" ] && [ ! -L "$gen" ] &&
    [ -d "$recorded" ] && [ ! -L "$recorded" ] ||
    fail 'actual original C220 receiver jail and custody directories changed'
jls -j fi-sor >/dev/null 2>&1 &&
    jls -j fi-receiver >/dev/null 2>&1 ||
    fail 'fi-sor and fi-receiver must both be running'
if jls -j fi-ingest >/dev/null 2>&1;then
    fail 'fi-ingest jail is running again; stop it before changing configuration'
fi
jexec fi-sor /usr/sbin/service fi_c1_sor onestatus >/dev/null 2>&1 &&
    fail 'old inter-jail C1 service is still running'
jexec fi-sor /usr/sbin/service fi_c1_sor_local onestatus >/dev/null 2>&1 &&
    fail 'single-jail C1 service is already running'
# The inactive service is staged and disabled; NO intake will start.
sorconf=$sor/etc/rc.conf.d/fi_c1_sor_local
[ -f "$sorconf" ] && [ ! -L "$sorconf" ] &&
    grep -Fx 'fi_c1_sor_local_enable="NO"' "$sorconf" >/dev/null ||
    fail 'single-jail worker is missing or not disabled'

for f in "$fstab" "$jailconf" "$rc";do
    [ -f "$f" ] && [ ! -L "$f" ] ||
        fail "missing or symlinked host configuration: $f"
done
[ "$(grep -c '^[[:space:]]*mount[.]fstab[[:space:]]*=' "$jailconf" || :)" -eq 1 ] &&
    grep -F 'mount.fstab = "/etc/jail.fstab.d/fi-c1-fi-sor.fstab";' "$jailconf" >/dev/null ||
    fail 'fi-sor jail config does not use expected persistent C1 fstab'
# Prevent duplicate READY mounts hidden in jail.conf mount+=.
if grep -F "$src" "$jailconf" >/dev/null;then
    fail 'fi-sor jail.conf already contains an original READY mount directive'
fi
expected_fstab=$(cat <<'EOF'
/fast/data/fi/sor/pgdata /fast/jails/roots/fi-sor/var/db/fi/sor/postgres nullfs rw 0 0
/var/run/fi-c1-handoff /fast/jails/roots/fi-sor/var/run/fi-c1-handoff nullfs ro 0 0
/work/fi-c220-20261114/custody/generation /fast/jails/roots/fi-sor/var/db/fi/custody/generation nullfs ro 0 0
/work/fi-c220-20261114/custody/recorded /fast/jails/roots/fi-sor/var/db/fi/custody/recorded nullfs ro 0 0
/work/fi-c220-20261114/config/receiver/pki/trust /fast/jails/roots/fi-sor/usr/local/etc/fi/pki/trust nullfs ro 0 0
/work/fi-c220-20261114/config/receiver/sources /fast/jails/roots/fi-sor/usr/local/etc/fi/sources nullfs ro 0 0
EOF
)
# The authenticated batch-cache installation added one persisted
# nullfs RO entry after the previous six-mount C220 baseline. Refuse
# to undo, cover or reorder it during the READY scheduling cutover.
current_fstab=$(cat "$fstab")
case "$current_fstab" in
    "$expected_fstab
$cache_line") persistence=absent ;;
    "$expected_fstab
$cache_line
$ready_line") persistence=present ;;
    *) fail 'fi-sor fstab differs from known six mounts plus signed receiver-cache RO; review before apply' ;;
esac
# The existing fi-sor signed generation + receipt mounts MUST remain RO.
for pair in "$gen $sor/var/db/fi/custody/generation" \
            "$recorded $sor/var/db/fi/custody/recorded";do
    set -- $pair
    check_mount "$1" "$2" ro ||
        fail "original signed receiver custody mount lost read-only protection: $2"
done
# The source must be backed by the original work ZFS pool.
mount -p | awk '
    $2=="/work" && $3=="zfs" {n++}
    END {exit !(n==1)}' ||
    fail 'original work ZFS pool no longer mounted at /work'

# The single jail boot list was proven to end in fi-ingest on 2026-11-25.
# Other workloads (911? Pathfinder, other FI services) remain unchanged.
list_count=$(grep -Ec '^jail_list=' "$rc" || :)
[ "$list_count" -eq 1 ] ||
    fail 'host rc.conf must have one unambiguous jail_list assignment'
original_list='jail_list="net-core pathfinder-ingest pathfinder-sor dev-pathfinder pathfinder-frontend cyber-work fi-sor fi-dev fi-frontend fi-receiver fi-ingest"'
new_list='jail_list="net-core pathfinder-ingest pathfinder-sor dev-pathfinder pathfinder-frontend cyber-work fi-sor fi-dev fi-frontend fi-receiver"'
if grep -Fx "$original_list" "$rc" >/dev/null;then
    boot=needs_retirement
elif grep -Fx "$new_list" "$rc" >/dev/null;then
    boot=retired
else
    fail 'jail_list differs from actual C220 observed inventory; do not edit other jails'
fi

# Exactly zero or one READY nullfs mounts; never cover a foreign mount.
if check_mount "$src" "$dst" rw;then
    live=present
elif mount -p | awk -v b="$dst" '$2==b{n++}END{exit !(n==0)}';then
    live=absent
else
    fail 'READY destination occupied by unexpected or duplicate mount'
fi
[ -d "$sor/var/db/fi/custody" ] &&
    [ ! -L "$sor/var/db/fi/custody" ] ||
    fail 'fi-sor original custody parent is unsafe'
if [ -e "$dst" ] || [ -L "$dst" ];then
    [ -d "$dst" ] && [ ! -L "$dst" ] ||
        fail 'fi-sor READY mountpoint is not a real directory'
    if [ "$live" = absent ] && [ -n "$(ls -A "$dst")" ];then
        fail 'unmounted fi-sor READY directory contains data; never cover it'
    fi
else
    [ "$live" = absent ] ||
        fail 'mounted READY missing directory'
fi

echo "C1_SOR_READY_PREFLIGHT live=$live persistent=$persistence fi_ingest_boot=$boot original_signed_custody=RO receiver_ready_original_unchanged=true"
if [ "$mode" = --audit ];then
    echo 'FI C1 SOR READY AUDIT COMPLETE read_only=true no_changes=true'
    exit 0
fi

# All source, jail, boot-list, and fstab invariants have passed.
backup=$(mktemp -d /var/backups/fi-c1-sor-ready.XXXXXXXX) ||
    fail 'cannot create original configuration backup directory'
chmod 0700 "$backup"
cp -p "$fstab" "$backup/fi-c1-fi-sor.fstab" ||
    fail 'cannot back up fi-sor persistent mount table'
cp -p "$rc" "$backup/rc.conf" ||
    fail 'cannot back up host jail boot list'
echo "ORIGINAL_HOST_CONFIG_BACKUPS=$backup"

if [ ! -d "$dst" ];then
    install -d -o root -g wheel -m 0755 "$dst" ||
        fail 'cannot create empty fi-sor READY mountpoint'
fi
if [ "$live" = absent ];then
    mount -t nullfs -o rw "$src" "$dst" ||
        fail 'live scheduling READY nullfs mount failed; no boot changes made'
fi
check_mount "$src" "$dst" rw ||
    fail 'live scheduling READY nullfs did not verify; no boot changes made'
jexec -U fi-sor fi-sor /bin/test -r /var/db/fi/custody/ready &&
jexec -U fi-sor fi-sor /bin/test -w /var/db/fi/custody/ready ||
    fail 'unprivileged fi-sor cannot read/write original READY scheduling directory; leave workers disabled'
if [ "$persistence" = absent ];then
    temp=$(mktemp /etc/jail.fstab.d/.fi-c1-sor-ready.XXXXXXXX) ||
        fail 'cannot prepare atomic persistent READY fstab'
    cat "$fstab" > "$temp"
    printf '%s\n' "$ready_line" >> "$temp"
    chown "$(stat -f '%u:%g' "$fstab")" "$temp"
    chmod "0$(stat -f '%Lp' "$fstab")" "$temp"
    cmp -s "$fstab" "$backup/fi-c1-fi-sor.fstab" ||
        fail 'fstab changed concurrently before replacement'
    mv -f "$temp" "$fstab" ||
        fail 'cannot publish persistent READY fstab'
fi
if [ "$boot" = needs_retirement ];then
    temp=$(mktemp /etc/.fi-c1-retire-ingest.XXXXXXXX) ||
        fail 'cannot prepare atomic jail boot-list change'
    awk -v old="$original_list" -v new="$new_list" '
        $0==old {print new;next}
        {print}
    ' "$rc" > "$temp"
    chown "$(stat -f '%u:%g' "$rc")" "$temp"
    chmod "0$(stat -f '%Lp' "$rc")" "$temp"
    cmp -s "$rc" "$backup/rc.conf" ||
        fail 'rc.conf changed concurrently before replacement'
    mv -f "$temp" "$rc" ||
        fail 'cannot publish retired fi-ingest boot list'
fi
[ "$(cat "$fstab")" = "$expected_fstab
$cache_line
$ready_line" ] ||
    fail 'persistent READY fstab postcheck failed'
grep -Fx "$new_list" "$rc" >/dev/null ||
    fail 'obsolete fi-ingest boot retirement postcheck failed'
jls -j fi-ingest >/dev/null 2>&1 &&
    fail 'obsolete ingest jail restarted during the operation'
[ -d "$gen" ] && [ -d "$recorded" ] ||
    fail 'original receiver signed custody disappeared'
echo 'FI C1 SOR READY MOUNT PASS live_rw=true reboot_persistent=true fi_ingest_not_in_boot_list=true original_signed_custody_ro=true original_custody_preserved=true c1_not_started=true postgres_untouched=true'
echo "RESTORE_REFERENCE=$backup"
