#!/bin/sh
# Copyright (c) 2026 John Joseph Wood. All rights reserved.
# C220 FI receiver-authenticated batch cache ONLY. No service starts,
# receiver restarts, signed custody mutations, SQL writes or READY retirement.
# --audit checks exact prestate; --apply adds only restricted cache mounts
# and appends the two exact persistent jail nullfs entries.
set -eu
umask 077
fail(){ echo "FI C1 CACHE MOUNT STOP: $*" >&2; exit 1; }
check_mount(){
    mount -p | awk -v a="$1" -v b="$2" -v o="$3" '
        $2==b {
            seen++
            n=split($4,opts,",")
            for (i=1;i<=n;i++)if($1==a && $3=="nullfs" && opts[i]==o)ok++
        }
        END {exit !(seen==1 && ok==1)}
    '
}
mount_empty(){
    mount -p | awk -v target="$1" '$2==target{found++} END{exit !(found==0)}'
}
fstab_state(){
    f=$1
    line=$2
    [ -f "$f" ] && [ ! -L "$f" ] || fail "unsafe persistent fstab: $f"
    matches=$(grep -cF -x "$line" "$f" || :)
    case "$matches" in
        0)
            if grep -F 'verified-cache' "$f" >/dev/null; then
                fail "foreign cache mount already configured in $f"
            fi
            echo absent
            ;;
        1)
            if [ "$(grep -cF 'verified-cache' "$f" || :)" -ne 1 ]; then
                fail "duplicate/foreign cache lines in $f"
            fi
            echo present
            ;;
        *) fail "duplicate cache line in $f" ;;
    esac
}
check_parent(){
    [ -d "$1" ] && [ ! -L "$1" ] ||
        fail "missing or symlinked parent: $1"
}
check_source(){
    check_parent "$src"
    [ "$(stat -f %u "$src")" = "$ruid" ] ||
        fail "cache source owner UID differs from receiver service UID"
    [ "$(stat -f %g "$src")" = "$sgid" ] ||
        fail "cache source group differs from SoR GID"
    # FreeBSD stat %Lp reports only the low rwx permission bits.
    # SGID is a separate st_mode "middle" bit; never expect %Lp to
    # print 2750. Verify ordinary permissions AND SGID independently.
    mode=$(stat -f '%#Lp' "$src")
    [ "$mode" = 0750 ] ||
        fail "cache source permission bits must be 0750; found $mode"
    [ -g "$src" ] || fail 'cache source setgid bit missing'
    echo "FI_C1_CACHE_SOURCE_MODE=$(stat -f '%Sp' "$src") low=$mode setgid=true"
}
check_target(){
    target=$1
    check_parent "$(dirname "$target")"
    if [ -e "$target" ] || [ -L "$target" ]; then
        check_parent "$target"
        if mount_empty "$target"; then
            [ -z "$(ls -A "$target")" ] ||
                fail "unmounted cache target not empty: $target"
        fi
    fi
}
# Exercise the mount-options parser on synthetic rows before host audit.
fixture_match(){
    awk -v a="$1" -v b="$2" -v o="$3" '
        $2==b {
            seen++
            n=split($4,opts,",")
            for(i=1;i<=n;i++)if($1==a && $3=="nullfs" && opts[i]==o)ok++
        }
        END{exit !(seen==1 && ok==1)}
    '
}
if [ "$#" -eq 1 ] && [ "$1" = --selftest ];then
    ro='/work/cache /fast/jails/roots/fi-sor/var/db/fi/verified-cache nullfs ro,nosuid 0 0'
    printf '%s\n' "$ro" |
      fixture_match /work/cache /fast/jails/roots/fi-sor/var/db/fi/verified-cache ro ||
      fail 'correct RO cache mount was not accepted'
    if printf '%s\n' "$ro" |
      fixture_match /work/cache /fast/jails/roots/fi-sor/var/db/fi/verified-cache rw;then
      fail 'RO mount incorrectly accepted as RW'
    fi
    if printf '%s\n%s\n' "$ro" "$ro" |
      fixture_match /work/cache /fast/jails/roots/fi-sor/var/db/fi/verified-cache ro;then
      fail 'duplicate cache mounts incorrectly accepted'
    fi
    echo 'FI C1 CACHE MOUNT SELFTEST PASS ro=true rejects_rw=true rejects_duplicates=true'
    exit 0
fi
[ "$#" -eq 1 ] || fail 'usage: --audit | --apply'
case "$1" in --audit|--apply) mode=$1 ;; *) fail 'unknown mode' ;; esac
[ "$(id -u)" = 0 ] && [ "$(uname -s)" = FreeBSD ] &&
[ "$(hostname -s)" = c220 ] ||
    fail 'physical root@c220 FreeBSD required'

src=/work/fi-c220-20261114/custody/verified-cache
recv=/fast/jails/roots/fi-receiver/var/db/fi/verified-cache
sor=/fast/jails/roots/fi-sor/var/db/fi/verified-cache
recv_f=/etc/jail.fstab.d/fi-c1-fi-receiver.fstab
sor_f=/etc/jail.fstab.d/fi-c1-fi-sor.fstab
recv_line="$src $recv nullfs rw 0 0"
sor_line="$src $sor nullfs ro 0 0"
for j in fi-receiver fi-sor;do
    jls -j "$j" >/dev/null 2>&1 || fail "required jail missing $j"
done
if jls -j fi-ingest >/dev/null 2>&1;then
    fail 'obsolete fi-ingest jail is running'
fi
if jexec fi-sor service fi_c1_sor_local onestatus >/dev/null 2>&1 ||
   jexec fi-sor service fi_c1_sor onestatus >/dev/null 2>&1;then
    fail 'SoR C1 service is running; cache mount install requires disabled processing'
fi
check_parent /work/fi-c220-20261114/custody
check_parent /fast/jails/roots/fi-receiver/var/db/fi
check_parent /fast/jails/roots/fi-sor/var/db/fi

# Identity is read from the actual running jails, never guessed from old
# snapshots or from the independent fi-ingest user namespace.
ruid=$(jexec fi-receiver id -u fi-receiver) ||
    fail 'fi-receiver service identity missing'
suid=$(jexec fi-sor id -u fi-sor) ||
    fail 'fi-sor service identity missing'
sgid=$(jexec fi-sor id -g fi-sor) ||
    fail 'fi-sor service group missing'
sall=$(jexec fi-sor id -G fi-sor) ||
    fail 'cannot read fi-sor numeric group memberships'
case " $sall " in *" $sgid "*) ;; *)
    fail 'SoR user does not belong to its own primary group' ;;
esac
case "$ruid:$suid:$sgid" in
    *[!0123456789:]*|'') fail 'unsafe numeric user/group identity' ;;
esac
echo "FI_C1_CACHE_IDENTITIES receiver_uid=$ruid sor_uid=$suid reader_gid=$sgid"
echo "FI_C1_CACHE_SOURCE=$src"

if [ -e "$src" ] || [ -L "$src" ];then
    check_source
    source_state=present
else
    source_state=absent
fi
check_target "$recv"
check_target "$sor"
recv_live=absent
sor_live=absent
if check_mount "$src" "$recv" rw;then
    recv_live=present
elif ! mount_empty "$recv";then
    fail 'receiver cache mountpoint occupied by foreign/duplicate mount'
fi
if check_mount "$src" "$sor" ro;then
    sor_live=present
elif ! mount_empty "$sor";then
    fail 'SoR cache mountpoint occupied by foreign/duplicate mount'
fi
recv_persist=$(fstab_state "$recv_f" "$recv_line")
sor_persist=$(fstab_state "$sor_f" "$sor_line")
for jail_and_file in \
    "fi-receiver $recv_f" \
    "fi-sor $sor_f";do
    set -- $jail_and_file
    jconf=/etc/jail.conf.d/$1.conf
    check_parent /etc/jail.conf.d
    [ -f "$jconf" ] && [ ! -L "$jconf" ] &&
    grep -F "mount.fstab = \"$2\";" "$jconf" >/dev/null ||
        fail "jail fstab persistence is not wired: $jconf"
done
echo "FI_C1_CACHE_PREFLIGHT source=$source_state receiver_live=$recv_live sor_live=$sor_live receiver_fstab=$recv_persist sor_fstab=$sor_persist"
if [ "$mode" = --audit ];then
    echo 'FI C1 CACHE MOUNT AUDIT COMPLETE read_only=true'
    exit 0
fi

# Install the new trusted cache root only when the full prestate matched.
# Chown before chmod: chmod must set setgid after final ownership is known.
if [ "$source_state" = absent ];then
    install -d -o "$ruid" -g "$sgid" -m 0750 "$src" ||
        fail 'cannot create receiver-owned restricted cache source'
    chown "$ruid:$sgid" "$src" ||
        fail 'cannot set cache ownership'
    chmod 2750 "$src" ||
        fail 'cannot set restricted setgid cache permissions'
fi
check_source
for d in "$recv" "$sor";do
    if [ ! -d "$d" ];then
        install -d -o root -g wheel -m 0755 "$d" ||
            fail "cannot create empty jail cache mountpoint $d"
    fi
done
if [ "$recv_live" = absent ];then
    mount -t nullfs -o rw "$src" "$recv" ||
        fail 'receiver writable cache nullfs mount failed'
fi
check_mount "$src" "$recv" rw || fail 'receiver rw mount verification failed'
if [ "$sor_live" = absent ];then
    mount -t nullfs -o ro "$src" "$sor" ||
        fail 'SoR readonly cache nullfs mount failed'
fi
check_mount "$src" "$sor" ro || fail 'SoR ro mount verification failed'
jexec -U fi-receiver fi-receiver test -w /var/db/fi/verified-cache ||
    fail 'receiver service user cannot write its cache'
jexec -U fi-sor fi-sor test -r /var/db/fi/verified-cache ||
    fail 'SoR service user cannot read cache'
# Access(W_OK) on nullfs may report owner permissions even for a read-only
# mount. Authoritative write isolation is the exact source+nullfs+ro mount
# verified above. Do not attempt a write probe into receiver-owned custody.

# Append persistent mounts atomically. Preserve the complete existing
# jail fstab; do not modify any existing signed custody, PostgreSQL or
# Pathfinder entries. Never restart the jails as a side effect.
backup=$(mktemp -d /var/backups/fi-c1-receiver-cache.XXXXXXXX) ||
    fail 'cannot allocate original fstab backup directory'
chmod 0700 "$backup"
cp -p "$recv_f" "$backup/fi-c1-fi-receiver.fstab"
cp -p "$sor_f" "$backup/fi-c1-fi-sor.fstab"
for f in "$recv_f" "$sor_f";do
    case "$f" in
        "$recv_f") wanted=$recv_line; state=$recv_persist ;;
        "$sor_f") wanted=$sor_line; state=$sor_persist ;;
    esac
    if [ "$state" = absent ];then
        tmp=$(mktemp "$f.c1-cache.XXXXXXXX") || fail 'cannot allocate fstab temp'
        cp -p "$f" "$tmp" || fail 'cannot copy fstab'
        printf '%s\n' "$wanted" >> "$tmp" || fail 'cannot append fstab'
        mv "$tmp" "$f" || fail 'cannot atomically publish fstab'
    fi
    [ "$(grep -cF -x "$wanted" "$f" || :)" -eq 1 ] ||
        fail "persistent cache mount failed verification: $f"
done
echo "FI_C1_CACHE_FSTAB_BACKUP=$backup"
echo 'FI C1 CACHE MOUNT APPLY PASS receiver_rw=true sor_ro=true reboot_persistent=true postgres_untouched=true signed_custody_untouched=true fi_ingest_unused=true services_started=false'
