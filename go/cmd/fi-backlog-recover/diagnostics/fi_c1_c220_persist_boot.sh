#!/bin/sh
# C220-only exact original + C1 boot configuration. Never restarts jails,
# mounts filesystems, changes PostgreSQL, or enables C1 ingestion workers.
set -eu
umask 077
die(){ echo "C1 C220 PERSIST BOOT STOP: $*" >&2; exit 1; }
[ "$#" = 1 ] || die 'usage: script --audit | --apply'
case "$1" in --audit|--apply) mode=$1;; *) die 'invalid mode';; esac
[ "$(id -un)" = root ] && [ "$(hostname -s)" = c220 ] || die 'physical C220 root required'
hostfstab='tmpfs /var/run/fi-c1-handoff tmpfs rw,noauto,nosuid,noexec,size=4g,uid=4100,gid=4100,mode=0770 0 0'
mounts(){
case "$1" in
fi-receiver) cat <<'E'
/work/fi-c220-20261114/config/receiver /fast/jails/roots/fi-receiver/var/db/fi/config/receiver nullfs ro 0 0
/work/fi-c220-20261114/config/receiver /fast/jails/roots/fi-receiver/usr/local/etc/fi nullfs ro 0 0
/work/fi-c220-20261114/custody/generation /fast/jails/roots/fi-receiver/var/db/fi/custody/generation nullfs rw 0 0
/work/fi-c220-20261114/custody/transport /fast/jails/roots/fi-receiver/var/db/fi/custody/transport nullfs rw 0 0
/work/fi-c220-20261114/custody/ready /fast/jails/roots/fi-receiver/var/db/fi/custody/ready nullfs rw 0 0
/work/fi-c220-20261114/custody/recorded /fast/jails/roots/fi-receiver/var/db/fi/custody/recorded nullfs rw 0 0
E
;;
fi-ingest) cat <<'E'
/work/fi-c220-20261114/ingest-config /fast/jails/roots/fi-ingest/usr/local/etc/fi nullfs ro 0 0
/work/fi-c220-20261114/custody/generation /fast/jails/roots/fi-ingest/var/db/fi/custody/generation nullfs ro 0 0
/work/fi-c220-20261114/custody/recorded /fast/jails/roots/fi-ingest/var/db/fi/custody/recorded nullfs ro 0 0
/work/fi-c220-20261114/custody/ready /fast/jails/roots/fi-ingest/var/db/fi/custody/ready nullfs rw 0 0
/work/fi-c220-20261114/config/receiver/pki/trust /fast/jails/roots/fi-ingest/usr/local/etc/fi/pki/trust nullfs ro 0 0
/var/run/fi-c1-handoff /fast/jails/roots/fi-ingest/var/run/fi-c1-handoff nullfs rw 0 0
E
;;
fi-sor) cat <<'E'
/fast/data/fi/sor/pgdata /fast/jails/roots/fi-sor/var/db/fi/sor/postgres nullfs rw 0 0
/var/run/fi-c1-handoff /fast/jails/roots/fi-sor/var/run/fi-c1-handoff nullfs ro 0 0
/work/fi-c220-20261114/custody/generation /fast/jails/roots/fi-sor/var/db/fi/custody/generation nullfs ro 0 0
/work/fi-c220-20261114/custody/recorded /fast/jails/roots/fi-sor/var/db/fi/custody/recorded nullfs ro 0 0
/work/fi-c220-20261114/config/receiver/pki/trust /fast/jails/roots/fi-sor/usr/local/etc/fi/pki/trust nullfs ro 0 0
/work/fi-c220-20261114/config/receiver/sources /fast/jails/roots/fi-sor/usr/local/etc/fi/sources nullfs ro 0 0
E
;;
*) die 'unexpected FI jail' ;;
esac
}
ramrc(){
cat <<'RC'
#!/bin/sh
# PROVIDE: fi_c1_ram
# REQUIRE: FILESYSTEMS
# BEFORE: jail
. /etc/rc.subr
name="fi_c1_ram"
rcvar="fi_c1_ram_enable"
load_rc_config "$name"
: ${fi_c1_ram_enable:="NO"}
start_cmd="ram_start"
stop_cmd="ram_stop"
ram_start()
{
    p=/var/run/fi-c1-handoff
    # Never mount over a foreign filesystem or a nonempty directory.
    if /sbin/mount -p | /usr/bin/awk -v p="$p" '
        $2==p {
            n++
            if($1!="tmpfs" || $3!="tmpfs")bad=1
            k=split($4,flags,",")
            for(i=1;i<=k;i++){if(flags[i]=="noexec")nx=1;if(flags[i]=="nosuid")ns=1}
        }
        END{exit !(n==1&&!bad&&nx&&ns)}
    '; then
        [ "$(stat -f '%u:%g:%Lp' "$p")" = '4100:4100:770' ] || {
            echo "FI C1: host RAM identity/mode wrong" >&2
            return 1
        }
        return 0
    fi
    if /sbin/mount -p | /usr/bin/awk -v p="$p" '$2==p{n++}END{exit !(n>0)}'; then
        echo "FI C1: foreign host mount at $p" >&2
        return 1
    fi
    # A bare underlay directory is NOT proof that work/fast ZFS is mounted.
    for pool in /fast /work; do
        /sbin/mount -p | /usr/bin/awk -v p="$pool" \
          '$2==p&&$3=="zfs"{n++}END{exit !(n==1)}' || {
            echo "FI C1: required original ZFS pool is not mounted at $pool" >&2
            return 1
        }
    done
    for source in /fast/data/fi/sor/pgdata \
       /work/fi-c220-20261114/custody/generation \
       /work/fi-c220-20261114/custody/recorded \
       /work/fi-c220-20261114/config/receiver/pki/trust \
       /work/fi-c220-20261114/config/receiver/sources; do
        [ -d "$source" ] && [ ! -L "$source" ] || return 1
    done
    [ ! -L "$p" ] && { [ ! -e "$p" ] || [ -d "$p" ]; } || return 1
    if [ -d "$p" ] && [ -n "$(/bin/ls -A "$p")" ]; then
        echo "FI C1: host RAM source is nonempty" >&2
        return 1
    fi
    /usr/bin/install -d -o 4100 -g 4100 -m 0770 "$p" || return 1
    /sbin/mount "$p" || return 1
    [ "$(stat -f '%u:%g:%Lp' "$p")" = '4100:4100:770' ] || {
        echo "FI C1: mounted tmpfs identity/mode unexpected" >&2
        return 1
    }
    /sbin/mount -p | /usr/bin/awk -v p="$p" '
       $1=="tmpfs"&&$2==p&&$3=="tmpfs"{
          n=split($4,a,",");for(i=1;i<=n;i++){
             if(a[i]=="noexec")nx=1
             if(a[i]=="nosuid")ns=1
          }
          ok=1
       }
       END{exit !(ok&&nx&&ns)}
    '
}
ram_stop()
{
    # Deliberately no automatic unmount of a RAM filesystem used by jails.
    :
}
run_rc_command "$1"
RC
}
# Confirm original work and fast are mounted ZFS filesystems.
for pool in /fast /work; do
    mount -p | awk -v p="$pool" '$2==p&&$3=="zfs"{n++}END{exit !(n==1)}' ||
        die "original ZFS pool not mounted: $pool"
done
# Fail before altering anything if live mounts or config changed from
# the accepted physical 2026-11-22 C220 inventory.
for jail in fi-receiver fi-ingest fi-sor; do
    root=/fast/jails/roots/$jail
    [ "$(jls -h jid name path | awk -v n="$jail" '$2==n{print $3}')" = "$root" ] ||
        die "unexpected running jail root: $jail"
    [ -f "/etc/jail.conf.d/$jail.conf" ] && [ ! -L "/etc/jail.conf.d/$jail.conf" ] ||
        die "unsafe jail configuration: $jail"
    grep -F "path = \"$root\";" "/etc/jail.conf.d/$jail.conf" >/dev/null ||
        die "jail path config drift: $jail"
    [ "$(grep -Ec '^[[:space:]]*mount[.]devfs[[:space:]]*;' "/etc/jail.conf.d/$jail.conf")" = 1 ] ||
        die "devfs configuration drift: $jail"
    mounts "$jail" | while read -r src dest typ opts zeroa zerob; do
        [ "$typ:$zeroa:$zerob" = nullfs:0:0 ] && [ -d "$src" ] && [ -d "$dest" ] && [ ! -L "$src" ] && [ ! -L "$dest" ] ||
            die "invalid original source or destination: $dest"
        mount -p | awk -v s="$src" -v d="$dest" -v o="$opts" \
           '$1==s&&$2==d&&$3=="nullfs"&&$4==o{n++}END{exit !(n==1)}' ||
           die "missing original signed live mount: $dest"
    done
    mount -p | awk -v root="$root" 'index($2,root"/")==1{
         if($3=="nullfs")n++
         else if($1=="devfs"&&$2==root"/dev"&&$3=="devfs")d++
         else bad=1
      }END{exit !(n==6&&d==1&&!bad)}' ||
        die "foreign additional mount in $jail"
    conf=/etc/jail.conf.d/$jail.conf
    link="mount.fstab = \"/etc/jail.fstab.d/fi-c1-$jail.fstab\";"
    n=$(grep -Ec '^[[:space:]]*mount[.]fstab[[:space:]]*=' "$conf" || :)
    case "$n" in
       0) : ;;
       1) grep -F "$link" "$conf" >/dev/null || die "foreign jail fstab reference: $jail" ;;
       *) die "duplicate fstab reference: $jail" ;;
    esac
    dest=/etc/jail.fstab.d/fi-c1-$jail.fstab
    [ ! -L "$dest" ] || die "symlinked fstab candidate: $dest"
    if [ -e "$dest" ]; then
       [ "$(stat -f '%u:%g:%Lp' "$dest")" = '0:0:644' ] ||
          die "fstab target permissions unexpected: $dest"
    fi
    if [ -e "$dest" ]; then
       [ -f "$dest" ] && [ "$(cat "$dest")" = "$(mounts "$jail")" ] ||
          die "foreign existing fstab: $dest"
    fi
    echo "C1_PERSISTENCE_JAIL=$jail nullfs=6 devfs=1 source_preserved=true"
done
mount -p | awk '$1=="tmpfs"&&$2=="/var/run/fi-c1-handoff"&&$3=="tmpfs"{n++}END{exit !(n==1)}' ||
    die 'original C1 volatile host mount missing'
[ -f /etc/fstab ] && [ ! -L /etc/fstab ] &&
[ -f /etc/rc.conf ] && [ ! -L /etc/rc.conf ] &&
grep -Fx 'jail_enable="YES"' /etc/rc.conf >/dev/null &&
grep -Fx 'jail_parallel_start="NO"' /etc/rc.conf >/dev/null ||
    die 'host boot jail state unexpected'
[ "$(jexec -U postgres fi-sor psql -X -w -At -v ON_ERROR_STOP=1 \
    -h /var/db/fi/sor/run -p 5432 -d fi \
    -c "SELECT (to_regnamespace('fi_recovery_projection') IS NULL AND to_regnamespace('fi_recovery') IS NULL)::text")" = true ] ||
    die 'private stage unexpectedly exists'
nf=$(awk '$0 !~ /^[[:space:]]*#/ && NF>=2 && $2=="/var/run/fi-c1-handoff"{n++}END{print n+0}' /etc/fstab)
case "$nf" in
0) : ;;
1) grep -Fx "$hostfstab" /etc/fstab >/dev/null || die 'foreign host fstab RAM entry' ;;
*) die 'duplicate host fstab RAM entry' ;;
esac
for target in /usr/local/etc/rc.d/fi_c1_ram /etc/rc.conf.d/fi_c1_ram; do
    [ ! -L "$target" ] || die "symlinked boot service: $target"
    if [ -e "$target" ]; then
        [ -f "$target" ] || die "foreign target type: $target"
        case "$target" in
        */rc.d/*)
            [ "$(stat -f '%u:%g:%Lp' "$target")" = '0:0:555' ] ||
                die "host RAM rc ownership/mode unsafe: $target" ;;
        */rc.conf.d/*)
            [ "$(stat -f '%u:%g:%Lp' "$target")" = '0:0:644' ] ||
                die "host RAM rc enablement ownership/mode unsafe: $target" ;;
        esac
        case "$target" in
        */rc.d/*) [ "$(cat "$target")" = "$(ramrc)" ] || die 'foreign host RAM rc' ;;
        */rc.conf.d/*) [ "$(cat "$target")" = 'fi_c1_ram_enable="YES"' ] ||
           die 'foreign RAM service setting' ;;
        esac
    fi
done
echo 'FI C1 C220 BOOT PREFLIGHT PASS original_nullfs=18 devfs=3 mount_changes=0'
if [ "$mode" = --audit ]; then
    echo 'FI C1 C220 BOOT PERSISTENCE AUDIT COMPLETE read_only=true'
    exit 0
fi
[ "$(printenv FI_C1_BOOT_INSTALL_APPROVED 2>/dev/null || :)" = PRESERVE_ALL_18_ORIGINAL_NULLFS ] ||
    die 'C220 exact persistent boot install approval required'
# Copy original full configs to root-only recoverable backup BEFORE edits.
backups=/var/backups/fi-c1-c220-boot-$(date +%Y%m%dT%H%M%S)-$$
install -d -o root -g wheel -m 0700 "$backups" || die 'backup root failed'
cp -p /etc/fstab "$backups/fstab" || die 'cannot backup host fstab'
for jail in fi-receiver fi-ingest fi-sor; do
    cp -p "/etc/jail.conf.d/$jail.conf" "$backups/$jail.conf" ||
        die "jail backup failed: $jail"
done
echo "FI_C1_C220_BOOT_BACKUP=$backups"
install -d -o root -g wheel -m 0755 /etc/jail.fstab.d /etc/rc.conf.d /usr/local/etc/rc.d ||
    die 'cannot create boot config directories'
# Publish absent files only, do not overwrite existing content.
for jail in fi-receiver fi-ingest fi-sor; do
    target=/etc/jail.fstab.d/fi-c1-$jail.fstab
    if [ ! -e "$target" ]; then
        tmp=$(mktemp /etc/jail.fstab.d/.fi-c1.XXXXXXXX) || die 'fstab staging failed'
        mounts "$jail" > "$tmp"
        chown 0:0 "$tmp"
        chmod 0644 "$tmp"
        [ ! -e "$target" ] || die 'fstab destination appeared'
        mv -n "$tmp" "$target" || die "fstab publish failed: $jail"
    fi
done
if [ "$nf" = 0 ]; then
    cmp -s /etc/fstab "$backups/fstab" || die 'host fstab changed during stage'
    tmp=$(mktemp /etc/.fi-c1-fstab.XXXXXXXX) || die 'host fstab stage failed'
    cat /etc/fstab > "$tmp"
    if [ -s "$tmp" ] && [ "$(tail -c 1 "$tmp" | od -An -tu1 | tr -d ' ')" != 10 ]; then
        printf '\n' >> "$tmp"
    fi
    printf '%s\n' "$hostfstab" >> "$tmp"
    chown "$(stat -f '%u:%g' /etc/fstab)" "$tmp"
    chmod "0$(stat -f '%Lp' /etc/fstab)" "$tmp"
    mv -f "$tmp" /etc/fstab || die 'host fstab publish failed'
fi
if [ ! -e /usr/local/etc/rc.d/fi_c1_ram ]; then
    tmp=$(mktemp /usr/local/etc/rc.d/.fi-c1.XXXXXXXX) || die 'host rc staging failed'
    ramrc > "$tmp"; chown 0:0 "$tmp"; chmod 0555 "$tmp"
    mv -n "$tmp" /usr/local/etc/rc.d/fi_c1_ram || die 'host rc publish failed'
fi
if [ ! -e /etc/rc.conf.d/fi_c1_ram ]; then
    tmp=$(mktemp /etc/rc.conf.d/.fi-c1.XXXXXXXX) || die 'host rcconf staging failed'
    printf '%s\n' 'fi_c1_ram_enable="YES"' > "$tmp"
    chown 0:0 "$tmp"; chmod 0644 "$tmp"
    mv -n "$tmp" /etc/rc.conf.d/fi_c1_ram || die 'host rcconf publish failed'
fi
for jail in fi-receiver fi-ingest fi-sor; do
    file=/etc/jail.conf.d/$jail.conf
    if ! grep -Eq '^[[:space:]]*mount[.]fstab[[:space:]]*=' "$file"; then
        cmp -s "$file" "$backups/$jail.conf" || die "jail.conf changed: $jail"
        tmp=$(mktemp /etc/jail.conf.d/.fi-c1.XXXXXXXX) || die 'jail stage failed'
        awk -v directive="    mount.fstab = \"/etc/jail.fstab.d/fi-c1-$jail.fstab\";" '
            /^[[:space:]]*mount[.]devfs[[:space:]]*;/ {print; print directive; next}
            {print}
        ' "$file" > "$tmp"
        chown "$(stat -f '%u:%g' "$file")" "$tmp"
        chmod "0$(stat -f '%Lp' "$file")" "$tmp"
        mv -f "$tmp" "$file" || die "jail.conf publish failed: $jail"
    fi
done
sync
for jail in fi-receiver fi-ingest fi-sor; do
    [ "$(cat /etc/jail.fstab.d/fi-c1-$jail.fstab)" = "$(mounts "$jail")" ] ||
        die "postinstall fstab mismatch: $jail"
    [ "$(grep -Ec '^[[:space:]]*mount[.]fstab[[:space:]]*=' "/etc/jail.conf.d/$jail.conf")" = 1 ] ||
        die "postinstall jail link mismatch: $jail"
done
grep -Fx "$hostfstab" /etc/fstab >/dev/null || die 'host fstab postinstall mismatch'
echo "FI C1 C220 BOOT CONFIG INSTALLED backup=$backups live_mount_changes=0 jail_restarts=0 c1_workers_started=false"
echo 'C1 FI JAIL RESTART NOT AUTHORIZED until rcorder and restart-lifecycle acceptance'
