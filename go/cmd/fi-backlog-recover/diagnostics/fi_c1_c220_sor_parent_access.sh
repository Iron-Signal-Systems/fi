#!/bin/sh
# FI C1 C220 fi-sor jail parent-directory traverse-only correction.
# Change ONLY three root-owned jail directories, from root:wheel 0700
# to root:GID4100 0710. No recursive change and no original receiver,
# trust, custody, mounted nullfs root, or PostgreSQL file modification.
set -eu
umask 077
fail(){ printf 'FI C1 SOR TRAVERSE STOP: %s\n' "$*" >&2; exit 1; }
[ "$#" -eq 1 ] || fail 'usage: sh script --audit | --apply'
case "$1" in --audit|--apply) mode=$1 ;; *) fail 'invalid mode' ;; esac
[ "$(id -un)" = root ] && [ "$(hostname -s)" = c220 ] ||
    fail 'requires root on physical C220'
root=/fast/jails/roots/fi-sor
actual=$(jls -h jid name path | awk '$2=="fi-sor" {print $3}')
[ "$actual" = "$root" ] || fail 'fi-sor jail root mismatch'
[ "$(jexec fi-sor id -u fi-sor)" = 4100 ] &&
[ "$(jexec fi-sor id -g fi-sor)" = 4100 ] ||
    fail 'fi-sor UID/GID changed'
[ "$(jexec fi-sor id -g postgres)" = 770 ] ||
    fail 'postgres identity changed'
[ "$(jexec fi-sor pw groupshow fi-ingest-socket | cut -d: -f3)" = 4100 ] ||
    fail 'existing PostgreSQL socket group changed'

# All original receiver sources must still be mounted read-only.
for pair in \
  "/work/fi-c220-20261114/custody/generation $root/var/db/fi/custody/generation" \
  "/work/fi-c220-20261114/custody/recorded $root/var/db/fi/custody/recorded" \
  "/work/fi-c220-20261114/config/receiver/pki/trust $root/usr/local/etc/fi/pki/trust" \
  "/work/fi-c220-20261114/config/receiver/sources $root/usr/local/etc/fi/sources"; do
    source=$(printf '%s\n' "$pair" | awk '{print $1}')
    target=$(printf '%s\n' "$pair" | awk '{print $2}')
    mount -p | awk -v s="$source" -v t="$target" \
      '$1==s && $2==t && $3=="nullfs" && $4=="ro" {ok=1} END{exit !ok}' ||
        fail "original signed receiver RO mount missing or altered: $target"
done

# Check the whole set before the first mutation. The two allowed states
# permit safe idempotent recovery after a partial preceding attempt.
for relative in usr/local/etc/fi usr/local/etc/fi/pki var/db/fi/custody; do
    path=$root/$relative
    [ -d "$path" ] && [ ! -L "$path" ] &&
      [ "$(realpath "$path")" = "$path" ] ||
        fail "unsafe jail directory: $path"
    observed=$(stat -f '%u:%g:%Sp' "$path") ||
        fail "cannot inspect jail directory: $path"
    case "$observed" in
    '0:0:drwx------')
        printf 'C1_SOR_PARENT_ACCESS=NEEDS_FIX|%s|%s\n' "$relative" "$observed" ;;
    '0:4100:drwx--x---')
        printf 'C1_SOR_PARENT_ACCESS=EXACT|%s|%s\n' "$relative" "$observed" ;;
    *)
        fail "unexpected ownership/mode on $path: $observed" ;;
    esac
done
if [ "$mode" = --audit ]; then
    echo 'FI C1 C220 SOR PARENT ACCESS AUDIT COMPLETE read_only=true'
    exit 0
fi
[ "$(printenv FI_C1_SOR_PARENT_ACCESS_APPROVED 2>/dev/null || :)" = \
  THREE_SOR_DIRECTORIES_TRAVERSE_ONLY ] ||
    fail 'explicit C220 parent-directory correction approval required'

# Never change file content or mounted directories. These chmod/chgrp
# operations apply only to original empty/search-blocking parent dirs.
for relative in usr/local/etc/fi usr/local/etc/fi/pki var/db/fi/custody; do
    path=$root/$relative
    [ -d "$path" ] && [ ! -L "$path" ] &&
      [ "$(realpath "$path")" = "$path" ] ||
        fail "directory replaced after preflight: $path"
    observed=$(stat -f '%u:%g:%Sp' "$path") ||
        fail "cannot reinspect jail directory: $path"
    case "$observed" in
    '0:4100:drwx--x---') continue ;;
    '0:0:drwx------') ;;
    *) fail "foreign changed state: $path $observed" ;;
    esac
    chgrp 4100 "$path" ||
        fail "cannot set C1 traverse group on $path"
    chmod 0710 "$path" ||
        fail "cannot set group search-only permission on $path"
    [ "$(stat -f '%u:%g:%Sp' "$path")" = '0:4100:drwx--x---' ] ||
        fail "post-change directory metadata mismatch: $path"
done
for relative in usr/local/etc/fi usr/local/etc/fi/pki var/db/fi/custody; do
    [ "$(stat -f '%u:%g:%Sp' "$root/$relative")" = '0:4100:drwx--x---' ] ||
        fail "post-apply final directory metadata mismatch: $relative"
done
jexec -U fi-sor fi-sor /bin/sh -c '
set -eu
for item in \
    /usr/local/etc/fi/pki/trust/fi-root-ca.crt.pem \
    /usr/local/etc/fi/pki/trust/fi-batch-signing-ca.crt.pem \
    /usr/local/etc/fi/pki/trust/fi-batch-signing-ca.crl.pem \
    /usr/local/etc/fi/sources/iss-fs-22a.iss.local.conf; do
    [ -f "$item" ] && [ -r "$item" ] ||
      { echo "FI C1 SoR signed trust/registry inaccessible: $item" >&2; exit 1; }
done
for item in /var/db/fi/custody/generation /var/db/fi/custody/recorded; do
    [ -d "$item" ] && [ -r "$item" ] && [ -x "$item" ] ||
      { echo "FI C1 SoR signed custody inaccessible: $item" >&2; exit 1; }
done
' || fail 'unprivileged SoR input access failed after correction'
jexec -U postgres fi-sor pg_isready -h /var/db/fi/sor/run -p 5432 >/dev/null 2>&1 ||
    fail 'PostgreSQL socket readiness changed'
echo 'FI C1 C220 SOR PARENT ACCESS PASS dirs=3 receiver_files_untouched=true mounts_untouched=true c1_started=false'
