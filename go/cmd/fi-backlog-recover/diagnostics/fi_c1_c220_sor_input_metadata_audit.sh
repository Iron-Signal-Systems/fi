#!/bin/sh
# C220 FI C1 signed-input path/permission inventory.
# READ ONLY: prints only file names, mode, numeric owner/group, size,
# symlink flags, jail IDs and per-user access. No certificate, CRL,
# source registry or receipt contents are read or printed.
set -eu
fail(){ printf 'FI C1 SIGNED INPUT AUDIT STOP: %s\n' "$*" >&2; exit 1; }
[ "$(id -un)" = root ] && [ "$(hostname -s)" = c220 ] ||
    fail 'physical C220 root required'
[ "$#" -eq 1 ] && [ "$1" = --audit ] ||
    fail 'usage: sh script --audit'
[ "$(jls -h jid name path | awk '$2=="fi-sor"{print $3}')" = /fast/jails/roots/fi-sor ] ||
    fail 'running actual fi-sor jail mismatch'
jexec fi-sor id fi-sor
jexec fi-receiver id fi-receiver || :
echo '===== ORIGINAL RECEIVER SOURCE METADATA (NO CONTENTS) ====='
for item in \
    /work/fi-c220-20261114/config/receiver \
    /work/fi-c220-20261114/config/receiver/pki \
    /work/fi-c220-20261114/config/receiver/pki/trust \
    /work/fi-c220-20261114/config/receiver/pki/trust/fi-root-ca.crt.pem \
    /work/fi-c220-20261114/config/receiver/pki/trust/fi-batch-signing-ca.crt.pem \
    /work/fi-c220-20261114/config/receiver/pki/trust/fi-batch-signing-ca.crl.pem \
    /work/fi-c220-20261114/config/receiver/sources \
    /work/fi-c220-20261114/config/receiver/sources/iss-fs-22a.iss.local.conf; do
    if [ -L "$item" ]; then
        printf 'SOURCE_SYMLINK=%s\n' "$item"
    elif [ -e "$item" ]; then
        stat -f 'SOURCE|%N|mode=%Sp|uid=%u|gid=%g|size=%z' "$item"
    else
        printf 'SOURCE_ABSENT=%s\n' "$item"
    fi
done
echo '===== FI-SOR FILESYSTEM PATH COMPONENT METADATA (NO CONTENTS) ====='
jexec fi-sor /bin/sh -c '
for item in \
    /usr /usr/local /usr/local/etc /usr/local/etc/fi \
    /usr/local/etc/fi/pki /usr/local/etc/fi/pki/trust \
    /usr/local/etc/fi/pki/trust/fi-root-ca.crt.pem \
    /usr/local/etc/fi/pki/trust/fi-batch-signing-ca.crt.pem \
    /usr/local/etc/fi/pki/trust/fi-batch-signing-ca.crl.pem \
    /usr/local/etc/fi/sources \
    /usr/local/etc/fi/sources/iss-fs-22a.iss.local.conf \
    /var/db/fi /var/db/fi/custody \
    /var/db/fi/custody/generation /var/db/fi/custody/recorded; do
    if [ -L "$item" ]; then
        printf "SOR_SYMLINK=%s\n" "$item"
    elif [ -e "$item" ]; then
        stat -f "SOR|%N|mode=%Sp|uid=%u|gid=%g|size=%z" "$item"
    else
        printf "SOR_ABSENT=%s\n" "$item"
    fi
done
'
echo '===== UNPRIVILEGED FI-SOR PATH RESOLUTION (NO CONTENTS) ====='
jexec -U fi-sor fi-sor /bin/sh -c '
for item in \
    /usr/local/etc/fi \
    /usr/local/etc/fi/pki \
    /usr/local/etc/fi/pki/trust \
    /usr/local/etc/fi/pki/trust/fi-root-ca.crt.pem \
    /usr/local/etc/fi/pki/trust/fi-batch-signing-ca.crt.pem \
    /usr/local/etc/fi/pki/trust/fi-batch-signing-ca.crl.pem \
    /usr/local/etc/fi/sources \
    /usr/local/etc/fi/sources/iss-fs-22a.iss.local.conf \
    /var/db/fi/custody/generation /var/db/fi/custody/recorded; do
    if [ -d "$item" ]; then
        if [ -r "$item" ] && [ -x "$item" ]; then
            printf "SOR_USER_DIR_ACCESS=YES|%s\n" "$item"
        else
            printf "SOR_USER_DIR_ACCESS=DENIED|%s\n" "$item"
        fi
    elif [ -f "$item" ]; then
        if [ -r "$item" ]; then
            printf "SOR_USER_FILE_ACCESS=YES|%s\n" "$item"
        else
            printf "SOR_USER_FILE_ACCESS=DENIED|%s\n" "$item"
        fi
    else
        printf "SOR_USER_PATH_NOT_VISIBLE_OR_NOT_REGULAR=%s\n" "$item"
    fi
done
'
echo '===== ORIGINAL SOURCE AND SOR MOUNT METADATA ====='
mount -p | grep -E '/fast/jails/roots/fi-sor/(usr/local/etc/fi/(pki/trust|sources)|var/db/fi/custody/(generation|recorded)) ' ||
    fail 'expected SoR signed-custody/trust mounts not observed'
echo 'FI C1 C220 SIGNED INPUT METADATA AUDIT COMPLETE read_only=true'
