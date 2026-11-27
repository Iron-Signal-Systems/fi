#!/bin/sh
# C1 actual C220 fi-sor service account, one-time explicit operator install.
# Reuse existing fi-ingest-socket GID 4100. NEVER groupadd or alter postgres.
# No SQL DDL, mount, jail restart, service enablement or ingestion.
set -eu
umask 077
fail(){ printf 'FI C1 SOR IDENTITY STOP: %s\n' "$*" >&2; exit 1; }
[ "$(id -un)" = root ] && [ "$(hostname -s)" = c220 ] ||
  fail 'requires root on physical c220'
[ "$#" -eq 1 ] || fail 'usage: sh script --audit | --apply'
case "$1" in --audit|--apply) ;; *) fail 'unknown mode';; esac

root=/fast/jails/roots/fi-sor
[ -d "$root" ] && [ ! -L "$root" ] || fail 'actual fi-sor root missing or symlinked'
sor_path=$(jls -h jid name path | awk '$2=="fi-sor" {print $3}')
[ "$sor_path" = "$root" ] || fail 'actual running SoR jail not bound to expected ZFS root'
if jls -j fi-sor-db jid >/dev/null 2>&1; then
  fail 'second conflicting SoR jail running'
fi
[ -f "$root/etc/group" ] && [ ! -L "$root/etc/group" ] ||
  fail 'unsafe existing SoR group database'
[ -f "$root/etc/master.passwd" ] && [ ! -L "$root/etc/master.passwd" ] ||
  fail 'unsafe existing SoR user database'

# Count both the exact existing group and all competing numeric/name entries.
socket_groups=$(awk -F: '$1=="fi-ingest-socket" && $3=="4100" {n++} END {print n+0}' "$root/etc/group")
gid_groups=$(awk -F: '$3=="4100" {n++} END {print n+0}' "$root/etc/group")
foreign_name=$(awk -F: '$1=="fi-sor" {n++} END {print n+0}' "$root/etc/group")
[ "$socket_groups" = 1 ] && [ "$gid_groups" = 1 ] && [ "$foreign_name" = 0 ] ||
  fail 'C220 socket GID 4100 is not uniquely owned by fi-ingest-socket'
uid_collisions=$(awk -F: '$3=="4100" && $1!="fi-sor" {n++} END {print n+0}' "$root/etc/master.passwd")
[ "$uid_collisions" = 0 ] || fail 'existing user owns UID 4100 in fi-sor'

jexec fi-sor id postgres >/dev/null || fail 'existing postgres user missing'
jexec -U postgres fi-sor pg_isready -h /var/db/fi/sor/run -p 5432 >/dev/null ||
  fail 'real SoR PostgreSQL socket not available'

existing_user=$(awk -F: '$1=="fi-sor" {n++} END {print n+0}' "$root/etc/master.passwd")
if [ "$existing_user" = 1 ]; then
  uid=$(jexec fi-sor id -u fi-sor)
  gid=$(jexec fi-sor id -g fi-sor)
  [ "$uid" = 4100 ] && [ "$gid" = 4100 ] ||
    fail 'existing fi-sor user has wrong numeric identity'
  echo 'C1_SOR_IDENTITY=EXACT_EXISTING uid=4100 gid=4100 group=fi-ingest-socket'
  exit 0
fi
[ "$existing_user" = 0 ] || fail 'duplicate fi-sor user entries'
echo 'C1_SOR_IDENTITY=ABSENT expected_uid=4100 existing_socket_group=fi-ingest-socket'
if [ "$1" = --audit ]; then
  echo 'C1_SOR_IDENTITY_AUDIT_COMPLETE read_only=true'
  exit 0
fi
[ "$(printenv FI_C1_SOR_IDENTITY_APPROVED 2>/dev/null || :)" = ADD_FI_SOR_USER_REUSE_SOCKET_GID ] ||
  fail 'explicit approval missing for useradd only'

echo '===== CREATE ONLY fi-sor USER; KEEP EXISTING SOCKET GROUP ====='
jexec fi-sor /usr/sbin/pw useradd fi-sor \
  -u 4100 -g fi-ingest-socket -d /nonexistent -s /usr/sbin/nologin -w no ||
  fail 'FreeBSD jailed user creation failed; inspect identity before retry'
[ "$(jexec fi-sor id -u fi-sor)" = 4100 ] ||
  fail 'new fi-sor UID verification failed'
[ "$(jexec fi-sor id -g fi-sor)" = 4100 ] ||
  fail 'new fi-sor GID verification failed'
[ "$(awk -F: '$1=="fi-ingest-socket"&&$3=="4100"{n++} END{print n+0}' "$root/etc/group")" = 1 ] ||
  fail 'existing socket group changed'
jexec -U postgres fi-sor pg_isready -h /var/db/fi/sor/run -p 5432 >/dev/null ||
  fail 'existing PostgreSQL readiness changed'
echo 'C1_SOR_IDENTITY=INSTALLED uid=4100 gid=4100 existing_socket_group_preserved=true c1_service_started=false'
