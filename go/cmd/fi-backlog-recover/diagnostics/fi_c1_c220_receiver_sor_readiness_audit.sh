#!/bin/sh
# Copyright (c) 2026 John Joseph Wood. All rights reserved.
# C220 receiver -> SoR C1: READ-ONLY infrastructure and canonical audit.
# Neither creates cache directories, changes mountpoints, starts services,
# extracts signed custody, clears SQL, retires READY, nor restarts a jail.
set -eu
fail(){ echo "FI C1 RECEIVER-SOR AUDIT STOP: $*" >&2;exit 1; }
mount_match(){
 awk -v src="$1" -v dst="$2" -v access="$3" '
  $2==dst {
   count++
   n=split($4,parts,",")
   for(i=1;i<=n;i++)if($1==src&&$3=="nullfs"&&parts[i]==access)matches++
  }
  END{exit !(count==1&&matches==1)}'
}
if [ "$#" -eq 1 ]&&[ "$1" = --selftest ];then
 printf '%s\n' '/work/cache /fast/jails/roots/fi-sor/var/db/fi/verified-cache nullfs ro,nosuid 0 0' |
  mount_match /work/cache /fast/jails/roots/fi-sor/var/db/fi/verified-cache ro ||
  fail 'RO mount matcher selftest failed'
 if printf '%s\n' '/work/cache /fast/jails/roots/fi-sor/var/db/fi/verified-cache nullfs rw 0 0' |
  mount_match /work/cache /fast/jails/roots/fi-sor/var/db/fi/verified-cache ro;then
  fail 'RW mount incorrectly passed RO matcher'
 fi
 echo 'FI C1 RECEIVER-SOR AUDIT SELFTEST PASS'
 exit 0
fi
[ "$#" -eq 1 ]&&[ "$1" = --audit ]||fail 'usage: --selftest|--audit'
[ "$(id -u)" -eq 0 ]&&[ "$(uname -s)" = FreeBSD ]&&
[ "$(hostname -s)" = c220 ]||fail 'physical root@c220 required'
host=/work/fi-c220-20261114
receiver=/fast/jails/roots/fi-receiver
sor=/fast/jails/roots/fi-sor
source=$host/custody/verified-cache
rw=$receiver/var/db/fi/verified-cache
ro=$sor/var/db/fi/verified-cache
echo '===== EXACT TWO-JAIL ARCHITECTURE ====='
for jail in fi-receiver fi-sor;do
 jls -j "$jail" >/dev/null 2>&1||fail "required $jail jail not running"
done
if jls -j fi-ingest >/dev/null 2>&1;then
 echo 'BLOCKER: obsolete fi-ingest jail is still running'
fi
jls -h jid name path|awk '$2=="fi-receiver"||$2=="fi-sor"{print}'
for path in "$host/custody/generation" "$host/custody/recorded";do
 [ -d "$path" ]&&[ ! -L "$path" ]||fail "original receiver custody missing: $path"
done
echo '===== RECEIVER VERIFIED BATCH CACHE SOURCE ====='
if [ -d "$source" ]&&[ ! -L "$source" ];then
 stat -f 'HOST_RECEIVER_CACHE=%N owner=%Su group=%Sg mode=%Sp' "$source"
 echo 'HOST_RECEIVER_CACHE_BYTES:'
 du -sh "$source" 2>/dev/null||:
 echo 'HOST_RECEIVER_COMPLETED_RECEIPTS:'
 find "$source" -maxdepth 1 -type d -name 'receipt-*'|wc -l
else
 echo "BLOCKER: RECEIVER_CACHE_NOT_STAGED=$source"
fi
echo '===== LIVE VERIFIED CACHE MOUNTS ====='
if mount -p|mount_match "$source" "$rw" rw;then
 echo 'RECEIVER_VERIFIED_CACHE_RW_MOUNT=PASS'
else
 echo "BLOCKER: RECEIVER_VERIFIED_CACHE_RW_MOUNT_MISSING=$rw"
fi
if mount -p|mount_match "$source" "$ro" ro;then
 echo 'SOR_VERIFIED_CACHE_RO_MOUNT=PASS'
else
 echo "BLOCKER: SOR_VERIFIED_CACHE_RO_MOUNT_MISSING=$ro"
fi
echo '===== FI-SOR SERVICE ACCOUNT READ-ONLY ACCESS ====='
if jexec -U fi-sor fi-sor /bin/sh -c 'test -r /var/db/fi/verified-cache && test -x /var/db/fi/verified-cache';then
 echo 'SOR_CACHE_READ_ACCESS=PASS'
else
 echo 'BLOCKER: FI_SOR_CANNOT_READ_RECEIVER_CACHE'
fi
echo '===== PERSISTENCE MOUNT REFERENCES (INSPECTION ONLY) ====='
for file in /etc/jail.fstab.d/fi-c1-fi-receiver.fstab /etc/jail.fstab.d/fi-c1-fi-sor.fstab;do
 if [ -f "$file" ]&&[ ! -L "$file" ];then
  echo "PERSISTENT_FSTAB=$file"
  grep -F '/verified-cache ' "$file" || echo "BLOCKER: no verified-cache line in $file"
 else
  echo "PERSISTENT_FSTAB_NOT_PRESENT=$file"
 fi
done
echo '===== REAL SOR INTEGRITY (READ ONLY) ====='
jexec -U postgres fi-sor psql -X -w -v ON_ERROR_STOP=1 -P pager=off \
 -h /var/db/fi/sor/run -p 5432 -d fi -c "
BEGIN READ ONLY;
SELECT (SELECT count(*) FROM fi.recorded_generation) AS generations,
       (SELECT count(*) FROM fi.source_batch) AS batches,
       (SELECT count(*) FROM fi.source_record) AS source_records,
       (SELECT count(*) FROM fi.ingest_journal) AS journal_entries,
       (SELECT count(*) FROM fi_c1_pending.generation_control) AS pending_generations;
COMMIT;"
echo '===== DISABLED SINGLE-JAIL SERVICE ====='
f=$sor/etc/rc.conf.d/fi_c1_sor_local
if [ -f "$f" ]&&[ ! -L "$f" ];then
 grep -E '^fi_c1_sor_local_(enable|receiver_cache_root|sources|ready_root)=' "$f"||:
else
 echo 'BLOCKER: fi-sor local service configuration missing'
fi
echo 'FI C1 RECEIVER-SOR AUDIT FINISHED read_only=true postgres_unchanged=true no_service_started=true'
