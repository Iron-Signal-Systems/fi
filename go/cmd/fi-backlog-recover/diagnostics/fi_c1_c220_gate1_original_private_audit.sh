#!/bin/sh
# FI C1 Gate 1 — READ-ONLY inventory of the ORIGINAL private benchmark.
# No cluster initialization, shell source, SQL writes, mount, copy or cleanup.
set -eu
umask 077
fail(){ echo "FI C1 ORIGINAL PRIVATE AUDIT STOP: $*" >&2; exit 1; }
[ "$(id -un)" = root ] && [ "$(hostname -s)" = c220 ] ||
  fail 'root@c220 required'
source_pin=f42ec639ffeccba31f2a2d4de82f20294c90cd40
seedstamp=20261115T153532Z
seed=/home/jwood/fi-window-bench-w512-$seedstamp
seedout=/var/tmp/fi-window-chunks-h16-w512-seed-$seedstamp
cache=/fast/jails/roots/fi-dev/home/jwood/fi-w512-c220-verified-cache
repo=/home/jwood/fi-w512-c220-stage
jailroot=$(jls -j fi-dev path) || fail 'fi-dev jail absent'
[ "$jailroot" = /fast/jails/roots/fi-dev ] ||
  fail "fi-dev jail root changed: $jailroot"
[ "$(jls -j fi-dev jid)" != "$(jls -j fi-sor jid)" ] ||
  fail 'dev jail and SoR are not distinct'
echo '===== FROZEN C1 SOURCE OBJECT ====='
if jexec -U jwood fi-dev git -C "$repo" cat-file -e "$source_pin^{commit}" 2>/dev/null;then
  echo "PASS: frozen C1 source=$source_pin available"
else
  echo "MISSING: frozen C1 source=$source_pin in $repo"
fi
echo '===== ORIGINAL PRIVATE SEED ====='
if [ -d "$jailroot$seed/clone-w512-2g/data" ] && [ -f "$jailroot$seed/recover.sha256" ];then
  echo "FOUND: $seed/clone-w512-2g/data"
  jexec -U jwood fi-dev du -Aks "$seed/clone-w512-2g/data" || :
  if jexec -U jwood fi-dev pg_ctl -D "$seed/clone-w512-2g/data" status >/dev/null 2>&1;then
    echo 'STOP: original seed PostgreSQL is running; do not clone it'
  else
    echo 'PASS: original seed PostgreSQL is stopped'
  fi
else
  echo 'MISSING: original 493478-row private seed; do not assume fresh 15M baseline equivalence'
fi
if [ -f "$seedout/clone-w512-2g/W512_SEED_CHECKPOINT.tsv" ];then
  echo '===== ORIGINAL VERIFIED SEED CHECKPOINT ====='
  cat "$seedout/clone-w512-2g/W512_SEED_CHECKPOINT.tsv"
fi
echo '===== VERIFIED RECEIVER CACHE ====='
if [ -d "$cache" ] && [ ! -L "$cache" ];then
  count=$(find "$cache" -type f -name 'batch-*.data' | wc -l | tr -d ' ')
  markers=$(find "$cache" -type f -name verified.json | wc -l | tr -d ' ')
  printf 'cached_signed_batches=%s original_verified_markers=%s\n' "$count" "$markers"
  [ "$count" = 8399 ] && [ "$markers" = 1 ] ||
    echo 'STOP: cache is not the complete originally verified 8399-batch source'
else
  echo 'MISSING: original fi-dev receiver-authenticated benchmark cache'
fi
echo '===== ORIGINAL PRIVATE RESULTS ====='
for path in /var/tmp/fi-c1-full-backlog-4g-20261121T121128Z \
  /var/tmp/fi-c1-full-candidate.UhU0yzbV;do
  if [ -d "$path" ];then
    echo "FOUND: $path"
    [ ! -f "$path/SUMMARY.txt" ] || tail -6 "$path/SUMMARY.txt"
  else
    echo "NOT PRESENT: $path"
  fi
done
echo '===== ISOLATION & CAPACITY ====='
jexec -U jwood fi-dev df -Pk /home/jwood || :
for svc in fi_c1_sor_local fi_c1_sor_worker;do
  if jexec fi-sor service "$svc" onestatus >/dev/null 2>&1;then
    echo "WARNING: fi-sor service running: $svc"
  fi
done
if jexec fi-ingest service fi_ingest_worker onestatus >/dev/null 2>&1;then
  echo 'WARNING: fi_ingest_worker is running; original private runner forbids concurrent operation'
fi
echo 'FI C1 ORIGINAL PRIVATE INVENTORY COMPLETE read_only=true no_postgres_started=true no_sql_writes=true'
