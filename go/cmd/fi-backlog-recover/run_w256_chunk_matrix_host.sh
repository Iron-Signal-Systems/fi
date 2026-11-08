#!/bin/sh
# FI DEVELOPMENT ONLY. Fresh four-arm W256 signed replay, not W128 resume.
# Run as root on fi-backend-b after a complete W256 window-zero seed exists.
set -eu
umask 077
fail(){ echo "FI W256 MATRIX STOP: $*" >&2;exit 1; }
[ "$#" = 2 ] || fail "usage: $0 /home/jwood/fi-w256-seed 55870"
seed=$1;seedport=$2
case "$seed" in /home/jwood/*) ;; *) fail "seed must be inside fi-dev";; esac
case "$seedport" in ''|*[!0-9]*) fail "seed port invalid";; esac
[ "$(id -un)" = root ] || fail "host root required"
jailroot=$(jls -j fi-dev path) || fail "fi-dev missing"
repo=/home/jwood/fi-deferred-experiment
provision="$repo/go/cmd/fi-backlog-recover/provision_w256_chunk_matrix_jail.sh"
runner="$jailroot$repo/go/cmd/fi-backlog-recover/run_w256_chunk_arm_host.sh"
[ -f "$jailroot$provision" ] && [ -f "$runner" ] || fail "matrix source files missing"
cache=/var/tmp/fi-window-chunks-20261103T172254Z/verified-cache
[ "$(find "$cache" -name 'batch-*.data' -type f | wc -l | tr -d ' ')" = 8399 ] || fail "verified signed cache differs"
[ "$(sysctl -n kern.racct.enable 2>/dev/null)" = 1 ] || fail "kernel RCTL not enabled"
space=$(df -Pk "$jailroot/home/jwood" | awk 'NR==2{print $4}')
[ "$space" -ge 100663296 ] || fail "less than 96GiB free"
stamp=$(date -u '+%Y%m%dT%H%M%SZ')
root="/home/jwood/fi-w256-matrix-$stamp"
out="/var/tmp/fi-w256-test-$stamp"
[ ! -e "$jailroot$root" ] && [ ! -e "$out" ] || fail "output collision"
jexec -U jwood fi-dev sh "$provision" "$root" "$seed" "$seedport" ||
 fail "W256 signed seed clone failed"
mkdir -m 700 "$out"
cp "$jailroot$root/source-status.txt" "$out/source-status.txt"
sql(){
 arm=$1;query=$2
 case "$arm" in K32) port=55991;;K64) port=55992;;K96) port=55993;;K128) port=55994;;*) fail "unknown arm";;esac
 jexec -U jwood fi-dev psql "host=$root/$arm/socket port=$port user=fi_ingest dbname=fi sslmode=disable" -X -qAt -v ON_ERROR_STOP=1 -c "$query"
}
checkpoint="SELECT count(*)::text||'|'||coalesce(sum(committed_records),0)::text||'|'||coalesce(max(window_index),-1)::text FROM fi_recovery.typed_window"
seedstate=$(sql K32 "$checkpoint")
for arm in K64 K96 K128; do
 [ "$(sql "$arm" "$checkpoint")" = "$seedstate" ] || fail "$arm initial W256 seed differs"
done
for arm in K32 K64 K96 K128; do
 sh "$runner" "$arm" "$root" "$out" || fail "$arm exact signed W256 run failed"
 [ "$(sql "$arm" "SELECT count(*) FROM fi_recovery.typed_window")" = 5 ] || fail "$arm missing durable W256 checkpoints"
 [ "$(sql "$arm" "SELECT max(window_index) FROM fi_recovery.typed_window")" = 4 ] || fail "$arm wrong final W256 window"
 [ "$(sql "$arm" "SELECT count(*) FROM fi_recovery.source_window")" = 5 ] || fail "$arm source window mismatch"
 [ "$(sql "$arm" "SELECT count(*) FROM fi_recovery.verified_artifact_window")" = 5 ] || fail "$arm verified artifact mismatch"
 [ "$(sql "$arm" "SELECT count(*) FROM fi.recorded_generation")" = 0 ] || fail "$arm unexpected authoritative generation"
 [ "$(sql "$arm" "SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted'")" = 0 ] || fail "$arm unexpected Accepted outcome"
 constraints=$(sql "$arm" "SELECT count(*) FROM pg_inherits i JOIN pg_class c ON c.oid=i.inhrelid
  WHERE i.inhparent='fi_recovery_projection.windows_security_event_field'::regclass
  AND c.relname IN ('windows_security_event_field_w000001','windows_security_event_field_w000002','windows_security_event_field_w000003','windows_security_event_field_w000004')
  AND EXISTS(SELECT 1 FROM pg_constraint k WHERE k.conrelid=c.oid AND k.contype='f' AND k.convalidated)
  AND EXISTS(SELECT 1 FROM pg_constraint k WHERE k.conrelid=c.oid AND k.contype='p' AND k.convalidated)")
 [ "$constraints" = 4 ] || fail "$arm PK/FK validated field partition attachments missing ($constraints)"
 sql "$arm" "SELECT window_index::text||'|'||encode(descriptor_sha256,'hex')||'|'||committed_records::text||'|'||committed_bytes::text FROM fi_recovery.typed_window ORDER BY window_index" > "$out/$arm/descriptors.tsv"
 # Reopen every published immutable artifact and compare its exact signed
 # payload AND manifest bytes with the already authenticated source cache.
 expected=$(sql "$arm" "SELECT coalesce(sum(end_batch-start_batch),0) FROM fi_recovery.verified_artifact_window WHERE window_index BETWEEN 1 AND 4")
 actual=0
 for ready in "$out/$arm/private"/receipt-*/window-*; do
  [ -d "$ready" ] || fail "$arm missing published signed artifact"
  receipt=$(basename "$(dirname "$ready")")
  for dest in "$ready"/batch-*.data; do
   [ -f "$dest" ] || fail "$arm no signed artifact payload"
   base=$(basename "$dest")
   original="$cache/$receipt/$base"
   [ -f "$original" ] || fail "$arm original cache batch missing"
   cmp -s "$dest" "$original" || fail "$arm signed data differs from original ($base)"
   cmp -s "${dest%.data}.manifest" "${original%.data}.manifest" ||
    fail "$arm signed manifest differs from original ($base)"
   actual=$((actual+1))
  done
 done
 [ "$actual" -eq "$expected" ] || fail "$arm artifact byte-readback count differs ($actual/$expected)"
 printf 'FI W256 ARTIFACT READBACK PASS arm=%s signed_batches=%s\n' "$arm" "$actual" >> "$out/$arm/result.txt"
done
for arm in K64 K96 K128; do
 cmp -s "$out/K32/descriptors.tsv" "$out/$arm/descriptors.tsv" ||
 fail "$arm signed checkpoint chain differs from K32"
done
printf 'FI W256 CHUNK MATRIX PASS real_signed_backlog=true identical_source_windows=true windows=4_per_arm 4GiB_RSS_guard=mandatory authoritative=0 accepted=0 output=%s\n' "$out"
for arm in K32 K64 K96 K128; do
 printf '\n==== %s ===\n' "$arm"
 cat "$out/$arm/result.txt"
 tail -1 "$out/$arm/memory.txt"
done
