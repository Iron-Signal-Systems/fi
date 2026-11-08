#!/bin/sh
# FI isolated W256 signed-cache test. Run on fi-backend-b as root.
# Requires a fresh, independently authenticated W256 window-zero seed
# cloned into K32/K64/K96/K128 by provision_w256_chunk_matrix_jail.sh.
set -eu
umask 077
fail(){ echo "FI W256 TEST STOP: $*" >&2; exit 1; }
[ "$#" = 3 ] || fail "usage: $0 K32|K64|K96|K128 /home/jwood/fi-w256-matrix-TIMESTAMP /var/tmp/fi-w256-test-TIMESTAMP"
arm=$1
root=$2
out=$3
case "$arm" in K32) chunk=32768;port=55991;; K64) chunk=65536;port=55992;; K96) chunk=98304;port=55993;; K128) chunk=131072;port=55994;; *) fail "unknown chunk arm";; esac
case "$root" in /home/jwood/fi-w256-matrix-[0-9]*) ;; *) fail "unknown fixture root";; esac
case "$out" in /var/tmp/fi-w256-test-[0-9]*) ;; *) fail "unknown output root";; esac
[ "$(id -un)" = root ] || fail "host root required"
jailroot=$(jls -j fi-dev path) || fail "fi-dev jail not found"
binary="$jailroot$root/fi-w256-recover"
[ -x "$binary" ] || fail "W256 binary missing"
[ "$(sha256 -q "$binary")" = "$(cat "$jailroot$root/recover.sha256")" ] || fail "binary hash differs"
cache=/var/tmp/fi-window-chunks-20261103T172254Z/verified-cache
[ -d "$cache" ] || fail "original signed cache unavailable"
dir="$out/$arm"
[ ! -e "$dir" ] || fail "arm already used"
mkdir -p -m 700 "$dir"
mkdir -m 700 "$dir/private"
"$binary" \
  -source=iss-fs-22a.iss.local \
  -generation-id=20261030T000032.061323100Z-3e38b2210771462c \
  -postgres="host=$jailroot$root/$arm/socket port=$port user=fi_ingest dbname=fi sslmode=disable" \
  -custody-root=/var/db/fi/custody/generation \
  -recorded-root=/var/db/fi/custody/recorded -source-namespaces=false \
  -private-root="$dir/private" -private-writes -private-field-partitions \
  -security-profile=P3 -file-profile=F3 -window-profile=W256 \
  "-processing-chunk-records=$chunk" -continuous-private -start-window=1 \
  -max-windows=0 -max-runtime=0s -deferred-verified-clone \
  -private-w256-memory4g -test-stop-after-windows=4 \
  -verified-cache-root="$cache" > "$dir/recover.log" 2>&1 ||
 { tail -n 35 "$dir/recover.log" >&2 || :; fail "$arm replay failed"; }
grep '^FI PRIVATE EXACT WINDOW STOP start=1 windows=4 last=4 records=.*authoritative=0 accepted=0$' "$dir/recover.log" > "$dir/result.txt" || fail "four-window exact-stop proof absent"
grep '^FI REAL BACKLOG DURABLE ' "$dir/recover.log" > "$dir/windows.txt" || fail "durable windows absent"
[ "$(wc -l < "$dir/windows.txt" | tr -d ' ')" = 4 ] || fail "durable count not four"
grep '^FI PRIVATE W256 MEMORY COMMITTED ' "$dir/recover.log" > "$dir/memory.txt" || fail "W256 RSS profile missing"
[ "$(wc -l < "$dir/memory.txt" | tr -d ' ')" = 4 ] || fail "incomplete W256 RSS samples"
grep '^FI PRIVATE STAGE PROFILE ' "$dir/recover.log" > "$dir/stages.txt" || fail "W256 stage profiles missing"
[ "$(wc -l < "$dir/stages.txt" | tr -d ' ')" = 4 ] || fail "incomplete stage profiles"
# Report observed process memory. It is a benchmark metric, not a
# kernel-enforced ceiling or an acceptance prerequisite.
awk '{for(i=1;i<=NF;i++){split($i,a,"=");if(a[1]=="peak_rss_bytes"&&a[2]+0>4294967296)print "FI W256 MEMORY OBSERVATION: RSS exceeded 4GiB soft target"}}' "$dir/memory.txt" || :
printf 'FI W256 TEST PASS arm=%s chunk=%d full_signed_windows=4 memory=observed_adaptive\n' "$arm" "$chunk"
cat "$dir/result.txt"
