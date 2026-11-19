#!/bin/sh
# FI C1: original accepted P6 native family buffers with five concurrent
# SQL writers. C220 disposable PostgreSQL clone only. No P7 code or bridge.
set -eu
umask 077
fail() { printf 'FI C1 STOP: %s\n' "$*" >&2; exit 1; }
[ "$(id -un)" = root ] && [ "$(hostname -s)" = c220 ] &&
[ "$#" -eq 2 ] || fail 'usage: sh controller preflight|compile|c1 20261115T153532Z'
case "$1" in preflight|compile|c1) mode=$1;;*)fail 'unknown mode';;esac
[ "$2" = 20261115T153532Z ] || fail 'only accepted signed W512 seed'
repo=/home/jwood/fi-w512-c220-stage
sourcepin=3fd55cb256ec5903741a4c8397d92a546360f48f
runnerpin=1b154a12c1388303411ae8e51d32536c45817a65
runnerpath=go/cmd/fi-backlog-recover/run_private_c1_five_family_c220_host.sh
jexec -U jwood fi-dev git -C "$repo" cat-file -e "$sourcepin^{commit}" ||
  fail 'native P6 signed source pin unavailable'
jexec -U jwood fi-dev git -C "$repo" cat-file -e "$runnerpin^{commit}" ||
  fail 'native P6 runner pin unavailable'
p5=/var/tmp/fi-window-chunks-family-p3-20261116T123717Z
p6=/var/tmp/fi-window-chunks-family-p3-20261116T230127Z
[ -s "$p5/SUMMARY.txt" ] && [ -s "$p6/SUMMARY.txt" ] ||
  fail 'P5/P6 accepted baseline missing'
grep -Fxq 'FI C220 W512 PERSISTENT P5 TWO-WINDOW ACCEPTED windows=2 new_records=997434 elapsed=3m57.995s min_workers=2 max_workers=16 max_slots=80 credits=32 writer=1 authoritative=0 accepted=0' "$p5/SUMMARY.txt" ||
  fail 'P5 signed performance baseline changed'
grep -Fxq 'FI C220 W512 ATOMIC FAMILY P6 TWO-WINDOW ACCEPTED windows=2 new_records=997434 elapsed=4m7.626s min_workers=2 max_workers=16 max_slots=80 credits=32 writer=1 authoritative=0 accepted=0' "$p6/SUMMARY.txt" ||
  fail 'P6 accepted source/relational performance baseline changed'
runroot=/var/tmp/fi-c1-five-family-$(date -u '+%Y%m%dT%H%M%SZ')
[ ! -e "$runroot" ] && [ ! -L "$runroot" ] || fail 'private C1 output path collision'
mkdir -m 0700 "$runroot"
runner="$runroot/pinned-c1-p6.sh"
jexec -U jwood fi-dev git -C "$repo" show "$runnerpin:$runnerpath" > "$runner" ||
  fail 'pinned P6-native runner missing'
chmod 0700 "$runner"
sh -n "$runner" || fail 'C1 P6-native runner shell syntax invalid'
grep -Fxq "sourcecommit=$sourcepin" "$runner" &&
grep -Fq 'go127 test -race' "$runner" &&
grep -Fq 'TestPrivateC1' "$runner" &&
grep -Fq 'private_c1_direct.go' "$runner" &&
grep -Fq 'TestPrivateC1' "$runner" &&
grep -Fq 'FI C1 CLEAN START PASS' "$runner" &&
grep -Fq 'C1_SECURITY_COPY.txt' "$runner" &&
grep -Fq 'FI C1 NATIVE P6 DIRECT SOURCE PASS p7_bridge=none source_stage=none' "$runner" &&
grep -Fq 'FI C1 P6 FIVE SQL PASS' "$runner" &&
grep -Fq 'FI C220 C1 P5-P6 NATIVE FAMILY ACCEPTED' "$runner" ||
  fail 'native P6 SQL or signed record acceptance scripts mismatched'
export FI_W512_P6_FAMILY_SQL=1
export FI_W512_P5_PERSISTENT=1
export FI_W512_P3_DYNAMIC_MIN=2
export FI_W512_P3_DYNAMIC_MAX=16
unset FI_W512_P7_SQL_WRITERS FI_W512_P8_REUSE FI_W512_P9_DIRECT_STREAM
unset FI_W512_P3_SECURITY_WORKERS FI_W512_P3_GENERAL_WORKERS
sh "$runner" preflight "$2" ||
  fail 'original P6 seed/source preflight rejected'
printf 'FI C1 NATIVE P6 PREFLIGHT PASS source=%s runner=%s postgres_started=false\n' "$sourcepin" "$runnerpin"
[ "$mode" = preflight ] && exit 0
if [ "$mode" = compile ]; then
  compilelog="$runroot/C1.compile.txt"
  if ! sh "$runner" compile "$2" > "$compilelog" 2>&1; then
    tail -n 100 "$compilelog" >&2 || :
    fail 'C1 private Go and race tests failed; no database started'
  fi
  cat "$compilelog"
  grep -Fxq 'FI C1 C220 PRIVATE GO/RACE GATE PASS original_seed_unchanged=true postgres_started=false' "$compilelog" ||
    fail 'C1 no-database compile receipt missing'
  echo 'FI C1 C220 GO/RACE COMPILE ACCEPTED original_seed_unchanged=true postgres_started=false'
  exit 0
fi
log="$runroot/C1.console.txt"
status="$runroot/C1.exit"
( if sh "$runner" family "$2";then printf '0\n' > "$status";else printf '1\n' > "$status";fi ) 2>&1 | tee "$log"
[ -s "$status" ] && [ "$(cat "$status")" = 0 ] ||
  fail 'native P6 five-writer Go build, signed stream, relational or clone acceptance failed'
receipt=$(grep '^FI W512 PILOT FINISHED exit=0 outputs=' "$log" | tail -n 1)
[ -n "$receipt" ] || fail 'C1 private SQL shutdown receipt missing'
out=$(printf '%s\n' "$receipt" | sed -n 's/.* outputs=\([^ ]*\) private_clone=.*/\1/p')
case "$out" in /var/tmp/fi-window-chunks-family-p3-*) :;;
 *) fail 'untrusted C1 private SQL output location';;esac
grep -Fq 'FI C220 C1 P5-P6 NATIVE FAMILY ACCEPTED windows=2 records=997434 ' "$out/SUMMARY.txt" ||
  fail 'native five-writer direct benchmark acceptance missing'
for f in C1_READ.txt C1_BACKENDS.txt C1_FAMILIES.txt C1_PREP.txt C1_P5_LANES.txt C1_SQL_PROFILE.txt C1_SECURITY_COPY.txt RESULT.txt WINDOWS.txt;do
  [ -s "$out/clone-w512-2g/$f" ] || fail "C1 metrics missing $f"
  cp "$out/clone-w512-2g/$f" "$runroot/$f"
done
# C1 is an unreleased DEVELOPMENT implementation, not a competition
# between historical performance experiments. The only success criteria
# here are signed data, five-family relational correctness and clean SQL
# shutdown. The historical P5/P6 receipts above only pin the original input.
cat "$runroot/C1_FAMILIES.txt"
printf 'FI C1 DEVELOPMENT INTEGRATION PASS windows=2 records=997434 sql_family_writers=5 source_parent_writers=1 clean_start=true source_staging=none authoritative=0 published=0 output=%s\n' "$runroot"
