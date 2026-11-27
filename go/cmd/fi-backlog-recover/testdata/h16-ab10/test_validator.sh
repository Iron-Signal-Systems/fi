#!/bin/sh
# Synthetic shell-contract test; NOT real signed FreeBSD/SQL acceptance.
set -eu
validator=go/cmd/fi-backlog-recover/testdata/h16-ab10/validate_signed_ab10.sh
test_variant() (
 variant=$1
 stamp=20261113T000000Z
 out=$(mktemp -d "/var/tmp/fi-window-chunks-ab10-$variant-contract-XXXXXXXX")
 name=clone-11-08-26
 cache="$out/verified-cache"
 mkdir -p "$out/$name/private/receipt-test" "$cache/receipt-test"
 trap 'rm -rf "$out"' EXIT
 fail(){ printf 'SYNTHETIC AB10 FAILURE: %s\n' "$*" >&2; exit 1; }
 stop_host_monitors(){ :; }
 snapshot_pg(){ printf '{}\n' > "$out/$name/pg_stat_wal_$1.jsonl"; printf '{}\n' > "$out/$name/pg_stat_io_$1.jsonl"; printf '{}\n' > "$out/$name/pg_stat_checkpointer_$1.jsonl"; printf 'stats\n' > "$out/$name/pg_$1.txt"; }
 snapshot_relations(){ printf '{}\n' > "$out/$name/relations_$1.jsonl"; }
 sql(){
   case "$1" in
     *"coalesce(sum(committed_records),0)::text"* ) printf '13|1688152|12\n' ;;
     *"sum(end_batch-start_batch)"* ) printf '566\n' ;;
     *"window_index BETWEEN 3 AND 12"* )
       if printf '%s' "$1" | grep -q 'chr(9)'; then
         w=3
         while [ "$w" -le 12 ];do
           if [ "$w" -eq 3 ];then n=129435
           elif [ "$w" -eq 4 ];then n=129743
           elif [ "$w" -eq 12 ];then n=129714
           else n=129839;fi
           printf '%s\t%s\n' "$w" "$n"
           w=$((w+1))
         done
       else printf '1297765\n';fi ;;
     *"SELECT CASE WHEN"* ) printf 'PASS\n' ;;
     *"w0000(0[3-9]|1[0-2])"* ) printf '10|10\n' ;;
     *"w00000[1-2]"* ) printf '2|0\n' ;;
     * ) fail "unexpected mocked SQL: $1" ;;
   esac
 }
 printf 'synthetic\n' > "$out/RUN_MANIFEST.txt"
 printf 'start\n' > "$out/SUMMARY.txt"
 printf 'preflight\n' > "$out/security-real-signed-preflight-summary.txt"
 printf '{}\n{}\n{}\n' > "$out/$name/pg_5sec_samples.jsonl"
 printf 'cpu samples\n' > "$out/$name/host-vmstat.txt"
 printf 'disk samples\n' > "$out/$name/host-iostat.txt"
 printf 'settings\n' > "$out/$name/pg_settings.txt"
 snapshot_pg before
 snapshot_relations before
 {
 printf 'FI PRIVATE HASH COPY EXPERIMENT profile=F3H16 max_rows=16384 max_bytes=16777216 other_F3_limits=unchanged\n'
 [ "$variant" != five ] || printf 'FI PRIVATE FIVE LANE ENABLED\n'
 w=3
 while [ "$w" -le 12 ];do
   if [ "$w" -eq 3 ];then rec=129435;ev=116357;dep=0;av=51
   elif [ "$w" -eq 4 ];then rec=129743;ev=116522;dep=29;av=53
   elif [ "$w" -eq 12 ];then rec=129714;ev=116400;dep=0;av=0
   else rec=129839;ev=116400;dep=0;av=0;fi
   printf 'FI REAL TYPED WINDOW index=%s records=%s security_events=%s security_fields=1630000\n' "$w" "$rec" "$ev"
   printf 'FI PRIVATE STAGE PROFILE index=%s security_single_pass_rows=%s\n' "$w" "$ev"
   if [ "$w" -eq 3 ];then batches=54
   elif [ "$w" -eq 12 ];then batches=56
   else batches=57;fi
   printf 'FI PRIVATE BATCH HASH ONCE window=%s trusted_batches=%s\n' "$w" "$batches"
   printf 'FI PRIVATE H16 COMBINED BUFFER ROUTE window=%s\n' "$w"
   printf 'FI PRIVATE BUFFER ROUTE WINDOW START window=%s\n' "$w"
   printf 'FI PRIVATE DEPENDENCY BUFFER PROOF window=%s dependency_records=%s security_event_copy_calls=30 security_source_copy_calls=30 coverage_security_flushes_avoided=%s\n' "$w" "$dep" "$av"
   [ "$variant" != five ] || printf 'FI PRIVATE FIVE LANE PROOF window=%s file_source_drains=2 deferred_file_projection=2 W128_atomic=true\n' "$w"
   printf 'FI DEFERRED ARTIFACT PUBLISHED window=%s\n' "$w"
   printf 'FI REAL BACKLOG DURABLE window=%s/117\n' "$((w+1))"
   printf 'FI TYPED CHUNK COMMITTED window=%s\n' "$w"
   mkdir -p "$out/$name/private/receipt-test/window-$w"
   i=1
   while [ "$i" -le "$batches" ];do
     id=$((w*1000+i))
     printf 'batch-%s\n' "$id" > "$cache/receipt-test/batch-$id.data"
     printf 'manifest-%s\n' "$id" > "$cache/receipt-test/batch-$id.manifest"
     cp "$cache/receipt-test/batch-$id.data" "$out/$name/private/receipt-test/window-$w/batch-$id.data"
     cp "$cache/receipt-test/batch-$id.manifest" "$out/$name/private/receipt-test/window-$w/batch-$id.manifest"
     i=$((i+1))
   done
   w=$((w+1))
 done
 printf 'FI PRIVATE EXACT WINDOW STOP start=3 windows=10 last=12 records=1297765 committed_window_time=8m0s authoritative=0 accepted=0\n'
 printf '    490.30 real    223.40 user    45.10 sys\n'
 printf '    431780 maximum resident set size\n'
 } > "$out/$name/recover.log"
 . "$validator"
 [ -s "$bundle" ] || fail 'no metrics bundle'
 printf 'FI SYNTHETIC AB10 VERIFIER PASS variant=%s\n' "$variant"
)
test_variant combined
test_variant five
