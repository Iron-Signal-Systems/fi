#!/bin/sh
# FI W512 1GiB-vs-8GiB PostgreSQL WAL checkpoint A/B:
# same ORIGINAL receiver-admitted signed windows W1/W2; new private seed copy
# per arm; two preparation workers, four in-flight records, one SQL writer.
# Both arms enable track_io_timing and track_wal_io_timing. Never production.
set -eu
umask 077
fail() { printf 'FI W512 WAL AB STOP: %s\n' "$*" >&2; exit 1; }
[ "$(id -un)" = root ] && [ "$#" -eq 1 ] && [ "$1" = h16 ] ||
    fail 'run as root on fi-backend-b with exactly h16'
jailroot=$(jls -j fi-dev path) || fail 'fi-dev missing'
devjid=$(jls -j fi-dev jid) || fail 'fi-dev JID missing'
sorjid=$(jls -j fi-sor-db jid) || fail 'fi-sor-db JID missing'
[ "$devjid" != "$sorjid" ] || fail 'SoR and dev jails match'
jexec fi-sor-db service postgresql status >/dev/null 2>&1 ||
    fail 'authoritative SoR PostgreSQL unavailable'
stamp=$(date -u '+%Y%m%dT%H%M%SZ')
arm1=/home/jwood/fi-h16-parallel-a-w512-wal1g.sh
arm8=/home/jwood/fi-h16-parallel-a-w512-wal8g.sh
sha1=9e150d4e1186d25775ed9b232c17bb8b29de5b77
sha8=604c201e3f14ecd779bff0bf5152a1c278afe8ee
for spec in "$sha1 $arm1" "$sha8 $arm8"; do
    set -- $spec
    [ -f "$jailroot$2" ] && [ ! -L "$jailroot$2" ] ||
        fail "pinned A/B arm missing or symlink: $2"
    actual=$(jexec -U jwood fi-dev git hash-object "$2") ||
        fail "cannot verify pinned A/B arm: $2"
    [ "$actual" = "$1" ] ||
        fail "incorrect A/B runner source: $2"
    sh -n "$jailroot$2" || fail "A/B arm shell syntax invalid: $2"
done
for label in w1g w8g; do
    case "$label" in
        w1g) script="$jailroot$arm1"; setting=1GB ;;
        w8g) script="$jailroot$arm8"; setting=8GB ;;
        *) fail 'unrecognized WAL arm' ;;
    esac
    result=/var/tmp/fi-window-chunks-h16-w512-$label-$stamp
    [ ! -e "$result" ] ||
        fail "result path collision: $result"
    echo "===== W512 WAL A/B $setting START ====="
    FI_WAL_AB_STAMP="$stamp" sh "$script" h16 ||
        fail "W512 WAL $setting failed; do not compare failed arms"
    summary="$result/SUMMARY.txt"
    [ -s "$summary" ] || fail "W512 WAL $setting summary missing"
    grep -Fq "FI W512 WAL $setting PILOT ACCEPTED windows=2 new_records=997434 elapsed=" "$summary" ||
        fail "W512 WAL $setting SQL, record-count, or signed replay acceptance missing"
    [ -s "$result/clone-w512-2g/W512_CHECKPOINTS.tsv" ] ||
        fail "W512 WAL $setting source descriptor matrix missing"
    [ -s "$result/clone-w512-2g/pg_settings.txt" ] ||
        fail "W512 WAL $setting PG settings evidence missing"
    for prop in "max_wal_size=$setting" wal_buffers=4MB track_io_timing=on track_wal_io_timing=on fsync=on synchronous_commit=on full_page_writes=on; do
        grep -Fqx "$prop" "$result/clone-w512-2g/pg_settings.txt" ||
            fail "W512 WAL $setting actual PG configuration evidence differs: $prop"
    done
    echo "===== W512 WAL A/B $setting ACCEPTED ====="
done
first=/var/tmp/fi-window-chunks-h16-w512-w1g-$stamp
second=/var/tmp/fi-window-chunks-h16-w512-w8g-$stamp
cmp -s "$first/clone-w512-2g/W512_CHECKPOINTS.tsv" \
       "$second/clone-w512-2g/W512_CHECKPOINTS.tsv" ||
    fail 'W512 1GB and 8GB typed-window hashes or record counts differ'
[ "$(wc -l < "$first/clone-w512-2g/W512_CHECKPOINTS.tsv" | tr -d ' ')" = 3 ] ||
    fail 'W512 WAL A/B SQL checkpoint matrix incomplete'
printf 'FI W512 WAL AB SOURCE MATRIX PASS windows=3 signed_descriptors_identical=true source_records_1_2=997434 seed_unchanged=true\n'

field(){
    line=$1
    key=$2
    printf '%s\n' "$line" | sed -n "s/.*\"$key\":\([0-9][0-9]*\).*/\1/p"
}
elapsed(){
    awk -v setting="$1" '
    function seconds(s, n, seg, u, v, total) {
       total=0
       while (length(s)>0) {
          if (!match(s,/^[0-9]+([.][0-9]+)?(h|m|s)/)) exit 3
          n=RLENGTH
          seg=substr(s,1,n);u=substr(seg,n,1);v=seg+0
          if(u=="h") total+=v*3600
          if(u=="m") total+=v*60
          if(u=="s") total+=v
          s=substr(s,n+1)
       }
       return total
    }
    index($0,"FI W512 WAL " setting " PILOT ACCEPTED windows=2 new_records=997434 elapsed=")==1 {
       for(i=1;i<=NF;i++) if($i~/^elapsed=/) {
           split($i,a,"=")
           printf "%.6f",seconds(a[2])
           found=1
       }
    }
    END {if(!found)exit 2}
    ' "$2"
}
sec1=$(elapsed 1GB "$first/SUMMARY.txt") ||
    fail 'W512 1GB elapsed conversion failed'
sec8=$(elapsed 8GB "$second/SUMMARY.txt") ||
    fail 'W512 8GB elapsed conversion failed'
awk -v a="$sec1" -v b="$sec8" '
BEGIN {
 if(a<=0||b<=0)exit 3
 printf "FI W512 WAL AB PERF records=997434 one_gib_seconds=%.3f one_gib_records_per_second=%.2f eight_gib_seconds=%.3f eight_gib_records_per_second=%.2f delta_seconds=%.3f speedup_percent=%.2f\n",
  a,997434/a,b,997434/b,b-a,100*(a/b-1)
}' || fail 'W512 WAL A/B performance calculation failed'

for label in w1g w8g; do
    case "$label" in w1g) dir="$first";; w8g) dir="$second";; esac
    d="$dir/clone-w512-2g"
    walbefore=$(cat "$d/wal_before.jsonl")
    walafter=$(cat "$d/wal_after.jsonl")
    cpbefore=$(cat "$d/checkpointer_before.jsonl")
    cpafter=$(cat "$d/checkpointer_after.jsonl")
    bbytes=$(field "$walbefore" wal_bytes)
    abytes=$(field "$walafter" wal_bytes)
    bfull=$(field "$walbefore" wal_buffers_full)
    afull=$(field "$walafter" wal_buffers_full)
    breq=$(field "$cpbefore" num_requested)
    areq=$(field "$cpafter" num_requested)
    case "$bbytes:$abytes:$bfull:$afull:$breq:$areq" in
        *[!0-9:]*|:*) fail "invalid WAL counters for $label" ;;
    esac
    [ "$abytes" -ge "$bbytes" ] &&
    [ "$afull" -ge "$bfull" ] &&
    [ "$areq" -ge "$breq" ] ||
        fail "nonmonotonic PostgreSQL WAL/checkpoint counters: $label"
    printf 'FI W512 WAL AB PG COUNTERS arm=%s wal_generated_bytes=%s wal_buffers_full=%s requested_checkpoints=%s\n' \
        "$label" "$((abytes-bbytes))" "$((afull-bfull))" "$((areq-breq))"
done
printf 'FI W512 WAL AB COMPLETE control=%s candidate=%s signed_source_identical=true authoritative=0 accepted=0\n' \
    "$first" "$second"
