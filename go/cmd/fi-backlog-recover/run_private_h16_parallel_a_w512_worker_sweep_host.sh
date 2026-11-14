#!/bin/sh
# FI W512 H16: four signed private recovery trials, preparation workers
# 2,4,8,16 with one CONSTANT 32-record credit budget and ONE SQL writer.
# Same original 997,434 records (W512 windows 1-2), same 8GB max WAL,
# wal_buffers=4MB, durability ON, IO timing ON, K32, P3, F3H16.
# All clones start independently from the stopped accepted W512 index-0 seed.
# No authoritative/canonical/Accepted changes and no W128 checkpoint.
set -eu
umask 077
fail() { printf 'FI W512 WORKER SWEEP STOP: %s\n' "$*" >&2; exit 1; }
[ "$(id -un)" = root ] && [ "$#" -eq 1 ] && [ "$1" = h16 ] ||
    fail 'run as root on fi-backend-b with exactly h16'
for command in jls jexec git sha256 awk grep sed cmp ps; do
    command -v "$command" >/dev/null 2>&1 ||
        fail "required command missing: $command"
done
jailroot=$(jls -j fi-dev path) || fail 'fi-dev jail missing'
devjid=$(jls -j fi-dev jid) || fail 'fi-dev JID missing'
sorjid=$(jls -j fi-sor-db jid) || fail 'fi-sor-db JID missing'
[ "$devjid" != "$sorjid" ] || fail 'FI dev and authoritative SoR jails match'
jexec fi-sor-db service postgresql status >/dev/null 2>&1 ||
    fail 'authoritative SoR must be available and untouched'
existing=$(ps -axww -o pid,jid,user,rss,command | awk -v jid="$devjid" '
    $2==jid && $5=="/usr/local/bin/postgres" && $6=="-D" {n++}
    END {print n+0}')
[ "$existing" = 0 ] ||
    fail 'PostgreSQL already running in fi-dev; no worker sweep started'
seed=/home/jwood/fi-window-bench-w512-20261113T205026Z
evidence=/var/tmp/fi-window-chunks-h16-w512-seed-20261113T205026Z
[ -d "$jailroot$seed/optimized-source/go/internal/recordingest" ] ||
    fail 'accepted W512 pinned source missing'
[ -d "$jailroot$seed/clone-w512-2g/data" ] ||
    fail 'accepted W512 private seed database missing'
jexec -U jwood fi-dev pg_ctl -D "$seed/clone-w512-2g/data" status >/dev/null 2>&1 &&
    fail 'accepted W512 seed database must remain stopped'
[ "$(sha256 -q "$evidence/fi-w512-private-seed-20261113T205026Z.tar.gz")" = \
  77d378fad4fd8a4cb0cee6e4f9c46bce644590de1fda7d818a5ab8891e6489ce ] ||
    fail 'accepted seed evidence digest changed'
[ "$(cat "$evidence/clone-w512-2g/W512_SEED_CHECKPOINT.tsv")" = \
  '0|493478|ff58478b40ca35f1f6cc5e52aa0300de6371ed58243c41f34e4f20ad6d61a319' ] ||
    fail 'accepted W512 signed first-window descriptor changed'
stamp=$(date -u '+%Y%m%dT%H%M%SZ')
suite=/var/tmp/fi-window-chunks-h16-w512-worker-sweep-$stamp
[ ! -e "$suite" ] || fail 'worker sweep result path collision'
mkdir -m 700 "$suite" || fail 'worker suite output init failed'
ref=2d75d29509f371e069891ae655dbc4a09d5d1354
baseline=b4364e0de3c1267545748ca739895a737c871a2c
patcher=go/cmd/fi-backlog-recover/patchers/w512_worker_sweep/main.go
pilot=go/cmd/fi-backlog-recover/run_private_h16_parallel_a_w512_wal_w8g_host.sh
echo "FI W512 WORKER SWEEP START workers=2,4,8,16 credits=32 fixed_wal=8GB fixed_writer=1 signed_windows=1,2 output=$suite"
echo 'workers,records,elapsed_seconds,records_per_second,postgresql_max_wal_size,credits,sql_writers,wal_bytes,requested_checkpoints,cpu_seconds,max_rss_kib' \
    > "$suite/RESULTS.csv"
for workers in 2 4 8 16; do
    stage=/home/jwood/fi-window-bench-w512-worker$workers-$stamp
    result=/var/tmp/fi-window-chunks-h16-w512-sweep-w$workers-$stamp
    [ ! -e "$jailroot$stage" ] && [ ! -e "$result" ] ||
        fail "W512 $workers-worker disposable destination collision"
    echo "===== FI W512 SWEEP WORKERS=$workers BUILD ====="
    # Read-only Git checkout: exact pinned Git objects only, copied into
    # disposable private source. Never modify original fi-dev repo or seed.
    jexec -U jwood fi-dev sh -s "$seed" "$stage" "$workers" "$ref" "$baseline" "$patcher" "$pilot" <<'JAIL'
set -eu
umask 077
seed=$1
stage=$2
workers=$3
ref=$4
baseline=$5
patcher=$6
pilot=$7
[ "$(id -un)" = jwood ] || exit 1
repo=/home/jwood/src/fi
[ ! -e "$stage" ] || exit 1
git -C "$repo" cat-file -e "$ref^{commit}" || exit 1
git -C "$repo" cat-file -e "$baseline^{commit}" || exit 1
[ "$(git -C "$repo" rev-parse "$ref:$patcher")" = \
  e85580c4452a5650b8cd8a0ddab6acdb1987fb9b ] || exit 1
[ "$(git -C "$repo" rev-parse "$baseline:$pilot")" = \
  604c201e3f14ecd779bff0bf5152a1c278afe8ee ] || exit 1
mkdir -m 700 "$stage" || exit 1
cp -R "$seed/optimized-source" "$stage/optimized-source" || exit 1
git -C "$repo" show "$baseline:$pilot" > "$stage/pilot-worker$workers.sh" || exit 1
[ "$(git -C "$repo" hash-object "$stage/pilot-worker$workers.sh")" = \
  604c201e3f14ecd779bff0bf5152a1c278afe8ee ] || exit 1
mkdir -p "$stage/optimized-source/go/cmd/fi-backlog-recover/patchers/w512_worker_sweep"
git -C "$repo" show "$ref:$patcher" > "$stage/optimized-source/$patcher" || exit 1
[ "$(git -C "$repo" hash-object "$stage/optimized-source/$patcher")" = \
  e85580c4452a5650b8cd8a0ddab6acdb1987fb9b ] || exit 1
(cd "$stage/optimized-source/go" &&
  GOTOOLCHAIN=auto go run ./cmd/fi-backlog-recover/patchers/w512_worker_sweep/main.go "$stage" "$workers") || exit 1
(cd "$stage/optimized-source/go" &&
  gofmt -w ./internal/recordingest/private_parallel_preparation.go \
    ./internal/recordingest/postgres_ingest.go \
    ./cmd/fi-backlog-recover/main_freebsd.go) || exit 1
(cd "$stage/optimized-source/go" &&
  GOTOOLCHAIN=auto go test -count=1 -timeout=180s ./internal/recordingest \
    -run '^TestPrivateParallelA') || exit 1
(cd "$stage/optimized-source/go" &&
  GOTOOLCHAIN=auto go build -o "$stage/fi-optfield-recover-w$workers" ./cmd/fi-backlog-recover) || exit 1
sha256 -q "$stage/fi-optfield-recover-w$workers" > "$stage/fi-optfield-recover-w$workers.sha256"
sh -n "$stage/pilot-worker$workers.sh" || exit 1
grep -Eq "privateParallelAPreparers[[:space:]]+=[[:space:]]+$workers" \
  "$stage/optimized-source/go/internal/recordingest/private_parallel_preparation.go" || exit 1
grep -Fq 'privateParallelAMaxInFlight = 32' \
  "$stage/optimized-source/go/internal/recordingest/private_parallel_preparation.go" || exit 1
grep -Fq "workers=$workers inflight=32 postgres_writers=1 source_window=%s atomic=true" \
  "$stage/optimized-source/go/cmd/fi-backlog-recover/main_freebsd.go" || exit 1
grep -Fq "workers=$workers inflight_limit=32 writers=1" \
  "$stage/optimized-source/go/internal/recordingest/postgres_ingest.go" || exit 1
grep -Fq "f[\"workers\"]!=$workers||f[\"inflight_limit\"]!=32" \
  "$stage/pilot-worker$workers.sh" || exit 1
grep -Fq 'f["reorder_peak"]+0>31' "$stage/pilot-worker$workers.sh" || exit 1
printf 'FI W512 WORKER SWEEP BUILD PASS workers=%s credits=32 postgres_writers=1 W512_source=accepted signed_seed=untouched binary_sha256=%s\n' \
  "$workers" "$(cat "$stage/fi-optfield-recover-w$workers.sha256")"
JAIL
    runner="$jailroot$stage/pilot-worker$workers.sh"
    [ -f "$runner" ] && [ ! -L "$runner" ] ||
        fail "W512 $workers-worker pilot missing"
    echo "===== FI W512 SWEEP WORKERS=$workers SIGNED REPLAY ====="
    FI_WAL_AB_STAMP="$stamp" sh "$runner" h16 ||
        fail "W512 $workers-worker signed replay failed; do not compare incomplete sweep"
    summary="$result/SUMMARY.txt"
    [ -f "$summary" ] &&
    grep -Fq "FI W512 WORKER $workers PILOT ACCEPTED windows=2 new_records=997434 elapsed=" "$summary" ||
        fail "W512 $workers-worker SQL acceptance missing"
    grep -Fq 'FI W512 SIGNED READBACK PASS batches=431 byte_identical=true manifests_identical=true' "$summary" ||
        fail "W512 $workers-worker signed byte readback missing"
    d="$result/clone-w512-2g"
    [ -s "$d/W512_CHECKPOINTS.tsv" ] &&
    [ "$(wc -l < "$d/W512_CHECKPOINTS.tsv" | tr -d ' ')" = 3 ] ||
        fail "W512 $workers-worker typed-window checkpoint evidence missing"
    for setting in max_wal_size=8GB wal_buffers=4MB track_io_timing=on track_wal_io_timing=on \
        fsync=on synchronous_commit=on full_page_writes=on; do
        grep -Fqx "$setting" "$d/pg_settings.txt" ||
            fail "W512 worker $workers actual PostgreSQL setting differs: $setting"
    done
    if [ "$workers" = 2 ]; then
        cp "$d/W512_CHECKPOINTS.tsv" "$suite/REFERENCE_CHECKPOINTS.tsv" ||
            fail 'cannot preserve reference signed descriptors'
    else
        cmp -s "$d/W512_CHECKPOINTS.tsv" "$suite/REFERENCE_CHECKPOINTS.tsv" ||
            fail "W512 worker $workers committed different signed source or SQL descriptor"
    fi
    elapsed=$(awk -v w="$workers" '
        function toseconds(s, total,n,p,u) {
            total=0
            while(length(s)>0) {
                if(!match(s,/^[0-9]+([.][0-9]+)?(h|m|s)/)) exit 2
                n=RLENGTH; p=substr(s,1,n); u=substr(p,n,1)
                if(u=="h") total+=(p+0)*3600
                if(u=="m") total+=(p+0)*60
                if(u=="s") total+=(p+0)
                s=substr(s,n+1)
            }
            return total
        }
        index($0,"FI W512 WORKER " w " PILOT ACCEPTED windows=2 new_records=997434 elapsed=")==1 {
            for(i=1;i<=NF;i++) if($i~/^elapsed=/) {
                split($i,a,"=");printf "%.6f",toseconds(a[2]);seen++
            }
        }
        END{if(seen!=1)exit 3}
    ' "$summary") || fail "W512 $workers-worker elapsed parser rejected"
    counters=$(awk '
       FNR==1 && NR==1 { }
       /"wal_bytes":/ {
            if(match($0,/"wal_bytes":[0-9]+/)) {
                n=substr($0,RSTART,RLENGTH)
                sub(/^"wal_bytes":/,"",n)
                value=n+0
                if(FILENAME ~ /wal_before/) before=value
                if(FILENAME ~ /wal_after/) after=value
            }
       }
       END { if(after<before || before==0)exit 3; printf "%.0f",after-before}
    ' "$d/wal_before.jsonl" "$d/wal_after.jsonl") ||
        fail "W512 $workers-worker WAL accounting invalid"
    checkpoints=$(awk '
        /"num_requested":/ {
           if(match($0,/"num_requested":[0-9]+/)) {
              v=substr($0,RSTART,RLENGTH)
              sub(/^"num_requested":/,"",v)
              if(FILENAME ~ /before/) b=v+0
              if(FILENAME ~ /after/) a=v+0
           }
        }
        END{if(a<b)exit 3;printf "%.0f",a-b}
    ' "$d/checkpointer_before.jsonl" "$d/checkpointer_after.jsonl") ||
        fail "W512 $workers-worker checkpoint accounting invalid"
    # FreeBSD /usr/bin/time -l records CPU time and peak process RSS.
    # Compare resource COST as well as throughput. These are process-only
    # metrics; the PostgreSQL worker processes are accounted for separately
    # in pg_stat_io and WAL/checkpoint counters.
    cpu_seconds=$(awk '
        $2=="real" && $4=="user" && $6=="sys" {
            total=($3+0)+($5+0)
            seen++
        }
        END {if(seen!=1)exit 4;printf "%.3f",total}
    ' "$d/recover.log") || fail "W512 worker $workers CPU time missing"
    peak_rss=$(awk '
        $2=="maximum" && $3=="resident" && $4=="set" && $5=="size" {
            value=$1+0
            seen++
        }
        END {if(seen!=1)exit 4;printf "%.0f",value}
    ' "$d/recover.log") || fail "W512 worker $workers max RSS missing"
    awk -v w="$workers" -v sec="$elapsed" -v wb="$counters" -v chk="$checkpoints" \
        -v cpu="$cpu_seconds" -v rss="$peak_rss" '
        BEGIN {
            if(sec<=0||cpu<=0||rss<=0)exit 4
            printf "%d,997434,%.6f,%.2f,8GB,32,1,%s,%s,%.3f,%s\n",
                w,sec,997434/sec,wb,chk,cpu,rss
            printf "FI W512 WORKER RESULT workers=%d records=997434 elapsed=%.3fs throughput=%.2f records_per_second WAL_bytes=%s checkpoints=%s recovery_cpu_seconds=%.3f max_rss_kib=%s\n",
                w,sec,997434/sec,wb,chk,cpu,rss > "/dev/stderr"
        }
    ' >> "$suite/RESULTS.csv" || fail 'worker sweep performance comparison calculation failed'
    cp "$summary" "$suite/SUMMARY-worker$workers.txt" ||
        fail "worker $workers acceptance archive failed"
done
[ "$(wc -l < "$suite/RESULTS.csv" | tr -d ' ')" = 5 ] ||
    fail 'four workers plus header must appear in result table'
echo '===== FI W512 WORKER SWEEP FINAL CSV ====='
cat "$suite/RESULTS.csv"
printf 'FI W512 WORKER SWEEP ACCEPTED workers=2,4,8,16 credits=32 WAL=8GB K32=32768 postgres_writers=1 signed_checkpoint_hashes_identical=true authoritative=0 accepted=0 output=%s\n' "$suite"
