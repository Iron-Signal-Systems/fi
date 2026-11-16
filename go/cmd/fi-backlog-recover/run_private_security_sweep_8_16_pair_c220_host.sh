#!/bin/sh
# FI C220 W512 isolated paired Security scheduler A/B.
# Security 8 + General 8, followed by Security 16 + General 8.
# All results use the same receiver-authenticated seed and independent clones.
# No authoritative PostgreSQL access, no live ingest, no accepted publication.
set -eu
umask 077
fail(){ printf 'FI C220 SECURITY SWEEP PAIR STOP: %s\n' "$*" >&2; exit 1; }
[ "$(id -un)" = root ] && [ "$(hostname -s)" = c220 ] && [ "$#" -eq 2 ] ||
    fail 'usage: sh pair.sh preflight|pair 20261115T153532Z'
case "$1" in preflight|pair) mode=$1 ;; *) fail 'invalid run mode' ;; esac
stamp=$2
[ "$stamp" = 20261115T153532Z ] || fail 'pair run requires the pinned accepted W512 seed'
repo=/home/jwood/fi-w512-c220-stage
branch=experiment/fi-security-sweep-8-16-w512-20261116
sourcepin=351043ee55a1876823fbe0370f7c126d8c96bc49
runnerpin=6f9dd33abdfdbd346bd2ba6d798e50dd50296046
rpath=go/cmd/fi-backlog-recover/run_private_family_w512_c220_p3_host.sh
[ -d "/fast/jails/roots/fi-dev" ] || fail 'fi-dev jail root missing'
jexec -U jwood fi-dev git -C "$repo" cat-file -e "$sourcepin^{commit}" ||
    fail 'pinned sweep source not fetched in fi-dev'
jexec -U jwood fi-dev git -C "$repo" cat-file -e "$runnerpin^{commit}" ||
    fail 'pinned sweep host runner not fetched in fi-dev'
pairroot=/var/tmp/fi-w512-security-sweep-pair-$(date -u '+%Y%m%dT%H%M%SZ')
[ ! -e "$pairroot" ] && [ ! -L "$pairroot" ] || fail 'pair output already exists'
mkdir -m 0700 "$pairroot" || fail 'cannot create pair output'
runner="$pairroot/fi-family-sweep-pinned.sh"
jexec -U jwood fi-dev git -C "$repo" show "$runnerpin:$rpath" > "$runner" ||
    fail 'cannot copy pinned clone runner'
chmod 0700 "$runner"
sh -n "$runner" || fail 'clone runner shell syntax invalid'
grep -Fxq "sourcecommit=$sourcepin" "$runner" ||
    fail 'family sweep source pin inconsistent with pair'
grep -Fxq 'port=55983' "$runner" || fail 'relay port must be the accepted 55983'
grep -Fq 'FI W512 SIGNED READBACK PASS' "$runner" ||
    fail 'signed-readback gate missing from pair'
grep -Fq 'FAMILY_LANE_SUMMARY.tsv' "$runner" ||
    fail 'per-family and per-worker acceptance gates missing'
printf 'FI C220 SECURITY SWEEP PAIR BEGIN mode=%s source=%s runner=%s output=%s\n' \
    "$mode" "$sourcepin" "$runnerpin" "$pairroot"
for sec in 8 16; do
    case "$sec" in 8) caseid=A8 ;; 16) caseid=B16 ;; esac
    export FI_W512_P3_SECURITY_WORKERS="$sec"
    export FI_W512_P3_GENERAL_WORKERS=8
    echo "===== $caseid: READ-ONLY ORIGINAL-SEED PREFLIGHT ====="
    sh "$runner" preflight "$stamp" ||
        fail "$caseid failed original-seed/source/relay preflight"
done
if [ "$mode" = preflight ]; then
    echo 'FI C220 SECURITY SWEEP PAIR PREFLIGHT PASS security=8,16 general=8 inflight=32 postgres_writers=1 no_clone_started=true'
    exit 0
fi
comparison="$pairroot/COMPARISON.tsv"
familyout="$pairroot/FAMILY_COMPARISON.tsv"
workerout="$pairroot/WORKER_COMPARISON.tsv"
printf 'run\tsecurity_workers\tgeneral_workers\tall_workers\tcredits\trecords\tseconds\trecords_per_sec\toutput\n' > "$comparison"
printf 'run\tfamily\tworkers\trecords\tbytes\tprepare_worker_seconds\tinput_wait_worker_seconds\toutput_wait_worker_seconds\tpeak_queue_depth\n' > "$familyout"
printf 'run\tfamily\tworker\trecords\tbytes\tprepare_worker_seconds\tinput_wait_worker_seconds\toutput_wait_worker_seconds\n' > "$workerout"
hostcpu="$pairroot/HOST_CPU_COMPARISON.tsv"
printf 'run\tsamples\tavg_user_cpu_pct\tavg_system_cpu_pct\tavg_idle_cpu_pct\n' > "$hostcpu"
for sec in 8 16; do
    case "$sec" in 8) caseid=A8 ;; 16) caseid=B16 ;; esac
    export FI_W512_P3_SECURITY_WORKERS="$sec"
    export FI_W512_P3_GENERAL_WORKERS=8
    echo "===== $caseid PRIVATE C220 TWO-WINDOW TEST: SECURITY $sec / GENERAL 8 ====="
    logfile="$pairroot/$caseid.console.txt"
    status="$pairroot/$caseid.exit"
    # Host shell pipelines can mask the benchmark exit code: persist the
    # FIRST process's status explicitly while tee streams live progress.
    ( if sh "$runner" family "$stamp"; then printf '0\n' > "$status"; else
          printf '1\n' > "$status"; fi ) 2>&1 | tee "$logfile"
    [ -s "$status" ] && [ "$(cat "$status")" = 0 ] ||
        fail "$caseid benchmark failed; B16 must not start unless A8 passes"
    result=$(grep '^FI W512 PILOT FINISHED exit=0 outputs=' "$logfile" | tail -n 1)
    [ -n "$result" ] || fail "$caseid completed without a successful private shutdown receipt"
    out=$(printf '%s\n' "$result" |
        sed -n 's/.* outputs=\([^ ]*\) private_clone=.*/\1/p')
    case "$out" in /var/tmp/fi-window-chunks-family-p3-*) : ;;
        *) fail "$caseid private results outside approved prefix";; esac
    [ -f "$out/SUMMARY.txt" ] || fail "$caseid SQL and signed-readback summary missing"
    grep -Fq 'FI W512 SIGNED READBACK PASS batches=431 byte_identical=true manifests_identical=true' "$out/SUMMARY.txt" ||
        fail "$caseid signed byte-for-byte readback not accepted"
    grep -Fq 'FI W512 FAMILY BREAKDOWN PASS windows=2 signed_batches=431 families=5' "$out/SUMMARY.txt" ||
        fail "$caseid per-family report not accepted"
    accepted=$(grep '^FI C220 W512 SECURITY SWEEP TWO-WINDOW ACCEPTED ' "$out/SUMMARY.txt" | tail -n 1)
    [ -n "$accepted" ] || fail "$caseid SQL/typed source window was not accepted"
    printf '%s\n' "$accepted" | grep -Fq "security_workers=$sec general_workers=8 credits=32 writer=1 authoritative=0 accepted=0" ||
        fail "$caseid dynamic worker or SQL isolation count differs"
    elapsed=$(printf '%s\n' "$accepted" | awk '{
        for(i=1;i<=NF;i++)if($i~/^elapsed=/){split($i,a,"=");print a[2]}
    }')
    seconds=$(awk -v elapsed="$elapsed" 'BEGIN{
        parts=split(elapsed,a,"m")
        if(parts!=2)exit 1
        split(a[2],b,"s")
        if((a[1]+0)<0||(b[1]+0)<0)exit 1
        printf "%.3f",a[1]*60+b[1]
    }') || fail "$caseid benchmark elapsed invalid"
    rps=$(awk -v secs="$seconds" 'BEGIN{
        if(secs<=0)exit 1
        printf "%.3f",997434/secs
    }') || fail "$caseid throughput arithmetic invalid"
    printf '%s\t%d\t8\t%d\t32\t997434\t%s\t%s\t%s\n' \
        "$caseid" "$sec" "$((sec+8))" "$seconds" "$rps" "$out" >> "$comparison"
    lanes="$out/clone-w512-2g/FAMILY_LANE_SUMMARY.tsv"
    workers="$out/clone-w512-2g/FAMILY_WORKER_SUMMARY.tsv"
    [ -s "$lanes" ] && [ -s "$workers" ] ||
        fail "$caseid individual lane/worker reports unavailable"
    awk -v run="$caseid" 'NR>1{print run "\t" $0}' "$lanes" >> "$familyout"
    awk -v run="$caseid" 'NR>1{print run "\t" $0}' "$workers" >> "$workerout"
    # FreeBSD vmstat's last three columns are us/sy/id. The first numeric
    # sample is a since-boot average, not a sample of this benchmark.
    awk -v run="$caseid" '
      NF>=3 && $NF~/^[0-9]+$/ && $(NF-1)~/^[0-9]+$/ &&
        $(NF-2)~/^[0-9]+$/ {
          if(!started++){next}
          u+=$(NF-2);sys+=$(NF-1);idle+=$NF;n++
        }
      END{
          if(n<10)exit 1
          printf "%s\t%d\t%.2f\t%.2f\t%.2f\n",
            run,n,u/n,sys/n,idle/n
      }' "$out/clone-w512-2g/vmstat.txt" >> "$hostcpu" ||
        fail "$caseid sampled host CPU utilization unavailable"
    bundle="$out/fi-w512-family-p3-pilot2-$(basename "$out" | sed 's/^fi-window-chunks-family-p3-//').tar.gz"
    [ -s "$bundle" ] || fail "$caseid metrics bundle missing"
    sha256 -q "$bundle" > "$pairroot/$caseid.bundle.sha256"
    printf '%s\n' "$out" > "$pairroot/$caseid.output-path"
    echo "FI C220 SWEEP CASE ACCEPTED run=$caseid records=997434 seconds=$seconds rps=$rps security=$sec general=8 writer=1"
done
echo '===== PAIRED THROUGHPUT COMPARISON ====='
cat "$comparison"
echo '===== PAIRED FAMILY BREAKDOWN (zero-activity families included) ====='
cat "$familyout"
echo '===== PAIRED HOST CPU USAGE (5-second vmstat samples) ====='
cat "$hostcpu"
echo "FI C220 W512 SECURITY SWEEP PAIR ACCEPTED cases=2 windows_per_case=2 source_records_per_case=997434 signed_batches_per_case=431 postgres_writers=1 original_seed_unchanged=true output=$pairroot"
