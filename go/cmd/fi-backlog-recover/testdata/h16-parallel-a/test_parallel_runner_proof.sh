#!/bin/sh
# Executes the EXACT Candidate A W3/W4 proof section from the host runner
# under inert local inputs. Prevents shell/awk failures that sh -n misses.
set -eu
runner=go/cmd/fi-backlog-recover/run_private_h16_parallel_a_w34_host.sh
[ -f "$runner" ] || exit 1
sh -n "$runner"
work=$(mktemp -d)
trap 'rm -rf "$work"' 0
mkdir -p "$work/clone-11-08-26"
name=clone-11-08-26
out=$work
export name out
log="$out/$name/recover.log"
set +e
awk '
 /^# Require proof that the parallel code actually processed ALL/ { active=1 }
 active && /^stop_host_monitors$/ { exit }
 active { print }
' "$runner" > "$work/proof.sh"
set -e
[ "$(grep -c '^proof_message=$(awk ' "$work/proof.sh")" -eq 1 ] ||
    { echo 'FI parallel proof test: cannot extract source proof' >&2; exit 1; }
sh -n "$work/proof.sh"
fail(){ printf 'FI candidate A synthetic proof STOP: %s\n' "$*" >&2; exit 1; }
echo 'starting synthetic proof checks' > "$out/SUMMARY.txt"

# Generate 111 unique signed batch identities with exact aggregate counts.
# Synthetics test the acceptance contract, not FI signed-data correctness.
{
  i=1
  while [ "$i" -le 111 ]; do
     if [ "$i" -eq 111 ]; then rows=39178; else rows=2000; fi
     printf 'FI PRIVATE PARALLEL PREP BATCH batch=fixture-%03d workers=2 inflight_limit=4 writers=1 records=%d read=1ms worker_prepare=2ms writer_wait=0s reordered=0 reorder_peak=0\n' "$i" "$rows"
     i=$((i+1))
  done
} > "$log"
. "$work/proof.sh"
grep -Fq 'FI H16 PARALLEL A SIGNED PREP PROOF PASS batches=111 rows=259178' "$out/SUMMARY.txt" ||
  { echo 'FI candidate A synthetic proof: correct input not accepted' >&2; exit 1; }

# Test the genuine source proof separately in a subprocess so that expected
# failure cannot terminate this verification suite.
cp "$log" "$work/good.log"
sed '1s/workers=2/workers=3/' "$work/good.log" > "$log"
if sh -c '
    fail(){ exit 1; }
    name=clone-11-08-26
    out=$1
    log="$out/$name/recover.log"
    . "$out/proof.sh"
' sh "$out" >/dev/null 2>&1; then
    echo 'FI candidate A synthetic proof: invalid worker count accepted' >&2
    exit 1
fi
sed -n '1,110p' "$work/good.log" > "$log"
if sh -c '
    fail(){ exit 1; }
    name=clone-11-08-26
    out=$1
    log="$out/$name/recover.log"
    . "$out/proof.sh"
' sh "$out" >/dev/null 2>&1; then
    echo 'FI candidate A synthetic proof: dropped signed batch accepted' >&2
    exit 1
fi
printf 'FI H16 PARALLEL A PROOF SHELL CONTRACT PASS exact_111=true signed_rows=259178 corrupt_worker_rejected=true missing_batch_rejected=true\n'
