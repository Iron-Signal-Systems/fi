#!/bin/sh
# Private, shared postrun verifier for original-H16 combined/five W3-W12.
# Sourced by the host runner after the timed Go process exits successfully.
# Requires: variant, out, name, stamp, cache; host functions fail(), sql(),
# stop_host_monitors(), snapshot_pg(), snapshot_relations().
set -eu
case "$variant" in combined|five) ;; *) fail 'AB10 unknown variant' ;; esac
case "$out" in /var/tmp/fi-window-chunks-*) ;; *) fail 'AB10 unsafe output root' ;; esac
log="$out/$name/recover.log"
[ -s "$log" ] || fail 'AB10 missing timed worker log'
stop_host_monitors
[ -s "$out/$name/pg_5sec_samples.jsonl" ] ||
    fail 'AB10 missing PostgreSQL interval telemetry'
[ "$(wc -l < "$out/$name/pg_5sec_samples.jsonl" | tr -d ' ')" -ge 3 ] ||
    fail 'AB10 insufficient PostgreSQL interval samples'
[ ! -s "$out/$name/pg_samples_errors.log" ] ||
    fail 'AB10 PostgreSQL sampling failed'
[ -s "$out/$name/host-iostat.txt" ] && [ -s "$out/$name/host-vmstat.txt" ] ||
    fail 'AB10 host CPU/disk samples missing'
snapshot_pg after
snapshot_relations after

# Every indexed proof must appear exactly once in EACH of W3..W12.
check_windows() {
    label=$1
    key=$2
    awk -v label="$label" -v key="$key" '
      index($0,label)==1 {
        w=-1
        for(i=1;i<=NF;i++){split($i,a,"=");if(a[1]==key){w=a[2]+0;break}}
        if(w<3||w>12||seen[w]++)bad=1
        n++
      }
      END {
        if(n!=10)bad=1
        for(w=3;w<=12;w++)if(seen[w]!=1)bad=1
        if(bad)exit 2
      }
    ' "$log" || fail "AB10 incomplete or duplicated window proof: $label"
}
check_windows 'FI REAL TYPED WINDOW index=' index
check_windows 'FI PRIVATE STAGE PROFILE index=' index
check_windows 'FI PRIVATE BATCH HASH ONCE window=' window
check_windows 'FI PRIVATE H16 COMBINED BUFFER ROUTE window=' window
check_windows 'FI PRIVATE BUFFER ROUTE WINDOW START window=' window
check_windows 'FI PRIVATE DEPENDENCY BUFFER PROOF window=' window
[ "$(grep -c '^FI REAL BACKLOG DURABLE ' "$log")" -eq 10 ] ||
    fail 'AB10 missing durable window progress'
[ "$(grep -c '^FI DEFERRED ARTIFACT PUBLISHED ' "$log")" -eq 10 ] ||
    fail 'AB10 missing verified artifact publication'
grep '^FI PRIVATE EXACT WINDOW STOP start=3 windows=10 last=12 records=1297765 ' "$log" \
    > "$out/$name/RESULT.txt" || fail 'AB10 durable W3-W12 stop missing'
[ "$(wc -l < "$out/$name/RESULT.txt" | tr -d ' ')" -eq 1 ] ||
    fail 'AB10 duplicate durable stop'
grep -Fq 'FI PRIVATE HASH COPY EXPERIMENT profile=F3H16 max_rows=16384 max_bytes=16777216 other_F3_limits=unchanged' "$log" ||
    fail 'AB10 H16 profile not active'

grep '^FI PRIVATE BATCH HASH ONCE ' "$log" > "$out/$name/HASH_ONCE.txt"
reused=$(awk '/^FI PRIVATE BATCH HASH ONCE window=/ {
 for(i=1;i<=NF;i++){split($i,a,"=");if(a[1]=="trusted_batches")n+=a[2]+0}
} END{print n+0}' "$log")
[ "$reused" -eq 566 ] || fail "AB10 expected 566 signed COW batches, got $reused"

state=$(sql "SELECT count(*)::text || '|' || coalesce(sum(committed_records),0)::text || '|' ||
 coalesce(max(window_index),-1)::text FROM fi_recovery.typed_window") ||
    fail 'AB10 checkpoint query failed'
[ "$state" = '13|1688152|12' ] || fail "AB10 incorrect checkpoint: $state"
new_records=$(sql "SELECT coalesce(sum(committed_records),0)
 FROM fi_recovery.typed_window WHERE window_index BETWEEN 3 AND 12") ||
    fail 'AB10 new-record query failed'
[ "$new_records" = 1297765 ] || fail "AB10 incorrect new-record count: $new_records"

# Verify strict single-pass Security rows match typed event rows in EACH
# signed window, including the already-accepted W3/W4 counts.
awk '
 /^FI REAL TYPED WINDOW index=/ {
  w=-1;r=-1;e=-1;f=-1
  for(i=1;i<=NF;i++){split($i,a,"=")
    if(a[1]=="index")w=a[2]+0
    if(a[1]=="records")r=a[2]+0
    if(a[1]=="security_events")e=a[2]+0
    if(a[1]=="security_fields")f=a[2]+0}
  if(w<3||w>12||r<=0||e<0||f<0||typed[w]++)bad=1
  tr[w]=r;te[w]=e;tf[w]=f
 }
 /^FI PRIVATE STAGE PROFILE index=/ {
  w=-1;s=-1
  for(i=1;i<=NF;i++){split($i,a,"=")
    if(a[1]=="index")w=a[2]+0
    if(a[1]=="security_single_pass_rows")s=a[2]+0}
  if(w<3||w>12||s<0||stage[w]++)bad=1
  fast[w]=s
 }
 END {
  for(w=3;w<=12;w++){
    if(typed[w]!=1||stage[w]!=1||te[w]!=fast[w])bad=1
    total+=tr[w]
  }
  if(te[3]!=116357||te[4]!=116522||total!=1297765)bad=1
  if(bad)exit 2
  print "window\trecords\tsecurity_events\tsecurity_fields\tsingle_pass_rows"
  for(w=3;w<=12;w++)printf "%d\t%d\t%d\t%d\t%d\n",w,tr[w],te[w],tf[w],fast[w]
 }
' "$log" > "$out/$name/SECURITY_PER_WINDOW.tsv" ||
    fail 'AB10 signed Security single-pass counts invalid'
field_new=$(awk -F '\t' 'NR>1 {n++;f+=$4}END{if(n!=10)exit 2;printf "%.0f",f}' \
    "$out/$name/SECURITY_PER_WINDOW.tsv") ||
    fail 'AB10 Security field count invalid'
field_expected=$((4838850 + field_new))

integrity=$(sql "
SELECT CASE WHEN
 (SELECT count(*) FROM fi_recovery.verified_artifact_window)=13
 AND (SELECT count(*) FROM fi_recovery.source_window)=13
 AND (SELECT count(*) FROM fi_recovery.typed_window)=13
 AND (SELECT count(*) FROM fi_recovery.pending_source_record)=1688152
 AND (SELECT count(*) FROM fi_recovery_projection.source_record)=1688152
 AND (SELECT count(*) FROM fi_recovery_projection.windows_security_event_field)=$field_expected
 AND (SELECT count(*) FROM pg_inherits WHERE inhparent=
      'fi_recovery_projection.windows_security_event_field'::regclass)=13
 AND (SELECT count(*) FROM fi.recorded_generation)=0
 AND (SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted')=0
 AND NOT EXISTS (
  SELECT 1 FROM fi_recovery.typed_window t
  JOIN fi_recovery.source_window s USING(receipt_sha256,window_index)
  JOIN fi_recovery.verified_artifact_window a USING(receipt_sha256,window_index)
  WHERE t.descriptor_sha256<>s.descriptor_sha256
     OR t.descriptor_sha256<>a.descriptor_sha256
 )
 THEN 'PASS' ELSE 'FAIL' END") ||
    fail 'AB10 SQL integrity query failed'
[ "$integrity" = PASS ] ||
    fail "AB10 SQL source/security integrity failed expected_field_rows=$field_expected"

# Preserve the previous accepted private-only Security field leaf policy.
leaf=$(sql "SELECT count(*)::text || '|' ||
 count(*) FILTER (WHERE 'autovacuum_vacuum_insert_threshold=-1' =
 ANY(coalesce(c.reloptions,ARRAY[]::text[])))::text
 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='fi_recovery_projection'
 AND c.relname ~ '^windows_security_event_field_w0000(0[3-9]|1[0-2])$'") ||
    fail 'AB10 field leaf query failed'
[ "$leaf" = '10|10' ] || fail "AB10 private new field-leaf policy differs: $leaf"
seed_leaf=$(sql "SELECT count(*)::text || '|' ||
 count(*) FILTER (WHERE 'autovacuum_vacuum_insert_threshold=-1' =
 ANY(coalesce(c.reloptions,ARRAY[]::text[])))::text
 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='fi_recovery_projection'
 AND c.relname ~ '^windows_security_event_field_w00000[1-2]$'") ||
    fail 'AB10 seed leaf query failed'
[ "$seed_leaf" = '2|0' ] || fail "AB10 original seed leaf policy changed: $seed_leaf"

expected=$(sql "SELECT coalesce(sum(end_batch-start_batch),0)
 FROM fi_recovery.verified_artifact_window
 WHERE window_index BETWEEN 3 AND 12") ||
    fail 'AB10 expected signed batches query failed'
[ "$expected" = 566 ] || fail "AB10 signed artifact count differs: $expected"
checked=0
directories=0
for directory in "$out/$name/private"/receipt-*/window-*; do
    [ -d "$directory" ] || fail 'AB10 signed artifact window missing'
    directories=$((directories+1))
    receipt=$(basename "$(dirname "$directory")")
    for batch in "$directory"/batch-*.data; do
        [ -f "$batch" ] || fail 'AB10 signed batch missing'
        filename=$(basename "$batch")
        original="$cache/$receipt/$filename"
        [ -f "$original" ] || fail "AB10 original signed batch missing: $filename"
        cmp -s "$batch" "$original" || fail "AB10 signed batch differs: $filename"
        manifest=$(printf '%s\n' "$batch" | sed 's/\.data$/.manifest/')
        original_manifest=$(printf '%s\n' "$original" | sed 's/\.data$/.manifest/')
        [ -f "$manifest" ] && [ -f "$original_manifest" ] ||
            fail "AB10 signed manifest missing: $filename"
        cmp -s "$manifest" "$original_manifest" ||
            fail "AB10 signed manifest differs: $filename"
        checked=$((checked+1))
    done
done
[ "$directories" -eq 10 ] && [ "$checked" -eq 566 ] && [ "$checked" -eq "$reused" ] ||
    fail "AB10 signed readback mismatch windows=$directories batches=$checked trust=$reused"

# Preserve the combined candidate's known real W3/W4 counters while allowing
# unknown W5..W12 distributions to be measured rather than invented.
grep '^FI PRIVATE DEPENDENCY BUFFER PROOF ' "$log" > "$out/$name/DEPENDENCY_PROOF.txt"
awk '
 /^FI PRIVATE DEPENDENCY BUFFER PROOF / {
  w=-1;dep=-1;calls=-1;source=-1;avoided=-1
  for(i=1;i<=NF;i++){split($i,a,"=")
    if(a[1]=="window")w=a[2]+0
    if(a[1]=="dependency_records")dep=a[2]+0
    if(a[1]=="security_event_copy_calls")calls=a[2]+0
    if(a[1]=="security_source_copy_calls")source=a[2]+0
    if(a[1]=="coverage_security_flushes_avoided")avoided=a[2]+0}
  if(w<3||w>12||seen[w]++||dep<0||calls<=0||source!=calls||avoided<0)bad=1
  d[w]=dep;c[w]=calls;a[w]=avoided;n++
 }
 END {
  if(n!=10||d[3]!=0||d[4]!=29||c[3]!=30||c[4]!=30||
     a[3]!=51||a[4]!=53)bad=1
  for(w=3;w<=12;w++)if(seen[w]!=1)bad=1
  if(bad)exit 2
  for(w=3;w<=12;w++){copies+=c[w];saved+=a[w]}
  printf "FI H16 AB10 SECURITY ROUTE PASS windows=10 copy_calls=%d coverage_flushes_avoided=%d\n",copies,saved
 }
' "$log" > "$out/$name/BUFFER_TOTALS.txt" ||
    fail 'AB10 Security/dependency buffer proof invalid'

if [ "$variant" = five ]; then
    check_windows 'FI PRIVATE FIVE LANE PROOF window=' window
    grep '^FI PRIVATE FIVE LANE PROOF ' "$log" > "$out/$name/FIVE_LANE_PROOF.txt"
    awk '
    /^FI PRIVATE FIVE LANE PROOF / {
      w=-1;source=-1;deferred=-1;atomic=0
      for(i=1;i<=NF;i++){split($i,a,"=")
       if(a[1]=="window")w=a[2]+0
       if(a[1]=="file_source_drains")source=a[2]+0
       if(a[1]=="deferred_file_projection")deferred=a[2]+0
       if(a[1]=="W128_atomic"&&a[2]=="true")atomic=1}
      if(w<3||w>12||seen[w]++||source<0||deferred<0||atomic!=1)bad=1
      if((w==3||w==4)&&(source<1||deferred<1))bad=1
      n++;total+=source;saved+=deferred
    }
    END{
      if(n!=10||total<1||saved<1)bad=1
      for(w=3;w<=12;w++)if(seen[w]!=1)bad=1
      if(bad)exit 2
      printf "FI H16 AB10 FILE PROJECTION PROOF PASS windows=10 source_drains=%d deferred_projection=%d\n",total,saved
    }' "$log" > "$out/$name/FIVE_LANE_TOTALS.txt" ||
        fail 'AB10 File projection was not independently exercised'
else
    if grep -q '^FI PRIVATE FIVE LANE PROOF ' "$log"; then
        fail 'AB10 combined buffer control unexpectedly enabled five-lane mode'
    fi
fi

grep '^FI PRIVATE STAGE PROFILE ' "$log" > "$out/$name/STAGES.txt"
grep '^FI REAL TYPED WINDOW ' "$log" > "$out/$name/SECURITY_COPY_CALLS.txt"
grep '^FI TYPED CHUNK COMMITTED ' "$log" > "$out/$name/CHUNK_BOUNDARIES.txt"
grep '^FI REAL BACKLOG DURABLE ' "$log" > "$out/$name/WINDOWS.txt"
grep '^FI DEFERRED ARTIFACT PUBLISHED ' "$log" > "$out/$name/DEFERRED.txt"
grep '^FI PRIVATE BUFFER ROUTE WINDOW START ' "$log" > "$out/$name/ROUTE_PROOF.txt"
grep '^FI PRIVATE H16 COMBINED BUFFER ROUTE ' "$log" > "$out/$name/COMBINED_ROUTE_PROOF.txt"
{
  printf 'window_index\tcommitted_records\n'
  sql "SELECT window_index::text || chr(9) || committed_records::text
   FROM fi_recovery.typed_window WHERE window_index BETWEEN 3 AND 12
   ORDER BY window_index"
} > "$out/$name/SQL_WINDOW_COUNTS.tsv" || fail 'AB10 SQL window matrix failed'
[ "$(wc -l < "$out/$name/SQL_WINDOW_COUNTS.tsv" | tr -d ' ')" -eq 11 ] ||
    fail 'AB10 SQL window matrix incomplete'
peak_rss_kib=$(awk '/maximum resident set size/ {v=$1}END{if(v=="")print "unavailable";else print v}' "$log")
printf 'FI H16 AB10 RESOURCE SUMMARY peak_worker_rss_kib=%s\n' "$peak_rss_kib" |
    tee -a "$out/SUMMARY.txt"
printf 'FI H16 AB10 ACCEPTED variant=%s windows=10 records=1297765 signed_batches=566 checkpoint=%s authoritative=0 accepted=0\n' \
    "$variant" "$state" | tee -a "$out/SUMMARY.txt"

# Include the complete timed worker output, guest/PG metrics, and source
# provenance. Exclude the actual signed payload cache, credentials, SQL dump
# and disposable PostgreSQL data directory.
bundle="$out/fi-h16-$variant-ab10-w3-w12-$stamp.tar.gz"
set -- RUN_MANIFEST.txt SUMMARY.txt "$name/recover.log" "$name/RESULT.txt" \
    "$name/SQL_WINDOW_COUNTS.tsv" "$name/WINDOWS.txt" "$name/DEFERRED.txt" \
    "$name/HASH_ONCE.txt" "$name/STAGES.txt" "$name/SECURITY_COPY_CALLS.txt" \
    "$name/SECURITY_PER_WINDOW.tsv" "$name/CHUNK_BOUNDARIES.txt" \
    "$name/ROUTE_PROOF.txt" "$name/COMBINED_ROUTE_PROOF.txt" \
    "$name/DEPENDENCY_PROOF.txt" "$name/BUFFER_TOTALS.txt" \
    "$name/pg_settings.txt" "$name/pg_before.txt" "$name/pg_after.txt" \
    "$name/pg_stat_wal_before.jsonl" "$name/pg_stat_wal_after.jsonl" \
    "$name/pg_stat_checkpointer_before.jsonl" "$name/pg_stat_checkpointer_after.jsonl" \
    "$name/pg_stat_io_before.jsonl" "$name/pg_stat_io_after.jsonl" \
    "$name/relations_before.jsonl" "$name/relations_after.jsonl" \
    "$name/pg_5sec_samples.jsonl" "$name/host-iostat.txt" "$name/host-vmstat.txt" \
    security-real-signed-preflight-summary.txt
if [ "$variant" = five ]; then
    set -- "$@" "$name/FIVE_LANE_PROOF.txt" "$name/FIVE_LANE_TOTALS.txt"
fi
(cd "$out" && tar -czf "$bundle" "$@") ||
    fail 'AB10 metrics bundle failed'
[ -s "$bundle" ] || fail 'AB10 metrics bundle empty'
printf 'FI H16 AB10 METRICS BUNDLE PASS variant=%s path=%s\n' "$variant" "$bundle" |
    tee -a "$out/SUMMARY.txt"
