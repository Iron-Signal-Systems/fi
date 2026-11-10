#!/bin/sh
# Copyright (c) 2026 John Joseph Wood. All rights reserved.
#
# FI RECOVERY-ONLY continuation for the already committed private W3-W22
# signed experiment. Never re-run the 20-window ingestion or recreate a seed.
# The original run exited after SQL-integrity PASS because W0 has no field
# partition and an incorrect check expected 3 restored leaf tables (3|0).
# Observed original W1/W2 seed leaf options are 2|0; all W3-W22 leaves
# have already been checked for the candidate option.
#
# Run on fi-backend-b as root, using stopped fi-dev clone ONLY.
# This script does not execute Go, replay data, rebuild/restore PostgreSQL,
# change global PostgreSQL settings, or touch fi-sor-db.
set -eu
umask 077

fail() { printf 'FI CANDIDATE20 FINISH STOP: %s\n' "$*" >&2; exit 1; }
[ "$(id -un)" = root ] || fail 'run on fi-backend-b as root'
[ "$#" -eq 0 ] || fail 'usage: sh finish_completed_private_vacuum_candidate20_host.sh'
for cmd in jls jexec ps awk grep find wc sha256 tar cmp date; do
    command -v "$cmd" >/dev/null 2>&1 || fail "missing host utility: $cmd"
done

name=clone-11-08-26
mode=candidate
ref=b01ff0d8cb6559797de052f34b18bd84a395dc4c
stamp=20261110T103933Z
root=/home/jwood/fi-window-bench-optfield-v20-c-$stamp
out=/var/tmp/fi-window-chunks-v20-c-$stamp
cache=/var/tmp/fi-window-chunks-20261103T172254Z/verified-cache
cluster="$root/$name"
log="$out/$name/recover.log"
bundle="$out/fi-vacuum-candidate20-$stamp.tar.gz"
jailroot=$(jls -j fi-dev path) || fail 'fi-dev jail not available'
devjid=$(jls -j fi-dev jid) || fail 'fi-dev jail ID unavailable'
sorjid=$(jls -j fi-sor-db jid) || fail 'real SoR jail unavailable'
[ "$devjid" != "$sorjid" ] || fail 'SoR and dev JIDs match'
jexec fi-sor-db service postgresql status >/dev/null 2>&1 ||
    fail 'SoR service is not reported running'
[ -d "$jailroot$cluster/data" ] && [ -d "$jailroot$cluster/socket" ] ||
    fail 'retained private clone data/socket missing'
[ -f "$jailroot$root/SOURCE_COMMIT" ] ||
    fail 'original recovered private source ID missing'
[ "$(cat "$jailroot$root/SOURCE_COMMIT")" = "$ref" ] ||
    fail 'private source commit differs from original experiment'
[ -d "$cache" ] || fail 'original signed evidence cache missing'
[ -f "$out/RUN_MANIFEST.txt" ] && [ -f "$out/SUMMARY.txt" ] &&
[ -f "$log" ] && [ -f "$out/$name/result.txt" ] ||
    fail 'completed 20-window run evidence missing'
[ ! -L "$jailroot$root" ] && [ ! -L "$jailroot$cluster" ] &&
[ ! -L "$jailroot$cluster/data" ] && [ ! -L "$jailroot$cluster/socket" ] &&
[ ! -L "$out" ] || fail 'unexpected symlink in private paths'
[ ! -e "$bundle" ] || fail 'existing final metrics archive; do not overwrite'
grep -Fxq "source_commit=$ref" "$out/RUN_MANIFEST.txt" ||
    fail 'completed run source commit does not match'
grep -Fxq 'vacuum_variant=candidate' "$out/RUN_MANIFEST.txt" ||
    fail 'wrong experiment variant'
grep -Fxq 'number_of_new_windows=20' "$out/RUN_MANIFEST.txt" ||
    fail 'wrong number of windows'
grep -Fq 'FI CLONE SQL INTEGRITY PASS checkpoint=23|2988103|22 canonical=0 accepted=0' "$out/SUMMARY.txt" ||
    fail 'original SQL integrity PASS not recorded'
grep -Fq 'FI PRIVATE EXACT WINDOW STOP start=3 windows=20 last=22 records=2597716 ' "$out/$name/result.txt" ||
    fail 'original durable W3-W22 stop not present'
for f in windows stages deferred; do
    [ "$(wc -l < "$out/$name/$f.txt" | tr -d ' ')" -eq 20 ] ||
        fail "$f does not have 20 accepted windows"
done
for f in pg_stat_wal_before.jsonl pg_stat_wal_after.jsonl \
         pg_stat_checkpointer_before.jsonl pg_stat_checkpointer_after.jsonl \
         pg_stat_io_before.jsonl pg_stat_io_after.jsonl \
         relations_before.jsonl relations_after.jsonl pg_5sec_samples.jsonl; do
    [ -s "$out/$name/$f" ] || fail "original captured metric $f absent/empty"
done

existing=$(ps -axww -o pid,jid,user,rss,command | awk -v jid="$devjid" '
    $2 == jid && $5 == "/usr/local/bin/postgres" && $6 == "-D" { n++ }
    END { print n + 0 }
')
[ "$existing" -eq 0 ] ||
    fail "$existing other private PostgreSQL postmaster(s) active in fi-dev"
jexec -U jwood fi-dev pg_ctl -D "$cluster/data" status >/dev/null 2>&1 &&
    fail 'original stopped clone already running; do not join live server'
[ "${#cluster}" -lt 90 ] ||
    fail 'PostgreSQL private socket directory is unexpectedly long'

started=0
cleanup() {
    code=$?
    trap - 0 1 2 15
    if [ "$started" -eq 1 ]; then
        printf 'FI CANDIDATE20 FINISH CLEANUP stopping retained PostgreSQL clone\n'
        jexec -U jwood fi-dev pg_ctl -D "$cluster/data" -m fast -w -t 60 stop ||
            code=1
    fi
    printf 'FI CANDIDATE20 FINISHED exit=%s output=%s\n' "$code" "$out"
    exit "$code"
}
trap cleanup 0
trap 'exit 130' 2
trap 'exit 143' 15

# PostgreSQL startup can generate some additional cumulative statistics and
# internal metadata, and is NOT bit-for-bit disk read-only. Preserve the exact
# original replay before/after snapshots and add distinct restarted snapshots.
started=1
jexec -U jwood fi-dev pg_ctl -D "$cluster/data" \
    -l "$cluster/postrun-finish-$stamp.log" \
    -o "-p 55981 -k $cluster/socket -c listen_addresses= -c unix_socket_permissions=0700" \
    -w start || fail 'retained private clone could not start'

sql() {
    jexec -U jwood fi-dev psql \
        "host=$cluster/socket port=55981 user=fi_ingest dbname=fi sslmode=disable" \
        -X -qAt -v ON_ERROR_STOP=1 -c "$1"
}
state=$(sql "SELECT count(*)::text || '|' ||
    coalesce(sum(committed_records),0)::text || '|' || max(window_index)::text
    FROM fi_recovery.typed_window")
[ "$state" = '23|2988103|22' ] ||
    fail "original signed twenty-window database state changed: $state"
new_records=$(sql "SELECT coalesce(sum(committed_records),0)
    FROM fi_recovery.typed_window WHERE window_index BETWEEN 3 AND 22")
[ "$new_records" = 2597716 ] ||
    fail "original signed source count changed: $new_records"
[ "$(sql "SELECT coalesce(sum(committed_records),0)
    FROM fi_recovery.typed_window WHERE window_index <= 17")" = 2338918 ] ||
    fail 'verified W0-W17 prefix changed'
[ "$(sql "SELECT (SELECT count(*) FROM fi.recorded_generation)
    + (SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted')")" = 0 ] ||
    fail 'clone contains authoritative or Accepted entries'

# The original candidate W3-W22 setting was already verified. Check again
# and correct only the mistaken 3|0 seed expectation, NOT any relation.
leaf_config=$(sql "SELECT count(*)::text || '|' ||
    count(*) FILTER (WHERE 'autovacuum_vacuum_insert_threshold=-1' =
      ANY(coalesce(c.reloptions,ARRAY[]::text[])))::text
 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='fi_recovery_projection'
   AND c.relname ~ '^windows_security_event_field_w0000(0[3-9]|1[0-9]|2[0-2])$'")
[ "$leaf_config" = '20|20' ] ||
    fail "expected candidate new leaf options 20|20, got $leaf_config"
seed_config=$(sql "SELECT count(*)::text || '|' ||
    count(*) FILTER (WHERE 'autovacuum_vacuum_insert_threshold=-1' =
      ANY(coalesce(c.reloptions,ARRAY[]::text[])))::text
 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='fi_recovery_projection'
   AND c.relname ~ '^windows_security_event_field_w00000[1-2]$'")
[ "$seed_config" = '2|0' ] ||
    fail "expected preserved W1/W2 seed leaves 2|0, got $seed_config"
# The seed-only W0 marker has no detached Security field leaf; check no
# unexpected W0 leaf appeared.
[ "$(sql "SELECT to_regclass('fi_recovery_projection.windows_security_event_field_w000000') IS NULL")" = t ] ||
    fail 'unexpected field leaf W0 appeared'
printf 'FI CANDIDATE20 RECOVERY GATE PASS checkpoint=%s new=%s seed=%s\n' \
    "$state" "$leaf_config" "$seed_config" | tee -a "$out/SUMMARY.txt"
printf 'FI VACUUM LEAF OPTIONS PASS new=%s seed=%s\n' \
    "$leaf_config" "$seed_config" | tee "$out/$name/leaf_options.txt"

snapshot_pg() {
    phase=$1
    {
        sql 'SELECT * FROM pg_stat_wal'
        sql 'SELECT * FROM pg_stat_checkpointer'
        sql 'SELECT * FROM pg_stat_io'
    } > "$out/$name/pg_${phase}.txt" || fail "PostgreSQL ${phase} stats snapshot failed"
    # JSON objects retain PG18 counter column names and units for offline
    # before/after deltas. All are read-only and sampled outside the replay.
    sql 'SELECT row_to_json(s)::text FROM (SELECT * FROM pg_stat_wal) s' \
        > "$out/$name/pg_stat_wal_${phase}.jsonl" || fail "WAL statistics snapshot failed"
    sql 'SELECT row_to_json(s)::text FROM (SELECT * FROM pg_stat_checkpointer) s' \
        > "$out/$name/pg_stat_checkpointer_${phase}.jsonl" || fail "checkpointer snapshot failed"
    sql 'SELECT row_to_json(s)::text FROM (SELECT * FROM pg_stat_io) s' \
        > "$out/$name/pg_stat_io_${phase}.jsonl" || fail "I/O statistics snapshot failed"
}
snapshot_relations() {
    phase=$1
    sql "SELECT row_to_json(r)::text FROM (
      SELECT clock_timestamp() AS observed_at,s.schemaname,s.relname,
             s.n_tup_ins,s.n_tup_upd,s.n_tup_del,s.n_dead_tup,
             s.autovacuum_count,s.autoanalyze_count,
             s.total_autovacuum_time,s.total_autoanalyze_time,
             c.reloptions,pg_relation_size(s.relid) AS heap_bytes
      FROM pg_stat_all_tables s JOIN pg_class c ON c.oid=s.relid
      WHERE s.schemaname IN ('fi_recovery','fi_recovery_projection')
      ORDER BY s.schemaname,s.relname
    ) r" > "$out/$name/relations_${phase}.jsonl" ||
        fail "private relation statistics ${phase} snapshot failed"
}

# Because this is a post-shutdown continuation, take NEW labeled snapshots
# without overwriting any of the exact original replay before/after evidence.
snapshot_pg restarted_before_maintenance
snapshot_relations restarted_before_maintenance

# The post-run restart can generate additional server stats. Counters at
# *restarted_before_maintenance isolate the continuation phase from the
# unchanged original before/after measured ingestion snapshots. Never claim
# that all restart or VACUUM effects occurred during the original ingestion.
# The remainder is lifted directly from the experimental script after the
# erroneous seed-count test; it performs exact signed-artifact readback, all
# stage matrices, *20* private leaf manual VACUUMs and the final metrics tar.

# Independent signed artifact readback is AFTER the benchmark timing.
expected=$(sql "SELECT coalesce(sum(end_batch-start_batch),0)::text FROM fi_recovery.verified_artifact_window WHERE window_index>=3")
checked=0
for windowdir in "$out/$name/private"/receipt-*/window-*; do
    [ -d "$windowdir" ] || fail 'missing signed artifact window'
    receipt=$(basename "$(dirname "$windowdir")")
    for batch in "$windowdir"/batch-*.data; do
        [ -f "$batch" ] || fail 'missing published batch'
        base=$(basename "$batch")
        original="$cache/$receipt/$base"
        [ -f "$original" ] || fail "missing original signed cached data $base"
        cmp -s "$batch" "$original" || fail "signed data differs $base"
        cmp -s "${batch%.data}.manifest" "${original%.data}.manifest" || fail "signed manifest differs $base"
        checked=$((checked+1))
    done
done
[ "$checked" -eq "$expected" ] || fail "signed artifact count mismatch $checked/$expected"
# The 20-window signed batch count is derived from the SQL verified-artifact
# custody and ALL published files are compared to signed-cache originals.
[ "$checked" -gt 0 ] || fail "twenty-window signed readback is empty: $checked"
printf 'FI CLONE SIGNED READBACK PASS batch_files=%s byte_identical=true manifests_identical=true\n' "$checked" | tee -a "$out/SUMMARY.txt"

# Real per-window throughput: difference in durable record positions divided
# by that window's own duration, never a ten-minute or provisioning clock.
awk '
function seconds(x, y,a,b) {
    y=x
    if (y ~ /ms$/) {sub(/ms$/, "", y); return (y+0)/1000}
    if (index(y,"h")) {split(y,a,"h"); return (a[1]+0)*3600+seconds(a[2])}
    if (index(y,"m")) {split(y,a,"m"); return (a[1]+0)*60+seconds(a[2])}
    sub(/s$/, "", y)
    return y+0
}
BEGIN {
    previous=390387
    printf "%-9s %-12s %-14s %-14s\n", "WINDOW", "RECORDS", "DURATION", "RECORDS/SEC"
}
/^FI REAL BACKLOG DURABLE / {
    idx=-1; through=-1; elapsed=""
    for (i=1; i<=NF; i++) {
        if ($i ~ /^window=[0-9]+\/[0-9]+$/) {
            split($i,a,"="); split(a[2],b,"/"); idx=b[1]-1
        } else if ($i ~ /^records_through=/) {
            split($i,a,"="); split(a[2],b,"/"); through=b[1]+0
        } else if ($i ~ /^window=[0-9.]+(h|m|s)/) {
            split($i,a,"="); elapsed=a[2]
        }
    }
    duration=seconds(elapsed)
    records=through-previous
    if (idx != count+3 || through<=previous || duration<=0) {
        print "FI CLONE RESULT ERROR inconsistent window order/count/duration" > "/dev/stderr"
        exit 1
    }
    previous=through
    totalrecords+=records
    totaltime+=duration
    printf "%-9d %-12d %-14s %-14.1f\n", idx, records, elapsed, records/duration
    count++
}
END {
    if (count!=20 || totaltime<=0) exit 1
    printf "TWENTY-WINDOW TOTAL: records=%d window_seconds=%.3f committed_rate=%.1f records/sec\n", totalrecords, totaltime, totalrecords/totaltime
}' "$log" > "$out/$name/WINDOW_RATES.txt" ||
    fail 'twenty-window rate extraction failed'
cat "$out/$name/WINDOW_RATES.txt"


# Export one row per durable W3..W22 stage profile. Preserve raw duration
# strings as well as a derived sum, without conflating nested stage counters
# with mutually exclusive wall-clock phases.
awk -v totals="$out/$name/STAGE_TOTALS.tsv" '
function seconds(s, h,m,a) {
    if (s ~ /ms$/) { sub(/ms$/, "", s); return (s+0)/1000 }
    h=0; m=0
    if (index(s,"h")) { split(s,a,"h"); h=a[1]+0; s=a[2] }
    if (index(s,"m")) { split(s,a,"m"); m=a[1]+0; s=a[2] }
    if (s ~ /ms$/) { sub(/ms$/, "", s); return h*3600+m*60+(s+0)/1000 }
    sub(/s$/, "", s)
    return h*3600+m*60+(s+0)
}
BEGIN {
    columns="index records joined typed_total setup batch_ingest joined_finish deferred_flush verification verify_counts verify_coverage marker_commit source_read batch_hash envelope_prepare security_prepare security_child_prepare source_sql projection_total file_projection_inclusive security_projection_inclusive other_projection_inclusive security_id_lookup security_source_copy security_event_copy security_scope_copy security_field_copy security_single_pass_rows"
    n=split(columns,col," ")
    for (i=1; i<=n; i++) printf "%s%s", col[i], (i<n ? "\t" : "\n")
}
/^FI PRIVATE STAGE PROFILE / {
    for (k in values) delete values[k]
    for (i=5; i<=NF; i++) {
        p=index($i,"=")
        if (p>0) values[substr($i,1,p-1)]=substr($i,p+1)
    }
    if (!("index" in values)) { bad=1; exit 2 }
    window=values["index"]+0
    if (window<3 || window>22 || seen[window]++) { bad=1; exit 2 }
    for (i=1; i<=n; i++) {
        if (!(col[i] in values)) { bad=1; exit 2 }
        printf "%s%s", values[col[i]], (i<n ? "\t" : "\n")
        if (i>=4 && col[i]!="security_single_pass_rows")
            duration[i] += seconds(values[col[i]])
    }
    total_single_pass+=values["security_single_pass_rows"]+0
    rows++
}
END {
    if (bad || rows!=20 || total_single_pass<=0) {
        printf "FI EFFICIENCY STAGE MATRIX FAIL rows=%d single_pass=%d bad=%d\n", rows,total_single_pass,bad > "/dev/stderr"
        exit 3
    }
    print "stage_key\ttotal_seconds\tavg_seconds\tinterpretation" > totals
    for (i=4; i<=n; i++) {
        if (col[i]=="security_single_pass_rows") continue
        printf "%s\t%.3f\t%.3f\t%s\n", col[i], duration[i], duration[i]/20,
            (col[i]=="typed_total" ? "outer_wall" : "nested_or_component_do_not_sum") >> totals
    }
    printf "FI EFFICIENCY SINGLE PASS PASS windows=%d selected_rows=%d\n", rows,total_single_pass > "/dev/stderr"
}' "$log" > "$out/$name/PER_WINDOW_STAGES.tsv" ||
    fail 'stage timing matrix or active single-pass selection acceptance failed'
[ "$(wc -l < "$out/$name/PER_WINDOW_STAGES.tsv" | tr -d ' ')" -eq 21 ] ||
    fail 'stage timing matrix does not contain a header plus 20 windows'

# Join typed Security counters, File validation counters, and field partition
# finalization records by canonical window index. No new SQL or per-record logs.
awk '
function parse_fields(   i,p,key,val) {
    for (key in fields) delete fields[key]
    for (i=2; i<=NF; i++) {
        p=index($i,"=")
        if (p>0) fields[substr($i,1,p-1)]=substr($i,p+1)
    }
}
BEGIN { print "window\trecords\tsecurity_events\tsecurity_fields\tfamilies\tfile_source_validated\tfile_bulk_reused\tfile_bulk_validated\tpartition_field_rows\tpartition_begin\tpartition_validate_attach" }
/^FI REAL TYPED WINDOW / {
    parse_fields()
    w=fields["index"]+0
    if (w>=3 && w<=22) {
        count[w]++
        records[w]=fields["records"]; events[w]=fields["security_events"]
        secfields[w]=fields["security_fields"]; families[w]=fields["families"]
    }
}
/^FI FILE VALIDATION WINDOW / {
    parse_fields(); w=fields["index"]+0
    if (w>=3 && w<=22) {
        file_seen[w]++
        file_valid[w]=fields["source_validated"]
        file_reused[w]=fields["bulk_reused"]
        file_bulk[w]=fields["bulk_validated"]
    }
}
/^FI PRIVATE FIELD PARTITION COMMITTED / {
    parse_fields(); w=fields["window"]+0
    if (w>=3 && w<=22) {
        partition_seen[w]++
        partition_rows[w]=fields["rows"]
        partition_begin[w]=fields["begin"]
        partition_finish[w]=fields["validate_attach"]
    }
}
END {
    for (w=3; w<=22; w++) {
        if (count[w]!=1 || file_seen[w]!=1 || partition_seen[w]!=1) {
            printf "FI EFFICIENCY FAMILY MATRIX incomplete window=%d typed=%d file=%d partition=%d\n",
                w,count[w],file_seen[w],partition_seen[w] > "/dev/stderr"
            exit 2
        }
        printf "%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
            w, records[w], events[w], secfields[w], families[w],
            file_valid[w], file_reused[w], file_bulk[w],
            partition_rows[w], partition_begin[w], partition_finish[w]
    }
}' "$log" > "$out/$name/PER_WINDOW_FAMILIES.tsv" ||
    fail 'per-window Security/File/field counts missing'
[ "$(wc -l < "$out/$name/PER_WINDOW_FAMILIES.tsv" | tr -d ' ')" -eq 21 ] ||
    fail 'family matrix does not contain a header plus 20 windows'

# Copy all observed processing chunks, including unusually slow chunks.
awk '
BEGIN { print "window\tchunk\tlimit\tbatches\trecords\tprocessing" }
/^FI TYPED CHUNK COMMITTED / {
    for (k in f) delete f[k]
    for (i=2; i<=NF; i++) {
        p=index($i,"=")
        if (p>0) f[substr($i,1,p-1)]=substr($i,p+1)
    }
    if (f["window"]+0>=3 && f["window"]+0<=7)
        printf "%s\t%s\t%s\t%s\t%s\t%s\n", f["window"],f["chunk"],f["limit"],f["batches"],f["records"],f["processing"]
}' "$log" > "$out/$name/PROCESSING_CHUNKS.tsv" ||
    fail 'processing chunk timing extraction failed'

# Cross-check durable SQL identity and record counts outside replay timing.
{
    printf 'window_index\tcommitted_records\n'
    sql "SELECT window_index::text || chr(9) || committed_records::text
         FROM fi_recovery.typed_window WHERE window_index BETWEEN 3 AND 22
         ORDER BY window_index"
} > "$out/$name/SQL_WINDOW_COUNTS.tsv" ||
    fail 'SQL committed-window record matrix failed'
[ "$(wc -l < "$out/$name/SQL_WINDOW_COUNTS.tsv" | tr -d ' ')" -eq 21 ] ||
    fail 'SQL committed-window matrix not exactly 20 rows'

grep '^gc [0-9]' "$log" > "$out/$name/GC_EVENTS.txt" || :
cat > "$out/$name/METRICS_README.txt" <<'FI_METRICS'
Private signed W128 window indexes 3..22; 20 fully durable windows.
PER_WINDOW_STAGES.tsv: source-reported Go stage durations and fast-path counts;
  columns named *_inclusive, COPY and source_sql are nested/overlapping.
STAGE_TOTALS.tsv: sum across the 20 windows of EACH individual stage ONLY;
  DO NOT ADD different stages together to infer elapsed wall clock.
PER_WINDOW_FAMILIES.tsv: Security event/field counts, File validation reuse,
  and private field-partition finish/attach durations by window.
PROCESSING_CHUNKS.tsv: per-processing-chunk duration, records, signed batches.
SQL_WINDOW_COUNTS.tsv: post-run PostgreSQL durable source-record positions.
WINDOW_RATES.txt: per-window records and actual durable-window durations.
GC_EVENTS.txt: Go runtime GC trace, enabled on replay only; instrumented
  elapsed time must not be confused with untraced baseline throughput.
process_resources.txt: FreeBSD rusage peak replay-process resident memory;
  this is not PostgreSQL RSS or total host memory.
pg_stat_wal_{before,after}.jsonl: named PostgreSQL 18 WAL counters.
pg_stat_checkpointer_{before,after}.jsonl: named checkpoint counters.
pg_stat_io_{before,after}.jsonl: named PostgreSQL IO records.
host-iostat.txt and host-vmstat.txt: 5-second HOST-WIDE observations.
recover.log: exact complete authoritative source of the profile and GC lines.
signed_artifact comparisons and fi_recovery SQL integrity: acceptance gates.
FI_METRICS
printf 'FI EFFICIENCY METRIC EXPORT PASS stage_windows=20 source_rows=%s\n' "$new_records" |
    tee -a "$out/SUMMARY.txt"

# Maintenance debt acceptance: this candidate pays explicit
# VACUUM (ANALYZE) of the 20 newly attached private field leaves, only
# AFTER committed-window timing, SQL integrity and signed custody checks.
# This is NOT a PostgreSQL global or production vacuum change.
# Comparing ingest+repayment helps expose deferred versus eliminated work.
maint_log="$out/$name/MAINTENANCE_REPAYMENT.tsv"
printf 'window\telapsed_seconds\n' > "$maint_log"
maint_start=$(date -u '+%s')
w=3
while [ "$w" -le 22 ]; do
    table=$(printf 'windows_security_event_field_w%06d' "$w")
    started=$(date -u '+%s')
    jexec -U jwood fi-dev psql \
        "host=$root/$name/socket port=55981 user=fi_m1_admin dbname=fi sslmode=disable" \
        -X -q -v ON_ERROR_STOP=1 -c "VACUUM (ANALYZE) fi_recovery_projection.$table" \
        > "$out/$name/vacuum_manual_w$w.log" 2>&1 ||
        fail "postrun private leaf VACUUM ANALYZE failed window=$w"
    stopped=$(date -u '+%s')
    printf '%s\t%s\n' "$w" "$((stopped-started))" >> "$maint_log"
    w=$((w+1))
done
maint_stop=$(date -u '+%s')
printf 'FI VACUUM REPAYMENT COMPLETE mode=%s leaf_windows=20 elapsed_seconds=%s\n' \
    "$mode" "$((maint_stop-maint_start))" | tee "$out/$name/MAINTENANCE_REPAYMENT_SUMMARY.txt"
snapshot_pg maintenance_after
snapshot_relations maintenance_after
# Postmaintenance remains within the disposable clone and cannot publish SoR.
post_state=$(sql "SELECT count(*)::text || '|' ||
   coalesce(sum(committed_records),0)::text || '|' || max(window_index)::text
   FROM fi_recovery.typed_window")
[ "$post_state" = "$state" ] ||
    fail "postmaintenance durable SQL checkpoint changed: $post_state"
[ "$(sql "SELECT (SELECT count(*) FROM fi.recorded_generation)
    + (SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted')")" = 0 ] ||
    fail 'postmaintenance canonical/accepted SoR invariant failed'
printf 'FI VACUUM POSTMAINTENANCE INTEGRITY PASS state=%s authoritative=0 accepted=0\n' "$state" |
    tee -a "$out/SUMMARY.txt"

cat "$out/$name/result.txt" | tee -a "$out/SUMMARY.txt"
cat "$out/$name/process_resources.txt" | tee -a "$out/SUMMARY.txt"
printf 'FI VACUUM CANDIDATE20 RECOVERED mode=%s output=%s source_commit=%s signed_data=real authoritative=0 accepted=0\n' "$mode" "$out" "$ref" | tee -a "$out/SUMMARY.txt"

# Shareable diagnostics only. Deliberately EXCLUDE private/ copied signed
# data, source.tar, PostgreSQL dump/cluster, and credentials. Every source
# observation remains available in the local directory for later audit.
bundle="$out/fi-vacuum-candidate20-$stamp.tar.gz"
(
    cd "$out" || exit 1
    tar -czf "$bundle" \
        RUN_MANIFEST.txt SUMMARY.txt relay.log \
        "$name/recover.log" "$name/result.txt" "$name/windows.txt" \
        "$name/stages.txt" "$name/deferred.txt" \
        "$name/WINDOW_RATES.txt" "$name/PER_WINDOW_STAGES.tsv" \
        "$name/STAGE_TOTALS.tsv" "$name/PER_WINDOW_FAMILIES.tsv" \
        "$name/PROCESSING_CHUNKS.tsv" "$name/SQL_WINDOW_COUNTS.tsv" \
        "$name/GC_EVENTS.txt" "$name/process_resources.txt" \
        "$name/METRICS_README.txt" "$name/pg_settings.txt" \
        "$name/pg_before.txt" "$name/pg_after.txt" \
        "$name/pg_stat_wal_before.jsonl" "$name/pg_stat_wal_after.jsonl" \
        "$name/pg_stat_checkpointer_before.jsonl" "$name/pg_stat_checkpointer_after.jsonl" \
        "$name/pg_stat_io_before.jsonl" "$name/pg_stat_io_after.jsonl" \
        "$name/host-iostat.txt" "$name/host-vmstat.txt" \
        "$name/relations_before.jsonl" "$name/relations_after.jsonl" \
        "$name/pg_5sec_samples.jsonl" "$name/leaf_options.txt" \
        "$name/MAINTENANCE_REPAYMENT.tsv" "$name/MAINTENANCE_REPAYMENT_SUMMARY.txt" \
        "$name/pg_stat_wal_restarted_before_maintenance.jsonl" \
        "$name/pg_stat_checkpointer_restarted_before_maintenance.jsonl" \
        "$name/pg_stat_io_restarted_before_maintenance.jsonl" \
        "$name/relations_restarted_before_maintenance.jsonl" \
        "$name/pg_stat_wal_maintenance_after.jsonl" \
        "$name/pg_stat_checkpointer_maintenance_after.jsonl" \
        "$name/pg_stat_io_maintenance_after.jsonl" \
        "$name/relations_maintenance_after.jsonl"
) || fail 'cannot package complete metrics-only archive'
[ -s "$bundle" ] || fail 'metrics archive empty'
printf 'FI EFFICIENCY METRICS BUNDLE PASS path=%s\n' "$bundle"
