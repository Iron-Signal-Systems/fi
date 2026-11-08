#!/bin/sh
# Read-only historical FI signed-data replay diagnosis; host root only.
# No SQL connections, PostgreSQL restarts, ZFS changes or repo mutations.
set -eu
fail() { printf 'FI DIAG STOP: %s\n' "$*" >&2; exit 1; }
[ "$(id -un)" = root ] || fail "run on fi-backend-b as root"
jailroot=$(jls -j fi-dev path) || fail "fi-dev jail unavailable"
base=/var/tmp/fi-window-chunks-clone-11-08-26-20261108T150115Z
first=/var/tmp/fi-window-chunks-clone-11-08-26-fileval-20261108T154127Z
new=/var/tmp/fi-window-chunks-file-once-20261108T171740Z
for path in "$base" "$first" "$new"; do
    [ -f "$path/RUN_MANIFEST.txt" ] || fail "missing manifest $path"
    [ -f "$path/clone-11-08-26/recover.log" ] || fail "missing log $path"
done

printf '%s\n' '=== Signed per-window Security field COPY comparison ==='
awk '
function secs(x) {
    if (x ~ /ns$/) return (x+0)/1000000000
    if (x ~ /µs$/ || x ~ /us$/) return (x+0)/1000000
    if (x ~ /ms$/) return (x+0)/1000
    return x+0
}
function run() { if (FILENAME==ARGV[1]) return "BASE"; if(FILENAME==ARGV[2]) return "FIRST"; return "NEW" }
function field(key, i,parts) {
    for(i=1;i<=NF;i++) {
        split($i,parts,"=")
        if(parts[1]==key) return parts[2]
    }
    return ""
}
/^FI PRIVATE STAGE PROFILE / {
    r=run(); w=field("index")+0
    if(w<3||w>12||stages[r,w]++)bad=1
    copy[r,w]=secs(field("security_field_copy"))
    sec[r,w]=secs(field("security_projection_inclusive"))
    file[r,w]=secs(field("file_projection_inclusive"))
    ingest[r,w]=secs(field("batch_ingest"))
}
/^FI REAL TYPED WINDOW / {
    r=run(); w=field("index")+0
    if(w<3||w>12||typed[r,w]++)bad=1
    fields[r,w]=field("security_fields")+0
    events[r,w]=field("security_events")+0
    for(i=1;i<=NF;i++) {
        if(index($i,"security_field_copy=")==1) {
            m=substr($i,length("security_field_copy=")+1)
            n=split(m,parts,",")
            for(j=1;j<=n;j++) {
                split(parts[j],keyval,"=")
                if(keyval[1]=="calls") calls[r,w]=keyval[2]+0
                if(keyval[1]=="max") maxcopy[r,w]=secs(keyval[2])
                if(keyval[1]=="ge_1s") slow1[r,w]=keyval[2]+0
                if(keyval[1]=="ge_5s") slow5[r,w]=keyval[2]+0
            }
        }
    }
}
END {
    printf "%-4s %11s %9s %9s %9s %9s %7s %7s %9s\n",
        "Win","Field_rows","BASE_s","FIRST_s","NEW_s","NEW-BASE","calls_B","calls_N","max_NEW"
    for(w=3;w<=12;w++) {
        for(g=1;g<=3;g++) {
            r=(g==1?"BASE":g==2?"FIRST":"NEW")
            if(stages[r,w]!=1||typed[r,w]!=1||fields[r,w]<=0||calls[r,w]<=0)bad=1
            if(fields[r,w]!=fields["BASE",w]||events[r,w]!=events["BASE",w])bad=1
            totalFields[r]+=fields[r,w]
            totalCalls[r]+=calls[r,w]
            totalCopy[r]+=copy[r,w]
            totalSecurity[r]+=sec[r,w]
            totalFile[r]+=file[r,w]
            totalIngest[r]+=ingest[r,w]
            totalSlow1[r]+=slow1[r,w]
            totalSlow5[r]+=slow5[r,w]
        }
        printf "%-4d %11d %9.3f %9.3f %9.3f %+9.3f %7d %7d %9.3f\n",
            w,fields["BASE",w],copy["BASE",w],copy["FIRST",w],copy["NEW",w],
            copy["NEW",w]-copy["BASE",w],calls["BASE",w],calls["NEW",w],maxcopy["NEW",w]
    }
    if(bad) {
        print "FI DIAG STOP: workload or metric mismatch across runs"
        exit 1
    }
    print ""
    printf "%-7s %12s %9s %11s %10s %8s %8s %10s %10s\n",
        "Run","Field_rows","Calls","FieldCOPY_s","s/Mfields","ge_1s","ge_5s","File_s","Security_s"
    for(g=1;g<=3;g++) {
        r=(g==1?"BASE":g==2?"FIRST":"NEW")
        printf "%-7s %12d %9d %11.3f %10.3f %8d %8d %10.3f %10.3f\n",
            r,totalFields[r],totalCalls[r],totalCopy[r],
            totalCopy[r]*1000000/totalFields[r],totalSlow1[r],
            totalSlow5[r],totalFile[r],totalSecurity[r]
    }
    printf "FIELD COPY DIFFERENCE: first-base=%+.3fs new-base=%+.3fs\n",
        totalCopy["FIRST"]-totalCopy["BASE"],totalCopy["NEW"]-totalCopy["BASE"]
}' "$base/clone-11-08-26/recover.log" \
   "$first/clone-11-08-26/recover.log" \
   "$new/clone-11-08-26/recover.log" || fail 'per-window data differ'

printf '\n%s\n' '=== Private PostgreSQL checkpoint logs ==='
printf '%s\n' 'Note: logs include clone restore as well as the 10-window replay.'
for run in BASE FIRST NEW; do
    case "$run" in
        BASE) path="$base" ;;
        FIRST) path="$first" ;;
        NEW) path="$new" ;;
    esac
    manifest="$path/RUN_MANIFEST.txt"
    cluster=$(awk -F= '$1=="clone_database_root" {print $2}' "$manifest")
    case "$cluster" in
        /home/jwood/fi-window-bench-*/clone-11-08-26) ;;
        *) fail "unexpected private cluster path for $run: $cluster" ;;
    esac
    pglog="$jailroot$cluster/postgres.log"
    cfg="$jailroot$cluster/data/postgresql.conf"
    printf '\nRUN=%s\n' "$run"
    grep -E '^(source_commit|security_profile|file_profile|max_wal_size_mb|fsync|synchronous_commit|full_page_writes)=' "$manifest" || :
    if [ -f "$cfg" ]; then
        grep -E '^[[:space:]]*log_timezone[[:space:]]*=' "$cfg" || :
    fi
    recover="$path/clone-11-08-26/recover.log"
    born=$(stat -f %B "$recover")
    touched=$(stat -f %m "$recover")
    if [ "$born" -gt 0 ] && [ "$touched" -ge "$born" ]; then
        printf 'recover_log_begin_utc=%s\n' "$(date -u -r "$born" '+%Y-%m-%d %H:%M:%S')"
        printf 'recover_log_end_utc=%s\n' "$(date -u -r "$touched" '+%Y-%m-%d %H:%M:%S')"
    fi
    if [ ! -f "$pglog" ]; then
        printf 'postgres_log_missing=%s\n' "$pglog"
        continue
    fi
    awk '
    /checkpoint starting:/ {start++; if(n<24) lines[n++]=$0}
    /checkpoint complete:/ {
        complete++
        for(i=1;i<=NF;i++) {
            if($i ~ /^write=/) {v=$i;sub(/^write=/,"",v);write+=v+0}
            if($i ~ /^sync=/) {v=$i;sub(/^sync=/,"",v);sync+=v+0}
            if($i ~ /^total=/){v=$i;sub(/^total=/,"",v);total+=v+0}
        }
        if(n<24) lines[n++]=$0
    }
    END {
        printf "checkpoint_starts=%d completes=%d write_s=%.3f sync_s=%.3f total_s=%.3f\n",start,complete,write,sync,total
        for(i=0;i<n;i++) print lines[i]
        if(n==0) print "no logged checkpoints (may not be enabled)"
        if(start+complete>24) print "checkpoint output truncated"
    }' "$pglog"
done
printf '\nFI DIAG COMPLETE. ARC and disk counters were not captured during historical runs.\n'
