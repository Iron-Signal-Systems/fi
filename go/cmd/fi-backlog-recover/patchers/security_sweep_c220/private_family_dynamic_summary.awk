# FI C220 P4 private dynamic per-lane scaling report.
# Pinned AWK source is exercised with synthetic receipts BEFORE PostgreSQL.
# In P5, scale_ups is the *new spawns in that batch* and spawned is the
# persistent pool size at batch completion; do not require equality.
# Input is all "FI FAMILY DYNAMIC LANE" receipts.
# Required -v batches=1 (preflight) or batches=431 (two-window).
BEGIN {
    if(batches<=0 || batches!=int(batches)) {
        print "FI DYNAMIC REPORT STOP: invalid signed-batch count" > "/dev/stderr"
        exit 2
    }
    split("Security File Coverage USNDependency Other",names," ")
    for(i=1;i<=5;i++)expected[names[i]]=1
}
/^FI FAMILY DYNAMIC LANE / {
    delete fields
    for(i=1;i<=NF;i++){
        split($i,a,"=")
        fields[a[1]]=a[2]
    }
    family=fields["family"]
    if(!(family in expected) || fields["complete"]!="true" ||
       fields["min"]!=2 || fields["max"]!=16 ||
       fields["spawned"]<2 || fields["spawned"]>16 ||
       fields["peak_busy"]<0 || fields["peak_busy"]>fields["spawned"] ||
       fields["scale_ups"]<0 ||
       fields["scale_ups"]>fields["spawned"]-2 ||
       fields["peak_pending"]<0 || fields["peak_pending"]>32 ||
       fields["assigned"]!=fields["prepared"] ||
       fields["assigned"]!=fields["dispatched"])bad=1
    seen[family]++
    processed[family]+=fields["prepared"]
    sumScaleUps[family]+=fields["scale_ups"]
    if(fields["spawned"]>peakSpawned[family])peakSpawned[family]=fields["spawned"]
    if(fields["peak_busy"]>peakBusy[family])peakBusy[family]=fields["peak_busy"]
    if(fields["peak_pending"]>peakPending[family])peakPending[family]=fields["peak_pending"]
    n++
}
END {
    if(n!=batches*5)bad=1
    for(i=1;i<=5;i++)if(seen[names[i]]!=batches)bad=1
    if(bad || n==0){
        print "FI DYNAMIC REPORT STOP: invalid lane counts, spawn limits, source accounting or completion" > "/dev/stderr"
        exit 1
    }
    print "family\tbatches\tprepared_records\tpeak_spawned_workers\tpeak_busy_workers\tpeak_pending_records\tscale_ups"
    for(i=1;i<=5;i++){
        family=names[i]
        printf "%s\t%d\t%.0f\t%d\t%d\t%d\t%.0f\n",family,seen[family],
            processed[family],peakSpawned[family],peakBusy[family],
            peakPending[family],sumScaleUps[family]
    }
}
