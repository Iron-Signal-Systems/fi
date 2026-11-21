# FI P5 persisted worker lifetime, per W512 atomic window.
# -v windows=2 -v first=1 -v records1=499052 -v records2=498382.
# Reuse this exact pinned file for preflight synthetic fixtures and final SQL
# benchmark reports; no database or network operations.
BEGIN {
    if(windows!=2 || first!=1 || records1!=499052 || records2!=498382) {
        print "FI P5 REPORT STOP: expected W512 two-window fixture bounds" > "/dev/stderr"
        exit 2
    }
    split("Security File Coverage USNDependency Other",familyNames," ")
    for(i=1;i<=5;i++)known[i-1]=familyNames[i]
}
/^FI P5 PERSISTENT WINDOW FAMILY / {
    delete fields
    for(i=1;i<=NF;i++){
        split($i,x,"=")
        fields[x[1]]=x[2]
    }
    window=fields["window"]+0
    id=fields["family"]+0
    key=window ":" id
    if((window!=1 && window!=2) || id<0 || id>4 ||
       fields["family"]!=id || fields["complete"]!="true" ||
       fields["spawned"]<2 || fields["spawned"]>32 ||
       fields["scale_ups"]!=fields["spawned"]-2 ||
       fields["peak_busy"]<0 || fields["peak_busy"]>fields["spawned"] ||
       fields["max_queue"]<0 || fields["max_queue"]>32 ||
       fields["processed"]<0 || seen[key]++)bad=1
    rows[window]+=fields["processed"]+0
    workerSum[key]=fields["spawned"]+0
    scaleSum[key]=fields["scale_ups"]+0
    processed[key]=fields["processed"]+0
    peakBusy[key]=fields["peak_busy"]+0
    peakQueue[key]=fields["max_queue"]+0
    n++
}
END {
    if(n!=windows*5 || rows[1]!=records1 || rows[2]!=records2)bad=1
    for(w=first;w<first+windows;w++){
        for(f=0;f<5;f++)if(seen[w ":" f]!=1)bad=1
    }
    if(bad || n==0){
        print "FI P5 REPORT STOP: invalid per-window signed records, workers or completion" > "/dev/stderr"
        exit 1
    }
    print "window\tfamily\tspawned_workers\tscale_ups\tpeak_busy\tmax_queued\tprepared_records"
    for(w=first;w<first+windows;w++){
        for(f=0;f<5;f++){
            key=w ":" f
            printf "%d\t%s\t%d\t%d\t%d\t%d\t%.0f\n",
                w,known[f],workerSum[key],scaleSum[key],
                peakBusy[key],peakQueue[key],processed[key]
        }
    }
}
