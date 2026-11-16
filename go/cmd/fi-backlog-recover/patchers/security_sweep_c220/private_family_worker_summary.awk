# FI W512 private clone — per-worker signed-batch aggregate.
# The SAME pinned file is smoke-tested in host preflight and used after replay.
# sec and general are passed with -v, for validated 8/8, 16/8, or 8/16.
# No database or network writes.
BEGIN {
    if(!((sec==8 && (general==8 || general==16)) ||
         (sec==16 && general==8))) {
        print "FI SWEEP REPORT STOP: invalid Security/general worker topology" > "/dev/stderr"
        exit 2
    }
}
/^FI FAMILY P3 WORKER / {
    delete fields
    for(i=1;i<=NF;i++) {
        split($i,part,"=")
        fields[part[1]]=part[2]
    }
    if (fields["complete"] != "true") {
        print "FI SWEEP REPORT STOP: incomplete per-worker snapshot" > "/dev/stderr"
        bad=1
    }
    key=fields["family"] ":" fields["worker"]
    rec[key]+=fields["records"]+0
    bytes[key]+=fields["bytes"]+0
    prep[key]+=fields["prepare_ns"]+0
    inbound[key]+=fields["input_wait_ns"]+0
    outbound[key]+=fields["output_wait_ns"]+0
    seen++
}
END {
    if(bad || seen==0) exit 1
    print "family\tworker\trecords\tbytes\tprepare_worker_seconds\tinput_wait_worker_seconds\toutput_wait_worker_seconds"
    split("Security File Coverage USNDependency Other",families," ")
    for(fi=1;fi<=5;fi++) {
        familyName=families[fi]
        limit=(familyName=="Security"?sec:general/4)
        for(j=0;j<limit;j++) {
            key=familyName ":" j
            printf "%s\t%d\t%.0f\t%.0f\t%.6f\t%.6f\t%.6f\n",
                familyName,j,rec[key],bytes[key],prep[key]/1e9,
                inbound[key]/1e9,outbound[key]/1e9
        }
    }
}
