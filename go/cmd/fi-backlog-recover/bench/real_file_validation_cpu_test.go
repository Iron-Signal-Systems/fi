// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
//go:build freebsd

// Standalone, read-only benchmark fixture. The runner copies this test into an
// isolated checkout of the EXACT historical FI source; it does not alter any
// application code or use a PostgreSQL connection.
package recordingest

import (
    "bufio"
    "bytes"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "io"
    "io/fs"
    "os"
    "path/filepath"
    "runtime"
    "sort"
    "strconv"
    "strings"
    "syscall"
    "testing"
    "time"

    "github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
)

type realFileValidationSample struct {
    raw []byte
    observation ntfs.Observation
}

type realValidatorTiming struct {
    arm string
    stage string
    calls int64
    elapsed time.Duration
    cpuUser float64
    cpuSystem float64
    mallocs uint64
    allocBytes uint64
    gcCount uint32
}

var realValidatorSink int64
var errEnoughRealFiles = errors.New("FI validator: requested real signed sample count reached")

// loadRealSignedFileSamples reads only the baseline's already verified,
// byte-identical original signed JSONL data artifacts. It fails closed on
// malformed candidates and never writes to the source tree or source data.
func loadRealSignedFileSamples(t *testing.T, dir string, limit int) ([]realFileValidationSample, string, int) {
    t.Helper()
    var samples []realFileValidationSample
    samples = make([]realFileValidationSample, 0, limit)
    hash := sha256.New()
    selected := []byte("\"record_kind\":\"FileObservation\"")
    filesSeen := 0
    err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, walkErr error) error {
        if walkErr != nil { return walkErr }
        if entry.IsDir() { return nil }
        if !strings.HasPrefix(entry.Name(), "batch-") || !strings.HasSuffix(entry.Name(), ".data") { return nil }
        filesSeen++
        file, openErr := os.Open(path)
        if openErr != nil { return fmt.Errorf("open signed batch %s: %w", path, openErr) }
        defer file.Close()
        reader := bufio.NewReaderSize(file, 256*1024)
        var recordNumber int
        for {
            raw, readErr := reader.ReadBytes('\n')
            if len(raw) == 0 && errors.Is(readErr, io.EOF) { break }
            recordNumber++
            if readErr != nil {
                return fmt.Errorf("read signed batch %s record %d: %w", path, recordNumber, readErr)
            }
            if !bytes.Contains(raw, selected) { continue }
            prepared, prepareErr := prepareOwnedSourceRecord(raw)
            if prepareErr != nil {
                return fmt.Errorf("invalid signed candidate %s record %d: %w", path, recordNumber, prepareErr)
            }
            if prepared.Record.RecordKind != "FileObservation" { continue }
            var value fileObservationPayload
            if decodeErr := decodeStrictPayload(prepared.Record.Payload, &value); decodeErr != nil {
                return fmt.Errorf("decode signed file %s record %d: %w", path, recordNumber, decodeErr)
            }
            value.NTFS.ContentHashes = &value.ContentHashes
            if validateErr := ntfs.ValidateObservation(value.NTFS); validateErr != nil {
                return fmt.Errorf("invalid signed file %s record %d: %w", path, recordNumber, validateErr)
            }
            if value.NTFS.GovernedRoot.ScopeID != prepared.Record.ScopeID {
                return fmt.Errorf("signed FileObservation source-scope mismatch: %s record %d", path, recordNumber)
            }
            if _, writeErr := hash.Write(raw); writeErr != nil { return writeErr }
            samples = append(samples, realFileValidationSample{raw: raw, observation: value.NTFS})
            if len(samples) == limit { return errEnoughRealFiles }
        }
        return nil
    })
    if err != nil && !errors.Is(err, errEnoughRealFiles) {
        t.Fatalf("signed data sample failed: %v", err)
    }
    if len(samples) != limit {
        t.Fatalf("required exactly %d real FileObservations, got %d from %d original batches", limit, len(samples), filesSeen)
    }
    return samples, hex.EncodeToString(hash.Sum(nil)), filesSeen
}

func rusageCPU() (user, system float64, err error) {
    var ru syscall.Rusage
    if err = syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil { return 0,0,err }
    user = float64(ru.Utime.Sec) + float64(ru.Utime.Usec)/1e6
    system = float64(ru.Stime.Sec) + float64(ru.Stime.Usec)/1e6
    return user, system, nil
}

// executeRealValidationLoop executes precisely the same original FI functions
// under both arms. The extra call in double mode is the only change.
// The original JSON is decoded anew for every iteration in the full-pipeline
// stage, and only once when samples are loaded in the validator-only stage.
func executeRealValidationLoop(samples []realFileValidationSample, repeats int, twice, full bool) (int64, error) {
    var calls int64
    for r:=0; r<repeats; r++ {
        for i:=range samples {
            observation := samples[i].observation
            if full {
                prepared, err:=prepareOwnedSourceRecord(samples[i].raw)
                if err!=nil { return calls,err }
                if prepared.Record.RecordKind!="FileObservation" { return calls, errors.New("unexpected source kind") }
                var value fileObservationPayload
                if err:=decodeStrictPayload(prepared.Record.Payload,&value); err!=nil { return calls,err }
                value.NTFS.ContentHashes=&value.ContentHashes
                if value.NTFS.GovernedRoot.ScopeID!=prepared.Record.ScopeID { return calls,errors.New("source scope mismatch") }
                observation=value.NTFS
            }
            if err:=ntfs.ValidateObservation(observation);err!=nil { return calls,err }
            calls++
            if twice {
                if err:=ntfs.ValidateObservation(observation);err!=nil { return calls,err }
                calls++
            }
        }
    }
    return calls,nil
}

func measureRealValidation(t *testing.T, stage string, samples []realFileValidationSample, repeats int, twice, full bool) realValidatorTiming {
    t.Helper()
    runtime.GC() // outside measurement; each arm starts from a collected heap
    var before, after runtime.MemStats
    runtime.ReadMemStats(&before)
    userBefore, sysBefore, err:=rusageCPU()
    if err!=nil {t.Fatalf("getrusage before: %v",err)}
    start:=time.Now()
    calls, err:=executeRealValidationLoop(samples,repeats,twice,full)
    elapsed:=time.Since(start)
    userAfter,sysAfter,ruErr:=rusageCPU()
    runtime.ReadMemStats(&after)
    if err!=nil {t.Fatalf("real validation call: %v",err)}
    if ruErr!=nil {t.Fatalf("getrusage after: %v",ruErr)}
    expected:=int64(len(samples)*repeats)
    if twice {expected*=2}
    if calls!=expected {t.Fatalf("wrong validation call count: %d expected %d",calls,expected)}
    realValidatorSink+=calls // prevent the counted calls from becoming dead code
    arm:="ONE";if twice {arm="TWO"}
    return realValidatorTiming{
        arm:arm,stage:stage,calls:calls,elapsed:elapsed,
        cpuUser:userAfter-userBefore,cpuSystem:sysAfter-sysBefore,
        mallocs:after.Mallocs-before.Mallocs,allocBytes:after.TotalAlloc-before.TotalAlloc,
        gcCount:after.NumGC-before.NumGC,
    }
}

func medianRealValues(values []float64) float64 {
    sort.Float64s(values)
    if len(values)==0 {return 0}
    n:=len(values)
    if n%2==1 {return values[n/2]}
    return (values[n/2-1]+values[n/2])/2
}

func summarizeRealValidation(stage string, result []realValidatorTiming, callsPerArm int64) {
    oneCPU,twoCPU:=[]float64{},[]float64{}
    oneWall,twoWall:=[]float64{},[]float64{}
    oneAllocs,twoAllocs:=[]float64{},[]float64{}
    for _,v:=range result {
        cpu:=v.cpuUser+v.cpuSystem
        if v.arm=="ONE" {
            oneCPU=append(oneCPU,cpu);oneWall=append(oneWall,v.elapsed.Seconds());oneAllocs=append(oneAllocs,float64(v.mallocs))
        } else {
            twoCPU=append(twoCPU,cpu);twoWall=append(twoWall,v.elapsed.Seconds());twoAllocs=append(twoAllocs,float64(v.mallocs))
        }
    }
    cpuA,cpuB:=medianRealValues(oneCPU),medianRealValues(twoCPU)
    wallA,wallB:=medianRealValues(oneWall),medianRealValues(twoWall)
    allocA,allocB:=medianRealValues(oneAllocs),medianRealValues(twoAllocs)
    // CPU delta divided by the number of extra validator calls in TWO.
    savedUS:=(cpuB-cpuA)*1e6/float64(callsPerArm)
    fmt.Printf("FI REAL VALIDATION SUMMARY stage=%s samples_per_arm=%d measurements_per_arm=%d one_cpu_s=%.6f two_cpu_s=%.6f delta_cpu_s=%.6f saved_cpu_us_per_removed_call=%.3f one_wall_s=%.6f two_wall_s=%.6f delta_wall_s=%.6f one_allocs=%.0f two_allocs=%.0f\n",
        stage,callsPerArm,len(oneCPU),cpuA,cpuB,cpuB-cpuA,savedUS,wallA,wallB,wallB-wallA,allocA,allocB)
    if cpuB < cpuA {
        fmt.Printf("FI REAL VALIDATION WARNING stage=%s cpu_delta_negative=true verify host noise and sample invariants before attribution\n",stage)
    }
}

// TestRealSignedFileValidatorCost measures original signed FileObservations with
// balanced ABBA order inside ONE process, on ONE Go runtime/host environment.
// There is no SQL activity and no fabricated payload in this experiment.
func TestRealSignedFileValidatorCost(t *testing.T) {
    dir:=os.Getenv("FI_SIGNED_DATA_ROOT")
    if dir=="" {t.Fatal("FI_SIGNED_DATA_ROOT must name the read-only baseline signed artifact root")}
    sampleLimit:=4096
    if raw:=os.Getenv("FI_VALIDATOR_SAMPLES");raw!="" {
        v,err:=strconv.Atoi(raw);if err!=nil||v<256||v>16384 {t.Fatal("FI_VALIDATOR_SAMPLES must be 256..16384")};sampleLimit=v
    }
    samples,fingerprint,files:=loadRealSignedFileSamples(t,dir,sampleLimit)
    fmt.Printf("FI REAL VALIDATION INPUT source=baseline_verified_signed_data samples=%d batches_read=%d concatenated_sample_sha256=%s go=%s gomaxprocs=%d\n",
        len(samples),files,fingerprint,runtime.Version(),runtime.GOMAXPROCS(0))
    if runtime.GOMAXPROCS(0)!=1 {t.Fatal("set GOMAXPROCS=1 for single-core paired measurement")}
    for _,phase:=range []struct{name string;repeats,groups int;full bool}{
        {"validator_only",12,3,false},
        {"envelope_decode_plus_validator",2,2,true},
    }{
        var results []realValidatorTiming
        for group:=0;group<phase.groups;group++ {
            // ABBA rotation controls for startup/thermal/cache drift; each
            // arm uses exactly the same signed data and original Go functions.
            for index,twice:=range []bool{false,true,true,false} {
                measure:=measureRealValidation(t,phase.name,samples,phase.repeats,twice,phase.full)
                results=append(results,measure)
                fmt.Printf("FI REAL VALIDATION ROUND stage=%s group=%d position=%d arm=%s calls=%d elapsed_ms=%.3f cpu_user_ms=%.3f cpu_system_ms=%.3f allocs=%d allocated_bytes=%d gc=%d\n",
                    phase.name,group,index,measure.arm,measure.calls,float64(measure.elapsed.Microseconds())/1000,
                    measure.cpuUser*1000,measure.cpuSystem*1000,measure.mallocs,measure.allocBytes,measure.gcCount)
            }
        }
        summarizeRealValidation(phase.name,results,int64(len(samples)*phase.repeats))
    }
    fmt.Printf("FI REAL VALIDATION COMPLETE status=PASS no_sql=true signed_input_readonly=true call_sink=%d\n",realValidatorSink)
}
