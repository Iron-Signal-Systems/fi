//go:build fi_c1_sor_dev

package recordingest

import (
    "context"
    "fmt"
    "reflect"
    "strings"
    "testing"

    "github.com/Iron-Signal-Systems/fi/go/internal/spool"
)

func c1SoRLocalPlanFixture(batches int)*PreparedGeneration{
    g:=&PreparedGeneration{ReceiptSHA256:strings.Repeat("a",64)}
    g.Receipt.Descriptor.SourceID="iss-fs-22a.iss.local"
    g.Receipt.Descriptor.GenerationID="20261124T100000.000000000Z-1234567890abcdef"
    g.Receipt.BatchCount=uint64(batches)
    g.Batches=make([]PreparedBatch,batches)
    for i:=0;i<batches;i++{
        id:=fmt.Sprintf("batch-%05d",i+1)
        g.Batches[i]=PreparedBatch{
            BatchID:id,DataPath:"/verified/receiver/"+id+".jsonl",
            Manifest:spool.Manifest{
                BatchID:id,RecordCount:100,DataBytes:32<<20,
            },
        }
    }
    g.Receipt.RecordCount=uint64(batches*100)
    g.Receipt.DataBytes=uint64(batches)*(32<<20)
    return g
}
func TestC1SoRLocalUsesOriginalSignedContinuousGroups(t *testing.T){
    g:=c1SoRLocalPlanFixture(130)
    start,signed,groups,err:=c1SoRLocalPlan(g,g.Receipt.Descriptor.SourceID)
    if err!=nil{t.Fatal(err)}
    if groups!=2||len(signed)!=130||len(start.BatchIDs)!=130||
       start.ExpectedRecords!=13000||start.ReceiptSHA256!=g.ReceiptSHA256{
        t.Fatal("original signed generation mapping changed")
    }
    if signed[0].Window!=1||signed[127].Window!=1||
       signed[128].Window!=2||signed[129].Window!=2{
        t.Fatal("4-GiB report group boundary changed")
    }
    for i,b:=range signed{
        if b.Index!=i||b.Batch.BatchID!=g.Batches[i].BatchID||
           b.Batch.DataPath!=g.Batches[i].DataPath{
            t.Fatal("signed source batch order or original byte path changed")
        }
    }
    if _,_,_,err:=c1SoRLocalPlan(g,"foreign-source");err==nil{
        t.Fatal("cross-source receipt admitted")
    }
    g.Receipt.RecordCount--
    if _,_,_,err:=c1SoRLocalPlan(g,g.Receipt.Descriptor.SourceID);err==nil{
        t.Fatal("inconsistent signed record count admitted")
    }
}
func TestC1SoRLocalRejectsUnconfiguredOrForeignWorker(t *testing.T){
    c:=C1SoRLocalConfig{
        SourceID:"iss-fs-22a.iss.local",
        WorkerDSN:"host=/var/run/postgresql port=5432 user=fi_ingest dbname=fi",
        PublisherDSN:"host=/var/run/postgresql port=5432 user=fi_c1_publisher dbname=fi",
        SQLWorkersMax:32,
        Custody:C1NativeBCustodyConfig{
            CustodyRoot:"/receiver/generation",
            RecordedRoot:"/receiver/recorded",
            SourceNamespaces:true,
            MaxCanonicalBytes:75161927680,MaxEncodedBytes:68719476736,
            MaxManifestBytes:1048576,
        },
    }
    if err:=validateC1SoRLocalConfig(c);err!=nil{t.Fatal(err)}
    load:=C1SoRLocalGenerationLoad(c)
    if load.SourceID!=c.SourceID||load.CustodyRoot!=c.Custody.CustodyRoot||
       load.RecordedRoot!=c.Custody.RecordedRoot||!load.SourceNamespaces{
        t.Fatal("fi-sor lost original receiver custody mapping")
    }
    c.SQLWorkersMax=33
    if err:=validateC1SoRLocalConfig(c);err==nil{
        t.Fatal("unbounded SQL pool admitted")
    }
    c.SQLWorkersMax=32
    c.WorkerDSN="host=192.168.20.4 port=5432 user=fi_ingest dbname=fi"
    if err:=validateC1SoRLocalConfig(c);err==nil{
        t.Fatal("remote PostgreSQL endpoint admitted")
    }
}
func TestC1SoRLocalNeverAdmitsWithoutAnActiveNativeSQLPool(t *testing.T){
    s:=&c1LocalDirectSQLSink{}
    if s.AsyncUSNDependencies(){t.Fatal("inactive local SQL sink advertised active USN sequencing")}
    if err:=s.Source(context.Background(),[]privateP6Record{{}});err==nil{
        t.Fatal("missing original native SQL pool accepted SourceParent")
    }
    if err:=s.Family(context.Background(),privateP6Security,[]privateP6Record{{}});err==nil{
        t.Fatal("missing original native SQL pool accepted Security SQL")
    }
}

type c1SoRLocalNoopSink struct{}
func(c1SoRLocalNoopSink)Source(context.Context,[]privateP6Record)error{return nil}
func(c1SoRLocalNoopSink)Family(context.Context,privateP6Family,[]privateP6Record)error{return nil}

func TestC1SoRLocalMatchesProvenHeaderFirstSecurityBuffer(t *testing.T){
    if reflect.ValueOf(c1SoRLocalBenchmarkedPrepare()).Pointer()!=
       reflect.ValueOf(privateHeaderFirstPrepare).Pointer(){
        t.Fatal("single-jail C1 substituted a non-benchmark P5 preparation function")
    }
    // The 20,482 records/sec C1 candidate used 8192/32MiB Security
    // buffering and 32 possible SQL workers; this is not the old 4096/16MiB.
    t.Setenv("FI_C1_SECURITY_8G_EXPERIMENT","0")
    t.Setenv("FI_C1_SECURITY_FULL_BACKLOG_CANDIDATE","0")
    buffers,err:=newC1NativeP6Buffers(1,c1SoRLocalNoopSink{})
    if err!=nil{t.Fatal(err)}
    limit:=buffers.lanes[privateP6Security].limit
    if limit.rows!=8192||limit.bytes!=32<<20{
        t.Fatalf("C1 native Security buffer regressed: %+v",limit)
    }
}
