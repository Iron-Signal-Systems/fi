// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
    "strings"
    "testing"
)

func privateC1EightGiBFixture(t *testing.T)(*PreparedGeneration,[]BacklogCheckpointDescriptor){
    t.Helper()
    const batchCount=200
    sizes:=make([]int,batchCount)
    for i:=range sizes{sizes[i]=8192}
    g:=backlogWindowFixture(sizes,64<<20)
    g.ReceiptSHA256=strings.Repeat("c",64)
    g.Receipt.TransferSHA256=strings.Repeat("d",64)
    g.Receipt.Descriptor.SourceID="signed-source"
    g.Receipt.Descriptor.GenerationID="verified-generation"
    for i:=range g.Batches{
        g.Batches[i].ManifestSHA256=strings.Repeat("a",64)
        g.Batches[i].Manifest.DataSHA256=strings.Repeat("b",64)
    }
    original,e:=DescribeBacklogWindows(g,BacklogWindowLimits{
        MaxRecords:524288,MaxDataBytes:2<<30,
    })
    if e!=nil{t.Fatal(e)}
    return g,original
}
func TestPrivateC1EightGiBGroupPairsHaveExactSignedCutoff(t *testing.T){
    g,original:=privateC1EightGiBFixture(t)
    w2,stop2,rows2,bytes2,e:=privateC1EightGiBGroups(g,original,2)
    if e!=nil{t.Fatal(e)}
    w4,stop4,rows4,bytes4,e:=privateC1EightGiBGroups(g,original,4)
    if e!=nil{t.Fatal(e)}
    if stop2!=4||stop4!=2||rows2!=rows4||bytes2!=bytes4||bytes2!=8<<30{
        t.Fatalf("2GiB stop=%d rows=%d bytes=%d 4GiB stop=%d rows=%d bytes=%d",
            stop2,rows2,bytes2,stop4,rows4,bytes4)
    }
    if w2[0].DigestSHA256!=original[0].DigestSHA256||
        w4[0].DigestSHA256!=original[0].DigestSHA256||
        w2[stop2].EndBatch!=w4[stop4].EndBatch||
        w2[stop2].EndRecord!=w4[stop4].EndRecord||
        w2[stop2].EndBatch!=160{
        t.Fatal("8GiB variants selected different authenticated batches or modified seeded checkpoint")
    }
    for group,windows:=range map[int][]BacklogCheckpointDescriptor{2:w2,4:w4}{
        for i:=1;i<len(windows);i++{
            prev,cur:=windows[i-1],windows[i]
            if cur.PreviousDigestSHA256!=prev.DigestSHA256||
               cur.StartBatch!=prev.EndBatch||
               cur.StartRecord!=prev.EndRecord||
               cur.DataBytes>uint64(group)<<30 {
                t.Fatalf("%dGiB group %d broke signed chain or byte limit",group,i)
            }
        }
        if windows[len(windows)-1].EndBatch!=len(g.Batches)||
           windows[len(windows)-1].EndRecord!=g.Receipt.RecordCount{
            t.Fatalf("%dGiB planner lost signed-generation tail",group)
        }
    }
}
func TestPrivateC1EightGiBGroupsRejectInvalidConfiguration(t *testing.T){
    g,original:=privateC1EightGiBFixture(t)
    for _,size:=range []int{0,1,3,8,16}{
        if _,_,_,_,e:=privateC1EightGiBGroups(g,original,size);e==nil{
            t.Fatalf("accepted unsupported group size %d",size)
        }
    }
    wrong:=append([]BacklogCheckpointDescriptor(nil),original...)
    wrong[0].EndRecord++
    if _,_,_,_,e:=privateC1EightGiBGroups(g,wrong,2);e==nil{
        t.Fatal("accepted changed signed seed")
    }
}
