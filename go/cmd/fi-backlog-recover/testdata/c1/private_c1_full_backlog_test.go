// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import "testing"

// Explicitly prove full signed generation coverage; stopping after the
// near-8GiB prefix is not a complete generation.
func TestPrivateC1FullFourGiBGroupsCoverEntireSignedGeneration(t *testing.T) {
    g,original:=privateC1EightGiBFixture(t)
    ds,prefixGroups,_,_,err:=privateC1EightGiBGroups(g,original,4)
    if err!=nil{t.Fatal(err)}
    if prefixGroups!=2||len(ds)<=prefixGroups+1{
        t.Fatalf("incorrect 8GiB stop-only plan groups=%d descriptors=%d",prefixGroups,len(ds))
    }
    if ds[0].DigestSHA256!=original[0].DigestSHA256{
        t.Fatal("original signed seed descriptor was replaced")
    }
    if ds[len(ds)-1].EndBatch!=len(g.Batches)||
        ds[len(ds)-1].EndRecord!=g.Receipt.RecordCount{
        t.Fatal("full-backlog plan doesn't reach the verified receipt's last record")
    }
    var totalBytes uint64
    for i,d:=range ds{
        totalBytes+=d.DataBytes
        if i>0{
            if d.PreviousDigestSHA256!=ds[i-1].DigestSHA256||
                d.StartBatch!=ds[i-1].EndBatch||
                d.StartRecord!=ds[i-1].EndRecord||
                d.DataBytes>4<<30{
                t.Fatalf("4GiB descriptor %d is not contiguous or exceeds byte budget",i)
            }
        }
    }
    if totalBytes!=g.Receipt.DataBytes{
        t.Fatalf("signed bytes changed: total=%d signed=%d",totalBytes,g.Receipt.DataBytes)
    }
}
