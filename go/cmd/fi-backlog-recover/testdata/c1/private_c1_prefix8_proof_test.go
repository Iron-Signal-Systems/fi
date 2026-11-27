// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import "testing"

func TestPrivateC1Prefix8SignedDescriptorsAreNonterminalAndExact(t *testing.T){
    g,old:=privateC1EightGiBFixture(t)
    groups,stop,_,_,err:=privateC1EightGiBGroups(g,old,4)
    if err!=nil||stop!=2{t.Fatalf("8GiB prefix planning stop=%d err=%v",stop,err)}
    if err=privateC1ValidateEightGiBPrefix(g,groups,3);err!=nil{t.Fatal(err)}
    // The untouched remainder may be a single terminal descriptor: the
    // prefix is still nonterminal because group 2 stops before that tail.
    if groups[3].EndBatch!=len(g.Batches) || groups[2].EndBatch>=len(g.Batches) {
        t.Fatal("test fixture does not cover terminal remainder descriptor")
    }
    if err=privateC1ValidateEightGiBPrefix(g,groups,2);err==nil{
        t.Fatal("accepted missing second 4GiB reporting group")
    }
    wrong:=append([]BacklogCheckpointDescriptor(nil),groups...)
    wrong[2].EndBatch=len(g.Batches)
    if err=privateC1ValidateEightGiBPrefix(g,wrong,3);err==nil{
        t.Fatal("accepted complete generation as an 8GiB prefix")
    }
    wrong=append([]BacklogCheckpointDescriptor(nil),groups...)
    wrong[2].StartBatch++
    if err=privateC1ValidateEightGiBPrefix(g,wrong,3);err==nil{
        t.Fatal("accepted discontinuous signed 8GiB prefix")
    }
    wrong=append([]BacklogCheckpointDescriptor(nil),groups...)
    wrong[1].DataBytes--
    if err=privateC1ValidateEightGiBPrefix(g,wrong,3);err==nil{
        t.Fatal("accepted signed byte-count mismatch")
    }
    wrong=append([]BacklogCheckpointDescriptor(nil),groups...)
    wrong[2].PreviousDigestSHA256="changed"
    if err=privateC1ValidateEightGiBPrefix(g,wrong,3);err==nil{
        t.Fatal("accepted broken signed descriptor chain")
    }
}
