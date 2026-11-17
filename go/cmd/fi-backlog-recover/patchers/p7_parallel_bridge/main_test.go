// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package main

import (
    "strings"
    "testing"
)

const privateP7BridgeFixture = `package recordingest
import "context"
type privateParallelAKey struct{}
func privateParallelARequested(ctx context.Context) bool {return true}
func privateParallelAEnabled(ctx context.Context) bool {
    return privateParallelARequested(ctx) &&
        privateDependencyBuffersEnabled(ctx) &&
        usePrivateSinglePassSecurity(ctx) &&
        joinedBacklogChunkRecords(ctx) == 32768 &&
        privateH16CombinedFileProfileValid(ctx) &&
        fileBulkLimitsFromContext(ctx).Name == "F3H16" &&
        securityBulkLimitsFromContext(ctx).Name == "P3"
}
`

func TestPrivateP7ASTBridgeAcceptsFormattingDifferences(t *testing.T) {
    for _,src := range []string{
        privateP7BridgeFixture,
        strings.ReplaceAll(privateP7BridgeFixture,"        ","\t"),
        strings.ReplaceAll(privateP7BridgeFixture,"\n        "," "),
    } {
        out,err:=bridgeCandidateA([]byte(src))
        if err!=nil {t.Fatal(err)}
        if strings.Count(string(out),"privateP7ParallelPreparationReader(ctx)")!=1 {
            t.Fatal("independent P7 activation guard absent or duplicated")
        }
        if _,err:=bridgeCandidateA(out);err==nil {
            t.Fatal("already patched Candidate A accepted a second edit")
        }
    }
}
func TestPrivateP7ASTBridgeRejectsModifiedH16Checks(t *testing.T) {
    for _,bad:=range []string{
        strings.Replace(privateP7BridgeFixture,"32768","16384",1),
        strings.Replace(privateP7BridgeFixture,"\"P3\"","\"P1\"",1),
        strings.Replace(privateP7BridgeFixture,"privateDependencyBuffersEnabled(ctx) &&","true &&",1),
        strings.Replace(privateP7BridgeFixture,"\"F3H16\"","\"F3\"",1),
    } {
        if _,err:=bridgeCandidateA([]byte(bad));err==nil {
            t.Fatal("changed Candidate A activation gate was accepted")
        }
    }
}
