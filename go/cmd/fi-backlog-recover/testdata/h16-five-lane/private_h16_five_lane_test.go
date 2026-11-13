// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
    "context"
    "testing"
)

// Select exactly the same established private dependency context as the
// pinned W3/W4 real signed route, then explicitly opt into fifth-lane mode.
func privateH16FiveLaneTestContext(t *testing.T) context.Context {
    t.Helper()
    base := privateDependencyTestContext(t)
    five,err := WithPrivateH16FiveLaneCoordinator(base)
    if err!=nil {t.Fatal(err)}
    h16,err := WithPrivateFileHashH16(five)
    if err!=nil {t.Fatal(err)}
    if !privateH16FiveLaneEnabled(h16) {t.Fatal("five-lane mode did not survive F3H16 hash-only profile")}
    return h16
}

func TestPrivateH16FiveLaneRejectsWrongModes(t *testing.T) {
    if _,err:=WithPrivateH16FiveLaneCoordinator(nil);err==nil {t.Fatal("nil context enabled five-lane")}
    if _,err:=WithPrivateH16FiveLaneCoordinator(context.Background());err==nil {t.Fatal("canonical mode enabled five-lane")}
    if _,err:=WithPrivateH16FiveLaneCoordinator(privateMixedTestContext(t));err==nil {t.Fatal("mixed-only mode enabled five-lane")}
    ctx:=privateH16FiveLaneTestContext(t)
    missingDependency:=context.WithValue(ctx,privateDependencyBuffersKey{},false)
    if privateH16FiveLaneEnabled(missingDependency) {t.Fatal("missing dependency mode accepted")}
    noFields:=context.WithValue(ctx,privateSecurityFieldPartitionsKey{},false)
    if privateH16FiveLaneEnabled(noFields) {t.Fatal("Security isolation missing")}
    bad:=fileBulkLimitsFromContext(ctx);bad.ObserveMaxBytes++
    if privateH16FiveLaneEnabled(context.WithValue(ctx,fileBulkProfileContextKey{},bad)) {
        t.Fatal("modified File projection cap accepted")
    }
}

func TestPrivateH16FiveLaneIndependentRoutingAndOrdering(t *testing.T) {
    ctx:=privateH16FiveLaneTestContext(t)
    for _,kind:=range []string{
        "WindowsSecurityEvent","FileObservation","WindowsSecurityCoverage",
        "USNReadBoundary","USNObjectObservation",
    } {
        if privateH16FiveLaneOrderingFence(kind) {t.Fatalf("%s triggered unnecessary all-lane drain",kind)}
        d:=securityFileFlushBeforeKind(ctx,kind)
        if d.files||d.security {t.Fatalf("%s drained unrelated Security/File source buffers",kind)}
    }
    for _,kind:=range []string{"USNContinuityGap","CollectorIdentity","UnknownFamily"} {
        if !privateH16FiveLaneOrderingFence(kind) {t.Fatalf("%s lost required conservative ordering fence",kind)}
        d:=securityFileFlushBeforeKind(ctx,kind)
        if !d.security||!d.files {t.Fatalf("%s lost source fences",kind)}
    }
    if !privateH16FiveLaneDeferProjectionAfterSource(ctx) {t.Fatal("fifth File projection lane was disabled")}
    if privateH16FiveLaneDeferProjectionAfterSource(context.Background()) {t.Fatal("ordinary H16 changed projection flush policy")}
    for i:=0;i<4;i++ {
        if h16FamilyDrainAtBoundary(ctx,true,false) {t.Fatalf("K32 partial drain %d",i)}
    }
    if !h16FamilyDrainAtBoundary(ctx,true,true) {t.Fatal("missing mandatory final W128 drain")}
}

func TestPrivateH16FiveLaneZeroCopySliceOwnership(t *testing.T) {
    // The coordinator accesses the same File source and projected File
    // buffers the original H16 processing chunk already owns. There is no
    // duplicate queue or copy of the record payload.
    state:=&backlogTypedChunkState{fileBulk:newFileObservationBulkState()}
    state.files=make([]fileSourceBulkRecord,1,4)
    state.security=make([]securityBulkRecord,1,4)
    fileBefore:=&state.files[0]
    securityBefore:=&state.security[0]
    ctx:=privateH16FiveLaneTestContext(t)
    ctx=context.WithValue(ctx,backlogTypedChunkContextKey{},backlogTypedChunkDirective{state:state})
    if err:=validatePrivateFamilyRoute(ctx);err!=nil {t.Fatal(err)}
    if &state.files[0]!=fileBefore||&state.security[0]!=securityBefore {
        t.Fatal("five-lane coordinator unexpectedly copied pre-existing buffers")
    }
    tele:=&privateH16FiveLaneTelemetry{}
    ctx=context.WithValue(ctx,privateH16FiveLaneTelemetryKey{},tele)
    if privateH16FiveLaneStats(ctx)!=tele {t.Fatal("telemetry does not preserve W128 ownership")}
}
