//go:build fi_c1_sor_dev

package recordingest

import (
    "context"
    "testing"
)

func TestC1SoRUSNProjectorContextBindsExactGenerationPerHandoff(t *testing.T) {
    base:=context.Background()
    a,err:=c1SoRUSNCaptureContext(base,"iss-fs-22a.iss.local","signed-generation-a")
    if err!=nil{t.Fatal(err)}
    b,err:=c1SoRUSNCaptureContext(base,"iss-fs-22a.iss.local","signed-generation-a")
    if err!=nil{t.Fatal(err)}
    stateA,ok:=a.Value(usnCaptureContextKey{}).(*usnCaptureState)
    if !ok||stateA==nil{t.Fatal("original USN source-bound projector missing capture state")}
    stateB,ok:=b.Value(usnCaptureContextKey{}).(*usnCaptureState)
    if !ok||stateB==nil{t.Fatal("second SQL handoff missing capture state")}
    if stateA==stateB||stateA.boundaries==nil||stateB.boundaries==nil{
        t.Fatal("different SQL handoffs must not reuse mutable USN capture state")
    }
    if stateA.sourceID!="iss-fs-22a.iss.local"||stateA.generationID!="signed-generation-a"||
       stateB.sourceID!=stateA.sourceID||stateB.generationID!=stateA.generationID{
        t.Fatal("C1 capture is not bound to authenticated generation identity")
    }
    if enabled,ok:=a.Value(backlogUSNCrossWindowContextKey{}).(bool);!ok||!enabled{
        t.Fatal("cross-handoff SQL-bound capture restoration disabled")
    }
    if base.Value(usnCaptureContextKey{})!=nil||base.Value(backlogUSNCrossWindowContextKey{})!=nil{
        t.Fatal("SQL capture leaked into unrelated worker context")
    }
    for _,invalid:=range []struct{source,generation string}{
        {"","signed-generation-a"},{"iss-fs-22a.iss.local",""},{"",""},
    }{
        if _,err:=c1SoRUSNCaptureContext(base,invalid.source,invalid.generation);err==nil{
            t.Fatal("missing source or generation admitted")
        }
    }
    if _,err:=c1SoRUSNCaptureContext(nil,"source","generation");err==nil{
        t.Fatal("nil C1 projector context admitted")
    }
    other,err:=c1SoRUSNCaptureContext(base,"iss-fs-22b.iss.local","signed-generation-b")
    if err!=nil{t.Fatal(err)}
    stateOther:=other.Value(usnCaptureContextKey{}).(*usnCaptureState)
    if stateOther.sourceID==stateA.sourceID||stateOther.generationID==stateA.generationID{
        t.Fatal("USN capture context crossed signed generations or sources")
    }
}
