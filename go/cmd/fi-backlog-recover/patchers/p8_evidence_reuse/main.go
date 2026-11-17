// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Exact-anchor P8 overlay. Only disposable C220 sources; production never
// builds or invokes this patcher. Historical P7 sources remain unchanged.
package main

import (
    "errors"
    "fmt"
    "go/ast"
    "go/parser"
    "go/token"
    "os"
    "path/filepath"
    "strings"
)

type edit struct{ path, old, replacement string }

var edits=[]edit{
    {
        "go/internal/recordingest/backlog_verified_cache_recovery.go",
        "if err=StageBacklogSourceAndTypedWindow(ctx,reader,writer,g,limits,window,privateRoot);err!=nil{",
        `stageCtx:=ctx
   // This proof is created ONLY AFTER the already-completed
   // MaterializeBacklogWindow + RecordVerifiedBacklogArtifactWindow.
   // No persisted checkpoint can mint a fresh in-memory proof.
   if privateP7FiveWriterSelected() {
    stageCtx,err=privateP8WithVerifiedOuterArtifact(ctx,privateRoot,d,window)
    if err!=nil{return empty,fmt.Errorf("FI P8: outer verified artifact handoff: %w",err)}
   }
   if err=StageBacklogSourceAndTypedWindow(stageCtx,reader,writer,g,limits,window,privateRoot);err!=nil{`,
    },
    {
        "go/internal/recordingest/backlog_source_window_postgres.go",
        `if err := VerifyMaterializedBacklogWindow(ctx, g, limits, index, privateRoot); err != nil {
        return fmt.Errorf("FI backlog source stage: source copy verification failed: %w", err)
    }`,
        `// StageVerifiedBacklogSourceWindow ALWAYS scans every signed batch,
    // checks its per-batch SHA/count/bytes and hashes all staged SQL rows.
    // Avoid a second full-data preliminary hash only when the SAME
    // operation already finished the exact outer artifact checkpoint.
    if !privateP8OuterEvidenceMatches(ctx,privateRoot,d,index) {
        if err := VerifyMaterializedBacklogWindow(ctx, g, limits, index, privateRoot); err != nil {
            return fmt.Errorf("FI backlog source stage: source copy verification failed: %w", err)
        }
    }`,
    },
}

func main(){
    if len(os.Args)!=3 {fail(errors.New("usage audit|apply /absolute/disposable/optimized-source"))}
    mode,root:=os.Args[1],filepath.Clean(os.Args[2])
    if !filepath.IsAbs(root)||!strings.HasSuffix(root,"/optimized-source"){
        fail(errors.New("source root must be absolute and optimized-source"))
    }
    original:=root=="/home/jwood/fi-window-bench-w512-20261115T153532Z/optimized-source"
    private:=(strings.HasPrefix(root,"/home/jwood/fi-window-bench-w512-family-p3-")||
        strings.HasPrefix(root,"/home/jwood/fi-p7-five-writer-go-tests-")) &&
        !strings.Contains(root,"..")
    if (mode=="audit" && !(private||original)) || (mode=="apply" && !private) {
        fail(errors.New("P8 patching allowed only on verified private disposable roots"))
    }
    if mode=="apply" {
        helper:=filepath.Join(root,"go/internal/recordingest/private_p8_verified_outer.go")
        p7:=filepath.Join(root,"go/internal/recordingest/private_p7_typed_window.go")
        for _,p:=range []string{helper,p7}{
            st,err:=os.Lstat(p)
            if err!=nil||!st.Mode().IsRegular(){fail(fmt.Errorf("missing private P8 source %s: %v",p,err))}
        }
    }
    files:=map[string][]byte{}
    perms:=map[string]os.FileMode{}
    for _,e:=range edits{
        p:=filepath.Join(root,e.path)
        st,err:=os.Lstat(p)
        if err!=nil||!st.Mode().IsRegular() {fail(fmt.Errorf("expected private source %s: %v",e.path,err))}
        old,err:=os.ReadFile(p)
        if err!=nil{fail(err)}
        rewritten,err:=rewrite(old,e)
        if err!=nil{fail(fmt.Errorf("%s: %w",e.path,err))}
        files[p]=rewritten
        perms[p]=st.Mode().Perm()
    }
    if mode=="audit" {
        fmt.Printf("FI P8 EVIDENCE SOURCE AUDIT PASS edits=%d source_unchanged=true\n",len(edits))
        return
    }
    // Every anchor has already passed before the first disposable file edit.
    for _,e:=range edits{
        p:=filepath.Join(root,e.path)
        tmp:=p+".p8-verified.tmp"
        if _,err:=os.Lstat(tmp);!errors.Is(err,os.ErrNotExist) {
            fail(fmt.Errorf("temporary P8 patch collision %s",tmp))
        }
        if err:=os.WriteFile(tmp,files[p],perms[p]);err!=nil{fail(err)}
        if err:=os.Rename(tmp,p);err!=nil {os.Remove(tmp);fail(err)}
    }
    fmt.Println("FI P8 VERIFIED EVIDENCE PATCH PASS outer_checkpoint=reused source_sql_scan=retained typed_canonical_sha=retained clone_only=true")
}

func rewrite(input []byte,e edit)([]byte,error){
    if strings.Contains(e.path,"backlog_verified_cache_recovery.go"){
        return rewriteOuterVerifiedCache(input)
    }
    s:=string(input)
    // Seed formatting may be gofmt tabs rather than the short literal
    // captured in the source review. Normalize only the exact initial
    // verification block's whitespace; never relax the function name,
    // digest comparison, or SQL source ledger.
    if strings.Contains(e.path,"backlog_source_window_postgres.go"){
        if strings.Contains(s,"if !privateP8OuterEvidenceMatches(ctx,privateRoot,d,index)") {
            return nil,errors.New("P8 signed-source verification prehash already patched")
        }
        start:=strings.Index(s,"if err := VerifyMaterializedBacklogWindow(ctx, g, limits, index, privateRoot); err != nil {")
        if start<0 || strings.Count(s,"if err := VerifyMaterializedBacklogWindow(ctx, g, limits, index, privateRoot); err != nil {")!=1{
            return nil,errors.New("P8 original full artifact verifier anchor missing")
        }
        end:=strings.Index(s[start:],"}\n")
        if end<0{return nil,errors.New("P8 original verification block incomplete")}
        end+=start+2
        section:=s[start:end]
        if !strings.Contains(section,`return fmt.Errorf("FI backlog source stage: source copy verification failed: %w", err)`) ||
            strings.Count(section,"return fmt.Errorf(")!=1 ||
            strings.Count(section,"}")!=1{
            return nil,errors.New("P8 original artifact verifier unexpectedly changed")
        }
        return []byte(s[:start]+e.replacement+s[end:]),nil
    }
    if strings.Count(s,e.old)!=1 || strings.Contains(s,e.replacement) {
        return nil,errors.New("P8 outer checkpoint handoff anchor changed or already patched")
    }
    return []byte(strings.Replace(s,e.old,e.replacement,1)),nil
}
// Parse the original optimized Go source instead of assuming the historical
// whitespace or equality-assignment syntax. A P8 proof may only be minted
// within the same window loop, AFTER materialization AND committed artifact
// verification. No branch around either operation is permitted.
func rewriteOuterVerifiedCache(input []byte)([]byte,error){
    if strings.Contains(string(input),"privateP8WithVerifiedOuterArtifact("){
        return nil,errors.New("P8 outer evidence already injected")
    }
    fs:=token.NewFileSet()
    parsed,err:=parser.ParseFile(fs,"backlog_verified_cache_recovery.go",input,parser.AllErrors)
    if err!=nil{return nil,fmt.Errorf("P8 outer Go source invalid: %w",err)}
    var target *ast.FuncDecl
    for _,d:=range parsed.Decls {
        fn,ok:=d.(*ast.FuncDecl)
        if !ok||fn.Name.Name!="recoverBacklogVerifiedCachedWindows"{continue}
        if target!=nil{return nil,errors.New("P8 duplicate verified-cache entrypoint")}
        target=fn
    }
    if target==nil||target.Body==nil{
        return nil,errors.New("P8 verified-cache entrypoint missing")
    }
    var sourceLoop *ast.ForStmt
    var stageStmt *ast.IfStmt
    var stageCall *ast.CallExpr
    matches:=0
    ast.Inspect(target.Body,func(n ast.Node)bool{
        loop,ok:=n.(*ast.ForStmt)
        if !ok||loop.Body==nil{return true}
        materialized,artifact,staged:=-1,-1,-1
        var candidate *ast.IfStmt
        var call *ast.CallExpr
        for i,s:=range loop.Body.List {
            if outerContainsCall(s,"MaterializeBacklogWindow"){materialized=i}
            if outerContainsCall(s,"RecordVerifiedBacklogArtifactWindow"){artifact=i}
            if outerContainsCall(s,"StageBacklogSourceAndTypedWindow"){
                staged=i
                stmt,ok:=s.(*ast.IfStmt)
                if !ok||stmt.Init==nil{continue}
                init,ok:=stmt.Init.(*ast.AssignStmt)
                if !ok||len(init.Rhs)!=1{continue}
                invoke,ok:=init.Rhs[0].(*ast.CallExpr)
                if !ok||!outerIsCall(invoke,"StageBacklogSourceAndTypedWindow"){continue}
                candidate=stmt
                call=invoke
            }
        }
        if staged>=0 {
            matches++
            if materialized<0||artifact<=materialized||staged<=artifact||
                candidate==nil||call==nil{
                // A second loop with invalid order must fail the entire patch.
                matches=100
                return false
            }
            sourceLoop,stageStmt,stageCall=loop,candidate,call
        }
        return true
    })
    if matches!=1||sourceLoop==nil||stageStmt==nil||stageCall==nil{
        return nil,errors.New("P8 exact signed materialize->artifact->typed stage sequence changed")
    }
    want:=[]string{"ctx","reader","writer","g","limits","window","privateRoot"}
    if len(stageCall.Args)!=len(want){
        return nil,errors.New("P8 original joined source stage argument count changed")
    }
    for i,argument:=range stageCall.Args {
        id,ok:=argument.(*ast.Ident)
        if !ok||id.Name!=want[i] {
            return nil,fmt.Errorf("P8 original joined source stage argument %d changed",i)
        }
    }
    hasDescriptor:=false
    for _,s:=range sourceLoop.Body.List{
        if !outerContainsCall(s,"DescribeBacklogWindows") {
            // The per-window descriptor is a direct local lookup.
            if assign,ok:=s.(*ast.AssignStmt);ok{
                for _,lhs:=range assign.Lhs{
                    if id,ok:=lhs.(*ast.Ident);ok&&id.Name=="d" {
                        hasDescriptor=true
                    }
                }
            }
        }
    }
    if !hasDescriptor {
        return nil,errors.New("P8 source loop descriptor binding missing")
    }
    if !outerHasCallInBody(target.Body,"VerifyCompleteBacklogTypedGeneration"){
        return nil,errors.New("P8 final signed typed verification no longer present")
    }
    start:=fs.Position(stageStmt.Pos()).Offset
    first:=fs.Position(stageCall.Args[0].Pos()).Offset
    last:=fs.Position(stageCall.Args[0].End()).Offset
    if start<0||first<=start||last!=first+3||last>len(input) ||
        string(input[first:last])!="ctx" {
        return nil,errors.New("P8 signed source stage AST offset mismatch")
    }
    // Only insert before this one verified-cache stage and replace exactly
    // its first argument. Preserve all original source lines and checks.
    lineStart:=start
    for lineStart>0&&input[lineStart-1]!='\n'{lineStart--}
    indent:=string(input[lineStart:start])
    for _,ch:=range indent{
        if ch!=' '&&ch!='\t'{
            return nil,errors.New("P8 original source statement indentation unsafe")
        }
    }
    prefix:=indent+"stageCtx := ctx\n"+
        indent+"if privateP7FiveWriterSelected() {\n"+
        indent+"    var proofErr error\n"+
        indent+"    stageCtx, proofErr = privateP8WithVerifiedOuterArtifact(ctx,privateRoot,d,window)\n"+
        indent+"    if proofErr != nil {return empty,fmt.Errorf(\"FI P8: outer verified artifact handoff: %w\",proofErr)}\n"+
        indent+"}\n"
    modified:=make([]byte,0,len(input)+len(prefix)+16)
    modified=append(modified,input[:lineStart]...)
    modified=append(modified,prefix...)
    modified=append(modified,input[lineStart:first]...)
    modified=append(modified,"stageCtx"...)
    modified=append(modified,input[last:]...)
    if _,err:=parser.ParseFile(token.NewFileSet(),"patched_backlog_verified_cache.go",modified,parser.AllErrors);err!=nil{
        return nil,fmt.Errorf("P8 source insertion produced invalid Go: %w",err)
    }
    return modified,nil
}

func outerIsCall(c *ast.CallExpr,name string)bool {
    if c==nil{return false}
    id,ok:=c.Fun.(*ast.Ident)
    return ok&&id.Name==name
}
func outerContainsCall(n ast.Node,name string)bool{
    return outerHasCallInBody(n,name)
}
func outerHasCallInBody(n ast.Node,name string)bool{
    found:=false
    ast.Inspect(n,func(child ast.Node)bool{
        if call,ok:=child.(*ast.CallExpr);ok&&outerIsCall(call,name){
            found=true;return false
        }
        return true
    })
    return found
}
func fail(err error){fmt.Fprintln(os.Stderr,"FI P8 EVIDENCE PATCH STOP:",err);os.Exit(1)}
