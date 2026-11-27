// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// DEV ONLY: exact-anchor 4->16 in-flight adjustment to an OFFLINE COPY of
// the already accepted W512/H16 Candidate A executable source and pilot runner.
// No worker-count, SQL, W512, K32, Security, File, or trust-path changes.
package main

import (
    "errors"
    "fmt"
    "os"
    "path/filepath"
    "strings"
)

type edit struct {
    file string
    before string
    after string
    count int
}

func regular(path string) ([]byte,error) {
    st,err:=os.Lstat(path)
    if err!=nil{return nil,err}
    if !st.Mode().IsRegular(){return nil,fmt.Errorf("not a regular file: %s",path)}
    return os.ReadFile(path)
}

func run(stage string) error {
    stage=filepath.Clean(stage)
    if !filepath.IsAbs(stage) ||
        !strings.HasPrefix(stage,"/home/jwood/fi-window-bench-w512-inflight16-") {
        return errors.New("FI W512 inflight16: only disposable stage roots allowed")
    }
    st,err:=os.Lstat(stage)
    if err!=nil{return err}
    if !st.IsDir(){return errors.New("stage path is not a real directory")}
    source:=filepath.Join(stage,"optimized-source")
    pilot:=filepath.Join(stage,"pilot-inflight16.sh")
    binary:=filepath.Join(stage,"fi-optfield-recover-16")
    // The new binary is checked against its pinned private build sha256
    // before installing it in an OFFLINE COPY of the known W512 SQL seed.
    injection:=strings.Join([]string{
        "JAIL",
        "candidate="+shellQuote(binary),
        "[ -f \"$jailroot$candidate\" ] && [ -f \"$jailroot$candidate.sha256\" ] ||",
        "    fail 'W512 inflight16 candidate executable or digest missing'",
        "[ \"$(sha256 -q \"$jailroot$candidate\")\" = \"$(cat \"$jailroot$candidate.sha256\")\" ] ||",
        "    fail 'W512 inflight16 candidate executable digest mismatch'",
        "jexec -U jwood fi-dev cp \"$candidate\" \"$root/fi-optfield-recover\" ||",
        "    fail 'W512 inflight16 cannot install candidate inside private clone'",
        "jexec -U jwood fi-dev sh -s \"$root\" <<'INFLIGHT16'",
        "set -eu",
        "root=$1",
        "sha256 -q \"$root/fi-optfield-recover\" > \"$root/recover.sha256\"",
        "INFLIGHT16",
        "mkdir -m 700 \"$out\"",
    },"\n")
    target:="mkdir -m 700 \"$out\""
    edits:=[]edit{
        {filepath.Join(source,"go/internal/recordingest/private_parallel_preparation.go"),
          "privateParallelAMaxInFlight = 4","privateParallelAMaxInFlight = 16",1},
        {filepath.Join(source,"go/internal/recordingest/postgres_ingest.go"),
          "inflight_limit=4 writers=1","inflight_limit=16 writers=1",1},
        {filepath.Join(source,"go/cmd/fi-backlog-recover/main_freebsd.go"),
          "workers=2 inflight=4 postgres_writers=1 source_window=%s atomic=true",
          "workers=2 inflight=16 postgres_writers=1 source_window=%s atomic=true",1},
        {pilot,"root=/home/jwood/fi-window-bench-w512-p2-$stamp",
          "root=/home/jwood/fi-window-bench-w512-i16-$stamp",1},
        {pilot,"out=/var/tmp/fi-window-chunks-h16-w512-p2-$stamp",
          "out=/var/tmp/fi-window-chunks-h16-w512-i16-$stamp",1},
        {pilot,"inflight_limit=4","inflight_limit=16",1},
        {pilot,"f[\"inflight_limit\"]!=4","f[\"inflight_limit\"]!=16",1},
        {pilot,"f[\"reorder_peak\"]+0>3","f[\"reorder_peak\"]+0>15",1},
        {pilot,"workers=2 inflight=4 postgres_writers=1 source_window=W512 atomic=true",
          "workers=2 inflight=16 postgres_writers=1 source_window=W512 atomic=true",1},
        {pilot,"FI W512 CANDIDATE A PILOT START start_index=1 windows=2 workers=2 writer=1 K32=32768",
          "FI W512 INFLIGHT16 PILOT START start_index=1 windows=2 workers=2 writer=1 K32=32768",1},
        {pilot,"FI W512 TWO-WINDOW PILOT ACCEPTED",
          "FI W512 INFLIGHT16 PILOT ACCEPTED",1},
        {pilot,"JAIL\n"+target, injection,1},
    }
    contents:=map[string]string{}
    for _,e:=range edits {
        s,ok:=contents[e.file]
        if !ok {
            b,err:=regular(e.file)
            if err!=nil{return err}
            s=string(b)
        }
        n:=strings.Count(s,e.before)
        if n!=e.count{return fmt.Errorf("FI W512 INFLIGHT16 STOP file=%s anchor=%q count=%d want=%d",e.file,e.before,n,e.count)}
        contents[e.file]=strings.Replace(s,e.before,e.after,e.count)
    }
    // All source anchors checked before ANY writes. Only disposable files.
    for file,s:=range contents {
        temp:=file+".inflight16-new"
        if _,err:=os.Lstat(temp);!os.IsNotExist(err){
            return fmt.Errorf("FI W512 INFLIGHT16 STOP temp collision %s: %v",temp,err)
        }
        if err:=os.WriteFile(temp,[]byte(s),0600);err!=nil{return err}
        if err:=os.Rename(temp,file);err!=nil{return err}
    }
    fmt.Printf("FI W512 INFLIGHT16 SOURCE PATCH PASS files=%d edits=%d workers=2 inflight=16 sql_writer=1 W512_unchanged=true K32_unchanged=true original_seed_untouched=true\n",len(contents),len(edits))
    return nil
}

func shellQuote(s string) string {
    // The stage root is constrained to a literal safe prefix with a single
    // basename; reject quote/injection control characters.
    for _,r:=range s {
        if !(r>='a'&&r<='z') && !(r>='A'&&r<='Z') &&
          !(r>='0'&&r<='9') && r!='/'&&r!='.'&&r!='_'&&r!='-' {
            panic("FI W512 INFLIGHT16: unsafe stage path")
        }
    }
    return "'"+s+"'"
}

func main(){
    if len(os.Args)!=2 {fmt.Fprintln(os.Stderr,"usage: w512_inflight16 <disposable stage>");os.Exit(2)}
    if err:=run(os.Args[1]);err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}
}
