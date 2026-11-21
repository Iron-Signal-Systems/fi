//go:build freebsd

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Disposable CI-only probe for the *real* production C1 RAMStore across
// native FreeBSD jail boundaries. No PostgreSQL, original custody, TLS
// credentials, installer operations or canonical SoR access is possible.
package main

import (
    "bytes"
    "encoding/hex"
    "errors"
    "flag"
    "fmt"
    "os"
    "strconv"
    "strings"

    "github.com/Iron-Signal-Systems/fi/go/internal/c1handoff"
)

const probeRoot="/var/run/fi-c1-handoff"
const probeBytes="C1 PREPARED P5 ORIGINAL SIGNED TEST DATA: FILE/SECURITY/USN"

func parseReference(input string)(c1handoff.SharedRAMRef,error){
    var ref c1handoff.SharedRAMRef
    pieces:=strings.Split(input,":")
    if len(pieces)!=4{return ref,errors.New("C1 probe: reference must have four exact fields")}
    ref.Name=pieces[0]
    size,e:=strconv.ParseUint(pieces[1],10,32)
    if e!=nil{return ref,e}
    count,e:=strconv.ParseUint(pieces[2],10,16)
    if e!=nil{return ref,e}
    digest,e:=hex.DecodeString(pieces[3])
    if e!=nil||len(digest)!=32{return ref,errors.New("C1 probe: invalid reference SHA-256")}
    ref.Bytes=uint32(size)
    ref.Rows=uint16(count)
    copy(ref.SHA256[:],digest)
    if e=ref.Validate();e!=nil{return ref,e}
    return ref,nil
}
func formatReference(ref c1handoff.SharedRAMRef)string{
    return fmt.Sprintf("%s:%d:%d:%x",ref.Name,ref.Bytes,ref.Rows,ref.SHA256[:])
}
func run(args []string)error{
    if os.Getenv("GITHUB_ACTIONS")!="true"||
        os.Getenv("FI_C1_RAM_PROBE_ISOLATED_VM")!="1"{
        return errors.New("C1 probe: disabled outside disposable CI VM")
    }
    host,e:=os.Hostname()
    if e!=nil{return e}
    if strings.HasPrefix(host,"c220"){
        return errors.New("C1 probe: production C220 host forbidden")
    }
    flags:=flag.NewFlagSet("fi-c1-ram-probe",flag.ContinueOnError)
    mode:=flags.String("mode","","publish/read/reclaim")
    reference:=flags.String("reference","","exact authenticated RAM object reference")
    if e=flags.Parse(args);e!=nil{return e}
    if flags.NArg()!=0{return errors.New("C1 probe: unexpected positional argument")}
    store,e:=c1handoff.NewRAMStore(probeRoot)
    if e!=nil{return e}
    switch *mode{
    case "publish":
        if *reference!=""{return errors.New("C1 probe: publish must not accept outside reference")}
        ref,e:=store.Put([]byte(probeBytes),1)
        if e!=nil{return e}
        fmt.Println(formatReference(ref))
        return nil
    case "read":
        ref,e:=parseReference(*reference)
        if e!=nil{return e}
        payload,e:=store.Get(ref)
        if e!=nil{return e}
        if !bytes.Equal(payload,[]byte(probeBytes)){
            return errors.New("C1 probe: original prepared record changed across jail mounts")
        }
        fmt.Println("FI C1 NATIVE JAIL RAM PROBE READ PASS")
        return nil
    case "reclaim":
        ref,e:=parseReference(*reference)
        if e!=nil{return e}
        if e=store.Remove(ref);e!=nil{return e}
        fmt.Println("FI C1 NATIVE JAIL RAM PROBE RECLAIM PASS")
        return nil
    default:
        return errors.New("C1 probe: invalid bounded mode")
    }
}
func main(){
    if err:=run(os.Args[1:]);err!=nil{
        fmt.Fprintln(os.Stderr,"FI C1 NATIVE JAIL RAM PROBE BLOCKED:",err)
        os.Exit(1)
    }
}
