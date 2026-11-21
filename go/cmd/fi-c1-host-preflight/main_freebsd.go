//go:build freebsd && fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Host-side, READ ONLY acceptance for FreeBSD tmpfs + nullfs. The worker
// jails cannot independently prove the backing host filesystem is RAM.
// This tool NEVER creates mounts, changes jail configs, opens PostgreSQL or
// starts a receiver/ingester.
package main

import (
    "errors"
    "flag"
    "fmt"
    "os"
    "path/filepath"
    "strings"
    "syscall"

    "github.com/Iron-Signal-Systems/fi/go/internal/freebsd/backendinstall"
)

const mntReadOnly uint64=0x00000001 // FreeBSD sys/mount.h MNT_RDONLY
type fsInfo struct{kind,source,target string;readonly bool}
func cString(value []int8)string{
    b:=make([]byte,0,len(value))
    for _,c:=range value{
        if c==0{break}
        b=append(b,byte(c))
    }
    return string(b)
}
func inspectFS(path string)(fsInfo,error){
    var st syscall.Statfs_t
    if err:=syscall.Statfs(path,&st);err!=nil{return fsInfo{},err}
    return fsInfo{kind:cString(st.Fstypename[:]),
        source:cString(st.Mntfromname[:]),
        target:cString(st.Mntonname[:]),
        readonly:st.Flags&mntReadOnly!=0},nil
}
func canonicalDirectory(path string)(string,error){
    if !filepath.IsAbs(path)||path=="/"{
        return "",errors.New("C1 host: absolute non-root mount path required")
    }
    clean:=filepath.Clean(path)
    st,err:=os.Lstat(clean)
    if err!=nil{return "",err}
    if !st.IsDir()||st.Mode()&os.ModeSymlink!=0{
        return "",fmt.Errorf("C1 host: mount path not a real directory: %s",clean)
    }
    return clean,nil
}
func jailedPath(root string,relative string)(string,error){
    jail,err:=canonicalDirectory(root)
    if err!=nil{return "",err}
    if !filepath.IsAbs(relative)||relative=="/"{
        return "",errors.New("C1 host: jail-relative RAM mount must be absolute")
    }
    rel:=strings.TrimPrefix(filepath.Clean(relative),"/")
    if rel==""||rel=="."||strings.HasPrefix(rel,"../"){
        return "",errors.New("C1 host: unsafe jail-relative RAM path")
    }
    return canonicalDirectory(filepath.Join(jail,rel))
}
func verifyMount(path,kind,source string,readonly bool)error{
    fs,err:=inspectFS(path)
    if err!=nil{return err}
    if fs.kind!=kind||fs.target!=path||fs.readonly!=readonly{
        return fmt.Errorf("C1 host: mount %s observed type=%q target=%q readonly=%t, wanted type=%q readonly=%t",
            path,fs.kind,fs.target,fs.readonly,kind,readonly)
    }
    if source!=""&&fs.source!=source{
        return fmt.Errorf("C1 host: jail RAM mount %s source=%q, not validated host tmpfs %q",
            path,fs.source,source)
    }
    return nil
}
func run()error{
    flags:=flag.NewFlagSet("fi-c1-host-preflight",flag.ContinueOnError)
    host:=flags.String("host-tmpfs","","absolute host tmpfs path, mounted as tmpfs")
    ingest:=flags.String("ingest-root","","actual fi-ingest jail root")
    sor:=flags.String("sor-root","","actual fi-sor-db jail root")
    at:=flags.String("jail-ram-path","/var/run/fi-c1-handoff","same in-jail mount path for both services")
    originalHost:=flags.String("host-custody-root","","real host original signed receiver custody root")
    receiptHost:=flags.String("host-recorded-root","","real host original signed recorded receipt root")
    originalJail:=flags.String("sor-custody-path","","read-only original signed custody path visible inside fi-sor jail")
    receiptJail:=flags.String("sor-recorded-path","","read-only recorded receipt path visible inside fi-sor jail")
    if err:=flags.Parse(os.Args[1:]);err!=nil{return err}
    if flags.NArg()!=0{return errors.New("C1 host: unexpected positional arguments")}
    if *host==""||*ingest==""||*sor==""||
        *originalHost==""||*receiptHost==""||
        *originalJail==""||*receiptJail==""{
        return errors.New("C1 host: RAM, both jail roots and both original signed custody RO mappings required")
    }
    hostPath,err:=canonicalDirectory(*host);if err!=nil{return err}
    ingestPath,err:=jailedPath(*ingest,*at);if err!=nil{return err}
    sorPath,err:=jailedPath(*sor,*at);if err!=nil{return err}
    if hostPath==ingestPath||hostPath==sorPath||ingestPath==sorPath{
        return errors.New("C1 host: tmpfs and jail mount paths must be distinct")
    }
    // Require actual mountpoints, not arbitrary descendants of a mount:
    // otherwise a normal ZFS folder could look like a RAM transport.
    if err=verifyMount(hostPath,"tmpfs","",false);err!=nil{return err}
    // Reject a default/unbounded tmpfs: C1 credits limit completed objects
    // to 2 GiB, while the actual host tmpfs must be 2..4 GiB including
    // temporary .part writes and metadata. Never use a ZFS-backed path.
    var ramStat syscall.Statfs_t
    if err=syscall.Statfs(hostPath,&ramStat);err!=nil{return err}
    if err=backendinstall.ValidateC1RAMFilesystemSize(ramStat.Blocks,ramStat.Bsize);err!=nil{
        return fmt.Errorf("C1 host: unsafe tmpfs byte ceiling: %w",err)
    }
    if err=verifyMount(ingestPath,"nullfs",hostPath,false);err!=nil{return err}
    if err=verifyMount(sorPath,"nullfs",hostPath,true);err!=nil{return err}
    originalPath,err:=canonicalDirectory(*originalHost)
    if err!=nil{return err}
    receiptPath,err:=canonicalDirectory(*receiptHost)
    if err!=nil{return err}
    originalTarget,err:=jailedPath(*sor,*originalJail)
    if err!=nil{return err}
    receiptTarget,err:=jailedPath(*sor,*receiptJail)
    if err!=nil{return err}
    if originalPath==receiptPath||originalTarget==receiptTarget||
        originalTarget==sorPath||receiptTarget==sorPath{
        return errors.New("C1 host: original custody, receipts and volatile RAM must be distinct")
    }
    if err=verifyMount(originalTarget,"nullfs",originalPath,true);err!=nil{
        return fmt.Errorf("C1 host: original receiver custody read-only mount: %w",err)
    }
    if err=verifyMount(receiptTarget,"nullfs",receiptPath,true);err!=nil{
        return fmt.Errorf("C1 host: original recorded receipt read-only mount: %w",err)
    }
    fmt.Printf("FI C1 HOST RAM AND SIGNED CUSTODY PREFLIGHT PASS tmpfs=%s producer=%s consumer=%s custody=%s recorded=%s all_consumer_mounts_readonly=true host_ram_backing=tmpfs handoff_durable=false\n",
        hostPath,ingestPath,sorPath,originalTarget,receiptTarget)
    return nil
}
func main(){
    if err:=run();err!=nil{
        fmt.Fprintln(os.Stderr,"FI C1 HOST PREFLIGHT BLOCKED:",err)
        os.Exit(1)
    }
}
