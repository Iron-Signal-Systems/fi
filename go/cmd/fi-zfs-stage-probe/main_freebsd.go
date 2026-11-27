//go:build freebsd

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// DEVELOPMENT-ONLY PROBE. Does not modify signed cache, existing checkpoints,
// FI SQL, or production ingest. Creates and removes ONLY a unique scratch dir.
package main

import (
    "context"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "errors"
    "flag"
    "fmt"
    "io"
    "os"
    "path/filepath"
    "strings"
    "syscall"
    "time"

)

type manifest struct {
    DataBytes int64  `json:"data_bytes"`
    DataSHA256 string `json:"data_sha256"`
}

type stages struct {
    Bytes int64
    Files int
    Stream time.Duration
    Clone time.Duration
    Hash time.Duration
    Sync time.Duration
}
func (s stages) CloneTotal() time.Duration {return s.Clone+s.Hash+s.Sync}

func main() {
    var root, scratch string
    var start, count int
    flag.StringVar(&root,"cache-root","","absolute verified-cache root (has exactly one receipt directory)")
    flag.StringVar(&scratch,"scratch-parent","/var/tmp","same-device destination parent, e.g. /var/tmp")
    flag.IntVar(&start,"start-batch",158,"first original signed batch index")
    flag.IntVar(&count,"count",57,"number of consecutive original signed batches")
    flag.Parse()
    if root=="" || !filepath.IsAbs(root) || !filepath.IsAbs(scratch) ||
       start<0 || count<1 || count>128 || flag.NArg()!=0 {
        die("invalid inputs; need -cache-root absolute, -scratch-parent absolute, start>=0, 1<=count<=128")
    }
    if err:=run(root,scratch,start,count);err!=nil {die("%v",err)}
}

func die(f string,args ...any) {
    fmt.Fprintf(os.Stderr,"FI ZFS STAGE PROBE STOP: "+f+"\n",args...)
    os.Exit(1)
}

func regular(path string) (os.FileInfo,error) {
    st,err:=os.Lstat(path)
    if err!=nil {return nil,err}
    if !st.Mode().IsRegular() || st.Mode()&os.ModeSymlink!=0 {
        return nil,fmt.Errorf("not a real regular file: %s",path)
    }
    return st,nil
}

func scanRoot(root string)(string,error){
    children,err:=os.ReadDir(root)
    if err!=nil{return "",err}
    found:=""
    for _,c:=range children {
        if !c.IsDir() || c.Type()&os.ModeSymlink!=0 || !strings.HasPrefix(c.Name(),"receipt-") {continue}
        p:=filepath.Join(root,c.Name())
        if _,err:=regular(filepath.Join(p,"verified.json"));err!=nil {continue}
        if found!="" {return "",errors.New("ambiguous receipt directories; use a cache with exactly one verified receipt")}
        found=p
    }
    if found=="" {return "",errors.New("no verified receipt directory found")}
    return found,nil
}

func shaFile(path string)(string,int64,error){
    f,err:=os.Open(path)
    if err!=nil{return "",0,err}
    h:=sha256.New()
    n,e:=io.CopyBuffer(h,f,make([]byte,256*1024))
    e=errors.Join(e,f.Close())
    if e!=nil{return "",0,e}
    return hex.EncodeToString(h.Sum(nil)),n,nil
}

// copyRangeCloneRequired does NOT allow the kernel's ordinary copy fallback.
// COPY_FILE_RANGE_CLONE is a FreeBSD 15 flag and returns EOPNOTSUPP if the
// filesystem cannot perform an actual block clone.
func copyRangeCloneRequired(src,dst *os.File,expected int64) error {
    // FreeBSD 15.1 RELENG definitions:
    // sys/sys/syscall.h: SYS_copy_file_range=569
    // sys/sys/unistd.h: COPY_FILE_RANGE_CLONE=0x00800000
    // The pinned x/sys/unix v0.47.0 does not expose these two symbols.
    // A nonzero clone-required flag fails closed when ZFS cannot clone.
    const (
        freebsdCopyFileRangeTrap = 569
        freebsdCopyFileRangeClone = 0x00800000
        toEOF = 1<<31 - 1
    )
    // Passing a larger size requests cloning to EOF, permitting a final
    // partial block. Every signed FI cache batch here is smaller than 2GiB.
    if expected<=0 || expected>=toEOF {return errors.New("out-of-range source size")}
    var got int64
    for got<expected {
        n,_,errno:=syscall.Syscall6(
            freebsdCopyFileRangeTrap,
            src.Fd(),0,dst.Fd(),0,
            uintptr(toEOF),freebsdCopyFileRangeClone,
        )
        if errno!=0{return fmt.Errorf("clone-required copy_file_range: %w",errno)}
        if n==0{return io.ErrUnexpectedEOF}
        got+=int64(n)
        if got>expected{return errors.New("clone exceeded expected file size")}
    }
    return nil
}

func run(root,scratch string,start,count int)error{
    rootInfo,err:=os.Lstat(root)
    if err!=nil{return err}
    if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink!=0 {return errors.New("cache root is not a real directory")}
    scratchInfo,err:=os.Lstat(scratch)
    if err!=nil{return err}
    if !scratchInfo.IsDir() || scratchInfo.Mode()&os.ModeSymlink!=0 {return errors.New("scratch parent is not a real directory")}
    srcStat,ok:=rootInfo.Sys().(*syscall.Stat_t)
    if !ok{return errors.New("cannot obtain source device")}
    dstStat,ok:=scratchInfo.Sys().(*syscall.Stat_t)
    if !ok{return errors.New("cannot obtain scratch device")}
    if srcStat.Dev!=dstStat.Dev {return errors.New("source and scratch are not on the same filesystem")}
    receipt,err:=scanRoot(root)
    if err!=nil{return err}
    dir,err:=os.MkdirTemp(scratch,"fi-zfs-clone-probe-")
    if err!=nil{return err}
    defer os.RemoveAll(dir)
    if err=os.Chmod(dir,0700);err!=nil{return err}
    sum:=stages{}
    fmt.Printf("FI ZFS STAGE PROBE START cache=%s scratch=%s start=%d count=%d source_device=%d\n",receipt,dir,start,count,srcStat.Dev)
    for i:=start;i<start+count;i++ {
        data:=filepath.Join(receipt,fmt.Sprintf("batch-%08d.data",i))
        meta:=filepath.Join(receipt,fmt.Sprintf("batch-%08d.manifest",i))
        raw,err:=os.ReadFile(meta)
        if err!=nil{return fmt.Errorf("batch %d manifest: %w",i,err)}
        var m manifest
        if err=json.Unmarshal(raw,&m);err!=nil{return err}
        if len(m.DataSHA256)!=64 || m.DataBytes<=0 || m.DataBytes>=1<<31 {
            return fmt.Errorf("batch %d invalid manifest identity/size",i)
        }
        stat,err:=regular(data)
        if err!=nil{return err}
        if stat.Size()!=m.DataBytes{return fmt.Errorf("batch %d source size changed",i)}
        // Mandatory pretest data digest: both operations consume the same
        // unchanged source bytes. This read is OUTSIDE measured copy timings.
        sourceHash,sourceBytes,err:=shaFile(data)
        if err!=nil{return err}
        if sourceHash!=m.DataSHA256 || sourceBytes!=m.DataBytes {
            return fmt.Errorf("batch %d source SHA-256 differs from verified manifest",i)
        }
        a:=filepath.Join(dir,fmt.Sprintf("stream-%08d",i))
        b:=filepath.Join(dir,fmt.Sprintf("clone-%08d",i))
        if err=measureStream(data,a,m.DataBytes,m.DataSHA256,&sum);err!=nil{return fmt.Errorf("batch %d stream: %w",i,err)}
        if err=measureClone(data,b,m.DataBytes,m.DataSHA256,&sum);err!=nil{return fmt.Errorf("batch %d clone: %w",i,err)}
        // Remove only exact scratch files, never the signed source or original
        // stage materialization. Failure stops rather than accumulating data.
        if err=os.Remove(a);err!=nil{return err}
        if err=os.Remove(b);err!=nil{return err}
        sum.Files++
        sum.Bytes+=m.DataBytes
    }
    fmt.Printf("FI ZFS STAGE PROBE PASS files=%d bytes=%d stream_copy_hash_sync=%s clone_only=%s clone_verify_sha=%s clone_fsync=%s clone_total=%s saved=%s\n",
       sum.Files,sum.Bytes,sum.Stream.Round(time.Millisecond),sum.Clone.Round(time.Millisecond),
       sum.Hash.Round(time.Millisecond),sum.Sync.Round(time.Millisecond),sum.CloneTotal().Round(time.Millisecond),
       (sum.Stream-sum.CloneTotal()).Round(time.Millisecond))
    return nil
}

func measureStream(src,dst string,size int64,expected string,sum *stages)error{
    in,err:=os.Open(src)
    if err!=nil{return err}
    defer in.Close()
    out,err:=os.OpenFile(dst,os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600)
    if err!=nil{return err}
    defer out.Close()
    start:=time.Now()
    h:=sha256.New()
    n,err:=io.CopyBuffer(io.MultiWriter(out,h),in,make([]byte,256*1024))
    if err!=nil{return err}
    if n!=size || hex.EncodeToString(h.Sum(nil))!=expected{return errors.New("stream destination mismatch")}
    if err=out.Sync();err!=nil{return err}
    if err=out.Close();err!=nil{return err}
    sum.Stream+=time.Since(start)
    return nil
}

func measureClone(src,dst string,size int64,expected string,sum *stages)error{
    in,err:=os.Open(src)
    if err!=nil{return err}
    defer in.Close()
    out,err:=os.OpenFile(dst,os.O_CREATE|os.O_EXCL|os.O_RDWR,0600)
    if err!=nil{return err}
    defer out.Close()
    start:=time.Now()
    if err=copyRangeCloneRequired(in,out,size);err!=nil{return err}
    sum.Clone+=time.Since(start)
    inInfo,err:=in.Stat()
    if err!=nil{return err}
    outInfo,err:=out.Stat()
    if err!=nil{return err}
    if os.SameFile(inInfo,outInfo) || outInfo.Size()!=size {
        return errors.New("clone does not have independent file identity and exact length")
    }
    start=time.Now()
    got,n,err:=shaFile(dst)
    if err!=nil{return err}
    if got!=expected || n!=size{return errors.New("cloned bytes differ from signed SHA-256")}
    sum.Hash+=time.Since(start)
    start=time.Now()
    if err=out.Sync();err!=nil{return err}
    if err=out.Close();err!=nil{return err}
    sum.Sync+=time.Since(start)
    return nil
}

// Keep a context reference so future cancellation plumbing can be added
// without changing the probe's stand-alone data flow.
var _ = context.Background
