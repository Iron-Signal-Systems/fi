// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Host-mounted tmpfs is a VOLATILE C1 transport, not custody or a journal.
// fi-ingest writes prepared buffers; fi-sor receives a read-only nullfs mount.
// All SQL checkpoints and original signed custody remain outside this store.
package c1handoff

import (
    "crypto/rand"
    "crypto/sha256"
    "crypto/subtle"
    "encoding/hex"
    "errors"
    "fmt"
    "io"
    "os"
    "path/filepath"
    "strings"
    "syscall"
)

const MaxSharedRAMObjectBytes = 128 << 20
const MaxSharedRAMInflight = 16

type SharedRAMRef struct {
    Name string
    Bytes uint32
    Rows uint16
    SHA256 [32]byte
}

func(r SharedRAMRef)Validate()error{
    if len(r.Name)!=41||!strings.HasPrefix(r.Name,"c1-")||
        !strings.HasSuffix(r.Name,".ready")||r.Bytes==0||
        r.Bytes>MaxSharedRAMObjectBytes||r.Rows==0||r.Rows>MaxRows{
        return errors.New("C1 RAM: invalid bounded immutable buffer reference")
    }
    if _,err:=hex.DecodeString(r.Name[3:35]);err!=nil||
        strings.ToLower(r.Name)!=r.Name{
        return errors.New("C1 RAM: invalid random opaque object name")
    }
    return nil
}
type RAMStore struct{root string}

func NewRAMStore(root string)(*RAMStore,error){
    if !filepath.IsAbs(root){return nil,errors.New("C1 RAM: absolute tmpfs jail mount required")}
    clean:=filepath.Clean(root)
    if clean=="/"{return nil,errors.New("C1 RAM: filesystem root forbidden")}
    stat,err:=os.Lstat(clean)
    if err!=nil{return nil,fmt.Errorf("C1 RAM: shared mount inaccessible: %w",err)}
    if !stat.IsDir()||stat.Mode()&os.ModeSymlink!=0||
        stat.Mode().Perm()&0007!=0 {
        return nil,errors.New("C1 RAM: mount must be a real directory, inaccessible to other users")
    }
    return &RAMStore{root:clean},nil
}

// Put writes a bounded immutable buffer under a non-guessable name.
// .part is never referenced by SQL; rename publishes only complete data.
// No fsync: a power loss discards tmpfs and causes signed-custody replay.
func(s *RAMStore)Put(payload []byte,rows int)(SharedRAMRef,error){
    var ref SharedRAMRef
    if s==nil||s.root==""||len(payload)==0||
        len(payload)>MaxSharedRAMObjectBytes||rows<1||rows>MaxRows{
        return ref,errors.New("C1 RAM: unbounded or absent prepared buffer")
    }
    var nonce [16]byte
    if _,err:=rand.Read(nonce[:]);err!=nil{return ref,err}
    ref.Name="c1-"+hex.EncodeToString(nonce[:])+".ready"
    ref.Bytes=uint32(len(payload))
    ref.Rows=uint16(rows)
    ref.SHA256=sha256.Sum256(payload)
    part:=filepath.Join(s.root,ref.Name+".part")
    final:=filepath.Join(s.root,ref.Name)
    f,err:=os.OpenFile(part,os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW,0600)
    if err!=nil{return SharedRAMRef{},err}
    defer os.Remove(part)
    if _,err=f.Write(payload);err!=nil{f.Close();return SharedRAMRef{},err}
    // Shared host group permits fi-sor READ; fi-sor's nullfs itself is RO.
    if err=f.Chmod(0640);err!=nil{f.Close();return SharedRAMRef{},err}
    if err=f.Close();err!=nil{return SharedRAMRef{},err}
    if err=os.Rename(part,final);err!=nil{return SharedRAMRef{},err}
    return ref,nil
}

// Get never follows a symbolic link and never trusts metadata in the directory.
// The SHA-256 is authenticated separately over mTLS on the control channel.
func(s *RAMStore)Get(ref SharedRAMRef)([]byte,error){
    if s==nil||s.root==""{return nil,errors.New("C1 RAM: reader not configured")}
    if err:=ref.Validate();err!=nil{return nil,err}
    path:=filepath.Join(s.root,ref.Name)
    f,err:=os.OpenFile(path,os.O_RDONLY|syscall.O_NOFOLLOW,0)
    if err!=nil{return nil,err}
    defer f.Close()
    info,err:=f.Stat()
    if err!=nil{return nil,err}
    if !info.Mode().IsRegular()||info.Size()!=int64(ref.Bytes){
        return nil,errors.New("C1 RAM: wrong file type or changed buffer byte count")
    }
    raw,err:=io.ReadAll(io.LimitReader(f,int64(ref.Bytes)+1))
    if err!=nil{return nil,err}
    if len(raw)!=int(ref.Bytes){return nil,errors.New("C1 RAM: truncated or grown prepared buffer")}
    digest:=sha256.Sum256(raw)
    if subtle.ConstantTimeCompare(digest[:],ref.SHA256[:])!=1{
        return nil,errors.New("C1 RAM: prepared buffer digest mismatch")
    }
    return raw,nil
}

// Remove is called by fi-ingest ONLY after an exact successful SQL COMMIT ACK.
// Failures leave volatile objects for the next session cleanup/restart.
func(s *RAMStore)Remove(ref SharedRAMRef)error{
    if s==nil||s.root==""{return errors.New("C1 RAM: producer not configured")}
    if err:=ref.Validate();err!=nil{return err}
    return os.Remove(filepath.Join(s.root,ref.Name))
}
