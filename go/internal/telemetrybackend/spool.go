// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// FI telemetry: durable, bounded local source custody, no SQL authority.
package telemetrybackend

import (
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "sort"
 "strings"
 "time"
)
const MaxEntryBytes = 1 << 20
const MaxQueuedEntries = 20000

// Entry is a versioned observation. A failed observation is NOT zero usage.
type Entry struct {
 Version int
 Host string
 RunID string
 Sequence uint64
 Stream string
 ObservedAt time.Time
 Data map[string]interface{}
}
type Pending struct {
 Path string
 SHA256 string
 Data []byte
 Entry Entry
}
func ValidateEntry(e Entry)error {
 if e.Version!=1||e.Host==""||e.RunID==""||
 e.ObservedAt.IsZero()||(e.Stream!="samples"&&e.Stream!="events")||
 len(e.Host)>256||len(e.RunID)>128||e.Data==nil {
  return errors.New("FI telemetry: invalid versioned source identity or observation")
 }
 return nil
}
func IsSafeSpool(dir string)error {
 if !filepath.IsAbs(dir){return errors.New("FI telemetry: spool must be absolute")}
 info,err:=os.Lstat(dir);if err!=nil{return err}
 if !info.IsDir()||info.Mode()&os.ModeSymlink!=0||
    info.Mode().Perm()&0077!=0 {
  return errors.New("FI telemetry: spool must be private, real directory (0700)")
 }
 return nil
}
func queuedNames(dir string)([]string,error){
 items,err:=os.ReadDir(dir);if err!=nil{return nil,err}
 names:=make([]string,0,len(items))
 for _,item:=range items{
  if strings.HasPrefix(item.Name(),".tmp-"){continue}
  if strings.HasSuffix(item.Name(),".json"){
   if !item.Type().IsRegular(){return nil,errors.New("FI telemetry: unsafe spool entry")}
   names=append(names,item.Name())
  }
 }
 sort.Strings(names)
 return names,nil
}
// Put commits each sample to disk before it becomes eligible for upload.
func Put(dir string,e Entry)(string,error){
 if err:=IsSafeSpool(dir);err!=nil{return "",err}
 if err:=ValidateEntry(e);err!=nil{return "",err}
 names,err:=queuedNames(dir);if err!=nil{return "",err}
 if len(names)>=MaxQueuedEntries{
  return "",errors.New("FI telemetry: bounded spool full; coverage gap, do not discard")
 }
 b,err:=json.Marshal(e);if err!=nil{return "",err}
 if len(b)>MaxEntryBytes{return "",errors.New("FI telemetry: sample exceeds custody bound")}
 digest:=sha256.Sum256(b); hash:=hex.EncodeToString(digest[:])
 name:=fmt.Sprintf("%020d_%s.json",e.ObservedAt.UTC().UnixNano(),hash)
 path:=filepath.Join(dir,name)
 if _,err:=os.Lstat(path);err==nil{return "",errors.New("FI telemetry: duplicate entry file")}
 tmp,err:=os.CreateTemp(dir,".tmp-");if err!=nil{return "",err}
 defer os.Remove(tmp.Name())
 if err:=tmp.Chmod(0600);err!=nil{tmp.Close();return "",err}
 if _,err:=tmp.Write(b);err!=nil{tmp.Close();return "",err}
 if err:=tmp.Sync();err!=nil{tmp.Close();return "",err}
 if err:=tmp.Close();err!=nil{return "",err}
 if err:=os.Rename(tmp.Name(),path);err!=nil{return "",err}
 d,err:=os.Open(dir);if err!=nil{return "",err}
 err=d.Sync();closeErr:=d.Close()
 if err!=nil{return "",err};if closeErr!=nil{return "",closeErr}
 return path,nil
}
func ReadPending(dir string,limit int)([]Pending,error){
 if err:=IsSafeSpool(dir);err!=nil{return nil,err}
 if limit<1||limit>512{return nil,errors.New("FI telemetry: batch limit outside 1..512")}
 names,err:=queuedNames(dir);if err!=nil{return nil,err}
 if len(names)>limit{names=names[:limit]}
 result:=make([]Pending,0,len(names))
 for _,name:=range names{
  path:=filepath.Join(dir,name)
  f,err:=os.OpenFile(path,os.O_RDONLY|os.O_NOFOLLOW,0)
  if err!=nil{return nil,err}
  info,err:=f.Stat()
  if err!=nil{f.Close();return nil,err}
  if !info.Mode().IsRegular()||info.Size()<=0||info.Size()>MaxEntryBytes {
   f.Close();return nil,errors.New("FI telemetry: invalid local file type/size")
  }
  b,err:=io.ReadAll(io.LimitReader(f,MaxEntryBytes+1));f.Close()
  if err!=nil{return nil,err}
  sum:=sha256.Sum256(b);hash:=hex.EncodeToString(sum[:])
  if !strings.HasSuffix(name,"_"+hash+".json"){
   return nil,errors.New("FI telemetry: spool content hash mismatch")
  }
  var e Entry
  if err:=json.Unmarshal(b,&e);err!=nil{return nil,err}
  if err:=ValidateEntry(e);err!=nil{return nil,err}
  result=append(result,Pending{Path:path,SHA256:hash,Data:b,Entry:e})
 }
 return result,nil
}
func Retire(dir string,items []Pending)error{
 if err:=IsSafeSpool(dir);err!=nil{return err}
 for _,p:=range items{
  if filepath.Dir(p.Path)!=dir{return errors.New("FI telemetry: foreign retirement path")}
  // Reopen and validate bytes BEFORE unlink. A changed spool remains retained.
  f,err:=os.OpenFile(p.Path,os.O_RDONLY|os.O_NOFOLLOW,0)
  if err!=nil{return err}
  b,err:=io.ReadAll(io.LimitReader(f,MaxEntryBytes+1));f.Close()
  if err!=nil{return err}
  sha:=sha256.Sum256(b)
  if hex.EncodeToString(sha[:])!=p.SHA256{
   return errors.New("FI telemetry: file changed after SQL commit; retain")
  }
  if err:=os.Remove(p.Path);err!=nil{return err}
 }
 d,err:=os.Open(dir);if err!=nil{return err}
 err=d.Sync();closeErr:=d.Close()
 if err!=nil{return err}
 return closeErr
}
