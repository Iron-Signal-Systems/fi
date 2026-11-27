//go:build freebsd

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use governed by repository LICENSE.
package main

// Installs an independently issued and cryptographically verified ISS-Root-CA
// base CRL from the Windows FI refresher. No LDAP credentials, services,
// PostgreSQL changes, private keys, or certificate validation bypasses.
import (
 "bytes"
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "flag"
 "fmt"
 "os"
 "path/filepath"
 "syscall"
 "time"

 "github.com/Iron-Signal-Systems/fi/go/internal/crlpublish"
)

type target struct{ name,path,root string; original,stage []byte; fileInfo os.FileInfo; stagedPath string }
var targets=[]target{
 {"receiver-transport","/var/db/fi/config/receiver/pki/trust/fi-transport-ca.crl.pem",
  "/var/db/fi/config/receiver/pki/trust/fi-root-ca.crt.pem",nil,nil,nil,""},
 {"receiver-batch","/var/db/fi/config/receiver/pki/trust/fi-batch-signing-ca.crl.pem",
  "/var/db/fi/config/receiver/pki/trust/fi-root-ca.crt.pem",nil,nil,nil,""},
 {"ingest-batch","/var/db/fi/config/ingest/pki/trust/fi-batch-signing-ca.crl.pem",
  "/var/db/fi/config/ingest/pki/trust/fi-root-ca.crt.pem",nil,nil,nil,""},
 {"benchmark-host-batch","/usr/local/etc/fi/pki/trust/fi-batch-signing-ca.crl.pem",
  "/usr/local/etc/fi/pki/trust/fi-root-ca.crt.pem",nil,nil,nil,""},
}

func main(){if err:=run();err!=nil{fmt.Fprintln(os.Stderr,"FI CRL PUBLISH STOP:",err);os.Exit(1)}}
func checked(path string)([]byte,os.FileInfo,error){
 if !filepath.IsAbs(path)||filepath.Clean(path)!=path{return nil,nil,errors.New("noncanonical path")}
 dir,err:=os.Lstat(filepath.Dir(path));if err!=nil{return nil,nil,err}
 if !dir.IsDir()||dir.Mode().Perm()&0022!=0{return nil,nil,fmt.Errorf("unsafe parent dir: %s",path)}
 info,err:=os.Lstat(path);if err!=nil{return nil,nil,err}
 if !info.Mode().IsRegular()||info.Mode().Perm()&0022!=0||info.Mode().Perm()&0111!=0 {
  return nil,nil,fmt.Errorf("unsafe file mode or link: %s",path)
 }
 st,ok:=info.Sys().(*syscall.Stat_t)
 if !ok||st.Nlink!=1 {return nil,nil,fmt.Errorf("unsafe file inode: %s",path)}
 b,err:=os.ReadFile(path);return b,info,err
}
func syncDir(path string)error{d,err:=os.Open(path);if err!=nil{return err};defer d.Close();return d.Sync()}
func stage(dest string,content []byte,info os.FileInfo)(string,error){
 f,err:=os.CreateTemp(filepath.Dir(dest),".fi-crl-new-*")
 if err!=nil{return "",err}
 name:=f.Name();success:=false
 defer func(){_ = f.Close();if !success {_=os.Remove(name)}}()
 st:=info.Sys().(*syscall.Stat_t)
 if _,err=f.Write(content);err!=nil{return "",err}
 if err=f.Chown(int(st.Uid),int(st.Gid));err!=nil{return "",err}
 if err=f.Chmod(info.Mode().Perm());err!=nil{return "",err}
 if err=f.Sync();err!=nil{return "",err}
 if err=f.Close();err!=nil{return "",err}
 success=true
 return name,nil
}
func backup(dir string,t target)error{
 path:=filepath.Join(dir,t.name+".crl.pem")
 f,err:=os.OpenFile(path,os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600)
 if err!=nil{return err}
 if _,err=f.Write(t.original);err!=nil{_ = f.Close();return err}
 if err=f.Sync();err!=nil{_ = f.Close();return err}
 return f.Close()
}
func run()error{
 var input string
 var apply bool
 flag.StringVar(&input,"input","","fresh CA-signed ISS Root CRL file from Windows FICRLRefresher (PEM or DER)")
 flag.BoolVar(&apply,"apply",false,"publish only after all signatures, freshness, and rollback checks pass")
 flag.Parse()
 if flag.NArg()!=0||input==""{return errors.New("usage: fi-crl-publish -input /absolute/fresh.crl [ -apply ]")}
 if os.Geteuid()!=0{return errors.New("run on fi-backend-b as root")}
 host,err:=os.Hostname();if err!=nil{return err}
 if host!="fi-backend-b"{return fmt.Errorf("refusing wrong backend hostname %q",host)}
 incoming,_,err:=checked(input);if err!=nil{return fmt.Errorf("input: %w",err)}
 newCRL,err:=crlpublish.Parse(incoming);if err!=nil{return err}
 now:=time.Now().UTC()
 pemBytes,err:=crlpublish.PEM(incoming);if err!=nil{return err}
 var pinnedRoot []byte
 for i:=range targets{
  t:=&targets[i]
  rootBytes,_,err:=checked(t.root)
  if err!=nil{return fmt.Errorf("%s root certificate: %w",t.name,err)}
  if pinnedRoot==nil {pinnedRoot=rootBytes
  }else if !bytes.Equal(pinnedRoot,rootBytes){
   return fmt.Errorf("%s has different root trust from receiver; no files touched",t.name)
  }
  root,err:=crlpublish.ParseRoot(rootBytes);if err!=nil{return err}
  if err:=crlpublish.Check(newCRL,root,now,true);err!=nil {
   return fmt.Errorf("%s new CRL: %w",t.name,err)
  }
  old,info,err:=checked(t.path)
  if err!=nil{return fmt.Errorf("%s installed CRL: %w",t.name,err)}
  previous,err:=crlpublish.Parse(old);if err!=nil{return fmt.Errorf("%s prior CRL: %w",t.name,err)}
  if err:=crlpublish.Check(previous,root,now,false);err!=nil{return fmt.Errorf("%s prior CRL trust: %w",t.name,err)}
  if err:=crlpublish.RejectRollback(newCRL,previous,now);err!=nil{return fmt.Errorf("%s rollback: %w",t.name,err)}
  t.original=old
  t.fileInfo=info
 }
 digest:=sha256.Sum256(pemBytes)
 fmt.Printf("FI CRL VERIFIED issuer=%s number=0x%s thisUpdate=%s nextUpdate=%s pemSHA256=%s\n",
  newCRL.Issuer.String(),crlpublish.Number(newCRL.Number),
  newCRL.ThisUpdate.UTC().Format(time.RFC3339),
  newCRL.NextUpdate.UTC().Format(time.RFC3339),hex.EncodeToString(digest[:]))
 for _,t:=range targets{fmt.Printf("FI CRL TARGET VERIFIED %s %s\n",t.name,t.path)}
 if !apply{fmt.Println("FI CRL DRY RUN ONLY: use -apply after reviewing new CRL");return nil}
 backupRoot,err:=os.MkdirTemp("/var/tmp","fi-crl-before-*");if err!=nil{return err}
 if err=os.Chmod(backupRoot,0700);err!=nil{return err}
 defer func(){for _,t:=range targets{if t.stagedPath!=""{_=os.Remove(t.stagedPath)}}}()
 for i:=range targets{
  t:=&targets[i]
  if err:=backup(backupRoot,*t);err!=nil{return fmt.Errorf("backup %s: %w",t.name,err)}
  t.stagedPath,err=stage(t.path,pemBytes,t.fileInfo)
  if err!=nil{return fmt.Errorf("stage %s: %w",t.name,err)}
 }
 if err:=syncDir(backupRoot);err!=nil{return err}
 // Reject races before first rename: all four existing trust files must
 // still have unchanged bytes, modes, and inode identities.
 for _,t:=range targets{
  old,info,err:=checked(t.path)
  if err!=nil{return err}
  if !os.SameFile(info,t.fileInfo)||info.Mode()!=t.fileInfo.Mode()||!bytes.Equal(old,t.original){
   return fmt.Errorf("%s trust path changed while staging",t.name)
  }
 }
 for i:=range targets{
  t:=&targets[i]
  if err:=os.Rename(t.stagedPath,t.path);err!=nil{
   return fmt.Errorf("%s install: %w (prior completed targets contain valid CRL; backups %s)",t.name,err,backupRoot)
  }
  t.stagedPath=""
  if err:=syncDir(filepath.Dir(t.path));err!=nil{return fmt.Errorf("%s sync directory: %w",t.name,err)}
  final,_,err:=checked(t.path);if err!=nil{return err}
  if !bytes.Equal(final,pemBytes){return fmt.Errorf("%s post-install bytes mismatch",t.name)}
  fmt.Printf("FI CRL INSTALLED %s nextUpdate=%s\n",t.name,newCRL.NextUpdate.UTC().Format(time.RFC3339))
 }
 fmt.Printf("FI CRL COMPLETE: 4 verified trust files installed; old copies retained at %s\n",backupRoot)
 fmt.Println("NOTICE: receiver and ingest worker may cache prior CRLs. Activate on controlled service restart; isolated benchmark uses newly loaded CRL on next invocation.")
 return nil
}
