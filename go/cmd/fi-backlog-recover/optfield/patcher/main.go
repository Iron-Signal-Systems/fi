// FI dev-only scoped patch of the local experimental field-partition guard.
// Permits 65536 in addition to 32768; refuses unexpected source structures.
package main

import (
 "bytes"
 "crypto/sha256"
 "flag"
 "fmt"
 "go/ast"
 "go/parser"
 "go/token"
 "os"
 "path/filepath"
 "strconv"
 "strings"
)
const diagnostic="FI private field partitions require isolated cached W128 continuous-private P3/F3 with 32768 processing chunk"
type edit struct{path string; before,after []byte; replacement string}
func candidate(path string,src []byte)(*edit,error){
 fs:=token.NewFileSet()
 file,err:=parser.ParseFile(fs,path,src,0);if err!=nil{return nil,err}
 if !bytes.Contains(src,[]byte(diagnostic)){return nil,nil}
 type choice struct{start,end int; replacement string}
 var choices []choice
 ast.Inspect(file,func(n ast.Node)bool{
  stmt,ok:=n.(*ast.IfStmt);if !ok{return true}
  a,b:=fs.Position(stmt.Body.Pos()).Offset,fs.Position(stmt.Body.End()).Offset
  if a<0||b>len(src)||!bytes.Contains(src[a:b],[]byte(diagnostic)){return true}
  ast.Inspect(stmt.Cond,func(n ast.Node)bool{
   x,ok:=n.(*ast.BinaryExpr);if !ok||(x.Op!=token.NEQ&&x.Op!=token.EQL){return true}
   name,ok:=x.X.(*ast.Ident);if !ok||name.Name!="processingChunkRecords"{return true}
   valid:=false
   switch y:=x.Y.(type){
   case *ast.BasicLit:
    if y.Kind==token.INT {v,e:=strconv.ParseInt(y.Value,0,64);valid=e==nil&&v==32768}
   case *ast.Ident:
    valid=strings.Contains(strings.ToLower(y.Name),"chunk")
   }
   if !valid{return true}
   start,end:=fs.Position(x.Pos()).Offset,fs.Position(x.End()).Offset
   expression:=string(src[start:end])
   replacement:="("+expression+" && processingChunkRecords != 65536)"
   if x.Op==token.EQL{replacement="("+expression+" || processingChunkRecords == 65536)"}
   choices=append(choices,choice{start,end,replacement})
   return true
  })
  return true
 })
 if len(choices)!=1{return nil,fmt.Errorf("FI K64 patch requires one guarded 32K comparison in %s, found %d; no change",path,len(choices))}
 c:=choices[0]
 out:=make([]byte,0,len(src)+len(c.replacement))
 out=append(out,src[:c.start]...);out=append(out,c.replacement...);out=append(out,src[c.end:]...)
 if _,err:=parser.ParseFile(token.NewFileSet(),path,out,0);err!=nil{return nil,fmt.Errorf("invalid patched syntax: %w",err)}
 return &edit{path,src,out,c.replacement},nil
}
func main(){
 var repo,backup string
 flag.StringVar(&repo,"repo","/home/jwood/src/fi","existing local fi-dev repository")
 flag.StringVar(&backup,"backup-dir","","existing isolated benchmark root")
 flag.Parse()
 if flag.NArg()!=0||repo!="/home/jwood/src/fi"||!strings.HasPrefix(backup,"/home/jwood/fi-window-bench-optfield-")||strings.Contains(backup,".."){
  fmt.Fprintln(os.Stderr,"FI K64 PATCH STOP: unapproved location");os.Exit(1)
 }
 info,err:=os.Stat(backup);if err!=nil||!info.IsDir(){fmt.Fprintln(os.Stderr,"FI K64 PATCH STOP: backup directory absent");os.Exit(1)}
 paths:=[]string{filepath.Join(repo,"go/cmd/fi-backlog-recover/main_freebsd.go"),filepath.Join(repo,"go/internal/recordingest/backlog_private_field_partition.go")}
 var matches []edit
 for _,p:=range paths{
  data,err:=os.ReadFile(p);if err!=nil{fmt.Fprintln(os.Stderr,"FI K64 PATCH STOP:",err);os.Exit(1)}
  e,err:=candidate(p,data);if err!=nil{fmt.Fprintln(os.Stderr,"FI K64 PATCH STOP:",err);os.Exit(1)}
  if e!=nil{matches=append(matches,*e)}
 }
 if len(matches)!=1{fmt.Fprintf(os.Stderr,"FI K64 PATCH STOP: expected one guarded source file, found %d; no changes\n",len(matches));os.Exit(1)}
 e:=matches[0]
 backupPath:=filepath.Join(backup,"before-allow-k64-"+filepath.Base(e.path))
 if _,err:=os.Stat(backupPath);err==nil{fmt.Fprintln(os.Stderr,"FI K64 PATCH STOP: existing backup, refusing repeat");os.Exit(1)}
 if err:=os.WriteFile(backupPath,e.before,0600);err!=nil{fmt.Fprintln(os.Stderr,"FI K64 PATCH STOP:",err);os.Exit(1)}
 info,err=os.Stat(e.path);if err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}
 tmp:=e.path+".fi-k64-new"
 if _,err:=os.Stat(tmp);err==nil{fmt.Fprintln(os.Stderr,"FI K64 PATCH STOP: temporary file exists");os.Exit(1)}
 if err:=os.WriteFile(tmp,e.after,info.Mode().Perm());err!=nil{fmt.Fprintln(os.Stderr,"FI K64 PATCH STOP:",err);os.Exit(1)}
 if err:=os.Rename(tmp,e.path);err!=nil{fmt.Fprintln(os.Stderr,"FI K64 PATCH STOP:",err);os.Exit(1)}
 fmt.Printf("FI OPTFIELD K64 GUARD PATCH PASS file=%s original_sha256=%x patched_sha256=%x replacement=%q backup=%s\n",e.path,sha256.Sum256(e.before),sha256.Sum256(e.after),e.replacement,backupPath)
}
