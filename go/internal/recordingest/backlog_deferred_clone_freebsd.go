//go:build freebsd

package recordingest

import (
 "errors"
 "fmt"
 "io"
 "os"
 "syscall"
)

// FreeBSD 15.1 syscall.h / unistd.h. Clone-only: never silently fall back
// to ordinary copying or accept a shared inode.
func cloneDeferredDataFile(src,dst string,expected int64)error{
 const (
  copyRangeSyscall=569
  copyRangeClone=0x00800000
  maxSize=1<<31-1
 )
 if expected<=0||expected>=maxSize{return errors.New("deferred clone: signed batch outside syscall bounds")}
 in,err:=os.Open(src);if err!=nil{return err}
 defer in.Close()
 out,err:=os.OpenFile(dst,os.O_CREATE|os.O_EXCL|os.O_RDWR,0600)
 if err!=nil{return err}
 defer out.Close()
 var got int64
 for got<expected{
  n,_,errno:=syscall.Syscall6(copyRangeSyscall,in.Fd(),0,out.Fd(),0,uintptr(maxSize),copyRangeClone)
  if errno!=0{return fmt.Errorf("deferred clone: copy_file_range clone-only: %w",errno)}
  if n==0{return io.ErrUnexpectedEOF}
  got+=int64(n)
  if got>expected{return errors.New("deferred clone: copied beyond signed length")}
 }
 return out.Sync()
}
