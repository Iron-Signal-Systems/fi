// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package volumecustody

import (
 "bytes"
 "context"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "sync"
 "syscall"
 "unsafe"

 "github.com/Iron-Signal-Systems/fi/go/internal/windows/volumeepoch"
)

const (
 volumeLockExclusive = 0x00000002
 volumeLockFailImmediately = 0x00000001
 volumeMoveReplaceExisting = 0x00000001
 volumeMoveWriteThrough = 0x00000008
 maxVolumeCheckpointBytes = 4096
)

var (
 volumeFileKernel32 = syscall.NewLazyDLL("kernel32.dll")
 volumeLockFileEx = volumeFileKernel32.NewProc("LockFileEx")
 volumeUnlockFileEx = volumeFileKernel32.NewProc("UnlockFileEx")
 volumeMoveFileEx = volumeFileKernel32.NewProc("MoveFileExW")
 ErrVolumeStateBusy = errors.New("FI enrolled-volume state lease is already held")
 ErrVolumeStateUntrusted = errors.New("FI volume state directory or checkpoint is not acceptable")
)

// WindowsVolumeState is an ISOLATED DEVELOPMENT backend implementing both
// LeaseProvider and CheckpointStore. It never initializes an epoch or an
// installation, creates directories, grants Windows rights or authorizes USN
// capture. A FUTURE installer must pre-provision and attest an appropriate
// protected directory and its ancestor chain before using this in a service.
//
// Both Load and Commit require the same process to hold the cross-process
// LockFileEx lease. A second state instance/process cannot commit concurrently.
// On-disk checkpoint contents are NOT signed or proof of trusted installation.
type WindowsVolumeState struct {
 Directory string
 mu sync.Mutex
 held map[string]*volumeStateLease
}

type volumeStateLease struct {
 owner *WindowsVolumeState
 id string
 file *os.File
 overlapped syscall.Overlapped
 released bool
}

func (s *WindowsVolumeState) checkedDirectory() (string,error) {
 if s==nil || !filepath.IsAbs(s.Directory) {return "",ErrVolumeStateUntrusted}
 path:=filepath.Clean(s.Directory)
 info,err:=os.Lstat(path)
 if err!=nil {return "",fmt.Errorf("%w: inspect pre-existing state directory: %v",ErrVolumeStateUntrusted,err)}
 if !info.IsDir() || info.Mode()&os.ModeSymlink!=0 {
  return "",fmt.Errorf("%w: state location must be an existing real directory",ErrVolumeStateUntrusted)
 }
 return path,nil
}

func (s *WindowsVolumeState) Acquire(ctx context.Context,id string) (Lease,error) {
 if ctx==nil || !validPassEnrollment(id) {return nil,ErrUnconfiguredPass}
 if err:=ctx.Err();err!=nil{return nil,err}
 dir,err:=s.checkedDirectory()
 if err!=nil{return nil,err}
 s.mu.Lock()
 defer s.mu.Unlock()
 if s.held==nil{s.held=make(map[string]*volumeStateLease)}
 if s.held[id]!=nil{return nil,ErrVolumeStateBusy}
 lockPath:=filepath.Join(dir,"fi-volume-"+id+".lock")
 if info,err:=os.Lstat(lockPath);err==nil{
  if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink!=0 {
   return nil,fmt.Errorf("%w: lease file is not regular",ErrVolumeStateUntrusted)
  }
 } else if !errors.Is(err,os.ErrNotExist) {return nil,err}
 f,err:=os.OpenFile(lockPath,os.O_CREATE|os.O_RDWR,0600)
 if err!=nil{return nil,fmt.Errorf("open enrolled-volume lease: %w",err)}
 fi,err:=f.Stat()
 if err!=nil || fi==nil || !fi.Mode().IsRegular(){
  _=f.Close()
  return nil,fmt.Errorf("%w: lease file handle is not regular: %v",ErrVolumeStateUntrusted,err)
 }
 l:=&volumeStateLease{owner:s,id:id,file:f}
 r,_,callErr:=volumeLockFileEx.Call(f.Fd(),uintptr(volumeLockExclusive|volumeLockFailImmediately),0,1,0,uintptr(unsafe.Pointer(&l.overlapped)))
 if r==0{
  _=f.Close()
  if callErr!=nil && callErr!=syscall.Errno(0){return nil,fmt.Errorf("%w: %v",ErrVolumeStateBusy,callErr)}
  return nil,ErrVolumeStateBusy
 }
 if err:=ctx.Err();err!=nil{
  // Do not leak a lock when cancellation races with the OS lock call.
  _,_,_ = volumeUnlockFileEx.Call(f.Fd(),0,1,0,uintptr(unsafe.Pointer(&l.overlapped)))
  _=f.Close()
  return nil,err
 }
 s.held[id]=l
 return l,nil
}

func (l *volumeStateLease) Release() error {
 if l==nil || l.owner==nil {return ErrUnconfiguredPass}
 s:=l.owner
 s.mu.Lock()
 defer s.mu.Unlock()
 if l.released{return nil}
 if s.held[l.id]!=l{return ErrVolumeCheckpointConflict}
 l.released=true
 delete(s.held,l.id)
 r,_,callErr:=volumeUnlockFileEx.Call(l.file.Fd(),0,1,0,uintptr(unsafe.Pointer(&l.overlapped)))
 closeErr:=l.file.Close()
 if r==0{return errors.Join(fmt.Errorf("unlock enrolled-volume lease: %v",callErr),closeErr)}
 return closeErr
}

// requireLease holds the instance mutex across the whole file operation,
// not merely its initial lease check. Otherwise another goroutine could call
// Release between the check and the durable write, forfeiting the native lock
// before our checkpoint replacement finishes. The unlock closure must always
// be deferred by Load or Commit.
func (s *WindowsVolumeState) requireLease(ctx context.Context,id string) (string,func(),error) {
 if ctx==nil || !validPassEnrollment(id) {return "",nil,ErrUnconfiguredPass}
 if err:=ctx.Err();err!=nil{return "",nil,err}
 dir,err:=s.checkedDirectory()
 if err!=nil{return "",nil,err}
 s.mu.Lock()
 active:=s.held[id]!=nil && !s.held[id].released
 if !active{
  s.mu.Unlock()
  return "",nil,fmt.Errorf("%w: checkpoint operations require an active enrolled-volume lease",ErrVolumeStateBusy)
 }
 return filepath.Join(dir,"fi-volume-"+id+".checkpoint.json"),s.mu.Unlock,nil
}

func (s *WindowsVolumeState) Load(ctx context.Context,id string) (volumeepoch.Checkpoint,error) {
 path,unlock,err:=s.requireLease(ctx,id)
 if err!=nil{return volumeepoch.Checkpoint{},err}
 defer unlock()
 return loadVolumeStateFile(path,id)
}

func loadVolumeStateFile(path,id string) (volumeepoch.Checkpoint,error) {
 info,err:=os.Lstat(path)
 if err!=nil{return volumeepoch.Checkpoint{},err}
 if !info.Mode().IsRegular() || info.Size()<=0 || info.Size()>maxVolumeCheckpointBytes {
  return volumeepoch.Checkpoint{},fmt.Errorf("%w: checkpoint must be a bounded regular file",ErrVolumeStateUntrusted)
 }
 f,err:=os.Open(path)
 if err!=nil{return volumeepoch.Checkpoint{},err}
 defer f.Close()
 // Lstat size is only a point-in-time observation. Always bound the actual
 // bytes read even if an untrusted file grows between stat and read.
 raw,err:=io.ReadAll(io.LimitReader(f,maxVolumeCheckpointBytes+1))
 if err!=nil{return volumeepoch.Checkpoint{},err}
 if len(raw)==0 || len(raw)>maxVolumeCheckpointBytes {
  return volumeepoch.Checkpoint{},fmt.Errorf("%w: checkpoint byte length outside permitted bounds",ErrVolumeStateUntrusted)
 }
 decoder:=json.NewDecoder(bytes.NewReader(raw))
 decoder.DisallowUnknownFields()
 var cp volumeepoch.Checkpoint
 if err:=decoder.Decode(&cp);err!=nil{return volumeepoch.Checkpoint{},fmt.Errorf("%w: decode checkpoint: %v",ErrVolumeStateUntrusted,err)}
 var trailing any
 if err:=decoder.Decode(&trailing);err!=io.EOF {
  return volumeepoch.Checkpoint{},fmt.Errorf("%w: trailing checkpoint content",ErrVolumeStateUntrusted)
 }
 if err:=volumeepoch.ValidateCheckpoint(id,cp);err!=nil {
  return volumeepoch.Checkpoint{},fmt.Errorf("%w: %v",ErrVolumeStateUntrusted,err)
 }
 // JSON decoders permit duplicate keys. The protected runtime checkpoint
 // is strictly our own one-line canonical encoding, so refuse duplicates,
 // extra whitespace and alternate representations rather than guessing
 // which disk bytes the previous writer actually committed.
 canonical,err:=json.Marshal(cp)
 if err!=nil{return volumeepoch.Checkpoint{},err}
 canonical=append(canonical,'\n')
 if !bytes.Equal(raw,canonical) {
  return volumeepoch.Checkpoint{},fmt.Errorf("%w: noncanonical or duplicate-key checkpoint encoding",ErrVolumeStateUntrusted)
 }
 return cp,nil
}

func (s *WindowsVolumeState) Commit(ctx context.Context,expected,next volumeepoch.Checkpoint) error {
 if err:=volumeepoch.ValidateCheckpoint(expected.EnrollmentID,expected);err!=nil{return err}
 if err:=volumeepoch.ValidateCheckpoint(expected.EnrollmentID,next);err!=nil{return err}
 if next.EnrollmentID!=expected.EnrollmentID || next.Epoch!=expected.Epoch ||
  next.Identity!=expected.Identity {return ErrVolumeCheckpointConflict}
 oldCursor,err:=parseVolumeCursor(expected.NextUSN)
 if err!=nil{return err}
 newCursor,err:=parseVolumeCursor(next.NextUSN)
 if err!=nil{return err}
 if newCursor<=oldCursor{return ErrVolumeCheckpointConflict}
 path,unlock,err:=s.requireLease(ctx,expected.EnrollmentID)
 if err!=nil{return err}
 defer unlock()
 // Reject stale or replaced saved state while retaining the cross-process
 // lease. An in-doubt prior write must never be blindly overwritten.
 current,err:=loadVolumeStateFile(path,expected.EnrollmentID)
 if err!=nil{return err}
 if current!=expected{return ErrVolumeCheckpointConflict}
 content,err:=json.Marshal(next)
 if err!=nil{return err}
 content=append(content,'\n')
 if len(content)>maxVolumeCheckpointBytes{return ErrVolumeStateUntrusted}
 dir:=filepath.Dir(path)
 // Never overwrite, auto-clean or adopt an interrupted prior checkpoint
 // transaction. Only explicit evidence-based manual recovery can resolve it.
 pending:=filepath.Join(dir,"fi-volume-"+expected.EnrollmentID+".checkpoint.pending")
 if _,err:=os.Lstat(pending);err==nil{return fmt.Errorf("%w: prior incomplete checkpoint write exists",ErrVolumeStateUntrusted)}else if !errors.Is(err,os.ErrNotExist){return err}
 f,err:=os.OpenFile(pending,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600)
 if err!=nil{return fmt.Errorf("reserve checkpoint pending file: %w",err)}
 // Keep the pending file after any error. An uncertain rename leaves state
 // requiring manual investigation, never an automatic cleanup/retry.
 if _,err:=f.Write(content);err!=nil{_ = f.Close();return err}
 if err:=f.Sync();err!=nil{_ = f.Close();return err}
 if err:=f.Close();err!=nil{return err}
 if err:=ctx.Err();err!=nil{return err}
 from,err:=syscall.UTF16PtrFromString(pending);if err!=nil{return err}
 to,err:=syscall.UTF16PtrFromString(path);if err!=nil{return err}
 r,_,callErr:=volumeMoveFileEx.Call(uintptr(unsafe.Pointer(from)),uintptr(unsafe.Pointer(to)),uintptr(volumeMoveReplaceExisting|volumeMoveWriteThrough))
 if r==0{return fmt.Errorf("replace volume checkpoint through WRITE_THROUGH rename (in doubt): %v",callErr)}
 // Success is not proof of power-loss durability on all storage devices.
 return nil
}

// parseVolumeCursor preserves unsigned width and canonical string encoding
// before verifying strictly forward-only progress.
func parseVolumeCursor(value string) (uint64,error) {
 if value=="" || (value!="0" && (value[0]<'1'||value[0]>'9')) {return 0,ErrVolumeCheckpointConflict}
 var n uint64
 for i:=0;i<len(value);i++{
  if value[i]<'0'||value[i]>'9'{return 0,ErrVolumeCheckpointConflict}
  digit:=uint64(value[i]-'0')
  if n>(^uint64(0)-digit)/10{return 0,ErrVolumeCheckpointConflict}
  n=n*10+digit
 }
 if n==0 && value!="0" || n!=0 && value[0]=='0' {return 0,ErrVolumeCheckpointConflict}
 return n,nil
}

// VerifyInstalledCheckpointLocation is deliberately absent. A secure native
// installer must establish trusted ancestor handles, owner/DACL, protected
// state directory, service access and a signed installed-grant before this
// component can be wired into a Windows FICollector service.
