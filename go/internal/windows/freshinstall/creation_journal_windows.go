// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package freshinstall

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

const nativeCreationJournalName = "fi-v2-create-only.journal"

// windowsCreationSink implements the native file I/O portion of the creation
// journal protocol. It is private and is NOT wired to fi-install. In
// particular, a caller must NOT assume an arbitrary directory is a trusted
// installer journal parent: native owner/DACL and issuer trust provisioning,
// crash recovery, and service authorization remain separate acceptance gates.
//
// Retain the parent and journal handles for the whole transaction. The journal
// is opened with zero file-sharing permissions and must never be truncated,
// overwritten, renamed, or removed on any failure path.
type windowsCreationSink struct {
	parentPath string
	parent     windows.Handle
	file       *os.File
	reserved   bool
	closed     bool
	poisoned   bool
}

func newWindowsCreationSink(parentPath string) *windowsCreationSink {
	return &windowsCreationSink{parentPath: parentPath}
}

// ReserveNew requires a pre-existing parent directory. It never creates a
// parent because this journal must precede EVERY installer creation phase.
// The future bootstrap must supply and independently verify a protected,
// trusted journal parent before invoking this internal writer.
func (s *windowsCreationSink) ReserveNew(installationID string) error {
	if s == nil || s.closed || s.reserved || s.poisoned {
		return errors.New("Windows FI journal sink is unavailable or already reserved")
	}
	if !validInstallHex128(installationID) {
		return errors.New("Windows FI journal reservation requires a canonical installation ID")
	}
	dir, err := validateJournalParentPath(s.parentPath)
	if err != nil {
		return err
	}
	parentName, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return fmt.Errorf("encode FI journal parent: %w", err)
	}
	parent, err := windows.CreateFile(
		parentName,
		windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, // deny delete/rename
		nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return fmt.Errorf("open FI journal parent without following final reparse point: %w", err)
	}
	// The retained parent handle is deliberately not released until Close.
	s.parent = parent
	if err := requireNativeHandleType(parent, true); err != nil {
		s.poisoned = true
		return fmt.Errorf("FI journal parent type: %w", err)
	}
	finalParent, err := nativeFinalPath(parent)
	if err != nil {
		s.poisoned = true
		return fmt.Errorf("resolve FI journal parent handle: %w", err)
	}
	// The Win32 path used to open this handle may contain an 8.3 alias
	// (RUNNER~1) while GetFinalPathNameByHandle returns its long spelling.
	// Never reject based on text spelling alone; the held directory handle
	// and the newly created file handle must instead resolve to the same
	// final parent. Reparse ancestry is checked separately below.
	if finalParent == "" {
		s.poisoned = true
		return errors.New("FI journal parent has no resolved native identity")
	}
	// Recheck ancestor paths after opening the parent. The held handle denies
	// rename of the opened directory; full native protected-parent provenance
	// and ancestry race testing remain required before installer integration.
	if _, err := validateJournalParentPath(dir); err != nil {
		s.poisoned = true
		return err
	}
	target := filepath.Join(dir, nativeCreationJournalName)
	targetName, err := windows.UTF16PtrFromString(target)
	if err != nil {
		s.poisoned = true
		return fmt.Errorf("encode FI journal target: %w", err)
	}
	// CREATE_NEW is atomic: even an empty preexisting file or reparse point
	// refuses this transaction. No FILE_SHARE_* flags are permitted while
	// holding the journal; every Write is explicitly followed by Sync.
	handle, err := windows.CreateFile(
		targetName,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0,
		nil,
		windows.CREATE_NEW,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_WRITE_THROUGH|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		s.poisoned = true
		return fmt.Errorf("exclusively create FI journal (never replace): %w", err)
	}
	if err := requireNativeHandleType(handle, false); err != nil {
		_ = windows.CloseHandle(handle)
		s.poisoned = true
		return fmt.Errorf("FI journal target type: %w", err)
	}
	finalFile, err := nativeFinalPath(handle)
	if err != nil || !sameNativePath(filepath.Dir(finalFile), finalParent) ||
		!strings.EqualFold(filepath.Base(finalFile), nativeCreationJournalName) {
		_ = windows.CloseHandle(handle)
		s.poisoned = true
		return errors.New("FI journal target does not belong to the retained native parent or expected basename")
	}
	file := os.NewFile(uintptr(handle), target)
	if file == nil {
		_ = windows.CloseHandle(handle)
		s.poisoned = true
		return errors.New("FI journal handle conversion failed")
	}
	s.file = file
	s.reserved = true
	return nil
}

// AppendAndSync permits precisely one complete bounded newline-terminated
// frame. Any write or flush failure permanently poisons the transaction:
// partial writes may already exist, so neither retry nor cleanup is safe.
func (s *windowsCreationSink) AppendAndSync(record []byte) error {
	if s == nil || !s.reserved || s.closed || s.poisoned || s.file == nil {
		return errors.New("FI journal is not exclusively reserved or has failed")
	}
	if len(record) < 2 || len(record) > maxCreationRecordBytes ||
		record[len(record)-1] != '\n' || bytes.Count(record, []byte{'\n'}) != 1 ||
		bytes.IndexByte(record, '\r') >= 0 {
		s.poisoned = true
		return errors.New("FI journal frame is not exactly one bounded canonical line")
	}
	s.poisoned = true // clear ONLY after the entire record has been flushed
	n, err := s.file.Write(record)
	if err != nil {
		return fmt.Errorf("write FI journal event: %w", err)
	}
	if n != len(record) {
		return io.ErrShortWrite
	}
	if err := s.file.Sync(); err != nil {
		return fmt.Errorf("flush FI journal event to durable storage: %w", err)
	}
	s.poisoned = false
	return nil
}

// Close releases both Windows handles. This never deletes or truncates the
// journal, including when the transaction is incomplete or suspect.
func (s *windowsCreationSink) Close() error {
	if s == nil || s.closed {
		return nil
	}
	s.closed = true
	var errs []error
	if s.file != nil {
		if err := s.file.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close FI journal file: %w", err))
		}
		s.file = nil
	}
	if s.parent != 0 {
		if err := windows.CloseHandle(s.parent); err != nil {
			errs = append(errs, fmt.Errorf("close FI journal parent: %w", err))
		}
		s.parent = 0
	}
	return errors.Join(errs...)
}

func requireNativeHandleType(handle windows.Handle, directory bool) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("Windows reparse point is not permitted for an FI journal")
	}
	isDirectory := info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if directory != isDirectory {
		return errors.New("FI journal handle has unexpected file/directory type")
	}
	return nil
}

func nativeFinalPath(handle windows.Handle) (string, error) {
	buf := make([]uint16, 32768)
	n, err := windows.GetFinalPathNameByHandle(handle, &buf[0], uint32(len(buf)), 0)
	if err != nil || n == 0 || n >= uint32(len(buf)) {
		return "", fmt.Errorf("resolve final Windows path: length=%d: %w", n, err)
	}
	return windows.UTF16ToString(buf[:n]), nil
}

// Only local drive-letter paths are currently supported. Network paths,
// device namespaces and mapped root aliases are not trusted bootstrap input.
// Future production policy must independently authenticate this location.
func validateJournalParentPath(path string) (string, error) {
	if path == "" || !filepath.IsAbs(path) {
		return "", errors.New("FI journal parent must be an existing absolute local path")
	}
	dir := filepath.Clean(path)
	vol := filepath.VolumeName(dir)
	if len(vol) != 2 || vol[1] != ':' || !filepath.IsAbs(dir) {
		return "", errors.New("FI journal parent must be on a local Windows drive")
	}
	if filepath.Clean(dir) == filepath.Clean(vol+"\\") {
		return "", errors.New("FI journal cannot be created at the volume root")
	}
	// Reject every ancestor reparse component, including mount points and
	// junctions. This is an additional defense, not a replacement for
	// handle-relative creation and trusted ownership/DACL validation.
	for cur := dir; ; cur = filepath.Dir(cur) {
		ptr, err := windows.UTF16PtrFromString(cur)
		if err != nil {
			return "", fmt.Errorf("encode FI journal ancestor: %w", err)
		}
		attr, err := windows.GetFileAttributes(ptr)
		if err != nil {
			return "", fmt.Errorf("inspect FI journal ancestor %q: %w", cur, err)
		}
		if attr&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
			attr&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
			return "", fmt.Errorf("FI journal ancestor is not a plain directory: %q", cur)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
	}
	return dir, nil
}

func sameNativePath(a, b string) bool {
	// GetFinalPathNameByHandle returns a DOS path with the \\?\ prefix.
	// Normalize that single expected prefix, never resolve UNC/device paths.
	clean := func(s string) string {
		s = strings.TrimPrefix(s, `\\?\`)
		return filepath.Clean(s)
	}
	return strings.EqualFold(clean(a), clean(b))
}
