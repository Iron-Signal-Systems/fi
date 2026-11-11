// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package freshinstall

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

const (
	nativeBootstrapDirectoryName = "FI-Installer"
	// Supply the protected owner/DACL AT native creation, not by making a
	// world/inherited-access directory and repairing it afterward. Assign
	// ownership to BUILTIN Administrators, not an arbitrary installer user.
	// An unelevated or unprivileged token must fail rather than fall back.
	nativeBootstrapSDDL = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
)

var (
	ErrBootstrapAlreadyExists = errors.New("FI v2 installer bootstrap directory already exists")
	ErrBootstrapInDoubt = errors.New("FI v2 protected bootstrap creation has an uncertain or incomplete outcome")
)

// windowsBootstrapReservation is a PRIVATE native creation experiment, not
// trusted installer approval or an installed authorization token.
//
// A future installer must prove that the parent directory itself is a
// trusted, immutable location on the correct local system volume; that the
// elevated creator and operator consent are authentic; and that a protected
// creation journal/commit is retained for crash recovery. This primitive
// cannot confer any of those facts. No public installer code invokes it.
//
// Both handles request no FILE_SHARE_DELETE, but Windows may still permit
// a directory rename while open. The fixed child is now CREATED relative to
// the live parent HANDLE, eliminating the second by-path create resolution.
// Every handoff still revalidates retained original native paths and DACLs.
// This is detection against subsequent relocation, NOT authentication of a
// hostile/replaced original parent or trusted system ProgramData provenance.
// Close NEVER removes the bootstrap directory (even after errors).
type windowsBootstrapReservation struct {
	parent windows.Handle
	child windows.Handle
	path string
	// These are the native paths observed through the retained handles on
	// successful creation. They must never be recomputed as a new baseline.
	parentNative string
	childNative string
	closed bool
}

func (r *windowsBootstrapReservation) Close() error {
	if r == nil || r.closed {
		return nil
	}
	r.closed = true
	var errs []error
	if r.child != 0 && r.child != windows.InvalidHandle {
		errs = append(errs, windows.CloseHandle(r.child))
		r.child = 0
	}
	if r.parent != 0 && r.parent != windows.InvalidHandle {
		errs = append(errs, windows.CloseHandle(r.parent))
		r.parent = 0
	}
	return errors.Join(errs...)
}

// verifyRetained detects if either held object was moved to a different
// path or lost its original descriptor after initial creation. In particular,
// lack of FILE_SHARE_DELETE does NOT guarantee that a directory cannot be
// renamed on every Windows filesystem. This must be rechecked at every
// future installation mutation boundary; it does not close TOCTOU windows
// between separate path operations. No installer or service calls it yet.
func (r *windowsBootstrapReservation) verifyRetained() error {
	if r == nil || r.closed || r.parent == 0 || r.child == 0 ||
		r.parent == windows.InvalidHandle || r.child == windows.InvalidHandle ||
		r.parentNative == "" || r.childNative == "" {
		return fmt.Errorf("%w: no live native bootstrap reservation", ErrBootstrapInDoubt)
	}
	if err := requireNativeHandleType(r.parent, true); err != nil {
		return fmt.Errorf("%w: original parent changed type: %v", ErrBootstrapInDoubt, err)
	}
	if err := requireNativeHandleType(r.child, true); err != nil {
		return fmt.Errorf("%w: original bootstrap child changed type: %v", ErrBootstrapInDoubt, err)
	}
	parentNow, err := nativeFinalPath(r.parent)
	if err != nil || !sameNativePath(parentNow, r.parentNative) {
		return fmt.Errorf("%w: retained parent relocated: %v", ErrBootstrapInDoubt, err)
	}
	childNow, err := nativeFinalPath(r.child)
	if err != nil || !sameNativePath(childNow, r.childNative) ||
		!sameNativePath(filepath.Dir(childNow), parentNow) {
		return fmt.Errorf("%w: retained bootstrap directory relocated: %v", ErrBootstrapInDoubt, err)
	}
	if err := verifyJournalParentHandle(r.child); err != nil {
		return fmt.Errorf("%w: retained bootstrap directory owner/DACL changed: %v", ErrBootstrapInDoubt, err)
	}
	return nil
}

// reserveProtectedBootstrap creates exactly ONE new FI-Installer child under
// an already existing local directory. It NEVER creates the parent, modifies
// existing ACLs, adopts an existing bootstrap, or retries an uncertain create.
//
// The native parent directory handle is retained across a parent-relative
// NtCreateFile(FILE_CREATE|FILE_DIRECTORY_FILE) child creation and subsequent
// identity/ACL attestation. The protected security descriptor is supplied
// in OBJECT_ATTRIBUTES at the first create call, never repaired later.
// RootDirectory binds the creation to the held parent object, not a second
// resolution of a caller-provided path. This does NOT independently establish
// the parent/ancestor's authenticity as system ProgramData, a trusted issuer,
// or an approved installation transaction.
func reserveProtectedBootstrap(parentPath string) (res *windowsBootstrapReservation, err error) {
	parentDir, err := validateJournalParentPath(parentPath)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid native bootstrap parent: %v", ErrBootstrapInDoubt, err)
	}
	// Caller passes the PARENT, never a path to an existing FI-Installer
	// artifact. A pre-existing child must fail the native atomic create.
	if strings.EqualFold(filepath.Base(parentDir), nativeBootstrapDirectoryName) {
		return nil, fmt.Errorf("%w: expected parent of %s, not the bootstrap itself",
			ErrBootstrapInDoubt, nativeBootstrapDirectoryName)
	}
	parentName, err := windows.UTF16PtrFromString(parentDir)
	if err != nil {
		return nil, fmt.Errorf("%w: encode parent: %v", ErrBootstrapInDoubt, err)
	}
	parent, err := windows.CreateFile(
		parentName,
		windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL|0x00000004, // FILE_ADD_SUBDIRECTORY
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, // no delete/rename
		nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("%w: open original parent: %v", ErrBootstrapInDoubt, err)
	}
	res = &windowsBootstrapReservation{parent: parent}
	success := false
	defer func() {
		if !success {
			// A failed/partial CREATE_NEW is never automatically rolled back.
			// Close only the handles; preserve any directory for review.
			err = errors.Join(err, res.Close())
			res = nil
		}
	}()
	if err = requireNativeHandleType(parent, true); err != nil {
		return res, fmt.Errorf("%w: parent directory native type: %v", ErrBootstrapInDoubt, err)
	}
	finalParent, resolveErr := nativeFinalPath(parent)
	if resolveErr != nil || finalParent == "" {
		return res, fmt.Errorf("%w: resolve original parent: %v", ErrBootstrapInDoubt, resolveErr)
	}
	if _, err = validateJournalParentPath(parentDir); err != nil {
		return res, fmt.Errorf("%w: recheck parent ancestor chain: %v", ErrBootstrapInDoubt, err)
	}

	descriptor, err := windows.SecurityDescriptorFromString(nativeBootstrapSDDL)
	if err != nil {
		return res, fmt.Errorf("%w: build protected initial directory ACL: %v", ErrBootstrapInDoubt, err)
	}
	observed, err := journalParentSecurityFromDescriptor(descriptor)
	if err != nil {
		return res, fmt.Errorf("%w: inspect intended protected descriptor: %v", ErrBootstrapInDoubt, err)
	}
	if err = ValidateJournalParentSecurity(observed); err != nil {
		return res, fmt.Errorf("%w: intended owner/DACL does not satisfy policy: %v", ErrBootstrapInDoubt, err)
	}
	childPath := filepath.Join(parentDir, nativeBootstrapDirectoryName)
	// The NT object name is the single fixed child component, and the
	// RootDirectory is the LIVE parent handle above. No absolute child path
	// or a fresh path lookup determines which directory receives this create.
	child, createErr := createProtectedBootstrapChildAt(parent, descriptor)
	if createErr != nil {
		return res, createErr
	}
	// FILE_CREATE reports a newly created handle, never an adopted older FI
	// directory. All subsequent checks use that EXACT returned native handle.
	// Any failure after creation leaves the object for manual recovery.
	res.child = child
	if err = requireNativeHandleType(child, true); err != nil {
		return res, fmt.Errorf("%w: created child is not a plain directory: %v", ErrBootstrapInDoubt, err)
	}
	finalChild, resolveErr := nativeFinalPath(child)
	if resolveErr != nil || !sameNativePath(filepath.Dir(finalChild), finalParent) ||
		!strings.EqualFold(filepath.Base(finalChild), nativeBootstrapDirectoryName) {
		return res, fmt.Errorf("%w: created directory is not the expected child of retained parent: %v",
			ErrBootstrapInDoubt, resolveErr)
	}
	if err = verifyJournalParentHandle(child); err != nil {
		return res, fmt.Errorf("%w: created directory owner/protected DACL differs from intended policy: %v",
			ErrBootstrapInDoubt, err)
	}
	// No file exists inside this bootstrap and no grant was issued. Store
	// the ORIGINAL native paths. If Windows permits a later rename despite
	// requested sharing restrictions, verifyRetained rejects that move at
	// the next handoff rather than believing the lock pinned a path.
	res.path = childPath
	res.parentNative = finalParent
	res.childNative = finalChild
	if err := res.verifyRetained(); err != nil {
		return res, err
	}
	success = true
	return res, nil
}
