// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package freshinstall

import (
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

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
// Both handles deny FILE_SHARE_DELETE, preventing path rename/removal of the
// opened parent and the newly created child while the reservation is held.
// Close NEVER removes the bootstrap directory (even after errors).
type windowsBootstrapReservation struct {
	parent windows.Handle
	child windows.Handle
	path string
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

// reserveProtectedBootstrap creates exactly ONE new FI-Installer child under
// an already existing local directory. It NEVER creates the parent, modifies
// existing ACLs, adopts an existing bootstrap, or retries an uncertain create.
//
// The native directory handle is retained across CreateDirectoryW and child
// attestation. Windows CreateDirectoryW with a non-nil SecurityAttributes
// initializes the protected descriptor atomically with the new directory.
// Handle/path/ancestor checks are defense-in-depth, not a substitute for
// a future trusted parent issuer or truly handle-relative native creation.
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
		windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL,
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
	childName, err := windows.UTF16PtrFromString(childPath)
	if err != nil {
		return res, fmt.Errorf("%w: encode new directory path: %v", ErrBootstrapInDoubt, err)
	}
	attrs := &windows.SecurityAttributes{
		Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	createErr := windows.CreateDirectory(childName, attrs)
	runtime.KeepAlive(descriptor)
	if createErr != nil {
		if errors.Is(createErr, windows.ERROR_ALREADY_EXISTS) ||
			errors.Is(createErr, windows.ERROR_FILE_EXISTS) {
			return res, fmt.Errorf("%w: %v", ErrBootstrapAlreadyExists, createErr)
		}
		return res, fmt.Errorf("%w: CreateDirectoryW with protected security attributes: %w", ErrBootstrapInDoubt, createErr)
	}

	// A successful CreateDirectoryW is not complete until the exact new
	// object is re-opened and its ACTUAL security and identity are verified.
	// Failure after this point is ALWAYS in doubt; never delete the child.
	child, openErr := windows.CreateFile(
		childName, windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if openErr != nil {
		return res, fmt.Errorf("%w: reopen created protected child: %v", ErrBootstrapInDoubt, openErr)
	}
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
	// No file exists inside this bootstrap and no grant was issued. This is
	// an object reservation only; the future trusted installer transaction
	// must decide whether any subsequent FI creation is permissible.
	res.path = childPath
	success = true
	return res, nil
}
