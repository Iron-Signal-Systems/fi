// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package ntfs

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strconv"
	"syscall"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

const contentHashBufferSize = 1024 * 1024

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader contextReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(buffer)
}

// CollectContentHashes is retained as a focused hash entry point for tests and
// callers that intentionally need only content fingerprints. Normal FI object
// collection now hashes before CollectPath/CollectFileReference returns, so the
// spool layer does not call this function separately.
//
// It reads the regular file's unnamed/default $DATA stream locally and
// calculates MD5, SHA-1, and SHA-256 in one pass. It never returns source bytes
// and does not hash named ADS.
func CollectContentHashes(
	ctx context.Context,
	scopeID string,
	governedRoot string,
	identity records.NTFSObjectIdentity,
	subjectKind records.SubjectKind,
) (records.ContentHashObservation, error) {
	if err := validateContext(ctx); err != nil {
		return records.ContentHashObservation{}, err
	}
	if err := records.ValidateNTFSObjectIdentity(identity); err != nil {
		return records.ContentHashObservation{}, err
	}

	rootUnits, err := syscall.UTF16FromString(governedRoot)
	if err != nil {
		return records.ContentHashObservation{}, err
	}
	rootPath := rootUnits[:len(rootUnits)-1]
	root, err := openGovernedRoot(scopeID, rootPath)
	if err != nil {
		return records.ContentHashObservation{}, err
	}
	defer syscall.CloseHandle(root.handle)

	return collectContentHashesOpened(ctx, root, root.handle, identity, subjectKind)
}

// collectContentHashesOpened performs the content portion of the same bounded
// FI object collection. volumeHint is an already-open handle on the same NTFS
// volume (normally the original target observation handle). FI reopens the
// exact object identity with GENERIC_READ rather than trusting a pathname.
func collectContentHashesOpened(
	ctx context.Context,
	root governedRootContext,
	volumeHint syscall.Handle,
	identity records.NTFSObjectIdentity,
	subjectKind records.SubjectKind,
) (records.ContentHashObservation, error) {
	if subjectKind == records.SubjectDirectory {
		value := records.ContentHashObservation{State: records.ContentHashNotApplicable}
		return value, records.ValidateContentHashObservation(value)
	}
	if subjectKind != records.SubjectFile {
		return records.ContentHashObservation{}, errors.New("unsupported subject kind for content hashing")
	}
	if err := validateContext(ctx); err != nil {
		return records.ContentHashObservation{}, err
	}
	if err := records.ValidateNTFSObjectIdentity(identity); err != nil {
		return records.ContentHashObservation{}, err
	}

	handle, err := openFileByObjectIdentityAccess(volumeHint, identity, syscall.GENERIC_READ)
	if err != nil {
		return contentHashError("ContentOpenFailed", err), nil
	}
	file := os.NewFile(uintptr(handle), "fi-content-hash")
	if file == nil {
		syscall.CloseHandle(handle)
		return contentHashError("ContentOpenFailed", errors.New("os.NewFile returned nil")), nil
	}
	defer file.Close()

	pre, err := queryNativeState(handle)
	if err != nil {
		return contentHashError("ContentStateReadFailed", err), nil
	}
	_, openedIdentity, err := buildObjectIdentity(pre.ID.VolumeSerialNumber, pre.ID.FileID)
	if err != nil || openedIdentity != identity {
		if err == nil {
			err = ErrObjectIdentityMismatch
		}
		return contentHashError("ObjectIdentityMismatch", err), nil
	}
	if pre.Standard.Directory != 0 || pre.Basic.FileAttributes&fileAttributeDirectory != 0 {
		return contentHashError("SubjectKindChanged", errors.New("object is now a directory")), nil
	}
	if err := proveHashContainment(root, handle); err != nil {
		return contentHashError("OutsideGovernedRoot", err), nil
	}

	md5Hash := md5.New()
	sha1Hash := sha1.New()
	sha256Hash := sha256.New()
	writer := io.MultiWriter(md5Hash, sha1Hash, sha256Hash)
	bytesHashed, readErr := io.CopyBuffer(
		writer,
		contextReader{ctx: ctx, reader: file},
		make([]byte, contentHashBufferSize),
	)
	if readErr != nil {
		// Context cancellation is collector control flow, not a source-file hash
		// failure. Propagate it so the surrounding bounded operation stops rather
		// than recording ContentReadFailed for an intentional cancellation.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return records.ContentHashObservation{}, ctxErr
		}
		return contentHashError("ContentReadFailed", readErr), nil
	}
	if err := validateContext(ctx); err != nil {
		return records.ContentHashObservation{}, err
	}

	post, err := queryNativeState(handle)
	if err != nil {
		return contentHashError("ContentStateReadFailed", err), nil
	}
	if pre.ID != post.ID {
		return contentHashError("ObjectIdentityChangedDuringHash", ErrIdentityChanged), nil
	}
	if hashRelevantStateChanged(pre, post) {
		return contentHashError("ChangedDuringHash", errors.New("file metadata changed while content was being hashed")), nil
	}
	if err := proveHashContainment(root, handle); err != nil {
		return contentHashError("OutsideGovernedRoot", err), nil
	}

	value := records.ContentHashObservation{
		State:       records.ContentHashPresent,
		BytesHashed: strconv.FormatInt(bytesHashed, 10),
		MD5:         hex.EncodeToString(md5Hash.Sum(nil)),
		SHA1:        hex.EncodeToString(sha1Hash.Sum(nil)),
		SHA256:      hex.EncodeToString(sha256Hash.Sum(nil)),
	}
	if err := records.ValidateContentHashObservation(value); err != nil {
		return records.ContentHashObservation{}, err
	}
	return value, nil
}

func hashRelevantStateChanged(left, right nativeState) bool {
	// Last-access time is intentionally excluded. Reading content can itself
	// update that timestamp on systems where NTFS last-access updates are enabled.
	return left.Standard != right.Standard ||
		left.Basic.CreationTime != right.Basic.CreationTime ||
		left.Basic.LastWriteTime != right.Basic.LastWriteTime ||
		left.Basic.ChangeTime != right.Basic.ChangeTime ||
		left.Basic.FileAttributes != right.Basic.FileAttributes ||
		left.AttributeTag != right.AttributeTag
}

func proveHashContainment(root governedRootContext, handle syscall.Handle) error {
	finalPath, err := finalVolumePath(handle)
	if err != nil {
		return err
	}
	volumeGUID, err := volumeGUIDFromFinalPath(finalPath)
	if err != nil {
		return err
	}
	if volumeGUID != root.volumeGUID || !pathContainedBy(root.finalPath, finalPath) {
		return ErrOutsideGovernedRoot
	}
	return nil
}

func contentHashError(reason string, err error) records.ContentHashObservation {
	value := records.ContentHashObservation{State: records.ContentHashError, ReasonCode: reason}
	if err != nil {
		value.Detail = err.Error()
	}
	return value
}
