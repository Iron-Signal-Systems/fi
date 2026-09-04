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
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strconv"
	"syscall"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

const contentHashBufferSize = 1024 * 1024

type contentPrefixWriter struct {
	value []byte
}

type contentReadObservation struct {
	Hashes records.ContentHashObservation
	Prefix records.ContentPrefixObservation
}

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

func (writer *contentPrefixWriter) Write(buffer []byte) (int, error) {
	if len(writer.value) < records.ContentPrefixMaxBytes {
		remaining := records.ContentPrefixMaxBytes - len(writer.value)
		if remaining > len(buffer) {
			remaining = len(buffer)
		}
		writer.value = append(writer.value, buffer[:remaining]...)
	}
	return len(buffer), nil
}

// CollectContentHashes is retained as a focused hash entry point for tests and
// callers that intentionally need only content fingerprints. Normal FI object
// collection now collects hashes and the bounded content prefix before
// CollectPath/CollectFileReference returns, so the spool layer does not call
// this function separately.
//
// It reads the regular file's unnamed/default $DATA stream locally and
// calculates MD5, SHA-1, and SHA-256 in one pass. It never returns source bytes
// through this hash-only entry point and does not hash named ADS.
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

	content, err := collectContentOpened(ctx, root, root.handle, identity, subjectKind)
	if err != nil {
		return records.ContentHashObservation{}, err
	}
	return content.Hashes, nil
}

// collectContentHashesOpened retains the focused internal hash contract for
// existing tests/callers. The underlying source read also captures the bounded
// content prefix so normal full collection does not need a second source read.
func collectContentHashesOpened(
	ctx context.Context,
	root governedRootContext,
	volumeHint syscall.Handle,
	identity records.NTFSObjectIdentity,
	subjectKind records.SubjectKind,
) (records.ContentHashObservation, error) {
	content, err := collectContentOpened(ctx, root, volumeHint, identity, subjectKind)
	if err != nil {
		return records.ContentHashObservation{}, err
	}
	return content.Hashes, nil
}

// collectContentOpened performs the content portion of the same bounded FI
// object collection. volumeHint is an already-open handle on the same NTFS
// volume (normally the original target observation handle). FI reopens the
// exact object identity with GENERIC_READ rather than trusting a pathname.
//
// The unnamed/default $DATA stream is read once. The same bytes feed MD5,
// SHA-1, SHA-256, and a writer that retains at most the first 16 bytes. No
// second file open or second content read is introduced for the prefix.
func collectContentOpened(
	ctx context.Context,
	root governedRootContext,
	volumeHint syscall.Handle,
	identity records.NTFSObjectIdentity,
	subjectKind records.SubjectKind,
) (contentReadObservation, error) {
	if subjectKind == records.SubjectDirectory {
		value := contentReadObservation{
			Hashes: records.ContentHashObservation{State: records.ContentHashNotApplicable},
			Prefix: records.ContentPrefixObservation{State: records.ContentPrefixNotApplicable},
		}
		if err := records.ValidateContentHashObservation(value.Hashes); err != nil {
			return contentReadObservation{}, err
		}
		if err := records.ValidateContentPrefixObservation(value.Prefix); err != nil {
			return contentReadObservation{}, err
		}
		return value, nil
	}
	if subjectKind != records.SubjectFile {
		return contentReadObservation{}, errors.New("unsupported subject kind for content hashing")
	}
	if err := validateContext(ctx); err != nil {
		return contentReadObservation{}, err
	}
	if err := records.ValidateNTFSObjectIdentity(identity); err != nil {
		return contentReadObservation{}, err
	}

	handle, err := openFileByObjectIdentityAccess(volumeHint, identity, syscall.GENERIC_READ)
	if err != nil {
		return contentReadError("ContentOpenFailed", err), nil
	}
	file := os.NewFile(uintptr(handle), "fi-content-hash")
	if file == nil {
		syscall.CloseHandle(handle)
		return contentReadError("ContentOpenFailed", errors.New("os.NewFile returned nil")), nil
	}
	defer file.Close()

	pre, err := queryNativeState(handle)
	if err != nil {
		return contentReadError("ContentStateReadFailed", err), nil
	}
	_, openedIdentity, err := buildObjectIdentity(pre.ID.VolumeSerialNumber, pre.ID.FileID)
	if err != nil || openedIdentity != identity {
		if err == nil {
			err = ErrObjectIdentityMismatch
		}
		return contentReadError("ObjectIdentityMismatch", err), nil
	}
	if pre.Standard.Directory != 0 || pre.Basic.FileAttributes&fileAttributeDirectory != 0 {
		return contentReadError("SubjectKindChanged", errors.New("object is now a directory")), nil
	}
	if err := proveHashContainment(root, handle); err != nil {
		return contentReadError("OutsideGovernedRoot", err), nil
	}

	md5Hash := md5.New()
	sha1Hash := sha1.New()
	sha256Hash := sha256.New()
	prefix := &contentPrefixWriter{value: make([]byte, 0, records.ContentPrefixMaxBytes)}
	writer := io.MultiWriter(md5Hash, sha1Hash, sha256Hash, prefix)
	bytesHashed, readErr := io.CopyBuffer(
		writer,
		contextReader{ctx: ctx, reader: file},
		make([]byte, contentHashBufferSize),
	)
	if readErr != nil {
		// Context cancellation is collector control flow, not a source-file
		// content failure. Propagate it so the surrounding bounded operation stops
		// rather than recording ContentReadFailed for intentional cancellation.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return contentReadObservation{}, ctxErr
		}
		return contentReadError("ContentReadFailed", readErr), nil
	}
	if err := validateContext(ctx); err != nil {
		return contentReadObservation{}, err
	}

	post, err := queryNativeState(handle)
	if err != nil {
		return contentReadError("ContentStateReadFailed", err), nil
	}
	if pre.ID != post.ID {
		return contentReadError("ObjectIdentityChangedDuringHash", ErrIdentityChanged), nil
	}
	if hashRelevantStateChanged(pre, post) {
		return contentReadError("ChangedDuringHash", errors.New("file metadata changed while content was being hashed")), nil
	}
	if err := proveHashContainment(root, handle); err != nil {
		return contentReadError("OutsideGovernedRoot", err), nil
	}

	value := contentReadObservation{
		Hashes: records.ContentHashObservation{
			State:       records.ContentHashPresent,
			BytesHashed: strconv.FormatInt(bytesHashed, 10),
			MD5:         hex.EncodeToString(md5Hash.Sum(nil)),
			SHA1:        hex.EncodeToString(sha1Hash.Sum(nil)),
			SHA256:      hex.EncodeToString(sha256Hash.Sum(nil)),
		},
		Prefix: records.ContentPrefixObservation{
			State:           records.ContentPrefixPresent,
			BytesObserved:   strconv.Itoa(len(prefix.value)),
			PrefixBase64URL: base64.RawURLEncoding.EncodeToString(prefix.value),
		},
	}
	if err := records.ValidateContentHashObservation(value.Hashes); err != nil {
		return contentReadObservation{}, err
	}
	if err := records.ValidateContentPrefixObservation(value.Prefix); err != nil {
		return contentReadObservation{}, err
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

func contentReadError(reason string, err error) contentReadObservation {
	detail := ""
	if err != nil {
		detail = err.Error()
	}
	return contentReadObservation{
		Hashes: records.ContentHashObservation{
			State:      records.ContentHashError,
			ReasonCode: reason,
			Detail:     detail,
		},
		Prefix: records.ContentPrefixObservation{
			State:      records.ContentPrefixError,
			ReasonCode: reason,
			Detail:     detail,
		},
	}
}

func contentHashError(reason string, err error) records.ContentHashObservation {
	return contentReadError(reason, err).Hashes
}
