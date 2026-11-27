// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package ntfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

func TestCollectOpenedTargetMatchesCollectPathIdentity(t *testing.T) {
	rootPath := t.TempDir()
	targetPath := filepath.Join(rootPath, "opened.txt")
	if err := os.WriteFile(targetPath, []byte("opened"), 0o600); err != nil {
		t.Fatal(err)
	}

	rootUnitsWithNUL, err := syscall.UTF16FromString(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	targetUnitsWithNUL, err := syscall.UTF16FromString(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	rootUnits := rootUnitsWithNUL[:len(rootUnitsWithNUL)-1]
	targetUnits := targetUnitsWithNUL[:len(targetUnitsWithNUL)-1]

	root, err := openGovernedRoot("opened-test", rootUnits)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(root.handle)

	handle, err := openPath(nulTerminate(targetUnits))
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(handle)

	openedObservation, err := collectOpenedTarget(context.Background(), root, CollectionEntryPath, targetUnits, handle, nil)
	if err != nil {
		t.Fatal(err)
	}
	pathObservation, err := CollectPath(context.Background(), "opened-test", rootPath, targetPath)
	if err != nil {
		t.Fatal(err)
	}

	if openedObservation.CollectionEntryMethod != CollectionEntryPath || pathObservation.CollectionEntryMethod != CollectionEntryPath {
		t.Fatalf("unexpected collection entry methods: opened=%q path=%q", openedObservation.CollectionEntryMethod, pathObservation.CollectionEntryMethod)
	}
	if !reflect.DeepEqual(openedObservation.ObjectIdentity, pathObservation.ObjectIdentity) {
		t.Fatalf("opened identity = %+v, path identity = %+v", openedObservation.ObjectIdentity, pathObservation.ObjectIdentity)
	}
	if !reflect.DeepEqual(openedObservation.ParentBinding, pathObservation.ParentBinding) {
		t.Fatalf("opened parent = %+v, path parent = %+v", openedObservation.ParentBinding, pathObservation.ParentBinding)
	}
}

func TestContextReaderStopsBeforeReadWhenCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	reader := contextReader{ctx: ctx, reader: bytes.NewBufferString("source-data")}
	buffer := make([]byte, 32)
	n, err := reader.Read(buffer)
	if n != 0 {
		t.Fatalf("read bytes = %d, want 0", n)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func TestApplyContentHashOutcomeMakesObservationPartial(t *testing.T) {
	observation := Observation{
		ObservationStatus: records.ObservationComplete,
	}
	hashes := records.ContentHashObservation{
		State:      records.ContentHashError,
		ReasonCode: "ContentOpenFailed",
		Detail:     "access denied",
	}

	applyContentHashOutcome(&observation, hashes)

	if observation.ObservationStatus != records.ObservationPartial {
		t.Fatalf("status = %q, want %q", observation.ObservationStatus, records.ObservationPartial)
	}
	if len(observation.Warnings) != 1 {
		t.Fatalf("warnings = %d, want 1", len(observation.Warnings))
	}
	if observation.Warnings[0].Code != "ContentHashFailed" {
		t.Fatalf("warning = %q, want ContentHashFailed", observation.Warnings[0].Code)
	}
}

func TestObservationConsistencyAcceptsContentHashFailureAsPartial(t *testing.T) {
	hashes := records.ContentHashObservation{
		State:      records.ContentHashError,
		ReasonCode: "ContentReadFailed",
	}
	observation := Observation{
		ObservationStatus: records.ObservationPartial,
		StreamInventory: records.StreamInventory{
			State: records.ObservationStatePresent,
		},
		Reparse: records.ReparseObservation{
			DataFormat: records.ReparseDataFormatNotApplicable,
			DataState:  records.ReparseDataStateNotApplicable,
			State:      records.ReparseStateNotPresent,
		},
		ContentHashes: &hashes,
		Warnings: []records.ObservationWarning{
			{Code: "ContentHashFailed"},
		},
	}

	if err := validateObservationConsistency(observation); err != nil {
		t.Fatal(err)
	}
}

func TestObservationConsistencyRejectsCompleteContentHashFailure(t *testing.T) {
	hashes := records.ContentHashObservation{
		State:      records.ContentHashError,
		ReasonCode: "ContentReadFailed",
	}
	observation := Observation{
		ObservationStatus: records.ObservationComplete,
		StreamInventory: records.StreamInventory{
			State: records.ObservationStatePresent,
		},
		Reparse: records.ReparseObservation{
			DataFormat: records.ReparseDataFormatNotApplicable,
			DataState:  records.ReparseDataStateNotApplicable,
			State:      records.ReparseStateNotPresent,
		},
		ContentHashes: &hashes,
		Warnings: []records.ObservationWarning{
			{Code: "ContentHashFailed"},
		},
	}

	if err := validateObservationConsistency(observation); err == nil {
		t.Fatal("expected Complete/hash-failure conflict")
	}
}

func TestCollectContentHashesKnownValues(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "abc.txt")
	if err := os.WriteFile(target, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	observation, err := CollectPath(context.Background(), "hash-test", root, target)
	if err != nil {
		t.Fatal(err)
	}
	hashes, err := CollectContentHashes(context.Background(), "hash-test", root, observation.ObjectIdentity, observation.SubjectKind)
	if err != nil {
		t.Fatal(err)
	}
	if hashes.State != records.ContentHashPresent || hashes.BytesHashed != "3" {
		t.Fatalf("hash state = %+v", hashes)
	}
	if hashes.MD5 != "900150983cd24fb0d6963f7d28e17f72" {
		t.Fatalf("md5 = %q", hashes.MD5)
	}
	if hashes.SHA1 != "a9993e364706816aba3e25717850c26c9cd0d89d" {
		t.Fatalf("sha1 = %q", hashes.SHA1)
	}
	if hashes.SHA256 != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("sha256 = %q", hashes.SHA256)
	}
}

func TestCollectContentHashesDirectoryNotApplicable(t *testing.T) {
	root := t.TempDir()
	observation, err := CollectPath(context.Background(), "hash-test", root, root)
	if err != nil {
		t.Fatal(err)
	}
	hashes, err := CollectContentHashes(context.Background(), "hash-test", root, observation.ObjectIdentity, observation.SubjectKind)
	if err != nil {
		t.Fatal(err)
	}
	if hashes.State != records.ContentHashNotApplicable {
		t.Fatalf("hash state = %+v", hashes)
	}
}

func TestComposeNTFSFileID(t *testing.T) {
	identity := records.NTFSObjectIdentity{
		MethodVersion:       IdentityMethodVersion,
		FileReferenceNumber: "144588",
		SequenceNumber:      "8",
	}
	got, err := composeNTFSFileID(identity)
	if err != nil {
		t.Fatal(err)
	}
	want := uint64(144588) | uint64(8)<<48
	if got != want {
		t.Fatalf("file ID = %#x, want %#x", got, want)
	}
}

func TestComposeNTFSFileIDRejectsOtherMethod(t *testing.T) {
	_, err := composeNTFSFileID(records.NTFSObjectIdentity{
		MethodVersion:       "other/1",
		FileReferenceNumber: "1",
		SequenceNumber:      "1",
	})
	if !errors.Is(err, ErrUnsupportedIdentityMethod) {
		t.Fatalf("error = %v, want ErrUnsupportedIdentityMethod", err)
	}
}

func TestOpenFileByObjectIdentityReturnsSameObject(t *testing.T) {
	rootPath := t.TempDir()
	targetPath := filepath.Join(rootPath, "object.txt")
	if err := os.WriteFile(targetPath, []byte("file id"), 0o600); err != nil {
		t.Fatal(err)
	}

	observation, err := CollectPath(context.Background(), "scope-test", rootPath, targetPath)
	if err != nil {
		t.Fatal(err)
	}

	rootUnits, err := syscall.UTF16FromString(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	root, err := openGovernedRoot("scope-test", rootUnits[:len(rootUnits)-1])
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(root.handle)

	handle, err := openFileByObjectIdentity(root.handle, observation.ObjectIdentity)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(handle)

	state, err := queryNativeState(handle)
	if err != nil {
		t.Fatal(err)
	}
	_, gotIdentity, err := buildObjectIdentity(state.ID.VolumeSerialNumber, state.ID.FileID)
	if err != nil {
		t.Fatal(err)
	}
	if gotIdentity != observation.ObjectIdentity {
		t.Fatalf("identity = %+v, want %+v", gotIdentity, observation.ObjectIdentity)
	}

	resolved, err := finalVolumePath(handle)
	if err != nil {
		t.Fatal(err)
	}
	if !pathContainedBy(root.finalPath, resolved) {
		t.Fatalf("ID-opened path is outside governed root")
	}
}

func TestFinalPathBufferLengthAcceptsBoundedLength(t *testing.T) {
	got, err := finalPathBufferLength(512)
	if err != nil {
		t.Fatal(err)
	}
	if got != 513 {
		t.Fatalf("size = %d, want 513", got)
	}

	got, err = finalPathBufferLength(maximumFinalPathUTF16Units - 1)
	if err != nil {
		t.Fatal(err)
	}
	if got != maximumFinalPathUTF16Units {
		t.Fatalf("size = %d, want %d", got, maximumFinalPathUTF16Units)
	}
}

func TestFinalPathBufferLengthRejectsCeiling(t *testing.T) {
	if _, err := finalPathBufferLength(maximumFinalPathUTF16Units); err == nil {
		t.Fatal("expected final-path allocation ceiling rejection")
	}
}

func FuzzParseStreamInfo(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, fileStreamInfoHeader))
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = func() error {
			_, err := parseStreamInfo(data)
			return err
		}()
	})
}

func FuzzParseReparseData(f *testing.F) {
	f.Add([]byte{})
	f.Add(testMountPointReparseData(`\??\C:\target`, `C:\target`))
	f.Add(testSymbolicLinkReparseData(`\??\C:\target`, `C:\target`, 0))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseReparseData(data)
	})
}

func TestCollectPathRecordsParentObjectBinding(t *testing.T) {
	root := t.TempDir()
	parentPath := filepath.Join(root, "parent")
	if err := os.Mkdir(parentPath, 0o700); err != nil {
		t.Fatal(err)
	}
	childPath := filepath.Join(parentPath, "child.txt")
	if err := os.WriteFile(childPath, []byte("child"), 0o600); err != nil {
		t.Fatal(err)
	}

	parentObservation, err := CollectPath(context.Background(), "parent-test", root, parentPath)
	if err != nil {
		t.Fatal(err)
	}
	childObservation, err := CollectPath(context.Background(), "parent-test", root, childPath)
	if err != nil {
		t.Fatal(err)
	}

	if childObservation.ParentBinding.State != records.ParentBindingPresent {
		t.Fatalf("parent binding state = %q, want %q", childObservation.ParentBinding.State, records.ParentBindingPresent)
	}
	if childObservation.ParentBinding.ObjectIdentity == nil {
		t.Fatal("parent binding omitted object identity")
	}
	if !reflect.DeepEqual(*childObservation.ParentBinding.ObjectIdentity, parentObservation.ObjectIdentity) {
		t.Fatalf("parent identity = %+v, want %+v", *childObservation.ParentBinding.ObjectIdentity, parentObservation.ObjectIdentity)
	}
}

func TestCollectPathGovernedRootParentBinding(t *testing.T) {
	root := t.TempDir()
	observation, err := CollectPath(context.Background(), "root-parent-test", root, root)
	if err != nil {
		t.Fatal(err)
	}
	if observation.ParentBinding.State != records.ParentBindingGovernedRoot {
		t.Fatalf("parent binding state = %q, want %q", observation.ParentBinding.State, records.ParentBindingGovernedRoot)
	}
	if observation.ParentBinding.ObjectIdentity != nil {
		t.Fatal("governed-root parent binding must not expose an object outside the governed scope")
	}
}

func TestDirectParentVolumePath(t *testing.T) {
	path := asciiUTF16(`\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\one\two`)
	got, err := directParentVolumePath(path)
	if err != nil {
		t.Fatal(err)
	}
	want := `\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\one`
	if stringFromASCIIUTF16(got) != want {
		t.Fatalf("parent = %q, want %q", stringFromASCIIUTF16(got), want)
	}
}

const benchmarkScopeID = "benchmark"

func BenchmarkCollectPathPlainFile(b *testing.B) {
	root := b.TempDir()
	target := filepath.Join(root, "plain.bin")
	if err := os.WriteFile(target, []byte("fi benchmark"), 0o600); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := CollectPath(context.Background(), benchmarkScopeID, root, target); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCollectPathADSHeavy(b *testing.B) {
	root := b.TempDir()
	target := filepath.Join(root, "ads-heavy.bin")
	if err := os.WriteFile(target, []byte("fi benchmark"), 0o600); err != nil {
		b.Fatal(err)
	}
	createBenchmarkADS(b, target, 32)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := CollectPath(context.Background(), benchmarkScopeID, root, target); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkQueryNativeState(b *testing.B) {
	root := b.TempDir()
	target := filepath.Join(root, "state.bin")
	if err := os.WriteFile(target, []byte("fi benchmark"), 0o600); err != nil {
		b.Fatal(err)
	}

	handle := openBenchmarkHandle(b, target)
	defer syscall.CloseHandle(handle)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := queryNativeState(handle); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkQueryStreamsDefaultOnly(b *testing.B) {
	root := b.TempDir()
	target := filepath.Join(root, "streams.bin")
	if err := os.WriteFile(target, []byte("fi benchmark"), 0o600); err != nil {
		b.Fatal(err)
	}

	handle := openBenchmarkHandle(b, target)
	defer syscall.CloseHandle(handle)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := queryStreams(handle); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkQueryStreamsADSHeavy(b *testing.B) {
	root := b.TempDir()
	target := filepath.Join(root, "streams-ads.bin")
	if err := os.WriteFile(target, []byte("fi benchmark"), 0o600); err != nil {
		b.Fatal(err)
	}
	createBenchmarkADS(b, target, 32)

	handle := openBenchmarkHandle(b, target)
	defer syscall.CloseHandle(handle)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := queryStreams(handle); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCollectPathSiblingEscape(b *testing.B) {
	parent := b.TempDir()
	root := filepath.Join(parent, "governed")
	sibling := filepath.Join(parent, "sibling")
	if err := os.Mkdir(root, 0o700); err != nil {
		b.Fatal(err)
	}
	if err := os.Mkdir(sibling, 0o700); err != nil {
		b.Fatal(err)
	}
	target := filepath.Join(sibling, "outside.bin")
	if err := os.WriteFile(target, []byte("outside"), 0o600); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := CollectPath(context.Background(), benchmarkScopeID, root, target); err == nil {
			b.Fatal("expected governed-root rejection")
		}
	}
}

func BenchmarkWalkGovernedRoot1000Files(b *testing.B) {
	root := b.TempDir()
	const directoryCount = 10
	const filesPerDirectory = 100
	const expectedObjects = 1 + directoryCount + directoryCount*filesPerDirectory

	for directoryIndex := 0; directoryIndex < directoryCount; directoryIndex++ {
		directory := filepath.Join(root, fmt.Sprintf("d-%02d", directoryIndex))
		if err := os.Mkdir(directory, 0o700); err != nil {
			b.Fatal(err)
		}
		for fileIndex := 0; fileIndex < filesPerDirectory; fileIndex++ {
			path := filepath.Join(directory, fmt.Sprintf("f-%03d.bin", fileIndex))
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				b.Fatal(err)
			}
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		observed := 0
		err := WalkGovernedRoot(
			context.Background(),
			benchmarkScopeID,
			root,
			func(_ string, _ Observation, objectErr error) error {
				if objectErr != nil {
					return objectErr
				}
				observed++
				return nil
			},
		)
		if err != nil {
			b.Fatal(err)
		}
		if observed != expectedObjects {
			b.Fatalf("observed %d objects, expected %d", observed, expectedObjects)
		}
	}
	elapsed := time.Since(start)
	b.StopTimer()

	b.ReportMetric(expectedObjects, "objects/op")
	if elapsed > 0 {
		b.ReportMetric(float64(expectedObjects*b.N)/elapsed.Seconds(), "objects/s")
	}
}

func createBenchmarkADS(b *testing.B, target string, count int) {
	b.Helper()
	for i := 0; i < count; i++ {
		streamPath := target + ":" + fmt.Sprintf("ads-%02d", i)
		if err := os.WriteFile(streamPath, []byte("x"), 0o600); err != nil {
			b.Fatalf("create ADS %d: %v", i, err)
		}
	}
}

func openBenchmarkHandle(b *testing.B, path string) syscall.Handle {
	b.Helper()
	units, err := syscall.UTF16FromString(path)
	if err != nil {
		b.Fatal(err)
	}
	handle, err := openPath(units)
	if err != nil {
		b.Fatal(err)
	}
	return handle
}

func TestCollectOpenedTargetWithContentHashesMarksPathReplacement(t *testing.T) {
	rootPath := t.TempDir()
	targetPath := filepath.Join(rootPath, "target.txt")
	movedPath := filepath.Join(rootPath, "original-moved.txt")

	const originalContent = "original-content"
	const replacementContent = "replacement-content"
	const originalSHA256 = "09757dab1d4c65e1bee3b4a452d1e8e45e1b28a2ff76de694be6b0c97e7e7d49"

	if err := os.WriteFile(targetPath, []byte(originalContent), 0o600); err != nil {
		t.Fatal(err)
	}

	rootUnits := testPathUnits(t, rootPath)
	targetUnits := testPathUnits(t, targetPath)

	root, err := openGovernedRoot("consistency-path-replacement", rootUnits)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(root.handle)

	targetHandle, err := openPath(nulTerminate(targetUnits))
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(targetHandle)

	originalState, err := queryNativeState(targetHandle)
	if err != nil {
		t.Fatal(err)
	}
	_, originalIdentity, err := buildObjectIdentity(
		originalState.ID.VolumeSerialNumber,
		originalState.ID.FileID,
	)
	if err != nil {
		t.Fatal(err)
	}

	// This recreates the exact namespace state FI can encounter if the path is
	// replaced immediately after CreateFileW returned the original handle.
	if err := os.Rename(targetPath, movedPath); err != nil {
		t.Skipf("environment would not rename open NTFS file: %v", err)
	}
	if err := os.WriteFile(targetPath, []byte(replacementContent), 0o600); err != nil {
		t.Fatal(err)
	}

	observation, err := collectOpenedTargetWithContentHashes(
		context.Background(),
		root,
		CollectionEntryPath,
		targetUnits,
		targetHandle,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	if observation.ObservationStatus != records.ObservationReplacedDuringCollection {
		t.Fatalf(
			"status = %q, want %q",
			observation.ObservationStatus,
			records.ObservationReplacedDuringCollection,
		)
	}
	if observation.ObjectIdentity != originalIdentity {
		t.Fatalf(
			"observed identity = %+v, want original %+v",
			observation.ObjectIdentity,
			originalIdentity,
		)
	}

	foundReplacementWarning := false
	for _, warning := range observation.Warnings {
		if warning.Code == "PathNowReferencesDifferentObject" {
			foundReplacementWarning = true
			break
		}
	}
	if !foundReplacementWarning {
		t.Fatal("replacement observation omitted PathNowReferencesDifferentObject")
	}

	if observation.ContentHashes == nil {
		t.Fatal("replacement observation omitted integrated content hashes")
	}
	if observation.ContentHashes.State != records.ContentHashPresent {
		t.Fatalf("hash state = %q", observation.ContentHashes.State)
	}
	if observation.ContentHashes.SHA256 != originalSHA256 {
		t.Fatalf(
			"sha256 = %q, want original-object hash %q",
			observation.ContentHashes.SHA256,
			originalSHA256,
		)
	}

	replacement, err := CollectPath(
		context.Background(),
		"consistency-path-replacement",
		rootPath,
		targetPath,
	)
	if err != nil {
		t.Fatal(err)
	}
	if replacement.ObjectIdentity == originalIdentity {
		t.Fatal("replacement pathname unexpectedly has the original NTFS identity")
	}
	if replacement.ContentHashes == nil ||
		replacement.ContentHashes.State != records.ContentHashPresent ||
		replacement.ContentHashes.SHA256 == originalSHA256 {
		t.Fatalf("replacement content observation = %+v", replacement.ContentHashes)
	}
}

func TestRevalidateObservationAfterContentDowngradesMetadataChange(t *testing.T) {
	rootPath := t.TempDir()
	targetPath := filepath.Join(rootPath, "target.txt")

	if err := os.WriteFile(targetPath, []byte("before"), 0o600); err != nil {
		t.Fatal(err)
	}

	rootUnits := testPathUnits(t, rootPath)
	targetUnits := testPathUnits(t, targetPath)

	root, err := openGovernedRoot("consistency-post-content", rootUnits)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(root.handle)

	targetHandle, err := openPath(nulTerminate(targetUnits))
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(targetHandle)

	initialState, err := queryNativeState(targetHandle)
	if err != nil {
		t.Fatal(err)
	}
	_, objectIdentity, err := buildObjectIdentity(
		initialState.ID.VolumeSerialNumber,
		initialState.ID.FileID,
	)
	if err != nil {
		t.Fatal(err)
	}
	metadata, subjectKind, err := metadataFromState(initialState)
	if err != nil {
		t.Fatal(err)
	}
	initialPath, err := finalVolumePath(targetHandle)
	if err != nil {
		t.Fatal(err)
	}

	observation := Observation{
		ObjectIdentity: objectIdentity,
		Metadata:       metadata,
		SubjectKind:    subjectKind,
		Reparse:        reparseObservationNotPresent(),
		PathBinding: records.PathBinding{
			ResolvedPathUTF16LEBase64URL: utf16LEBase64URL(initialPath),
		},
		ObservationStatus: records.ObservationComplete,
		Warnings:          []records.ObservationWarning{},
	}

	// A size-changing write is deliberately used so the consistency signal does
	// not depend on filesystem timestamp granularity.
	if err := os.WriteFile(
		targetPath,
		[]byte("after-content-change-with-different-size"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	if err := revalidateObservationAfterContent(
		context.Background(),
		root,
		targetHandle,
		&observation,
	); err != nil {
		t.Fatal(err)
	}

	if observation.ObservationStatus != records.ObservationChangedDuringCollection {
		t.Fatalf(
			"status = %q, want %q",
			observation.ObservationStatus,
			records.ObservationChangedDuringCollection,
		)
	}

	found := false
	for _, warning := range observation.Warnings {
		if warning.Code == "MetadataChangedDuringCollection" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("post-content mutation omitted MetadataChangedDuringCollection")
	}
}

func TestRevalidateScopeHandlesRejectsTargetMovedOutsideRoot(t *testing.T) {
	parent := t.TempDir()
	rootPath := filepath.Join(parent, "governed")
	outsidePath := filepath.Join(parent, "outside")

	if err := os.Mkdir(rootPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outsidePath, 0o700); err != nil {
		t.Fatal(err)
	}

	targetPath := filepath.Join(rootPath, "target.txt")
	movedTargetPath := filepath.Join(outsidePath, "target.txt")
	if err := os.WriteFile(targetPath, []byte("scope"), 0o600); err != nil {
		t.Fatal(err)
	}

	rootUnits := testPathUnits(t, rootPath)
	targetUnits := testPathUnits(t, targetPath)

	rootHandle, err := openPath(nulTerminate(rootUnits))
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(rootHandle)

	targetHandle, err := openPath(nulTerminate(targetUnits))
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(targetHandle)

	rootState, err := queryNativeState(rootHandle)
	if err != nil {
		t.Fatal(err)
	}
	targetState, err := queryNativeState(targetHandle)
	if err != nil {
		t.Fatal(err)
	}
	rootFinalPath, err := finalVolumePath(rootHandle)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := revalidateScopeHandles(
		rootHandle,
		targetHandle,
		rootUnits,
		rootFinalPath,
		rootState.ID,
		targetState.ID,
	); err != nil {
		t.Fatalf("baseline revalidation failed: %v", err)
	}

	if err := os.Rename(targetPath, movedTargetPath); err != nil {
		t.Skipf("environment would not move open NTFS file: %v", err)
	}

	_, err = revalidateScopeHandles(
		rootHandle,
		targetHandle,
		rootUnits,
		rootFinalPath,
		rootState.ID,
		targetState.ID,
	)
	if !errors.Is(err, ErrOutsideGovernedRoot) {
		t.Fatalf("error = %v, want ErrOutsideGovernedRoot", err)
	}
}
func TestObservationRelevantNativeStateChangedIgnoresLastAccessTime(t *testing.T) {
	state := nativeState{}
	metadata, subjectKind, err := metadataFromState(state)
	if err != nil {
		t.Fatal(err)
	}
	observation := Observation{Metadata: metadata, SubjectKind: subjectKind}

	state.Basic.LastAccessTime = 123456789
	changed, err := observationRelevantNativeStateChanged(observation, state)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("LastAccessTime-only change must not invalidate content-read consistency")
	}
}

func TestObservationRelevantNativeStateChangedDetectsLastWriteTime(t *testing.T) {
	state := nativeState{}
	metadata, subjectKind, err := metadataFromState(state)
	if err != nil {
		t.Fatal(err)
	}
	observation := Observation{Metadata: metadata, SubjectKind: subjectKind}

	state.Basic.LastWriteTime = 123456789
	changed, err := observationRelevantNativeStateChanged(observation, state)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("LastWriteTime change must be detected")
	}
}

func TestReparseObservationChangedDetectsStateAndTagChanges(t *testing.T) {
	if reparseObservationChanged(reparseObservationNotPresent(), fileAttributeTagInfo{}) {
		t.Fatal("not-present reparse state changed unexpectedly")
	}
	if !reparseObservationChanged(
		reparseObservationNotPresent(),
		fileAttributeTagInfo{FileAttributes: fileAttributeReparse, ReparseTag: reparseTagSymlink},
	) {
		t.Fatal("new reparse state was not detected")
	}

	present := records.ReparseObservation{
		State: records.ReparseStatePresent,
		Tag:   reparseTagString(reparseTagSymlink),
	}
	if reparseObservationChanged(
		present,
		fileAttributeTagInfo{FileAttributes: fileAttributeReparse, ReparseTag: reparseTagSymlink},
	) {
		t.Fatal("matching reparse state changed unexpectedly")
	}
	if !reparseObservationChanged(
		present,
		fileAttributeTagInfo{FileAttributes: fileAttributeReparse, ReparseTag: reparseTagMountPoint},
	) {
		t.Fatal("reparse tag change was not detected")
	}
}

func TestRevalidateScopeHandlesRejectsRootReplacement(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "governed")
	moved := filepath.Join(parent, "moved")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target.txt")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	rootUnits := testPathUnits(t, root)
	targetUnits := testPathUnits(t, target)
	rootHandle, err := openPath(nulTerminate(rootUnits))
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(rootHandle)
	targetHandle, err := openPath(nulTerminate(targetUnits))
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(targetHandle)

	rootState, err := queryNativeState(rootHandle)
	if err != nil {
		t.Fatal(err)
	}
	targetState, err := queryNativeState(targetHandle)
	if err != nil {
		t.Fatal(err)
	}
	rootFinal, err := finalVolumePath(rootHandle)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := revalidateScopeHandles(rootHandle, targetHandle, rootUnits, rootFinal, rootState.ID, targetState.ID); err != nil {
		t.Fatalf("baseline revalidation failed: %v", err)
	}

	if err := os.Rename(root, moved); err != nil {
		t.Skipf("environment would not rename open NTFS directory: %v", err)
	}
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}

	_, err = revalidateScopeHandles(rootHandle, targetHandle, rootUnits, rootFinal, rootState.ID, targetState.ID)
	if !errors.Is(err, ErrGovernedRootChangedDuringCollection) && !errors.Is(err, ErrOutsideGovernedRoot) {
		t.Fatalf("error = %v, want governed-root change or outside-root rejection", err)
	}
}

func TestVerifyWalkDirectoryIdentityRejectsPathReplacement(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "governed")
	moved := filepath.Join(parent, "moved")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}

	observation, err := CollectPath(nil, "scope-walk-race", root, root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(root, moved); err != nil {
		t.Skipf("environment would not rename NTFS directory: %v", err)
	}
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}

	directory, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	if err := verifyWalkDirectoryIdentity(directory, observation); !errors.Is(err, ErrWalkDirectoryChanged) {
		t.Fatalf("error = %v, want ErrWalkDirectoryChanged", err)
	}
}

func testPathUnits(t *testing.T, value string) []uint16 {
	t.Helper()
	units, err := syscall.UTF16FromString(value)
	if err != nil {
		t.Fatal(err)
	}
	return units[:len(units)-1]
}

// Server 2016 regression: FI must be able to collect a directory security
// descriptor through the production OpenFileById path. ReOpenFile(READ_CONTROL)
// was proven to fail with Access Denied for directory handles on the target
// Server 2016 environment.
func TestDirectorySecurityDescriptorOpenByID(t *testing.T) {
	path := t.TempDir()

	units, err := syscall.UTF16FromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := openPath(units)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(handle)

	raw, err := querySecurityDescriptor(handle)
	if err != nil {
		t.Fatal(err)
	}

	observation, err := records.ParseSecurityDescriptor(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := records.ValidateSecurityObservation(observation); err != nil {
		t.Fatal(err)
	}
	if observation.OwnerSID == "" {
		t.Fatal("expected owner SID")
	}
	if observation.DACL.State == "" {
		t.Fatal("expected DACL state")
	}
}

// Server 2016 regression: with SeSecurityPrivilege available, FI must be able
// to collect a directory SACL through the production OpenFileById path.
func TestDirectorySACLDescriptorOpenByID(t *testing.T) {
	path := t.TempDir()
	rootUnits, err := syscall.UTF16FromString(path)
	if err != nil {
		t.Fatal(err)
	}
	root, err := openGovernedRoot(
		"sacl-broker-directory-test",
		rootUnits[:len(rootUnits)-1],
	)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(root.handle)

	identity, err := securityObjectIdentity(root.handle)
	if err != nil {
		t.Fatal(err)
	}
	wantFileReferenceNumber, err := strconv.ParseUint(identity.FileReferenceNumber, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	wantSequenceNumber, err := strconv.ParseUint(identity.SequenceNumber, 10, 16)
	if err != nil {
		t.Fatal(err)
	}

	wantRaw := []byte{1, 2, 3, 4}
	reader := func(
		ctx context.Context,
		governedRoot string,
		fileReferenceNumber uint64,
		sequenceNumber uint16,
	) ([]byte, error) {
		if ctx == nil {
			t.Fatal("broker SACL reader received a nil context")
		}
		if governedRoot != path {
			t.Fatalf("governed root = %q, want %q", governedRoot, path)
		}
		if fileReferenceNumber != wantFileReferenceNumber {
			t.Fatalf("file reference = %d, want %d", fileReferenceNumber, wantFileReferenceNumber)
		}
		if sequenceNumber != uint16(wantSequenceNumber) {
			t.Fatalf("sequence = %d, want %d", sequenceNumber, uint16(wantSequenceNumber))
		}
		return append([]byte(nil), wantRaw...), nil
	}

	raw, err := querySACLDescriptorWithReader(
		context.Background(),
		root,
		root.handle,
		reader,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, wantRaw) {
		t.Fatalf("raw SACL = %v, want %v", raw, wantRaw)
	}
}

const (
	writeDAC                   = 0x00040000
	seFileObject               = 1
	protectedDACLInformation   = 0x80000000
	objectInheritACE           = 0x01
	inheritOnlyACE             = 0x08
	inheritedACE               = 0x10
	unprotectedDACLInformation = 0x20000000
	fileReadDataMask           = 0x00000001
	fileWriteDataMask          = 0x00000002
	readControlMask            = 0x00020000
	fileAllAccessMask          = 0x001F01FF
)

var procSetSecurityInfoForTest = securityAdvapi32.NewProc("SetSecurityInfo")

func TestSecurityNativeDenyACE(t *testing.T) {
	handle, cleanup := createSecurityTestFile(t)
	defer cleanup()

	everyone := nativeTestSID(1, 0)
	deny := nativeTestSimpleACE(0x01, 0, fileWriteDataMask, everyone)
	allow := nativeTestSimpleACE(0x00, 0, readControlMask|fileReadDataMask, everyone)

	if err := setNativeTestDACL(handle, nativeTestACL(deny, allow)); err != nil {
		t.Fatal(err)
	}

	// Query through the handle opened before the DACL change. This test is about
	// preserving the native deny ACE, its order, mask, SID, and raw bytes; it is
	// not a second test of ReOpenFile authorization.
	observation := queryAndParseSecurityFromOpenHandle(t, handle)
	if observation.DACL.State != records.ACLStatePresent || len(observation.DACL.ACEs) != 2 {
		t.Fatalf("DACL = %#v", observation.DACL)
	}

	denyACE := observation.DACL.ACEs[0]
	if denyACE.TypeName != "AccessDenied" || denyACE.Mask != "2" || denyACE.SID != "S-1-1-0" {
		t.Fatalf("deny ACE = %#v", denyACE)
	}
	if denyACE.RawBase64URL == "" {
		t.Fatal("deny ACE raw bytes were not preserved")
	}

	allowACE := observation.DACL.ACEs[1]
	if allowACE.TypeName != "AccessAllowed" || allowACE.Mask != "131073" || allowACE.SID != "S-1-1-0" {
		t.Fatalf("allow ACE = %#v", allowACE)
	}
}

func TestSecurityNativeInheritedACE(t *testing.T) {
	parentHandle, directory, cleanup := createSecurityInheritanceParent(t)
	defer cleanup()

	everyone := nativeTestSID(1, 0)

	// Keep the parent usable for child creation with one explicit parent-only ACE.
	parentAllow := nativeTestSimpleACE(0x00, 0, fileAllAccessMask, everyone)
	// This ACE is not effective on the parent. It exists only to be inherited by
	// file children. Windows must set INHERITED_ACE on the child's copy.
	inheritable := nativeTestSimpleACE(0x00, objectInheritACE|inheritOnlyACE, fileAllAccessMask, everyone)
	if err := setNativeTestDACL(parentHandle, nativeTestACL(parentAllow, inheritable)); err != nil {
		t.Fatal(err)
	}

	childPath := filepath.Join(directory, "child.txt")
	if err := os.WriteFile(childPath, []byte("fi"), 0o600); err != nil {
		t.Fatal(err)
	}

	childUnits, err := syscall.UTF16FromString(childPath)
	if err != nil {
		t.Fatal(err)
	}
	childHandle, err := syscall.CreateFile(
		&childUnits[0],
		readControl|writeDAC,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = setNativeTestDACL(childHandle, nil)
		_ = syscall.CloseHandle(childHandle)
	}()

	observation := queryAndParseSecurityFromOpenHandle(t, childHandle)
	if observation.DACL.State != records.ACLStatePresent {
		t.Fatalf("DACL state = %q", observation.DACL.State)
	}

	found := false
	for _, ace := range observation.DACL.ACEs {
		flags, err := strconv.ParseUint(ace.Flags, 10, 8)
		if err != nil {
			t.Fatalf("ACE flags %q: %v", ace.Flags, err)
		}
		if ace.TypeName == "AccessAllowed" &&
			ace.Mask == "2032127" &&
			ace.SID == "S-1-1-0" &&
			byte(flags)&inheritedACE != 0 {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("no Windows-inherited ACE found in %#v", observation.DACL.ACEs)
	}
}

func TestSecurityNativeEmptyDACL(t *testing.T) {
	handle, cleanup := createSecurityTestFile(t)
	defer cleanup()

	if err := setNativeTestDACL(handle, nativeTestACL()); err != nil {
		t.Fatal(err)
	}

	// An empty DACL denies all new access. Query the descriptor through the
	// already-open test handle, whose READ_CONTROL access was granted before the
	// empty DACL was installed. Reopening with READ_CONTROL is intentionally not
	// required for this semantic test.
	observation := queryAndParseSecurityFromOpenHandle(t, handle)
	if observation.DACL.State != records.ACLStatePresent {
		t.Fatalf("DACL state = %q", observation.DACL.State)
	}
	if observation.DACL.Size != "8" || len(observation.DACL.ACEs) != 0 {
		t.Fatalf("empty DACL = %#v", observation.DACL)
	}
}

func TestSecurityNativeNullDACL(t *testing.T) {
	handle, cleanup := createSecurityTestFile(t)
	defer cleanup()

	if err := setNativeTestDACL(handle, nil); err != nil {
		t.Fatal(err)
	}
	observation := queryAndParseSecurity(t, handle)
	if observation.DACL.State != records.ACLStateNull {
		t.Fatalf("DACL state = %q", observation.DACL.State)
	}
	if observation.DACL.Revision != "" || observation.DACL.Size != "" || len(observation.DACL.ACEs) != 0 {
		t.Fatalf("NULL DACL contains ACL fields: %#v", observation.DACL)
	}
}

func queryAndParseSecurity(t *testing.T, handle syscall.Handle) records.SecurityObservation {
	t.Helper()
	raw, err := querySecurityDescriptor(handle)
	if err != nil {
		t.Fatal(err)
	}
	return parseAndValidateSecurity(t, raw)
}

func queryAndParseSecurityFromOpenHandle(t *testing.T, handle syscall.Handle) records.SecurityObservation {
	t.Helper()
	raw, err := querySecurityDescriptorFromOpenHandle(handle)
	if err != nil {
		t.Fatal(err)
	}
	return parseAndValidateSecurity(t, raw)
}

func parseAndValidateSecurity(t *testing.T, raw []byte) records.SecurityObservation {
	t.Helper()
	observation, err := records.ParseSecurityDescriptor(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := records.ValidateSecurityObservation(observation); err != nil {
		t.Fatal(err)
	}
	return observation
}

// querySecurityDescriptorFromOpenHandle is test-only. It uses the rights that
// were granted when createSecurityTestFile opened the handle, allowing the test
// to inspect an empty DACL after that DACL prevents all new opens.
func querySecurityDescriptorFromOpenHandle(handle syscall.Handle) ([]byte, error) {
	requested := uintptr(ownerSecurityInformation | groupSecurityInformation | daclSecurityInformation)
	var needed uint32
	result, _, callErr := procGetKernelObjectSecurity.Call(
		uintptr(handle),
		requested,
		0,
		0,
		uintptr(unsafe.Pointer(&needed)),
	)
	if result != 0 && needed == 0 {
		return nil, syscall.EINVAL
	}
	if needed == 0 {
		return nil, windowsCallError("GetKernelObjectSecurity(size)", callErr)
	}
	if needed > maximumSecurityDescriptorBuffer {
		return nil, syscall.ENOMEM
	}

	buffer := make([]byte, needed)
	result, _, callErr = procGetKernelObjectSecurity.Call(
		uintptr(handle),
		requested,
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
		uintptr(unsafe.Pointer(&needed)),
	)
	if result == 0 {
		return nil, windowsCallError("GetKernelObjectSecurity", callErr)
	}
	if needed == 0 || int(needed) > len(buffer) {
		return nil, syscall.EINVAL
	}
	return append([]byte(nil), buffer[:needed]...), nil
}

func createSecurityInheritanceParent(t *testing.T) (syscall.Handle, string, func()) {
	t.Helper()

	directory, err := os.MkdirTemp("", "fi-security-inheritance-*")
	if err != nil {
		t.Fatal(err)
	}

	parentUnits, err := syscall.UTF16FromString(directory)
	if err != nil {
		os.RemoveAll(directory)
		t.Fatal(err)
	}
	parentHandle, err := syscall.CreateFile(
		&parentUnits[0],
		readControl|writeDAC,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		os.RemoveAll(directory)
		t.Fatal(err)
	}

	cleanup := func() {
		// Restore a NULL DACL through the original handle so cleanup does not depend
		// on whatever ACL shape the test installed.
		_ = setNativeTestDACL(parentHandle, nil)
		_ = syscall.CloseHandle(parentHandle)
		_ = os.RemoveAll(directory)
	}
	return parentHandle, directory, cleanup
}

func createSecurityTestFile(t *testing.T) (syscall.Handle, func()) {
	t.Helper()
	file, err := os.CreateTemp("", "fi-security-hardening-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	path := file.Name()
	if err := file.Close(); err != nil {
		os.Remove(path)
		t.Fatal(err)
	}

	units, err := syscall.UTF16FromString(path)
	if err != nil {
		os.Remove(path)
		t.Fatal(err)
	}
	handle, err := syscall.CreateFile(
		&units[0],
		readControl|writeDAC,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		os.Remove(path)
		t.Fatal(err)
	}

	cleanup := func() {
		// A NULL DACL restores unrestricted DACL access before cleanup even when
		// the test deliberately installed an empty/denying DACL.
		_ = setNativeTestDACL(handle, nil)
		_ = syscall.CloseHandle(handle)
		_ = os.Remove(path)
	}
	return handle, cleanup
}

func setNativeTestDACL(handle syscall.Handle, acl []byte) error {
	return setNativeTestDACLWithInformation(
		handle,
		acl,
		daclSecurityInformation|protectedDACLInformation,
	)
}

func setNativeTestDACLWithInformation(handle syscall.Handle, acl []byte, information uint32) error {
	var aclPointer uintptr
	if len(acl) != 0 {
		aclPointer = uintptr(unsafe.Pointer(&acl[0]))
	}
	result, _, _ := procSetSecurityInfoForTest.Call(
		uintptr(handle),
		seFileObject,
		uintptr(information),
		0,
		0,
		aclPointer,
		0,
	)
	runtime.KeepAlive(acl)
	if result != 0 {
		return syscall.Errno(result)
	}
	return nil
}

func nativeTestACL(aces ...[]byte) []byte {
	size := 8
	for _, ace := range aces {
		size += len(ace)
	}
	acl := make([]byte, size)
	acl[0] = 2
	binary.LittleEndian.PutUint16(acl[2:4], uint16(size))
	binary.LittleEndian.PutUint16(acl[4:6], uint16(len(aces)))
	cursor := 8
	for _, ace := range aces {
		copy(acl[cursor:], ace)
		cursor += len(ace)
	}
	return acl
}

func nativeTestSimpleACE(aceType byte, flags byte, mask uint32, sid []byte) []byte {
	ace := make([]byte, 8+len(sid))
	ace[0] = aceType
	ace[1] = flags
	binary.LittleEndian.PutUint16(ace[2:4], uint16(len(ace)))
	binary.LittleEndian.PutUint32(ace[4:8], mask)
	copy(ace[8:], sid)
	return ace
}

func nativeTestSID(authority uint64, subAuthorities ...uint32) []byte {
	sid := make([]byte, 8+len(subAuthorities)*4)
	sid[0] = 1
	sid[1] = byte(len(subAuthorities))
	for index := 0; index < 6; index++ {
		shift := uint((5 - index) * 8)
		sid[2+index] = byte(authority >> shift)
	}
	for index, subAuthority := range subAuthorities {
		start := 8 + index*4
		binary.LittleEndian.PutUint32(sid[start:start+4], subAuthority)
	}
	return sid
}

func TestSecuritySACLBrokerReadFailure(t *testing.T) {
	rootPath := t.TempDir()
	path := filepath.Join(rootPath, "sacl.txt")
	if err := os.WriteFile(path, []byte("fi"), 0o600); err != nil {
		t.Fatal(err)
	}

	rootUnits, err := syscall.UTF16FromString(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	root, err := openGovernedRoot(
		"sacl-broker-failure-test",
		rootUnits[:len(rootUnits)-1],
	)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(root.handle)

	targetUnits, err := syscall.UTF16FromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := openPath(targetUnits)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(handle)

	reader := func(
		context.Context,
		string,
		uint64,
		uint16,
	) ([]byte, error) {
		return nil, syscall.ERROR_ACCESS_DENIED
	}

	_, err = querySACLDescriptorWithReader(
		context.Background(),
		root,
		handle,
		reader,
	)
	if err == nil {
		t.Fatal("expected broker SACL read failure")
	}
	if got := saclQueryReasonCode(err); got != saclDescriptorReadFailed {
		t.Fatalf("reason code = %q, want %q", got, saclDescriptorReadFailed)
	}
}

func TestSACLQueryReasonCodeDefaultsToReadFailure(t *testing.T) {
	if got := saclQueryReasonCode(syscall.EINVAL); got != saclDescriptorReadFailed {
		t.Fatalf("reason code = %q", got)
	}
}

func TestQuerySecurityDescriptorFromExistingHandle(t *testing.T) {
	file, err := os.CreateTemp("", "fi-security-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	path := file.Name()
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(path)

	units, err := syscall.UTF16FromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := openPath(units)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(handle)

	raw, err := querySecurityDescriptor(handle)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := records.ParseSecurityDescriptor(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := records.ValidateSecurityObservation(observation); err != nil {
		t.Fatal(err)
	}
	if observation.OwnerSID == "" {
		t.Fatal("expected owner SID")
	}
	if observation.DACL.State == "" {
		t.Fatal("expected DACL state")
	}
}

// NextEntryOffset must never point into the current variable-length stream name.
func TestParseStreamInfoRejectsOffsetInsideName(t *testing.T) {
	buffer := make([]byte, 64)

	// Header is 24 bytes and the name is 20 bytes, so the next entry cannot
	// begin before align8(44) == 48.
	binary.LittleEndian.PutUint32(buffer[0:4], 24)
	binary.LittleEndian.PutUint32(buffer[4:8], 20)

	_, err := parseStreamInfo(buffer)
	if !errors.Is(err, ErrMalformedStreamInfo) {
		t.Fatalf("error = %v, want ErrMalformedStreamInfo", err)
	}
}
