// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package ntfs

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func TestWalkGovernedRootCollectsNestedTree(t *testing.T) {
	root := t.TempDir()
	levelOne := filepath.Join(root, "level-one")
	levelTwo := filepath.Join(levelOne, "level-two")

	if err := os.MkdirAll(levelTwo, 0o755); err != nil {
		t.Fatal(err)
	}

	rootFile := filepath.Join(root, "root.txt")
	levelOneFile := filepath.Join(levelOne, "one.txt")
	levelTwoFile := filepath.Join(levelTwo, "two.txt")
	if err := os.WriteFile(rootFile, []byte("root"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(levelOneFile, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(levelTwoFile, []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(levelTwoFile+`:payload`, []byte("hidden stream"), 0o600); err != nil {
		t.Fatal(err)
	}

	want := map[string]records.SubjectKind{
		filepath.Clean(root):         records.SubjectDirectory,
		filepath.Clean(levelOne):     records.SubjectDirectory,
		filepath.Clean(levelTwo):     records.SubjectDirectory,
		filepath.Clean(rootFile):     records.SubjectFile,
		filepath.Clean(levelOneFile): records.SubjectFile,
		filepath.Clean(levelTwoFile): records.SubjectFile,
	}
	got := make(map[string]records.SubjectKind)
	foundADS := false

	err := WalkGovernedRoot(
		context.Background(),
		"scope-walk-test",
		root,
		func(path string, observation Observation, objectErr error) error {
			if objectErr != nil {
				t.Errorf("walk %q: %v", path, objectErr)
				return nil
			}
			cleanPath := filepath.Clean(path)
			got[cleanPath] = observation.SubjectKind
			if cleanPath == filepath.Clean(levelTwoFile) {
				for _, stream := range observation.StreamInventory.Streams {
					if stream.Identity.Kind == records.StreamNamedData {
						foundADS = true
					}
				}
			}
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("walk returned %d objects, want %d: %+v", len(got), len(want), got)
	}
	for path, wantKind := range want {
		if got[path] != wantKind {
			t.Fatalf("subject kind for %q = %s, want %s", path, got[path], wantKind)
		}
	}
	if !foundADS {
		t.Fatal("nested file observation did not contain named data stream")
	}
}

func TestWalkGovernedRootPreservesIllFormedUTF16Path(t *testing.T) {
	root := t.TempDir()
	rootUnits, err := syscall.UTF16FromString(root)
	if err != nil {
		t.Fatal(err)
	}
	rootUnits = rootUnits[:len(rootUnits)-1]

	nameUnits := []uint16{'w', 'e', 'i', 'r', 'd', '-', 0xD800, '.', 't', 'x', 't'}
	fullPathUnits := append(append(append([]uint16(nil), rootUnits...), '\\'), nameUnits...)
	createRawUTF16File(t, append(append([]uint16(nil), fullPathUnits...), 0))

	found := false
	err = WalkGovernedRoot(
		context.Background(),
		"scope-wtf8-test",
		root,
		func(_ string, observation Observation, objectErr error) error {
			if objectErr != nil {
				return objectErr
			}
			requested, err := decodeUTF16LEBase64URLUnits(observation.PathBinding.RequestedPathUTF16LEBase64URL)
			if err != nil {
				return err
			}
			if equalUint16(requested, fullPathUnits) {
				found = true
			}
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("walker did not preserve the ill-formed UTF-16 filename exactly")
	}
}

func TestWalkGovernedRootReadsMultipleBatches(t *testing.T) {
	root := t.TempDir()
	const fileCount = walkDirectoryBatchSize*2 + 17

	for index := 0; index < fileCount; index++ {
		name := filepath.Join(root, fmt.Sprintf("file-%04d.txt", index))
		if err := os.WriteFile(name, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	seenFiles := 0
	err := WalkGovernedRoot(
		context.Background(),
		"scope-batch-test",
		root,
		func(_ string, observation Observation, objectErr error) error {
			if objectErr != nil {
				return objectErr
			}
			if observation.SubjectKind == records.SubjectFile {
				seenFiles++
			}
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if seenFiles != fileCount {
		t.Fatalf("walk saw %d files, want %d", seenFiles, fileCount)
	}
}

func TestWalkGovernedRootRejectsFileRoot(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "not-a-directory.txt")
	if err := os.WriteFile(file, []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := WalkGovernedRoot(
		context.Background(),
		"scope-walk-test",
		file,
		func(string, Observation, error) error { return nil },
	)
	if !errors.Is(err, ErrGovernedRootNotDirectory) {
		t.Fatalf("error = %v, want ErrGovernedRootNotDirectory", err)
	}
}

func TestWalkGovernedRootSkipsJunctionTarget(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	outsideFile := filepath.Join(outside, "SHOULD-NOT-BE-WALKED.txt")
	junction := filepath.Join(root, "escape")

	if err := os.WriteFile(outsideFile, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("cmd", "/c", "mklink", "/J", junction, outside).CombinedOutput(); err != nil {
		t.Fatalf("create junction: %v: %s", err, output)
	}

	seenJunction := false
	err := WalkGovernedRoot(
		context.Background(),
		"scope-walk-test",
		root,
		func(path string, observation Observation, objectErr error) error {
			if objectErr != nil {
				return objectErr
			}
			clean := filepath.Clean(path)
			if strings.HasPrefix(strings.ToLower(clean), strings.ToLower(filepath.Clean(junction))+`\`) {
				t.Fatalf("walker descended through junction: %q", path)
			}
			if strings.EqualFold(clean, filepath.Clean(junction)) {
				seenJunction = true
				if observation.Reparse.State != records.ReparseStatePresent ||
					observation.Reparse.Tag != "0xA0000003" {
					t.Fatalf("junction observation = %+v", observation.Reparse)
				}
			}
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !seenJunction {
		t.Fatal("walker did not observe the junction")
	}
}

func createRawUTF16File(t *testing.T, path []uint16) {
	t.Helper()
	if len(path) == 0 || path[len(path)-1] != 0 {
		t.Fatal("raw UTF-16 test path is not NUL terminated")
	}

	handle, err := syscall.CreateFile(
		&path[0],
		syscall.GENERIC_WRITE,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.CREATE_NEW,
		0x00000080,
		0,
	)
	if err != nil {
		t.Fatalf("CreateFileW raw UTF-16 name: %v", err)
	}
	if err := syscall.CloseHandle(handle); err != nil {
		t.Fatal(err)
	}
}

func decodeUTF16LEBase64URLUnits(value string) ([]uint16, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}
	units := make([]uint16, len(decoded)/2)
	for index := range units {
		units[index] = binary.LittleEndian.Uint16(decoded[index*2:])
	}
	return units, nil
}

func equalUint16(left []uint16, right []uint16) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
