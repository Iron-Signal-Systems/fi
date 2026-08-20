// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package ntfs

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func TestCollectPathDirectorySymlinkReparse(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	link := filepath.Join(root, "directory-link")

	if output, err := exec.Command("cmd", "/c", "mklink", "/D", link, outside).CombinedOutput(); err != nil {
		t.Skipf("directory symlink unavailable: %v: %s", err, output)
	}

	observation, err := CollectPath(context.Background(), "scope-reparse-test", root, link)
	if err != nil {
		t.Fatal(err)
	}

	assertReparseObservation(
		t,
		observation,
		records.SubjectDirectory,
		records.ReparseDataFormatSymbolicLink,
		"0xA000000C",
		"IO_REPARSE_TAG_SYMLINK",
		outside,
	)
	if observation.Reparse.SymbolicLinkFlags != "0x00000000" {
		t.Fatalf("symbolic link flags = %q", observation.Reparse.SymbolicLinkFlags)
	}
}

func TestCollectPathFileSymlinkReparse(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	target := filepath.Join(outside, "target.txt")
	link := filepath.Join(root, "file-link.txt")

	if err := os.WriteFile(target, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("cmd", "/c", "mklink", link, target).CombinedOutput(); err != nil {
		t.Skipf("file symlink unavailable: %v: %s", err, output)
	}

	observation, err := CollectPath(context.Background(), "scope-reparse-test", root, link)
	if err != nil {
		t.Fatal(err)
	}

	assertReparseObservation(
		t,
		observation,
		records.SubjectFile,
		records.ReparseDataFormatSymbolicLink,
		"0xA000000C",
		"IO_REPARSE_TAG_SYMLINK",
		target,
	)
	if observation.Reparse.SymbolicLinkFlags != "0x00000000" {
		t.Fatalf("symbolic link flags = %q", observation.Reparse.SymbolicLinkFlags)
	}
}

func TestCollectPathJunctionReparse(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	junction := filepath.Join(root, "junction")

	if output, err := exec.Command("cmd", "/c", "mklink", "/J", junction, outside).CombinedOutput(); err != nil {
		t.Fatalf("create junction: %v: %s", err, output)
	}

	observation, err := CollectPath(context.Background(), "scope-reparse-test", root, junction)
	if err != nil {
		t.Fatal(err)
	}

	assertReparseObservation(
		t,
		observation,
		records.SubjectDirectory,
		records.ReparseDataFormatMountPoint,
		"0xA0000003",
		"IO_REPARSE_TAG_MOUNT_POINT",
		outside,
	)
	if observation.Reparse.SymbolicLinkFlags != "" {
		t.Fatalf("junction unexpectedly has symlink flags %q", observation.Reparse.SymbolicLinkFlags)
	}
}

func assertReparseObservation(
	t *testing.T,
	observation Observation,
	wantSubject records.SubjectKind,
	wantDataFormat records.ReparseDataFormat,
	wantTag string,
	wantTagName string,
	wantTarget string,
) {
	t.Helper()

	if observation.SubjectKind != wantSubject {
		t.Fatalf("subject kind = %q, want %q", observation.SubjectKind, wantSubject)
	}
	if observation.Reparse.State != records.ReparseStatePresent {
		t.Fatalf("reparse state = %q", observation.Reparse.State)
	}
	if observation.Reparse.DataState != records.ReparseDataStatePresent {
		t.Fatalf("reparse data state = %q", observation.Reparse.DataState)
	}
	if observation.Reparse.DataFormat != wantDataFormat {
		t.Fatalf("reparse data format = %q, want %q", observation.Reparse.DataFormat, wantDataFormat)
	}
	if observation.Reparse.Tag != wantTag || observation.Reparse.TagName != wantTagName {
		t.Fatalf("reparse tag/name = %q %q", observation.Reparse.Tag, observation.Reparse.TagName)
	}
	if observation.Reparse.RawBufferBase64URL == "" {
		t.Fatal("raw reparse buffer is empty")
	}

	raw, err := base64.RawURLEncoding.DecodeString(observation.Reparse.RawBufferBase64URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < 8 || reparseTagString(binary.LittleEndian.Uint32(raw[0:4])) != wantTag {
		t.Fatalf("raw reparse buffer tag mismatch")
	}

	substitute, err := decodeUTF16Base64URL(observation.Reparse.SubstituteNameUTF16LEBase64URL)
	if err != nil {
		t.Fatal(err)
	}
	substitute = strings.TrimPrefix(substitute, `\??\`)
	if !strings.EqualFold(filepath.Clean(substitute), filepath.Clean(wantTarget)) {
		t.Fatalf("substitute target = %q, want %q", substitute, wantTarget)
	}
}

func decodeUTF16Base64URL(value string) (string, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return "", err
	}
	units := make([]uint16, len(decoded)/2)
	for index := range units {
		units[index] = binary.LittleEndian.Uint16(decoded[index*2:])
	}
	return syscall.UTF16ToString(units), nil
}
