// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package ntfs

import (
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func TestKnownReparseTagNames(t *testing.T) {
	tests := []struct {
		name string
		tag  uint32
	}{
		{"IO_REPARSE_TAG_AF_UNIX", reparseTagAFUnix},
		{"IO_REPARSE_TAG_APPEXECLINK", reparseTagAppExecLink},
		{"IO_REPARSE_TAG_APPXSTRM", reparseTagAppxStrm},
		{"IO_REPARSE_TAG_CLOUD", reparseTagCloud},
		{"IO_REPARSE_TAG_CLOUD_1", reparseTagCloud1},
		{"IO_REPARSE_TAG_CLOUD_2", reparseTagCloud2},
		{"IO_REPARSE_TAG_CLOUD_3", reparseTagCloud3},
		{"IO_REPARSE_TAG_CLOUD_4", reparseTagCloud4},
		{"IO_REPARSE_TAG_CLOUD_5", reparseTagCloud5},
		{"IO_REPARSE_TAG_CLOUD_6", reparseTagCloud6},
		{"IO_REPARSE_TAG_CLOUD_7", reparseTagCloud7},
		{"IO_REPARSE_TAG_CLOUD_8", reparseTagCloud8},
		{"IO_REPARSE_TAG_CLOUD_9", reparseTagCloud9},
		{"IO_REPARSE_TAG_CLOUD_A", reparseTagCloudA},
		{"IO_REPARSE_TAG_CLOUD_B", reparseTagCloudB},
		{"IO_REPARSE_TAG_CLOUD_C", reparseTagCloudC},
		{"IO_REPARSE_TAG_CLOUD_D", reparseTagCloudD},
		{"IO_REPARSE_TAG_CLOUD_E", reparseTagCloudE},
		{"IO_REPARSE_TAG_CLOUD_F", reparseTagCloudF},
		{"IO_REPARSE_TAG_CSV", reparseTagCSV},
		{"IO_REPARSE_TAG_DEDUP", reparseTagDedup},
		{"IO_REPARSE_TAG_DFM", reparseTagDFM},
		{"IO_REPARSE_TAG_DFS", reparseTagDFS},
		{"IO_REPARSE_TAG_DFSR", reparseTagDFSR},
		{"IO_REPARSE_TAG_DRIVE_EXTENDER", reparseTagDriveExtender},
		{"IO_REPARSE_TAG_FILE_PLACEHOLDER", reparseTagFilePlaceholder},
		{"IO_REPARSE_TAG_FILTER_MANAGER", reparseTagFilterManager},
		{"IO_REPARSE_TAG_GLOBAL_REPARSE", reparseTagGlobalReparse},
		{"IO_REPARSE_TAG_HSM", reparseTagHSM},
		{"IO_REPARSE_TAG_HSM2", reparseTagHSM2},
		{"IO_REPARSE_TAG_IIS_CACHE", reparseTagIISCache},
		{"IO_REPARSE_TAG_LX_BLK", reparseTagLXBLK},
		{"IO_REPARSE_TAG_LX_CHR", reparseTagLXCHR},
		{"IO_REPARSE_TAG_LX_FIFO", reparseTagLXFIFO},
		{"IO_REPARSE_TAG_LX_SYMLINK", reparseTagLXSymlink},
		{"IO_REPARSE_TAG_MOUNT_POINT", reparseTagMountPoint},
		{"IO_REPARSE_TAG_NFS", reparseTagNFS},
		{"IO_REPARSE_TAG_ONEDRIVE", reparseTagOneDrive},
		{"IO_REPARSE_TAG_PROJFS", reparseTagProjFS},
		{"IO_REPARSE_TAG_PROJFS_TOMBSTONE", reparseTagProjFSTombstone},
		{"IO_REPARSE_TAG_RESERVED_ONE", reparseTagReservedOne},
		{"IO_REPARSE_TAG_RESERVED_TWO", reparseTagReservedTwo},
		{"IO_REPARSE_TAG_RESERVED_ZERO", reparseTagReservedZero},
		{"IO_REPARSE_TAG_SIS", reparseTagSIS},
		{"IO_REPARSE_TAG_STORAGE_SYNC", reparseTagStorageSync},
		{"IO_REPARSE_TAG_STORAGE_SYNC_FOLDER", reparseTagStorageSyncFolder},
		{"IO_REPARSE_TAG_SYMLINK", reparseTagSymlink},
		{"IO_REPARSE_TAG_UNHANDLED", reparseTagUnhandled},
		{"IO_REPARSE_TAG_WCI", reparseTagWCI},
		{"IO_REPARSE_TAG_WCI_1", reparseTagWCI1},
		{"IO_REPARSE_TAG_WCI_LINK", reparseTagWCILink},
		{"IO_REPARSE_TAG_WCI_LINK_1", reparseTagWCILink1},
		{"IO_REPARSE_TAG_WCI_TOMBSTONE", reparseTagWCITombstone},
		{"IO_REPARSE_TAG_WIM", reparseTagWIM},
		{"IO_REPARSE_TAG_WOF", reparseTagWOF},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := knownReparseTagName(test.tag); got != test.name {
				t.Fatalf("tag 0x%08X name = %q, want %q", test.tag, got, test.name)
			}
		})
	}
}

func TestReparseObservationKnown(t *testing.T) {
	got := reparseObservation(true, reparseTagMountPoint)

	if got.State != records.ReparseStatePresent {
		t.Fatalf("state = %q", got.State)
	}
	if got.Tag != "0xA0000003" {
		t.Fatalf("tag = %q", got.Tag)
	}
	if got.TagName != "IO_REPARSE_TAG_MOUNT_POINT" {
		t.Fatalf("tag name = %q", got.TagName)
	}
}

func TestReparseObservationNotPresent(t *testing.T) {
	got := reparseObservation(false, reparseTagMountPoint)

	if got.State != records.ReparseStateNotPresent {
		t.Fatalf("state = %q", got.State)
	}
	if got.Tag != "" || got.TagName != "" {
		t.Fatalf("not-present reparse retained tag data: %+v", got)
	}
}

func TestReparseObservationUnknown(t *testing.T) {
	const unknownTag uint32 = 0xDEADBEEF

	got := reparseObservation(true, unknownTag)

	if got.State != records.ReparseStatePresent {
		t.Fatalf("state = %q", got.State)
	}
	if got.Tag != "0xDEADBEEF" {
		t.Fatalf("tag = %q", got.Tag)
	}
	if got.TagName != records.ReparseTagNameNotKnown {
		t.Fatalf("tag name = %q", got.TagName)
	}
}
