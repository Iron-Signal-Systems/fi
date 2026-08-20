// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package records

// ReparseTagNameNotKnown means FI preserved an exact reparse tag value but does
// not have an exact documented name for that value.
const ReparseTagNameNotKnown = "NotKnown"

// Reference:
// Microsoft Open Specifications [MS-FSCC], section 2.1.2.1, "Reparse Tags".
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/c8e77b37-3909-4fe6-a4ea-2b9d423b1ee4
//
// These are exact published tag-to-name mappings. This shared record package is
// the single FI source of truth for the friendly name associated with a
// canonical 32-bit reparse tag. Unknown values remain NotKnown.
var reparseTagNames = map[string]string{
	"0x00000000": "IO_REPARSE_TAG_RESERVED_ZERO",
	"0x00000001": "IO_REPARSE_TAG_RESERVED_ONE",
	"0x00000002": "IO_REPARSE_TAG_RESERVED_TWO",
	"0x80000005": "IO_REPARSE_TAG_DRIVE_EXTENDER",
	"0x80000006": "IO_REPARSE_TAG_HSM2",
	"0x80000007": "IO_REPARSE_TAG_SIS",
	"0x80000008": "IO_REPARSE_TAG_WIM",
	"0x80000009": "IO_REPARSE_TAG_CSV",
	"0x8000000A": "IO_REPARSE_TAG_DFS",
	"0x8000000B": "IO_REPARSE_TAG_FILTER_MANAGER",
	"0x80000012": "IO_REPARSE_TAG_DFSR",
	"0x80000013": "IO_REPARSE_TAG_DEDUP",
	"0x80000014": "IO_REPARSE_TAG_NFS",
	"0x80000015": "IO_REPARSE_TAG_FILE_PLACEHOLDER",
	"0x80000016": "IO_REPARSE_TAG_DFM",
	"0x80000017": "IO_REPARSE_TAG_WOF",
	"0x80000018": "IO_REPARSE_TAG_WCI",
	"0x8000001B": "IO_REPARSE_TAG_APPEXECLINK",
	"0x8000001E": "IO_REPARSE_TAG_STORAGE_SYNC",
	"0x80000020": "IO_REPARSE_TAG_UNHANDLED",
	"0x80000021": "IO_REPARSE_TAG_ONEDRIVE",
	"0x80000023": "IO_REPARSE_TAG_AF_UNIX",
	"0x80000024": "IO_REPARSE_TAG_LX_FIFO",
	"0x80000025": "IO_REPARSE_TAG_LX_CHR",
	"0x80000026": "IO_REPARSE_TAG_LX_BLK",
	"0x9000001A": "IO_REPARSE_TAG_CLOUD",
	"0x9000001C": "IO_REPARSE_TAG_PROJFS",
	"0x90000027": "IO_REPARSE_TAG_STORAGE_SYNC_FOLDER",
	"0x90001018": "IO_REPARSE_TAG_WCI_1",
	"0x9000101A": "IO_REPARSE_TAG_CLOUD_1",
	"0x9000201A": "IO_REPARSE_TAG_CLOUD_2",
	"0x9000301A": "IO_REPARSE_TAG_CLOUD_3",
	"0x9000401A": "IO_REPARSE_TAG_CLOUD_4",
	"0x9000501A": "IO_REPARSE_TAG_CLOUD_5",
	"0x9000601A": "IO_REPARSE_TAG_CLOUD_6",
	"0x9000701A": "IO_REPARSE_TAG_CLOUD_7",
	"0x9000801A": "IO_REPARSE_TAG_CLOUD_8",
	"0x9000901A": "IO_REPARSE_TAG_CLOUD_9",
	"0x9000A01A": "IO_REPARSE_TAG_CLOUD_A",
	"0x9000B01A": "IO_REPARSE_TAG_CLOUD_B",
	"0x9000C01A": "IO_REPARSE_TAG_CLOUD_C",
	"0x9000D01A": "IO_REPARSE_TAG_CLOUD_D",
	"0x9000E01A": "IO_REPARSE_TAG_CLOUD_E",
	"0x9000F01A": "IO_REPARSE_TAG_CLOUD_F",
	"0xA0000003": "IO_REPARSE_TAG_MOUNT_POINT",
	"0xA000000C": "IO_REPARSE_TAG_SYMLINK",
	"0xA0000010": "IO_REPARSE_TAG_IIS_CACHE",
	"0xA0000019": "IO_REPARSE_TAG_GLOBAL_REPARSE",
	"0xA000001D": "IO_REPARSE_TAG_LX_SYMLINK",
	"0xA000001F": "IO_REPARSE_TAG_WCI_TOMBSTONE",
	"0xA0000022": "IO_REPARSE_TAG_PROJFS_TOMBSTONE",
	"0xA0000027": "IO_REPARSE_TAG_WCI_LINK",
	"0xA0001027": "IO_REPARSE_TAG_WCI_LINK_1",
	"0xC0000004": "IO_REPARSE_TAG_HSM",
	"0xC0000014": "IO_REPARSE_TAG_APPXSTRM",
}

// ReparseTagName returns the exact documented FI name for a canonical tag, or
// NotKnown when FI has no exact mapping for that value.
func ReparseTagName(tag string) string {
	if name, ok := reparseTagNames[tag]; ok {
		return name
	}
	return ReparseTagNameNotKnown
}
