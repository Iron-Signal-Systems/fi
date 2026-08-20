// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package ntfs

import (
	"fmt"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

// Reference:
// Microsoft Open Specifications [MS-FSCC], section 2.1.2.1, "Reparse Tags".
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/c8e77b37-3909-4fe6-a4ea-2b9d423b1ee4
//
// The values below are transcribed from the documented reparse-tag constants.
// No Microsoft sample-program logic is incorporated here.
const (
	reparseTagAFUnix            uint32 = 0x80000023
	reparseTagAppExecLink       uint32 = 0x8000001B
	reparseTagAppxStrm          uint32 = 0xC0000014
	reparseTagCloud             uint32 = 0x9000001A
	reparseTagCloud1            uint32 = 0x9000101A
	reparseTagCloud2            uint32 = 0x9000201A
	reparseTagCloud3            uint32 = 0x9000301A
	reparseTagCloud4            uint32 = 0x9000401A
	reparseTagCloud5            uint32 = 0x9000501A
	reparseTagCloud6            uint32 = 0x9000601A
	reparseTagCloud7            uint32 = 0x9000701A
	reparseTagCloud8            uint32 = 0x9000801A
	reparseTagCloud9            uint32 = 0x9000901A
	reparseTagCloudA            uint32 = 0x9000A01A
	reparseTagCloudB            uint32 = 0x9000B01A
	reparseTagCloudC            uint32 = 0x9000C01A
	reparseTagCloudD            uint32 = 0x9000D01A
	reparseTagCloudE            uint32 = 0x9000E01A
	reparseTagCloudF            uint32 = 0x9000F01A
	reparseTagCSV               uint32 = 0x80000009
	reparseTagDedup             uint32 = 0x80000013
	reparseTagDFM               uint32 = 0x80000016
	reparseTagDFS               uint32 = 0x8000000A
	reparseTagDFSR              uint32 = 0x80000012
	reparseTagDriveExtender     uint32 = 0x80000005
	reparseTagFilePlaceholder   uint32 = 0x80000015
	reparseTagFilterManager     uint32 = 0x8000000B
	reparseTagGlobalReparse     uint32 = 0xA0000019
	reparseTagHSM               uint32 = 0xC0000004
	reparseTagHSM2              uint32 = 0x80000006
	reparseTagIISCache          uint32 = 0xA0000010
	reparseTagLXBLK             uint32 = 0x80000026
	reparseTagLXCHR             uint32 = 0x80000025
	reparseTagLXFIFO            uint32 = 0x80000024
	reparseTagLXSymlink         uint32 = 0xA000001D
	reparseTagMountPoint        uint32 = 0xA0000003
	reparseTagNFS               uint32 = 0x80000014
	reparseTagOneDrive          uint32 = 0x80000021
	reparseTagProjFS            uint32 = 0x9000001C
	reparseTagProjFSTombstone   uint32 = 0xA0000022
	reparseTagReservedOne       uint32 = 0x00000001
	reparseTagReservedTwo       uint32 = 0x00000002
	reparseTagReservedZero      uint32 = 0x00000000
	reparseTagSIS               uint32 = 0x80000007
	reparseTagStorageSync       uint32 = 0x8000001E
	reparseTagStorageSyncFolder uint32 = 0x90000027
	reparseTagSymlink           uint32 = 0xA000000C
	reparseTagUnhandled         uint32 = 0x80000020
	reparseTagWCI               uint32 = 0x80000018
	reparseTagWCI1              uint32 = 0x90001018
	reparseTagWCILink           uint32 = 0xA0000027
	reparseTagWCILink1          uint32 = 0xA0001027
	reparseTagWCITombstone      uint32 = 0xA000001F
	reparseTagWIM               uint32 = 0x80000008
	reparseTagWOF               uint32 = 0x80000017
)

func knownReparseTagName(tag uint32) string {
	switch tag {
	case reparseTagAFUnix:
		return "IO_REPARSE_TAG_AF_UNIX"
	case reparseTagAppExecLink:
		return "IO_REPARSE_TAG_APPEXECLINK"
	case reparseTagAppxStrm:
		return "IO_REPARSE_TAG_APPXSTRM"
	case reparseTagCloud:
		return "IO_REPARSE_TAG_CLOUD"
	case reparseTagCloud1:
		return "IO_REPARSE_TAG_CLOUD_1"
	case reparseTagCloud2:
		return "IO_REPARSE_TAG_CLOUD_2"
	case reparseTagCloud3:
		return "IO_REPARSE_TAG_CLOUD_3"
	case reparseTagCloud4:
		return "IO_REPARSE_TAG_CLOUD_4"
	case reparseTagCloud5:
		return "IO_REPARSE_TAG_CLOUD_5"
	case reparseTagCloud6:
		return "IO_REPARSE_TAG_CLOUD_6"
	case reparseTagCloud7:
		return "IO_REPARSE_TAG_CLOUD_7"
	case reparseTagCloud8:
		return "IO_REPARSE_TAG_CLOUD_8"
	case reparseTagCloud9:
		return "IO_REPARSE_TAG_CLOUD_9"
	case reparseTagCloudA:
		return "IO_REPARSE_TAG_CLOUD_A"
	case reparseTagCloudB:
		return "IO_REPARSE_TAG_CLOUD_B"
	case reparseTagCloudC:
		return "IO_REPARSE_TAG_CLOUD_C"
	case reparseTagCloudD:
		return "IO_REPARSE_TAG_CLOUD_D"
	case reparseTagCloudE:
		return "IO_REPARSE_TAG_CLOUD_E"
	case reparseTagCloudF:
		return "IO_REPARSE_TAG_CLOUD_F"
	case reparseTagCSV:
		return "IO_REPARSE_TAG_CSV"
	case reparseTagDedup:
		return "IO_REPARSE_TAG_DEDUP"
	case reparseTagDFM:
		return "IO_REPARSE_TAG_DFM"
	case reparseTagDFS:
		return "IO_REPARSE_TAG_DFS"
	case reparseTagDFSR:
		return "IO_REPARSE_TAG_DFSR"
	case reparseTagDriveExtender:
		return "IO_REPARSE_TAG_DRIVE_EXTENDER"
	case reparseTagFilePlaceholder:
		return "IO_REPARSE_TAG_FILE_PLACEHOLDER"
	case reparseTagFilterManager:
		return "IO_REPARSE_TAG_FILTER_MANAGER"
	case reparseTagGlobalReparse:
		return "IO_REPARSE_TAG_GLOBAL_REPARSE"
	case reparseTagHSM:
		return "IO_REPARSE_TAG_HSM"
	case reparseTagHSM2:
		return "IO_REPARSE_TAG_HSM2"
	case reparseTagIISCache:
		return "IO_REPARSE_TAG_IIS_CACHE"
	case reparseTagLXBLK:
		return "IO_REPARSE_TAG_LX_BLK"
	case reparseTagLXCHR:
		return "IO_REPARSE_TAG_LX_CHR"
	case reparseTagLXFIFO:
		return "IO_REPARSE_TAG_LX_FIFO"
	case reparseTagLXSymlink:
		return "IO_REPARSE_TAG_LX_SYMLINK"
	case reparseTagMountPoint:
		return "IO_REPARSE_TAG_MOUNT_POINT"
	case reparseTagNFS:
		return "IO_REPARSE_TAG_NFS"
	case reparseTagOneDrive:
		return "IO_REPARSE_TAG_ONEDRIVE"
	case reparseTagProjFS:
		return "IO_REPARSE_TAG_PROJFS"
	case reparseTagProjFSTombstone:
		return "IO_REPARSE_TAG_PROJFS_TOMBSTONE"
	case reparseTagReservedOne:
		return "IO_REPARSE_TAG_RESERVED_ONE"
	case reparseTagReservedTwo:
		return "IO_REPARSE_TAG_RESERVED_TWO"
	case reparseTagReservedZero:
		return "IO_REPARSE_TAG_RESERVED_ZERO"
	case reparseTagSIS:
		return "IO_REPARSE_TAG_SIS"
	case reparseTagStorageSync:
		return "IO_REPARSE_TAG_STORAGE_SYNC"
	case reparseTagStorageSyncFolder:
		return "IO_REPARSE_TAG_STORAGE_SYNC_FOLDER"
	case reparseTagSymlink:
		return "IO_REPARSE_TAG_SYMLINK"
	case reparseTagUnhandled:
		return "IO_REPARSE_TAG_UNHANDLED"
	case reparseTagWCI:
		return "IO_REPARSE_TAG_WCI"
	case reparseTagWCI1:
		return "IO_REPARSE_TAG_WCI_1"
	case reparseTagWCILink:
		return "IO_REPARSE_TAG_WCI_LINK"
	case reparseTagWCILink1:
		return "IO_REPARSE_TAG_WCI_LINK_1"
	case reparseTagWCITombstone:
		return "IO_REPARSE_TAG_WCI_TOMBSTONE"
	case reparseTagWIM:
		return "IO_REPARSE_TAG_WIM"
	case reparseTagWOF:
		return "IO_REPARSE_TAG_WOF"
	default:
		return records.ReparseTagNameNotKnown
	}
}

func reparseObservation(present bool, tag uint32) records.ReparseObservation {
	if !present {
		return records.ReparseObservation{
			State: records.ReparseStateNotPresent,
		}
	}

	return records.ReparseObservation{
		State:   records.ReparseStatePresent,
		Tag:     fmt.Sprintf("0x%08X", tag),
		TagName: knownReparseTagName(tag),
	}
}
