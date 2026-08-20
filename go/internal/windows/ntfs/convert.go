// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package ntfs

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strconv"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

// Windows APIs return native integers, FILETIME values, UTF-16 code units, and
// FILE_ID_INFO structures. This file converts those Windows values into the
// shared FI record representation.

const windowsUnixEpochOffsetSeconds int64 = 11644473600

// splitNTFSFileID separates the NTFS file reference number and sequence number
// from the low 64 bits of FILE_ID_INFO.
//
// The current NTFS identity method does not accept a non-zero high 64 bits
// because FI would no longer be interpreting the identifier as the expected
// NTFS file-reference format.
func splitNTFSFileID(fileID [16]byte) (recordNumber uint64, sequenceNumber uint16, err error) {
	for _, value := range fileID[8:] {
		if value != 0 {
			return 0, 0, fmt.Errorf("NTFS file ID high 64 bits are not zero")
		}
	}
	low := binary.LittleEndian.Uint64(fileID[:8])
	return low & 0x0000FFFFFFFFFFFF, uint16(low >> 48), nil
}

// filetimeToCanonical converts Windows FILETIME to the fixed UTC representation
// used in shared FI source records.
func filetimeToCanonical(value int64) (string, error) {
	if value < 0 {
		return "", fmt.Errorf("negative Windows file time")
	}
	seconds := value/10_000_000 - windowsUnixEpochOffsetSeconds
	nanoseconds := (value % 10_000_000) * 100
	return time.Unix(seconds, nanoseconds).UTC().Format("2006-01-02T15:04:05.000000000Z"), nil
}

// utf16LEBase64URL preserves the exact UTF-16 code units Windows returned.
//
// FI uses this for record fidelity instead of forcing Windows names through a
// potentially lossy text conversion before the source record is staged.
func utf16LEBase64URL(units []uint16) string {
	encoded := make([]byte, len(units)*2)
	for index, unit := range units {
		binary.LittleEndian.PutUint16(encoded[index*2:], unit)
	}
	return base64.RawURLEncoding.EncodeToString(encoded)
}

func buildObjectIdentity(volumeSerial uint64, fileID [16]byte) (records.VolumeIdentity, records.NTFSObjectIdentity, error) {
	recordNumber, sequenceNumber, err := splitNTFSFileID(fileID)
	if err != nil {
		return records.VolumeIdentity{}, records.NTFSObjectIdentity{}, err
	}
	return records.VolumeIdentity{
		MethodVersion: IdentityMethodVersion,
		VolumeSerial:  strconv.FormatUint(volumeSerial, 10),
	}, records.NTFSObjectIdentity{
		MethodVersion:       IdentityMethodVersion,
		FileReferenceNumber: strconv.FormatUint(recordNumber, 10),
		SequenceNumber:      strconv.FormatUint(uint64(sequenceNumber), 10),
	}, nil
}

// streamIdentityFromWindowsName parses the :name:type form returned by
// FILE_STREAM_INFO while always preserving the exact raw UTF-16 stream name.
func streamIdentityFromWindowsName(name []uint16) records.StreamIdentity {
	identity := records.StreamIdentity{
		RawNameUTF16LEBase64URL: utf16LEBase64URL(name),
	}

	first := -1
	last := -1
	for i, unit := range name {
		if unit == ':' {
			if first < 0 {
				first = i
			}
			last = i
		}
	}

	if first != 0 || last <= first {
		identity.Kind = records.StreamOther
		identity.NameUTF16LEBase64URL = utf16LEBase64URL(name)
		identity.StreamType = "Unknown"
		return identity
	}

	streamName := name[first+1 : last]
	streamType := string(runesFromUTF16(name[last+1:]))
	identity.StreamType = streamType

	if len(streamName) == 0 && streamType == "$DATA" {
		identity.Kind = records.StreamDefaultData
		return identity
	}

	identity.NameUTF16LEBase64URL = utf16LEBase64URL(streamName)
	if streamType == "$DATA" {
		identity.Kind = records.StreamNamedData
	} else {
		identity.Kind = records.StreamOther
	}
	return identity
}

func runesFromUTF16(units []uint16) []rune {
	runes := make([]rune, len(units))
	for i, unit := range units {
		runes[i] = rune(unit)
	}
	return runes
}
