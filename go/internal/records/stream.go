// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package records

import (
	"encoding/base64"
	"encoding/binary"
)

// StreamIdentityFromRawUTF16 derives FI's canonical interpreted stream identity
// from the exact UTF-16 FILE_STREAM_INFO name returned by Windows.
//
// RawNameUTF16LEBase64URL remains authoritative. Kind, NameUTF16LEBase64URL,
// and StreamType are deterministic projections of that raw name and can be
// independently recomputed by receivers.
func StreamIdentityFromRawUTF16(name []uint16) StreamIdentity {
	identity := StreamIdentity{
		RawNameUTF16LEBase64URL: encodeUTF16LEBase64URL(name),
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
		identity.Kind = StreamOther
		identity.NameUTF16LEBase64URL = encodeUTF16LEBase64URL(name)
		identity.StreamType = "Unknown"
		return identity
	}

	streamName := name[first+1 : last]
	streamType := string(runesFromUTF16CodeUnits(name[last+1:]))
	identity.StreamType = streamType

	if len(streamName) == 0 && streamType == "$DATA" {
		identity.Kind = StreamDefaultData
		return identity
	}

	identity.NameUTF16LEBase64URL = encodeUTF16LEBase64URL(streamName)
	if streamType == "$DATA" {
		identity.Kind = StreamNamedData
	} else {
		identity.Kind = StreamOther
	}
	return identity
}

func encodeUTF16LEBase64URL(units []uint16) string {
	encoded := make([]byte, len(units)*2)
	for index, unit := range units {
		binary.LittleEndian.PutUint16(encoded[index*2:], unit)
	}
	return base64.RawURLEncoding.EncodeToString(encoded)
}

func runesFromUTF16CodeUnits(units []uint16) []rune {
	runes := make([]rune, len(units))
	for i, unit := range units {
		runes[i] = rune(unit)
	}
	return runes
}
