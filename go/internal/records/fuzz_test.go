// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package records

import (
	"encoding/base64"
	"fmt"
	"testing"
)

func FuzzValidateReparseObservation(f *testing.F) {
	f.Add([]byte{}, uint32(0), "", "", "")
	f.Add(hardeningMountPointBuffer(`\??\C:\target`, `C:\target`), uint32(0xA0000003), hardeningUTF16Base64(`\??\C:\target`), hardeningUTF16Base64(`C:\target`), "")
	f.Add(hardeningSymlinkBuffer(`\??\C:\target`, `C:\target`, 0), uint32(0xA000000C), hardeningUTF16Base64(`\??\C:\target`), hardeningUTF16Base64(`C:\target`), "0x00000000")

	f.Fuzz(func(t *testing.T, raw []byte, tag uint32, substitute string, printName string, flags string) {
		format := ReparseDataFormatRaw
		switch tag {
		case 0xA0000003:
			format = ReparseDataFormatMountPoint
		case 0xA000000C:
			format = ReparseDataFormatSymbolicLink
		}
		observation := ReparseObservation{
			DataFormat:                     format,
			DataState:                      ReparseDataStatePresent,
			PrintNameUTF16LEBase64URL:      printName,
			RawBufferBase64URL:             base64.RawURLEncoding.EncodeToString(raw),
			State:                          ReparseStatePresent,
			SubstituteNameUTF16LEBase64URL: substitute,
			SymbolicLinkFlags:              flags,
			Tag:                            fmt.Sprintf("0x%08X", tag),
			TagName:                        ReparseTagName(fmt.Sprintf("0x%08X", tag)),
		}
		_ = ValidateReparseObservation(observation)
	})
}

func FuzzValidateStreamIdentity(f *testing.F) {
	f.Add([]byte{':', 0, ':', 0, '$', 0, 'D', 0, 'A', 0, 'T', 0, 'A', 0})
	f.Add([]byte{':', 0, 'x', 0, ':', 0, '$', 0, 'D', 0, 'A', 0, 'T', 0, 'A', 0})

	f.Fuzz(func(t *testing.T, raw []byte) {
		identity := StreamIdentity{
			Kind:                    StreamOther,
			NameUTF16LEBase64URL:    base64.RawURLEncoding.EncodeToString(raw),
			StreamType:              "Unknown",
			RawNameUTF16LEBase64URL: base64.RawURLEncoding.EncodeToString(raw),
		}
		_ = ValidateStreamIdentity(identity)
	})
}
