// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportack

import (
	"bytes"
	"strings"
	"testing"
)

func FuzzReadAcknowledgement(f *testing.F) {
	valid := Acknowledgement{
		Version:        AcknowledgementVersion,
		Outcome:        OutcomeDurableNew,
		SourceID:       "iss-fs-01.iss.local",
		BatchID:        "20260913T100000.000000000Z-0011223344556677",
		DataBytes:      1024,
		DataSHA256:     strings.Repeat("0", 64),
		ManifestSHA256: strings.Repeat("1", 64),
		FrameBytes:     2048,
		FrameSHA256:    strings.Repeat("2", 64),
	}

	var encoded bytes.Buffer
	if err := WriteAcknowledgement(&encoded, valid); err != nil {
		f.Fatalf("WriteAcknowledgement() seed error = %v", err)
	}

	f.Add([]byte{})
	f.Add([]byte(wireMagic))
	f.Add(encoded.Bytes())

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1024*1024 {
			return
		}

		acknowledgement, err := ReadAcknowledgement(bytes.NewReader(data))
		if err != nil {
			return
		}

		if err := acknowledgement.Validate(); err != nil {
			t.Fatalf(
				"ReadAcknowledgement() returned acknowledgement that fails Validate(): %v",
				err,
			)
		}
	})
}
