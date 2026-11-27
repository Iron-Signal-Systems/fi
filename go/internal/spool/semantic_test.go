// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package spool

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestDecodeManifestRejectsUnknownField(
	t *testing.T,
) {
	value :=
		validSemanticTestManifest(
			[]byte("{\"record\":1}\n"),
		)

	raw, err :=
		json.Marshal(
			value,
		)
	if err != nil {
		t.Fatal(err)
	}

	raw =
		append(
			raw[:len(raw)-1],
			[]byte(",\"unknown\":true}")...,
		)

	if _, err :=
		DecodeManifest(
			bytes.NewReader(
				raw,
			),
		); err == nil {
		t.Fatal(
			"manifest with unknown field was accepted",
		)
	}
}

func TestDecodeManifestRejectsTrailingJSON(
	t *testing.T,
) {
	value :=
		validSemanticTestManifest(
			[]byte("{\"record\":1}\n"),
		)

	raw, err :=
		json.Marshal(
			value,
		)
	if err != nil {
		t.Fatal(err)
	}

	raw =
		append(
			raw,
			[]byte("{}")...,
		)

	if _, err :=
		DecodeManifest(
			bytes.NewReader(
				raw,
			),
		); err == nil {
		t.Fatal(
			"manifest with trailing JSON was accepted",
		)
	}
}

func TestInspectDataAndVerifyManifestData(
	t *testing.T,
) {
	data :=
		[]byte(
			"{\"record\":1}\n{\"record\":2}\n",
		)

	manifest :=
		validSemanticTestManifest(
			data,
		)

	inspection, err :=
		InspectData(
			bytes.NewReader(
				data,
			),
		)
	if err != nil {
		t.Fatal(err)
	}

	if err :=
		VerifyManifestData(
			manifest,
			inspection,
		); err != nil {
		t.Fatal(err)
	}

	if inspection.DataBytes !=
		int64(
			len(data),
		) {
		t.Fatalf(
			"DataBytes = %d, want %d",
			inspection.DataBytes,
			len(data),
		)
	}

	if inspection.RecordCount != 2 {
		t.Fatalf(
			"RecordCount = %d, want 2",
			inspection.RecordCount,
		)
	}
}

func TestInspectDataRejectsMissingFinalNewline(
	t *testing.T,
) {
	if _, err :=
		InspectData(
			strings.NewReader(
				"{\"record\":1}",
			),
		); err == nil {
		t.Fatal(
			"data without final newline was accepted",
		)
	}
}

func TestVerifyManifestDataRejectsHashMismatch(
	t *testing.T,
) {
	data :=
		[]byte(
			"{\"record\":1}\n",
		)

	manifest :=
		validSemanticTestManifest(
			data,
		)

	inspection, err :=
		InspectData(
			bytes.NewReader(
				[]byte(
					"{\"record\":2}\n",
				),
			),
		)
	if err != nil {
		t.Fatal(err)
	}

	err =
		VerifyManifestData(
			manifest,
			inspection,
		)

	if !errors.Is(
		err,
		ErrBatchHashMismatch,
	) {
		t.Fatalf(
			"VerifyManifestData() error = %v, want ErrBatchHashMismatch",
			err,
		)
	}
}

func validSemanticTestManifest(
	data []byte,
) Manifest {
	digest :=
		sha256.Sum256(
			data,
		)

	return Manifest{
		Version: ManifestVersion,

		BatchID: "20260918T160000.000000000Z-0011223344556677",

		TargetBatchSize: DefaultBatchSize,

		RecordCount: bytes.Count(
			data,
			[]byte{'\n'},
		),

		DataBytes: int64(
			len(data),
		),

		DataSHA256: hex.EncodeToString(
			digest[:],
		),

		DataFile: "batch-20260918T160000.000000000Z-0011223344556677.jsonl",

		Collector: CollectorIdentity{
			ExecutablePath: "C:\\Program Files\\FI\\fi.exe",

			ExecutableSHA256: strings.Repeat(
				"1",
				64,
			),
		},

		CreatedAt: "2026-09-18T16:00:00.000000000Z",

		CompletedAt: "2026-09-18T16:00:01.000000000Z",
	}
}
