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
	"io"
)

// DataInspection contains the streaming facts needed to verify one finalized
// collector data artifact against its published batch manifest.
//
// It deliberately contains no transport or generation fields. The collector
// manifest remains authoritative for batch identity and expected data facts.
type DataInspection struct {
	DataBytes   int64
	DataSHA256  string
	RecordCount int
}

// DecodeManifest reads exactly one FI batch manifest from reader, rejects
// unknown fields and trailing JSON, and applies the same manifest validation
// rules used by VerifyManifest.
func DecodeManifest(
	reader io.Reader,
) (
	Manifest,
	error,
) {
	if reader == nil {
		return Manifest{},
			errors.New(
				"FI batch manifest reader is required",
			)
	}

	decoder :=
		json.NewDecoder(
			reader,
		)

	decoder.DisallowUnknownFields()

	var manifest Manifest

	if err :=
		decoder.Decode(
			&manifest,
		); err != nil {
		return Manifest{}, err
	}

	var extra any

	if err :=
		decoder.Decode(
			&extra,
		); err != io.EOF {
		return Manifest{},
			errors.New(
				"manifest contains trailing data",
			)
	}

	if err :=
		validateManifest(
			manifest,
		); err != nil {
		return Manifest{}, err
	}

	return manifest, nil
}

// InspectData reads one finalized FI batch data stream once and computes the
// exact byte count, SHA-256, and newline-delimited record count used by the
// collector manifest contract.
func InspectData(
	reader io.Reader,
) (
	DataInspection,
	error,
) {
	if reader == nil {
		return DataInspection{},
			errors.New(
				"FI batch data reader is required",
			)
	}

	hasher :=
		sha256.New()

	buffer :=
		make(
			[]byte,
			128*1024,
		)

	var total int64

	records :=
		0

	var last byte

	for {
		n, readErr :=
			reader.Read(
				buffer,
			)

		if n > 0 {
			chunk :=
				buffer[:n]

			if _, err :=
				hasher.Write(
					chunk,
				); err != nil {
				return DataInspection{}, err
			}

			if int64(n) >
				int64(^uint64(0)>>1)-
					total {
				return DataInspection{},
					errors.New(
						"FI batch data byte count overflow",
					)
			}

			total +=
				int64(n)

			newlines :=
				bytes.Count(
					chunk,
					[]byte{'\n'},
				)

			if newlines >
				int(^uint(0)>>1)-
					records {
				return DataInspection{},
					errors.New(
						"FI batch record count overflow",
					)
			}

			records +=
				newlines

			last =
				chunk[len(chunk)-1]
		}

		if readErr == io.EOF {
			break
		}

		if readErr != nil {
			return DataInspection{}, readErr
		}
	}

	if total == 0 ||
		last != '\n' {
		return DataInspection{},
			errors.New(
				"batch data is empty or missing final newline",
			)
	}

	return DataInspection{
		DataBytes: total,

		DataSHA256: hex.EncodeToString(
			hasher.Sum(
				nil,
			),
		),

		RecordCount: records,
	}, nil
}

// VerifyManifestData compares one validated FI manifest with streaming facts
// computed from its paired data artifact.
func VerifyManifestData(
	manifest Manifest,
	inspection DataInspection,
) error {
	if err :=
		validateManifest(
			manifest,
		); err != nil {
		return err
	}

	if inspection.DataSHA256 !=
		manifest.DataSHA256 {
		return ErrBatchHashMismatch
	}

	if inspection.DataBytes !=
		manifest.DataBytes {
		return ErrBatchSizeMismatch
	}

	if inspection.RecordCount !=
		manifest.RecordCount {
		return ErrBatchCountMismatch
	}

	return nil
}
