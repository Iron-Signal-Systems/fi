// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportgeneration

import (
	"errors"
	"fmt"

	"github.com/Iron-Signal-Systems/fi/go/internal/generationsealer"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportencoding"
)

// DescriptorFromSeal converts the exact facts produced by the semantic-free
// generation sealer into the transport-generation descriptor.
//
// This boundary intentionally does not inspect collector manifests, batch
// identities, record counts or individual batch contents.
func DescriptorFromSeal(
	sourceID string,
	result generationsealer.Result,
) (Descriptor, error) {
	if generationsealer.CanonicalVersion !=
		CanonicalVersion {
		return Descriptor{},
			fmt.Errorf(
				"generation sealer canonical version %q does not match transport generation canonical version %q",
				generationsealer.CanonicalVersion,
				CanonicalVersion,
			)
	}

	if result.SealedPath == "" {
		return Descriptor{},
			errors.New(
				"sealed generation path is required",
			)
	}

	descriptor :=
		Descriptor{
			Version: DescriptorVersion,

			SourceID: sourceID,

			GenerationID: result.GenerationID,

			CanonicalVersion: generationsealer.CanonicalVersion,

			DataEncoding: transportencoding.DataEncodingZstd,

			ArtifactCount: result.FileCount,

			SourceBytes: result.SourceBytes,

			CanonicalBytes: result.CanonicalBytes,

			CanonicalSHA256: result.CanonicalSHA256,

			EncodedDataBytes: result.EncodedBytes,

			EncodedDataSHA256: result.EncodedSHA256,
		}

	if err :=
		descriptor.Validate(); err != nil {
		return Descriptor{},
			fmt.Errorf(
				"validate descriptor from sealed generation: %w",
				err,
			)
	}

	return descriptor, nil
}
