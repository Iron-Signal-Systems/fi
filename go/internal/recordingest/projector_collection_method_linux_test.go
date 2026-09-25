// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package recordingest

import (
	"errors"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
)

// ProjectSourceRecord(FileObservation) and projectUSNObjectObservation() both
// run ntfs.ValidateObservation() before relational projection. Keep every
// producer-emitted NTFS collection_method covered by the Linux/backend test
// suite so a source-side semantic addition cannot silently outrun a strict
// receiver validator.
func TestRelationalNTFSCollectionMethodCompatibility(t *testing.T) {
	for _, method := range []records.CollectionMethod{
		records.CollectionBackupAuthorityWindowsNTFS,
		records.CollectionDirectWindowsNTFS,
	} {
		observation := relationalNTFSCollectionMethodObservation(method)

		if err := ntfs.ValidateObservation(observation); err != nil {
			t.Fatalf(
				"ntfs.ValidateObservation() rejected collection method %q: %v",
				method,
				err,
			)
		}
	}
}

func TestRelationalNTFSCollectionMethodRejectsUnknownValue(t *testing.T) {
	observation := relationalNTFSCollectionMethodObservation(
		records.CollectionMethod("FutureUnknownNTFSMethod"),
	)

	err := ntfs.ValidateObservation(observation)
	if err == nil {
		t.Fatal("ntfs.ValidateObservation() accepted unknown collection method")
	}

	var validationErr *records.ValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf(
			"ntfs.ValidateObservation() error type = %T, want *records.ValidationError",
			err,
		)
	}

	if validationErr.Code != "UnsupportedValue" ||
		validationErr.Field != "collection_method" {
		t.Fatalf(
			"validation error = %s/%s, want UnsupportedValue/collection_method",
			validationErr.Code,
			validationErr.Field,
		)
	}
}

func relationalNTFSCollectionMethodObservation(
	method records.CollectionMethod,
) ntfs.Observation {
	volume := records.VolumeIdentity{
		MethodVersion: "windows-volume-identity-test/0.1",
		VolumeGUID:    `\\?\Volume{0eafbd57-0000-0000-0000-100000000000}\`,
		VolumeSerial:  "14137429470364904372",
	}

	rootObject := records.NTFSObjectIdentity{
		MethodVersion:       ntfs.IdentityMethodVersion,
		FileReferenceNumber: "5",
		SequenceNumber:      "1",
	}

	object := records.NTFSObjectIdentity{
		MethodVersion:       ntfs.IdentityMethodVersion,
		FileReferenceNumber: "270203",
		SequenceNumber:      "1070",
	}

	parent := records.NTFSObjectIdentity{
		MethodVersion:       ntfs.IdentityMethodVersion,
		FileReferenceNumber: "100",
		SequenceNumber:      "2",
	}

	hashes := records.ContentHashObservation{
		State:       records.ContentHashPresent,
		BytesHashed: "1",
		MD5:         "00000000000000000000000000000000",
		SHA1:        "0000000000000000000000000000000000000000",
		SHA256:      "0000000000000000000000000000000000000000000000000000000000000000",
	}

	prefix := records.ContentPrefixObservation{
		State:           records.ContentPrefixPresent,
		BytesObserved:   "1",
		PrefixBase64URL: "QQ",
	}

	return ntfs.Observation{
		GovernedRoot: records.GovernedRootIdentity{
			ScopeID:                       "root-backend-compatibility-test",
			RequestedPathUTF16LEBase64URL: "WQA6AFwARgBJAC0ATABhAGIA",
			ResolvedPathUTF16LEBase64URL:  "WQA6AFwARgBJAC0ATABhAGIA",
			MethodVersion:                 "windows-governed-root-test/0.1",
			VolumeIdentity:                volume,
			ObjectIdentity:                rootObject,
		},
		Containment: records.PathContainment{
			MethodVersion: ntfs.ContainmentMethodVersion,
		},
		VolumeIdentity: volume,
		ObjectIdentity: object,
		ParentBinding:  records.ParentObjectBindingFor(parent),
		SubjectKind:    records.SubjectFile,
		PathBinding: records.PathBinding{
			RequestedPathUTF16LEBase64URL: "WQA6AFwARgBJAC0ATABhAGIAXABvAGIAagBlAGMAdAAuAHQAeAB0AA",
			ResolvedPathUTF16LEBase64URL:  "WQA6AFwARgBJAC0ATABhAGIAXABvAGIAagBlAGMAdAAuAHQAeAB0AA",
		},
		ObservedAt: "2026-09-25T20:42:51.810489000Z",
		Metadata: records.MetadataObservation{
			LogicalSize:    "1",
			AllocatedSize:  "4096",
			CreationTime:   "2026-09-25T20:42:00.000000000Z",
			LastWriteTime:  "2026-09-25T20:42:00.000000000Z",
			ChangeTime:     "2026-09-25T20:42:00.000000000Z",
			LastAccessTime: "2026-09-25T20:42:00.000000000Z",
			RawAttributes:  "32",
			LinkCount:      "1",
		},
		Security: records.SecurityObservationError(
			"SecurityDescriptorReadFailed",
		),
		SACL: records.SACLObservationError(
			"SACLDescriptorReadFailed",
		),
		Reparse: records.ReparseObservation{
			State:      records.ReparseStateNotPresent,
			DataState:  records.ReparseDataStateNotApplicable,
			DataFormat: records.ReparseDataFormatNotApplicable,
		},
		StreamInventory: records.StreamInventory{
			State:   records.ObservationStatePresent,
			Streams: []records.StreamObservation{},
		},
		ContentHashes:         &hashes,
		ContentPrefix:         &prefix,
		CollectionEntryMethod: ntfs.CollectionEntryNTFSFileID,
		CollectionMethod:      method,
		ObservationStatus:     records.ObservationPartial,
		Warnings: []records.ObservationWarning{
			{Code: "SACLDescriptorReadFailed"},
			{Code: "SecurityDescriptorReadFailed"},
		},
	}
}
