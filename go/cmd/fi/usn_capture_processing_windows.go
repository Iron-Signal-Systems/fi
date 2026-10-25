// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/runtimeidentity"
	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
	"github.com/Iron-Signal-Systems/fi/go/internal/usncapture"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/usn"
)

// processCapturedUSNOnce is an INACTIVE M3 processing-lane bridge. It consumes
// the original cached USN facts without reading the live NTFS journal. Every
// distinct File-ID is re-observed once; every triggering change is published.
// M2 hints are NOT authoritative historical containment or exclusion proofs.
// Until historical ancestry is proven, no source object may be filtered out.
//
// Service activation still requires migration, lock coordination, replay-safe
// idempotent publication, and installer/runtime acceptance. This function is
// intentionally not called by the FI Windows service in this milestone.
func processCapturedUSNOnce(
	ctx context.Context, scopeID, governedRoot string,
	rootIdentity records.NTFSObjectIdentity,
	store *usncapture.Store, statePath string,
) (bool, error) {
	if ctx == nil || store == nil {
		return false, errors.New("cached USN processor requires context and store")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	seg, found, err := store.Next()
	if err != nil || !found {
		return false, err
	}
	if seg.Batch.ScopeID != scopeID {
		return false, fmt.Errorf("%w: source scope mismatch", usncapture.ErrConflict)
	}
	correlation, err := store.Correlate(seg, rootIdentity)
	if err != nil {
		return false, err
	}
	// Recover a previously verified publication before scheduling another NTFS
	// pass. Once an intent exists, an absent active-spool manifest is NOT
	// permission to republish: sender may have already transported it.
	pending, err := store.PublicationPending(seg, correlation)
	if err != nil {
		return false, err
	}
	dir, err := spool.DefaultDir()
	if err != nil {
		return false, err
	}
	if pending {
		return store.RecoverPendingSpoolPublication(seg, correlation, dir,
			func(manifests []string) error {
				observedSIDs, err := capturePublicationSIDs(manifests)
				if err != nil {
					return err
				}
				_, err = mergeUSNObservedSIDSet(observedSIDs)
				return err
			})
	}
	staged, err := usn.ReobserveCapturedJournaledStaged(
		usn.WithoutInterruptedRecovery(ctx), scopeID, governedRoot,
		seg.Batch, statePath,
		usn.CurrentProcessingChunkObjects(), usn.CurrentProcessingMaxInflight(),
	)
	if err != nil {
		return false, err
	}
	if staged.Stage == nil {
		return false, errors.New("cached USN re-observation stage missing")
	}
	defer staged.Stage.Close()
	if !reflect.DeepEqual(staged.Result.USNBatch, seg.Batch) ||
		len(staged.Result.Reobservations) != len(correlation.Work) {
		return false, errors.New("cached USN source or work list changed during observation")
	}
	// This must be durable before the first manifest could be published.
	// A process crash or source failure after this boundary blocks any blind
	// republishing until the original custody outcome has been resolved.
	if err := store.BeginSpoolPublication(seg, correlation); err != nil {
		return false, err
	}
	executable, err := runtimeidentity.CurrentExecutable()
	if err != nil {
		return false, err
	}
	writer, err := spool.NewWriter(dir, spool.DefaultBatchSize, spool.CollectorIdentity{
		ExecutablePath:   executable.Path,
		ExecutableSHA256: executable.SHA256,
	})
	if err != nil {
		return false, err
	}

	// This boundary binds the FI spool to an exact immutable capture segment.
	// Every candidate is carried forward until historical scope can be proven.
	if err := writer.Append("USNReadBoundary", scopeID, spooledUSNReadBoundary{
		ObservedAt:                 seg.Batch.ObservedAt,
		CollectionMethod:           seg.Batch.CollectionMethod,
		VolumeIdentity:             seg.Batch.VolumeIdentity,
		JournalID:                  seg.Batch.JournalID,
		StartUSN:                   seg.Batch.StartUSN,
		NextUSN:                    seg.Batch.NextUSN,
		SourceBatchSHA256:          seg.SHA256,
		CorrelationSHA256:          correlation.SHA256,
		RootIdentity:               &correlation.RootIdentity,
		SourceRecordCount:          len(seg.Batch.Records),
		SourceDistinctObjectCount:  len(seg.Work),
		SelectedRecordCount:        len(seg.Batch.Records),
		SelectedObjectCount:        len(seg.Work),
		ScopeUnresolvedObjectCount: len(seg.Work),
		ReObservationOperationID:   staged.ReObservationOperation.OperationID,
	}); err != nil {
		return false, err
	}

	byID := groupUSNChanges(seg.Batch.Records)
	observedSIDs := newObservedSIDSet()
	for i, work := range correlation.Work {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		hint := staged.Result.Reobservations[i]
		if hint.FileIdentity != work.FileIdentity {
			return false, errors.New("cached USN staged observation order mismatch")
		}
		observation, err := staged.Stage.Read(work.FileIdentity)
		if err != nil {
			return false, err
		}
		if observation.Status != hint.Status || observation.ReasonCode != hint.ReasonCode {
			return false, errors.New("cached USN staged status mismatch")
		}
		if observation.Status == usn.ReobservationObserved && observation.Observation != nil {
			addNTFSObservationSIDs(observedSIDs, *observation.Observation)
		}
		record := spooledUSNObjectObservation{
			SourceBatchSHA256: seg.SHA256,
			FileIdentity:      work.FileIdentity,
			Changes:           byID[work.FileIdentity],
			ScopeBasis:        scopeBasisUnresolvedIncluded,
			ScopeDetail:       "CachedUSN:" + work.ScopeHint,
			Status:            observation.Status,
			ReasonCode:        observation.ReasonCode,
			Error:             observation.Error,
			NTFS:              observation.Observation,
		}
		if observation.Status == usn.ReobservationObserved && observation.Observation != nil {
			if observation.Observation.ContentHashes == nil {
				return false, errors.New("cached USN observation missing content hash result")
			}
			hashes := *observation.Observation.ContentHashes
			if err := records.ValidateContentHashObservation(hashes); err != nil {
				return false, err
			}
			ntfsBody := *observation.Observation
			ntfsBody.ContentHashes = nil
			record.NTFS = &ntfsBody
			record.ContentHashes = &hashes
		}
		if record.NTFS != nil && record.NTFS.ObjectIdentity != (ntfs.Observation{}).ObjectIdentity && record.NTFS.ObjectIdentity != work.FileIdentity {
			return false, errors.New("cached NTFS body File-ID mismatch")
		}
		if err := writer.Append("USNObjectObservation", scopeID, record); err != nil {
			return false, err
		}
	}
	if err := writer.Close(); err != nil {
		return false, err
	}
	published := writer.FinalizedBatches()
	manifests := make([]string, 0, len(published))
	for _, b := range published {
		manifests = append(manifests, b.ManifestPath)
	}

	// Serialize proof inspection and processed-cursor publication against
	// sender's active-spool generation rollover. If rollover already won the
	// race, verification fails closed; service activation needs replay-safe
	// publication recovery before that race can be accepted operationally.
	boundary, err := spool.AcquirePublishBoundary()
	if err != nil {
		return false, err
	}
	defer boundary.Close()
	if _, err := usncapture.VerifySpoolPublication(seg, correlation, dir, manifests); err != nil {
		return false, err
	}
	// Persist the exact verified source-manifest inventory while holding the
	// sender publication boundary. A sender rollover cannot relocate these
	// active manifests between verification, inventory and cursor commit.
	// This inventory is not a receiver acknowledgement or replay permission.
	if _, err := store.RecordActiveSourceManifestLedger(seg, correlation, dir, manifests); err != nil {
		return false, fmt.Errorf("record FI source manifest ledger: %w", err)
	}
	// Only custody-verified NTFS results can add observed identity state.
	if _, err := mergeUSNObservedSIDSet(observedSIDs); err != nil {
		return false, err
	}
	if err := store.CommitVerifiedSpool(seg, correlation, dir, manifests); err != nil {
		return false, err
	}
	return true, nil
}

// capturePublicationSIDs rebuilds the source-derived supporting SID set from
// custody-verified FI spool manifests after a Windows collector restart.
// Verification and processing cursor advancement stay under the caller's
// machine-wide publish lock.
func capturePublicationSIDs(manifests []string) (*observedSIDSet, error) {
	set := newObservedSIDSet()
	for _, manifestPath := range manifests {
		verified, err := spool.VerifyManifest(manifestPath)
		if err != nil || !verified.Verified {
			return nil, fmt.Errorf("verify captured USN spool for SID recovery: %v", err)
		}
		f, err := os.Open(verified.DataPath)
		if err != nil {
			return nil, err
		}
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 4096), int(spool.DefaultMaxBatchBytes)+1)
		for scanner.Scan() {
			var record spool.Record
			if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
				f.Close()
				return nil, err
			}
			if record.RecordKind != "USNObjectObservation" {
				continue
			}
			var value struct {
				Status string            `json:"status"`
				NTFS   *ntfs.Observation `json:"ntfs_observation"`
			}
			if err := json.Unmarshal(record.Payload, &value); err != nil {
				f.Close()
				return nil, err
			}
			if value.Status == string(usn.ReobservationObserved) && value.NTFS != nil {
				addNTFSObservationSIDs(set, *value.NTFS)
			}
		}
		err = errors.Join(scanner.Err(), f.Close())
		if err != nil {
			return nil, err
		}
	}
	return set, nil
}
