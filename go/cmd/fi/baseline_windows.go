// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
)

const (
	baselineKindCollectorIdentity   = "CollectorIdentity"
	baselineKindSMBShareSnapshot    = "SMBShareSnapshot"
	baselineKindLocalPrincipals     = "LocalPrincipalSnapshot"
	baselineKindDirectoryPrincipals = "DirectoryPrincipalSnapshot"
	baselineKindNTFSObservation     = "NTFSObservation"
)

// baselineEvent is the JSON Lines envelope used by the current baseline-root
// command. Each line is independently decodable so a large governed root can
// stream without retaining the full baseline in memory.
type baselineEvent struct {
	Kind                 string                              `json:"kind"`
	CollectorIdentity    *records.ProcessIdentityObservation `json:"collector_identity,omitempty"`
	SMBShareSnapshot     *records.SMBShareSnapshot           `json:"smb_share_snapshot,omitempty"`
	LocalPrincipals      *records.LocalPrincipalSnapshot     `json:"local_principal_snapshot,omitempty"`
	DirectoryPrincipals  *records.DirectoryPrincipalSnapshot `json:"directory_principal_snapshot,omitempty"`
	Observation          *ntfs.Observation                   `json:"observation,omitempty"`
	PathDisplay          string                              `json:"path_display,omitempty"`
	PathUTF16LEBase64URL string                              `json:"path_utf16le_base64url,omitempty"`
	Error                string                              `json:"error,omitempty"`
}

func runBaselineRoot(governedRoot string) {
	if err := writeBaselineRoot(context.Background(), os.Stdout, governedRoot); err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
}

// writeBaselineRoot records collector identity, local SMB share state, local
// principals/direct local-group membership, and the governed NTFS baseline.
// While those source facts stream, FI gathers the unique SIDs it actually saw.
// After the NTFS walk completes, those observed current-domain SIDs seed one AD
// snapshot containing principals plus direct AD membership edges.
//
// The NTFS observations continue to stream and are never retained as one giant
// in-memory baseline. Only the bounded unique SID set is retained for the later
// directory lookup.
//
// Process identity is required. SMB, local-identity, and directory collection
// failures are emitted explicitly and do not discard an otherwise valid NTFS
// baseline.
func writeBaselineRoot(ctx context.Context, writer io.Writer, governedRoot string) error {
	if ctx == nil {
		ctx = context.Background()
	}

	encoder := json.NewEncoder(writer)

	supporting, err := collectSupportingSourceContext(ctx)
	if err != nil {
		return err
	}

	if err := encoder.Encode(baselineEvent{
		Kind:              baselineKindCollectorIdentity,
		CollectorIdentity: &supporting.CollectorIdentity,
	}); err != nil {
		return fmt.Errorf("encode collector identity: %w", err)
	}

	shareEvent := baselineEvent{Kind: baselineKindSMBShareSnapshot}
	if supporting.SMBShareError != "" {
		shareEvent.Error = supporting.SMBShareError
	} else {
		shareEvent.SMBShareSnapshot = supporting.SMBShareSnapshot
	}
	if err := encoder.Encode(shareEvent); err != nil {
		return fmt.Errorf("encode SMB share snapshot: %w", err)
	}

	localEvent := baselineEvent{Kind: baselineKindLocalPrincipals}
	if supporting.LocalPrincipalError != "" {
		localEvent.Error = supporting.LocalPrincipalError
	} else {
		localEvent.LocalPrincipals = supporting.LocalPrincipals
	}
	if err := encoder.Encode(localEvent); err != nil {
		return fmt.Errorf("encode local principal snapshot: %w", err)
	}

	walkErr := ntfs.WalkGovernedRoot(
		ctx,
		"manual-test",
		governedRoot,
		func(path string, observation ntfs.Observation, objectErr error) error {
			exactPath, err := pathUTF16LEBase64URL(path)
			if err != nil {
				return fmt.Errorf("encode exact path: %w", err)
			}

			event := baselineEvent{
				Kind:                 baselineKindNTFSObservation,
				PathDisplay:          path,
				PathUTF16LEBase64URL: exactPath,
			}
			if observation.ObservedAt != "" {
				event.Observation = &observation
				addNTFSObservationSIDs(supporting.ObservedSIDs, observation)
			}
			if objectErr != nil {
				event.Error = objectErr.Error()
			}
			if err := encoder.Encode(event); err != nil {
				return fmt.Errorf("encode NTFS observation: %w", err)
			}
			return nil
		},
	)
	if walkErr != nil {
		return walkErr
	}

	directorySource := collectDirectorySource(
		ctx,
		supporting.CollectorIdentity,
		supporting.ObservedSIDs,
	)
	directoryEvent := baselineEvent{Kind: baselineKindDirectoryPrincipals}
	if directorySource.Error != "" {
		directoryEvent.Error = directorySource.Error
	} else {
		directoryEvent.DirectoryPrincipals = directorySource.Snapshot
	}
	if err := encoder.Encode(directoryEvent); err != nil {
		return fmt.Errorf("encode directory principal snapshot: %w", err)
	}

	return nil
}
