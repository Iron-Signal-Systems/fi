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
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/process"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/smb"
)

const (
	baselineKindCollectorIdentity = "CollectorIdentity"
	baselineKindSMBShareSnapshot  = "SMBShareSnapshot"
	baselineKindNTFSObservation   = "NTFSObservation"
)

// baselineEvent is the JSON Lines envelope used by the current baseline-root
// command. Each line is independently decodable so a large governed root can
// stream without retaining the full baseline in memory.
type baselineEvent struct {
	Kind                 string                              `json:"kind"`
	CollectorIdentity    *records.ProcessIdentityObservation `json:"collector_identity,omitempty"`
	SMBShareSnapshot     *records.SMBShareSnapshot           `json:"smb_share_snapshot,omitempty"`
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

// writeBaselineRoot collects the process identity once, records the local SMB
// share state once, then walks the governed NTFS root in the same FI process.
//
// Process identity is required. SMB share collection is useful access context
// but is not allowed to discard a valid NTFS baseline; an SMB collection error
// is therefore emitted explicitly and the NTFS walk continues.
func writeBaselineRoot(ctx context.Context, writer io.Writer, governedRoot string) error {
	if ctx == nil {
		ctx = context.Background()
	}

	encoder := json.NewEncoder(writer)

	identity, err := process.CurrentIdentity()
	if err != nil {
		return fmt.Errorf("collector identity: %w", err)
	}
	if err := encoder.Encode(baselineEvent{
		Kind:              baselineKindCollectorIdentity,
		CollectorIdentity: &identity,
	}); err != nil {
		return fmt.Errorf("encode collector identity: %w", err)
	}

	shareSnapshot, shareErr := smb.CollectLocalShares(ctx)
	shareEvent := baselineEvent{Kind: baselineKindSMBShareSnapshot}
	if shareErr != nil {
		shareEvent.Error = shareErr.Error()
	} else {
		shareEvent.SMBShareSnapshot = &shareSnapshot
	}
	if err := encoder.Encode(shareEvent); err != nil {
		return fmt.Errorf("encode SMB share snapshot: %w", err)
	}

	return ntfs.WalkGovernedRoot(
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
}
