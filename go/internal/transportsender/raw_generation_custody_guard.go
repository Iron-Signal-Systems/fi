// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportsender

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
)

// ErrSourceCustodyHandoffRequired prohibits retiring frozen USN source bytes
// while M5D/M5E sender handoff has no integrated authorization transaction.
// It does not grant a future caller any way to waive the guard.
var ErrSourceCustodyHandoffRequired = errors.New("FI captured USN generation requires durable custody handoff before raw retirement")

// guardRawGenerationRetirement is a development-stage safety fence, not a
// completed sender handoff. The caller already validated the frozen generation
// root and exclusively owns its immutable files. It checks every manifested
// data file rather than assuming the original capture batch still exists.
//
// Once M5D/M5E retirement authorization is integrated, this guard must be
// replaced by exact sealed-generation and source-ledger verification, not by
// deleting it or bypassing its failure.
func guardRawGenerationRetirement(rawDir string) error {
	entries, err := os.ReadDir(rawDir)
	if err != nil {
		return err
	}
	manifestCount := 0
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "batch-") ||
			!strings.HasSuffix(entry.Name(), ".manifest.json") {
			continue
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("FI raw generation manifest %q is not a regular file", entry.Name())
		}
		manifestCount++
		verified, err := spool.VerifyManifest(filepath.Join(rawDir, entry.Name()))
		if err != nil {
			return fmt.Errorf("verify FI raw generation manifest %q before retirement: %w", entry.Name(), err)
		}
		if !verified.Verified {
			return fmt.Errorf("FI raw generation manifest %q did not verify", entry.Name())
		}
		info, err := os.Lstat(verified.DataPath)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("FI raw generation data %q is not a regular file", verified.DataPath)
		}
		if err := inspectRawRetirementRecords(verified.DataPath); err != nil {
			return fmt.Errorf("inspect %s: %w", entry.Name(), err)
		}
	}
	if manifestCount == 0 {
		return errors.New("FI raw generation has no verified manifests")
	}
	return nil
}

// inspectRawRetirementRecords reads bounded JSONL records. Both the USN
// boundary and its object observations require handoff; an absent or corrupt
// source digest is a failure, never permission to discard a generation.
func inspectRawRetirementRecords(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), int(spool.DefaultMaxBatchBytes)+1)
	for scanner.Scan() {
		var record struct {
			RecordKind string `json:"record_kind"`
			Payload    struct {
				SourceBatchSHA256 string `json:"source_batch_sha256"`
			} `json:"payload"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			return fmt.Errorf("malformed FI raw generation record: %w", err)
		}
		switch record.RecordKind {
		case "USNReadBoundary", "USNObjectObservation":
			if len(record.Payload.SourceBatchSHA256) != 64 {
				return errors.New("FI USN source record lacks a full source-batch digest")
			}
			return ErrSourceCustodyHandoffRequired
		}
	}
	return scanner.Err()
}
