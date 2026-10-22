// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package usn

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
)

// StagedReobservations owns temporary, non-authoritative observation bodies.
// The FI verified spool, not this temporary file, is the custody boundary.
// Call Close on every returned stage, including after an error downstream.
type StagedReobservations struct {
	file      *os.File
	path      string
	positions map[records.NTFSObjectIdentity]stagedPosition
}

type stagedPosition struct {
	offset int64
	length int64
	digest [32]byte
}

type stagedObservation struct {
	index int
	value ChangeReobservation
}

// Read returns an exact recorded observation, never a re-observation of a
// potentially changed NTFS object. A missing/corrupt staging entry fails the
// overall source range before its USN checkpoint can advance.
func (stage *StagedReobservations) Read(identity records.NTFSObjectIdentity) (ChangeReobservation, error) {
	if stage == nil || stage.file == nil {
		return ChangeReobservation{}, errors.New("USN observation stage is not open")
	}
	position, ok := stage.positions[identity]
	if !ok {
		return ChangeReobservation{}, fmt.Errorf("USN observation stage missing object %v", identity)
	}
	if position.length <= 0 {
		return ChangeReobservation{}, errors.New("staged USN record length is invalid")
	}
	raw := make([]byte, int(position.length))
	if _, err := stage.file.ReadAt(raw, position.offset); err != nil {
		return ChangeReobservation{}, fmt.Errorf("read staged USN observation: %w", err)
	}
	if sha256.Sum256(raw) != position.digest {
		return ChangeReobservation{}, errors.New("staged USN observation checksum mismatch")
	}
	var value ChangeReobservation
	if err := json.Unmarshal(raw, &value); err != nil {
		return ChangeReobservation{}, fmt.Errorf("decode staged USN observation: %w", err)
	}
	if value.FileIdentity != identity {
		return ChangeReobservation{}, errors.New("staged USN object identity mismatch")
	}
	return value, nil
}

func (stage *StagedReobservations) Close() error {
	if stage == nil {
		return nil
	}
	var err error
	if stage.file != nil {
		err = stage.file.Close()
		stage.file = nil
	}
	if stage.path != "" {
		err = errors.Join(err, os.Remove(stage.path))
		stage.path = ""
	}
	return err
}

// stageReobservationBatch holds at most maxInflight heavyweight worker results
// concurrently; all completed bodies are immediately serialized to a private
// staging file, while small scope-decision metadata is kept in original order.
// This does not drop SACLs, hashes, streams, USN facts, or fallback results.
func stageReobservationBatch(
	ctx context.Context,
	governedRoot string,
	batch records.USNReadBatch,
	stageDir string,
	workers, chunkObjects, maxInflight int,
	collect fileReferenceCollector,
	observeBackup backupObjectObserver,
	checkContainment containmentChecker,
) (ReobservationBatch, *StagedReobservations, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if workers < 1 || workers > MaxReobserveWorkers || chunkObjects < 64 || chunkObjects > 2048 || maxInflight < 1 || maxInflight > 64 {
		return ReobservationBatch{}, nil, errors.New("invalid bounded USN re-observation configuration")
	}
	file, err := os.CreateTemp(stageDir, ".fi-usn-observations-*.tmp")
	if err != nil {
		return ReobservationBatch{}, nil, fmt.Errorf("create FI observation stage: %w", err)
	}
	stage := &StagedReobservations{
		file: file, path: file.Name(),
		positions: make(map[records.NTFSObjectIdentity]stagedPosition),
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = stage.Close()
		}
	}()

	candidates := distinctReobservationCandidates(batch.Records)
	output := ReobservationBatch{
		USNBatch:       batch,
		Reobservations: make([]ChangeReobservation, len(candidates)),
	}
	if workers > maxInflight {
		workers = maxInflight
	}
	if workers > len(candidates) {
		workers = len(candidates)
	}
	if workers == 0 {
		if err := file.Sync(); err != nil {
			return ReobservationBatch{}, nil, err
		}
		cleanup = false
		return output, stage, nil
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan int)
	results := make(chan stagedObservation)
	permits := make(chan struct{}, maxInflight)
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for index := range jobs {
				observation := reobserveCandidate(ctx, governedRoot, batch.ScopeID, candidates[index], collect, observeBackup, checkContainment)
				results <- stagedObservation{index: index, value: observation}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for index := range candidates {
			select {
			case permits <- struct{}{}:
			case <-ctx.Done():
				return
			}
			select {
			case jobs <- index:
			case <-ctx.Done():
				<-permits
				return
			}
		}
	}()
	go func() { wg.Wait(); close(results) }()

	buffered := bufio.NewWriterSize(file, 256*1024)
	var offset int64
	completed := 0
	var stageErr error
	for item := range results {
		if stageErr == nil {
			raw, encodeErr := json.Marshal(item.value)
			if encodeErr != nil {
				stageErr = fmt.Errorf("encode staged USN observation: %w", encodeErr)
			} else {
				raw = append(raw, '\n')
				if _, writeErr := buffered.Write(raw); writeErr != nil {
					stageErr = fmt.Errorf("write staged USN observation: %w", writeErr)
				} else {
					identity := item.value.FileIdentity
					stage.positions[identity] = stagedPosition{offset: offset, length: int64(len(raw)), digest: sha256.Sum256(raw)}
					offset += int64(len(raw))
					// Preserve exact trigger records, result codes and original
					// order, but never retain the heavyweight observation body.
					light := item.value
					if light.Observation != nil {
						light.Observation = &ntfs.Observation{}
					}
					output.Reobservations[item.index] = light
					completed++
					if completed%chunkObjects == 0 {
						if flushErr := buffered.Flush(); flushErr != nil {
							stageErr = flushErr
						}
					}
				}
			}
			if stageErr != nil {
				cancel()
			}
		}
		<-permits
	}
	if stageErr != nil {
		return ReobservationBatch{}, nil, stageErr
	}
	if err := ctx.Err(); err != nil {
		return ReobservationBatch{}, nil, err
	}
	if completed != len(candidates) {
		return ReobservationBatch{}, nil, errors.New("incomplete staged USN re-observation")
	}
	if err := buffered.Flush(); err != nil {
		return ReobservationBatch{}, nil, fmt.Errorf("flush staged USN observations: %w", err)
	}
	if err := file.Sync(); err != nil {
		return ReobservationBatch{}, nil, fmt.Errorf("sync staged USN observations: %w", err)
	}
	cleanup = false
	return output, stage, nil
}
