// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportsender

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const publishedBatchManifestSuffix = ".manifest.json"
const publishedBatchPrefix = "batch-"
const publishedBatchReadChunk = 4096

// PublishedBatchQueue holds one deterministic snapshot of published Phase 1
// manifests. The queue intentionally does not refresh while entries remain, so
// a backlog drains in the order captured by the snapshot and a failed current
// batch remains the current batch until the caller explicitly advances it.
type PublishedBatchQueue struct {
	manifestPaths []string
	spoolDir      string
}

// Advance removes the current manifest only after the caller has completed the
// transport transaction for that exact path. Calling Advance for any other path
// is rejected so a failed transport cannot accidentally skip a queued batch.
func (queue *PublishedBatchQueue) Advance(manifestPath string) error {
	if queue == nil {
		return errors.New("FI published-batch queue is required")
	}
	if len(queue.manifestPaths) == 0 {
		return errors.New("FI published-batch queue is empty")
	}

	current := queue.manifestPaths[0]
	if filepath.Clean(manifestPath) != current {
		return fmt.Errorf(
			"FI published-batch queue current manifest is %q, not %q",
			current,
			manifestPath,
		)
	}

	queue.manifestPaths[0] = ""
	queue.manifestPaths = queue.manifestPaths[1:]
	return nil
}

// NewPublishedBatchQueue validates the absolute Phase 1 spool directory. The
// first directory snapshot is deferred until Next so construction does not hash
// or inspect any batch payloads.
func NewPublishedBatchQueue(spoolDir string) (*PublishedBatchQueue, error) {
	if spoolDir == "" {
		return nil, errors.New("FI Phase 1 spool directory is required")
	}
	if !filepath.IsAbs(spoolDir) {
		return nil, errors.New("FI Phase 1 spool directory must be absolute")
	}

	clean := filepath.Clean(spoolDir)
	info, err := os.Stat(clean)
	if err != nil {
		return nil, fmt.Errorf("inspect FI Phase 1 spool directory: %w", err)
	}
	if !info.IsDir() {
		return nil, errors.New("FI Phase 1 spool path must name a directory")
	}

	return &PublishedBatchQueue{spoolDir: clean}, nil
}

// Next returns the oldest manifest from the current snapshot. If the snapshot
// is empty, Next takes a new lightweight filename-only snapshot first. It never
// opens or verifies manifest/data contents; authoritative validation remains in
// PrepareOutboundFrame before transport.
func (queue *PublishedBatchQueue) Next() (string, bool, error) {
	if queue == nil {
		return "", false, errors.New("FI published-batch queue is required")
	}

	if len(queue.manifestPaths) == 0 {
		manifestPaths, err := scanPublishedBatchManifests(queue.spoolDir)
		if err != nil {
			return "", false, err
		}
		queue.manifestPaths = manifestPaths
	}

	if len(queue.manifestPaths) == 0 {
		return "", false, nil
	}
	return queue.manifestPaths[0], true, nil
}

func isPublishedBatchManifestName(name string) bool {
	if !strings.HasPrefix(name, publishedBatchPrefix) ||
		!strings.HasSuffix(name, publishedBatchManifestSuffix) {
		return false
	}

	batchID := strings.TrimSuffix(
		strings.TrimPrefix(name, publishedBatchPrefix),
		publishedBatchManifestSuffix,
	)
	return batchID != ""
}

func scanPublishedBatchManifests(spoolDir string) ([]string, error) {
	directory, err := os.Open(spoolDir)
	if err != nil {
		return nil, fmt.Errorf("open FI Phase 1 spool directory: %w", err)
	}
	defer directory.Close()

	manifestPaths := make([]string, 0)
	for {
		entries, readErr := directory.ReadDir(publishedBatchReadChunk)
		for _, entry := range entries {
			if !isPublishedBatchManifestName(entry.Name()) {
				continue
			}
			if entry.Type()&os.ModeSymlink != 0 {
				continue
			}

			info, err := entry.Info()
			if err != nil {
				return nil, fmt.Errorf(
					"inspect FI published-batch queue entry %q: %w",
					entry.Name(),
					err,
				)
			}
			if !info.Mode().IsRegular() {
				continue
			}

			manifestPaths = append(
				manifestPaths,
				filepath.Join(spoolDir, entry.Name()),
			)
		}

		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return nil, fmt.Errorf("scan FI Phase 1 spool directory: %w", readErr)
		}
	}

	sort.Strings(manifestPaths)
	return manifestPaths, nil
}
