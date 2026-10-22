// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package usn

import (
	"errors"
	"sync/atomic"
)

const (
	defaultProcessingChunkObjects = 256
	defaultProcessingMaxInflight  = 32
)

var processingChunkObjects atomic.Int32
var processingMaxInflight atomic.Int32

// ConfigureProcessingBounds sets validated per-process limits. It must run
// before any USN collection begins and is never changed during a live batch.
func ConfigureProcessingBounds(chunkObjects, maxInflight int) error {
	if chunkObjects < 64 || chunkObjects > 2048 {
		return errors.New("collector.usn_processing_chunk_objects must be between 64 and 2048")
	}
	if maxInflight < 1 || maxInflight > 64 {
		return errors.New("collector.usn_processing_max_inflight must be between 1 and 64")
	}
	processingChunkObjects.Store(int32(chunkObjects))
	processingMaxInflight.Store(int32(maxInflight))
	return nil
}

func CurrentProcessingChunkObjects() int {
	if value := processingChunkObjects.Load(); value > 0 {
		return int(value)
	}
	return defaultProcessingChunkObjects
}

func CurrentProcessingMaxInflight() int {
	if value := processingMaxInflight.Load(); value > 0 {
		return int(value)
	}
	return defaultProcessingMaxInflight
}
