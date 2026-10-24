// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build !freebsd

package recordingest

import (
	"os"
	"time"
)

// Other platforms retain existing staging semantics. Only FreeBSD backend
// ingesters create/reconcile lease-marked stages.
func newGenerationStageLease(string) (*os.File, error)                    { return nil, nil }
func ReclaimAbandonedGenerationStages(string, time.Duration) (int, error) { return 0, nil }
