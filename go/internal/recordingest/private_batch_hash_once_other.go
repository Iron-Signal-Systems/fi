//go:build !freebsd

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the FI Source Review License.
//
// Private SHA-once is a FreeBSD 15+ COW clone trust-handoff experiment.
// Non-FreeBSD builds must never bypass signed batch SHA verification.
package recordingest

import (
    "context"
    "errors"
    "os"
)

type privateVerifiedBatchEvidence struct{}

func privateReuseSignedBatchDigest(context.Context, PreparedBatch, *os.File) (*privateVerifiedBatchEvidence, error) {
    return nil, nil // fail closed: ingestSourceBatch computes original batch SHA
}

func (*privateVerifiedBatchEvidence) check() error {
    return errors.New("FI verified COW handoff unavailable on this operating system")
}
