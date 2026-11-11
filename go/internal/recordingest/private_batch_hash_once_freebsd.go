//go:build freebsd

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the FI Source Review License.
//
// EXPERIMENTAL PRIVATE-ONLY: reuse the authenticated batch digest from the
// receipt-bound cache while reading a fresh, owned COW clone. This file is
// used by the development branch's private authenticated-cache/COW path.
package recordingest

import (
    "context"
    "errors"
    "fmt"
    "os"
    "path/filepath"
    "syscall"
)

// privateVerifiedBatchEvidence attests the opened *file descriptor*, rather
// than merely a pathname supplied by the caller. Only the unpublished COW
// clones registered by the verified-cache recovery path can qualify.
// It does not hash the data again; trust comes from the previously validated
// cache and the clone-only handoff. A same-inode, same-size undetectable
// mutation remains outside this metadata check; see the experiment document.
type privateVerifiedBatchEvidence struct {
    source deferredFileIdentity
    file *os.File
}

func privateReuseSignedBatchDigest(ctx context.Context, batch PreparedBatch, f *os.File) (*privateVerifiedBatchEvidence, error) {
    deferred := deferredWindowFromContext(ctx)
    if deferred == nil {
        return nil, nil // original canonical and all unproved paths still hash
    }
    if f == nil || deferred.pending == "" || deferred.published {
        return nil, errors.New("FI batch once: private deferred clone not pending")
    }
    if filepath.Dir(batch.DataPath) != deferred.pending {
        return nil, errors.New("FI batch once: source not inside owned private clone")
    }
    if batch.Manifest.DataBytes <= 0 || len(batch.Manifest.DataSHA256) != 64 {
        return nil, errors.New("FI batch once: missing signed batch manifest")
    }
    // The deferred sourceFiles entries are populated ONLY after a successful
    // clone from a previously authenticated, receipt-bound cache and an
    // independent inode identity check.
    var want *deferredFileIdentity
    for i := range deferred.sourceFiles {
        if deferred.sourceFiles[i].path == batch.DataPath {
            if want != nil {
                return nil, errors.New("FI batch once: duplicate clone identity")
            }
            want = &deferred.sourceFiles[i]
        }
    }
    if want == nil || want.size != batch.Manifest.DataBytes {
        return nil, errors.New("FI batch once: missing clone-to-signed-batch binding")
    }
    proof := &privateVerifiedBatchEvidence{source:*want,file:f}
    if err := proof.check(); err != nil {
        return nil, fmt.Errorf("FI batch once: untrusted opened clone: %w",err)
    }
    return proof, nil
}

// check binds the open fd and the published path to the original COW clone
// identity, including size and nanosecond mtime. This is NOT a cryptographic
// substitute for a hash over mutated bytes.
func (p *privateVerifiedBatchEvidence) check() error {
    if p == nil || p.file == nil {
        return errors.New("FI batch once: missing opened clone proof")
    }
    opened, err := p.file.Stat()
    if err != nil {return err}
    native, ok := opened.Sys().(*syscall.Stat_t)
    if !ok || !opened.Mode().IsRegular() || opened.Mode().Perm() != 0600 ||
        uint64(native.Dev)!=p.source.dev || native.Ino!=p.source.ino ||
        opened.Size()!=p.source.size || opened.ModTime().UnixNano()!=p.source.modtime {
        return errors.New("FI batch once: open descriptor changed from verified COW handoff")
    }
    current, err := deferredFileStat(p.source.path)
    if err != nil {return err}
    if current.dev!=p.source.dev || current.ino!=p.source.ino ||
        current.size!=p.source.size || current.modtime!=p.source.modtime {
        return errors.New("FI batch once: clone pathname changed after verified handoff")
    }
    return nil
}
