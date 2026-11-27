// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, in the repository root LICENSE file.

package recordingest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// MaterializeBacklogWindow makes an independently verifiable, private, durable
// copy of the original signed generation's WHOLE source-batch artifact pairs.
// It NEVER records a successful relational ingest, modifies the signed receipt,
// changes custody, writes PostgreSQL, or publishes anything as authoritative.
//
// This is currently an opt-in engineering seam; the production loader and
// ingestion path do not call it. Full signed custody validation is a PRECONDITION
// supplied by LoadRecordedGeneration, not performed by this function.
func MaterializeBacklogWindow(ctx context.Context, g *PreparedGeneration, limits BacklogWindowLimits, index int, privateRoot string) (string, error) {
	return materializeBacklogWindow(ctx, g, limits, index, privateRoot, false)
}

// materializeBacklogWindow permits a verified hard-link handoff only when the
// continuous private loader itself stages original, authenticated batch data
// inside this same private root. All other callers retain copy-and-hash.
func materializeBacklogWindow(ctx context.Context, g *PreparedGeneration, limits BacklogWindowLimits, index int, privateRoot string, reuseStage bool) (string, error) {
	if ctx == nil {
		return "", errors.New("FI backlog stage: context required")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	descriptors, err := DescribeBacklogWindows(g, limits)
	if err != nil {
		return "", err
	}
	if index < 0 || index >= len(descriptors) {
		return "", errors.New("FI backlog stage: window index out of bounds")
	}
	if err := verifyPrivateBacklogRoot(privateRoot); err != nil {
		return "", err
	}

	d := descriptors[index]
	generationDir := filepath.Join(privateRoot, "receipt-"+d.ReceiptSHA256)
	if err := os.Mkdir(generationDir, 0700); err != nil && !os.IsExist(err) {
		return "", fmt.Errorf("FI backlog stage: create receipt namespace: %w", err)
	}
	if err := verifyPrivateBacklogRoot(generationDir); err != nil {
		return "", err
	}
	ready := filepath.Join(generationDir, fmt.Sprintf("window-%08d", index))
	if _, err := os.Lstat(ready); err == nil {
		if err := VerifyMaterializedBacklogWindow(ctx, g, limits, index, privateRoot); err != nil {
			return "", fmt.Errorf("FI backlog stage: existing window is invalid: %w", err)
		}
		return ready, nil
	} else if !os.IsNotExist(err) {
		return "", err
	}

	tmp, err := os.MkdirTemp(generationDir, ".window-building-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp) // removes only the unpublished, privately owned copy

	var linked, copied int
	if reuseStage {
		// Never link arbitrary custody or caller-owned files into the private
		// durable area. Only a 0700 staging directory created directly under
		// our previously verified privateRoot is eligible.
		if g.stagedDirectory == "" ||
			filepath.Dir(g.stagedDirectory) != privateRoot ||
			!strings.HasPrefix(filepath.Base(g.stagedDirectory), ".fi-backlog-continuous-") {
			return "", errors.New("FI backlog stage: verified reuse requires owned continuous private staging")
		}
		if err := verifyPrivateBacklogRoot(g.stagedDirectory); err != nil {
			return "", err
		}
	}
	for i := d.StartBatch; i < d.EndBatch; i++ {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		b := g.Batches[i]
		dst := filepath.Join(tmp, fmt.Sprintf("batch-%08d.data", i))
		if reuseStage {
			if b.DataPath != filepath.Join(g.stagedDirectory, fmt.Sprintf("batch-%08d.data", i)) {
				return "", fmt.Errorf("FI backlog stage: batch %d is not owned by continuous staging", i)
			}
			usedLink, err := linkVerifiedBacklogStageArtifact(ctx, b.DataPath, dst, b.Manifest.DataBytes, b.Manifest.DataSHA256)
			if err != nil {
				return "", fmt.Errorf("FI backlog stage: data batch %d: %w", i, err)
			}
			if usedLink { linked++ } else { copied++ }
		} else {
			if err := copyBacklogStageArtifact(ctx, b.DataPath, dst, b.Manifest.DataBytes, b.Manifest.DataSHA256); err != nil {
				return "", fmt.Errorf("FI backlog stage: data batch %d: %w", i, err)
			}
			copied++
		}
		if len(b.ManifestRawBytes) == 0 || len(b.ManifestRawBytes) > 1<<20 {
			return "", fmt.Errorf("FI backlog stage: manifest %d outside byte limits", i)
		}
		h := sha256.Sum256(b.ManifestRawBytes)
		if hex.EncodeToString(h[:]) != b.ManifestSHA256 {
			return "", fmt.Errorf("FI backlog stage: manifest %d hash mismatch", i)
		}
		if err := writeBacklogStageFile(filepath.Join(tmp, fmt.Sprintf("batch-%08d.manifest", i)), b.ManifestRawBytes); err != nil {
			return "", err
		}
	}
	raw, err := json.Marshal(d)
	if err != nil {
		return "", err
	}
	if err := writeBacklogStageFile(filepath.Join(tmp, "descriptor.json"), raw); err != nil {
		return "", err
	}
	if err := syncBacklogStageDir(tmp); err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	// A completed window directory is published only after every file was
	// written and synced. Never overwrite an existing completed directory.
	if _, err := os.Lstat(ready); err == nil {
		return "", errors.New("FI backlog stage: concurrent publication conflict")
	} else if !os.IsNotExist(err) {
		return "", err
	}
	if err := os.Rename(tmp, ready); err != nil {
		return "", fmt.Errorf("FI backlog stage: atomic window publication: %w", err)
	}
	if err := syncBacklogStageDir(generationDir); err != nil {
		return "", fmt.Errorf("FI backlog stage: directory sync after publication: %w", err)
	}
	if reuseStage {
		fmt.Printf("FI PRIVATE ARTIFACT HANDOFF window=%d verified_links=%d verified_copy_fallbacks=%d\n", index, linked, copied)
	}
	return ready, nil
}

// VerifyMaterializedBacklogWindow never treats a directory or descriptor as
// authority. It checks original receipt+manifest identity AND every copied
// byte hash before allowing a window to be reused after an interrupted run.
// It still does not prove completed RELATIONAL ingestion or source trust status.
func VerifyMaterializedBacklogWindow(ctx context.Context, g *PreparedGeneration, limits BacklogWindowLimits, index int, privateRoot string) error {
	if ctx == nil {
		return errors.New("FI backlog stage: context required")
	}
	descriptors, err := DescribeBacklogWindows(g, limits)
	if err != nil {
		return err
	}
	if index < 0 || index >= len(descriptors) {
		return errors.New("FI backlog stage: window index out of bounds")
	}
	if err := verifyPrivateBacklogRoot(privateRoot); err != nil {
		return err
	}
	d := descriptors[index]
	generationDir := filepath.Join(privateRoot, "receipt-"+d.ReceiptSHA256)
	if err := verifyPrivateBacklogRoot(generationDir); err != nil {
		return err
	}
	ready := filepath.Join(generationDir, fmt.Sprintf("window-%08d", index))
	if err := verifyPrivateBacklogRoot(ready); err != nil {
		return err
	}
	descriptorPath := filepath.Join(ready, "descriptor.json")
	raw, err := readBacklogStageFile(descriptorPath, 16<<10)
	if err != nil {
		return err
	}
	var got BacklogCheckpointDescriptor
	if err := json.Unmarshal(raw, &got); err != nil {
		return err
	}
	if got != d {
		return errors.New("FI backlog stage: descriptor identity mismatch")
	}
	for i := d.StartBatch; i < d.EndBatch; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := g.Batches[i]
		gotManifest, err := readBacklogStageFile(filepath.Join(ready, fmt.Sprintf("batch-%08d.manifest", i)), 1<<20)
		if err != nil {
			return err
		}
		manifestHash := sha256.Sum256(gotManifest)
		if hex.EncodeToString(manifestHash[:]) != b.ManifestSHA256 {
			return fmt.Errorf("FI backlog stage: manifest hash mismatch at batch %d", i)
		}
		if err := hashBacklogStageFile(ctx, filepath.Join(ready, fmt.Sprintf("batch-%08d.data", i)), b.Manifest.DataBytes, b.Manifest.DataSHA256); err != nil {
			return fmt.Errorf("FI backlog stage: data check at batch %d: %w", i, err)
		}
	}
	return nil
}

func verifyPrivateBacklogRoot(dir string) error {
	if !filepath.IsAbs(dir) {
		return errors.New("FI backlog stage: absolute directory required")
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0700 {
		return fmt.Errorf("FI backlog stage: private directory must be real and 0700: %s (mode=%s permissions=%#o)", dir, info.Mode(), info.Mode().Perm())
	}
	return nil
}

func writeBacklogStageFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	return errors.Join(err, f.Close())
}

func readBacklogStageFile(path string, max int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() < 1 || info.Size() > max {
		return nil, fmt.Errorf("FI backlog stage: file metadata invalid: %s", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	err = errors.Join(err, f.Close())
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != info.Size() {
		return nil, errors.New("FI backlog stage: file changed during read")
	}
	return data, nil
}

func copyBacklogStageArtifact(ctx context.Context, src, dst string, expectedBytes int64, expectedSHA string) error {
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() != expectedBytes {
		return errors.New("FI backlog stage: source data is not an expected regular file")
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(out, h), io.LimitReader(&backlogContextReader{ctx: ctx, r: in}, expectedBytes+1))
	if copyErr == nil && (n != expectedBytes || hex.EncodeToString(h.Sum(nil)) != expectedSHA) {
		copyErr = errors.New("FI backlog stage: source bytes or digest differ from signed manifest")
	}
	if copyErr == nil {
		copyErr = out.Sync()
	}
	return errors.Join(copyErr, out.Close())
}

// linkVerifiedBacklogStageArtifact checks the entire signed SHA-256 and
// syncs the source inode before linking into the new durable window. It never
// changes signed custody. Linking only changes a directory entry: after
// continuous staging cleanup, the durable file remains independently readable
// and verifiable using VerifyMaterializedBacklogWindow on every restart.
// If the filesystem refuses hard links, retain the original copy-and-sync
// implementation. An invalid digest or metadata always fails closed.
func linkVerifiedBacklogStageArtifact(ctx context.Context, src, dst string, expectedBytes int64, expectedSHA string) (bool, error) {
	info, err := os.Lstat(src)
	if err != nil { return false, err }
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 ||
		info.Mode()&os.ModeSymlink != 0 || info.Size() != expectedBytes {
		return false, errors.New("FI backlog stage: invalid continuous stage file")
	}
	if err := hashBacklogStageFile(ctx, src, expectedBytes, expectedSHA); err != nil {
		return false, err
	}
	// Hash and fsync are separate checks: source content must be verified
	// before it can become a persistent directory entry.
	f, err := os.Open(src)
	if err != nil { return false, err }
	opened, statErr := f.Stat()
	syncErr := error(nil)
	if statErr == nil && !os.SameFile(info, opened) {
		statErr = errors.New("FI backlog stage: source replaced before durable handoff")
	}
	if statErr == nil {
		syncErr = f.Sync()
	}
	closeErr := f.Close()
	if err := errors.Join(statErr, syncErr, closeErr); err != nil {
		return false, err
	}
	if err := os.Link(src, dst); err != nil {
		if errCopy := copyBacklogStageArtifact(ctx, src, dst, expectedBytes, expectedSHA); errCopy != nil {
			return false, fmt.Errorf("FI backlog stage: link failed (%v), copy fallback: %w", err, errCopy)
		}
		return false, nil
	}
	linked, err := os.Lstat(dst)
	if err != nil { return false, err }
	if !os.SameFile(info, linked) || linked.Mode().Perm() != 0600 ||
		linked.Size() != expectedBytes {
		return false, errors.New("FI backlog stage: linked durable inode identity changed")
	}
	return true, nil
}

func hashBacklogStageFile(ctx context.Context, path string, expectedBytes int64, expectedSHA string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() != expectedBytes {
		return errors.New("FI backlog stage: data metadata mismatch")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, hashErr := io.Copy(h, io.LimitReader(&backlogContextReader{ctx: ctx, r: f}, expectedBytes+1))
	hashErr = errors.Join(hashErr, f.Close())
	if hashErr != nil {
		return hashErr
	}
	if n != expectedBytes || hex.EncodeToString(h.Sum(nil)) != expectedSHA {
		return errors.New("FI backlog stage: staged data digest mismatch")
	}
	return nil
}

type backlogContextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *backlogContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}
func syncBacklogStageDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}
