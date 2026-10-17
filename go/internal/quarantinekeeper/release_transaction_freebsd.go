// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package quarantinekeeper

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const keeperReleaseAuditVersion = "fi-ingest-quarantine-release/0.1"

// KeeperReleaseRequest is never a worker protocol message. A future,
// independently authenticated administrative endpoint must construct it only
// after verifying the caller's kernel credentials and acquiring the protected
// singleton lock. The marker store does not infer operator authorization.
type KeeperReleaseRequest struct {
	SourceID      string
	ConfirmSource string
	Reference     string
	Justification string
	OperatorUID   uint32
}

type keeperReleaseAudit struct {
	Version              string           `json:"version"`
	OperationID          string           `json:"operation_id"`
	Phase                string           `json:"phase"`
	SourceID             string           `json:"source_id"`
	OperatorUID          uint32           `json:"operator_uid"`
	Reference            string           `json:"reference"`
	Reason               string           `json:"reason"`
	RequestedAtUTC       string           `json:"requested_at_utc"`
	ReleasedAtUTC        string           `json:"released_at_utc,omitempty"`
	OriginalMarker       QuarantineMarker `json:"original_marker"`
	OriginalMarkerSHA256 string           `json:"original_marker_sha256"`
}

func validateKeeperReleaseRequest(req KeeperReleaseRequest) error {
	if !validSourceID(req.SourceID) || req.ConfirmSource != req.SourceID {
		return errors.New("keeper release requires exact source confirmation")
	}
	if req.OperatorUID != 0 {
		return errors.New("keeper release requires independently authenticated root peer")
	}
	for _, field := range []struct {
		value string
		max   int
	}{
		{req.Reference, 256}, {req.Justification, 2048},
	} {
		if strings.TrimSpace(field.value) == "" || len(field.value) > field.max ||
			strings.ContainsAny(field.value, "\x00\r\n") {
			return errors.New("keeper release requires bounded change reference and justification")
		}
	}
	return nil
}

// releaseTransaction is the keeper-owned storage transaction. It must NEVER
// be dispatched through Handle or the worker-facing socket. Its caller must
// hold the protected singleton inode flock for its entire duration and must
// have verified a root Unix peer on an independent administrative endpoint.
//
// The durable intent is written before marker unlink. A quarantine-directory
// guard makes interrupted releases fail closed at every subsequent startup
// and worker read until separately reviewed. There is no automatic repair.
func (store *KeeperStore) releaseTransaction(
	ctx context.Context, historyRoot string, req KeeperReleaseRequest,
) (string, error) {
	if store == nil || ctx == nil {
		return "", errors.New("missing keeper release store or context")
	}
	if err := validateKeeperReleaseRequest(req); err != nil {
		return "", err
	}
	if !store.enrolled[req.SourceID] {
		return "", errors.New("keeper release source is not enrolled")
	}

	store.mu.Lock()
	defer store.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return "", err
	}
	quarantineFD, err := store.openRoot()
	if err != nil {
		return "", err
	}
	defer unix.Close(quarantineFD)
	markers, err := store.readInventory(quarantineFD)
	if err != nil {
		return "", err
	}
	marker, ok := markers[req.SourceID]
	if !ok {
		return "", errors.New("keeper release source is not quarantined")
	}

	historyFD, err := store.openReleaseHistory(historyRoot)
	if err != nil {
		return "", err
	}
	defer unix.Close(historyFD)

	name := req.SourceID + ".json"
	var before unix.Stat_t
	if err := unix.Fstatat(quarantineFD, name, &before, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return "", err
	}
	// readMarker already checked the full schema and exact metadata.
	if _, err := store.readMarker(quarantineFD, name, req.SourceID); err != nil {
		return "", err
	}
	fd, err := unix.Openat(quarantineFD, name,
		unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return "", err
	}
	file := os.NewFile(uintptr(fd), name)
	raw, readErr := io.ReadAll(io.LimitReader(file, keeperMarkerMaxBytes+1))
	closeErr := file.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return "", err
	}
	var after unix.Stat_t
	if err := unix.Fstatat(quarantineFD, name, &after, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return "", err
	}
	if !sameMarker(before, after) || int64(len(raw)) != before.Size {
		return "", errors.New("keeper release marker changed during audit inspection")
	}
	hash := sha256.Sum256(raw)
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	operationID := hex.EncodeToString(nonce[:])
	audit := keeperReleaseAudit{
		Version: keeperReleaseAuditVersion, OperationID: operationID,
		Phase: "intent", SourceID: req.SourceID, OperatorUID: req.OperatorUID,
		Reference: req.Reference, Reason: req.Justification,
		RequestedAtUTC: time.Now().UTC().Format(time.RFC3339Nano),
		OriginalMarker: marker, OriginalMarkerSHA256: hex.EncodeToString(hash[:]),
	}
	intentName := "release-" + operationID + ".intent.json"
	if err := keeperPublishAudit(historyFD, intentName, audit); err != nil {
		return "", fmt.Errorf("durably record release intent: %w", err)
	}

	// A guard in the marker inventory prevents a crash during release from
	// making the source appear clear. Its name intentionally fails the strict
	// keeper inventory check. Any stranded guard requires operator review.
	guardName := ".release-" + operationID + ".pending"
	guardFD, err := unix.Openat(quarantineFD, guardName,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0400)
	if err != nil {
		return "", err
	}
	guard := os.NewFile(uintptr(guardFD), guardName)
	if _, err := guard.Write([]byte(operationID + "\n")); err != nil {
		_ = guard.Close()
		return "", err
	}
	if err := guard.Sync(); err != nil {
		_ = guard.Close()
		return "", err
	}
	if err := guard.Close(); err != nil {
		return "", err
	}
	if err := unix.Fsync(quarantineFD); err != nil {
		return "", err
	}

	// Never remove an inode different from the audited marker.
	if err := ctx.Err(); err != nil {
		return "", err
	}
	var current unix.Stat_t
	if err := unix.Fstatat(quarantineFD, name, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return "", err
	}
	if !sameMarker(before, current) {
		return "", errors.New("keeper release marker identity changed before unlink")
	}
	if err := unix.Unlinkat(quarantineFD, name, 0); err != nil {
		return "", err
	}
	if err := unix.Fsync(quarantineFD); err != nil {
		return "", err
	}

	audit.Phase = "complete"
	audit.ReleasedAtUTC = time.Now().UTC().Format(time.RFC3339Nano)
	completeName := "release-" + operationID + ".complete.json"
	if err := keeperPublishAudit(historyFD, completeName, audit); err != nil {
		return "", fmt.Errorf("release completed but final audit failed; quarantine guard retained: %w", err)
	}
	if err := unix.Unlinkat(quarantineFD, guardName, 0); err != nil {
		return "", err
	}
	if err := unix.Fsync(quarantineFD); err != nil {
		return "", err
	}
	return filepath.Join(historyRoot, completeName), nil
}

func (store *KeeperStore) openReleaseHistory(root string) (int, error) {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root ||
		filepath.Dir(root) != filepath.Dir(store.root) || root == store.root {
		return -1, errors.New("keeper history requires a sibling absolute directory")
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return -1, err
	}
	if resolved != root {
		return -1, errors.New("keeper history path traverses a symlink")
	}
	parentFD, err := unix.Open(filepath.Dir(root),
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	defer unix.Close(parentFD)
	var parent unix.Stat_t
	if err := unix.Fstat(parentFD, &parent); err != nil {
		return -1, err
	}
	if parent.Mode&unix.S_IFMT != unix.S_IFDIR || parent.Mode&0022 != 0 ||
		(parent.Uid != 0 && parent.Uid != store.keeperUID) {
		return -1, errors.New("keeper release history parent is not protected")
	}
	fd, err := unix.Openat(parentFD, filepath.Base(root),
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	var info unix.Stat_t
	if err := unix.Fstat(fd, &info); err != nil {
		unix.Close(fd)
		return -1, err
	}
	if info.Mode&unix.S_IFMT != unix.S_IFDIR || info.Mode&07777 != 0700 ||
		info.Uid != store.keeperUID || info.Gid != store.keeperGID {
		unix.Close(fd)
		return -1, errors.New("keeper release history ownership or mode mismatch")
	}
	return fd, nil
}

func keeperPublishAudit(dirFD int, name string, audit keeperReleaseAudit) error {
	raw, err := json.Marshal(audit)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	temp := ".audit-" + hex.EncodeToString(nonce[:]) + ".pending"
	fd, err := unix.Openat(dirFD, temp,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	defer unix.Unlinkat(dirFD, temp, 0)
	file := os.NewFile(uintptr(fd), temp)
	if _, err := file.Write(raw); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Chmod(0400); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := unix.Linkat(dirFD, temp, dirFD, name, 0); err != nil {
		return err
	}
	if err := unix.Unlinkat(dirFD, temp, 0); err != nil {
		return err
	}
	return unix.Fsync(dirFD)
}
