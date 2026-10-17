// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package quarantinekeeper

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const (
	keeperMarkerVersion  = "fi-ingest-source-quarantine/0.1"
	keeperMarkerMaxBytes = 16384
)

// QuarantineMarker uses the existing FI marker representation so a later
// independently reviewed migration can preserve recorded marker identities.
// These markers are owned by the keeper, not by the ingestion worker.
type QuarantineMarker struct {
	CreatedAtUTC string `json:"created_at_utc"`
	Detail       string `json:"detail"`
	GenerationID string `json:"generation_id,omitempty"`
	Reason       string `json:"reason"`
	SourceID     string `json:"source_id"`
	Version      string `json:"version"`
}

// KeeperStore is a keeper-process-only authority. Root must already exist
// with mode 0700 and belong to the distinct unprivileged keeper UID/GID.
// The directory's immediate parent must not be writable by other identities.
// The worker never receives a directory FD, path access, or release operation.
type KeeperStore struct {
	root      string
	keeperUID uint32
	keeperGID uint32
	enrolled  map[string]bool
	mu        sync.Mutex
}

func NewKeeperStore(root string, keeperUID, keeperGID uint32, enrolled []string) (*KeeperStore, error) {
	if keeperUID == 0 || uint32(os.Geteuid()) != keeperUID ||
		uint32(os.Getegid()) != keeperGID {
		return nil, errors.New("quarantine keeper requires its dedicated non-root identity")
	}
	if len(enrolled) == 0 {
		return nil, errors.New("quarantine keeper requires enrolled sources")
	}
	store := &KeeperStore{
		root:      root,
		keeperUID: keeperUID,
		keeperGID: keeperGID,
		enrolled:  make(map[string]bool, len(enrolled)),
	}
	for _, source := range enrolled {
		if !validSourceID(source) || store.enrolled[source] {
			return nil, fmt.Errorf("invalid or duplicate keeper source %q", source)
		}
		store.enrolled[source] = true
	}
	fd, err := store.openRoot()
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	if _, err = store.readInventory(fd); err != nil {
		return nil, err
	}
	return store, nil
}

// Handle implements WorkerHandler after the caller has authenticated the
// FreeBSD Unix peer. It never interprets a request as an authorization to
// release, change enrollment, or replace an existing marker.
func (store *KeeperStore) Handle(ctx context.Context, request Request) (Response, error) {
	if ctx == nil || store == nil {
		return Response{}, errors.New("missing quarantine keeper context or store")
	}
	if err := ctx.Err(); err != nil {
		return Response{}, err
	}
	if err := request.Validate(); err != nil {
		return Response{}, err
	}
	if !store.enrolled[request.SourceID] {
		return Response{}, errors.New("quarantine request source is not enrolled")
	}
	if request.Operation == OperationPublish &&
		request.Reason != "RELATIONAL_CONFLICT" &&
		request.Reason != "RECORDED_RECEIPT_INVALID" {
		return Response{}, errors.New("unsupported keeper quarantine reason")
	}

	store.mu.Lock()
	defer store.mu.Unlock()

	fd, err := store.openRoot()
	if err != nil {
		return Response{}, err
	}
	defer unix.Close(fd)

	// Validate every marker on every request; unknown sources, unexpected
	// directory entries, malformed markers, and abandoned temp files fail
	// closed rather than treating an unverifiable inventory as clear.
	markers, err := store.readInventory(fd)
	if err != nil {
		return Response{}, err
	}
	if err := ctx.Err(); err != nil {
		return Response{}, err
	}

	response := Response{Version: ProtocolVersion, SourceID: request.SourceID}
	if _, exists := markers[request.SourceID]; exists {
		response.Status = StatusQuarantined
		return response, nil
	}
	if request.Operation == OperationRead {
		response.Status = StatusClear
		return response, nil
	}
	if err := store.publish(fd, request); err != nil {
		return Response{}, err
	}
	// The publication and parent directory are synced before acknowledgment.
	// An expired caller may retry: publication is immutable and idempotent.
	if err := ctx.Err(); err != nil {
		return Response{}, err
	}
	response.Status = StatusQuarantined
	return response, nil
}

func (store *KeeperStore) openRoot() (int, error) {
	if store.root == "" || !filepath.IsAbs(store.root) ||
		filepath.Clean(store.root) != store.root ||
		store.keeperUID == 0 ||
		uint32(os.Geteuid()) != store.keeperUID ||
		uint32(os.Getegid()) != store.keeperGID {
		return -1, errors.New("invalid keeper storage identity or root")
	}
	resolved, err := filepath.EvalSymlinks(store.root)
	if err != nil {
		return -1, err
	}
	if resolved != store.root {
		return -1, errors.New("keeper storage path traverses a symlink")
	}
	parentFD, err := unix.Open(filepath.Dir(store.root),
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	defer unix.Close(parentFD)
	var parent unix.Stat_t
	if err := unix.Fstat(parentFD, &parent); err != nil {
		return -1, err
	}
	if parent.Mode&unix.S_IFMT != unix.S_IFDIR ||
		parent.Mode&0022 != 0 ||
		(parent.Uid != 0 && parent.Uid != store.keeperUID) {
		return -1, errors.New("keeper storage parent is not protected")
	}
	fd, err := unix.Openat(parentFD, filepath.Base(store.root),
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	var info unix.Stat_t
	if err := unix.Fstat(fd, &info); err != nil {
		unix.Close(fd)
		return -1, err
	}
	if info.Mode&unix.S_IFMT != unix.S_IFDIR ||
		info.Mode&07777 != 0700 ||
		info.Uid != store.keeperUID ||
		info.Gid != store.keeperGID {
		unix.Close(fd)
		return -1, errors.New("keeper quarantine directory ownership or mode mismatch")
	}
	return fd, nil
}

func (store *KeeperStore) readInventory(fd int) (map[string]QuarantineMarker, error) {
	dup, err := unix.Dup(fd)
	if err != nil {
		return nil, err
	}
	directory := os.NewFile(uintptr(dup), "keeper quarantine directory")
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return nil, err
	}

	result := make(map[string]QuarantineMarker, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".json") ||
			!store.enrolled[strings.TrimSuffix(name, ".json")] {
			return nil, fmt.Errorf("unrecognized keeper quarantine directory object %q", name)
		}
		source := strings.TrimSuffix(name, ".json")
		marker, err := store.readMarker(fd, name, source)
		if err != nil {
			return nil, err
		}
		result[source] = marker
	}
	return result, nil
}

func (store *KeeperStore) readMarker(fd int, name, source string) (QuarantineMarker, error) {
	var marker QuarantineMarker
	var before unix.Stat_t
	if err := unix.Fstatat(fd, name, &before, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return marker, err
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG ||
		before.Mode&07777 != 0400 ||
		before.Uid != store.keeperUID ||
		before.Gid != store.keeperGID || before.Nlink != 1 ||
		before.Size <= 0 || before.Size > keeperMarkerMaxBytes {
		return marker, errors.New("unsafe keeper quarantine marker metadata")
	}
	markerFD, err := unix.Openat(fd, name,
		unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return marker, err
	}
	file := os.NewFile(uintptr(markerFD), name)
	var opened unix.Stat_t
	statErr := unix.Fstat(markerFD, &opened)
	if statErr != nil || !sameMarker(before, opened) {
		_ = file.Close()
		return marker, errors.New("keeper quarantine marker changed during open")
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, keeperMarkerMaxBytes+1))
	closeErr := file.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return marker, err
	}
	var after unix.Stat_t
	if err := unix.Fstatat(fd, name, &after, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return marker, err
	}
	if !sameMarker(before, after) || int64(len(raw)) != before.Size {
		return marker, errors.New("keeper quarantine marker changed during read")
	}
	if err := validateStrictObject(raw, []string{
		"created_at_utc", "detail", "generation_id", "reason", "source_id", "version",
	}); err != nil {
		return marker, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&marker); err != nil {
		return marker, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return marker, errors.New("trailing keeper marker content")
	}
	if marker.Version != keeperMarkerVersion || marker.SourceID != source ||
		(marker.Reason != "RELATIONAL_CONFLICT" && marker.Reason != "RECORDED_RECEIPT_INVALID") ||
		!validGenerationID(marker.GenerationID) || marker.Detail == "" ||
		len(marker.Detail) > 4096 {
		return marker, errors.New("invalid keeper quarantine marker content")
	}
	if _, err := time.Parse(time.RFC3339Nano, marker.CreatedAtUTC); err != nil {
		return marker, errors.New("invalid keeper quarantine marker timestamp")
	}
	return marker, nil
}

func sameMarker(first, second unix.Stat_t) bool {
	return first.Dev == second.Dev && first.Ino == second.Ino &&
		first.Uid == second.Uid && first.Gid == second.Gid &&
		first.Mode == second.Mode && first.Nlink == second.Nlink &&
		first.Size == second.Size
}

func (store *KeeperStore) publish(fd int, request Request) error {
	var suffix [16]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return err
	}
	temp := ".keeper-" + hex.EncodeToString(suffix[:]) + ".pending"
	target := request.SourceID + ".json"
	tmpFD, err := unix.Openat(fd, temp,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0600)
	if err != nil {
		return err
	}
	defer unix.Unlinkat(fd, temp, 0)
	marker := QuarantineMarker{
		CreatedAtUTC: time.Now().UTC().Format(time.RFC3339Nano),
		Detail:       request.Detail,
		GenerationID: request.GenerationID,
		Reason:       request.Reason,
		SourceID:     request.SourceID,
		Version:      keeperMarkerVersion,
	}
	raw, err := json.Marshal(marker)
	if err != nil {
		unix.Close(tmpFD)
		return err
	}
	raw = append(raw, '\n')
	file := os.NewFile(uintptr(tmpFD), temp)
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
	if err := unix.Linkat(fd, temp, fd, target, 0); err != nil {
		// A preexisting marker can never be overwritten or auto-released.
		// Treat concurrent publication as a failure requiring reread.
		return fmt.Errorf("publish keeper quarantine marker: %w", err)
	}
	if err := unix.Unlinkat(fd, temp, 0); err != nil {
		return err
	}
	return unix.Fsync(fd)
}
