// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/workerlock"
)

const m1ReleaseVersion = "fi-ingest-quarantine-release/0.1"

type m1QuarantineReleaseRequest struct {
	EnrolledSources []string
	HistoryRoot     string
	LockFile        string
	Operator        string
	QuarantineRoot  string
	Reason          string
	Reference       string
	SourceID        string
}

type m1QuarantineReleaseRecord struct {
	Marker        m1QuarantineMarker `json:"original_marker"`
	MarkerSHA256  string             `json:"original_marker_sha256"`
	Operator      string             `json:"operator"`
	Reason        string             `json:"reason"`
	Reference     string             `json:"reference"`
	ReleasedAtUTC string             `json:"released_at_utc"`
	SourceID      string             `json:"source_id"`
	Version       string             `json:"version"`
}

// m1ReleaseQuarantinedSource may only be called while the worker
// singleton lock is available. A durable audit record must exist
// before the quarantine marker can be removed.
//
// This is an internal operation, not a worker CLI command.
func m1ReleaseQuarantinedSource(
	request m1QuarantineReleaseRequest,
) (auditPath string, returnErr error) {
	if err := m1ValidateQuarantineReleaseRequest(request); err != nil {
		return "", err
	}

	singleton, err := workerlock.Acquire(request.LockFile)
	if err != nil {
		return "", fmt.Errorf(
			"acquire FI worker lock for quarantine release: %w",
			err,
		)
	}
	defer func() {
		returnErr = errors.Join(returnErr, singleton.Close())
	}()

	store := m1QuarantineStore{Root: request.QuarantineRoot}

	markers, err := store.Load(request.EnrolledSources)
	if err != nil {
		return "", fmt.Errorf(
			"verify quarantine inventory before release: %w",
			err,
		)
	}

	marker, present := markers[request.SourceID]
	if !present {
		return "", fmt.Errorf(
			"FI source %q has no quarantine marker to release",
			request.SourceID,
		)
	}

	if err := m1ValidateReleaseHistoryRoot(
		request.HistoryRoot,
	); err != nil {
		return "", err
	}

	markerPath, err := store.markerPath(request.SourceID)
	if err != nil {
		return "", err
	}

	before, err := os.Lstat(markerPath)
	if err != nil {
		return "", err
	}

	raw, err := os.ReadFile(markerPath)
	if err != nil {
		return "", err
	}

	after, err := os.Lstat(markerPath)
	if err != nil {
		return "", err
	}

	if !os.SameFile(before, after) ||
		int64(len(raw)) != before.Size() {
		return "", errors.New(
			"FI quarantine marker changed during release inspection",
		)
	}

	digest := sha256.Sum256(raw)

	release := m1QuarantineReleaseRecord{
		Marker:        marker,
		MarkerSHA256:  hex.EncodeToString(digest[:]),
		Operator:      request.Operator,
		Reason:        request.Reason,
		Reference:     request.Reference,
		ReleasedAtUTC: time.Now().UTC().Format(time.RFC3339Nano),
		SourceID:      request.SourceID,
		Version:       m1ReleaseVersion,
	}

	// Audit publication is deliberately before marker removal.
	auditPath, err = m1WriteQuarantineReleaseAudit(
		request.HistoryRoot,
		release,
	)
	if err != nil {
		return "", fmt.Errorf(
			"persist FI quarantine release audit: %w",
			err,
		)
	}

	// Reject a marker replacement even after audit publication.
	current, err := os.Lstat(markerPath)
	if err != nil {
		return auditPath, err
	}

	if !os.SameFile(before, current) {
		return auditPath, errors.New(
			"FI quarantine marker changed before release",
		)
	}

	if err := os.Remove(markerPath); err != nil {
		return auditPath, fmt.Errorf(
			"remove reviewed FI quarantine marker: %w",
			err,
		)
	}

	directory, err := os.Open(request.QuarantineRoot)
	if err != nil {
		return auditPath, err
	}

	syncErr := directory.Sync()
	closeErr := directory.Close()

	if err := errors.Join(syncErr, closeErr); err != nil {
		return auditPath, fmt.Errorf(
			"synchronize FI quarantine release: %w",
			err,
		)
	}

	return auditPath, nil
}

func m1ValidateQuarantineReleaseRequest(
	request m1QuarantineReleaseRequest,
) error {
	if !m1ValidQuarantineSource(request.SourceID) {
		return errors.New("FI release source identity is invalid")
	}

	for _, value := range []struct {
		name  string
		value string
		limit int
	}{
		{"operator", request.Operator, 256},
		{"reference", request.Reference, 256},
		{"reason", request.Reason, 2048},
	} {
		if strings.TrimSpace(value.value) == "" ||
			len(value.value) > value.limit ||
			strings.ContainsAny(value.value, "\r\n") {
			return fmt.Errorf(
				"FI quarantine release %s is invalid",
				value.name,
			)
		}
	}

	paths := []string{
		request.QuarantineRoot,
		request.HistoryRoot,
		request.LockFile,
	}

	for _, path := range paths {
		if path == "" ||
			!filepath.IsAbs(path) ||
			filepath.Clean(path) != path {
			return errors.New(
				"FI quarantine release requires clean absolute paths",
			)
		}
	}

	if filepath.Dir(request.HistoryRoot) !=
		filepath.Dir(request.QuarantineRoot) ||
		request.HistoryRoot == request.QuarantineRoot {
		return errors.New(
			"FI quarantine history must be a separate sibling directory",
		)
	}

	for _, path := range []string{
		request.QuarantineRoot,
		request.HistoryRoot,
	} {
		if m1PathWithin(path, request.LockFile) {
			return errors.New(
				"FI worker lock cannot reside in quarantine or history storage",
			)
		}
	}

	if len(request.EnrolledSources) == 0 {
		return errors.New(
			"FI quarantine release requires an enrolled source inventory",
		)
	}

	return nil
}

func m1ValidateReleaseHistoryRoot(root string) error {
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return err
	}

	if resolved != root {
		return errors.New(
			"FI quarantine release history traverses symlinks",
		)
	}

	info, err := os.Lstat(root)
	if err != nil {
		return err
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok ||
		!info.IsDir() ||
		info.Mode().Perm() != 0700 ||
		stat.Uid != uint32(os.Geteuid()) {
		return errors.New(
			"FI quarantine release history must be worker-owned 0700 storage",
		)
	}

	return nil
}

func m1WriteQuarantineReleaseAudit(
	historyRoot string,
	release m1QuarantineReleaseRecord,
) (string, error) {
	raw, err := json.Marshal(release)
	if err != nil {
		return "", err
	}
	raw = append(raw, '\n')

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	final := filepath.Join(
		historyRoot,
		"release-"+release.SourceID+"-"+
			hex.EncodeToString(nonce)+".json",
	)

	temporary, err := os.CreateTemp(
		historyRoot,
		".release-*.pending",
	)
	if err != nil {
		return "", err
	}

	tempPath := temporary.Name()
	defer os.Remove(tempPath)

	if _, err := temporary.Write(raw); err != nil {
		_ = temporary.Close()
		return "", err
	}

	if err := temporary.Chmod(0400); err != nil {
		_ = temporary.Close()
		return "", err
	}

	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return "", err
	}

	if err := temporary.Close(); err != nil {
		return "", err
	}

	// Never replace a prior audit record.
	if err := os.Link(tempPath, final); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return "", errors.New(
				"FI quarantine release audit identity collision",
			)
		}
		return "", err
	}

	if err := os.Remove(tempPath); err != nil {
		return "", err
	}

	directory, err := os.Open(historyRoot)
	if err != nil {
		return "", err
	}

	syncErr := directory.Sync()
	closeErr := directory.Close()

	if err := errors.Join(syncErr, closeErr); err != nil {
		return "", err
	}

	return final, nil
}
