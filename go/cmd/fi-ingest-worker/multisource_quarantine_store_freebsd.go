// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const m1QuarantineVersion = "fi-ingest-source-quarantine/0.1"

type m1QuarantineMarker struct {
	CreatedAtUTC string `json:"created_at_utc"`
	Detail       string `json:"detail"`
	GenerationID string `json:"generation_id,omitempty"`
	Reason       string `json:"reason"`
	SourceID     string `json:"source_id"`
	Version      string `json:"version"`
}

type m1QuarantineStore struct {
	Root string
}

func m1ValidQuarantineSource(sourceID string) bool {
	if sourceID == "" || len(sourceID) > 255 ||
		sourceID == "." || sourceID == ".." ||
		strings.Contains(sourceID, "..") ||
		filepath.Base(sourceID) != sourceID {
		return false
	}

	for _, character := range sourceID {
		if (character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') ||
			character == '.' || character == '-' {
			continue
		}
		return false
	}

	return true
}

func (store m1QuarantineStore) validateRoot() error {
	if store.Root == "" ||
		!filepath.IsAbs(store.Root) ||
		filepath.Clean(store.Root) != store.Root {
		return errors.New(
			"FI quarantine state root must be a clean absolute path",
		)
	}

	resolved, err := filepath.EvalSymlinks(store.Root)
	if err != nil {
		return fmt.Errorf("resolve FI quarantine root: %w", err)
	}
	if resolved != store.Root {
		return errors.New(
			"FI quarantine root must not traverse symlinks",
		)
	}

	info, err := os.Lstat(store.Root)
	if err != nil {
		return err
	}

	stat, ok := info.Sys().(*syscall.Stat_t)

	if !ok || !info.IsDir() ||
		info.Mode().Perm() != 0700 ||
		stat.Uid != uint32(os.Geteuid()) {
		return errors.New(
			"FI quarantine root must be a worker-owned 0700 directory",
		)
	}

	return nil
}

func (store m1QuarantineStore) markerPath(
	sourceID string,
) (string, error) {
	if !m1ValidQuarantineSource(sourceID) {
		return "", fmt.Errorf(
			"invalid FI quarantine source identity %q",
			sourceID,
		)
	}

	return filepath.Join(store.Root, sourceID+".json"), nil
}

func m1ReadQuarantineMarker(
	path string,
	expectedSource string,
) (m1QuarantineMarker, error) {
	var marker m1QuarantineMarker

	before, err := os.Lstat(path)
	if err != nil {
		return marker, err
	}

	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || !before.Mode().IsRegular() ||
		before.Mode().Perm() != 0400 ||
		before.Size() <= 0 || before.Size() > 16384 ||
		stat.Uid != uint32(os.Geteuid()) ||
		stat.Nlink != 1 {
		return marker, fmt.Errorf(
			"FI quarantine marker has unsafe filesystem identity: %q",
			path,
		)
	}

	file, err := os.Open(path)
	if err != nil {
		return marker, err
	}

	opened, statErr := file.Stat()
	if statErr != nil || !os.SameFile(before, opened) {
		_ = file.Close()
		return marker, fmt.Errorf(
			"FI quarantine marker changed while opening: %q",
			path,
		)
	}

	raw, readErr := io.ReadAll(io.LimitReader(file, 16385))
	closeErr := file.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return marker, err
	}

	after, err := os.Lstat(path)
	if err != nil {
		return marker, err
	}
	if !os.SameFile(before, after) ||
		int64(len(raw)) != before.Size() {
		return marker, fmt.Errorf(
			"FI quarantine marker changed while reading: %q",
			path,
		)
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&marker); err != nil {
		return marker, err
	}

	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return marker, errors.New(
			"FI quarantine marker contains trailing content",
		)
	}

	if marker.Version != m1QuarantineVersion ||
		marker.SourceID != expectedSource ||
		(marker.Reason != "RELATIONAL_CONFLICT" &&
			marker.Reason != "RECORDED_RECEIPT_INVALID") ||
		marker.Detail == "" ||
		len(marker.Detail) > 4096 {
		return marker, fmt.Errorf(
			"FI quarantine marker failed source or reason validation: %q",
			path,
		)
	}

	if _, err := time.Parse(
		time.RFC3339Nano, marker.CreatedAtUTC,
	); err != nil {
		return marker, fmt.Errorf(
			"FI quarantine marker timestamp invalid: %w",
			err,
		)
	}

	return marker, nil
}

// Load reads all quarantine markers and rejects unexpected objects.
// Absence of a marker means the source is not quarantined.
func (store m1QuarantineStore) Load(
	sources []string,
) (map[string]m1QuarantineMarker, error) {
	if err := store.validateRoot(); err != nil {
		return nil, err
	}

	allowed := make(map[string]bool, len(sources))

	for _, sourceID := range sources {
		if !m1ValidQuarantineSource(sourceID) ||
			allowed[sourceID] {
			return nil, fmt.Errorf(
				"FI quarantine inventory has invalid or repeated source %q",
				sourceID,
			)
		}
		allowed[sourceID] = true
	}

	if len(allowed) == 0 {
		return nil, errors.New(
			"FI quarantine source inventory must not be empty",
		)
	}

	entries, err := os.ReadDir(store.Root)
	if err != nil {
		return nil, err
	}

	found := make(
		map[string]m1QuarantineMarker,
		len(entries),
	)

	for _, entry := range entries {
		name := entry.Name()

		if !strings.HasSuffix(name, ".json") {
			return nil, fmt.Errorf(
				"FI quarantine root contains unexpected object %q",
				name,
			)
		}

		sourceID := strings.TrimSuffix(name, ".json")
		if !allowed[sourceID] {
			return nil, fmt.Errorf(
				"FI quarantine marker belongs to unknown source %q",
				sourceID,
			)
		}

		path, err := store.markerPath(sourceID)
		if err != nil {
			return nil, err
		}

		marker, err := m1ReadQuarantineMarker(
			path, sourceID,
		)
		if err != nil {
			return nil, err
		}

		found[sourceID] = marker
	}

	return found, nil
}

// Persist creates an immutable marker without replacing an existing one.
// A successful return requires the marker and directory entry to have
// crossed their durability boundaries.
func (store m1QuarantineStore) Persist(
	sourceID string,
	reason string,
	generationID string,
	detail string,
) error {
	if err := store.validateRoot(); err != nil {
		return err
	}

	path, err := store.markerPath(sourceID)
	if err != nil {
		return err
	}

	if (reason != "RELATIONAL_CONFLICT" &&
		reason != "RECORDED_RECEIPT_INVALID") ||
		detail == "" || len(detail) > 4096 {
		return errors.New(
			"FI quarantine persistence reason or detail is invalid",
		)
	}

	if existing, err := m1ReadQuarantineMarker(
		path, sourceID,
	); err == nil {
		_ = existing
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	marker := m1QuarantineMarker{
		CreatedAtUTC: time.Now().UTC().Format(time.RFC3339Nano),
		Detail:       detail,
		GenerationID: generationID,
		Reason:       reason,
		SourceID:     sourceID,
		Version:      m1QuarantineVersion,
	}

	raw, err := json.Marshal(marker)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')

	file, err := os.CreateTemp(store.Root, ".quarantine-*.pending")
	if err != nil {
		return err
	}

	temp := file.Name()
	defer os.Remove(temp)

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

	// Hard-link publication cannot overwrite an existing marker.
	if err := os.Link(temp, path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			_, verifyErr := m1ReadQuarantineMarker(
				path, sourceID,
			)
			return verifyErr
		}
		return err
	}

	if err := os.Remove(temp); err != nil {
		return err
	}

	dir, err := os.Open(store.Root)
	if err != nil {
		return err
	}

	syncErr := dir.Sync()
	closeErr := dir.Close()

	return errors.Join(syncErr, closeErr)
}
