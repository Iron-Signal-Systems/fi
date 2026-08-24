// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package spool

import (
	"bytes"
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
)

const (
	RecordVersion    = "fi-spool-record/0.1"
	ManifestVersion  = "fi-batch-manifest/0.1"
	DefaultBatchSize = 64
)

var (
	ErrWriterClosed       = errors.New("FI spool writer is closed")
	ErrBatchHashMismatch  = errors.New("FI batch SHA-256 mismatch")
	ErrBatchCountMismatch = errors.New("FI batch record count mismatch")
	ErrBatchSizeMismatch  = errors.New("FI batch byte count mismatch")
)

type CollectorIdentity struct {
	ExecutablePath   string `json:"executable_path"`
	ExecutableSHA256 string `json:"executable_sha256"`
}

type Record struct {
	Version    string          `json:"version"`
	RecordKind string          `json:"record_kind"`
	ScopeID    string          `json:"scope_id"`
	WrittenAt  string          `json:"written_at"`
	Payload    json.RawMessage `json:"payload"`
}

type Manifest struct {
	Version         string            `json:"version"`
	BatchID         string            `json:"batch_id"`
	TargetBatchSize int               `json:"target_batch_size"`
	RecordCount     int               `json:"record_count"`
	DataBytes       int64             `json:"data_bytes"`
	DataSHA256      string            `json:"data_sha256"`
	DataFile        string            `json:"data_file"`
	Collector       CollectorIdentity `json:"collector"`
	CreatedAt       string            `json:"created_at"`
	CompletedAt     string            `json:"completed_at"`
}

type FinalizedBatch struct {
	DataPath     string   `json:"data_path"`
	ManifestPath string   `json:"manifest_path"`
	Manifest     Manifest `json:"manifest"`
}

type Verification struct {
	Verified bool     `json:"verified"`
	DataPath string   `json:"data_path"`
	Manifest Manifest `json:"manifest"`
}

type Writer struct {
	dir       string
	batchSize int
	collector CollectorIdentity
	file      *os.File
	openPath  string
	batchID   string
	createdAt string
	count     int
	closed    bool
	finalized []FinalizedBatch
}

func DefaultDir() (string, error) {
	if value := os.Getenv("FI_SPOOL_DIR"); value != "" {
		return value, nil
	}
	programData := os.Getenv("ProgramData")
	if programData == "" {
		return "", errors.New("ProgramData is not set")
	}
	return filepath.Join(programData, "FI", "spool"), nil
}

func NewWriter(dir string, batchSize int, collector CollectorIdentity) (*Writer, error) {
	if dir == "" {
		return nil, errors.New("spool directory is required")
	}
	if batchSize <= 0 {
		return nil, errors.New("batch size must be greater than zero")
	}
	if collector.ExecutablePath == "" || !validSHA256(collector.ExecutableSHA256) {
		return nil, errors.New("collector executable identity is invalid")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Writer{dir: dir, batchSize: batchSize, collector: collector, finalized: []FinalizedBatch{}}, nil
}

func (w *Writer) Append(recordKind, scopeID string, payload any) error {
	if w == nil || w.closed {
		return ErrWriterClosed
	}
	if recordKind == "" || scopeID == "" {
		return errors.New("record kind and scope ID are required")
	}
	if w.file == nil {
		if err := w.openBatch(); err != nil {
			return err
		}
	}

	rawPayload, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	record := Record{
		Version:    RecordVersion,
		RecordKind: recordKind,
		ScopeID:    scopeID,
		WrittenAt:  canonicalNow(),
		Payload:    rawPayload,
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if _, err := w.file.Write(encoded); err != nil {
		return err
	}
	w.count++
	if w.count == w.batchSize {
		return w.finalizeCurrent()
	}
	return nil
}

func (w *Writer) Close() error {
	if w == nil || w.closed {
		return nil
	}
	if err := w.finalizeCurrent(); err != nil {
		return err
	}
	w.closed = true
	return nil
}

func (w *Writer) FinalizedBatches() []FinalizedBatch {
	if w == nil {
		return nil
	}
	result := make([]FinalizedBatch, len(w.finalized))
	copy(result, w.finalized)
	return result
}

func (w *Writer) openBatch() error {
	id, err := newBatchID()
	if err != nil {
		return err
	}
	openPath := filepath.Join(w.dir, "batch-"+id+".open")
	file, err := os.OpenFile(openPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	w.file = file
	w.openPath = openPath
	w.batchID = id
	w.createdAt = canonicalNow()
	w.count = 0
	return nil
}

func (w *Writer) finalizeCurrent() error {
	if w.file == nil {
		return nil
	}
	if w.count == 0 {
		name := w.openPath
		_ = w.file.Close()
		w.file = nil
		w.openPath = ""
		return os.Remove(name)
	}
	if err := w.file.Sync(); err != nil {
		return err
	}
	if err := w.file.Close(); err != nil {
		return err
	}
	w.file = nil

	dataName := "batch-" + w.batchID + ".jsonl"
	dataPath := filepath.Join(w.dir, dataName)
	if err := os.Rename(w.openPath, dataPath); err != nil {
		return err
	}

	digest, dataBytes, records, err := inspectDataFile(dataPath)
	if err != nil {
		return err
	}
	if records != w.count {
		return fmt.Errorf("%w: wrote %d, inspected %d", ErrBatchCountMismatch, w.count, records)
	}

	manifest := Manifest{
		Version:         ManifestVersion,
		BatchID:         w.batchID,
		TargetBatchSize: w.batchSize,
		RecordCount:     records,
		DataBytes:       dataBytes,
		DataSHA256:      digest,
		DataFile:        dataName,
		Collector:       w.collector,
		CreatedAt:       w.createdAt,
		CompletedAt:     canonicalNow(),
	}
	manifestPath := filepath.Join(w.dir, "batch-"+w.batchID+".manifest.json")
	if err := writeManifest(manifestPath, manifest); err != nil {
		return err
	}

	w.finalized = append(w.finalized, FinalizedBatch{DataPath: dataPath, ManifestPath: manifestPath, Manifest: manifest})
	w.openPath = ""
	w.batchID = ""
	w.createdAt = ""
	w.count = 0
	return nil
}

func VerifyManifest(manifestPath string) (Verification, error) {
	file, err := os.Open(manifestPath)
	if err != nil {
		return Verification{}, err
	}
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		file.Close()
		return Verification{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		file.Close()
		return Verification{}, errors.New("manifest contains trailing data")
	}
	if err := file.Close(); err != nil {
		return Verification{}, err
	}
	if err := validateManifest(manifest); err != nil {
		return Verification{}, err
	}

	dataPath := filepath.Join(filepath.Dir(manifestPath), manifest.DataFile)
	digest, dataBytes, records, err := inspectDataFile(dataPath)
	if err != nil {
		return Verification{}, err
	}
	if digest != manifest.DataSHA256 {
		return Verification{}, ErrBatchHashMismatch
	}
	if dataBytes != manifest.DataBytes {
		return Verification{}, ErrBatchSizeMismatch
	}
	if records != manifest.RecordCount {
		return Verification{}, ErrBatchCountMismatch
	}
	return Verification{Verified: true, DataPath: dataPath, Manifest: manifest}, nil
}

func validateManifest(value Manifest) error {
	if value.Version != ManifestVersion || value.BatchID == "" || value.TargetBatchSize <= 0 ||
		value.RecordCount <= 0 || value.RecordCount > value.TargetBatchSize || value.DataBytes <= 0 ||
		!validSHA256(value.DataSHA256) || value.DataFile == "" || value.CreatedAt == "" || value.CompletedAt == "" {
		return errors.New("invalid FI batch manifest")
	}
	if filepath.Base(value.DataFile) != value.DataFile || strings.ContainsAny(value.DataFile, `/\\`) {
		return errors.New("manifest data_file must be a local base filename")
	}
	if value.DataFile != "batch-"+value.BatchID+".jsonl" {
		return errors.New("manifest data_file does not match batch_id")
	}
	if value.Collector.ExecutablePath == "" || !validSHA256(value.Collector.ExecutableSHA256) {
		return errors.New("invalid manifest collector identity")
	}
	return nil
}

func writeManifest(path string, value Manifest) error {
	tempPath := path + ".open"
	file, err := os.OpenFile(tempPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	keep := true
	defer func() {
		if keep {
			_ = file.Close()
			_ = os.Remove(tempPath)
		}
	}()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	keep = false
	return nil
}

func inspectDataFile(path string) (string, int64, int, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, 0, err
	}
	defer file.Close()

	hasher := sha256.New()
	buffer := make([]byte, 128*1024)
	var total int64
	records := 0
	var last byte
	for {
		n, readErr := file.Read(buffer)
		if n > 0 {
			chunk := buffer[:n]
			if _, err := hasher.Write(chunk); err != nil {
				return "", 0, 0, err
			}
			total += int64(n)
			records += bytes.Count(chunk, []byte{'\n'})
			last = chunk[len(chunk)-1]
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return "", 0, 0, readErr
		}
	}
	if total == 0 || last != '\n' {
		return "", 0, 0, errors.New("batch data is empty or missing final newline")
	}
	return hex.EncodeToString(hasher.Sum(nil)), total, records, nil
}

func newBatchID() (string, error) {
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return time.Now().UTC().Format("20060102T150405.000000000Z") + "-" + hex.EncodeToString(random[:]), nil
}

func canonicalNow() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z")
}

func validSHA256(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
