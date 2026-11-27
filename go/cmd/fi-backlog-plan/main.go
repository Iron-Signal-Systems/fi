// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, in the repository root.
//
// Read-only MANIFEST inventory and hypothetical grouping calculator.
// It does NOT validate signed custody or modify any source.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const manifestCap = 1 << 20

type manifest struct {
	BatchID         string `json:"batch_id"`
	TargetBatchSize int    `json:"target_batch_size"`
	RecordCount     int    `json:"record_count"`
	DataBytes       int64  `json:"data_bytes"`
	DataSHA256      string `json:"data_sha256"`
	DataFile        string `json:"data_file"`
}
type batch struct {
	name    string
	records int
	bytes   int64
}
type summary struct {
	batches, groups, oversized, maxRecords int
	records, bytes, maxBytes               int64
}

func main() {
	active := flag.String("spool-dir", "", "published spool directory (read only)")
	raw := flag.String("raw-root", "", "generation-raw directory (read only)")
	capRecords := flag.Int("max-records", 65536, "hypothetical maximum record count")
	capBytes := flag.Int64("max-data-bytes", 64<<20, "hypothetical source JSONL data-byte limit")
	flag.Parse()
	if flag.NArg() != 0 || (*active == "" && *raw == "") || *capRecords <= 0 || *capBytes <= 0 {
		fmt.Fprintln(os.Stderr, "usage: fi-backlog-plan [-spool-dir PATH] [-raw-root PATH] [-max-records N] [-max-data-bytes N]")
		os.Exit(2)
	}
	fmt.Printf("READ-ONLY MANIFEST INVENTORY (NOT CUSTODY VALIDATION); target_records=%d target_source_bytes=%d\n", *capRecords, *capBytes)
	bad := false
	if *active != "" {
		if err := inventory("ACTIVE", *active, *capRecords, *capBytes); err != nil {
			fmt.Fprintln(os.Stderr, "ACTIVE ERROR:", err)
			bad = true
		}
	}
	if *raw != "" {
		if err := realDir(*raw); err != nil {
			fmt.Fprintln(os.Stderr, "RAW ROOT ERROR:", err)
			bad = true
		} else {
			entries, err := os.ReadDir(*raw)
			if err != nil {
				fmt.Fprintln(os.Stderr, "RAW ROOT READ ERROR:", err)
				bad = true
			} else {
				n := 0
				for _, e := range entries {
					if !strings.HasPrefix(e.Name(), "generation-") {
						continue
					}
					if !e.IsDir() || e.Type()&os.ModeSymlink != 0 {
						fmt.Fprintln(os.Stderr, "UNSAFE RAW GENERATION:", e.Name())
						bad = true
						continue
					}
					n++
					if err := inventory("FROZEN "+e.Name(), filepath.Join(*raw, e.Name()), *capRecords, *capBytes); err != nil {
						fmt.Fprintln(os.Stderr, "FROZEN ERROR:", e.Name(), err)
						bad = true
					}
				}
				fmt.Printf("RAW_GENERATIONS=%d\n", n)
			}
		}
	}
	fmt.Println("NOTE: HYPOTHETICAL groups are NOT new authenticated generations; never split or re-sign existing signed evidence.")
	fmt.Println("NOTE: This inspects metadata and file sizes only; it does not hash data or verify signatures/receipts/DB.")
	if bad {
		os.Exit(1)
	}
}
func realDir(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("absolute path required")
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return fmt.Errorf("not a real directory: %s", path)
	}
	return nil
}
func inventory(label, dir string, capRecords int, capBytes int64) error {
	if err := realDir(dir); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	batches := make([]batch, 0)
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "batch-") || !strings.HasSuffix(name, ".manifest.json") {
			continue
		}
		if len(batches) >= 100000 {
			return errors.New("inventory exceeds 100000 manifests")
		}
		m, err := loadManifest(dir, name)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		batches = append(batches, batch{name: name, records: m.RecordCount, bytes: m.DataBytes})
	}
	sort.Slice(batches, func(i, j int) bool { return batches[i].name < batches[j].name })
	s := group(batches, capRecords, capBytes)
	fmt.Printf("%s path=%s manifests=%d records=%d data_bytes=%d largest_batch_records=%d largest_batch_bytes=%d hypothetical_groups=%d oversized=%d\n", label, dir, s.batches, s.records, s.bytes, s.maxRecords, s.maxBytes, s.groups, s.oversized)
	if s.oversized != 0 {
		return errors.New("intact batch exceeds hypothetical budget; splitting it would change source-batch identity")
	}
	return nil
}
func loadManifest(dir, name string) (manifest, error) {
	var m manifest
	path := filepath.Join(dir, name)
	fi, err := os.Lstat(path)
	if err != nil {
		return m, err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() || fi.Size() < 2 || fi.Size() > manifestCap {
		return m, errors.New("manifest must be bounded regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return m, err
	}
	data, readErr := io.ReadAll(io.LimitReader(f, manifestCap+1))
	closeErr := f.Close()
	if readErr != nil {
		return m, readErr
	}
	if closeErr != nil {
		return m, closeErr
	}
	if len(data) > manifestCap || int64(len(data)) != fi.Size() {
		return m, errors.New("manifest changed size or exceeded bound")
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return m, err
	}
	id := strings.TrimSuffix(strings.TrimPrefix(name, "batch-"), ".manifest.json")
	want := "batch-" + id + ".jsonl"
	if id == "" || m.BatchID != id || m.DataFile != want || m.TargetBatchSize < 1 || m.RecordCount < 1 || m.RecordCount > m.TargetBatchSize || m.DataBytes < 1 || len(m.DataSHA256) != 64 {
		return m, errors.New("invalid source-batch identity/count/bytes")
	}
	for _, c := range m.DataSHA256 {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return m, errors.New("invalid SHA-256 syntax")
		}
	}
	di, err := os.Lstat(filepath.Join(dir, want))
	if err != nil {
		return m, err
	}
	if di.Mode()&os.ModeSymlink != 0 || !di.Mode().IsRegular() || di.Size() != m.DataBytes {
		return m, errors.New("source data file missing, not regular or size mismatch")
	}
	return m, nil
}
func group(batches []batch, capRecords int, capBytes int64) summary {
	s := summary{batches: len(batches)}
	usedRecords := 0
	var usedBytes int64
	for _, b := range batches {
		s.records += int64(b.records)
		s.bytes += b.bytes
		if b.records > s.maxRecords {
			s.maxRecords = b.records
		}
		if b.bytes > s.maxBytes {
			s.maxBytes = b.bytes
		}
		if b.records > capRecords || b.bytes > capBytes {
			s.oversized++
			continue
		}
		if usedRecords > 0 && (b.records > capRecords-usedRecords || b.bytes > capBytes-usedBytes) {
			s.groups++
			usedRecords = 0
			usedBytes = 0
		}
		usedRecords += b.records
		usedBytes += b.bytes
	}
	if usedRecords > 0 {
		s.groups++
	}
	return s
}
