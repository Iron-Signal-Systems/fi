// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the FI Source Review License.
//
// Development acceptance against REAL, previously verified signed cache.
// Intentionally outside the timed PostgreSQL replay. Reads only; never writes
// or logs the contents of any Security event.
package recordingest

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestSecurityJSONOnceRealSignedPreflight(t *testing.T) {
	root := os.Getenv("FI_SECURITY_JSON_REAL_SIGNED_CACHE")
	if root == "" {
		t.Skip("real verified cache required only by private FreeBSD benchmark runner")
	}
	const wanted = 512
	const maxBatchFiles = 2048
	var seenFiles, seenSecurity, legacyFast, candidateFast int
	errStop := errors.New("FI security preflight sampled all required signed events")

	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "batch-") ||
			!strings.HasSuffix(entry.Name(), ".data") {
			return nil
		}
		seenFiles++
		if seenFiles > maxBatchFiles {
			return errStop
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		reader := bufio.NewReaderSize(file, 256<<10)
		for seenSecurity < wanted {
			raw, readErr := reader.ReadBytes('\n')
			if errors.Is(readErr, io.EOF) && len(raw) == 0 {
				break
			}
			if readErr != nil {
				return fmt.Errorf("read signed batch: %w", readErr)
			}
			if !bytes.HasPrefix(raw, securityEnvelopePrefix) {
				continue
			}
			seenSecurity++
			oldSelected := legacySecurityJSONSelection(raw)
			got, fast, selected, fastErr := tryPrepareSinglePassSecurity(raw)
			if !oldSelected || !selected || fastErr != nil {
				return fmt.Errorf("Security JSON fast path mismatch in signed sample %d (old=%t new=%t decode_failed=%t)",
					seenSecurity, oldSelected, selected, fastErr != nil)
			}
			legacyFast++
			candidateFast++
			legacy, err := prepareOwnedSourceRecord(raw)
			if err != nil {
				return fmt.Errorf("signed source strict decode sample %d: %w", seenSecurity, err)
			}
			legacySecurity, err := prepareSecurityBulkRecord(1, legacy, legacy.RecordDigest[:])
			if err != nil {
				return fmt.Errorf("signed Security strict decode sample %d: %w", seenSecurity, err)
			}
			if !reflect.DeepEqual(got, legacy) ||
				!reflect.DeepEqual(fast.value, legacySecurity.value) ||
				!reflect.DeepEqual(fast.eventRecordID, legacySecurity.eventRecordID) ||
				!bytes.Equal(fast.digest, legacySecurity.digest) {
				return fmt.Errorf("signed Security evidence or projection differs in sample %d", seenSecurity)
			}
		}
		if seenSecurity >= wanted {
			return errStop
		}
		return nil
	})
	if err != nil && !errors.Is(err, errStop) {
		t.Fatal(err)
	}
	if seenSecurity != wanted || legacyFast != wanted || candidateFast != wanted {
		t.Fatalf("FI SECURITY JSON PREFLIGHT FAIL files=%d records=%d legacy_selected=%d candidate_selected=%d want=%d",
			seenFiles, seenSecurity, legacyFast, candidateFast, wanted)
	}
	t.Logf("FI SECURITY JSON REAL SIGNED PREFLIGHT PASS files=%d security_records=%d single_pass=%d strict_equivalent=true",
		seenFiles, seenSecurity, candidateFast)
}
