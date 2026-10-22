// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package config

import (
	"strings"
	"testing"
)

func TestUSNProcessingBoundsConfiguration(t *testing.T) {
	for _, test := range []struct {
		line     string
		valid    bool
		chunk    int
		inflight int
	}{
		{"", true, 256, 32},
		{"collector.usn_processing_chunk_objects = 64\n", true, 64, 32},
		{"collector.usn_processing_chunk_objects = 2048\n", true, 2048, 32},
		{"collector.usn_processing_max_inflight = 1\n", true, 256, 1},
		{"collector.usn_processing_max_inflight = 64\n", true, 256, 64},
		{"collector.usn_processing_chunk_objects = 63\n", false, 0, 0},
		{"collector.usn_processing_chunk_objects = 2049\n", false, 0, 0},
		{"collector.usn_processing_max_inflight = 0\n", false, 0, 0},
		{"collector.usn_processing_max_inflight = 65\n", false, 0, 0},
	} {
		result, err := Parse(strings.NewReader(validVersion11OperationalConfiguration() + test.line))
		if (err == nil) != test.valid {
			t.Fatalf("line=%q valid=%v err=%v", test.line, test.valid, err)
		}
		if test.valid && (result.Collector.USNProcessingChunkObjects != test.chunk || result.Collector.USNProcessingMaxInflight != test.inflight) {
			t.Fatalf("line=%q bounds=%+v", test.line, result.Collector)
		}
	}
}
