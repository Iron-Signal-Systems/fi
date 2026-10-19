// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package config

import (
	"strings"
	"testing"
)

func TestUSNReobserveWorkersConfiguration(t *testing.T) {
	for _, test := range []struct {
		name  string
		line  string
		want  int
		valid bool
	}{
		{"default", "", 8, true},
		{"minimum", "collector.usn_reobserve_workers = 1\n", 1, true},
		{"four", "collector.usn_reobserve_workers = 4\n", 4, true},
		{"eight", "collector.usn_reobserve_workers = 8\n", 8, true},
		{"maximum", "collector.usn_reobserve_workers = 16\n", 16, true},
		{"zero", "collector.usn_reobserve_workers = 0\n", 0, false},
		{"above", "collector.usn_reobserve_workers = 17\n", 0, false},
		{"negative", "collector.usn_reobserve_workers = -1\n", 0, false},
		{"fraction", "collector.usn_reobserve_workers = 1.5\n", 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := Parse(strings.NewReader(validVersion11OperationalConfiguration() + test.line))
			if (err == nil) != test.valid {
				t.Fatalf("valid=%v err=%v", test.valid, err)
			}
			if test.valid && got.Collector.USNReobserveWorkers != test.want {
				t.Fatalf("workers=%d want=%d", got.Collector.USNReobserveWorkers, test.want)
			}
		})
	}
}
