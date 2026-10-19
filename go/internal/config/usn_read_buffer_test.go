// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package config

import (
	"strings"
	"testing"
)

func TestUSNReadBufferMiBConfiguration(t *testing.T) {
	for _, test := range []struct {
		name  string
		line  string
		want  int
		valid bool
	}{
		{"default", "", 1, true},
		{"minimum", "collector.usn_read_buffer_mib = 1\n", 1, true},
		{"two", "collector.usn_read_buffer_mib = 2\n", 2, true},
		{"four", "collector.usn_read_buffer_mib = 4\n", 4, true},
		{"maximum", "collector.usn_read_buffer_mib = 64\n", 64, true},
		{"zero", "collector.usn_read_buffer_mib = 0\n", 0, false},
		{"above", "collector.usn_read_buffer_mib = 65\n", 0, false},
		{"negative", "collector.usn_read_buffer_mib = -1\n", 0, false},
		{"fraction", "collector.usn_read_buffer_mib = 1.5\n", 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			conf := validVersion11OperationalConfiguration() + test.line
			got, err := Parse(strings.NewReader(conf))
			if (err == nil) != test.valid {
				t.Fatalf("valid = %v, error = %v", test.valid, err)
			}
			if test.valid && got.Collector.USNReadBufferMiB != test.want {
				t.Fatalf("size = %d, want %d", got.Collector.USNReadBufferMiB, test.want)
			}
		})
	}
}
