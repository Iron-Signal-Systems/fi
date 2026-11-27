// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import "testing"

func TestBacklogStreamBatchBufferNeverTracksFullOneGiBWindow(t *testing.T) {
	tests := []struct {
		window uint64
		want   uint64
	}{
		{64 << 20, 64 << 20},
		{256 << 20, 256 << 20},
		{1 << 30, 256 << 20},
	}
	for _, tc := range tests {
		if got := backlogStreamBatchBufferLimit(tc.window); got != tc.want {
			t.Fatalf("window bytes=%d buffer cap=%d want=%d", tc.window, got, tc.want)
		}
	}
}
