// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import "testing"

func TestLabBootstrapExactOptIn(t *testing.T) {
	t.Setenv(labBootstrapEnv, "")
	on, err := labBootstrapRequested()
	if err != nil || on {
		t.Fatalf("unexpected default %v %v", on, err)
	}
	t.Setenv(labBootstrapEnv, "1")
	on, err = labBootstrapRequested()
	if err != nil || !on {
		t.Fatalf("explicit bootstrap not enabled %v %v", on, err)
	}
	t.Setenv(labBootstrapEnv, "true")
	if _, err := labBootstrapRequested(); err == nil {
		t.Fatal("accepted ambiguous bootstrap opt-in")
	}
}
