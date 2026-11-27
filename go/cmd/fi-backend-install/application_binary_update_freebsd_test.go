// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseInvocationUpdateBinaries(t *testing.T) {
	request, err := parseInvocation([]string{
		"update-binaries", "/root/fi-backend.conf", "/root/fi-update/release", "/root/fi-update/prior",
	}, strings.NewReader(""), &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if request.command != "update-binaries" || request.configPath != "/root/fi-backend.conf" ||
		request.applicationBinaryRelease != "/root/fi-update/release" ||
		request.approvedPriorBinaries != "/root/fi-update/prior" {
		t.Fatalf("unexpected update-binaries invocation: %+v", request)
	}
}

func TestParseInvocationUpdateBinariesRequiresAllPaths(t *testing.T) {
	for _, args := range [][]string{
		{"update-binaries"},
		{"update-binaries", "/root/fi-backend.conf"},
		{"update-binaries", "/root/fi-backend.conf", "/root/fi-update/release"},
	} {
		if _, err := parseInvocation(args, strings.NewReader(""), &bytes.Buffer{}); err == nil {
			t.Fatalf("accepted incomplete arguments: %v", args)
		}
	}
}
