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

func TestConfigPathArgument(t *testing.T) {
	path, err := configPath(
		[]string{"/root/fi-backend.conf"},
		strings.NewReader(""),
		&bytes.Buffer{},
	)
	if err != nil {
		t.Fatalf(
			"configPath() error = %v",
			err,
		)
	}

	if path != "/root/fi-backend.conf" {
		t.Fatalf(
			"configPath() = %q",
			path,
		)
	}
}

func TestConfigPathPrompt(t *testing.T) {
	var output bytes.Buffer

	path, err := configPath(
		nil,
		strings.NewReader("/root/fi-backend.conf\n"),
		&output,
	)
	if err != nil {
		t.Fatalf(
			"configPath() error = %v",
			err,
		)
	}

	if path != "/root/fi-backend.conf" {
		t.Fatalf(
			"configPath() = %q",
			path,
		)
	}

	if output.String() != "Configuration file: " {
		t.Fatalf(
			"prompt = %q",
			output.String(),
		)
	}
}

func TestParseInvocationExplicitPreflight(t *testing.T) {
	request, err := parseInvocation(
		[]string{
			"preflight",
			"/root/fi-backend.conf",
		},
		strings.NewReader(""),
		&bytes.Buffer{},
	)
	if err != nil {
		t.Fatalf(
			"parseInvocation() error = %v",
			err,
		)
	}

	if request.command != "preflight" {
		t.Fatalf(
			"command = %q",
			request.command,
		)
	}

	if request.configPath != "/root/fi-backend.conf" {
		t.Fatalf(
			"configPath = %q",
			request.configPath,
		)
	}
}

func TestParseInvocationLegacyConfigArgument(t *testing.T) {
	request, err := parseInvocation(
		[]string{
			"/root/fi-backend.conf",
		},
		strings.NewReader(""),
		&bytes.Buffer{},
	)
	if err != nil {
		t.Fatalf(
			"parseInvocation() error = %v",
			err,
		)
	}

	if request.command != "validate" {
		t.Fatalf(
			"command = %q",
			request.command,
		)
	}
}

func TestParseInvocationRejectsTooManyArguments(t *testing.T) {
	_, err := parseInvocation(
		[]string{
			"preflight",
			"one",
			"two",
		},
		strings.NewReader(""),
		&bytes.Buffer{},
	)
	if err == nil {
		t.Fatal(
			"parseInvocation() expected usage error",
		)
	}
}

func TestParseInvocationExplicitApplyZFSRoot(t *testing.T) {
	request, err := parseInvocation(
		[]string{
			"apply-zfs-root",
			"/root/fi-backend.conf",
		},
		strings.NewReader(""),
		&bytes.Buffer{},
	)
	if err != nil {
		t.Fatalf(
			"parseInvocation() error = %v",
			err,
		)
	}

	if request.command != "apply-zfs-root" {
		t.Fatalf(
			"command = %q",
			request.command,
		)
	}

	if request.configPath != "/root/fi-backend.conf" {
		t.Fatalf(
			"configPath = %q",
			request.configPath,
		)
	}
}

func TestParseInvocationExplicitApplyZFSHierarchy(t *testing.T) {
	request, err := parseInvocation(
		[]string{
			"apply-zfs-hierarchy",
			"/root/fi-backend.conf",
		},
		strings.NewReader(""),
		&bytes.Buffer{},
	)
	if err != nil {
		t.Fatalf(
			"parseInvocation() error = %v",
			err,
		)
	}

	if request.command != "apply-zfs-hierarchy" {
		t.Fatalf(
			"command = %q",
			request.command,
		)
	}

	if request.configPath != "/root/fi-backend.conf" {
		t.Fatalf(
			"configPath = %q",
			request.configPath,
		)
	}
}
