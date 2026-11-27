// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package main

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestM1ReleaseAuthorityGateBlocksOperationalCommand(
	t *testing.T,
) {
	args := m1ValidReleaseCLIArgs()

	// The proposed release is syntactically valid.
	// Authorization must still independently reject it.
	if _, err := m1ParseQuarantineReleaseOptions(
		args, io.Discard,
	); err != nil {
		t.Fatal(err)
	}

	err := m1RunQuarantineReleaseCommand(
		args,
		io.Discard,
	)

	if !errors.Is(
		err,
		errM1ReleaseAuthorityPending,
	) {
		t.Fatalf(
			"operational release did not fail closed: %v",
			err,
		)
	}

	t.Log("PASS: Valid release arguments cannot bypass authority")
}

func TestM1ReleaseAuthorityGateRetainsHelp(
	t *testing.T,
) {
	var output bytes.Buffer

	if err := m1RunQuarantineReleaseCommand(
		[]string{"-h"},
		&output,
	); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(
		output.String(),
		"-confirm-source-id",
	) {
		t.Fatal("maintenance help is unavailable")
	}

	t.Log("PASS: Help remains available without release authority")
}

func TestM1ReleaseAuthorityGateRejectsDirectAuthorization(
	t *testing.T,
) {
	if !errors.Is(
		m1RequireIndependentReleaseAuthority(),
		errM1ReleaseAuthorityPending,
	) {
		t.Fatal("unauthenticated release authority accepted")
	}

	t.Log("PASS: No release authorization exists before keeper")
}
