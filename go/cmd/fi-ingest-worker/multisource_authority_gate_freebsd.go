// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package main

import "errors"

// m1ValidateQuarantineAuthorityReady is the activation gate for
// namespaced ingest. It deliberately fails closed until the worker
// no longer owns or can remove its own durable quarantine markers.
//
// This restriction applies to the operational CLI entry point.
// Isolated package tests can continue validating the underlying
// namespaced ingest and quarantine behavior.
// Until the independently authenticated quarantine keeper exists,
// the operational release command is not authorized to clear markers.
var errM1ReleaseAuthorityPending = errors.New(
	"FI quarantine release is disabled: independent operator " +
		"authorization and keeper-controlled marker release are required",
)

func m1RequireIndependentReleaseAuthority() error {
	return errM1ReleaseAuthorityPending
}

func m1ValidateQuarantineAuthorityReady(
	config workerConfig,
) error {
	if !config.SourceNamespaces {
		return nil
	}

	return errors.New(
		"FI namespaced ingest is not activated: independent " +
			"quarantine publication, release authorization, " +
			"and protected singleton-lock authority are required",
	)
}
