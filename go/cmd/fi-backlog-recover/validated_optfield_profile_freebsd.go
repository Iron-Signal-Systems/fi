//go:build freebsd

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package main

import (
	"errors"
	"fmt"
)

// selectedPrivateProfile is an opt-in, non-authoritative profile.
// This cannot substitute for the separately validated field-partition implementation.
type selectedPrivateProfile struct {
	Name                    string
	WindowProfile           string
	ProcessingChunkRecords  int
	SecurityProfile         string
	FileProfile             string
}

func selectValidatedK32(
	explicit map[string]string,
	fieldPartitions, privateWrites, continuousPrivate,
	indexedPrivate, streamLoader, preflightOnly, verifiedCache bool,
	startWindow, maxWindows int,
) (selectedPrivateProfile, error) {
	var empty selectedPrivateProfile
	if !fieldPartitions {
		return empty, errors.New("FI optimized K32 requires enabled -private-field-partitions; no unpartitioned fallback")
	}
	if !privateWrites || !continuousPrivate || indexedPrivate || streamLoader || preflightOnly ||
		!verifiedCache || startWindow < 1 || maxWindows != 0 {
		return empty, errors.New("FI optimized K32 requires isolated verified-cache continuous private recovery, start-window>=1, max-windows=0; never authoritative")
	}
	for flagName, required := range map[string]string{
		"window-profile": "W128",
		"processing-chunk-records": "32768",
		"security-profile": "P3",
		"file-profile": "F3",
	} {
		if actual, set := explicit[flagName]; set && actual != required {
			return empty, fmt.Errorf("FI optimized K32 conflicts with -%s=%s, required %s", flagName, actual, required)
		}
	}
	return selectedPrivateProfile{
		Name: "optfield-k32-w128-p3-f3",
		WindowProfile: "W128",
		ProcessingChunkRecords: 32768,
		SecurityProfile: "P3",
		FileProfile: "F3",
	}, nil
}
