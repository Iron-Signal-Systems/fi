// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package main

import (
	"errors"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportreceiver"
)

type generationRuntimeOptions struct {
	CustodyRoot       string
	Enabled           bool
	MaxCanonicalBytes uint64
	MaxEncodedBytes   uint64
	MaxManifestBytes  uint64
	RecordedRoot      string
}

func (
	options generationRuntimeOptions,
) validate() error {
	configured :=
		options.CustodyRoot != "" ||
			options.RecordedRoot != "" ||
			options.MaxCanonicalBytes != 0 ||
			options.MaxEncodedBytes != 0 ||
			options.MaxManifestBytes != 0

	if !options.Enabled {
		if configured {
			return errors.New(
				"generation settings require -generation-enable",
			)
		}

		return nil
	}

	if options.CustodyRoot == "" ||
		options.RecordedRoot == "" ||
		options.MaxCanonicalBytes == 0 ||
		options.MaxEncodedBytes == 0 ||
		options.MaxManifestBytes == 0 {
		return errors.New(
			"-generation-enable requires generation custody/recorded roots and all generation byte limits",
		)
	}

	return nil
}

func (
	options generationRuntimeOptions,
) apply(
	config *transportreceiver.Config,
) {
	if config == nil {
		return
	}

	config.GenerationEnabled =
		options.Enabled
	config.GenerationCustodyRoot =
		options.CustodyRoot
	config.GenerationRecordedRoot =
		options.RecordedRoot
	config.GenerationMaxCanonicalBytes =
		options.MaxCanonicalBytes
	config.GenerationMaxEncodedBytes =
		options.MaxEncodedBytes
	config.GenerationMaxManifestBytes =
		options.MaxManifestBytes
}
