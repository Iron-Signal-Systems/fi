// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"fmt"
	"os"
	"regexp"
)

const hostFileMarker = "# FI-MANAGED: ironsignal-fi-freebsd-host-file-v1"

var hostFileTokenPattern = regexp.MustCompile(
	`@FI_[A-Z0-9_]+@`,
)

type hostFileSpec struct {
	Content []byte
	GID     uint64
	Mode    os.FileMode
	Role    string
	Target  string
	UID     uint64
}

func hostFileSpecs(
	config Config,
) ([]hostFileSpec, error) {
	definitions := []struct {
		asset  string
		mode   os.FileMode
		role   string
		target string
	}{
		{
			asset:  hostFileAssetReceiverJail,
			mode:   0o644,
			role:   "jail-config-receiver",
			target: "/etc/jail.conf.d/fi-receiver.conf",
		},
		{
			asset:  hostFileAssetIngestJail,
			mode:   0o644,
			role:   "jail-config-ingest",
			target: "/etc/jail.conf.d/fi-ingest.conf",
		},
		{
			asset:  hostFileAssetSORJail,
			mode:   0o644,
			role:   "jail-config-sor-db",
			target: "/etc/jail.conf.d/fi-sor-db.conf",
		},
		{
			asset: hostFileAssetReceiverFstab,
			mode:  0o600,
			role:  "fstab-receiver",
			target: config.Value(
				"FI_RECEIVER_FSTAB",
			),
		},
		{
			asset: hostFileAssetIngestFstab,
			mode:  0o600,
			role:  "fstab-ingest",
			target: config.Value(
				"FI_INGEST_FSTAB",
			),
		},
		{
			asset: hostFileAssetSORFstab,
			mode:  0o600,
			role:  "fstab-sor-db",
			target: config.Value(
				"FI_SOR_DB_FSTAB",
			),
		},
		{
			asset:  hostFileAssetDevfsRules,
			mode:   0o644,
			role:   "devfs-rules",
			target: "/etc/devfs.rules.fi",
		},
		{
			asset:  hostFileAssetVNETHelper,
			mode:   0o555,
			role:   "vnet-helper",
			target: "/usr/local/libexec/fi-vnet-pair",
		},
	}

	specs := make(
		[]hostFileSpec,
		0,
		len(definitions),
	)

	for _, definition := range definitions {
		content, err := renderHostFileAsset(
			definition.asset,
			config,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"render host file %s: %w",
				definition.role,
				err,
			)
		}

		if !containsExactLine(
			content,
			hostFileMarker,
		) {
			return nil, fmt.Errorf(
				"rendered host file lacks FI marker: %s",
				definition.role,
			)
		}

		expectedRole := "# FI-ROLE: " +
			definition.role

		if !containsExactLine(
			content,
			expectedRole,
		) {
			return nil, fmt.Errorf(
				"rendered host file lacks exact FI role: %s",
				definition.role,
			)
		}

		specs = append(
			specs,
			hostFileSpec{
				Content: content,
				GID:     0,
				Mode:    definition.mode,
				Role:    definition.role,
				Target:  definition.target,
				UID:     0,
			},
		)
	}

	return specs, nil
}

func renderHostFileAsset(
	asset string,
	config Config,
) ([]byte, error) {
	unresolved := ""

	rendered := hostFileTokenPattern.ReplaceAllStringFunc(
		asset,
		func(token string) string {
			key := token[1 : len(token)-1]

			value, exists := config.values[key]
			if !exists || value == "" {
				if unresolved == "" {
					unresolved = token
				}

				return token
			}

			return value
		},
	)

	if unresolved != "" {
		return nil, fmt.Errorf(
			"unresolved configuration token: %s",
			unresolved,
		)
	}

	if token := hostFileTokenPattern.FindString(
		rendered,
	); token != "" {
		return nil, fmt.Errorf(
			"unresolved configuration token after rendering: %s",
			token,
		)
	}

	return []byte(rendered), nil
}
