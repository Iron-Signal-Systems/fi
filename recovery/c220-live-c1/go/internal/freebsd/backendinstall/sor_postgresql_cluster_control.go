// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"fmt"
	"strings"
)

const (
	sorPostgreSQLExpectedClusterState    = "shut down"
	sorPostgreSQLExpectedBlockSize       = "8192"
	sorPostgreSQLExpectedChecksumVersion = "1"
)

type sorPostgreSQLControlData struct {
	BlockSize       string
	ChecksumVersion string
	ClusterState    string
}

func parseSORPostgreSQLControlData(
	output []byte,
) (sorPostgreSQLControlData, error) {
	required := map[string]*string{}

	control := sorPostgreSQLControlData{}

	required["Database cluster state"] =
		&control.ClusterState

	required["Database block size"] =
		&control.BlockSize

	required["Data page checksum version"] =
		&control.ChecksumVersion

	seen := make(
		map[string]bool,
		len(required),
	)

	normalized := strings.ReplaceAll(
		string(output),
		"\r\n",
		"\n",
	)

	for _, line := range strings.Split(
		normalized,
		"\n",
	) {
		key, value, found :=
			strings.Cut(
				line,
				":",
			)

		if !found {
			continue
		}

		key = strings.TrimSpace(
			key,
		)

		destination, requiredKey :=
			required[key]

		if !requiredKey {
			continue
		}

		if seen[key] {
			return sorPostgreSQLControlData{},
				fmt.Errorf(
					"duplicate pg_controldata field %q",
					key,
				)
		}

		value = strings.TrimSpace(
			value,
		)

		if value == "" {
			return sorPostgreSQLControlData{},
				fmt.Errorf(
					"empty pg_controldata field %q",
					key,
				)
		}

		*destination = value
		seen[key] = true
	}

	for key := range required {
		if !seen[key] {
			return sorPostgreSQLControlData{},
				fmt.Errorf(
					"missing pg_controldata field %q",
					key,
				)
		}
	}

	return control, nil
}

func validateSORPostgreSQLControlData(
	output []byte,
) error {
	control, err :=
		parseSORPostgreSQLControlData(
			output,
		)
	if err != nil {
		return err
	}

	if control.ClusterState !=
		sorPostgreSQLExpectedClusterState {
		return fmt.Errorf(
			"PostgreSQL cluster state = %q, want %q",
			control.ClusterState,
			sorPostgreSQLExpectedClusterState,
		)
	}

	if control.BlockSize !=
		sorPostgreSQLExpectedBlockSize {
		return fmt.Errorf(
			"PostgreSQL database block size = %q, want %q",
			control.BlockSize,
			sorPostgreSQLExpectedBlockSize,
		)
	}

	if control.ChecksumVersion !=
		sorPostgreSQLExpectedChecksumVersion {
		return fmt.Errorf(
			"PostgreSQL data page checksum version = %q, want %q",
			control.ChecksumVersion,
			sorPostgreSQLExpectedChecksumVersion,
		)
	}

	return nil
}
