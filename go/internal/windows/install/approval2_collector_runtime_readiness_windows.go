// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	approval2CollectorRuntimeLogName          = "service-runtime.jsonl"
	approval2CollectorRuntimeReadinessTimeout = 10 * time.Second
	approval2CollectorRuntimeTailBytes        = int64(1024 * 1024)
	approval2CollectorRuntimeVersion          = "fi-service-runtime/0.1"
	approval2TransactionTimestampLayout       = "20060102T150405.000000000Z"
)

type approval2CollectorRuntimeRecord struct {
	Version    string `json:"version"`
	RecordKind string `json:"record_kind"`
	ObservedAt string `json:"observed_at"`
	Outcome    string `json:"outcome,omitempty"`
	Error      string `json:"error,omitempty"`
}

func resolveApproval2CollectorRuntimeStateDir(
	rediscover func() Report,
) (string, error) {
	if rediscover == nil {
		return "", errors.New(
			"FICollector runtime readiness rediscovery dependency is nil",
		)
	}

	current := rediscover()

	if current.Config.Presence != presencePresent {
		return "", fmt.Errorf(
			"FICollector runtime readiness requires an installed FI operational configuration; observed presence=%s",
			current.Config.Presence,
		)
	}

	stateDir := strings.TrimSpace(
		current.Config.StateDir,
	)

	if stateDir == "" {
		return "", errors.New(
			"FICollector runtime readiness installed configuration has an empty state directory",
		)
	}

	return stateDir, nil
}
func inspectApproval2CollectorRuntimeReadiness(
	records []approval2CollectorRuntimeRecord,
	notBefore time.Time,
) (bool, error) {
	serviceStarted := false
	securityReady := false

	for _, record := range records {
		observedAt, err :=
			time.Parse(
				time.RFC3339Nano,
				strings.TrimSpace(
					record.ObservedAt,
				),
			)
		if err != nil {
			return false, fmt.Errorf(
				"parse FICollector runtime observed_at %q: %w",
				record.ObservedAt,
				err,
			)
		}

		if observedAt.Before(
			notBefore,
		) {
			continue
		}

		if record.Version !=
			approval2CollectorRuntimeVersion {
			return false, fmt.Errorf(
				"FICollector runtime record version=%q expected=%q",
				record.Version,
				approval2CollectorRuntimeVersion,
			)
		}

		switch record.RecordKind {
		case "ServiceStarted":
			serviceStarted = true

		case "WindowsSecurityCatchUp":
			switch record.Outcome {
			case "Complete", "Partial":
				securityReady = true

			case "Failed":
				detail :=
					strings.TrimSpace(
						record.Error,
					)

				if detail == "" {
					detail =
						"runtime record did not include an error"
				}

				return false, fmt.Errorf(
					"FICollector Windows Security readiness failed: %s",
					detail,
				)

			case "Interrupted":
				return false, errors.New(
					"FICollector Windows Security readiness was interrupted",
				)

			default:
				return false, fmt.Errorf(
					"FICollector Windows Security readiness returned unsupported outcome %q",
					record.Outcome,
				)
			}
		}
	}

	return serviceStarted &&
			securityReady,
		nil
}

func readApproval2CollectorRuntimeRecords(
	path string,
) ([]approval2CollectorRuntimeRecord, error) {
	file, err :=
		os.Open(
			path,
		)
	if errors.Is(
		err,
		os.ErrNotExist,
	) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf(
			"open FICollector runtime log %s: %w",
			path,
			err,
		)
	}
	defer file.Close()

	info, err :=
		file.Stat()
	if err != nil {
		return nil, fmt.Errorf(
			"stat FICollector runtime log %s: %w",
			path,
			err,
		)
	}

	start :=
		int64(0)

	if info.Size() >
		approval2CollectorRuntimeTailBytes {
		start =
			info.Size() -
				approval2CollectorRuntimeTailBytes

		if _, err :=
			file.Seek(
				start,
				io.SeekStart,
			); err != nil {
			return nil, fmt.Errorf(
				"seek FICollector runtime log %s: %w",
				path,
				err,
			)
		}
	}

	data, err :=
		io.ReadAll(
			io.LimitReader(
				file,
				approval2CollectorRuntimeTailBytes,
			),
		)
	if err != nil {
		return nil, fmt.Errorf(
			"read FICollector runtime log %s: %w",
			path,
			err,
		)
	}

	if start != 0 {
		firstNewline :=
			bytes.IndexByte(
				data,
				'\n',
			)

		if firstNewline < 0 {
			return nil, nil
		}

		data = data[firstNewline+1:]
	}

	lastNewline :=
		bytes.LastIndexByte(
			data,
			'\n',
		)

	if lastNewline < 0 {
		// The service may currently be appending the first record. Only complete
		// newline-terminated records are authoritative for readiness.
		return nil, nil
	}

	data = data[:lastNewline+1]

	lines :=
		bytes.Split(
			data,
			[]byte{'\n'},
		)

	records :=
		make(
			[]approval2CollectorRuntimeRecord,
			0,
			len(lines),
		)

	for _, line := range lines {
		line =
			bytes.TrimSpace(
				line,
			)

		if len(line) == 0 {
			continue
		}

		var record approval2CollectorRuntimeRecord

		if err :=
			json.Unmarshal(
				line,
				&record,
			); err != nil {
			return nil, fmt.Errorf(
				"decode FICollector runtime record: %w",
				err,
			)
		}

		records =
			append(
				records,
				record,
			)
	}

	return records, nil
}

func waitForFICollectorRuntimeReadinessFromRediscovery(
	rediscover func() Report,
	transactionID string,
	timeout time.Duration,
) error {
	stateDir, err :=
		resolveApproval2CollectorRuntimeStateDir(
			rediscover,
		)
	if err != nil {
		return err
	}

	return waitForFICollectorRuntimeReadiness(
		stateDir,
		transactionID,
		timeout,
	)
}
func waitForFICollectorRuntimeReadiness(
	stateDir string,
	transactionID string,
	timeout time.Duration,
) error {
	stateDir =
		strings.TrimSpace(
			stateDir,
		)

	if stateDir == "" {
		return errors.New(
			"FICollector runtime readiness state directory is required",
		)
	}

	if timeout <= 0 {
		return fmt.Errorf(
			"FICollector runtime readiness timeout must be positive; observed=%s",
			timeout,
		)
	}

	notBefore, err :=
		time.Parse(
			approval2TransactionTimestampLayout,
			strings.TrimSpace(
				transactionID,
			),
		)
	if err != nil {
		return fmt.Errorf(
			"parse Approval 2 transaction timestamp %q for FICollector runtime readiness: %w",
			transactionID,
			err,
		)
	}

	path :=
		filepath.Join(
			stateDir,
			approval2CollectorRuntimeLogName,
		)

	deadline :=
		time.Now().Add(
			timeout,
		)

	for {
		records, err :=
			readApproval2CollectorRuntimeRecords(
				path,
			)
		if err != nil {
			return err
		}

		ready, err :=
			inspectApproval2CollectorRuntimeReadiness(
				records,
				notBefore,
			)
		if err != nil {
			return err
		}

		if ready {
			return nil
		}

		remaining :=
			time.Until(
				deadline,
			)

		if remaining <= 0 {
			return fmt.Errorf(
				"FICollector runtime readiness did not observe current-transaction ServiceStarted and WindowsSecurityCatchUp records within %s; path=%s",
				timeout,
				path,
			)
		}

		delay :=
			approval2ServiceStabilityPollInterval

		if remaining < delay {
			delay = remaining
		}

		time.Sleep(
			delay,
		)
	}
}
