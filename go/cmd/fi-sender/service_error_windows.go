// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/windows/runtimeowner"
)

const senderRuntimeErrorFileName = "sender-runtime-errors.jsonl"

type senderRuntimeErrorRecord struct {
	Error      string `json:"error"`
	RecordKind string `json:"record_kind"`
	Service    string `json:"service"`
	Timestamp  string `json:"timestamp"`
}

func persistSenderRuntimeError(runtimeErr error) error {
	if runtimeErr == nil {
		return errors.New("FI sender terminal runtime error is required")
	}

	lockPath, err := runtimeowner.SenderPath()
	if err != nil {
		return fmt.Errorf("resolve FI sender state directory: %w", err)
	}

	stateDir := filepath.Dir(lockPath)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return fmt.Errorf("create FI sender state directory: %w", err)
	}

	path := filepath.Join(stateDir, senderRuntimeErrorFileName)
	file, err := os.OpenFile(
		path,
		os.O_CREATE|os.O_APPEND|os.O_WRONLY,
		0o600,
	)
	if err != nil {
		return fmt.Errorf("open FI sender runtime-error journal: %w", err)
	}

	record := senderRuntimeErrorRecord{
		Error:      runtimeErr.Error(),
		RecordKind: "SenderTerminalRuntimeError",
		Service:    windowsSenderServiceName,
		Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
	}

	encoded, err := json.Marshal(record)
	if err == nil {
		encoded = append(encoded, '\n')
		_, err = file.Write(encoded)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()

	if err != nil {
		return fmt.Errorf("persist FI sender runtime-error journal: %w", err)
	}
	if closeErr != nil {
		return fmt.Errorf("close FI sender runtime-error journal: %w", closeErr)
	}

	return nil
}
