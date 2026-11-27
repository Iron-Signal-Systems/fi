// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows/svc"
)

func TestPersistSenderRuntimeErrorWritesDurableJSONL(t *testing.T) {
	stateDir := t.TempDir()
	t.Setenv("FI_STATE_DIR", stateDir)

	wantError := "FI generation builder fail-stopped: signing failed"
	if err := persistSenderRuntimeError(errors.New(wantError)); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(stateDir, senderRuntimeErrorFileName)
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		t.Fatalf("sender runtime-error journal contains no record: %v", scanner.Err())
	}

	var record senderRuntimeErrorRecord
	if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
		t.Fatal(err)
	}

	if record.RecordKind != "SenderTerminalRuntimeError" {
		t.Fatalf("record_kind=%q", record.RecordKind)
	}
	if record.Service != windowsSenderServiceName {
		t.Fatalf("service=%q", record.Service)
	}
	if record.Error != wantError {
		t.Fatalf("error=%q want=%q", record.Error, wantError)
	}
	if record.Timestamp == "" {
		t.Fatal("timestamp is empty")
	}

	if scanner.Scan() {
		t.Fatal("unexpected extra runtime-error record")
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestPersistSenderRuntimeErrorAppends(t *testing.T) {
	stateDir := t.TempDir()
	t.Setenv("FI_STATE_DIR", stateDir)

	for _, message := range []string{"first", "second"} {
		if err := persistSenderRuntimeError(errors.New(message)); err != nil {
			t.Fatal(err)
		}
	}

	path := filepath.Join(stateDir, senderRuntimeErrorFileName)
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var messages []string
	for scanner.Scan() {
		var record senderRuntimeErrorRecord
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			t.Fatal(err)
		}
		messages = append(messages, record.Error)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}

	if len(messages) != 2 || messages[0] != "first" || messages[1] != "second" {
		t.Fatalf("runtime-error messages=%v", messages)
	}
}

func TestFISenderServiceRuntimeFailurePersistsTerminalError(t *testing.T) {
	stateDir := t.TempDir()
	t.Setenv("FI_STATE_DIR", stateDir)

	statuses := make(chan svc.Status, 4)
	runtimeRelease := make(chan struct{})

	service := &fiSenderService{
		loadConfig: func() (senderConfig, error) {
			return senderConfig{}, nil
		},
		runRuntime: func(context.Context, senderConfig) error {
			<-runtimeRelease
			return errors.New("durable-runtime-failure")
		},
	}

	results := make(chan senderServiceExecutionResult, 1)
	go func() {
		serviceSpecific, exitCode := service.Execute(
			nil,
			make(chan svc.ChangeRequest),
			statuses,
		)
		results <- senderServiceExecutionResult{
			exitCode:        exitCode,
			serviceSpecific: serviceSpecific,
		}
	}()

	if status := receiveSenderServiceStatus(t, statuses); status.State != svc.StartPending {
		t.Fatalf("first status=%v want=StartPending", status.State)
	}
	if status := receiveSenderServiceStatus(t, statuses); status.State != svc.Running {
		t.Fatalf("second status=%v want=Running", status.State)
	}

	close(runtimeRelease)

	if status := receiveSenderServiceStatus(t, statuses); status.State != svc.StopPending {
		t.Fatalf("third status=%v want=StopPending", status.State)
	}

	result := receiveSenderServiceResult(t, results)
	if result.exitCode != 1 || result.serviceSpecific {
		t.Fatalf("service result=%+v", result)
	}

	path := filepath.Join(stateDir, senderRuntimeErrorFileName)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte("durable-runtime-failure")) {
		t.Fatalf("runtime-error journal does not contain terminal error: %q", raw)
	}
}
