// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/windows/usnbroker"
	"golang.org/x/sys/windows/svc"
)

const (
	probeErrorPath  = `C:\FI-Test\production-containment\containment-client-2025-error.txt`
	probeInputPath  = `C:\FI-Test\production-containment\containment-client-2025-input.json`
	probeResultPath = `C:\FI-Test\production-containment\containment-client-2025-result.json`
	probeVersion    = "windows-server-2025-production-containment-client/0.1"
)

type probeInput struct {
	FileReferenceNumber string `json:"file_reference_number"`
	GovernedRoot        string `json:"governed_root"`
	SequenceNumber      string `json:"sequence_number"`
	TargetDescription   string `json:"target_description"`
}

type probeOutput struct {
	BrokerResult        string `json:"broker_result"`
	FileReferenceNumber string `json:"file_reference_number"`
	GovernedRoot        string `json:"governed_root"`
	ObservedAt          string `json:"observed_at"`
	SequenceNumber      string `json:"sequence_number"`
	TargetDescription   string `json:"target_description"`
	Version             string `json:"version"`
}

type probeService struct{}

func main() {
	if err := svc.Run(usnbroker.CollectorServiceName, &probeService{}); err != nil {
		_ = writeError(err)
		os.Exit(1)
	}
}

func (service *probeService) Execute(
	_ []string,
	_ <-chan svc.ChangeRequest,
	statuses chan<- svc.Status,
) (bool, uint32) {
	statuses <- svc.Status{State: svc.StartPending}
	statuses <- svc.Status{State: svc.Running}

	if err := runProbe(); err != nil {
		_ = writeError(err)
		statuses <- svc.Status{State: svc.StopPending}
		return false, 1
	}

	statuses <- svc.Status{State: svc.StopPending}
	return false, 0
}

func runProbe() error {
	inputBytes, err := os.ReadFile(probeInputPath)
	if err != nil {
		return fmt.Errorf("read probe input: %w", err)
	}

	var input probeInput
	if err := json.Unmarshal(inputBytes, &input); err != nil {
		return fmt.Errorf("parse probe input: %w", err)
	}
	if input.GovernedRoot == "" {
		return fmt.Errorf("governed_root is required")
	}
	if input.TargetDescription == "" {
		return fmt.Errorf("target_description is required")
	}

	fileReferenceNumber, err := strconv.ParseUint(input.FileReferenceNumber, 10, 48)
	if err != nil {
		return fmt.Errorf("parse file_reference_number: %w", err)
	}
	sequenceNumber, err := strconv.ParseUint(input.SequenceNumber, 10, 16)
	if err != nil {
		return fmt.Errorf("parse sequence_number: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	result, err := usnbroker.CheckContainment(
		ctx,
		input.GovernedRoot,
		fileReferenceNumber,
		uint16(sequenceNumber),
	)
	if err != nil {
		return fmt.Errorf("production FIUSNReader containment request: %w", err)
	}

	var resultText string
	switch result {
	case usnbroker.ContainmentContained:
		resultText = "Contained"
	case usnbroker.ContainmentOutside:
		resultText = "Outside"
	case usnbroker.ContainmentUnavailable:
		resultText = "Unavailable"
	default:
		return fmt.Errorf("unexpected containment result %d", result)
	}

	output := probeOutput{
		BrokerResult:        resultText,
		FileReferenceNumber: input.FileReferenceNumber,
		GovernedRoot:        input.GovernedRoot,
		ObservedAt:          time.Now().UTC().Format(time.RFC3339Nano),
		SequenceNumber:      input.SequenceNumber,
		TargetDescription:   input.TargetDescription,
		Version:             probeVersion,
	}

	if err := os.MkdirAll(filepath.Dir(probeResultPath), 0o700); err != nil {
		return fmt.Errorf("create probe result directory: %w", err)
	}

	encoded, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("encode probe result: %w", err)
	}
	encoded = append(encoded, '\n')

	if err := os.WriteFile(probeResultPath, encoded, 0o600); err != nil {
		return fmt.Errorf("write probe result: %w", err)
	}
	return nil
}

func writeError(err error) error {
	if err == nil {
		return nil
	}
	if mkdirErr := os.MkdirAll(filepath.Dir(probeErrorPath), 0o700); mkdirErr != nil {
		return mkdirErr
	}
	return os.WriteFile(probeErrorPath, []byte(err.Error()+"\n"), 0o600)
}
