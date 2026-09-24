// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package config

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	Version1  = "1.0"
	Version11 = "1.1"
)

type CollectorSettings struct {
	CollectionEvery        time.Duration
	SupportingRefreshEvery time.Duration
	USNEvery               time.Duration
	WindowsSecurityEvery   time.Duration
}

type Config struct {
	VersionID     string
	GovernedRoots []string
	Collector     CollectorSettings
	Receiver      ReceiverSettings
	Sender        SenderSettings
	Source        SourceSettings
	Spool         SpoolSettings
	Storage       StorageSettings
	Troubleshoot  TroubleshootSettings
}

type ReceiverSettings struct {
	Address string
	Name    string
	Timeout time.Duration
}

type SenderSettings struct {
	GenerationInterval        time.Duration
	GenerationMaxEncodedBytes uint64
	GenerationTransferTimeout time.Duration
	PollInterval              time.Duration
	RecoveryThresholdBytes    uint64
	RecoveryTimeout           time.Duration
	RetryBackoff              time.Duration
}

type SourceSettings struct {
	ID string
}

type SpoolSettings struct {
	MaxBatchRecords  int
	MaxRecordBytes   int64
	TargetBatchBytes int64
}

type StorageSettings struct {
	SpoolDir string
	StageDir string
	StateDir string
}

type TroubleshootSettings struct {
	AllowCollectorCLIOverride bool
	AllowSenderCLIOverride    bool
	AllowStorageCLIOverride   bool
	AllowTrustCLIOverride     bool
	Enabled                   bool
}

// Load reads and validates one FI configuration file.
func Load(path string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open FI config: %w", err)
	}
	defer file.Close()

	value, err := Parse(file)
	if err != nil {
		return Config{}, fmt.Errorf("parse FI config %q: %w", path, err)
	}
	return value, nil
}

// Parse reads FI configuration version 1.0 or 1.1.
//
// Version 1.0 remains accepted for compatibility and contains only
// version_id plus one or more governed_root directives.
//
// Version 1.1 adds strict operational settings. The first meaningful line
// remains "version_id: <version>". governed_root continues to use ":" so
// repeated roots remain human-readable. Operational settings use "=".
// Unknown and duplicate settings fail closed.
func Parse(reader io.Reader) (Config, error) {
	if reader == nil {
		return Config{}, errors.New("reader is required")
	}

	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 1024*1024)

	var value Config
	seenVersion := false
	seenRoots := make(map[string]struct{})
	seenSettings := make(map[string]struct{})
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		if lineNumber == 1 {
			line = strings.TrimPrefix(line, "\uFEFF")
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if !seenVersion {
			key, rawValue, ok := strings.Cut(line, ":")
			if !ok {
				return Config{}, fmt.Errorf("line %d: first directive must be version_id", lineNumber)
			}
			key = strings.TrimSpace(key)
			rawValue = strings.TrimSpace(rawValue)
			if key != "version_id" {
				return Config{}, fmt.Errorf("line %d: first directive must be version_id", lineNumber)
			}
			switch rawValue {
			case Version1, Version11:
				value.VersionID = rawValue
			default:
				return Config{}, fmt.Errorf("line %d: unsupported version_id %q", lineNumber, rawValue)
			}
			seenVersion = true
			continue
		}

		if strings.HasPrefix(line, "version_id") {
			if key, _, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(key) == "version_id" {
				return Config{}, fmt.Errorf("line %d: duplicate version_id", lineNumber)
			}
		}

		if key, rawValue, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(key) == "governed_root" {
			rawValue = strings.TrimSpace(rawValue)
			if rawValue == "" {
				return Config{}, fmt.Errorf("line %d: governed_root path is required", lineNumber)
			}
			if err := validateWindowsPath(rawValue); err != nil {
				return Config{}, fmt.Errorf("line %d: governed_root: %w", lineNumber, err)
			}
			rootKey := governedRootKey(rawValue)
			if _, exists := seenRoots[rootKey]; exists {
				return Config{}, fmt.Errorf("line %d: duplicate governed_root %q", lineNumber, rawValue)
			}
			seenRoots[rootKey] = struct{}{}
			value.GovernedRoots = append(value.GovernedRoots, rawValue)
			continue
		}

		if value.VersionID == Version1 {
			key := line
			if before, _, ok := strings.Cut(line, ":"); ok {
				key = strings.TrimSpace(before)
			}
			return Config{}, fmt.Errorf("line %d: unknown directive %q", lineNumber, key)
		}

		key, rawValue, ok := strings.Cut(line, "=")
		if !ok {
			return Config{}, fmt.Errorf("line %d: expected operational setting followed by '='", lineNumber)
		}
		key = strings.TrimSpace(key)
		rawValue = strings.TrimSpace(stripInlineComment(rawValue))
		if key == "" {
			return Config{}, fmt.Errorf("line %d: setting name is required", lineNumber)
		}
		if rawValue == "" {
			return Config{}, fmt.Errorf("line %d: %s value is required", lineNumber, key)
		}
		if _, exists := seenSettings[key]; exists {
			return Config{}, fmt.Errorf("line %d: duplicate setting %q", lineNumber, key)
		}
		seenSettings[key] = struct{}{}

		if err := assignSetting(&value, key, rawValue); err != nil {
			return Config{}, fmt.Errorf("line %d: %w", lineNumber, err)
		}
	}

	if err := scanner.Err(); err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	if !seenVersion {
		return Config{}, errors.New("version_id is required")
	}
	if len(value.GovernedRoots) == 0 {
		return Config{}, errors.New("at least one governed_root is required")
	}
	if value.VersionID == Version11 {
		if err := validateVersion11(&value, seenSettings); err != nil {
			return Config{}, err
		}
	}
	return value, nil
}

func assignSetting(value *Config, key string, rawValue string) error {
	switch key {
	case "collector.collection_every":
		duration, err := parsePositiveDuration(key, rawValue)
		if err != nil {
			return err
		}
		value.Collector.CollectionEvery = duration
	case "collector.supporting_refresh_every":
		duration, err := parsePositiveDuration(key, rawValue)
		if err != nil {
			return err
		}
		value.Collector.SupportingRefreshEvery = duration
	case "collector.usn_every":
		duration, err := parsePositiveDuration(key, rawValue)
		if err != nil {
			return err
		}
		value.Collector.USNEvery = duration
	case "collector.windows_security_every":
		duration, err := parsePositiveDuration(key, rawValue)
		if err != nil {
			return err
		}
		value.Collector.WindowsSecurityEvery = duration
	case "receiver.address":
		value.Receiver.Address = rawValue
	case "receiver.name":
		value.Receiver.Name = rawValue
	case "receiver.timeout":
		duration, err := parsePositiveDuration(key, rawValue)
		if err != nil {
			return err
		}
		value.Receiver.Timeout = duration
	case "sender.generation_interval":
		duration, err := time.ParseDuration(rawValue)
		if err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
		if duration < 0 {
			return fmt.Errorf("%s cannot be negative", key)
		}
		value.Sender.GenerationInterval = duration
	case "sender.generation_max_encoded_bytes":
		number, err := parsePositiveUint64(key, rawValue)
		if err != nil {
			return err
		}
		value.Sender.GenerationMaxEncodedBytes = number
	case "sender.generation_transfer_timeout":
		duration, err := parsePositiveDuration(key, rawValue)
		if err != nil {
			return err
		}
		value.Sender.GenerationTransferTimeout = duration
	case "sender.poll_interval":
		duration, err := parsePositiveDuration(key, rawValue)
		if err != nil {
			return err
		}
		value.Sender.PollInterval = duration
	case "sender.recovery_threshold_bytes":
		number, err := parseUint64(key, rawValue)
		if err != nil {
			return err
		}
		value.Sender.RecoveryThresholdBytes = number
	case "sender.recovery_timeout":
		duration, err := parsePositiveDuration(key, rawValue)
		if err != nil {
			return err
		}
		value.Sender.RecoveryTimeout = duration
	case "sender.retry_backoff":
		duration, err := parsePositiveDuration(key, rawValue)
		if err != nil {
			return err
		}
		value.Sender.RetryBackoff = duration
	case "source.id":
		value.Source.ID = rawValue
	case "spool.max_batch_records":
		number, err := strconv.ParseInt(rawValue, 10, 32)
		if err != nil || number <= 0 {
			return fmt.Errorf("%s must be a positive base-10 integer", key)
		}
		value.Spool.MaxBatchRecords = int(number)
	case "spool.max_record_bytes":
		number, err := strconv.ParseInt(rawValue, 10, 64)
		if err != nil || number <= 0 {
			return fmt.Errorf("%s must be a positive base-10 integer", key)
		}
		value.Spool.MaxRecordBytes = number
	case "spool.target_batch_bytes":
		number, err := strconv.ParseInt(rawValue, 10, 64)
		if err != nil || number <= 0 {
			return fmt.Errorf("%s must be a positive base-10 integer", key)
		}
		value.Spool.TargetBatchBytes = number
	case "storage.spool_dir":
		if err := validateWindowsPath(rawValue); err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
		value.Storage.SpoolDir = rawValue
	case "storage.stage_dir":
		if err := validateWindowsPath(rawValue); err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
		value.Storage.StageDir = rawValue
	case "storage.state_dir":
		if err := validateWindowsPath(rawValue); err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
		value.Storage.StateDir = rawValue
	case "troubleshoot.allow_collector_cli_override":
		parsed, err := parseBool(key, rawValue)
		if err != nil {
			return err
		}
		value.Troubleshoot.AllowCollectorCLIOverride = parsed
	case "troubleshoot.allow_sender_cli_override":
		parsed, err := parseBool(key, rawValue)
		if err != nil {
			return err
		}
		value.Troubleshoot.AllowSenderCLIOverride = parsed
	case "troubleshoot.allow_storage_cli_override":
		parsed, err := parseBool(key, rawValue)
		if err != nil {
			return err
		}
		value.Troubleshoot.AllowStorageCLIOverride = parsed
	case "troubleshoot.allow_trust_cli_override":
		parsed, err := parseBool(key, rawValue)
		if err != nil {
			return err
		}
		value.Troubleshoot.AllowTrustCLIOverride = parsed
	case "troubleshoot.enabled":
		parsed, err := parseBool(key, rawValue)
		if err != nil {
			return err
		}
		value.Troubleshoot.Enabled = parsed
	default:
		return fmt.Errorf("unknown setting %q", key)
	}
	return nil
}

func governedRootKey(path string) string {
	key := strings.TrimRight(path, "\\")
	if len(key) == 2 && key[1] == ':' {
		key += "\\"
	}
	return strings.ToLower(key)
}

func isASCIILetter(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}

func parseBool(name string, value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, fmt.Errorf("%s must be true or false", name)
	}
}

func parsePositiveDuration(name string, value string) (time.Duration, error) {
	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	if duration <= 0 {
		return 0, fmt.Errorf("%s must be greater than zero", name)
	}
	return duration, nil
}

func parsePositiveUint64(name string, value string) (uint64, error) {
	number, err := parseUint64(name, value)
	if err != nil {
		return 0, err
	}
	if number == 0 {
		return 0, fmt.Errorf("%s must be greater than zero", name)
	}
	return number, nil
}

func parseUint64(name string, value string) (uint64, error) {
	number, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s must be an unsigned base-10 integer", name)
	}
	return number, nil
}

func stripInlineComment(value string) string {
	for index, current := range value {
		if current != '#' {
			continue
		}
		if index == 0 {
			return ""
		}
		previous := value[index-1]
		if previous == ' ' || previous == '\t' {
			return strings.TrimSpace(value[:index])
		}
	}
	return strings.TrimSpace(value)
}

func validateVersion11(value *Config, seen map[string]struct{}) error {
	required := []string{
		"collector.collection_every",
		"collector.supporting_refresh_every",
		"collector.usn_every",
		"collector.windows_security_every",
		"receiver.address",
		"receiver.name",
		"receiver.timeout",
		"sender.generation_interval",
		"sender.generation_max_encoded_bytes",
		"sender.generation_transfer_timeout",
		"sender.poll_interval",
		"sender.retry_backoff",
		"source.id",
		"spool.max_batch_records",
		"spool.max_record_bytes",
		"spool.target_batch_bytes",
		"storage.spool_dir",
		"storage.stage_dir",
		"storage.state_dir",
	}
	for _, key := range required {
		if _, ok := seen[key]; !ok {
			return fmt.Errorf("%s is required for version_id %s", key, Version11)
		}
	}

	if _, ok := seen["sender.recovery_timeout"]; !ok {
		value.Sender.RecoveryTimeout = 2 * time.Hour
	}
	if value.Sender.RecoveryThresholdBytes != 0 && value.Sender.RecoveryTimeout <= 0 {
		return errors.New("sender.recovery_timeout must be greater than zero when recovery is enabled")
	}
	if strings.TrimSpace(value.Source.ID) == "" ||
		strings.ContainsAny(value.Source.ID, `/\\`) ||
		value.Source.ID == "." ||
		value.Source.ID == ".." {
		return errors.New("source.id is invalid")
	}
	if _, _, err := net.SplitHostPort(value.Receiver.Address); err != nil {
		return fmt.Errorf("receiver.address must be host:port: %w", err)
	}
	if strings.TrimSpace(value.Receiver.Name) == "" {
		return errors.New("receiver.name is required")
	}
	if value.Spool.MaxRecordBytes < 1 || value.Spool.TargetBatchBytes < 1 {
		return errors.New("spool byte limits must be greater than zero")
	}
	return nil
}

func validateWindowsPath(path string) error {
	if !utf8.ValidString(path) {
		return errors.New("path is not valid UTF-8")
	}
	if len(path) < 3 {
		return errors.New("path must be an absolute local Windows path")
	}
	if !isASCIILetter(path[0]) || path[1] != ':' || path[2] != '\\' {
		return errors.New("path must be an absolute local Windows path such as D:\\Shares\\Finance")
	}
	if strings.Contains(path, "/") {
		return errors.New("path must use Windows backslashes")
	}
	if strings.ContainsRune(path[3:], ':') {
		return errors.New("path contains an unexpected ':'")
	}
	for _, part := range strings.Split(path[3:], "\\") {
		switch part {
		case ".", "..":
			return errors.New("path must not contain '.' or '..' segments")
		}
	}
	return nil
}
