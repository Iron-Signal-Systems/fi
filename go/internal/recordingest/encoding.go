// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

func decodeBase64URL(value string, required bool, field string) ([]byte, error) {
	if value == "" {
		if required {
			return nil, fmt.Errorf("%s is required", field)
		}
		return nil, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, fmt.Errorf("%s is not canonical raw base64url", field)
	}
	return decoded, nil
}

func decodeHex(value string, expectedBytes int, required bool, field string) ([]byte, error) {
	if value == "" {
		if required {
			return nil, fmt.Errorf("%s is required", field)
		}
		return nil, nil
	}
	if value != strings.ToLower(value) || len(value) != expectedBytes*2 {
		return nil, fmt.Errorf("%s is not canonical lowercase hex", field)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != expectedBytes {
		return nil, fmt.Errorf("%s has invalid hex length", field)
	}
	return decoded, nil
}

func decodeStrictPayload(raw json.RawMessage, target any) error {
	if len(raw) == 0 || target == nil {
		return errors.New("FI relational payload and target are required")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("FI relational payload contains trailing JSON")
	}
	return nil
}

func nullString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func parseDecimalCanonical(value string, field string) (uint64, error) {
	if value == "" {
		return 0, fmt.Errorf("%s is required", field)
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", field, err)
	}
	if strconv.FormatUint(parsed, 10) != value {
		return 0, fmt.Errorf("%s is not canonical unsigned decimal", field)
	}
	return parsed, nil
}

func parseInt(value string, bits int, field string) (int64, error) {
	parsed, err := strconv.ParseInt(value, 10, bits)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", field, err)
	}
	return parsed, nil
}

func parseRFC3339(value string, field string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse %s: %w", field, err)
	}
	return parsed.UTC(), nil
}

func parseUint(value string, bits int, field string) (uint64, error) {
	parsed, err := strconv.ParseUint(value, 10, bits)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", field, err)
	}
	return parsed, nil
}

func parseUintFlexible(value string, bits int, field string) (uint64, error) {
	if value == "" {
		return 0, fmt.Errorf("%s is required", field)
	}
	base := 10
	normalized := value
	if strings.HasPrefix(value, "0x") {
		base = 16
		normalized = value[2:]
		if normalized == "" {
			return 0, fmt.Errorf("%s is invalid", field)
		}
	}
	parsed, err := strconv.ParseUint(normalized, base, bits)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", field, err)
	}
	return parsed, nil
}
