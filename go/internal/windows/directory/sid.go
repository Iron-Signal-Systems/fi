// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package directory

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

const maxSIDSubAuthorities = 15

func sidStringToBytes(value string) ([]byte, error) {
	parts := strings.Split(value, "-")
	if len(parts) < 4 || parts[0] != "S" {
		return nil, fmt.Errorf("invalid SID %q", value)
	}

	revision, err := strconv.ParseUint(parts[1], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("invalid SID revision: %w", err)
	}
	authority, err := strconv.ParseUint(parts[2], 10, 48)
	if err != nil {
		return nil, fmt.Errorf("invalid SID authority: %w", err)
	}

	subCount := len(parts) - 3
	if subCount > maxSIDSubAuthorities {
		return nil, fmt.Errorf("SID has too many sub-authorities")
	}

	raw := make([]byte, 8+subCount*4)
	raw[0] = byte(revision)
	raw[1] = byte(subCount)
	for i := 0; i < 6; i++ {
		shift := uint((5 - i) * 8)
		raw[2+i] = byte(authority >> shift)
	}
	for i, part := range parts[3:] {
		subAuthority, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid SID sub-authority %d: %w", i, err)
		}
		binary.LittleEndian.PutUint32(raw[8+i*4:], uint32(subAuthority))
	}
	return raw, nil
}

func sidBytesToString(raw []byte) (string, error) {
	if len(raw) < 8 {
		return "", fmt.Errorf("SID shorter than header")
	}
	count := int(raw[1])
	if count > maxSIDSubAuthorities {
		return "", fmt.Errorf("SID has too many sub-authorities")
	}
	length := 8 + count*4
	if length != len(raw) {
		return "", fmt.Errorf("SID length mismatch")
	}
	authority := uint64(0)
	for _, value := range raw[2:8] {
		authority = authority<<8 | uint64(value)
	}
	result := "S-" + strconv.FormatUint(uint64(raw[0]), 10) + "-" + strconv.FormatUint(authority, 10)
	for i := 0; i < count; i++ {
		result += "-" + strconv.FormatUint(uint64(binary.LittleEndian.Uint32(raw[8+i*4:])), 10)
	}
	return result, nil
}

func ldapSIDFilterValue(raw []byte) string {
	var builder strings.Builder
	builder.Grow(len(raw) * 3)
	const hex = "0123456789abcdef"
	for _, value := range raw {
		builder.WriteByte('\\')
		builder.WriteByte(hex[value>>4])
		builder.WriteByte(hex[value&0x0f])
	}
	return builder.String()
}

func sortedUnique(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	result := append([]string(nil), values...)
	sort.Strings(result)
	write := 0
	for _, value := range result {
		if value == "" {
			continue
		}
		if write > 0 && result[write-1] == value {
			continue
		}
		result[write] = value
		write++
	}
	return result[:write]
}
