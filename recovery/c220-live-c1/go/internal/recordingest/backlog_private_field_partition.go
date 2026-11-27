// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// EXPERIMENTAL: private-only Security event field partition construction.
// This context switch never changes the canonical fi.* system of record.
package recordingest

import (
	"context"
	"errors"
	"fmt"
)

type privateSecurityFieldPartitionsKey struct{}
type privateSecurityFieldFailWindowKey struct{}

// WithPrivateSecurityFieldPartitions opts an isolated full-W128 recovery trial
// into detached field-table COPY + validated FK + atomic partition attachment.
// The database MUST have been installed by the isolated schema experiment.
func WithPrivateSecurityFieldPartitions(ctx context.Context) context.Context {
	return context.WithValue(ctx, privateSecurityFieldPartitionsKey{}, true)
}

func privateSecurityFieldPartitionsEnabled(ctx context.Context) bool {
	return ctx.Value(privateSecurityFieldPartitionsKey{}) == true
}

// WithPrivateSecurityFieldLateFailure is ONLY an acceptance-test injection.
// It runs after field FK validation and partition attachment but before the
// private typed-window marker, proving rollback of the complete W128 tx.
func WithPrivateSecurityFieldLateFailure(ctx context.Context, index int) (context.Context, error) {
	if index < 1 || index > 999999 {
		return nil, errors.New("FI field partition failpoint: invalid window")
	}
	return context.WithValue(ctx, privateSecurityFieldFailWindowKey{}, index), nil
}

func privateSecurityFieldShouldFail(ctx context.Context, index int) bool {
	n, ok := ctx.Value(privateSecurityFieldFailWindowKey{}).(int)
	return ok && n == index
}

// No user-supplied SQL identifiers. SQL functions derive their own identifier
// from the integer and the Go wrapper checks that exact same derivation.
func privateSecurityFieldWindowTable(index int) (string, error) {
	if index < 1 || index > 999999 {
		return "", fmt.Errorf("FI field partition: unsupported window index %d", index)
	}
	return fmt.Sprintf("windows_security_event_field_w%06d", index), nil
}
