// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package recordingest

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestIsPostgreSQLUnavailable(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil",
			err:  nil,
			want: false,
		},
		{
			name: "context canceled",
			err:  context.Canceled,
			want: false,
		},
		{
			name: "context deadline",
			err:  context.DeadlineExceeded,
			want: false,
		},
		{
			name: "parse configuration",
			err: pgconn.NewParseConfigError(
				"host='unterminated",
				"invalid connection string",
				nil,
			),
			want: false,
		},
		{
			name: "connection exception class",
			err: &pgconn.PgError{
				Code:     "08006",
				Severity: "FATAL",
				Message:  "connection failure",
			},
			want: true,
		},
		{
			name: "administrator shutdown",
			err: &pgconn.PgError{
				Code:     "57P01",
				Severity: "FATAL",
				Message:  "terminating connection",
			},
			want: true,
		},
		{
			name: "cannot connect now",
			err: &pgconn.PgError{
				Code:     "57P03",
				Severity: "FATAL",
				Message:  "database system is starting up",
			},
			want: true,
		},
		{
			name: "too many connections",
			err: &pgconn.PgError{
				Code:     "53300",
				Severity: "FATAL",
				Message:  "too many connections",
			},
			want: true,
		},
		{
			name: "authentication failure",
			err: &pgconn.PgError{
				Code:     "28P01",
				Severity: "FATAL",
				Message:  "password authentication failed",
			},
			want: false,
		},
		{
			name: "database missing",
			err: &pgconn.PgError{
				Code:     "3D000",
				Severity: "FATAL",
				Message:  "database does not exist",
			},
			want: false,
		},
		{
			name: "ordinary relational error",
			err: &pgconn.PgError{
				Code:     "23505",
				Severity: "ERROR",
				Message:  "unique violation",
			},
			want: false,
		},
		{
			name: "closed pg connection",
			err:  pgconn.ErrConnClosed,
			want: true,
		},
		{
			name: "connection refused",
			err: &net.OpError{
				Op:  "dial",
				Net: "unix",
				Err: syscall.ECONNREFUSED,
			},
			want: true,
		},
		{
			name: "unix socket absent",
			err: &net.OpError{
				Op:  "dial",
				Net: "unix",
				Err: syscall.ENOENT,
			},
			want: true,
		},
		{
			name: "permission denied is configuration",
			err: &net.OpError{
				Op:  "dial",
				Net: "unix",
				Err: syscall.EACCES,
			},
			want: false,
		},
		{
			name: "unrelated application error",
			err:  errors.New("recorded generation identity mismatch"),
			want: false,
		},
		{
			name: "joined availability error",
			err: errors.Join(
				errors.New("ingest operation failed"),
				pgconn.ErrConnClosed,
			),
			want: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := IsPostgreSQLUnavailable(test.err)
			if got != test.want {
				t.Fatalf(
					"IsPostgreSQLUnavailable(%v) = %v, want %v",
					test.err,
					got,
					test.want,
				)
			}
		})
	}
}
