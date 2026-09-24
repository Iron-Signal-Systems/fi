// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package recordingest

import (
	"context"
	"errors"
	"io"
	"net"
	"syscall"

	"github.com/jackc/pgx/v5/pgconn"
)

// IsPostgreSQLUnavailable reports whether err represents a PostgreSQL
// connectivity / availability failure for which the ingest worker may safely
// establish a new database session.
//
// This is intentionally narrower than "retry any PostgreSQL error". Schema,
// authority, authentication, configuration, relational-conflict, and ordinary
// SQL errors remain fail-closed.
func IsPostgreSQLUnavailable(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	var parseErr *pgconn.ParseConfigError
	if errors.As(err, &parseErr) {
		return false
	}

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		if len(pgErr.Code) >= 2 && pgErr.Code[:2] == "08" {
			return true
		}

		switch pgErr.Code {
		case
			"53300",
			"57P01",
			"57P02",
			"57P03":
			return true
		default:
			return false
		}
	}

	if errors.Is(err, pgconn.ErrConnClosed) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}

	if pgconn.Timeout(err) {
		return true
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.Timeout() || dnsErr.Temporary()
	}

	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case
			syscall.ECONNABORTED,
			syscall.ECONNREFUSED,
			syscall.ECONNRESET,
			syscall.EHOSTDOWN,
			syscall.EHOSTUNREACH,
			syscall.ENETDOWN,
			syscall.ENETUNREACH,
			syscall.ENOENT,
			syscall.EPIPE,
			syscall.ETIMEDOUT:
			return true
		default:
			return false
		}
	}

	return false
}
