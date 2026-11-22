// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// c1GovernedPendingSchema is an exact, compile-time-only SQL destination.
// No remote frame or runtime environment may supply a schema name.
const c1GovernedPendingSchema = "fi_c1_pending"

// privateProjectionTx routes only FI's existing SQL statements from a
// transaction into the shadow copy of the full relational schema. It is an
// experimental projector boundary for isolated testing, NOT a production
// acceptance or publication path. The caller owns the transaction.
//
// This is not a generic SQL gateway and must not receive untrusted SQL.
// Its only intended client is FI's existing statically authored projectors.
type privateProjectionTx struct {
	pgx.Tx
	fieldPartition string // empty unless the isolated, opt-in W128 experiment is active
	schema string // empty defaults to the unchanged private benchmark target
}

// Only these two compile-time-known schemas are permitted. Never accept
// schema names from a network frame, user input, or dynamic SQL identifier.
func (p privateProjectionTx) destinationSchema() (string, error) {
	schema := p.schema
	if schema == "" {
		schema = privateProjectionSchema
	}
	if schema != privateProjectionSchema && schema != c1GovernedPendingSchema {
		return "", errors.New("FI C1: unapproved relational projection schema")
	}
	return schema, nil
}

func (p privateProjectionTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	rewritten, err := rewritePrivateProjectionStatementTo(sql, p.schema)
	if err != nil {
		return pgconn.CommandTag{}, err
	}
	return p.Tx.Exec(ctx, rewritten, args...)
}
func (p privateProjectionTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	rewritten, err := rewritePrivateProjectionStatementTo(sql, p.schema)
	if err != nil {
		return nil, err
	}
	return p.Tx.Query(ctx, rewritten, args...)
}
func (p privateProjectionTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	rewritten, err := rewritePrivateProjectionStatementTo(sql, p.schema)
	if err != nil {
		return privateProjectionErrorRow{err: err}
	}
	return p.Tx.QueryRow(ctx, rewritten, args...)
}
func (p privateProjectionTx) CopyFrom(ctx context.Context, table pgx.Identifier, cols []string, src pgx.CopyFromSource) (int64, error) {
	if len(table) != 2 || table[0] != "fi" || table[1] == "" {
		return 0, errors.New("FI private projector: COPY target must be explicitly qualified fi table")
	}
	schema, err := p.destinationSchema()
	if err != nil {
		return 0, err
	}
	if table[1] == "windows_security_event_field" && p.fieldPartition != "" {
		if schema != privateProjectionSchema {
			return 0, errors.New("FI C1: experimental field partitions are forbidden in governed pending")
		}
		return p.Tx.CopyFrom(ctx, pgx.Identifier{schema, p.fieldPartition}, cols, src)
	}
	return p.Tx.CopyFrom(ctx, pgx.Identifier{schema, table[1]}, cols, src)
}

// Prevent alternate access paths from bypassing the qualified SQL rewrite.
// The existing FI record projectors do not use any of these methods.
func (p privateProjectionTx) Begin(context.Context) (pgx.Tx, error) {
	return nil, errors.New("FI private projector: nested transactions are forbidden")
}
func (p privateProjectionTx) Prepare(context.Context, string, string) (*pgconn.StatementDescription, error) {
	return nil, errors.New("FI private projector: prepared statements are forbidden")
}
func (p privateProjectionTx) Conn() *pgx.Conn { return nil }
func (p privateProjectionTx) SendBatch(context.Context, *pgx.Batch) pgx.BatchResults {
	return privateProjectionFailedBatch{}
}
func (p privateProjectionTx) LargeObjects() pgx.LargeObjects { return pgx.LargeObjects{} }

type privateProjectionErrorRow struct{ err error }

func (r privateProjectionErrorRow) Scan(...any) error { return r.err }

type privateProjectionFailedBatch struct{}

func (privateProjectionFailedBatch) Exec() (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, errors.New("FI private projector: batch execution is forbidden")
}
func (privateProjectionFailedBatch) Query() (pgx.Rows, error) {
	return nil, errors.New("FI private projector: batch querying is forbidden")
}
func (privateProjectionFailedBatch) QueryRow() pgx.Row {
	return privateProjectionErrorRow{errors.New("FI private projector: batch querying is forbidden")}
}
func (privateProjectionFailedBatch) Close() error {
	return errors.New("FI private projector: batch execution is forbidden")
}

// rewritePrivateProjectionStatement substitutes the *qualified identifier*
// token fi. outside SQL strings/comments. Unknown SQL verb, unqualified
// statement, multiple statements, dollar-quote or unterminated literal
// fails closed. All projector statements must be statically authored.
func rewritePrivateProjectionStatement(sql string) (string, error) {
	return rewritePrivateProjectionStatementTo(sql, privateProjectionSchema)
}

// This SQL parser accepts only static qualified FI projector SQL. It changes
// the destination namespace without changing the original typed projection.
func rewritePrivateProjectionStatementTo(sql, targetSchema string) (string, error) {
	if targetSchema == "" {
		targetSchema = privateProjectionSchema
	}
	if targetSchema != privateProjectionSchema && targetSchema != c1GovernedPendingSchema {
		return "", errors.New("FI C1: unapproved relational projection schema")
	}
	words := strings.Fields(sql)
	if len(words) == 0 {
		return "", errors.New("FI private projector: empty SQL")
	}
	verb := strings.ToUpper(words[0])
	if verb != "SELECT" && verb != "INSERT" && verb != "WITH" {
		return "", errors.New("FI private projector: only SELECT/INSERT/WITH are allowed")
	}
	if strings.Contains(sql, privateProjectionSchema+".") || strings.Contains(sql, "fi_c1_pending.") {
		return "", errors.New("FI private projector: already-qualified private reference prohibited")
	}
	var out strings.Builder
	out.Grow(len(sql) + 32)
	refs := 0
	for i := 0; i < len(sql); {
		switch {
		case sql[i] == '\'':
			start := i
			i++
			closed := false
			for i < len(sql) {
				if sql[i] == '\'' {
					if i+1 < len(sql) && sql[i+1] == '\'' {
						i += 2
						continue
					}
					i++
					closed = true
					break
				}
				i++
			}
			if !closed {
				return "", errors.New("FI private projector: unterminated SQL literal")
			}
			out.WriteString(sql[start:i])
		case sql[i] == '"':
			start := i
			i++
			closed := false
			for i < len(sql) {
				if sql[i] == '"' {
					if i+1 < len(sql) && sql[i+1] == '"' {
						i += 2
						continue
					}
					i++
					closed = true
					break
				}
				i++
			}
			if !closed {
				return "", errors.New("FI private projector: unterminated SQL identifier")
			}
			out.WriteString(sql[start:i])
		case i+1 < len(sql) && sql[i] == '-' && sql[i+1] == '-':
			start := i
			i += 2
			for i < len(sql) && sql[i] != '\n' {
				i++
			}
			out.WriteString(sql[start:i])
		case i+1 < len(sql) && sql[i] == '/' && sql[i+1] == '*':
			start := i
			i += 2
			for i+1 < len(sql) && !(sql[i] == '*' && sql[i+1] == '/') {
				i++
			}
			if i+1 >= len(sql) {
				return "", errors.New("FI private projector: unterminated SQL comment")
			}
			i += 2
			out.WriteString(sql[start:i])
		case i+1 < len(sql) && sql[i] == '$' && sql[i+1] == '$':
			return "", errors.New("FI private projector: dollar quotes are not supported")
		case sql[i] == ';':
			return "", errors.New("FI private projector: multiple or terminated SQL statements forbidden")
		case i+3 <= len(sql) && sql[i:i+3] == "fi." &&
			(i == 0 || !sqlIdentifierCharacter(rune(sql[i-1]))) &&
			i+3 < len(sql) && sqlIdentifierCharacter(rune(sql[i+3])):
			out.WriteString(targetSchema + ".")
			i += 3
			refs++
		default:
			out.WriteByte(sql[i])
			i++
		}
	}
	if refs == 0 {
		return "", fmt.Errorf("FI private projector: statement has no qualified canonical schema reference")
	}
	return out.String(), nil
}
func sqlIdentifierCharacter(r rune) bool {
	return r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r)
}
