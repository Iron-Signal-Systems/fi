// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/windows/crlrefresh"
)

func TestRunRefreshAttemptNoChange(
	t *testing.T,
) {
	now :=
		time.Date(
			2026,
			time.October,
			4,
			21,
			30,
			0,
			0,
			time.UTC,
		)

	journal :=
		filepath.Join(
			t.TempDir(),
			"crl-refresh.jsonl",
		)

	if err :=
		os.WriteFile(
			journal,
			nil,
			0600,
		); err != nil {
		t.Fatal(err)
	}

	refreshCalled := false

	dependencies :=
		runtimeDependencies{
			appendJournal: appendRefreshJournal,

			domainDNS: func() (
				string,
				error,
			) {
				return "iss.local", nil
			},

			now: func() time.Time {
				return now
			},

			refresh: func(
				options crlrefresh.Options,
			) (
				crlrefresh.Result,
				error,
			) {
				refreshCalled = true

				if options.DomainDNS !=
					"iss.local" {
					t.Fatalf(
						"DomainDNS=%q",
						options.DomainDNS,
					)
				}

				if options.TrustConfigPath !=
					"trust.conf" {
					t.Fatalf(
						"TrustConfigPath=%q",
						options.TrustConfigPath,
					)
				}

				if options.TransactionID == "" {
					t.Fatal(
						"transaction ID is empty",
					)
				}

				return crlrefresh.Result{
					CandidateCRLNumber: "43",
					CandidateSHA256:    "candidate",
					NextUpdate: now.Add(
						72 * time.Hour,
					).Format(
						time.RFC3339,
					),
					PreviousCRLNumber: "43",
					PreviousSHA256:    "current",
					Reason:            "candidate transport CRL matches current signed DER",
					Source:            "ldap:///CN=CA,DC=iss,DC=local?certificateRevocationList?base?objectClass=cRLDistributionPoint",
					ThisUpdate: now.Add(
						-time.Hour,
					).Format(
						time.RFC3339,
					),
				}, nil
			},
		}

	delay, err :=
		runRefreshAttempt(
			context.Background(),
			runtimeConfig{
				JournalPath:     journal,
				TrustConfigPath: "trust.conf",
			},
			dependencies,
		)
	if err != nil {
		t.Fatal(err)
	}

	if !refreshCalled {
		t.Fatal(
			"refresh transaction was not called",
		)
	}

	if delay !=
		24*time.Hour {
		t.Fatalf(
			"delay=%s want=24h",
			delay,
		)
	}

	records :=
		readRefreshJournalTestRecords(
			t,
			journal,
		)

	if len(records) != 2 {
		t.Fatalf(
			"journal records=%d want=2",
			len(records),
		)
	}

	if records[0].RecordKind !=
		"CRLRefreshStarted" {
		t.Fatalf(
			"first record kind=%q",
			records[0].RecordKind,
		)
	}

	if records[1].RecordKind !=
		"CRLRefreshFinished" {
		t.Fatalf(
			"second record kind=%q",
			records[1].RecordKind,
		)
	}

	if records[1].Outcome !=
		"NoChange" {
		t.Fatalf(
			"outcome=%q",
			records[1].Outcome,
		)
	}

	if records[0].TransactionID !=
		records[1].TransactionID {
		t.Fatal(
			"started/finished transaction IDs differ",
		)
	}
}

func TestRunRefreshAttemptFailsClosedBeforeRefreshWhenJournalMissing(
	t *testing.T,
) {
	refreshCalled := false

	_, err :=
		runRefreshAttempt(
			context.Background(),
			runtimeConfig{
				JournalPath: filepath.Join(
					t.TempDir(),
					"missing.jsonl",
				),
				TrustConfigPath: "trust.conf",
			},
			runtimeDependencies{
				appendJournal: appendRefreshJournal,

				domainDNS: func() (
					string,
					error,
				) {
					return "iss.local", nil
				},

				now: func() time.Time {
					return time.Now()
				},

				refresh: func(
					crlrefresh.Options,
				) (
					crlrefresh.Result,
					error,
				) {
					refreshCalled = true

					return crlrefresh.Result{}, nil
				},
			},
		)

	if err == nil {
		t.Fatal(
			"missing pre-created journal was unexpectedly accepted",
		)
	}

	if refreshCalled {
		t.Fatal(
			"refresh executed despite missing start journal boundary",
		)
	}
}

func TestRunRefreshAttemptJournalsErrorAndRetries(
	t *testing.T,
) {
	now :=
		time.Date(
			2026,
			time.October,
			4,
			21,
			30,
			0,
			0,
			time.UTC,
		)

	journal :=
		filepath.Join(
			t.TempDir(),
			"crl-refresh.jsonl",
		)

	if err :=
		os.WriteFile(
			journal,
			nil,
			0600,
		); err != nil {
		t.Fatal(err)
	}

	delay, err :=
		runRefreshAttempt(
			context.Background(),
			runtimeConfig{
				JournalPath:     journal,
				TrustConfigPath: "trust.conf",
			},
			runtimeDependencies{
				appendJournal: appendRefreshJournal,

				domainDNS: func() (
					string,
					error,
				) {
					return "iss.local", nil
				},

				now: func() time.Time {
					return now
				},

				refresh: func(
					crlrefresh.Options,
				) (
					crlrefresh.Result,
					error,
				) {
					return crlrefresh.Result{},
						errors.New(
							"synthetic acquisition failure",
						)
				},
			},
		)

	if err == nil {
		t.Fatal(
			"refresh acquisition failure was not surfaced",
		)
	}

	if !errors.Is(
		err,
		errRefreshAttemptFailed,
	) {
		t.Fatalf(
			"error=%v want errRefreshAttemptFailed",
			err,
		)
	}

	if delay !=
		refreshRetryInterval {
		t.Fatalf(
			"retry delay=%s want=%s",
			delay,
			refreshRetryInterval,
		)
	}

	records :=
		readRefreshJournalTestRecords(
			t,
			journal,
		)

	if len(records) != 2 {
		t.Fatalf(
			"journal records=%d want=2",
			len(records),
		)
	}

	if records[1].Outcome !=
		"Error" {
		t.Fatalf(
			"outcome=%q",
			records[1].Outcome,
		)
	}

	if records[1].Error !=
		"synthetic acquisition failure" {
		t.Fatalf(
			"error=%q",
			records[1].Error,
		)
	}
}
func TestNextRefreshDelayMovesToHourlyInsideLeadWindow(
	t *testing.T,
) {
	now :=
		time.Date(
			2026,
			time.October,
			4,
			21,
			30,
			0,
			0,
			time.UTC,
		)

	result :=
		crlrefresh.Result{
			NextUpdate: now.Add(
				12 * time.Hour,
			).Format(
				time.RFC3339,
			),
		}

	delay :=
		nextRefreshDelay(
			now,
			result,
			false,
		)

	if delay !=
		refreshRetryInterval {
		t.Fatalf(
			"delay=%s want=%s",
			delay,
			refreshRetryInterval,
		)
	}
}

func TestRunRefreshLoopKeepsServiceAliveAcrossRefreshFailure(
	t *testing.T,
) {
	now :=
		time.Date(
			2026,
			time.October,
			5,
			9,
			0,
			0,
			0,
			time.UTC,
		)

	journal :=
		filepath.Join(
			t.TempDir(),
			"crl-refresh.jsonl",
		)

	if err :=
		os.WriteFile(
			journal,
			nil,
			0600,
		); err != nil {
		t.Fatal(err)
	}

	ctx, cancel :=
		context.WithCancel(
			context.Background(),
		)
	defer cancel()

	attempts := 0

	dependencies :=
		runtimeDependencies{
			appendJournal: appendRefreshJournal,

			domainDNS: func() (
				string,
				error,
			) {
				return "iss.local", nil
			},

			now: func() time.Time {
				return now
			},

			refresh: func(
				crlrefresh.Options,
			) (
				crlrefresh.Result,
				error,
			) {
				attempts++

				cancel()

				return crlrefresh.Result{},
					errors.New(
						"synthetic retryable refresh failure",
					)
			},
		}

	if err :=
		runRefreshLoop(
			ctx,
			runtimeConfig{
				JournalPath:     journal,
				TrustConfigPath: "trust.conf",
			},
			dependencies,
		); err != nil {
		t.Fatal(err)
	}

	if attempts != 1 {
		t.Fatalf(
			"refresh attempts=%d want=1",
			attempts,
		)
	}

	records :=
		readRefreshJournalTestRecords(
			t,
			journal,
		)

	if len(records) != 2 {
		t.Fatalf(
			"journal records=%d want=2",
			len(records),
		)
	}

	if records[1].Outcome !=
		"Error" {
		t.Fatalf(
			"finished outcome=%q want=Error",
			records[1].Outcome,
		)
	}
}

func TestAppendRefreshJournalPreservesExistingPrefix(
	t *testing.T,
) {
	path :=
		filepath.Join(
			t.TempDir(),
			"crl-refresh.jsonl",
		)

	const prefix = "{\"record_kind\":\"ExistingRecord\"}\n"

	if err :=
		os.WriteFile(
			path,
			[]byte(
				prefix,
			),
			0600,
		); err != nil {
		t.Fatal(err)
	}

	record :=
		refreshJournalRecord{
			Outcome:       "NoChange",
			RecordKind:    "CRLRefreshFinished",
			Service:       windowsCRLRefresherServiceName,
			Timestamp:     "2026-10-05T09:00:00Z",
			TransactionID: "refresh-test",
		}

	if err :=
		appendRefreshJournal(
			path,
			record,
		); err != nil {
		t.Fatal(err)
	}

	value, err :=
		os.ReadFile(
			path,
		)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.HasPrefix(
		string(
			value,
		),
		prefix,
	) {
		t.Fatalf(
			"existing journal prefix changed: %q",
			value,
		)
	}

	records :=
		bytesLines(
			value,
		)

	if len(records) != 2 {
		t.Fatalf(
			"journal lines=%d want=2",
			len(records),
		)
	}
}
func readRefreshJournalTestRecords(
	t *testing.T,
	path string,
) []refreshJournalRecord {
	t.Helper()

	value, err :=
		os.ReadFile(
			path,
		)
	if err != nil {
		t.Fatal(err)
	}

	var records []refreshJournalRecord

	for _, line := range bytesLines(
		value,
	) {
		var record refreshJournalRecord

		if err :=
			json.Unmarshal(
				line,
				&record,
			); err != nil {
			t.Fatal(err)
		}

		records =
			append(
				records,
				record,
			)
	}

	return records
}

func bytesLines(
	value []byte,
) [][]byte {
	var result [][]byte

	start := 0

	for index, current := range value {
		if current != '\n' {
			continue
		}

		if index > start {
			result =
				append(
					result,
					value[start:index],
				)
		}

		start =
			index + 1
	}

	return result
}
