// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/windows/crlrefresh"
)

const (
	defaultRefreshJournalPath = `C:\ProgramData\FI\crl-refresh\crl-refresh.jsonl`

	refreshSuccessInterval = 24 * time.Hour

	refreshRetryInterval = time.Hour

	refreshExpiryLead = 24 * time.Hour
)

var errRefreshAttemptFailed = errors.New(
	"CRL refresh attempt failed",
)

type runtimeConfig struct {
	JournalPath     string
	TrustConfigPath string
}

type runtimeDependencies struct {
	appendJournal func(
		string,
		refreshJournalRecord,
	) error

	domainDNS func() (
		string,
		error,
	)

	now func() time.Time

	refresh func(
		crlrefresh.Options,
	) (crlrefresh.Result, error)
}

type refreshJournalRecord struct {
	Activated          bool   `json:"activated,omitempty"`
	BackupPath         string `json:"backup_path,omitempty"`
	CandidateCRLNumber string `json:"candidate_crl_number,omitempty"`
	CandidateSHA256    string `json:"candidate_sha256,omitempty"`
	Error              string `json:"error,omitempty"`
	FailedPath         string `json:"failed_path,omitempty"`
	NextAttempt        string `json:"next_attempt,omitempty"`
	NextUpdate         string `json:"next_update,omitempty"`
	Outcome            string `json:"outcome"`
	PreviousCRLNumber  string `json:"previous_crl_number,omitempty"`
	PreviousSHA256     string `json:"previous_sha256,omitempty"`
	Reason             string `json:"reason,omitempty"`
	RecordKind         string `json:"record_kind"`
	Service            string `json:"service"`
	Source             string `json:"source,omitempty"`
	ThisUpdate         string `json:"this_update,omitempty"`
	Timestamp          string `json:"timestamp"`
	TransactionID      string `json:"transaction_id"`
}

func defaultRuntimeConfig() runtimeConfig {
	return runtimeConfig{
		JournalPath:     defaultRefreshJournalPath,
		TrustConfigPath: crlrefresh.DefaultTrustConfigPath,
	}
}

func defaultRuntimeDependencies() runtimeDependencies {
	return runtimeDependencies{
		appendJournal: appendRefreshJournal,
		domainDNS:     computerDNSDomain,
		now:           time.Now,
		refresh:       crlrefresh.RefreshOnce,
	}
}

func nextRefreshDelay(
	now time.Time,
	result crlrefresh.Result,
	failed bool,
) time.Duration {
	if failed {
		return refreshRetryInterval
	}

	now =
		now.UTC()

	next :=
		now.Add(
			refreshSuccessInterval,
		)

	if strings.TrimSpace(
		result.NextUpdate,
	) == "" {
		return refreshRetryInterval
	}

	nextUpdate, err :=
		time.Parse(
			time.RFC3339,
			result.NextUpdate,
		)
	if err != nil {
		return refreshRetryInterval
	}

	if !nextUpdate.After(
		now,
	) {
		return refreshRetryInterval
	}

	refreshBeforeExpiry :=
		nextUpdate.Add(
			-refreshExpiryLead,
		)

	if refreshBeforeExpiry.Before(
		next,
	) {
		next =
			refreshBeforeExpiry
	}

	if !next.After(
		now,
	) {
		return refreshRetryInterval
	}

	return next.Sub(
		now,
	)
}

func refreshTransactionID(
	at time.Time,
) string {
	return fmt.Sprintf(
		"refresh-%d",
		at.UTC().UnixNano(),
	)
}

func runRefreshAttempt(
	ctx context.Context,
	config runtimeConfig,
	dependencies runtimeDependencies,
) (
	time.Duration,
	error,
) {
	if ctx == nil {
		return 0, errors.New(
			"CRL refresh context is required",
		)
	}

	if dependencies.appendJournal == nil ||
		dependencies.domainDNS == nil ||
		dependencies.now == nil ||
		dependencies.refresh == nil {
		return 0, errors.New(
			"CRL refresh runtime dependencies are incomplete",
		)
	}

	if strings.TrimSpace(
		config.JournalPath,
	) == "" {
		return 0, errors.New(
			"CRL refresh journal path is required",
		)
	}

	if strings.TrimSpace(
		config.TrustConfigPath,
	) == "" {
		return 0, errors.New(
			"CRL refresh trust config path is required",
		)
	}

	select {
	case <-ctx.Done():
		return 0, nil

	default:
	}

	at :=
		dependencies.now().
			UTC()

	transactionID :=
		refreshTransactionID(
			at,
		)

	started :=
		refreshJournalRecord{
			Outcome:    "Started",
			RecordKind: "CRLRefreshStarted",
			Service:    windowsCRLRefresherServiceName,
			Timestamp: at.Format(
				time.RFC3339Nano,
			),
			TransactionID: transactionID,
		}

	// Journal the transaction boundary before performing any CRL acquisition
	// or activation. If this append fails, no refresh mutation is attempted.
	if err :=
		dependencies.appendJournal(
			config.JournalPath,
			started,
		); err != nil {
		return 0, fmt.Errorf(
			"persist CRL refresh start boundary: %w",
			err,
		)
	}

	domainDNS, domainErr :=
		dependencies.domainDNS()

	var (
		result     crlrefresh.Result
		refreshErr error
	)

	if domainErr != nil {
		refreshErr =
			fmt.Errorf(
				"resolve Windows DNS domain for CRL refresh: %w",
				domainErr,
			)
	} else {
		result, refreshErr =
			dependencies.refresh(
				crlrefresh.Options{
					At:              at,
					DomainDNS:       domainDNS,
					TransactionID:   transactionID,
					TrustConfigPath: config.TrustConfigPath,
				},
			)
	}

	delay :=
		nextRefreshDelay(
			at,
			result,
			refreshErr != nil,
		)

	finished :=
		refreshJournalRecord{
			Activated:          result.Activated,
			BackupPath:         result.BackupPath,
			CandidateCRLNumber: result.CandidateCRLNumber,
			CandidateSHA256:    result.CandidateSHA256,
			FailedPath:         result.FailedPath,
			NextAttempt: at.Add(
				delay,
			).UTC().Format(
				time.RFC3339Nano,
			),
			NextUpdate:        result.NextUpdate,
			PreviousCRLNumber: result.PreviousCRLNumber,
			PreviousSHA256:    result.PreviousSHA256,
			Reason:            result.Reason,
			RecordKind:        "CRLRefreshFinished",
			Service:           windowsCRLRefresherServiceName,
			Source: sanitizeRefreshSource(
				result.Source,
			),
			ThisUpdate: result.ThisUpdate,
			Timestamp: dependencies.now().
				UTC().
				Format(
					time.RFC3339Nano,
				),
			TransactionID: transactionID,
		}

	switch {
	case refreshErr != nil:
		finished.Error =
			refreshErr.Error()

		finished.Outcome =
			"Error"

	case result.Activated:
		finished.Outcome =
			"Activated"

	default:
		finished.Outcome =
			"NoChange"
	}

	if err :=
		dependencies.appendJournal(
			config.JournalPath,
			finished,
		); err != nil {
		return 0, errors.Join(
			refreshErr,
			fmt.Errorf(
				"persist CRL refresh completion boundary: %w",
				err,
			),
		)
	}

	// Acquisition, validation, and activation failures are durably journaled
	// before returning a classified error. The service loop retries this class,
	// while the interactive -once command reports the failure to its caller.
	//
	// Journal failure remains terminal because FI must never evaluate or mutate
	// transport trust without its audit boundary.
	if refreshErr != nil {
		return delay, fmt.Errorf(
			"%w: %v",
			errRefreshAttemptFailed,
			refreshErr,
		)
	}

	return delay, nil
}

func runRefreshLoop(
	ctx context.Context,
	config runtimeConfig,
	dependencies runtimeDependencies,
) error {
	if ctx == nil {
		return errors.New(
			"CRL refresh context is required",
		)
	}

	for {
		delay, err :=
			runRefreshAttempt(
				ctx,
				config,
				dependencies,
			)

		if err != nil &&
			!errors.Is(
				err,
				errRefreshAttemptFailed,
			) {
			return err
		}

		select {
		case <-ctx.Done():
			return nil

		default:
		}

		timer :=
			time.NewTimer(
				delay,
			)

		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}

			return nil

		case <-timer.C:
		}
	}
}
func sanitizeRefreshSource(
	value string,
) string {
	value =
		strings.TrimSpace(
			value,
		)

	if value == "" {
		return ""
	}

	parsed, err :=
		url.Parse(
			value,
		)
	if err != nil {
		return ""
	}

	parsed.User = nil
	parsed.Fragment = ""

	return parsed.String()
}
