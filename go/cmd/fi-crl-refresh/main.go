// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

// fi-crl-refresh retrieves Microsoft AD CS base CRLs over HTTP(S), verifies
// them against FI's installed issuing CAs, and atomically replaces older files.
// This intentionally does NOT reload active FI receiver or ingest processes.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/crlrefresh"
	"github.com/Iron-Signal-Systems/fi/go/internal/receivertrust"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
}

func run() error {
	var transportURL string
	var batchURL string
	flag.StringVar(&transportURL, "transport-url", "", "approved HTTP(S) CDP for the FI transport issuing CA")
	flag.StringVar(&batchURL, "batch-url", "", "approved HTTP(S) CDP for the FI batch-signing CA")
	flag.Parse()
	if flag.NArg() != 0 || transportURL == "" || batchURL == "" {
		return errors.New("usage: fi-crl-refresh -transport-url <http(s)://...crl> -batch-url <http(s)://...crl>")
	}
	if os.Geteuid() != 0 {
		return errors.New("CRL publication requires root privileges")
	}
	for _, check := range []struct {
		name  string
		state receivertrust.ValidationState
	}{
		{"root CA", receivertrust.InspectRootCAValidation()},
		{"transport issuing CA", receivertrust.InspectTransportIssuerValidation()},
		{"batch-signing issuing CA", receivertrust.InspectBatchIssuerValidation()},
	} {
		if !check.state.Valid {
			return fmt.Errorf("%s trust validation failed: %s", check.name, check.state.Detail)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	targets := []crlrefresh.Target{
		{Name: "transport", URL: transportURL, IssuerPath: receivertrust.TransportIssuerPath, InstalledPath: receivertrust.TransportCRLPath},
		{Name: "batch", URL: batchURL, IssuerPath: receivertrust.BatchIssuerPath, InstalledPath: receivertrust.BatchCRLPath},
	}
	fmt.Println("FI CRL refresh: retrieving and verifying both signed CRLs")
	results, err := crlrefresh.Refresh(ctx, targets, time.Now())
	if err != nil {
		return err
	}
	changed := false
	for _, r := range results {
		state := "UNCHANGED"
		if r.Changed {
			state = "UPDATED"
			changed = true
		}
		fmt.Printf("CRL %-10s %-9s number=%s nextUpdate=%s\n", r.Name, state, r.Number, r.NextUpdate.UTC().Format(time.RFC3339))
	}
	if changed {
		fmt.Println("ACTION REQUIRED: receiver and ingest worker still hold the previous CRLs in memory; activate the updated trust by a controlled service restart. Live reload is not yet implemented.")
	}
	return nil
}
