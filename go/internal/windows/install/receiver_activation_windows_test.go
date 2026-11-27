// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"strings"
	"testing"
)

func TestReceiverPendingPlanInputIsTransient(t *testing.T) {
	t.Parallel()

	inputs := PlanInputs{
		ReceiverPending: true,
	}
	if !inputs.ConfigEmpty() {
		t.Fatal("receiver-pending state unexpectedly became deployment configuration")
	}
	if !inputs.Empty() {
		t.Fatal("receiver-pending state unexpectedly made otherwise empty plan input persistent")
	}
}

func TestNormalizeReceiverPendingPlanChangesOnlySenderActivation(t *testing.T) {
	t.Parallel()

	plan := InstallPlan{
		Actions: []PlanAction{
			{
				Action:    planActionReconcile,
				Authority: "SCM",
				Detail:    "sender automatic",
				Target:    "FISender",
			},
			{
				Action:    planActionReconcile,
				Authority: "RUNTIME",
				Detail:    "sender running",
				Target:    "FISender",
			},
			{
				Action:    planActionReconcile,
				Authority: "RUNTIME",
				Detail:    "collector running",
				Target:    "FICollector",
			},
		},
	}

	normalized := NormalizeReceiverPendingPlan(plan)
	if normalized.Actions[0].Action != planActionNoChange ||
		normalized.Actions[1].Action != planActionNoChange {
		t.Fatalf("FISender pending actions were not normalized: %+v", normalized.Actions)
	}
	if !strings.Contains(normalized.Actions[0].Detail, receiverPendingPlanMarker) ||
		!strings.Contains(normalized.Actions[1].Detail, receiverPendingPlanMarker) {
		t.Fatalf("FISender pending marker missing: %+v", normalized.Actions)
	}
	if normalized.Actions[2] != plan.Actions[2] {
		t.Fatalf("non-sender action changed: got=%+v want=%+v", normalized.Actions[2], plan.Actions[2])
	}
}

func TestRequiresReceiverActivation(t *testing.T) {
	t.Parallel()

	if RequiresReceiverActivation(InstallPlan{}) {
		t.Fatal("empty plan unexpectedly requires receiver activation")
	}
	plan := InstallPlan{
		Actions: []PlanAction{
			{
				Action:    planActionReconcile,
				Authority: "SCM",
				Target:    "FISender",
			},
		},
	}
	if !RequiresReceiverActivation(plan) {
		t.Fatal("FISender SCM mutation did not require receiver activation")
	}
}

func TestReceiverActivationCertificateIsRevoked(t *testing.T) {
	t.Parallel()

	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(42),
	}
	crl := &x509.RevocationList{
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{SerialNumber: big.NewInt(42)},
		},
	}
	if !receiverActivationCertificateIsRevoked(certificate, crl) {
		t.Fatal("matching CRL serial was not detected")
	}
}

func TestReceiverActivationTLSVersion(t *testing.T) {
	t.Parallel()

	if got := receiverActivationTLSVersion(tls.VersionTLS12); got != "TLS1.2" {
		t.Fatalf("TLS1.2=%q", got)
	}
	if got := receiverActivationTLSVersion(tls.VersionTLS13); got != "TLS1.3" {
		t.Fatalf("TLS1.3=%q", got)
	}
}

func TestReceiverPendingPlanConvertsAutomaticStoppedSender(
	t *testing.T,
) {
	t.Parallel()

	identities, err := DeriveDesiredFIIdentities(
		"ISS-FS-19",
		"ISS",
	)
	if err != nil {
		t.Fatal(err)
	}

	report := Report{
		Services: []ServiceState{
			{
				Account:        identities.CollectorSender.Account,
				BinaryPath:     `"C:\Program Files\FI\fi-collector.exe" -service`,
				ManagedAccount: "true",
				Name:           "FICollector",
				Presence:       presencePresent,
				SIDType:        "UNRESTRICTED",
				StartType:      "Automatic",
				State:          "Running",
			},
			{
				Account:        identities.USNReader.Account,
				BinaryPath:     `"C:\Program Files\FI\fi-usn-reader.exe"`,
				ManagedAccount: "true",
				Name:           "FIUSNReader",
				Presence:       presencePresent,
				SIDType:        "UNRESTRICTED",
				StartType:      "Automatic",
				State:          "Running",
			},
			{
				Account:        identities.ObjReader.Account,
				BinaryPath:     `"C:\Program Files\FI\fi-obj-reader.exe"`,
				ManagedAccount: "true",
				Name:           "FIObjReader",
				Presence:       presencePresent,
				SIDType:        "UNRESTRICTED",
				StartType:      "Automatic",
				State:          "Running",
			},
			{
				Account:        identities.CRLRefresher.Account,
				BinaryPath:     `"C:\Program Files\FI\fi-crl-refresher.exe"`,
				ManagedAccount: "true",
				Name:           "FICRLRefresher",
				Presence:       presencePresent,
				SIDType:        "NONE",
				StartType:      "Automatic",
				State:          "Running",
			},
			{
				Account:        identities.CollectorSender.Account,
				BinaryPath:     `"C:\Program Files\FI\fi-sender.exe"`,
				ManagedAccount: "true",
				Name:           "FISender",
				Presence:       presencePresent,
				SIDType:        "NONE",
				StartType:      "Automatic",
				State:          "Stopped",
			},
		},
	}

	plan := InstallPlan{}
	planServices(
		&plan,
		report,
		identities,
		nil,
		true,
	)

	var senderSCM *PlanAction
	var senderRuntime *PlanAction
	for index := range plan.Actions {
		action := &plan.Actions[index]
		if action.Target != "FISender" {
			continue
		}
		switch action.Authority {
		case "SCM":
			senderSCM = action
		case "RUNTIME":
			senderRuntime = action
		}
	}

	if senderSCM == nil ||
		senderSCM.Action != planActionReconcile ||
		!strings.Contains(senderSCM.Detail, "start=Manual") ||
		!strings.Contains(senderSCM.Detail, receiverPendingPlanMarker) {
		t.Fatalf(
			"automatic/stopped FISender did not plan Manual receiver-pending SCM reconciliation: %+v",
			senderSCM,
		)
	}

	if senderRuntime == nil ||
		senderRuntime.Action != planActionNoChange ||
		!strings.Contains(senderRuntime.Detail, receiverPendingPlanMarker) {
		t.Fatalf(
			"stopped FISender did not remain stopped in receiver-pending runtime plan: %+v",
			senderRuntime,
		)
	}
}
