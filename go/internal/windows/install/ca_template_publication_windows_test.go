// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"bytes"
	"strings"
	"testing"
)

func testFIThreeTemplateDefinitions() []CATemplateDefinitionSnapshot {
	return []CATemplateDefinitionSnapshot{
		{Name: fiTransportClientTemplateName, OID: "1.2.3.10"},
		{Name: fiBatchSigningTemplateName, OID: "1.2.3.11"},
		{Name: fiReceiverTLSTemplateName, OID: "1.2.3.12"},
	}
}

func testFIThreeTemplateNames() []string {
	return []string{
		fiTransportClientTemplateName,
		fiBatchSigningTemplateName,
		fiReceiverTLSTemplateName,
	}
}

func TestBuildCATemplatePublicationPlanFromCAsBindsExactBeforeAfter(t *testing.T) {
	cas := []enterpriseCertificateAuthorityState{
		{
			Configuration: "ca.example.test\\Example-CA",
			Templates: []string{
				"Administrator",
				"Computer",
			},
		},
	}

	plan, required, err := buildCATemplatePublicationPlanFromCAs(
		"dc.example.test",
		cas,
		testFIThreeTemplateNames(),
		testFIThreeTemplateDefinitions(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !required {
		t.Fatal("expected CA template publication to be required")
	}
	if len(plan.MissingTemplates) != 3 {
		t.Fatalf("unexpected missing templates: %#v", plan.MissingTemplates)
	}
	if got := strings.Join(plan.CurrentTemplates, ","); got != "Administrator,Computer" {
		t.Fatalf("unexpected current values: %q", got)
	}
	if got := strings.Join(plan.ResultingTemplates, ","); got != "Administrator,Computer,FI-Batch-Signing,FI-Receiver-TLS,FI-Transport-Client" {
		t.Fatalf("unexpected resulting values: %q", got)
	}
	if plan.DigestSHA256 == "" {
		t.Fatal("expected publication digest")
	}
}

func TestCATemplatePublicationDigestChangesWithBeforeState(t *testing.T) {
	casA := []enterpriseCertificateAuthorityState{
		{Configuration: "ca.example.test\\Example-CA", Templates: []string{"Computer"}},
	}
	casB := []enterpriseCertificateAuthorityState{
		{Configuration: "ca.example.test\\Example-CA", Templates: []string{"Computer", "User"}},
	}

	planA, requiredA, err := buildCATemplatePublicationPlanFromCAs(
		"dc.example.test",
		casA,
		testFIThreeTemplateNames(),
		testFIThreeTemplateDefinitions(),
	)
	if err != nil || !requiredA {
		t.Fatalf("plan A failed: required=%t err=%v", requiredA, err)
	}
	planB, requiredB, err := buildCATemplatePublicationPlanFromCAs(
		"dc.example.test",
		casB,
		testFIThreeTemplateNames(),
		testFIThreeTemplateDefinitions(),
	)
	if err != nil || !requiredB {
		t.Fatalf("plan B failed: required=%t err=%v", requiredB, err)
	}
	if planA.DigestSHA256 == planB.DigestSHA256 {
		t.Fatal("digest must change when the current CA certificateTemplates values change")
	}
}

func TestCATemplatePublicationDigestChangesWithTemplateOID(t *testing.T) {
	cas := []enterpriseCertificateAuthorityState{
		{Configuration: "ca.example.test\\Example-CA"},
	}
	definitionsA := testFIThreeTemplateDefinitions()
	definitionsB := testFIThreeTemplateDefinitions()
	definitionsB[2].OID = "1.2.3.999"

	planA, requiredA, err := buildCATemplatePublicationPlanFromCAs(
		"dc.example.test",
		cas,
		testFIThreeTemplateNames(),
		definitionsA,
	)
	if err != nil || !requiredA {
		t.Fatalf("plan A failed: required=%t err=%v", requiredA, err)
	}
	planB, requiredB, err := buildCATemplatePublicationPlanFromCAs(
		"dc.example.test",
		cas,
		testFIThreeTemplateNames(),
		definitionsB,
	)
	if err != nil || !requiredB {
		t.Fatalf("plan B failed: required=%t err=%v", requiredB, err)
	}
	if planA.DigestSHA256 == planB.DigestSHA256 {
		t.Fatal("digest must change when a template definition OID changes")
	}
}

func TestPromptCATemplatePublicationApprovalShowsExactExecutionAndValues(t *testing.T) {
	cas := []enterpriseCertificateAuthorityState{
		{
			Configuration: "ca.example.test\\Example-CA",
			Templates:     []string{"Administrator", "Computer"},
		},
	}
	plan, required, err := buildCATemplatePublicationPlanFromCAs(
		"dc.example.test",
		cas,
		testFIThreeTemplateNames(),
		testFIThreeTemplateDefinitions(),
	)
	if err != nil || !required {
		t.Fatalf("build plan failed: required=%t err=%v", required, err)
	}

	input := bytes.NewBufferString(
		"APPROVE-CA-TEMPLATES " + plan.DigestSHA256[:16] + "\n",
	)
	var output bytes.Buffer
	approval, err := PromptCATemplatePublicationApproval(
		input,
		&output,
		plan,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !approval.Given {
		t.Fatal("expected approval")
	}

	text := output.String()
	for _, requiredText := range []string{
		"CURRENT CA certificateTemplates VALUES:",
		"RESULTING CA certificateTemplates VALUES AFTER THIS CHANGE:",
		"EXACT PROCESS + ARGUMENTS FI WILL EXECUTE:",
		"argv[6]:    +FI-Batch-Signing,FI-Receiver-TLS,FI-Transport-Client",
		"POWERSHELL EQUIVALENT FOR OPERATOR REVIEW:",
		"FI-Receiver-TLS  OID=1.2.3.12",
		"FI-Transport-Client  OID=1.2.3.10",
	} {
		if !strings.Contains(text, requiredText) {
			t.Fatalf("approval output missing %q:\n%s", requiredText, text)
		}
	}
}

func TestBuildCATemplatePublicationPlanFromCAsAlreadyPublished(t *testing.T) {
	cas := []enterpriseCertificateAuthorityState{
		{
			Configuration: "ca.example.test\\Example-CA",
			Templates: append(
				[]string{"Administrator"},
				testFIThreeTemplateNames()...,
			),
		},
	}
	plan, required, err := buildCATemplatePublicationPlanFromCAs(
		"dc.example.test",
		cas,
		testFIThreeTemplateNames(),
		testFIThreeTemplateDefinitions(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if required {
		t.Fatal("publication should not be required")
	}
	if plan.CAConfiguration != "ca.example.test\\Example-CA" {
		t.Fatalf("unexpected CA selection: %q", plan.CAConfiguration)
	}
}

func TestBuildCATemplatePublicationPlanFromCAsRefusesAmbiguousCA(t *testing.T) {
	cas := []enterpriseCertificateAuthorityState{
		{Configuration: "ca1.example.test\\CA1"},
		{Configuration: "ca2.example.test\\CA2"},
	}
	_, _, err := buildCATemplatePublicationPlanFromCAs(
		"dc.example.test",
		cas,
		testFIThreeTemplateNames(),
		testFIThreeTemplateDefinitions(),
	)
	if err == nil {
		t.Fatal("expected ambiguous CA selection to fail")
	}
}
