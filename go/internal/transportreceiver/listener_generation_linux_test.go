// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package transportreceiver

import (
	"bufio"
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/generationrecorder"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportack"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportgeneration"
)

func TestReceiveAuthenticatedApplicationDispatchesGeneration(
	t *testing.T,
) {
	fixture := newGenerationTransactionFixture(t, false)
	config := listenerGenerationConfigFromFixture(t, fixture)

	var output bytes.Buffer
	result, err := receiveAuthenticatedApplication(
		bufio.NewReader(
			bytes.NewReader(
				fixture.transactionBytes,
			),
		),
		&output,
		config,
		fixture.config.Custody.Receive.CurrentTime,
	)
	if err != nil {
		t.Fatal(err)
	}

	if !result.Generation {
		t.Fatal("generation transaction was not identified as generation")
	}

	if result.Recovery {
		t.Fatal("generation transaction was incorrectly identified as recovery")
	}

	if result.BatchID != "" {
		t.Fatalf(
			"generation transaction batch ID = %q, want empty",
			result.BatchID,
		)
	}

	if result.GenerationID != fixture.offer.Descriptor.GenerationID {
		t.Fatalf(
			"generation ID = %q, want %q",
			result.GenerationID,
			fixture.offer.Descriptor.GenerationID,
		)
	}

	if result.SourceID != fixture.offer.Descriptor.SourceID {
		t.Fatalf(
			"source ID = %q, want %q",
			result.SourceID,
			fixture.offer.Descriptor.SourceID,
		)
	}

	if result.CustodyDisposition != CustodyDispositionNew {
		t.Fatalf(
			"custody disposition = %q, want NEW",
			result.CustodyDisposition,
		)
	}

	if result.GenerationRecordedState !=
		string(generationrecorder.RecordedDispositionNew) {
		t.Fatalf(
			"recorded state = %q, want NEW",
			result.GenerationRecordedState,
		)
	}

	if result.GenerationAcknowledgement !=
		transportgeneration.AcknowledgementOutcomeRecorded {
		t.Fatalf(
			"generation acknowledgement = %q, want recorded",
			result.GenerationAcknowledgement,
		)
	}

	if result.GenerationArtifactCount !=
		fixture.offer.Descriptor.ArtifactCount {
		t.Fatalf(
			"artifact count = %d, want %d",
			result.GenerationArtifactCount,
			fixture.offer.Descriptor.ArtifactCount,
		)
	}

	if result.GenerationCanonicalBytes !=
		fixture.offer.Descriptor.CanonicalBytes {
		t.Fatalf(
			"canonical bytes = %d, want %d",
			result.GenerationCanonicalBytes,
			fixture.offer.Descriptor.CanonicalBytes,
		)
	}

	if result.GenerationEncodedBytes !=
		fixture.offer.Descriptor.EncodedDataBytes {
		t.Fatalf(
			"encoded bytes = %d, want %d",
			result.GenerationEncodedBytes,
			fixture.offer.Descriptor.EncodedDataBytes,
		)
	}

	if result.GenerationTransferSHA256 != fixture.transfer.TransferSHA256 {
		t.Fatal(
			"listener generation transfer SHA-256 does not match exact FIGT transfer",
		)
	}

	if result.FrameSHA256 != "" {
		t.Fatalf(
			"generation legacy frame SHA-256 = %q, want empty",
			result.FrameSHA256,
		)
	}

	if result.DataBytes != 0 {
		t.Fatalf(
			"generation legacy data bytes = %d, want zero",
			result.DataBytes,
		)
	}

	if result.GenerationDataBytes == 0 {
		t.Fatal("generation semantic data byte count was not reported")
	}

	decision, acknowledgement :=
		readGenerationTransactionOutput(
			t,
			output.Bytes(),
		)

	if !decision.Accepted {
		t.Fatalf("generation decision = %#v, want accepted", decision)
	}

	if acknowledgement.Outcome !=
		transportgeneration.AcknowledgementOutcomeRecorded {
		t.Fatalf(
			"generation acknowledgement outcome = %q, want recorded",
			acknowledgement.Outcome,
		)
	}

	if err :=
		transportgeneration.AcknowledgementMatches(
			acknowledgement,
			fixture.transfer,
		); err != nil {
		t.Fatal(err)
	}
}

func TestReceiveAuthenticatedApplicationRejectsGenerationWhenDisabled(
	t *testing.T,
) {
	fixture := newGenerationTransactionFixture(t, false)

	var input bytes.Buffer
	if err :=
		transportgeneration.WriteOffer(
			&input,
			fixture.offer,
		); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	_, err := receiveAuthenticatedApplication(
		bufio.NewReader(
			bytes.NewReader(
				input.Bytes(),
			),
		),
		&output,
		validTestConfig(t),
		fixture.config.Custody.Receive.CurrentTime,
	)
	if err == nil ||
		!errors.Is(
			err,
			ErrGenerationNotEnabled,
		) {
		t.Fatalf(
			"disabled generation error = %v, want ErrGenerationNotEnabled",
			err,
		)
	}

	reader :=
		bytes.NewReader(
			output.Bytes(),
		)

	decision, readErr :=
		transportgeneration.ReadDecision(
			reader,
		)
	if readErr != nil {
		t.Fatal(readErr)
	}

	if decision.Accepted ||
		decision.Reason !=
			"GENERATION_DISABLED" {
		t.Fatalf(
			"disabled generation decision = %#v",
			decision,
		)
	}

	if reader.Len() != 0 {
		t.Fatalf(
			"disabled generation response has %d trailing bytes",
			reader.Len(),
		)
	}
}

func TestReceiveAuthenticatedApplicationStillDispatchesBatch(
	t *testing.T,
) {
	fixture := newIntakeTestFixture(t)
	frame := encodeIntakeTestFrame(
		t,
		fixture.signedBatch,
		fixture.manifest,
		fixture.data,
	)

	config := validTestConfig(t)
	config.BatchCRL = fixture.config.BatchCRL
	config.BatchIssuer = fixture.config.BatchIssuer
	config.MaxDataBytes = fixture.config.MaxDataBytes
	config.Root = fixture.config.Root
	config.Source = fixture.config.Source

	var acknowledgement bytes.Buffer
	result, err := receiveAuthenticatedApplication(
		bufio.NewReader(
			bytes.NewReader(
				frame,
			),
		),
		&acknowledgement,
		config,
		fixture.config.CurrentTime,
	)
	if err != nil {
		t.Fatal(err)
	}

	if result.Generation ||
		result.Recovery {
		t.Fatal("batch transaction was dispatched to non-batch path")
	}

	if result.BatchID !=
		fixture.signedBatch.Descriptor.BatchID {
		t.Fatalf(
			"batch ID = %q, want %q",
			result.BatchID,
			fixture.signedBatch.Descriptor.BatchID,
		)
	}

	decoded, err :=
		transportack.ReadAcknowledgement(
			bytes.NewReader(
				acknowledgement.Bytes(),
			),
		)
	if err != nil {
		t.Fatal(err)
	}

	if decoded.Outcome !=
		transportack.OutcomeDurableNew {
		t.Fatalf(
			"batch acknowledgement outcome = %q, want %q",
			decoded.Outcome,
			transportack.OutcomeDurableNew,
		)
	}
}

func TestValidateGenerationListenerConfig(
	t *testing.T,
) {
	valid :=
		validTestConfig(t)

	if err :=
		validateGenerationListenerConfig(
			valid,
		); err != nil {
		t.Fatalf(
			"disabled generation listener rejected: %v",
			err,
		)
	}

	configuredWithoutEnable :=
		valid
	configuredWithoutEnable.GenerationCustodyRoot =
		t.TempDir()
	configuredWithoutEnable.GenerationRecordedRoot =
		t.TempDir()
	configuredWithoutEnable.GenerationMaxCanonicalBytes =
		64 << 20
	configuredWithoutEnable.GenerationMaxEncodedBytes =
		64 << 20
	configuredWithoutEnable.GenerationMaxManifestBytes =
		1 << 20

	if err :=
		validateGenerationListenerConfig(
			configuredWithoutEnable,
		); err == nil ||
		!strings.Contains(
			err.Error(),
			"require explicit enablement",
		) {
		t.Fatalf(
			"configured-but-disabled generation listener error = %v, want explicit enablement rejection",
			err,
		)
	}

	valid.GenerationEnabled =
		true
	valid.GenerationCustodyRoot =
		t.TempDir()
	valid.GenerationRecordedRoot =
		t.TempDir()
	valid.GenerationMaxCanonicalBytes =
		64 << 20
	valid.GenerationMaxEncodedBytes =
		64 << 20
	valid.GenerationMaxManifestBytes =
		1 << 20

	if err :=
		validateGenerationListenerConfig(
			valid,
		); err != nil {
		t.Fatalf(
			"enabled generation listener rejected: %v",
			err,
		)
	}

	tests :=
		[]struct {
			name   string
			mutate func(*Config)
			want   string
		}{
			{
				name: "partial",
				mutate: func(value *Config) {
					value.GenerationMaxManifestBytes = 0
				},
				want: "must all be configured when enabled",
			},
			{
				name: "same generation roots",
				mutate: func(value *Config) {
					value.GenerationRecordedRoot =
						value.GenerationCustodyRoot
				},
				want: "custody and recorder roots must be distinct",
			},
			{
				name: "shares batch custody root",
				mutate: func(value *Config) {
					value.GenerationCustodyRoot =
						value.CustodyRoot
				},
				want: "distinct from batch/recovery custody root",
			},
			{
				name: "manifest limit too large",
				mutate: func(value *Config) {
					value.GenerationMaxManifestBytes =
						(64 << 20) + 1
				},
				want: "manifest limit exceeds semantic safety bound",
			},
		}

	for _, test := range tests {
		t.Run(
			test.name,
			func(t *testing.T) {
				value := valid
				test.mutate(&value)

				err :=
					validateGenerationListenerConfig(
						value,
					)
				if err == nil {
					t.Fatalf(
						"validation error = nil, want containing %q",
						test.want,
					)
				}

				if !strings.Contains(
					err.Error(),
					test.want,
				) {
					t.Fatalf(
						"validation error = %q, want containing %q",
						err,
						test.want,
					)
				}
			},
		)
	}
}

func listenerGenerationConfigFromFixture(
	t *testing.T,
	fixture generationTransactionFixture,
) Config {
	t.Helper()

	config :=
		validTestConfig(
			t,
		)

	config.BatchCRL =
		fixture.config.Custody.Receive.BatchCRL
	config.BatchIssuer =
		fixture.config.Custody.Receive.BatchIssuer
	config.Root =
		fixture.config.Custody.Receive.Root
	config.Source =
		fixture.config.Custody.Receive.Source

	config.GenerationEnabled =
		true
	config.GenerationCustodyRoot =
		fixture.config.Custody.RootDir
	config.GenerationRecordedRoot =
		fixture.config.Recorder.RootDir
	config.GenerationMaxCanonicalBytes =
		fixture.config.Custody.Receive.MaxCanonicalBytes
	config.GenerationMaxEncodedBytes =
		fixture.config.Custody.Receive.MaxEncodedBytes
	config.GenerationMaxManifestBytes =
		fixture.config.Recorder.Semantic.MaxManifestBytes

	return config
}
