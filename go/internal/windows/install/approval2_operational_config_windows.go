// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/config"
)

func approval2OperationalConfigProposal(
	report Report,
	plan InstallPlan,
	inputs PlanInputs,
) (ConfigState, error) {
	working := report
	var proposalPlan InstallPlan

	planConfiguration(
		&proposalPlan,
		&working,
		inputs,
	)

	if proposalPlan.HasBlockers() {
		return ConfigState{}, errors.New(
			"Approval 2 operational configuration proposal contains blockers",
		)
	}

	if proposalPlan.HasQuestions() {
		return ConfigState{}, errors.New(
			"Approval 2 operational configuration proposal still contains unanswered questions",
		)
	}

	proposal := working.Config

	if proposal.Presence != presenceAbsent {
		return ConfigState{}, fmt.Errorf(
			"Approval 2 operational configuration proposal requires presence=%s; observed=%s",
			presenceAbsent,
			proposal.Presence,
		)
	}

	if err := validateProposedConfigPaths(
		proposal,
	); err != nil {
		return ConfigState{}, fmt.Errorf(
			"validate Approval 2 operational configuration proposal: %w",
			err,
		)
	}

	if err := validateApproval2OperationalConfigPlan(
		plan,
		proposal,
	); err != nil {
		return ConfigState{}, err
	}

	return proposal, nil
}

func approval2OperationalConfigValue(
	proposal ConfigState,
) (config.Config, error) {
	for name, value := range map[string]string{
		"configuration path": proposal.Path,
		"receiver address":   proposal.ReceiverAddress,
		"receiver name":      proposal.ReceiverName,
		"source id":          proposal.SourceID,
		"spool directory":    proposal.SpoolDir,
		"stage directory":    proposal.StageDir,
		"state directory":    proposal.StateDir,
	} {
		if strings.TrimSpace(value) == "" {
			return config.Config{}, fmt.Errorf(
				"Approval 2 operational configuration %s is empty",
				name,
			)
		}
		if strings.ContainsAny(value, "\r\n") {
			return config.Config{}, fmt.Errorf(
				"Approval 2 operational configuration %s contains a line break",
				name,
			)
		}
	}

	if len(proposal.GovernedRoots) == 0 {
		return config.Config{}, errors.New(
			"Approval 2 operational configuration requires at least one governed root",
		)
	}

	for _, root := range proposal.GovernedRoots {
		if strings.ContainsAny(root, "\r\n") {
			return config.Config{}, fmt.Errorf(
				"Approval 2 governed root %q contains a line break",
				root,
			)
		}
	}

	value := config.Config{
		VersionID: config.Version11,
		GovernedRoots: append(
			[]string(nil),
			proposal.GovernedRoots...,
		),
		Collector: config.CollectorSettings{
			CollectionEvery:        time.Minute,
			SupportingRefreshEvery: 30 * time.Minute,
			USNEvery:               10 * time.Minute,
			WindowsSecurityEvery:   time.Minute,
		},
		Receiver: config.ReceiverSettings{
			Address: proposal.ReceiverAddress,
			Name:    proposal.ReceiverName,
			Timeout: 30 * time.Second,
		},
		Sender: config.SenderSettings{
			GenerationInterval:        10 * time.Minute,
			GenerationMaxEncodedBytes: 68719476736,
			GenerationTransferTimeout: 2 * time.Hour,
			PollInterval:              5 * time.Second,
			RecoveryThresholdBytes:    0,
			RecoveryTimeout:           2 * time.Hour,
			RetryBackoff:              5 * time.Second,
		},
		Source: config.SourceSettings{
			ID: proposal.SourceID,
		},
		Spool: config.SpoolSettings{
			MaxBatchRecords:  262144,
			MaxRecordBytes:   67108864,
			TargetBatchBytes: 33554432,
		},
		Storage: config.StorageSettings{
			SpoolDir: proposal.SpoolDir,
			StageDir: proposal.StageDir,
			StateDir: proposal.StateDir,
		},
		Troubleshoot: config.TroubleshootSettings{},
	}

	if _, err := renderApproval2OperationalConfig(value); err != nil {
		return config.Config{}, err
	}

	return value, nil
}

func renderApproval2OperationalConfig(
	value config.Config,
) ([]byte, error) {
	var builder strings.Builder

	fmt.Fprintf(&builder, "version_id: %s\n\n", value.VersionID)
	for _, root := range value.GovernedRoots {
		fmt.Fprintf(&builder, "governed_root: %s\n", root)
	}

	fmt.Fprintf(
		&builder,
		"\ncollector.collection_every = %s\ncollector.supporting_refresh_every = %s\ncollector.usn_every = %s\ncollector.windows_security_every = %s\n",
		value.Collector.CollectionEvery,
		value.Collector.SupportingRefreshEvery,
		value.Collector.USNEvery,
		value.Collector.WindowsSecurityEvery,
	)
	fmt.Fprintf(
		&builder,
		"\nspool.target_batch_bytes = %d\nspool.max_record_bytes = %d\nspool.max_batch_records = %d\n",
		value.Spool.TargetBatchBytes,
		value.Spool.MaxRecordBytes,
		value.Spool.MaxBatchRecords,
	)
	fmt.Fprintf(
		&builder,
		"\nstorage.spool_dir = %s\nstorage.stage_dir = %s\nstorage.state_dir = %s\n",
		value.Storage.SpoolDir,
		value.Storage.StageDir,
		value.Storage.StateDir,
	)
	fmt.Fprintf(&builder, "\nsource.id = %s\n", value.Source.ID)
	fmt.Fprintf(
		&builder,
		"\nsender.poll_interval = %s\nsender.retry_backoff = %s\nsender.generation_interval = %s\nsender.generation_max_encoded_bytes = %d\nsender.generation_transfer_timeout = %s\nsender.recovery_threshold_bytes = %d\nsender.recovery_timeout = %s\n",
		value.Sender.PollInterval,
		value.Sender.RetryBackoff,
		value.Sender.GenerationInterval,
		value.Sender.GenerationMaxEncodedBytes,
		value.Sender.GenerationTransferTimeout,
		value.Sender.RecoveryThresholdBytes,
		value.Sender.RecoveryTimeout,
	)
	fmt.Fprintf(
		&builder,
		"\nreceiver.address = %s\nreceiver.name = %s\nreceiver.timeout = %s\n",
		value.Receiver.Address,
		value.Receiver.Name,
		value.Receiver.Timeout,
	)
	fmt.Fprintf(
		&builder,
		"\ntroubleshoot.enabled = %t\ntroubleshoot.allow_collector_cli_override = %t\ntroubleshoot.allow_sender_cli_override = %t\ntroubleshoot.allow_storage_cli_override = %t\ntroubleshoot.allow_trust_cli_override = %t\n",
		value.Troubleshoot.Enabled,
		value.Troubleshoot.AllowCollectorCLIOverride,
		value.Troubleshoot.AllowSenderCLIOverride,
		value.Troubleshoot.AllowStorageCLIOverride,
		value.Troubleshoot.AllowTrustCLIOverride,
	)

	encoded := []byte(builder.String())
	parsed, err := config.Parse(bytes.NewReader(encoded))
	if err != nil {
		return nil, fmt.Errorf(
			"self-validate generated FI operational configuration: %w",
			err,
		)
	}

	if !sameApproval2OperationalConfig(parsed, value) {
		return nil, errors.New(
			"generated FI operational configuration did not round-trip exactly",
		)
	}

	return encoded, nil
}

func sameApproval2OperationalConfig(
	left config.Config,
	right config.Config,
) bool {
	if left.VersionID != right.VersionID ||
		len(left.GovernedRoots) != len(right.GovernedRoots) {
		return false
	}

	for index := range left.GovernedRoots {
		if left.GovernedRoots[index] != right.GovernedRoots[index] {
			return false
		}
	}

	return left.Collector == right.Collector &&
		left.Receiver == right.Receiver &&
		left.Sender == right.Sender &&
		left.Source == right.Source &&
		left.Spool == right.Spool &&
		left.Storage == right.Storage &&
		left.Troubleshoot == right.Troubleshoot
}

func validateApproval2OperationalConfigPlan(
	plan InstallPlan,
	proposal ConfigState,
) error {
	configCreates := 0
	sourceCreates := 0
	expectedSourceTarget := "source.id=" + strings.TrimSpace(proposal.SourceID)

	for _, action := range plan.Actions {
		if action.Authority != "CONFIG" || !planActionMutates(action.Action) {
			continue
		}

		target := strings.TrimSpace(action.Target)
		switch {
		case strings.EqualFold(target, strings.TrimSpace(proposal.Path)):
			if action.Action != planActionCreate {
				return fmt.Errorf(
					"Approval 2 operational configuration action=%s target=%s; expected CREATE",
					action.Action,
					action.Target,
				)
			}
			configCreates++
		case strings.EqualFold(target, expectedSourceTarget):
			if action.Action != planActionCreate {
				return fmt.Errorf(
					"Approval 2 source identity action=%s target=%s; expected CREATE",
					action.Action,
					action.Target,
				)
			}
			sourceCreates++
		}
	}

	if configCreates != 1 || sourceCreates != 1 {
		return fmt.Errorf(
			"Approval 2 operational configuration requires exactly one config CREATE and one source.id CREATE; config=%d source=%d",
			configCreates,
			sourceCreates,
		)
	}

	return nil
}
