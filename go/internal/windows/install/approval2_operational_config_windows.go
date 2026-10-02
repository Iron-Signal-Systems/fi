// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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

func approval2OperationalConfigRequired(
	report Report,
	plan InstallPlan,
) bool {
	configPath := strings.TrimSpace(
		report.Config.Path,
	)
	expectedSource := approval2ExpectedSourceTarget(
		report,
	)

	for _, action := range plan.Actions {
		if action.Authority != "CONFIG" ||
			!planActionMutates(
				action.Action,
			) {
			continue
		}

		target := strings.TrimSpace(
			action.Target,
		)

		if configPath != "" &&
			strings.EqualFold(
				target,
				configPath,
			) {
			return true
		}

		if expectedSource != "" &&
			strings.EqualFold(
				target,
				expectedSource,
			) {
			return true
		}
	}

	return false
}

func approval2ExpectedSourceTarget(
	report Report,
) string {
	computer := strings.TrimSpace(
		report.Host.Computer,
	)
	domain := strings.TrimSpace(
		report.Host.DomainDNS,
	)

	if computer == "" ||
		domain == "" ||
		strings.EqualFold(
			computer,
			notKnown,
		) ||
		strings.EqualFold(
			domain,
			notKnown,
		) {
		return ""
	}

	return "source.id=" + strings.ToLower(
		computer+"."+domain,
	)
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

func joinApproval2RollbackFailure(
	base error,
	context string,
	rollback func() error,
) error {
	if base == nil {
		base = errors.New(
			"Approval 2 mutation failed",
		)
	}

	if rollback == nil {
		return base
	}

	rollbackErr := rollback()
	if rollbackErr == nil {
		return base
	}

	context = strings.TrimSpace(
		context,
	)
	if context == "" {
		context = "Approval 2 rollback"
	}

	return errors.Join(
		base,
		fmt.Errorf(
			"%s: %w",
			context,
			rollbackErr,
		),
	)
}
func createApproval2OperationalConfig(
	report Report,
	plan InstallPlan,
	inputs PlanInputs,
	handoff approval1PKIHandoff,
	transactionID string,
) (func() error, error) {
	if !validApproval2TransactionID(
		transactionID,
	) {
		return nil, fmt.Errorf(
			"invalid Approval 2 transaction ID %q",
			transactionID,
		)
	}

	proposal, err := approval2OperationalConfigProposal(
		report,
		plan,
		inputs,
	)
	if err != nil {
		return nil, err
	}

	expectedPath, err := config.DefaultPath()
	if err != nil {
		return nil, fmt.Errorf(
			"resolve fixed FI operational configuration path: %w",
			err,
		)
	}

	if !strings.EqualFold(
		filepath.Clean(
			strings.TrimSpace(
				proposal.Path,
			),
		),
		filepath.Clean(
			expectedPath,
		),
	) {
		return nil, fmt.Errorf(
			"operational configuration path=%q does not match fixed FI path=%q",
			proposal.Path,
			expectedPath,
		)
	}

	if report.Config.Presence != presenceAbsent {
		return nil, fmt.Errorf(
			"Approval 2 operational CONFIG CREATE requires presence=%s; observed=%s",
			presenceAbsent,
			report.Config.Presence,
		)
	}

	value, err := approval2OperationalConfigValue(
		proposal,
	)
	if err != nil {
		return nil, err
	}

	encoded, err := renderApproval2OperationalConfig(
		value,
	)
	if err != nil {
		return nil, err
	}

	directories := []string{
		filepath.Dir(
			proposal.Path,
		),
		proposal.SpoolDir,
		proposal.StageDir,
		proposal.StateDir,
	}

	if handoff.complete() {
		directories = append(
			directories,
			filepath.Dir(
				handoff.CRLDestinationPath,
			),
		)
	}

	createdDirectories, err := prepareApproval2OwnedDirectories(
		directories,
	)
	if err != nil {
		return nil, err
	}

	rollbackDirectories := func() error {
		return rollbackApproval2CreatedDirectories(
			createdDirectories,
		)
	}

	configPath := filepath.Clean(
		proposal.Path,
	)

	if _, err := os.Lstat(
		configPath,
	); err == nil {
		base := fmt.Errorf(
			"Approval 2 CREATE refuses existing operational configuration %s",
			configPath,
		)

		return nil, joinApproval2RollbackFailure(
			base,
			"rollback Approval 2 operational directories",
			rollbackDirectories,
		)
	} else if !errors.Is(
		err,
		os.ErrNotExist,
	) {
		base := fmt.Errorf(
			"inspect Approval 2 operational configuration destination %s: %w",
			configPath,
			err,
		)

		return nil, joinApproval2RollbackFailure(
			base,
			"rollback Approval 2 operational directories",
			rollbackDirectories,
		)
	}

	stage := configPath +
		".fi-new-" +
		transactionID

	removeStage := func() error {
		err := removeFileWithRetry(
			stage,
			5*time.Second,
		)
		if err == nil ||
			errors.Is(
				err,
				os.ErrNotExist,
			) {
			return nil
		}

		return fmt.Errorf(
			"remove staged FI operational configuration %s: %w",
			stage,
			err,
		)
	}

	rollbackStageAndDirectories := func() error {
		return errors.Join(
			removeStage(),
			rollbackDirectories(),
		)
	}

	if err := removeStage(); err != nil {
		return nil, joinApproval2RollbackFailure(
			err,
			"rollback Approval 2 operational directories",
			rollbackDirectories,
		)
	}

	if err := writeApproval2ExclusiveFile(
		stage,
		encoded,
	); err != nil {
		return nil, joinApproval2RollbackFailure(
			err,
			"rollback Approval 2 operational directories",
			rollbackDirectories,
		)
	}

	staged, err := config.Load(
		stage,
	)
	if err != nil {
		base := fmt.Errorf(
			"verify staged FI operational configuration: %w",
			err,
		)

		return nil, joinApproval2RollbackFailure(
			base,
			"rollback staged FI operational configuration",
			rollbackStageAndDirectories,
		)
	}

	if !sameApproval2OperationalConfig(
		staged,
		value,
	) {
		return nil, joinApproval2RollbackFailure(
			errors.New(
				"staged FI operational configuration does not match the approved typed contract",
			),
			"rollback staged FI operational configuration",
			rollbackStageAndDirectories,
		)
	}

	if err := os.Rename(
		stage,
		configPath,
	); err != nil {
		base := fmt.Errorf(
			"activate FI operational configuration %s: %w",
			configPath,
			err,
		)

		return nil, joinApproval2RollbackFailure(
			base,
			"rollback staged FI operational configuration",
			rollbackStageAndDirectories,
		)
	}

	rollback := func() error {
		var found []error

		if err := removeFileWithRetry(
			configPath,
			5*time.Second,
		); err != nil &&
			!errors.Is(
				err,
				os.ErrNotExist,
			) {
			found = append(
				found,
				err,
			)
		}

		if err := rollbackDirectories(); err != nil {
			found = append(
				found,
				err,
			)
		}

		return errors.Join(
			found...,
		)
	}

	activated, err := config.Load(
		configPath,
	)
	if err != nil {
		base := fmt.Errorf(
			"verify activated FI operational configuration: %w",
			err,
		)

		return nil, joinApproval2RollbackFailure(
			base,
			"rollback activated FI operational configuration",
			rollback,
		)
	}

	if !sameApproval2OperationalConfig(
		activated,
		value,
	) {
		return nil, joinApproval2RollbackFailure(
			errors.New(
				"activated FI operational configuration does not match the approved typed contract",
			),
			"rollback activated FI operational configuration",
			rollback,
		)
	}

	return rollback, nil
}
func prepareApproval2OwnedDirectories(
	paths []string,
) ([]string, error) {
	created := make(
		[]string,
		0,
	)
	seen := make(
		map[string]struct{},
	)

	rollback := func() error {
		return rollbackApproval2CreatedDirectories(
			created,
		)
	}

	for _, raw := range paths {
		path := filepath.Clean(
			strings.TrimSpace(
				raw,
			),
		)

		if path == "" ||
			path == "." {
			return nil, joinApproval2RollbackFailure(
				errors.New(
					"Approval 2 FI-owned directory path is empty",
				),
				"rollback previously created Approval 2 directories",
				rollback,
			)
		}

		key := strings.ToLower(
			path,
		)
		if _, found := seen[key]; found {
			continue
		}
		seen[key] = struct{}{}

		added, err := prepareApproval2OwnedDirectory(
			path,
		)
		if err != nil {
			return nil, joinApproval2RollbackFailure(
				err,
				"rollback previously created Approval 2 directories",
				rollback,
			)
		}

		for _, directory := range added {
			createdKey := strings.ToLower(
				directory,
			)
			if _, found := seen[createdKey]; !found {
				seen[createdKey] = struct{}{}
			}
			created = append(
				created,
				directory,
			)
		}
	}

	return created, nil
}
func prepareApproval2OwnedDirectory(
	path string,
) ([]string, error) {
	path = filepath.Clean(
		path,
	)

	missing := make(
		[]string,
		0,
	)
	cursor := path

	for {
		_, err := os.Lstat(
			cursor,
		)
		if err == nil {
			if err := requireApproval2PlainDirectory(
				cursor,
			); err != nil {
				return nil, err
			}
			break
		}

		if !errors.Is(
			err,
			os.ErrNotExist,
		) {
			return nil, fmt.Errorf(
				"inspect Approval 2 FI-owned directory %s: %w",
				cursor,
				err,
			)
		}

		missing = append(
			missing,
			cursor,
		)

		parent := filepath.Dir(
			cursor,
		)
		if parent == cursor ||
			parent == "." ||
			parent == "" {
			return nil, fmt.Errorf(
				"cannot establish existing parent for Approval 2 directory %s",
				path,
			)
		}
		cursor = parent
	}

	created := make(
		[]string,
		0,
		len(missing),
	)

	rollback := func() error {
		return rollbackApproval2CreatedDirectories(
			created,
		)
	}

	for index := len(missing) - 1; index >= 0; index-- {
		directory := missing[index]

		if err := os.Mkdir(
			directory,
			0o700,
		); err != nil {
			base := fmt.Errorf(
				"create Approval 2 FI-owned directory %s: %w",
				directory,
				err,
			)

			return nil, joinApproval2RollbackFailure(
				base,
				"rollback Approval 2 directory preparation",
				rollback,
			)
		}

		created = append(
			created,
			directory,
		)

		if err := withEnabledProcessPrivilege(
			"SeRestorePrivilege",
			func() error {
				return setNamedSecurityDescriptorFromSDDL(
					directory,
					desiredProtectedDirectorySDDL(
						nil,
					),
				)
			},
		); err != nil {
			base := fmt.Errorf(
				"protect Approval 2 FI-owned directory %s: %w",
				directory,
				err,
			)

			return nil, joinApproval2RollbackFailure(
				base,
				"rollback Approval 2 directory preparation",
				rollback,
			)
		}
	}

	return created, nil
}
func rollbackApproval2CreatedDirectories(
	created []string,
) error {
	var found []error

	for index := len(created) - 1; index >= 0; index-- {
		directory := created[index]

		err := os.RemoveAll(
			directory,
		)
		if err == nil ||
			errors.Is(
				err,
				os.ErrNotExist,
			) {
			continue
		}

		found = append(
			found,
			fmt.Errorf(
				"remove transaction-created FI directory %s: %w",
				directory,
				err,
			),
		)
	}

	return errors.Join(
		found...,
	)
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
