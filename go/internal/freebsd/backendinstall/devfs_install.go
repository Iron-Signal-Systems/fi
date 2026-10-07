// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// -----------------------------------------------------------------------------
// Devfs contract
// -----------------------------------------------------------------------------

type devfsState string

const (
	devfsAbsent           devfsState = "ABSENT"
	devfsForeignCollision devfsState = "FOREIGN_COLLISION"
	devfsOwnedMatch       devfsState = "OWNED_MATCH"
	devfsUnknown          devfsState = "UNKNOWN"
)

var expectedDevfsRules = []string{
	"hide",
	"path null unhide",
	"path zero unhide",
	"path random unhide",
	"path urandom unhide",
}

// -----------------------------------------------------------------------------
// Public operations
// -----------------------------------------------------------------------------

func ApplyDevfs(config Config) error {
	probe := systemHostProbe{}

	if err := requireDevfsHost(
		config,
		probe,
	); err != nil {
		return err
	}

	ruleset, err := devfsRuleset(config)
	if err != nil {
		return err
	}

	state := classifyDevfsRuleset(
		probe,
		ruleset,
	)

	switch state {
	case devfsOwnedMatch:
		return nil

	case devfsAbsent:

	case devfsForeignCollision:
		return fmt.Errorf(
			"FOREIGN_COLLISION: FI production devfs ruleset %d collides with existing state",
			ruleset,
		)

	case devfsUnknown:
		return fmt.Errorf(
			"UNKNOWN: FI production devfs ruleset %d could not be classified safely",
			ruleset,
		)

	default:
		return fmt.Errorf(
			"invalid FI production devfs state: %s",
			state,
		)
	}

	state = classifyDevfsRuleset(
		probe,
		ruleset,
	)

	if state != devfsAbsent {
		return fmt.Errorf(
			"FI production devfs ruleset changed before creation: %d (%s)",
			ruleset,
			state,
		)
	}

	mutator := systemDevfsMutator{}

	if err := mutator.CreateRuleset(
		ruleset,
	); err != nil {
		return err
	}

	state = classifyDevfsRuleset(
		probe,
		ruleset,
	)

	if state != devfsOwnedMatch {
		return fmt.Errorf(
			"FI production devfs ruleset failed post-create verification: %d (%s)",
			ruleset,
			state,
		)
	}

	return nil
}

func VerifyDevfs(config Config) error {
	probe := systemHostProbe{}

	if err := requireDevfsHost(
		config,
		probe,
	); err != nil {
		return err
	}

	ruleset, err := devfsRuleset(config)
	if err != nil {
		return err
	}

	state := classifyDevfsRuleset(
		probe,
		ruleset,
	)

	if state != devfsOwnedMatch {
		return fmt.Errorf(
			"FI production devfs ruleset is not OWNED_MATCH: %d (%s)",
			ruleset,
			state,
		)
	}

	return nil
}

// -----------------------------------------------------------------------------
// Classification
// -----------------------------------------------------------------------------

func classifyDevfsRuleset(
	probe hostProbe,
	ruleset uint64,
) devfsState {
	output, err := probe.Run(
		"devfs",
		"rule",
		"showsets",
	)
	if err != nil {
		return devfsUnknown
	}

	present, err := devfsRulesetPresent(
		output,
		ruleset,
	)
	if err != nil {
		return devfsUnknown
	}

	if !present {
		return devfsAbsent
	}

	output, err = probe.Run(
		"devfs",
		"rule",
		"-s",
		strconv.FormatUint(
			ruleset,
			10,
		),
		"show",
	)
	if err != nil {
		return devfsUnknown
	}

	actual, err := normalizeDevfsRules(output)
	if err != nil {
		return devfsUnknown
	}

	if equalStringSlices(
		actual,
		expectedDevfsRules,
	) {
		return devfsOwnedMatch
	}

	return devfsForeignCollision
}

func devfsRulesetPresent(
	output string,
	ruleset uint64,
) (bool, error) {
	for _, field := range strings.Fields(output) {
		value, err := strconv.ParseUint(
			field,
			10,
			64,
		)
		if err != nil {
			return false, fmt.Errorf(
				"invalid devfs ruleset number in showsets output: %q",
				field,
			)
		}

		if value == ruleset {
			return true, nil
		}
	}

	return false, nil
}

func normalizeDevfsRules(
	output string,
) ([]string, error) {
	rules := make(
		[]string,
		0,
	)

	for _, line := range strings.Split(
		output,
		"\n",
	) {
		fields := strings.Fields(line)

		if len(fields) == 0 {
			continue
		}

		start := 0

		if _, err := strconv.ParseUint(
			fields[0],
			10,
			64,
		); err == nil {
			start = 1
		}

		if start >= len(fields) {
			return nil, fmt.Errorf(
				"devfs rule contains no action: %q",
				line,
			)
		}

		rules = append(
			rules,
			strings.Join(
				fields[start:],
				" ",
			),
		)
	}

	return rules, nil
}

func equalStringSlices(
	left []string,
	right []string,
) bool {
	if len(left) != len(right) {
		return false
	}

	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}

	return true
}

// -----------------------------------------------------------------------------
// Host prerequisites
// -----------------------------------------------------------------------------

func devfsRuleset(
	config Config,
) (uint64, error) {
	value, err := strconv.ParseUint(
		config.Value("FI_DEVFS_RULESET"),
		10,
		64,
	)
	if err != nil {
		return 0, fmt.Errorf(
			"invalid FI_DEVFS_RULESET: %w",
			err,
		)
	}

	if value < 100 {
		return 0, fmt.Errorf(
			"FI_DEVFS_RULESET must be 100 or greater",
		)
	}

	return value, nil
}

func requireDevfsHost(
	config Config,
	probe hostProbe,
) error {
	if probe.EUID() != 0 {
		return fmt.Errorf(
			"devfs operation must run as root on the intended FreeBSD host",
		)
	}

	kernel, err := probe.Run(
		"uname",
		"-s",
	)
	if err != nil {
		return fmt.Errorf(
			"inspect operating system before devfs operation: %w",
			err,
		)
	}

	if strings.TrimSpace(kernel) != "FreeBSD" {
		return fmt.Errorf(
			"devfs operation requires FreeBSD",
		)
	}

	hostname, err := probe.Run(
		"hostname",
	)
	if err != nil {
		return fmt.Errorf(
			"inspect hostname before devfs operation: %w",
			err,
		)
	}

	hostname = strings.TrimSpace(hostname)

	if hostname != config.Value("FI_HOSTNAME") {
		return fmt.Errorf(
			"deployment hostname mismatch: expected %s, observed %s",
			config.Value("FI_HOSTNAME"),
			hostname,
		)
	}

	return nil
}

// -----------------------------------------------------------------------------
// System mutation
// -----------------------------------------------------------------------------

type systemDevfsMutator struct {
	execute func(
		string,
		...string,
	) ([]byte, error)
}

func (mutator systemDevfsMutator) CreateRuleset(
	ruleset uint64,
) error {
	number := strconv.FormatUint(
		ruleset,
		10,
	)

	definitions := [][]string{
		{
			"rule", "-s", number,
			"add", "100", "hide",
		},
		{
			"rule", "-s", number,
			"add", "200", "path", "null", "unhide",
		},
		{
			"rule", "-s", number,
			"add", "300", "path", "zero", "unhide",
		},
		{
			"rule", "-s", number,
			"add", "400", "path", "random", "unhide",
		},
		{
			"rule", "-s", number,
			"add", "500", "path", "urandom", "unhide",
		},
	}

	for _, arguments := range definitions {
		if err := mutator.run(
			"/sbin/devfs",
			arguments...,
		); err != nil {
			return fmt.Errorf(
				"create FI devfs ruleset %d: %w",
				ruleset,
				err,
			)
		}
	}

	return nil
}

func (mutator systemDevfsMutator) run(
	executable string,
	args ...string,
) error {
	execute := mutator.execute

	if execute == nil {
		execute = func(
			path string,
			arguments ...string,
		) ([]byte, error) {
			return exec.Command(
				path,
				arguments...,
			).CombinedOutput()
		}
	}

	output, err := execute(
		executable,
		args...,
	)
	if err == nil {
		return nil
	}

	message := strings.TrimSpace(
		string(output),
	)

	if message == "" {
		return err
	}

	return fmt.Errorf(
		"%w: %s",
		err,
		message,
	)
}
