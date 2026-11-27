// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"testing"
)

func TestDevfsRulesetPresent(t *testing.T) {
	present, err := devfsRulesetPresent(
		"1 2 3 100 200\n",
		100,
	)
	if err != nil {
		t.Fatalf(
			"devfsRulesetPresent() error = %v",
			err,
		)
	}

	if !present {
		t.Fatal(
			"ruleset 100 not found",
		)
	}

	present, err = devfsRulesetPresent(
		"1 2 3 100 200\n",
		101,
	)
	if err != nil {
		t.Fatalf(
			"devfsRulesetPresent() error = %v",
			err,
		)
	}

	if present {
		t.Fatal(
			"unexpected ruleset 101 found",
		)
	}
}

func TestNormalizeDevfsRules(t *testing.T) {
	output := "" +
		"100 hide\n" +
		"200 path null unhide\n" +
		"300 path zero unhide\n" +
		"400 path random unhide\n" +
		"500 path urandom unhide\n"

	rules, err := normalizeDevfsRules(output)
	if err != nil {
		t.Fatalf(
			"normalizeDevfsRules() error = %v",
			err,
		)
	}

	if !equalStringSlices(
		rules,
		expectedDevfsRules,
	) {
		t.Fatalf(
			"rules = %#v",
			rules,
		)
	}
}

func TestNormalizeDevfsRulesRejectsNumberOnly(t *testing.T) {
	if _, err := normalizeDevfsRules(
		"100\n",
	); err == nil {
		t.Fatal(
			"normalizeDevfsRules accepted rule number without action",
		)
	}
}

func TestDevfsRulesetRejectsBelow100(t *testing.T) {
	config := loadTestConfig(t)

	config.values["FI_DEVFS_RULESET"] = "99"

	if _, err := devfsRuleset(config); err == nil {
		t.Fatal(
			"devfsRuleset accepted ruleset below 100",
		)
	}
}

func TestSystemDevfsMutatorCreatesExactRules(t *testing.T) {
	commands := make(
		[][]string,
		0,
	)

	mutator := systemDevfsMutator{
		execute: func(
			executable string,
			args ...string,
		) ([]byte, error) {
			command := append(
				[]string{
					executable,
				},
				args...,
			)

			commands = append(
				commands,
				command,
			)

			return nil, nil
		},
	}

	if err := mutator.CreateRuleset(
		100,
	); err != nil {
		t.Fatalf(
			"CreateRuleset() error = %v",
			err,
		)
	}

	expected := [][]string{
		{
			"/sbin/devfs",
			"rule", "-s", "100",
			"add", "100", "hide",
		},
		{
			"/sbin/devfs",
			"rule", "-s", "100",
			"add", "200", "path", "null", "unhide",
		},
		{
			"/sbin/devfs",
			"rule", "-s", "100",
			"add", "300", "path", "zero", "unhide",
		},
		{
			"/sbin/devfs",
			"rule", "-s", "100",
			"add", "400", "path", "random", "unhide",
		},
		{
			"/sbin/devfs",
			"rule", "-s", "100",
			"add", "500", "path", "urandom", "unhide",
		},
	}

	if len(commands) != len(expected) {
		t.Fatalf(
			"command count = %d, want %d",
			len(commands),
			len(expected),
		)
	}

	for index := range expected {
		if !equalStringSlices(
			commands[index],
			expected[index],
		) {
			t.Fatalf(
				"command %d = %#v, want %#v",
				index,
				commands[index],
				expected[index],
			)
		}
	}
}
