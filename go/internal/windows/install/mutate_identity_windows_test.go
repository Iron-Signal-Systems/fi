// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"errors"
	"strings"
	"testing"
)

func TestServer2016RightsFailureRollsBackFailingAndEarlierAccounts(
	t *testing.T,
) {
	t.Parallel()

	identities := approval2LocalIdentityTestIdentities()

	original := map[string][]string{
		identities.CollectorSender.Account: {
			"SeDebugPrivilege",
			"SeServiceLogonRight",
		},
		identities.USNReader.Account: {
			"SeBackupPrivilege",
			"SeServiceLogonRight",
		},
		identities.ObjReader.Account: {
			"SeServiceLogonRight",
		},
	}

	state := make(
		map[string][]string,
		len(original),
	)
	for account, rights := range original {
		state[account] = append(
			[]string(nil),
			rights...,
		)
	}

	failed := false

	backend := server2016RightsBackend{
		enumerate: func(
			account string,
		) ([]string, error) {
			return append(
				[]string(nil),
				state[account]...,
			), nil
		},

		setExact: func(
			account string,
			rights []string,
		) error {
			state[account] = append(
				[]string(nil),
				rights...,
			)

			if account ==
				identities.ObjReader.Account &&
				!failed {
				failed = true
				return errors.New(
					"synthetic rights mutation failure after state change",
				)
			}

			return nil
		},
	}

	_, err := reconcileServer2016RightsWithBackend(
		identities,
		backend,
	)
	if err == nil {
		t.Fatal(
			"synthetic rights failure unexpectedly succeeded",
		)
	}

	if !strings.Contains(
		err.Error(),
		"synthetic rights mutation failure",
	) {
		t.Fatalf(
			"unexpected error: %v",
			err,
		)
	}

	for account, want := range original {
		if !exactRights(
			state[account],
			want,
		) {
			t.Fatalf(
				"rights for %s=%v want restored=%v",
				account,
				state[account],
				want,
			)
		}
	}
}

func TestServer2016RightsFailureReportsRollbackFailure(
	t *testing.T,
) {
	t.Parallel()

	identities := approval2LocalIdentityTestIdentities()

	original := map[string][]string{
		identities.CollectorSender.Account: {
			"SeServiceLogonRight",
		},
		identities.USNReader.Account: {
			"SeServiceLogonRight",
		},
		identities.ObjReader.Account: {
			"SeServiceLogonRight",
		},
	}

	state := make(
		map[string][]string,
		len(original),
	)
	for account, rights := range original {
		state[account] = append(
			[]string(nil),
			rights...,
		)
	}

	objCalls := 0

	backend := server2016RightsBackend{
		enumerate: func(
			account string,
		) ([]string, error) {
			return append(
				[]string(nil),
				state[account]...,
			), nil
		},

		setExact: func(
			account string,
			rights []string,
		) error {
			if account ==
				identities.ObjReader.Account {
				objCalls++

				if objCalls == 1 {
					state[account] = append(
						[]string(nil),
						rights...,
					)

					return errors.New(
						"synthetic rights mutation failure",
					)
				}

				return errors.New(
					"synthetic rights rollback failure",
				)
			}

			state[account] = append(
				[]string(nil),
				rights...,
			)

			return nil
		},
	}

	_, err := reconcileServer2016RightsWithBackend(
		identities,
		backend,
	)
	if err == nil {
		t.Fatal(
			"synthetic rollback failure unexpectedly succeeded",
		)
	}

	for _, expected := range []string{
		"synthetic rights mutation failure",
		"synthetic rights rollback failure",
	} {
		if !strings.Contains(
			err.Error(),
			expected,
		) {
			t.Fatalf(
				"combined error does not contain %q: %v",
				expected,
				err,
			)
		}
	}
}

func TestServer2016GroupFailureRollsBackFailingAndEarlierMemberships(
	t *testing.T,
) {
	t.Parallel()

	identities := approval2LocalIdentityTestIdentities()

	type membershipKey struct {
		account string
		group   string
	}

	state := map[membershipKey]bool{
		{
			account: identities.CollectorSender.Account,
			group:   "Administrators",
		}: true,

		{
			account: identities.CollectorSender.Account,
			group:   "Event Log Readers",
		}: false,

		{
			account: identities.USNReader.Account,
			group:   "Administrators",
		}: true,

		{
			account: identities.ObjReader.Account,
			group:   "Administrators",
		}: false,

		{
			account: identities.ObjReader.Account,
			group:   "Backup Operators",
		}: false,
	}

	original := make(
		map[membershipKey]bool,
		len(state),
	)
	for key, value := range state {
		original[key] = value
	}

	failed := false

	backend := server2016GroupsBackend{
		member: func(
			group string,
			account string,
		) (bool, error) {
			return state[membershipKey{
				account: account,
				group:   group,
			}], nil
		},

		setMembership: func(
			group string,
			account string,
			want bool,
		) error {
			key := membershipKey{
				account: account,
				group:   group,
			}

			state[key] = want

			if group == "Event Log Readers" &&
				account ==
					identities.CollectorSender.Account &&
				want &&
				!failed {
				failed = true

				return errors.New(
					"synthetic group mutation failure after state change",
				)
			}

			return nil
		},
	}

	_, err := reconcileServer2016GroupsWithBackend(
		identities,
		backend,
	)
	if err == nil {
		t.Fatal(
			"synthetic local-group failure unexpectedly succeeded",
		)
	}

	if !strings.Contains(
		err.Error(),
		"synthetic group mutation failure",
	) {
		t.Fatalf(
			"unexpected error: %v",
			err,
		)
	}

	for key, want := range original {
		if state[key] != want {
			t.Fatalf(
				"membership account=%s group=%s observed=%t want restored=%t",
				key.account,
				key.group,
				state[key],
				want,
			)
		}
	}
}

func TestServer2016GroupFailureReportsRollbackFailure(
	t *testing.T,
) {
	t.Parallel()

	identities := approval2LocalIdentityTestIdentities()

	type membershipKey struct {
		account string
		group   string
	}

	state := map[membershipKey]bool{
		{
			account: identities.CollectorSender.Account,
			group:   "Administrators",
		}: false,

		{
			account: identities.CollectorSender.Account,
			group:   "Event Log Readers",
		}: false,

		{
			account: identities.USNReader.Account,
			group:   "Administrators",
		}: true,

		{
			account: identities.ObjReader.Account,
			group:   "Administrators",
		}: false,

		{
			account: identities.ObjReader.Account,
			group:   "Backup Operators",
		}: false,
	}

	eventCalls := 0

	backend := server2016GroupsBackend{
		member: func(
			group string,
			account string,
		) (bool, error) {
			return state[membershipKey{
				account: account,
				group:   group,
			}], nil
		},

		setMembership: func(
			group string,
			account string,
			want bool,
		) error {
			key := membershipKey{
				account: account,
				group:   group,
			}

			if group == "Event Log Readers" &&
				account ==
					identities.CollectorSender.Account {
				eventCalls++

				if eventCalls == 1 {
					state[key] = want

					return errors.New(
						"synthetic group mutation failure",
					)
				}

				return errors.New(
					"synthetic group rollback failure",
				)
			}

			state[key] = want
			return nil
		},
	}

	_, err := reconcileServer2016GroupsWithBackend(
		identities,
		backend,
	)
	if err == nil {
		t.Fatal(
			"synthetic group rollback failure unexpectedly succeeded",
		)
	}

	for _, expected := range []string{
		"synthetic group mutation failure",
		"synthetic group rollback failure",
	} {
		if !strings.Contains(
			err.Error(),
			expected,
		) {
			t.Fatalf(
				"combined error does not contain %q: %v",
				expected,
				err,
			)
		}
	}
}
