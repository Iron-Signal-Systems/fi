// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"errors"
	"fmt"
	"runtime"
	"sort"
	"strings"
)

const policyCreateAccount = uint32(0x00000010)

var (
	lsaAddAccountRightsProc     = advapi32DLL.NewProc("LsaAddAccountRights")
	lsaRemoveAccountRightsProc  = advapi32DLL.NewProc("LsaRemoveAccountRights")
	netLocalGroupAddMembersProc = netapi32DLL.NewProc("NetLocalGroupAddMembers")
	netLocalGroupDelMembersProc = netapi32DLL.NewProc("NetLocalGroupDelMembers")
)

type server2016RightsBackend struct {
	enumerate func(string) ([]string, error)
	setExact  func(string, []string) error
}

func reconcileServer2016Rights(
	identities DesiredFIIdentities,
) (func() error, error) {
	return reconcileServer2016RightsWithBackend(
		identities,
		server2016RightsBackend{
			enumerate: func(
				account string,
			) ([]string, error) {
				identity, found :=
					desiredFIIdentityByAccount(
						identities,
						account,
					)
				if !found {
					return nil, fmt.Errorf(
						"approved FI identity is unavailable for rights discovery: %s",
						account,
					)
				}

				sid, err :=
					authoritativeDesiredFIIdentitySID(
						identity,
					)
				if err != nil {
					return nil, err
				}

				return enumerateDirectAccountRightsSID(
					sid,
					account,
				)
			},

			setExact: func(
				account string,
				desired []string,
			) error {
				identity, found :=
					desiredFIIdentityByAccount(
						identities,
						account,
					)
				if !found {
					return fmt.Errorf(
						"approved FI identity is unavailable for rights mutation: %s",
						account,
					)
				}

				sid, err :=
					authoritativeDesiredFIIdentitySID(
						identity,
					)
				if err != nil {
					return err
				}

				return setExactAccountRightsSID(
					sid,
					account,
					desired,
				)
			},
		},
	)
}

func reconcileServer2016RightsWithBackend(
	identities DesiredFIIdentities,
	backend server2016RightsBackend,
) (func() error, error) {
	if backend.enumerate == nil ||
		backend.setExact == nil {
		return nil, errors.New(
			"Server 2016 rights backend is incomplete",
		)
	}

	type contract struct {
		account string
		rights  []string
	}

	contracts := []contract{
		{
			account: identities.CollectorSender.Account,
			rights: []string{
				"SeServiceLogonRight",
			},
		},
		{
			account: identities.CRLRefresher.Account,
			rights: []string{
				"SeServiceLogonRight",
			},
		},
		{
			account: identities.USNReader.Account,
			rights: []string{
				"SeServiceLogonRight",
			},
		},
		{
			account: identities.ObjReader.Account,
			rights: []string{
				"SeBackupPrivilege",
				"SeSecurityPrivilege",
				"SeServiceLogonRight",
			},
		},
	}

	original := make(
		map[string][]string,
		len(contracts),
	)

	for _, item := range contracts {
		rights, err := backend.enumerate(
			item.account,
		)
		if err != nil {
			return nil, err
		}

		original[item.account] = append(
			[]string(nil),
			rights...,
		)
	}

	applied := make(
		[]contract,
		0,
		len(contracts),
	)

	rollbackApplied := func() error {
		var found []error

		for index := len(applied) - 1; index >= 0; index-- {
			item := applied[index]

			if err := backend.setExact(
				item.account,
				original[item.account],
			); err != nil {
				found = append(
					found,
					fmt.Errorf(
						"restore direct rights for %s: %w",
						item.account,
						err,
					),
				)
			}
		}

		return errors.Join(
			found...,
		)
	}

	for _, item := range contracts {
		// Take rollback ownership before mutation. setExact may partially
		// change LSA state before returning an error.
		applied = append(
			applied,
			item,
		)

		if err := backend.setExact(
			item.account,
			item.rights,
		); err != nil {
			base := fmt.Errorf(
				"reconcile direct rights for %s: %w",
				item.account,
				err,
			)

			if rollbackErr := rollbackApplied(); rollbackErr != nil {
				base = errors.Join(
					base,
					fmt.Errorf(
						"rollback Server 2016 direct-right transaction: %w",
						rollbackErr,
					),
				)
			}

			return nil, base
		}
	}

	return rollbackApplied, nil
}
func setExactAccountRights(
	account string,
	desired []string,
) error {
	sid, sidBuffer, err :=
		lookupAccountSID(
			account,
		)
	if err != nil {
		return err
	}

	result :=
		setExactAccountRightsSID(
			sid,
			account,
			desired,
		)

	runtime.KeepAlive(
		sidBuffer,
	)

	return result
}

func mutateAccountRight(
	account string,
	right string,
	add bool,
) error {
	sid, sidBuffer, err :=
		lookupAccountSID(
			account,
		)
	if err != nil {
		return err
	}

	result :=
		mutateAccountRightSID(
			sid,
			account,
			right,
			add,
		)

	runtime.KeepAlive(
		sidBuffer,
	)

	return result
}

type server2016GroupsBackend struct {
	member        func(string, string) (bool, error)
	setMembership func(string, string, bool) error
}

func reconcileServer2016Groups(
	identities DesiredFIIdentities,
) (func() error, error) {
	return reconcileServer2016GroupsWithBackend(
		identities,
		server2016GroupsBackend{
			member: func(
				group string,
				account string,
			) (bool, error) {
				identity, found :=
					desiredFIIdentityByAccount(
						identities,
						account,
					)
				if !found {
					return false, fmt.Errorf(
						"approved FI identity is unavailable for local-group discovery: %s",
						account,
					)
				}

				sid, err :=
					authoritativeDesiredFIIdentitySID(
						identity,
					)
				if err != nil {
					return false, err
				}

				return accountSIDIsDirectLocalGroupMember(
					group,
					sid,
				)
			},

			setMembership: func(
				group string,
				account string,
				want bool,
			) error {
				identity, found :=
					desiredFIIdentityByAccount(
						identities,
						account,
					)
				if !found {
					return fmt.Errorf(
						"approved FI identity is unavailable for local-group mutation: %s",
						account,
					)
				}

				sid, err :=
					authoritativeDesiredFIIdentitySID(
						identity,
					)
				if err != nil {
					return err
				}

				return setDirectLocalGroupMembershipSID(
					group,
					account,
					sid,
					want,
				)
			},
		},
	)
}

func reconcileServer2016GroupsWithBackend(
	identities DesiredFIIdentities,
	backend server2016GroupsBackend,
) (func() error, error) {
	if backend.member == nil ||
		backend.setMembership == nil {
		return nil, errors.New(
			"Server 2016 local-group backend is incomplete",
		)
	}

	type contract struct {
		account string
		group   string
		want    bool
	}

	contracts := []contract{
		{
			account: identities.CollectorSender.Account,
			group:   "Administrators",
			want:    false,
		},
		{
			account: identities.CollectorSender.Account,
			group:   "Event Log Readers",
			want:    true,
		},
		{
			account: identities.CRLRefresher.Account,
			group:   "Administrators",
			want:    false,
		},
		{
			account: identities.CRLRefresher.Account,
			group:   "Event Log Readers",
			want:    false,
		},
		{
			account: identities.CRLRefresher.Account,
			group:   "Backup Operators",
			want:    false,
		},
		{
			account: identities.USNReader.Account,
			group:   "Administrators",
			want:    true,
		},
		{
			account: identities.ObjReader.Account,
			group:   "Administrators",
			want:    false,
		},
		{
			account: identities.ObjReader.Account,
			group:   "Backup Operators",
			want:    false,
		},
	}

	original := make(
		[]bool,
		len(contracts),
	)

	for index, item := range contracts {
		member, err := backend.member(
			item.group,
			item.account,
		)
		if err != nil {
			return nil, err
		}
		original[index] = member
	}

	applied := make(
		[]int,
		0,
		len(contracts),
	)

	rollbackApplied := func() error {
		var found []error

		for position := len(applied) - 1; position >= 0; position-- {
			index := applied[position]
			item := contracts[index]

			if err := backend.setMembership(
				item.group,
				item.account,
				original[index],
			); err != nil {
				found = append(
					found,
					fmt.Errorf(
						"restore direct local-group membership account=%s group=%s: %w",
						item.account,
						item.group,
						err,
					),
				)
			}
		}

		return errors.Join(
			found...,
		)
	}

	for index, item := range contracts {
		if original[index] == item.want {
			continue
		}

		// Take rollback ownership before mutation. NetAPI may change membership
		// successfully and the authoritative read-back may then fail.
		applied = append(
			applied,
			index,
		)

		if err := backend.setMembership(
			item.group,
			item.account,
			item.want,
		); err != nil {
			base := fmt.Errorf(
				"reconcile direct local-group membership account=%s group=%s: %w",
				item.account,
				item.group,
				err,
			)

			if rollbackErr := rollbackApplied(); rollbackErr != nil {
				base = errors.Join(
					base,
					fmt.Errorf(
						"rollback Server 2016 local-group transaction: %w",
						rollbackErr,
					),
				)
			}

			return nil, base
		}
	}

	return rollbackApplied, nil
}
func setDirectLocalGroupMembership(
	group string,
	account string,
	want bool,
) error {
	sid, sidBuffer, err :=
		lookupAccountSID(
			account,
		)
	if err != nil {
		return err
	}

	result :=
		setDirectLocalGroupMembershipSID(
			group,
			account,
			sid,
			want,
		)

	runtime.KeepAlive(
		sidBuffer,
	)

	return result
}

func uniqueSortedFold(values []string) []string {
	seen := make(map[string]string, len(values))
	for _, value := range values {
		key := strings.ToLower(strings.TrimSpace(value))
		if key == "" {
			continue
		}
		if _, ok := seen[key]; !ok {
			seen[key] = value
		}
	}
	result := make([]string, 0, len(seen))
	for _, value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
