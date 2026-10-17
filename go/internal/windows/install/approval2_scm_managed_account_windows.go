// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

const approval2ServiceAccountManagedValueName = "ServiceAccountManaged"

// setApproval2ServiceManagedAccountFlag marks a newly-created FI Windows
// service as SCM-managed-account backed.
//
// Windows stores this state separately from ServiceStartName. A gMSA service
// can therefore expose the correct DOMAIN\account$ identity while still
// lacking the managed-account flag required by FI's authoritative discovery
// and by Windows' managed-service-account handling.
//
// Approval 2 calls this only for transaction-created FI services. If this
// write or its authoritative read-back fails, the caller rolls the created
// service back before returning.
func setApproval2ServiceManagedAccountFlag(
	serviceName string,
	account string,
) error {
	serviceName = strings.TrimSpace(serviceName)
	account = strings.TrimSpace(account)

	if serviceName == "" {
		return fmt.Errorf(
			"service name is required",
		)
	}

	if err := validateApproval2ManagedServiceAccount(account); err != nil {
		return err
	}

	key, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\`+serviceName,
		registry.QUERY_VALUE|registry.SET_VALUE,
	)
	if err != nil {
		return fmt.Errorf(
			"open service registry key for managed-account state %s: %w",
			serviceName,
			err,
		)
	}
	defer key.Close()

	if err := key.SetDWordValue(
		approval2ServiceAccountManagedValueName,
		1,
	); err != nil {
		return fmt.Errorf(
			"set %s for service %s: %w",
			approval2ServiceAccountManagedValueName,
			serviceName,
			err,
		)
	}

	if observed := readManagedAccountState(
		serviceName,
	); observed != "true" {
		return fmt.Errorf(
			"verify %s for service %s: observed=%s expected=true",
			approval2ServiceAccountManagedValueName,
			serviceName,
			observed,
		)
	}

	return nil
}

func validateApproval2ManagedServiceAccount(
	account string,
) error {
	account = strings.TrimSpace(account)
	if account == "" {
		return fmt.Errorf(
			"managed service account is required",
		)
	}

	separator := strings.Index(
		account,
		`\`,
	)
	if separator <= 0 ||
		separator == len(account)-1 {
		return fmt.Errorf(
			"managed service account %q must use DOMAIN\\account$ form",
			account,
		)
	}

	name := account[separator+1:]
	if !strings.HasSuffix(
		name,
		"$",
	) {
		return fmt.Errorf(
			"managed service account %q must end in $",
			account,
		)
	}

	return nil
}
