// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"fmt"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	approval2ServiceStabilityWindow       = 5 * time.Second
	approval2ServiceStabilityPollInterval = 250 * time.Millisecond
)

var approval2FIServiceStabilityOrder = []string{
	"FIUSNReader",
	"FIObjReader",
	"FICollector",
	"FICRLRefresher",
	"FISender",
}

func approval2ServiceStabilityRequired(
	plan InstallPlan,
) bool {
	for _, action := range plan.Actions {
		if !planActionMutates(
			action.Action,
		) {
			continue
		}

		switch action.Authority {
		case "PACKAGE", "SCM", "RUNTIME":
			return true
		}
	}

	return false
}

func waitForFIServiceStability(
	window time.Duration,
) error {
	if window <= 0 {
		return fmt.Errorf(
			"FI service stability window must be positive; observed=%s",
			window,
		)
	}

	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf(
			"connect to service control manager for FI service stability: %w",
			err,
		)
	}
	defer manager.Disconnect()

	type openedService struct {
		name    string
		service *mgr.Service
	}

	opened := make(
		[]openedService,
		0,
		len(approval2FIServiceStabilityOrder),
	)
	defer func() {
		for _, current := range opened {
			current.service.Close()
		}
	}()

	for _, name := range approval2FIServiceStabilityOrder {
		service, err := manager.OpenService(
			name,
		)
		if err != nil {
			return fmt.Errorf(
				"open FI service %s for stability verification: %w",
				name,
				err,
			)
		}
		opened = append(
			opened,
			openedService{
				name:    name,
				service: service,
			},
		)
	}

	check := func() error {
		for _, current := range opened {
			status, err := current.service.Query()
			if err != nil {
				return fmt.Errorf(
					"query FI service %s during stability verification: %w",
					current.name,
					err,
				)
			}
			if status.State != svc.Running {
				return fmt.Errorf(
					"FI service %s did not remain Running during %s stability window; state=%d",
					current.name,
					window,
					status.State,
				)
			}
		}
		return nil
	}

	deadline := time.Now().Add(
		window,
	)

	for {
		if err := check(); err != nil {
			return err
		}

		remaining := time.Until(
			deadline,
		)
		if remaining <= 0 {
			return nil
		}

		delay := approval2ServiceStabilityPollInterval
		if remaining < delay {
			delay = remaining
		}
		time.Sleep(
			delay,
		)
	}
}
