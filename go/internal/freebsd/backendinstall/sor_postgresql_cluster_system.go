// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

type systemSORPostgreSQLClusterInitializer struct {
	execute func(
		string,
		...string,
	) ([]byte, error)
}

func (
	initializer systemSORPostgreSQLClusterInitializer,
) Initialize() (returnErr error) {
	execute := initializer.execute

	if execute == nil {
		execute = func(
			path string,
			args ...string,
		) ([]byte, error) {
			return exec.Command(
				path,
				args...,
			).CombinedOutput()
		}
	}

	if err := requireSORInitializerJailsStopped(
		execute,
	); err != nil {
		return err
	}

	if err := requireSORInitializerPFRuntimeReady(
		execute,
	); err != nil {
		return fmt.Errorf(
			"FI PF runtime is not ready for PostgreSQL initialization: %w",
			err,
		)
	}

	if err := executeSORInitializerCommand(
		execute,
		"/etc/rc.d/jail",
		"onestart",
		"fi-sor-db",
	); err != nil {
		return fmt.Errorf(
			"start fi-sor-db for PostgreSQL initialization: %w",
			err,
		)
	}

	sorStarted := true

	defer func() {
		if !sorStarted {
			return
		}

		cleanupErr := stopAndVerifySORInitializerJail(
			execute,
		)
		if cleanupErr == nil {
			return
		}

		cleanupErr = fmt.Errorf(
			"emergency PostgreSQL initialization cleanup: %w",
			cleanupErr,
		)

		returnErr = errors.Join(
			returnErr,
			cleanupErr,
		)
	}()

	if err := executeSORInitializerCommand(
		execute,
		"/usr/sbin/jls",
		"-j",
		"fi-sor-db",
	); err != nil {
		return fmt.Errorf(
			"verify fi-sor-db after initialization start: %w",
			err,
		)
	}

	if err := executeSORInitializerCommand(
		execute,
		"/usr/sbin/jexec",
		"fi-sor-db",
		"/usr/sbin/service",
		"postgresql",
		"oneinitdb",
	); err != nil {
		return fmt.Errorf(
			"run PostgreSQL oneinitdb: %w",
			err,
		)
	}

	controlOutput, controlErr := execute(
		"/usr/sbin/jexec",
		"fi-sor-db",
		"/usr/local/bin/pg_controldata",
		"/var/db/fi/sor/postgres",
	)
	if controlErr != nil {
		message := strings.TrimSpace(
			string(controlOutput),
		)

		if message == "" {
			return fmt.Errorf(
				"verify PostgreSQL control data: %w",
				controlErr,
			)
		}

		return fmt.Errorf(
			"verify PostgreSQL control data: %w: %s",
			controlErr,
			message,
		)
	}

	if err := validateSORPostgreSQLControlData(
		controlOutput,
	); err != nil {
		return fmt.Errorf(
			"validate PostgreSQL control data: %w",
			err,
		)
	}

	if err := stopAndVerifySORInitializerJail(
		execute,
	); err != nil {
		return fmt.Errorf(
			"stop fi-sor-db after PostgreSQL initialization: %w",
			err,
		)
	}

	sorStarted = false

	return nil
}

func executeSORInitializerCommand(
	execute func(
		string,
		...string,
	) ([]byte, error),
	path string,
	args ...string,
) error {
	output, err := execute(
		path,
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

func inspectSORInitializerJailStopped(
	execute func(
		string,
		...string,
	) ([]byte, error),
	jailName string,
) (bool, error) {
	output, err := execute(
		"/usr/sbin/jls",
		"-j",
		jailName,
	)

	if err == nil {
		return false, nil
	}

	if jlsReportsSORInitializerJailAbsent(
		output,
		jailName,
	) {
		return true, nil
	}

	message := strings.TrimSpace(
		string(output),
	)

	if message == "" {
		return false, fmt.Errorf(
			"jls failed without recognized stopped-jail signature: %w",
			err,
		)
	}

	return false, fmt.Errorf(
		"jls failed without recognized stopped-jail signature: %w: %s",
		err,
		message,
	)
}

func jlsReportsSORInitializerJailAbsent(
	output []byte,
	jailName string,
) bool {
	normalized := strings.ReplaceAll(
		string(output),
		"\r\n",
		"\n",
	)

	lines := strings.Split(
		strings.TrimSpace(
			normalized,
		),
		"\n",
	)

	if len(lines) != 2 {
		return false
	}

	expectedFirst := fmt.Sprintf(
		`jls: jail %q not found`,
		jailName,
	)

	if strings.TrimSpace(
		lines[0],
	) != expectedFirst {
		return false
	}

	fields := strings.Fields(
		lines[1],
	)

	if len(fields) != 5 {
		return false
	}

	return fields[0] == "JID" &&
		fields[1] == "IP" &&
		fields[2] == "Address" &&
		fields[3] == "Hostname" &&
		fields[4] == "Path"
}

func requireSORInitializerPFRuntimeReady(
	execute func(
		string,
		...string,
	) ([]byte, error),
) error {
	return executeSORInitializerCommand(
		execute,
		"/usr/local/etc/rc.d/fi_pf",
		"onestatus",
	)
}

func requireSORInitializerJailsStopped(
	execute func(
		string,
		...string,
	) ([]byte, error),
) error {
	for _, jailName := range []string{
		"fi-sor-db",
		"fi-ingest",
		"fi-receiver",
	} {
		stopped, err :=
			inspectSORInitializerJailStopped(
				execute,
				jailName,
			)

		if err != nil {
			return fmt.Errorf(
				"cannot prove %s is stopped: %w",
				jailName,
				err,
			)
		}

		if !stopped {
			return fmt.Errorf(
				"PostgreSQL initialization requires all FI jails stopped: %s is running",
				jailName,
			)
		}
	}

	return nil
}

func stopAndVerifySORInitializerJail(
	execute func(
		string,
		...string,
	) ([]byte, error),
) error {
	if err := executeSORInitializerCommand(
		execute,
		"/etc/rc.d/jail",
		"onestop",
		"fi-sor-db",
	); err != nil {
		return fmt.Errorf(
			"stop fi-sor-db: %w",
			err,
		)
	}

	stopped, err :=
		inspectSORInitializerJailStopped(
			execute,
			"fi-sor-db",
		)

	if err != nil {
		return fmt.Errorf(
			"verify fi-sor-db stopped: %w",
			err,
		)
	}

	if !stopped {
		return fmt.Errorf(
			"fi-sor-db remained running",
		)
	}

	return nil
}

func (
	initializer systemSORPostgreSQLClusterInitializer,
) PublishPolicy(
	policy sorPostgreSQLClusterPolicy,
	uid uint64,
	gid uint64,
) error {
	return publishSORPostgreSQLClusterPolicy(
		policy,
		uid,
		gid,
	)
}
