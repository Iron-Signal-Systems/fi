// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import "fmt"

type sorPostgreSQLClusterInitializer interface {
	Initialize() error

	PublishPolicy(
		sorPostgreSQLClusterPolicy,
		uint64,
		uint64,
	) error
}

func InitializeSORPostgreSQL(
	config Config,
) error {
	probe := systemHostProbe{}

	if err := requireSORPostgreSQLPolicyHost(
		config,
		probe,
	); err != nil {
		return err
	}

	if err := requireSORPostgreSQLPolicyPrerequisites(
		config,
		probe,
	); err != nil {
		return err
	}

	rcSpec := sorPostgreSQLPolicySpecForConfig(
		config,
	)

	rcState := classifySORPostgreSQLPolicy(
		rcSpec,
	)

	if rcState != sorPostgreSQLPolicyOwnedMatch {
		return fmt.Errorf(
			"PostgreSQL rc policy is not OWNED_MATCH: %s",
			rcState,
		)
	}

	if err := verifySORPostgreSQLInitializationSubstrate(
		config,
	); err != nil {
		return err
	}

	identity, err := inspectSORPostgreSQLIdentity(
		config.Value("FI_SOR_DB_ROOT"),
	)
	if err != nil {
		return fmt.Errorf(
			"inspect PostgreSQL service identity for cluster initialization: %w",
			err,
		)
	}

	policy, err := buildSORPostgreSQLClusterPolicy(
		config,
	)
	if err != nil {
		return fmt.Errorf(
			"build PostgreSQL cluster policy for initialization: %w",
			err,
		)
	}

	spec := sorPostgreSQLClusterSpec{
		GID:          identity.GID,
		MajorVersion: sorPostgreSQLClusterMajorVersion,
		PGData:       config.Value("FI_SOR_POSTGRES_HOST"),
		UID:          identity.UID,
	}

	return initializeSORPostgreSQLCluster(
		spec,
		policy,
		systemSORPostgreSQLClusterInitializer{},
	)
}

type sorPostgreSQLInitializationSubstrateVerifiers struct {
	Devfs       func(Config) error
	HostFiles   func(Config) error
	HostNetwork func(Config) error
	Lifecycle   func(Config) error
	PFPolicy    func(Config) error
}

func verifySORPostgreSQLInitializationSubstrate(
	config Config,
) error {
	return verifySORPostgreSQLInitializationSubstrateWith(
		config,
		sorPostgreSQLInitializationSubstrateVerifiers{
			Devfs:       VerifyDevfs,
			HostFiles:   VerifyHostFiles,
			HostNetwork: VerifyHostNetwork,
			Lifecycle:   VerifyLifecycle,
			PFPolicy:    VerifyPFPolicy,
		},
	)
}

func verifySORPostgreSQLInitializationSubstrateWith(
	config Config,
	verifiers sorPostgreSQLInitializationSubstrateVerifiers,
) error {
	if err := verifiers.Devfs(
		config,
	); err != nil {
		return fmt.Errorf(
			"PostgreSQL initialization devfs prerequisite failed: %w",
			err,
		)
	}

	if err := verifiers.HostFiles(
		config,
	); err != nil {
		return fmt.Errorf(
			"PostgreSQL initialization host-file prerequisite failed: %w",
			err,
		)
	}

	if err := verifiers.HostNetwork(
		config,
	); err != nil {
		return fmt.Errorf(
			"PostgreSQL initialization host-network prerequisite failed: %w",
			err,
		)
	}

	if err := verifiers.PFPolicy(
		config,
	); err != nil {
		return fmt.Errorf(
			"PostgreSQL initialization persistent PF prerequisite failed: %w",
			err,
		)
	}

	if err := verifiers.Lifecycle(
		config,
	); err != nil {
		return fmt.Errorf(
			"PostgreSQL initialization lifecycle prerequisite failed: %w",
			err,
		)
	}

	return nil
}

func initializeSORPostgreSQLCluster(
	spec sorPostgreSQLClusterSpec,
	policy sorPostgreSQLClusterPolicy,
	initializer sorPostgreSQLClusterInitializer,
) error {
	initialClusterState :=
		classifySORPostgreSQLCluster(
			spec,
		)

	switch initialClusterState {
	case sorPostgreSQLClusterInitialized:
		policyState :=
			classifySORPostgreSQLClusterPolicy(
				policy,
				spec.UID,
				spec.GID,
			)

		if policyState ==
			sorPostgreSQLClusterPolicyOwnedMatch {
			return nil
		}

		return fmt.Errorf(
			"PostgreSQL cluster already initialized but FI policy is not OWNED_MATCH: %s",
			policyState,
		)

	case sorPostgreSQLClusterEmpty:

	case sorPostgreSQLClusterAbsent:
		return fmt.Errorf(
			"PostgreSQL cluster initialization requires existing authoritative PGDATA: %s",
			initialClusterState,
		)

	case sorPostgreSQLClusterPartial:
		return fmt.Errorf(
			"PostgreSQL cluster initialization blocked by partial or foreign PGDATA state: %s",
			initialClusterState,
		)

	case sorPostgreSQLClusterUnknown:
		return fmt.Errorf(
			"PostgreSQL cluster initialization blocked by unknown PGDATA state: %s",
			initialClusterState,
		)

	default:
		return fmt.Errorf(
			"invalid PostgreSQL cluster state: %s",
			initialClusterState,
		)
	}

	if err := initializer.Initialize(); err != nil {
		return fmt.Errorf(
			"initialize PostgreSQL cluster: %w",
			err,
		)
	}

	initializedState :=
		classifySORPostgreSQLCluster(
			spec,
		)

	if initializedState !=
		sorPostgreSQLClusterInitialized {
		return fmt.Errorf(
			"PostgreSQL cluster did not verify after initialization: %s",
			initializedState,
		)
	}

	unmanagedPolicyState :=
		classifySORPostgreSQLClusterPolicy(
			policy,
			spec.UID,
			spec.GID,
		)

	if unmanagedPolicyState !=
		sorPostgreSQLClusterPolicyUnmanaged {
		return fmt.Errorf(
			"new PostgreSQL cluster is not exact UNMANAGED state before FI policy publication: %s",
			unmanagedPolicyState,
		)
	}

	if err := initializer.PublishPolicy(
		policy,
		spec.UID,
		spec.GID,
	); err != nil {
		return fmt.Errorf(
			"publish FI PostgreSQL cluster policy: %w",
			err,
		)
	}

	finalClusterState :=
		classifySORPostgreSQLCluster(
			spec,
		)

	if finalClusterState !=
		sorPostgreSQLClusterInitialized {
		return fmt.Errorf(
			"PostgreSQL cluster changed during policy publication: %s",
			finalClusterState,
		)
	}

	finalPolicyState :=
		classifySORPostgreSQLClusterPolicy(
			policy,
			spec.UID,
			spec.GID,
		)

	if finalPolicyState !=
		sorPostgreSQLClusterPolicyOwnedMatch {
		return fmt.Errorf(
			"FI PostgreSQL cluster policy did not verify after publication: %s",
			finalPolicyState,
		)
	}

	return nil
}
