// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import "fmt"

func verifySORPostgreSQLClusterState(
	spec sorPostgreSQLClusterSpec,
	policy sorPostgreSQLClusterPolicy,
) error {
	clusterState :=
		classifySORPostgreSQLCluster(
			spec,
		)

	if clusterState !=
		sorPostgreSQLClusterInitialized {
		return fmt.Errorf(
			"PostgreSQL cluster is not INITIALIZED: %s",
			clusterState,
		)
	}

	policyState :=
		classifySORPostgreSQLClusterPolicy(
			policy,
			spec.UID,
			spec.GID,
		)

	if policyState !=
		sorPostgreSQLClusterPolicyOwnedMatch {
		return fmt.Errorf(
			"PostgreSQL cluster policy is not OWNED_MATCH: %s",
			policyState,
		)
	}

	return nil
}
