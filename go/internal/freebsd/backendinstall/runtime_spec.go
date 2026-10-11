// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"fmt"
	"os"
	"path/filepath"
)

const runtimeFileMarker = "# FI-MANAGED: ironsignal-fi-freebsd-runtime-v1"

type runtimeFileSpec struct {
	Content   []byte
	GID       uint64
	Mode      os.FileMode
	PriorName string
	Role      string
	Target    string
	UID       uint64
}

type runtimePlan struct {
	Files   []runtimeFileSpec
	Parents []lifecycleParentSpec
}

func buildRuntimePlan(
	config Config,
) (runtimePlan, error) {
	values, err := runtimeRenderValues(
		config,
	)
	if err != nil {
		return runtimePlan{}, err
	}

	receiverRoot := config.Value(
		"FI_RECEIVER_ROOT",
	)

	ingestRoot := config.Value(
		"FI_INGEST_ROOT",
	)

	parents := []lifecycleParentSpec{
		{
			GID:  0,
			Mode: 0o755,
			Path: filepath.Join(
				receiverRoot,
				"usr/local/libexec",
			),
			Role: "receiver-local-libexec",
			UID:  0,
		},
		{
			GID:  0,
			Mode: 0o755,
			Path: filepath.Join(
				receiverRoot,
				"usr/local/etc/rc.d",
			),
			Role: "receiver-local-rc-directory",
			UID:  0,
		},
		{
			GID:  0,
			Mode: 0o755,
			Path: filepath.Join(
				receiverRoot,
				"etc/rc.conf.d",
			),
			Role: "receiver-rc-conf-directory",
			UID:  0,
		},
		{
			GID:  0,
			Mode: 0o755,
			Path: filepath.Join(
				ingestRoot,
				"usr/local/libexec",
			),
			Role: "ingest-local-libexec",
			UID:  0,
		},
		{
			GID:  0,
			Mode: 0o755,
			Path: filepath.Join(
				ingestRoot,
				"usr/local/etc/rc.d",
			),
			Role: "ingest-local-rc-directory",
			UID:  0,
		},
		{
			GID:  0,
			Mode: 0o755,
			Path: filepath.Join(
				ingestRoot,
				"etc/rc.conf.d",
			),
			Role: "ingest-rc-conf-directory",
			UID:  0,
		},
	}

	definitions := []struct {
		asset     string
		mode      os.FileMode
		priorName string
		role      string
		target    string
	}{
		{
			asset:     runtimeAssetReceiverSupervisor,
			mode:      0o555,
			priorName: "fi-receiver-supervisor",
			role:      "receiver-supervisor",
			target: filepath.Join(
				receiverRoot,
				"usr/local/libexec/fi-receiver-supervisor",
			),
		},
		{
			asset:     runtimeAssetReceiverRCService,
			mode:      0o555,
			priorName: "rc.d.fi_receiver",
			role:      "receiver-rc-service",
			target: filepath.Join(
				receiverRoot,
				"usr/local/etc/rc.d/fi_receiver",
			),
		},
		{
			asset:     runtimeAssetReceiverRCConfig,
			mode:      0o644,
			priorName: "rc.conf.d.fi_receiver",
			role:      "receiver-runtime-config",
			target: filepath.Join(
				receiverRoot,
				"etc/rc.conf.d/fi_receiver",
			),
		},
		{
			asset:     runtimeAssetIngestRunner,
			mode:      0o555,
			priorName: "fi-ingest-worker-run",
			role:      "ingest-worker-runner",
			target: filepath.Join(
				ingestRoot,
				"usr/local/libexec/fi-ingest-worker-run",
			),
		},
		{
			asset:     runtimeAssetIngestRCService,
			mode:      0o555,
			priorName: "rc.d.fi_ingest_worker",
			role:      "ingest-worker-rc-service",
			target: filepath.Join(
				ingestRoot,
				"usr/local/etc/rc.d/fi_ingest_worker",
			),
		},
		{
			asset:     runtimeAssetIngestRCConfig,
			mode:      0o644,
			priorName: "rc.conf.d.fi_ingest_worker",
			role:      "ingest-worker-runtime-config",
			target: filepath.Join(
				ingestRoot,
				"etc/rc.conf.d/fi_ingest_worker",
			),
		},
	}

	files := make(
		[]runtimeFileSpec,
		0,
		len(definitions),
	)

	for _, definition := range definitions {
		rendered, err := renderRuntimeAsset(
			definition.asset,
			values,
		)
		if err != nil {
			return runtimePlan{}, fmt.Errorf(
				"render runtime file %s: %w",
				definition.role,
				err,
			)
		}

		if !containsExactLine(
			rendered,
			runtimeFileMarker,
		) {
			return runtimePlan{}, fmt.Errorf(
				"rendered runtime file lacks FI marker: %s",
				definition.role,
			)
		}

		if !containsExactLine(
			rendered,
			"# FI-ROLE: "+definition.role,
		) {
			return runtimePlan{}, fmt.Errorf(
				"rendered runtime file lacks exact FI role: %s",
				definition.role,
			)
		}

		files = append(
			files,
			runtimeFileSpec{
				Content:   rendered,
				GID:       0,
				Mode:      definition.mode,
				PriorName: definition.priorName,
				Role:      definition.role,
				Target:    definition.target,
				UID:       0,
			},
		)
	}

	return runtimePlan{
		Files:   files,
		Parents: parents,
	}, nil
}

func renderRuntimeAsset(
	asset string,
	values map[string]string,
) ([]byte, error) {
	unresolved := ""

	rendered := hostFileTokenPattern.ReplaceAllStringFunc(
		asset,
		func(token string) string {
			key := token[1 : len(token)-1]

			value, exists := values[key]
			if !exists || value == "" {
				if unresolved == "" {
					unresolved = token
				}

				return token
			}

			return value
		},
	)

	if unresolved != "" {
		return nil, fmt.Errorf(
			"unresolved runtime configuration token: %s",
			unresolved,
		)
	}

	if token := hostFileTokenPattern.FindString(
		rendered,
	); token != "" {
		return nil, fmt.Errorf(
			"unresolved runtime configuration token after rendering: %s",
			token,
		)
	}

	return []byte(rendered), nil
}

func runtimeRenderValues(
	config Config,
) (map[string]string, error) {
	receiverIP, err := pfAddressOnly(
		"FI_RECEIVER_EXTERNAL_ADDRESS",
		config,
	)
	if err != nil {
		return nil, err
	}

	sorIP, err := pfAddressOnly(
		"FI_SOR_DB_WORK_ADDRESS",
		config,
	)
	if err != nil {
		return nil, err
	}

	return map[string]string{
		"FI_RECEIVER_EXTERNAL_IP": receiverIP,
		"FI_SOR_DB_WORK_IP":       sorIP,
	}, nil
}
