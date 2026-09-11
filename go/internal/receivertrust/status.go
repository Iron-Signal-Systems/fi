// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package receivertrust

import (
	"fmt"
	"os"
)

const (
	BatchCRLPath        = "/etc/fi/pki/trust/fi-batch-signing-ca.crl.pem"
	BatchIssuerPath     = "/etc/fi/pki/trust/fi-batch-signing-ca.crt.pem"
	ReceiverCertPath    = "/etc/fi/pki/receiver/certs/fi-receiver-tls-fullchain.pem"
	ReceiverKeyPath     = "/etc/fi/pki/receiver/private/fi-receiver-tls.key.pem"
	RootCAPath          = "/etc/fi/pki/trust/fi-root-ca.crt.pem"
	SourceRegistryPath  = "/etc/fi/sources"
	TransportCRLPath    = "/etc/fi/pki/trust/fi-transport-ca.crl.pem"
	TransportIssuerPath = "/etc/fi/pki/trust/fi-transport-ca.crt.pem"
)

// PathState describes whether one required receiver trust path is present.
type PathState struct {
	Path    string
	Present bool
}

// Status describes the receiver trust material currently present on disk.
//
// Complete means all required paths are present. It does not mean the
// cryptographic relationships or contents have been validated.
type Status struct {
	BatchCRL        PathState
	BatchIssuer     PathState
	Complete        bool
	ReceiverCert    PathState
	ReceiverKey     PathState
	RootCA          PathState
	SourceRegistry  PathState
	TransportCRL    PathState
	TransportIssuer PathState
}

type pathSet struct {
	BatchCRL        string
	BatchIssuer     string
	ReceiverCert    string
	ReceiverKey     string
	RootCA          string
	SourceRegistry  string
	TransportCRL    string
	TransportIssuer string
}

// Inspect reads receiver trust-path presence without modifying receiver state.
func Inspect() (Status, error) {
	return inspect(pathSet{
		BatchCRL:        BatchCRLPath,
		BatchIssuer:     BatchIssuerPath,
		ReceiverCert:    ReceiverCertPath,
		ReceiverKey:     ReceiverKeyPath,
		RootCA:          RootCAPath,
		SourceRegistry:  SourceRegistryPath,
		TransportCRL:    TransportCRLPath,
		TransportIssuer: TransportIssuerPath,
	})
}

func inspect(paths pathSet) (Status, error) {
	status := Status{
		BatchCRL: PathState{
			Path: paths.BatchCRL,
		},
		BatchIssuer: PathState{
			Path: paths.BatchIssuer,
		},
		ReceiverCert: PathState{
			Path: paths.ReceiverCert,
		},
		ReceiverKey: PathState{
			Path: paths.ReceiverKey,
		},
		RootCA: PathState{
			Path: paths.RootCA,
		},
		SourceRegistry: PathState{
			Path: paths.SourceRegistry,
		},
		TransportCRL: PathState{
			Path: paths.TransportCRL,
		},
		TransportIssuer: PathState{
			Path: paths.TransportIssuer,
		},
	}

	checks := []*PathState{
		&status.BatchCRL,
		&status.BatchIssuer,
		&status.ReceiverCert,
		&status.ReceiverKey,
		&status.RootCA,
		&status.SourceRegistry,
		&status.TransportCRL,
		&status.TransportIssuer,
	}

	for _, check := range checks {
		present, err := pathExists(check.Path)
		if err != nil {
			return Status{}, err
		}

		check.Present = present
	}

	status.Complete =
		status.BatchCRL.Present &&
			status.BatchIssuer.Present &&
			status.ReceiverCert.Present &&
			status.ReceiverKey.Present &&
			status.RootCA.Present &&
			status.SourceRegistry.Present &&
			status.TransportCRL.Present &&
			status.TransportIssuer.Present

	return status, nil
}

func pathExists(path string) (bool, error) {
	_, err := os.Stat(path)

	switch {
	case err == nil:
		return true, nil

	case os.IsNotExist(err):
		return false, nil

	default:
		return false, fmt.Errorf(
			"inspect receiver trust path %q: %w",
			path,
			err,
		)
	}
}
