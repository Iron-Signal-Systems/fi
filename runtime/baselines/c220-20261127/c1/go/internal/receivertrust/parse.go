// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package receivertrust

// ParseState describes whether one receiver trust object can be parsed.
type ParseState struct {
	Detail string
	Parsed bool
	Path   string
}

// ParseStatus describes parsing of receiver X.509 and CRL material.
//
// Complete means all required certificate and CRL objects parsed successfully.
// It does not mean their cryptographic relationships or policy are valid.
type ParseStatus struct {
	BatchCRL        ParseState
	BatchIssuer     ParseState
	Complete        bool
	ReceiverCert    ParseState
	RootCA          ParseState
	TransportCRL    ParseState
	TransportIssuer ParseState
}

// InspectParsing parses receiver certificate and CRL material without
// modifying receiver state.
func InspectParsing() ParseStatus {
	return inspectParsing(pathSet{
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

func inspectParsing(paths pathSet) ParseStatus {
	status := ParseStatus{
		BatchCRL:        parseCRLState(paths.BatchCRL),
		BatchIssuer:     parseCertificateState(paths.BatchIssuer),
		ReceiverCert:    parseCertificateChainState(paths.ReceiverCert),
		RootCA:          parseCertificateState(paths.RootCA),
		TransportCRL:    parseCRLState(paths.TransportCRL),
		TransportIssuer: parseCertificateState(paths.TransportIssuer),
	}

	status.Complete =
		status.BatchCRL.Parsed &&
			status.BatchIssuer.Parsed &&
			status.ReceiverCert.Parsed &&
			status.RootCA.Parsed &&
			status.TransportCRL.Parsed &&
			status.TransportIssuer.Parsed

	return status
}

func newParseState(path string, err error) ParseState {
	if err == nil {
		return ParseState{
			Parsed: true,
			Path:   path,
		}
	}

	return ParseState{
		Detail: err.Error(),
		Parsed: false,
		Path:   path,
	}
}

func parseCertificateChainState(path string) ParseState {
	_, err := LoadCertificateChain(path)
	return newParseState(path, err)
}

func parseCertificateState(path string) ParseState {
	_, err := LoadCertificate(path)
	return newParseState(path, err)
}

func parseCRLState(path string) ParseState {
	_, err := LoadCRL(path)
	return newParseState(path, err)
}
