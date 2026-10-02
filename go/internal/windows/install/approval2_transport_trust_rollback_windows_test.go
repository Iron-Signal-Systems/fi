// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/config"
)

type approval2TransportTrustRollbackFixture struct {
	configBytes []byte
	crlDER      []byte
	crlPath     string
	crlSHA256   string
	trustPath   string
}

func TestCreateApproval2TransportTrustFilesCleansStagesAfterStagedConfigFailure(
	t *testing.T,
) {
	t.Parallel()

	fixture := newApproval2TransportTrustRollbackFixture(
		t,
	)

	transactionID := "staged-config-failure"

	_, err :=
		createApproval2TransportTrustFilesWithRename(
			fixture.trustPath,
			fixture.crlPath,
			[]byte(
				"version_id: invalid-transport-trust-version\n",
			),
			fixture.crlDER,
			fixture.crlSHA256,
			transactionID,
			os.Rename,
		)

	if err == nil {
		t.Fatal(
			"invalid staged transport-trust configuration unexpectedly succeeded",
		)
	}

	for _, path := range []string{
		fixture.crlPath,
		fixture.trustPath,
		fixture.crlPath +
			".fi-new-" +
			transactionID,
		fixture.trustPath +
			".fi-new-" +
			transactionID,
	} {
		if _, statErr := os.Lstat(
			path,
		); !errors.Is(
			statErr,
			os.ErrNotExist,
		) {
			t.Fatalf(
				"failed staged transaction left %s present: %v",
				path,
				statErr,
			)
		}
	}
}

func TestCreateApproval2TransportTrustFilesRollsBackCRLAfterSecondActivationFailure(
	t *testing.T,
) {
	t.Parallel()

	fixture := newApproval2TransportTrustRollbackFixture(
		t,
	)

	transactionID := "second-rename-failure"

	synthetic := errors.New(
		"synthetic trust activation failure",
	)

	renameCalls := 0

	renameFile := func(
		oldPath string,
		newPath string,
	) error {
		renameCalls++

		if renameCalls == 2 {
			return synthetic
		}

		return os.Rename(
			oldPath,
			newPath,
		)
	}

	_, err :=
		createApproval2TransportTrustFilesWithRename(
			fixture.trustPath,
			fixture.crlPath,
			fixture.configBytes,
			fixture.crlDER,
			fixture.crlSHA256,
			transactionID,
			renameFile,
		)

	if err == nil {
		t.Fatal(
			"synthetic second activation failure unexpectedly succeeded",
		)
	}

	if !errors.Is(
		err,
		synthetic,
	) {
		t.Fatalf(
			"activation failure was not preserved: %v",
			err,
		)
	}

	if renameCalls != 2 {
		t.Fatalf(
			"rename calls=%d want=2",
			renameCalls,
		)
	}

	for _, path := range []string{
		fixture.crlPath,
		fixture.trustPath,
		fixture.crlPath +
			".fi-new-" +
			transactionID,
		fixture.trustPath +
			".fi-new-" +
			transactionID,
	} {
		if _, statErr := os.Lstat(
			path,
		); !errors.Is(
			statErr,
			os.ErrNotExist,
		) {
			t.Fatalf(
				"failed activation left %s present: %v",
				path,
				statErr,
			)
		}
	}
}

func TestCreateApproval2TransportTrustFilesStillReturnsRollbackOwnership(
	t *testing.T,
) {
	t.Parallel()

	fixture := newApproval2TransportTrustRollbackFixture(
		t,
	)

	rollback, err :=
		createApproval2TransportTrustFilesWithRename(
			fixture.trustPath,
			fixture.crlPath,
			fixture.configBytes,
			fixture.crlDER,
			fixture.crlSHA256,
			"successful-activation",
			os.Rename,
		)
	if err != nil {
		t.Fatal(err)
	}

	if rollback == nil {
		t.Fatal(
			"successful transport-trust activation returned nil rollback",
		)
	}

	if err := rollback(); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{
		fixture.crlPath,
		fixture.trustPath,
	} {
		if _, statErr := os.Lstat(
			path,
		); !errors.Is(
			statErr,
			os.ErrNotExist,
		) {
			t.Fatalf(
				"rollback left %s present: %v",
				path,
				statErr,
			)
		}
	}
}

func newApproval2TransportTrustRollbackFixture(
	t *testing.T,
) approval2TransportTrustRollbackFixture {
	t.Helper()

	root := t.TempDir()

	configDirectory := filepath.Join(
		root,
		"config",
	)

	crlDirectory := filepath.Join(
		root,
		"pki",
		"trust",
	)

	if err := os.MkdirAll(
		configDirectory,
		0o700,
	); err != nil {
		t.Fatal(err)
	}

	if err := os.MkdirAll(
		crlDirectory,
		0o700,
	); err != nil {
		t.Fatal(err)
	}

	crlDER := createApproval2TestCRL(
		t,
	)

	digest := sha256.Sum256(
		crlDER,
	)

	crlSHA256 := hex.EncodeToString(
		digest[:],
	)

	crlPath := filepath.Join(
		crlDirectory,
		"fi-transport-ca.crl.pem",
	)

	trustPath := filepath.Join(
		configDirectory,
		"fi-transport-trust.conf",
	)

	value := config.TransportTrustConfig{
		VersionID: config.TransportTrustVersion1,

		BatchSigningCertificateSHA256: strings.Repeat(
			"b",
			64,
		),

		RootCertificateSHA256: strings.Repeat(
			"d",
			64,
		),

		TransportCertificateSHA256: strings.Repeat(
			"a",
			64,
		),

		TransportCRLPath: crlPath,

		TransportIssuerSHA256: strings.Repeat(
			"d",
			64,
		),
	}

	configBytes, err :=
		renderApproval2TransportTrustConfig(
			value,
		)
	if err != nil {
		t.Fatal(err)
	}

	return approval2TransportTrustRollbackFixture{
		configBytes: configBytes,
		crlDER:      crlDER,
		crlPath:     crlPath,
		crlSHA256:   crlSHA256,
		trustPath:   trustPath,
	}
}
