// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"strings"
	"testing"
)

func TestValidateSORPostgreSQLControlDataAccepted(
	t *testing.T,
) {
	output := []byte(
		"pg_control version number:            1800\n" +
			"Catalog version number:               202506181\n" +
			"Database system identifier:           123456789\n" +
			"Database cluster state:               shut down\n" +
			"Database block size:                  8192\n" +
			"Data page checksum version:           1\n",
	)

	if err :=
		validateSORPostgreSQLControlData(
			output,
		); err != nil {
		t.Fatalf(
			"validateSORPostgreSQLControlData() error = %v",
			err,
		)
	}
}

func TestParseSORPostgreSQLControlDataIgnoresUnrelatedFields(
	t *testing.T,
) {
	output := []byte(
		"Something unrelated: value\n" +
			"Database cluster state: shut down\n" +
			"Another field: another value\n" +
			"Database block size: 8192\n" +
			"Data page checksum version: 1\n",
	)

	control, err :=
		parseSORPostgreSQLControlData(
			output,
		)
	if err != nil {
		t.Fatal(err)
	}

	if control.ClusterState != "shut down" ||
		control.BlockSize != "8192" ||
		control.ChecksumVersion != "1" {
		t.Fatalf(
			"unexpected parsed control data: %+v",
			control,
		)
	}
}

func TestValidateSORPostgreSQLControlDataRejectsRunningCluster(
	t *testing.T,
) {
	output := []byte(
		"Database cluster state: in production\n" +
			"Database block size: 8192\n" +
			"Data page checksum version: 1\n",
	)

	err :=
		validateSORPostgreSQLControlData(
			output,
		)

	if err == nil {
		t.Fatal(
			"running cluster was accepted",
		)
	}

	if !strings.Contains(
		err.Error(),
		`cluster state = "in production"`,
	) {
		t.Fatalf(
			"unexpected error = %v",
			err,
		)
	}
}

func TestValidateSORPostgreSQLControlDataRejectsWrongBlockSize(
	t *testing.T,
) {
	output := []byte(
		"Database cluster state: shut down\n" +
			"Database block size: 16384\n" +
			"Data page checksum version: 1\n",
	)

	err :=
		validateSORPostgreSQLControlData(
			output,
		)

	if err == nil {
		t.Fatal(
			"wrong block size was accepted",
		)
	}

	if !strings.Contains(
		err.Error(),
		`block size = "16384"`,
	) {
		t.Fatalf(
			"unexpected error = %v",
			err,
		)
	}
}

func TestValidateSORPostgreSQLControlDataRejectsChecksumsDisabled(
	t *testing.T,
) {
	output := []byte(
		"Database cluster state: shut down\n" +
			"Database block size: 8192\n" +
			"Data page checksum version: 0\n",
	)

	err :=
		validateSORPostgreSQLControlData(
			output,
		)

	if err == nil {
		t.Fatal(
			"disabled checksums were accepted",
		)
	}

	if !strings.Contains(
		err.Error(),
		`checksum version = "0"`,
	) {
		t.Fatalf(
			"unexpected error = %v",
			err,
		)
	}
}

func TestValidateSORPostgreSQLControlDataRejectsMissingField(
	t *testing.T,
) {
	output := []byte(
		"Database cluster state: shut down\n" +
			"Database block size: 8192\n",
	)

	err :=
		validateSORPostgreSQLControlData(
			output,
		)

	if err == nil {
		t.Fatal(
			"missing checksum field was accepted",
		)
	}

	if !strings.Contains(
		err.Error(),
		"missing pg_controldata field",
	) {
		t.Fatalf(
			"unexpected error = %v",
			err,
		)
	}
}

func TestValidateSORPostgreSQLControlDataRejectsDuplicateRequiredField(
	t *testing.T,
) {
	output := []byte(
		"Database cluster state: shut down\n" +
			"Database cluster state: shut down\n" +
			"Database block size: 8192\n" +
			"Data page checksum version: 1\n",
	)

	err :=
		validateSORPostgreSQLControlData(
			output,
		)

	if err == nil {
		t.Fatal(
			"duplicate required field was accepted",
		)
	}

	if !strings.Contains(
		err.Error(),
		"duplicate pg_controldata field",
	) {
		t.Fatalf(
			"unexpected error = %v",
			err,
		)
	}
}

func TestValidateSORPostgreSQLControlDataAcceptsCRLF(
	t *testing.T,
) {
	output := []byte(
		"Database cluster state: shut down\r\n" +
			"Database block size: 8192\r\n" +
			"Data page checksum version: 1\r\n",
	)

	if err :=
		validateSORPostgreSQLControlData(
			output,
		); err != nil {
		t.Fatalf(
			"CRLF output rejected: %v",
			err,
		)
	}
}
