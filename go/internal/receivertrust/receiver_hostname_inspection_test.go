// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package receivertrust

import (
	"path/filepath"
	"testing"
)

func TestInspectReceiverHostnameValidationAt(t *testing.T) {
	_, issuer, leaf, _, _ := newReceiverIdentityMaterial(t)
	directory := t.TempDir()
	certificatePath := filepath.Join(directory, "receiver-fullchain.crt")

	writeReceiverCertificateChain(
		t,
		certificatePath,
		leaf,
		issuer,
	)

	state := inspectReceiverHostnameValidationAt(
		certificatePath,
		"fi-receiver-test.iss.local",
	)

	if !state.Valid {
		t.Fatalf(
			"ValidationState.Valid = false, want true: %s",
			state.Detail,
		)
	}

	state = inspectReceiverHostnameValidationAt(
		certificatePath,
		"other-receiver.iss.local",
	)

	if state.Valid {
		t.Fatal("ValidationState.Valid = true, want false")
	}
}
