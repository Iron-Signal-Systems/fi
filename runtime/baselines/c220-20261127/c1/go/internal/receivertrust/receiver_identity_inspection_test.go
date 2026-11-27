// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package receivertrust

import (
	"path/filepath"
	"testing"
	"time"
)

func TestInspectReceiverCertificateValidationAtMaterial(t *testing.T) {
	root, issuer, leaf, _, leafKey := newReceiverIdentityMaterial(t)

	directory := t.TempDir()
	rootPath := filepath.Join(directory, "root.crt")
	issuerPath := filepath.Join(directory, "transport.crt")
	certificatePath := filepath.Join(directory, "receiver-fullchain.crt")
	keyPath := filepath.Join(directory, "receiver.key")

	writeReceiverCertificateChain(t, rootPath, root)
	writeReceiverCertificateChain(t, issuerPath, issuer)
	writeReceiverCertificateChain(
		t,
		certificatePath,
		leaf,
		issuer,
		root,
	)
	writeReceiverPrivateKey(t, keyPath, leafKey)

	state := inspectReceiverCertificateValidationAt(
		certificatePath,
		rootPath,
		issuerPath,
		time.Now(),
	)

	if !state.Valid {
		t.Fatalf(
			"ValidationState.Valid = false, want true: %s",
			state.Detail,
		)
	}

	keyState := inspectReceiverKeyValidationAt(
		certificatePath,
		keyPath,
	)

	if !keyState.Valid {
		t.Fatalf(
			"key ValidationState.Valid = false, want true: %s",
			keyState.Detail,
		)
	}
}
