// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package freshinstall

import (
	"errors"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/config"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/volumeconsent"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/volumereview"
)

// Exercise the Windows-native bridge without assuming a GitHub runner is an
// eligible interactive administrator. The deliberately absent signed
// approval can never become installer authority, regardless of runner token.
func TestNativeInstallerOperatorCannotAuthorizeMissingSignedReceipt(t *testing.T) {
	err := verifyNativeInstallerOperatorReceipt(
		nil,
		volumeconsent.Expected{},
		config.VolumeConfig{},
		volumereview.Review{},
		nil,
	)
	if err == nil {
		t.Fatal("native token inspection authorized an absent signed receipt")
	}
	if !errors.Is(err, ErrUnqualifiedInstallerToken) &&
		!errors.Is(err, volumeconsent.ErrInvalidReceipt) {
		t.Fatalf("unexpected native consent boundary failure: %v", err)
	}
}
