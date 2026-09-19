//go:build linux

package transportreceiver

import "testing"

func TestValidateRecoveryConfig(t *testing.T) {
	if err := validateRecoveryConfig(Config{}); err != nil {
		t.Fatalf("all-zero recovery config should disable recovery cleanly: %v", err)
	}
	if err := validateRecoveryConfig(Config{RecoveryMaxCanonicalBytes: 1}); err == nil {
		t.Fatal("partial recovery configuration unexpectedly accepted")
	}
	if err := validateRecoveryConfig(Config{
		RecoveryMaxCanonicalBytes: 64 << 30,
		RecoveryMaxEncodedBytes:   8 << 30,
		RecoveryMaxMembers:        50000,
	}); err != nil {
		t.Fatalf("valid recovery limits rejected: %v", err)
	}
}
