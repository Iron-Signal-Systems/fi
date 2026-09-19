//go:build windows

package main

import (
	"testing"
	"time"
)

func TestGenerationRuntimeConfigDefaultsAreUsable(t *testing.T) {
	config := senderConfig{
		GenerationInterval:        time.Minute,
		GenerationMaxEncodedBytes: 64 << 30,
		GenerationTransferTimeout: 2 * time.Hour,
	}
	if config.GenerationInterval <= 0 {
		t.Fatal("generation interval must be positive")
	}
	if config.GenerationMaxEncodedBytes == 0 {
		t.Fatal("generation encoded ceiling must be positive")
	}
	if config.GenerationTransferTimeout <= 0 {
		t.Fatal("generation transport timeout must be positive")
	}
}
