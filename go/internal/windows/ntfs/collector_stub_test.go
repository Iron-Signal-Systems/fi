//go:build !windows

package ntfs

import (
	"context"
	"errors"
	"testing"
)

func TestNonWindowsCollectorIsExplicitlyUnsupported(t *testing.T) {
	_, err := CollectPath(context.Background(), "scope-test", `C:\approved`, `C:\approved\example`)
	if !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("error = %v", err)
	}
}
