//go:build windows

package ntfs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func TestCollectPathOnWindowsNTFS(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "object.txt")
	if err := os.WriteFile(target, []byte("file intelligence"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target+`:payload`, []byte("hidden stream"), 0o600); err != nil {
		t.Fatal(err)
	}

	observation, err := CollectPath(context.Background(), "scope-test", root, target)
	if err != nil {
		t.Fatal(err)
	}
	if observation.SubjectKind != records.SubjectFile {
		t.Fatalf("subject kind = %s", observation.SubjectKind)
	}
	if observation.Metadata.LogicalSize != strconv.Itoa(len("file intelligence")) {
		t.Fatalf("logical size = %s", observation.Metadata.LogicalSize)
	}
	if observation.VolumeIdentity.VolumeGUID == "" || observation.ObjectIdentity.FileReferenceNumber == "" {
		t.Fatalf("identity is incomplete: %+v %+v", observation.VolumeIdentity, observation.ObjectIdentity)
	}
	if observation.GovernedRoot.ScopeID != "scope-test" || observation.GovernedRoot.State != records.ObservationStatePresent || observation.Containment.State != records.ObservationStatePresent {
		t.Fatalf("scope result is incomplete: %+v %+v", observation.GovernedRoot, observation.Containment)
	}
	foundDefault := false
	foundADS := false
	for _, stream := range observation.StreamInventory.Streams {
		if stream.Identity.Kind == records.StreamDefaultData {
			foundDefault = true
		}
		if stream.Identity.Kind == records.StreamNamedData {
			foundADS = true
		}
	}
	if !foundDefault || !foundADS {
		t.Fatalf("stream inventory missing default or named data stream: %+v", observation.StreamInventory.Streams)
	}
}

func TestCollectPathRejectsSiblingEscape(t *testing.T) {
	root := t.TempDir()
	outsideRoot := t.TempDir()
	target := filepath.Join(outsideRoot, "outside.txt")
	if err := os.WriteFile(target, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := CollectPath(context.Background(), "scope-test", root, target)
	if !errors.Is(err, ErrOutsideGovernedRoot) {
		t.Fatalf("error = %v, want ErrOutsideGovernedRoot", err)
	}
}
