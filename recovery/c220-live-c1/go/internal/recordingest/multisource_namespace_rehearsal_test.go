package recordingest

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestM1SourceNamespaceRehearsal(t *testing.T) {
	if os.Getenv("FI_M1_NAMESPACE_REHEARSAL") != "1" {
		t.Skip("M1 namespace rehearsal not requested")
	}

	base := filepath.Join(
		os.Getenv("HOME"),
		"fi-m1-receipts-20261012",
	)
	flat := filepath.Join(base, "flat")
	target := filepath.Join(base, "namespaced")
	sources := filepath.Join(target, "sources")

	const (
		fs19 = "iss-fs-2019.iss.local"
		fs22 = "iss-fs-22.iss.local"
	)

	candidates, err := DiscoverRecordedReceipts(flat, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 238 {
		t.Fatalf("flat receipt count=%d, want 238", len(candidates))
	}

	counts := map[string]int{
		fs19: 0,
		fs22: 0,
	}

	for _, candidate := range candidates {
		if _, ok := counts[candidate.SourceID]; !ok {
			t.Fatalf("unexpected source %q", candidate.SourceID)
		}
		counts[candidate.SourceID]++
	}

	if counts[fs19] != 104 || counts[fs22] != 134 {
		t.Fatalf("unexpected source distribution: %v", counts)
	}

	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatalf("namespace destination already exists or cannot be inspected: %v", err)
	}

	syncDir := func(path string) error {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		syncErr := f.Sync()
		closeErr := f.Close()
		if syncErr != nil {
			return syncErr
		}
		return closeErr
	}

	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	if err := syncDir(base); err != nil {
		t.Fatal(err)
	}

	if err := os.Mkdir(sources, 0700); err != nil {
		t.Fatal(err)
	}
	if err := syncDir(target); err != nil {
		t.Fatal(err)
	}

	for _, source := range []string{fs19, fs22} {
		if err := os.Mkdir(
			filepath.Join(sources, source),
			0700,
		); err != nil {
			t.Fatal(err)
		}
	}
	if err := syncDir(sources); err != nil {
		t.Fatal(err)
	}

	for _, candidate := range candidates {
		destination := filepath.Join(
			sources,
			candidate.SourceID,
			filepath.Base(candidate.Path),
		)

		if err := os.Link(candidate.Path, destination); err != nil {
			t.Fatalf("hard-link receipt: %v", err)
		}

		original, err := os.Lstat(candidate.Path)
		if err != nil {
			t.Fatal(err)
		}
		linked, err := os.Lstat(destination)
		if err != nil {
			t.Fatal(err)
		}

		if !os.SameFile(original, linked) {
			t.Fatalf("receipt hard-link identity mismatch: %s", destination)
		}
	}

	for _, source := range []string{fs19, fs22} {
		if err := syncDir(filepath.Join(sources, source)); err != nil {
			t.Fatal(err)
		}
	}

	discover := func(source string, want int) error {
		root := filepath.Join(sources, source)
		found, err := DiscoverRecordedReceipts(root, source)
		if err != nil {
			return err
		}
		if len(found) != want {
			return fmt.Errorf(
				"source %s: found %d, expected %d",
				source, len(found), want,
			)
		}
		return nil
	}

	if err := discover(fs19, 104); err != nil {
		t.Fatal(err)
	}
	if err := discover(fs22, 134); err != nil {
		t.Fatal(err)
	}

	t.Log("PASS: 238 source-specific hard links validated")

	corruptPath := filepath.Join(
		sources,
		fs19,
		"generation-"+strings.Repeat("0", 64)+".record.json",
	)

	file, err := os.OpenFile(
		corruptPath,
		os.O_CREATE|os.O_EXCL|os.O_WRONLY,
		0400,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(corruptPath)

	if _, err := file.Write([]byte("{invalid-receipt")); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	source19Root := filepath.Join(sources, fs19)

	if err := syncDir(source19Root); err != nil {
		t.Fatal(err)
	}

	if err := discover(fs19, 104); err == nil {
		t.Fatal("malformed FS2019 receipt was silently accepted")
	}

	if err := discover(fs22, 134); err != nil {
		t.Fatalf("FS2019 corruption affected FS22: %v", err)
	}

	t.Log("PASS: malformed FS2019 receipt fails closed")
	t.Log("PASS: FS22 independently discovers all 134 receipts")

	if err := os.Remove(corruptPath); err != nil {
		t.Fatal(err)
	}
	if err := syncDir(source19Root); err != nil {
		t.Fatal(err)
	}

	if err := discover(fs19, 104); err != nil {
		t.Fatal(err)
	}

	t.Log("PASS: FS2019 discovery recovered after malformed test object removal")
}
