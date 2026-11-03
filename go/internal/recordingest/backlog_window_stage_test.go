// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, in the repository root LICENSE file.

package recordingest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// privateBacklogTestRoot sets the explicit security boundary required by
// the durable stage. testing.T.TempDir() need not use mode 0700 for every
// child directory on every operating system and test umask.
func privateBacklogTestRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := verifyPrivateBacklogRoot(root); err != nil {
		t.Fatal(err)
	}
	return root
}

func privateBacklogStageFixture(t *testing.T) *PreparedGeneration {
	t.Helper()
	g := backlogWindowFixture([]int{3, 3, 3}, 8)
	g.Receipt.Descriptor.SourceID = "fi-private-stage-test.iss.local"
	g.Receipt.Descriptor.GenerationID = "20261101T120000.000000000Z-test"
	g.ReceiptSHA256 = strings.Repeat("a", 64)
	g.Receipt.TransferSHA256 = strings.Repeat("b", 64)
	for i := range g.Batches {
		data := bytes.Repeat([]byte{byte('a' + i)}, 8)
		dataHash := sha256.Sum256(data)
		manifest := []byte(fmt.Sprintf("test original manifest %d", i))
		manifestHash := sha256.Sum256(manifest)
		g.Batches[i].Manifest.DataSHA256 = hex.EncodeToString(dataHash[:])
		g.Batches[i].ManifestSHA256 = hex.EncodeToString(manifestHash[:])
		g.Batches[i].ManifestRawBytes = manifest
		g.Batches[i].DataPath = filepath.Join(t.TempDir(), "source.jsonl")
		if err := os.WriteFile(g.Batches[i].DataPath, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return g
}

func TestBacklogStagePrivateDurableWindowAndVerifiedReuse(t *testing.T) {
	g := privateBacklogStageFixture(t)
	root := privateBacklogTestRoot(t)
	limits := BacklogWindowLimits{MaxRecords: 6, MaxDataBytes: 32}
	ctx := context.Background()
	path, err := MaterializeBacklogWindow(ctx, g, limits, 0, root)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyMaterializedBacklogWindow(ctx, g, limits, 0, root); err != nil {
		t.Fatal(err)
	}
	// Simulate loss of the original ephemeral loader staging files. The
	// durable copy must independently survive and verify on resume.
	if err := os.Remove(g.Batches[0].DataPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(g.Batches[1].DataPath); err != nil {
		t.Fatal(err)
	}
	path2, err := MaterializeBacklogWindow(ctx, g, limits, 0, root)
	if err != nil || path2 != path {
		t.Fatalf("durable stage reuse: first=%s second=%s err=%v", path, path2, err)
	}
	path3, err := MaterializeBacklogWindow(ctx, g, limits, 1, root)
	if err != nil || path3 == path {
		t.Fatalf("second window materialization: %s %v", path3, err)
	}
	if err := VerifyMaterializedBacklogWindow(ctx, g, limits, 1, root); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(path, "batch-00000002.data")); !os.IsNotExist(err) {
		t.Fatalf("window 0 unexpectedly contains batch 2: %v", err)
	}
}

func TestBacklogStageRejectsTamperedMaterializedBytesAndNeverOverwrites(t *testing.T) {
	g := privateBacklogStageFixture(t)
	root := privateBacklogTestRoot(t)
	limits := BacklogWindowLimits{MaxRecords: 6, MaxDataBytes: 32}
	ctx := context.Background()
	p, err := MaterializeBacklogWindow(ctx, g, limits, 0, root)
	if err != nil {
		t.Fatal(err)
	}
	tamper := filepath.Join(p, "batch-00000000.data")
	if err := os.WriteFile(tamper, []byte("cccccccc"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyMaterializedBacklogWindow(ctx, g, limits, 0, root); err == nil {
		t.Fatal("tampered data accepted")
	}
	if _, err := MaterializeBacklogWindow(ctx, g, limits, 0, root); err == nil {
		t.Fatal("existing tampered window silently replaced")
	}
	rechecked, err := os.ReadFile(tamper)
	if err != nil || string(rechecked) != "cccccccc" {
		t.Fatalf("tampered evidence overwritten %q %v", rechecked, err)
	}
}

func TestBacklogStageRejectsManifestChangeAndReceiptChange(t *testing.T) {
	g := privateBacklogStageFixture(t)
	root := privateBacklogTestRoot(t)
	limits := BacklogWindowLimits{MaxRecords: 6, MaxDataBytes: 32}
	ctx := context.Background()
	p, err := MaterializeBacklogWindow(ctx, g, limits, 0, root)
	if err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(p, "batch-00000000.manifest")
	if err := os.WriteFile(manifest, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyMaterializedBacklogWindow(ctx, g, limits, 0, root); err == nil {
		t.Fatal("changed manifest accepted")
	}
	g.ReceiptSHA256 = strings.Repeat("c", 64)
	if err := VerifyMaterializedBacklogWindow(ctx, g, limits, 0, root); err == nil {
		t.Fatal("different receipt accepted at same stage")
	}
}

func TestBacklogStageRejectsCorruptedInputWithoutPublishing(t *testing.T) {
	g := privateBacklogStageFixture(t)
	root := privateBacklogTestRoot(t)
	limits := BacklogWindowLimits{MaxRecords: 6, MaxDataBytes: 32}
	if err := os.WriteFile(g.Batches[1].DataPath, []byte("badbytes"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := MaterializeBacklogWindow(context.Background(), g, limits, 0, root); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("modified source data must fail at its digest check, got %v", err)
	}
	d, err := DescribeBacklogWindows(g, limits)
	if err != nil {
		t.Fatal(err)
	}
	ready := filepath.Join(root, "receipt-"+d[0].ReceiptSHA256, "window-00000000")
	if _, err := os.Stat(ready); !os.IsNotExist(err) {
		t.Fatalf("unverified complete window became visible: %v", err)
	}
}

func TestBacklogStageRejectsUnsafePrivateRootAndCancel(t *testing.T) {
	g := privateBacklogStageFixture(t)
	limits := BacklogWindowLimits{MaxRecords: 6, MaxDataBytes: 32}
	root := t.TempDir()
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := MaterializeBacklogWindow(context.Background(), g, limits, 0, root); err == nil {
		t.Fatal("world-readable stage root accepted")
	}
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "stage-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := MaterializeBacklogWindow(context.Background(), g, limits, 0, link); err == nil {
		t.Fatal("symlink stage root accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := MaterializeBacklogWindow(ctx, g, limits, 0, target); err == nil {
		t.Fatal("canceled stage request accepted")
	}
}

// The optimized continuous-private handoff is tested for signed hash equality
// and persistent file survival, not as a synthetic throughput benchmark.
func TestVerifiedBacklogStageLinkSurvivesEphemeralSourceRemoval(t *testing.T) {
	root := privateBacklogTestRoot(t)
	stageDir, err := os.MkdirTemp(root, ".fi-backlog-continuous-")
	if err != nil { t.Fatal(err) }
	data := []byte("exact signed FI source bytes\n")
	src := filepath.Join(stageDir, "batch-00000000.data")
	dest := filepath.Join(root, "durable-window.data")
	if err := os.WriteFile(src, data, 0600); err != nil { t.Fatal(err) }
	sum := sha256.Sum256(data)
	linked, err := linkVerifiedBacklogStageArtifact(context.Background(), src, dest,
		int64(len(data)), hex.EncodeToString(sum[:]))
	if err != nil { t.Fatal(err) }
	if !linked { t.Skip("filesystem does not support hardlink handoff; verified copy fallback passed") }
	s, err := os.Stat(src)
	if err != nil { t.Fatal(err) }
	d, err := os.Stat(dest)
	if err != nil { t.Fatal(err) }
	if !os.SameFile(s,d) { t.Fatal("optimized durable handoff copied rather than linked inode") }
	if err := os.RemoveAll(stageDir); err != nil { t.Fatal(err) }
	got, err := os.ReadFile(dest)
	if err != nil || !bytes.Equal(got,data) { t.Fatalf("durable linked evidence lost: %v",err) }
	if err := hashBacklogStageFile(context.Background(),dest,int64(len(data)),hex.EncodeToString(sum[:]));err!=nil { t.Fatal(err) }
}

func TestVerifiedBacklogStageLinkFailsClosedOnBadDigestAndMode(t *testing.T) {
	root := privateBacklogTestRoot(t)
	src := filepath.Join(root,"staged.data")
	dest := filepath.Join(root,"durable.data")
	data := []byte("original signed bytes")
	if err:=os.WriteFile(src,data,0600);err!=nil{t.Fatal(err)}
	other := sha256.Sum256([]byte("different signed bytes"))
	if _,err:=linkVerifiedBacklogStageArtifact(context.Background(),src,dest,int64(len(data)),hex.EncodeToString(other[:]));err==nil{t.Fatal("tampered data linked")}
	if _,err:=os.Lstat(dest);!os.IsNotExist(err){t.Fatalf("invalid data materialized: %v",err)}
	sum:=sha256.Sum256(data)
	if err:=os.Chmod(src,0644);err!=nil{t.Fatal(err)}
	if _,err:=linkVerifiedBacklogStageArtifact(context.Background(),src,dest,int64(len(data)),hex.EncodeToString(sum[:]));err==nil{t.Fatal("unsafe stage file permissions accepted")}
}
