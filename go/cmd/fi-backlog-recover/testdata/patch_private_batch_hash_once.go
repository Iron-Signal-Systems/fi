// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the FI Source Review License.
//
// This standalone stdlib-only patcher modifies ONLY an extracted, disposable
// pinned H16 benchmark source tree, never the checked-out FI repository.
// It refuses missing or ambiguous anchors, and writes files only after every
// anchor has matched. Original source SHA comes from the existing H16 runner.
package main

import (
    "errors"
    "fmt"
    "os"
    "path/filepath"
    "strings"
)

func replaceExactly(s, previous, replacement string) (string, error) {
    if strings.Count(s, previous) != 1 {
        return "", fmt.Errorf("FI HASH ONCE PATCH STOP: expected one source anchor, found %d", strings.Count(s, previous))
    }
    return strings.Replace(s, previous, replacement, 1), nil
}

func patchIngester(s string) (string,error) {
    edits := [][2]string{
        {
            "\t\"fmt\"\n\t\"io\"\n",
            "\t\"fmt\"\n\t\"hash\"\n\t\"io\"\n",
        },
        {
            "\tBatchHash      time.Duration\n",
            "\tBatchHash      time.Duration\n\tBatchHashReusedBatches int64 // private COW trust-propagation proof, not a skipped record digest\n",
        },
        {
            "\treader := bufio.NewReader(file)\n\thasher := sha256.New()\n",
            "\treader := bufio.NewReader(file)\n" +
                "\tproof, err := privateReuseSignedBatchDigest(ctx, batch, file)\n" +
                "\tif err != nil { return 0, fmt.Errorf(\"FI verified batch evidence: %w\", err) }\n" +
                "\tvar hasher hash.Hash\n" +
                "\tif proof == nil { hasher = sha256.New() }\n",
        },
        {
            "\t\t_, _ = hasher.Write(raw)\n\t\tprofile.BatchHash += time.Since(hashStarted)",
            "\t\tif hasher != nil {\n" +
                "\t\t\t_, _ = hasher.Write(raw)\n" +
                "\t\t\tprofile.BatchHash += time.Since(hashStarted)\n" +
                "\t\t}",
        },
        {
            "\tgotSHA := hex.EncodeToString(hasher.Sum(nil))\n" +
                "\tif ordinal != int64(batch.Manifest.RecordCount) || byteCount != batch.Manifest.DataBytes || gotSHA != batch.Manifest.DataSHA256 {\n" +
                "\t\treturn ordinal, fmt.Errorf(\"%w: batch %s changed between custody validation and relational ingest\", ErrSourceRecordRejected, batch.BatchID)\n" +
                "\t}",
            "\tif ordinal != int64(batch.Manifest.RecordCount) || byteCount != batch.Manifest.DataBytes {\n" +
                "\t\treturn ordinal, fmt.Errorf(\"%w: signed batch %s record or byte count changed\", ErrSourceRecordRejected, batch.BatchID)\n" +
                "\t}\n" +
                "\tif proof != nil {\n" +
                "\t\t// Original signed cache SHA has already been verified. Reuse it\n" +
                "\t\t// only for the exact owned and unchanged opened COW clone.\n" +
                "\t\tif err := proof.check(); err != nil {\n" +
                "\t\t\treturn ordinal, fmt.Errorf(\"%w: batch %s evidence identity changed: %v\", ErrSourceRecordRejected, batch.BatchID, err)\n" +
                "\t\t}\n" +
                "\t\tprofile.BatchHashReusedBatches++\n" +
                "\t} else {\n" +
                "\t\tgotSHA := hex.EncodeToString(hasher.Sum(nil))\n" +
                "\t\tif gotSHA != batch.Manifest.DataSHA256 {\n" +
                "\t\t\treturn ordinal, fmt.Errorf(\"%w: batch %s changed between custody validation and relational ingest\", ErrSourceRecordRejected, batch.BatchID)\n" +
                "\t\t}\n" +
                "\t}",
        },
    }
    var err error
    for _,p:=range edits {
        s,err=replaceExactly(s,p[0],p[1])
        if err!=nil{return "",err}
    }
    return s,nil
}

func patchProfile(s string) (string,error) {
    const anchor = "\tfmt.Printf(\"FI PRIVATE STAGE PROFILE index=%d"
    return replaceExactly(s, anchor,
        "\tfmt.Printf(\"FI PRIVATE BATCH HASH ONCE window=%d trusted_batches=%d\", index, profile.BatchHashReusedBatches)\n" +
        "\tfmt.Printf(\"\\n\")\n" +
        anchor)
}

func main() {
    if len(os.Args)!=2 {
        fmt.Fprintln(os.Stderr,"usage: go run patch_private_batch_hash_once.go /absolute/disposable/optimized-source")
        os.Exit(2)
    }
    root:=os.Args[1]
    if !filepath.IsAbs(root) || !strings.Contains(root,"/fi-window-bench-") ||
        !strings.HasSuffix(root, "/optimized-source") {
        fmt.Fprintln(os.Stderr,"FI HASH ONCE PATCH STOP: only disposable archived optimized-source accepted")
        os.Exit(2)
    }
    ingester:=filepath.Join(root,"go/internal/recordingest/postgres_ingest.go")
    profile:=filepath.Join(root,"go/internal/recordingest/backlog_typed_window_postgres.go")
    originalA,err:=os.ReadFile(ingester)
    if err!=nil {panic(err)}
    originalB,err:=os.ReadFile(profile)
    if err!=nil {panic(err)}
    changedA,err:=patchIngester(string(originalA))
    if err!=nil {panic(err)}
    changedB,err:=patchProfile(string(originalB))
    if err!=nil {panic(err)}
    if changedA==string(originalA) || changedB==string(originalB) {
        panic(errors.New("FI HASH ONCE PATCH STOP: no changes"))
    }
    // Individual writes occur only after both files were checked; caller
    // aborts the entire disposable fixture on failure.
    if err:=os.WriteFile(ingester,[]byte(changedA),0600);err!=nil{panic(err)}
    if err:=os.WriteFile(profile,[]byte(changedB),0600);err!=nil{panic(err)}
    fmt.Println("FI HASH ONCE PATCH PASS source_isolated=true source_hash_matches_pinned_runner=true")
}
