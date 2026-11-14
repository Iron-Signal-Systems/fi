// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// DEV ONLY. Build one four-arm W512 preparation concurrency experiment.
// Keep a CONSTANT 32-record credit budget for workers=2,4,8,16,
// one original ordered PostgreSQL writer, signed bytes/SQL unchanged.
// The only functional source change between arms is worker goroutine count.
// Never patch the accepted W512 seed or any authoritative SoR source.
package main

import (
    "errors"
    "fmt"
    "os"
    "path/filepath"
    "regexp"
    "strconv"
    "strings"
)

const fixedCredits = 32

type replace struct {
    path   string
    before string
    after  string
}

func exact(m map[string]string, r replace) error {
    source, ok := m[r.path]
    if !ok {
        info, err := os.Lstat(r.path)
        if err != nil { return err }
        if !info.Mode().IsRegular() { return fmt.Errorf("nonregular source %s", r.path) }
        bytes, err := os.ReadFile(r.path)
        if err != nil { return err }
        source = string(bytes)
    }
    n := strings.Count(source, r.before)
    if n != 1 {
        return fmt.Errorf("FI W512 WORKERS STOP path=%s anchor_matches=%d expected=1 anchor=%q",
            r.path, n, r.before)
    }
    m[r.path] = strings.Replace(source, r.before, r.after, 1)
    return nil
}

func run(stage string, workers int) error {
    if workers != 2 && workers != 4 && workers != 8 && workers != 16 {
        return errors.New("worker count must be exactly one of 2, 4, 8, 16")
    }
    stage = filepath.Clean(stage)
    prefix := fmt.Sprintf("/home/jwood/fi-window-bench-w512-worker%d-", workers)
    if !strings.HasPrefix(stage, prefix) || len(stage) <= len(prefix) {
        return errors.New("stage must be a specific isolated W512 worker experiment directory")
    }
    for _, r := range stage[len(prefix):] {
        if !(r >= '0' && r <= '9') && r != 'T' && r != 'Z' {
            return errors.New("stage timestamp contains unapproved characters")
        }
    }
    st, err := os.Lstat(stage)
    if err != nil { return err }
    if !st.IsDir() { return errors.New("stage is not a real directory") }
    source := filepath.Join(stage, "optimized-source")
    pilot := filepath.Join(stage, fmt.Sprintf("pilot-worker%d.sh", workers))
    ingest := filepath.Join(source, "go/internal/recordingest")
    cli := filepath.Join(source, "go/cmd/fi-backlog-recover")
    w := strconv.Itoa(workers)
    replacements := []replace{
        {
            filepath.Join(ingest, "private_parallel_preparation.go"),
            "privateParallelAMaxInFlight = 4",
            "privateParallelAMaxInFlight = 32",
        },
        {
            filepath.Join(ingest, "postgres_ingest.go"),
            "workers=2 inflight_limit=4 writers=1",
            "workers=" + w + " inflight_limit=32 writers=1",
        },
        {
            filepath.Join(cli, "main_freebsd.go"),
            "workers=2 inflight=4 postgres_writers=1 source_window=%s atomic=true",
            "workers=" + w + " inflight=32 postgres_writers=1 source_window=%s atomic=true",
        },
        {
            pilot,
            "root=/home/jwood/fi-window-bench-w512-w8g-$stamp",
            "root=/home/jwood/fi-window-bench-w512-sweep-w" + w + "-$stamp",
        },
        {
            pilot,
            "out=/var/tmp/fi-window-chunks-h16-w512-w8g-$stamp",
            "out=/var/tmp/fi-window-chunks-h16-w512-sweep-w" + w + "-$stamp",
        },
        {
            pilot,
            "workers=2\ninflight_limit=4\nsql_writers=1",
            "workers=" + w + "\ninflight_limit=32\nsql_writers=1",
        },
        {
            pilot,
            "FI PRIVATE PARALLEL PREP A ENABLED workers=2 inflight=4 postgres_writers=1 source_window=W512 atomic=true",
            "FI PRIVATE PARALLEL PREP A ENABLED workers=" + w + " inflight=32 postgres_writers=1 source_window=W512 atomic=true",
        },
        {
            pilot,
            "f[\"workers\"]!=2||f[\"inflight_limit\"]!=4||f[\"writers\"]!=1",
            "f[\"workers\"]!=" + w + "||f[\"inflight_limit\"]!=32||f[\"writers\"]!=1",
        },
        {
            pilot,
            "f[\"reorder_peak\"]+0>3",
            "f[\"reorder_peak\"]+0>31",
        },
        {
            pilot,
            "FI W512 WAL 8GB PILOT START start_index=1 windows=2 workers=2 writer=1 K32=32768",
            "FI W512 WORKER " + w + " PILOT START start_index=1 windows=2 workers=" + w + " writer=1 credits=32 K32=32768",
        },
        {
            pilot,
            "FI W512 WAL 8GB PILOT ACCEPTED windows=2 new_records=%s elapsed=%s workers=2 credits=4",
            "FI W512 WORKER " + w + " PILOT ACCEPTED windows=2 new_records=%s elapsed=%s workers=" + w + " credits=32",
        },
        {
            pilot,
            "FI W512 WAL 8GB METRICS BUNDLE PASS",
            "FI W512 WORKER " + w + " METRICS BUNDLE PASS",
        },
        {
            pilot,
            "bundle=\"$out/fi-w512-wal-w8g-$stamp.tar.gz\"",
            "bundle=\"$out/fi-w512-worker" + w + "-$stamp.tar.gz\"",
        },
    }
    // The immutable verified W512 seed stays offline. This insertion runs
    // inside the newly copied private jail and replaces only its recovery
    // executable, with pre- and post-copy SHA256 checks.
    install := strings.Join([]string{
        "JAIL",
        "candidate=" + stage + "/fi-optfield-recover-w" + w,
        "jexec -U jwood fi-dev sh -s \"$candidate\" \"$root\" <<'WORKER_CANDIDATE'",
        "set -eu",
        "umask 077",
        "candidate=$1",
        "root=$2",
        "[ -f \"$candidate\" ] && [ -f \"$candidate.sha256\" ] || exit 1",
        "[ \"$(sha256 -q \"$candidate\")\" = \"$(cat \"$candidate.sha256\")\" ] || exit 1",
        "cp \"$candidate\" \"$root/fi-optfield-recover\" || exit 1",
        "[ \"$(sha256 -q \"$root/fi-optfield-recover\")\" = \"$(cat \"$candidate.sha256\")\" ] || exit 1",
        "sha256 -q \"$root/fi-optfield-recover\" > \"$root/recover.sha256\" || exit 1",
        "WORKER_CANDIDATE",
        "mkdir -m 700 \"$out\"",
    }, "\n")
    replacements = append(replacements, replace{
        path: pilot,
        before: "JAIL\nmkdir -m 700 \"$out\"",
        after: install,
    })
    // gofmt may insert tabs between the Go constant identifier and '='.
    // Match precisely one named assignment with the literal original value 2.
    // Reject absence, duplicates, changed values, symlinks, or directories.
    workersFile := filepath.Join(ingest, "private_parallel_preparation.go")
    info, err := os.Lstat(workersFile)
    if err != nil { return err }
    if !info.Mode().IsRegular() {
        return fmt.Errorf("FI W512 WORKERS STOP: nonregular worker source %s", workersFile)
    }
    bytes, err := os.ReadFile(workersFile)
    if err != nil { return err }
    original := string(bytes)
    pattern := regexp.MustCompile(`(?m)^([ \t]*privateParallelAPreparers[ \t]*=[ \t]*)2([ \t]*)$`)
    matches := pattern.FindAllStringSubmatchIndex(original, -1)
    if len(matches) != 1 {
        return fmt.Errorf("FI W512 WORKERS STOP: exact worker-constant count=%d expected=1", len(matches))
    }
    m := matches[0]
    updated := original[:m[0]] + original[m[2]:m[3]] + w +
        original[m[4]:m[5]] + original[m[1]:]
    // Every anchor is validated first, before modifying ANY file.
    modified := map[string]string{workersFile: updated}
    for _, r := range replacements {
        if err := exact(modified, r); err != nil { return err }
    }
    for path, data := range modified {
        tmp := path + ".worker-sweep-new"
        if _, err := os.Lstat(tmp); !os.IsNotExist(err) {
            return fmt.Errorf("unexpected staging file collision %s: %v", tmp, err)
        }
        if err := os.WriteFile(tmp, []byte(data), 0600); err != nil { return err }
        if err := os.Rename(tmp, path); err != nil { return err }
    }
    fmt.Printf("FI W512 WORKER SWEEP PATCH PASS workers=%d inflight=%d "+
        "source_files=%d edits=%d original_seed_untouched=true "+
        "one_sql_writer=true sql_schema_unchanged=true K32_unchanged=true\n",
        workers, fixedCredits, len(modified), len(replacements)+1)
    return nil
}

func main() {
    if len(os.Args) != 3 {
        fmt.Fprintln(os.Stderr, "usage: worker-sweep <disposable-stage> <2|4|8|16>")
        os.Exit(2)
    }
    workers, err := strconv.Atoi(os.Args[2])
    if err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
    if err := run(os.Args[1], workers); err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
}
