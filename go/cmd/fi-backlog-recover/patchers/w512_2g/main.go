// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// DEV ONLY: exact-anchor W512/2GiB profile patch for a disposable,
 // historical H16 Candidate A archive. Never run on a checkout.
package main

import (
    "errors"
    "fmt"
    "os"
    "path/filepath"
    "strings"
)

type change struct { path, before, after string; count int }

var changes = []change{
    {"go/cmd/fi-backlog-recover/main_freebsd.go", "case \"W128\":\n\t\treturn recordingest.BacklogWindowLimits{MaxRecords: 131072, MaxDataBytes: 1 << 30}, nil", "case \"W128\":\n\t\treturn recordingest.BacklogWindowLimits{MaxRecords: 131072, MaxDataBytes: 1 << 30}, nil\n\tcase \"W512\":\n\t\treturn recordingest.BacklogWindowLimits{MaxRecords: 524288, MaxDataBytes: 2 << 30}, nil", 1},
    {"go/cmd/fi-backlog-recover/main_freebsd.go", "window-profile must be W32, W64, W96, or W128", "window-profile must be W32, W64, W96, W128, or W512", 1},
    {"go/cmd/fi-backlog-recover/main_freebsd.go", "var deferredVerifiedClone bool", "var deferredVerifiedClone bool\n\tvar privateW512TwoGiB bool\n\tvar privateW512VerifiedCacheSeed bool", 1},
    {"go/cmd/fi-backlog-recover/main_freebsd.go", "flag.BoolVar(&deferredVerifiedClone, \"deferred-verified-clone\", false,", "flag.BoolVar(&privateW512TwoGiB, \"private-w512-2g\", false, \"DEV ONLY: isolated W512/2GiB fresh signed checkpoint chain\")\n\tflag.BoolVar(&privateW512VerifiedCacheSeed, \"private-w512-verified-cache-seed\", false, \"DEV ONLY: use prior receiver-admitted cache for fresh W512 first-window seed\")\n\tflag.BoolVar(&deferredVerifiedClone, \"deferred-verified-clone\", false,", 1},
    {"go/cmd/fi-backlog-recover/main_freebsd.go", "flag.Parse()\n\tif optimizedK32 {", "flag.Parse()\n\tif (windowProfile == \"W512\") != privateW512TwoGiB ||\n\t\t(privateW512VerifiedCacheSeed && !privateW512TwoGiB) {\n\t\treturn errors.New(\"FI W512: explicit W512 profile and isolated selector are required\")\n\t}\n\tif privateW512TwoGiB {\n\t\tif !enable || indexedPrivate || preflightOnly || optimizedK32 ||\n\t\t\t!((streamLoader && !continuousPrivate && startWindow == 0 && maxWindows == 1 &&\n\t\t\t\t!privateFieldPartitions && !privateMixedBuffers && !privateDependencyBuffers && !privateParallelA &&\n\t\t\t\t!deferredVerifiedClone && !privateHashH16 && processingChunkRecords == 0 &&\n\t\t\t\tprivateW512VerifiedCacheSeed && verifiedCacheRoot != \"\") ||\n\t\t\t  (continuousPrivate && !streamLoader && startWindow == 1 && maxWindows == 0 &&\n\t\t\t\tprivateFieldPartitions && privateMixedBuffers && privateDependencyBuffers && privateParallelA &&\n\t\t\t\tdeferredVerifiedClone && privateHashH16 && processingChunkRecords == 32768 &&\n\t\t\t\t!privateW512VerifiedCacheSeed && verifiedCacheRoot != \"\")) {\n\t\t\treturn errors.New(\"FI W512: exact receiver-admitted-cache seed or two-worker private verified-cache resume required\")\n\t\t}\n\t}\n\tif optimizedK32 {", 1},
    {"go/cmd/fi-backlog-recover/main_freebsd.go", "if windowProfile != \"W128\" || !enable ||", "if (windowProfile != \"W128\" && windowProfile != \"W512\") || !enable ||", 1},
    {"go/cmd/fi-backlog-recover/main_freebsd.go", "if windowProfile != \"W128\" || !continuousPrivate {", "if (windowProfile != \"W128\" && windowProfile != \"W512\") || !continuousPrivate {", 1},
    {"go/cmd/fi-backlog-recover/main_freebsd.go", "if privateFieldPartitions && (!continuousPrivate || !enable || windowProfile != \"W128\" ||", "if privateFieldPartitions && (!continuousPrivate || !enable ||\n\t\t(windowProfile != \"W128\" && windowProfile != \"W512\") ||", 1},
    {"go/cmd/fi-backlog-recover/main_freebsd.go", "windowProfile != \"W128\" || processingChunkRecords != 32768 ||", "(windowProfile != \"W128\" && windowProfile != \"W512\") || processingChunkRecords != 32768 ||", 3},
    {"go/cmd/fi-backlog-recover/main_freebsd.go", "verifiedCacheRoot == \"\" || startWindow != 3 || maxWindows != 0 ||", "verifiedCacheRoot == \"\" ||\n\t\t((windowProfile == \"W128\" && startWindow != 3) ||\n\t\t (windowProfile == \"W512\" && startWindow != 1)) || maxWindows != 0 ||", 2},
    {"go/cmd/fi-backlog-recover/main_freebsd.go", "startWindow != 3 || maxWindows != 0 || indexedPrivate ||", "((windowProfile == \"W128\" && startWindow != 3) ||\n\t\t (windowProfile == \"W512\" && startWindow != 1)) || maxWindows != 0 || indexedPrivate ||", 1},
    {"go/cmd/fi-backlog-recover/main_freebsd.go", "windowProfile != \"W128\" || verifiedCacheRoot == \"\" || processingChunkRecords != 32768)) ||", "(windowProfile != \"W128\" && windowProfile != \"W512\") || verifiedCacheRoot == \"\" || processingChunkRecords != 32768)) ||", 1},
    {"go/cmd/fi-backlog-recover/main_freebsd.go", "fmt.Println(\"FI PRIVATE PARALLEL PREP A ENABLED workers=2 inflight=4 postgres_writers=1 W128_atomic=true\")", "fmt.Printf(\"FI PRIVATE PARALLEL PREP A ENABLED workers=2 inflight=4 postgres_writers=1 source_window=%s atomic=true\\n\", windowProfile)", 1},
    {"go/internal/recordingest/backlog_continuous_private.go", "if limits.MaxRecords == 0 || limits.MaxDataBytes == 0 || limits.MaxDataBytes > 1<<30 {", "if limits.MaxRecords == 0 || limits.MaxDataBytes == 0 ||\n\t\t(limits.MaxDataBytes > 1<<30 && !(limits.MaxRecords == 524288 && limits.MaxDataBytes == 2<<30)) {", 1},
    {"go/cmd/fi-backlog-recover/main_freebsd.go", "} else if streamLoader {", "} else if privateW512VerifiedCacheSeed {\n\t\tfmt.Printf(\"FI W512 HISTORICAL RECEIVER-ADMITTED CACHE SEED source=%s generation=%s root=%s no_repeat_crl_admission=true\\n\",\n\t\t\tsource, generation, verifiedCacheRoot)\n\t\tprepared, err = recordingest.LoadPrivateW512FirstWindowFromAdmittedCache(\n\t\t\tctx, loadConfig, generation, verifiedCacheRoot, limits)\n\t} else if streamLoader {", 1},
    {"go/internal/recordingest/backlog_stream_load.go", "limits.MaxDataBytes > 1<<30 || limits.MaxDataBytes > math.MaxInt64-1 {", "(limits.MaxDataBytes > 1<<30 && !(limits.MaxRecords == 524288 && limits.MaxDataBytes == 2<<30)) || limits.MaxDataBytes > math.MaxInt64-1 {", 1},
}

func run(root string) error {
    root = filepath.Clean(root)
    if !strings.HasPrefix(root, "/home/jwood/fi-window-bench-") ||
        !strings.HasSuffix(root, "/optimized-source") ||
        strings.Contains(root, "..") {
        return errors.New("W512 overlay only accepts an isolated /home/jwood/fi-window-bench-*/optimized-source")
    }
    info, err := os.Lstat(root)
    if err != nil { return err }
    if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
        return errors.New("W512 overlay source must be a real directory")
    }
    content := make(map[string][]byte)
    permissions := make(map[string]os.FileMode)
    for _, ch := range changes {
        if _, ok := content[ch.path]; ok { continue }
        p := filepath.Join(root,ch.path)
        st, err := os.Lstat(p)
        if err != nil { return err }
        if !st.Mode().IsRegular() { return fmt.Errorf("W512 overlay rejected nonregular source %s",ch.path) }
        b, err := os.ReadFile(p)
        if err != nil { return err }
        content[ch.path]=b
        permissions[ch.path]=st.Mode().Perm()
    }
    for _, ch := range changes {
        s:=string(content[ch.path])
        if n:=strings.Count(s,ch.before); n!=ch.count {
            return fmt.Errorf("W512 overlay exact-anchor failure %s expected=%d got=%d at %q",ch.path,ch.count,n,ch.before)
        }
        content[ch.path]=[]byte(strings.ReplaceAll(s,ch.before,ch.after))
    }
    for p, b := range content {
        dst:=filepath.Join(root,p)
        tmp:=dst+".w512-candidate.tmp"
        if _,err:=os.Lstat(tmp); !os.IsNotExist(err) { return fmt.Errorf("W512 temporary path already exists %s: %v",tmp,err) }
        if err:=os.WriteFile(tmp,b,permissions[p]); err!=nil{return err}
        if err:=os.Rename(tmp,dst); err!=nil { return err }
    }
    fmt.Printf("FI W512 2G SOURCE OVERLAY PASS files=%d edits=%d private_only=true outer_records=524288 outer_bytes=2147483648 K32_unchanged=true\n",len(content),len(changes))
    return nil
}

func main() {
    if len(os.Args)!=2 { fmt.Fprintln(os.Stderr,"FI W512 SOURCE STOP: provide one isolated source root"); os.Exit(2) }
    if err:=run(os.Args[1]);err!=nil {fmt.Fprintln(os.Stderr,"FI W512 SOURCE STOP:",err);os.Exit(1)}
}
