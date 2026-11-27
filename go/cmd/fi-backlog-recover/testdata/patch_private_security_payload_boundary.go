// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// FI isolated and pinned Security payload boundary optimization.
// Never edits the checked-out Git worktree; accepts only the disposable H16
// replay's extracted source, after exact source anchors have matched.
package main

import (
    "fmt"
    "os"
    "path/filepath"
    "strings"
)

func main() {
    if len(os.Args) != 2 { panic("FI SECURITY BOUNDARY PATCH STOP: usage <disposable optimized-source>") }
    root:=os.Args[1]
    if !filepath.IsAbs(root) || !strings.Contains(root,"/fi-window-bench-") ||
        !strings.HasSuffix(root,"/optimized-source") {
        panic("FI SECURITY BOUNDARY PATCH STOP: forbidden source destination")
    }
    path:=filepath.Join(root,"go/internal/recordingest/security_single_pass_candidate.go")
    original,err:=os.ReadFile(path)
    if err!=nil {panic(err)}
    src:=string(original)
    oldCheck:=`if len(rawPayload) == 0 || !json.Valid(rawPayload) {
		return emptySource, emptySecurity, false, nil
	}`
    // The canonical scanner remains a shape check, not the JSON acceptance
    // authority. Valid full payload JSON is still strictly decoded once.
    newCheck:=`boundary := privateSingleJSONObjectBoundary(rawPayload)
	if len(rawPayload) == 0 || (!boundary && !json.Valid(rawPayload)) {
		return emptySource, emptySecurity, false, nil
	}`
    oldErr:=`if err := decodeStrictPayload(json.RawMessage(body), &parsed); err != nil {
		return emptySource, emptySecurity, true, fmt.Errorf("decode FI ingest source record: %w", err)
	}`
    newErr:=`if err := decodeStrictPayload(json.RawMessage(body), &parsed); err != nil {
		// Structural scanning intentionally does not validate JSON grammar.
		// If malformed payload JSON was admitted by the cheap boundary
		// scan, decline exactly as the original json.Valid gate did.
		if boundary && !json.Valid(rawPayload) {
			return emptySource, emptySecurity, false, nil
		}
		return emptySource, emptySecurity, true, fmt.Errorf("decode FI ingest source record: %w", err)
	}`
    for _,edit:=range [][2]string{{oldCheck,newCheck},{oldErr,newErr}} {
        if strings.Count(src,edit[0])!=1 {
            panic(fmt.Sprintf("FI SECURITY BOUNDARY PATCH STOP: anchor count=%d",strings.Count(src,edit[0])))
        }
        src=strings.Replace(src,edit[0],edit[1],1)
    }
    if err:=os.WriteFile(path,[]byte(src),0600);err!=nil {panic(err)}
    fmt.Println("FI SECURITY BOUNDARY PATCH PASS only_disposable_source=true strict_decoder=unchanged")
}
