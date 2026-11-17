// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// AST-anchored, private-clone-only Candidate A bridge for P7 five-SQL writers.
// The seven existing H16 activation predicates are all required and unchanged.
package main

import (
    "bytes"
    "errors"
    "fmt"
    "go/ast"
    "go/format"
    "go/parser"
    "go/token"
    "os"
    "path/filepath"
    "strings"
)

func main() {
    if len(os.Args) != 2 { stop(errors.New("expected one disposable source root")) }
    root := filepath.Clean(os.Args[1])
    if !filepath.IsAbs(root) || !strings.HasSuffix(root, "/optimized-source") ||
        !(strings.HasPrefix(root, "/home/jwood/fi-window-bench-w512-family-p3-") ||
          strings.HasPrefix(root, "/home/jwood/fi-p7-five-writer-go-tests-")) {
        stop(errors.New("outside the P7 disposable source namespaces"))
    }
    path := filepath.Join(root, "go/internal/recordingest/private_parallel_preparation.go")
    p7 := filepath.Join(root, "go/internal/recordingest/private_p7_typed_window.go")
    st, err := os.Lstat(path)
    if err != nil || !st.Mode().IsRegular() { stop(fmt.Errorf("expected regular private preparer: %v", err)) }
    p7st, err := os.Lstat(p7)
    if err != nil || !p7st.Mode().IsRegular() { stop(errors.New("P7 source overlay missing")) }
    p7bytes, err := os.ReadFile(p7)
    if err != nil || !strings.Contains(string(p7bytes), "func privateP7ParallelPreparationReader(") {
        stop(errors.New("P7 reader ownership gate unavailable"))
    }
    original, err := os.ReadFile(path)
    if err != nil { stop(err) }
    next, err := bridgeCandidateA(original)
    if err != nil { stop(err) }
    tmp := path + ".p7-bridge-tmp"
    if _, err := os.Lstat(tmp); !errors.Is(err, os.ErrNotExist) {
        stop(errors.New("P7 patch destination already exists"))
    }
    if err := os.WriteFile(tmp, next, st.Mode().Perm()); err != nil { stop(err) }
    if err := os.Rename(tmp, path); err != nil { os.Remove(tmp); stop(err) }
    fmt.Println("FI P7 PREPARER BRIDGE PATCH PASS legacy_k32_unchanged=true private_p7_guard=required original_h16_profile=required")
}

// bridgeCandidateA replaces one call site, never the historical test's
// activation logic or any other preparation/SQL code. Go's parser owns
// whitespace matching; the original source is preserved byte-for-byte
// except for this precise call expression.
func bridgeCandidateA(original []byte) ([]byte, error) {
    fs := token.NewFileSet()
    file, err := parser.ParseFile(fs, "private_parallel_preparation.go", original, parser.AllErrors)
    if err != nil { return nil, fmt.Errorf("Candidate A source syntax: %w", err) }
    var predicate *ast.FuncDecl
    for _, d := range file.Decls {
        fn, ok := d.(*ast.FuncDecl)
        if !ok || fn.Name.Name != "privateParallelAEnabled" { continue }
        if predicate != nil { return nil, errors.New("duplicate Candidate A activation function") }
        predicate = fn
    }
    if predicate == nil || predicate.Recv != nil || predicate.Body == nil ||
        len(predicate.Body.List) != 1 {
        return nil, errors.New("Candidate A activation function structure changed")
    }
    ret, ok := predicate.Body.List[0].(*ast.ReturnStmt)
    if !ok || len(ret.Results) != 1 { return nil, errors.New("Candidate A return structure changed") }
    var terms []ast.Expr
    flattenAnd(ret.Results[0], &terms)
    required := map[string]bool{
        "privateParallelARequested(ctx)": false,
        "privateDependencyBuffersEnabled(ctx)": false,
        "usePrivateSinglePassSecurity(ctx)": false,
        "joinedBacklogChunkRecords(ctx)==32768": false,
        "privateH16CombinedFileProfileValid(ctx)": false,
        "fileBulkLimitsFromContext(ctx).Name==\"F3H16\"": false,
        "securityBulkLimitsFromContext(ctx).Name==\"P3\"": false,
    }
    var selected ast.Expr
    for _, term := range terms {
        var b bytes.Buffer
        if err := format.Node(&b, fs, term); err != nil { return nil, err }
        normalized := strings.Join(strings.Fields(b.String()), "")
        used, known := required[normalized]
        if !known || used { return nil, fmt.Errorf("Candidate A unexpected or duplicate conjunct %q", normalized) }
        required[normalized] = true
        if normalized == "privateDependencyBuffersEnabled(ctx)" { selected = term }
    }
    if len(terms) != len(required) || selected == nil {
        return nil, errors.New("Candidate A seven required activation gates not present")
    }
    for gate, matched := range required {
        if !matched { return nil, fmt.Errorf("Candidate A activation gate changed: %s", gate) }
    }
    start := fs.Position(selected.Pos()).Offset
    end := fs.Position(selected.End()).Offset
    if start < 0 || end <= start || end > len(original) ||
        string(original[start:end]) != "privateDependencyBuffersEnabled(ctx)" {
        return nil, errors.New("Candidate A AST ownership token mismatch")
    }
    const bridge = "(privateDependencyBuffersEnabled(ctx) || privateP7ParallelPreparationReader(ctx))"
    next := make([]byte, 0, len(original)+len(bridge))
    next = append(next, original[:start]...)
    next = append(next, bridge...)
    next = append(next, original[end:]...)
    if _, err := parser.ParseFile(token.NewFileSet(), "patched_private_parallel_preparation.go", next, parser.AllErrors); err != nil {
        return nil, fmt.Errorf("patched Candidate A syntax: %w", err)
    }
    return next, nil
}

func flattenAnd(e ast.Expr, out *[]ast.Expr) {
    if paren, ok := e.(*ast.ParenExpr); ok { flattenAnd(paren.X, out); return }
    if b, ok := e.(*ast.BinaryExpr); ok && b.Op == token.LAND {
        flattenAnd(b.X, out)
        flattenAnd(b.Y, out)
        return
    }
    *out = append(*out, e)
}

func stop(err error) {
    fmt.Fprintln(os.Stderr, "FI P7 PREPARER BRIDGE STOP:", err)
    os.Exit(1)
}
