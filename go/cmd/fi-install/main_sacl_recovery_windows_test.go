// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// Check the actual entrypoint, not a substitute mock: recovery must run only
// inside the apply branch and before first-run trust or discovery.
func TestMainSACLRecoveryPrecedesTrustAndDiscovery(t *testing.T) {
	fs := token.NewFileSet()
	f, err := parser.ParseFile(fs, "main_windows.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var mainBody *ast.BlockStmt
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == "main" {
			mainBody = fn.Body
			break
		}
	}
	if mainBody == nil {
		t.Fatal("main function not found")
	}
	names := map[string]token.Pos{}
	hasApplyGuard := false
	ast.Inspect(mainBody, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			x, ok := selector.X.(*ast.Ident)
			if ok && x.Name == "install" {
				switch selector.Sel.Name {
				case "RecoverPendingWindowsSACLTransactions", "FirstRunDevelopmentSigningTrust", "Discover":
					if _, exists := names[selector.Sel.Name]; !exists {
						names[selector.Sel.Name] = call.Pos()
					}
				}
			}
		}
		if stmt, ok := n.(*ast.IfStmt); ok {
			cond, isIdent := stmt.Cond.(*ast.Ident)
			if !isIdent || cond.Name != "doApply" {
				return true
			}
			ast.Inspect(stmt.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || selector.Sel.Name != "RecoverPendingWindowsSACLTransactions" {
					return true
				}
				x, ok := selector.X.(*ast.Ident)
				if ok && x.Name == "install" {
					hasApplyGuard = true
				}
				return true
			})
		}
		return true
	})
	recovery := names["RecoverPendingWindowsSACLTransactions"]
	trust := names["FirstRunDevelopmentSigningTrust"]
	discovery := names["Discover"]
	if !hasApplyGuard || !recovery.IsValid() || !trust.IsValid() || !discovery.IsValid() || !(recovery < trust && recovery < discovery) {
		t.Fatalf("SACL recovery must be apply-only and before trust/discovery: guarded=%t recovery=%v trust=%v discovery=%v", hasApplyGuard, recovery, trust, discovery)
	}
}
