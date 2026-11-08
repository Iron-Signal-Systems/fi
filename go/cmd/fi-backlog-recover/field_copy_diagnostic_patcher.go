//go:build ignore

// Private experiment-only source instrumenter. It patches a disposable git
// archive, not an active FI worktree or the authoritative ingestion binary.
// Every edit is guarded by an exact anchor and count to fail closed on drift.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func replaceOne(source, from, to, file string) string {
	n := strings.Count(source, from)
	if n != 1 {
		panic(fmt.Sprintf("%s: diagnostic anchor count=%d, expected=1: %q", file, n, from))
	}
	return strings.Replace(source, from, to, 1)
}

func replaceOrdered(source, from string, replacements []string, file string) string {
	parts := strings.Split(source, from)
	if len(parts) != len(replacements)+1 {
		panic(fmt.Sprintf("%s: expected %d flush calls, found %d", file, len(replacements), len(parts)-1))
	}
	var b strings.Builder
	b.WriteString(parts[0])
	for i, r := range replacements {
		b.WriteString(r)
		b.WriteString(parts[i+1])
	}
	return b.String()
}

func patch(root, filename string, transform func(string) string) error {
	path := filepath.Join(root, "internal", "recordingest", filename)
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	before := string(raw)
	after := transform(before)
	if before == after {
		return fmt.Errorf("%s: diagnostic patch unexpectedly made no changes", path)
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	return os.WriteFile(path, []byte(after), info.Mode().Perm())
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go run field_copy_diagnostic_patcher.go /disposable/archive/go")
		os.Exit(2)
	}
	root := os.Args[1]
	if err := patch(root, "security_bulk.go", func(s string) string {
		s = replaceOne(s, "type securityBulkTimingCounters struct {",
			"type fiFieldCopyDiagWindowKey struct{}\n"+
				"type fiFieldCopyDiagReasonKey struct{}\n\n"+
				"type securityBulkTimingCounters struct {", "security_bulk.go")
		return replaceOne(s,
			"\t\telapsedFieldCopy := time.Since(fieldCopyStarted)\n",
			"\t\telapsedFieldCopy := time.Since(fieldCopyStarted)\n"+
				"\t\t// Diagnostic runs only: called after CopyFrom, outside its timer.\n"+
				"\t\tfmt.Printf(\"FI FIELD COPY TRACE window=%v reason=%v source_batch=%d events=%d rows=%d input_bytes=%d elapsed_ns=%d\\n\",\n"+
				"\t\t\tctx.Value(fiFieldCopyDiagWindowKey{}), ctx.Value(fiFieldCopyDiagReasonKey{}),\n"+
				"\t\t\tsourceBatchID, len(pending), chunk.rows, chunk.bytes, elapsedFieldCopy.Nanoseconds())\n",
			"security_bulk.go")
	}); err != nil {
		panic(err)
	}
	if err := patch(root, "postgres_ingest.go", func(s string) string {
		s = replaceOne(s, "flushSecurity := func() error {",
			"flushSecurity := func(reason string) error {", "postgres_ingest.go")
		s = replaceOne(s,
			"if err := copySecurityBulk(ctx, tx, sourceBatchID, pendingSecurity, profile); err != nil {",
			"if err := copySecurityBulk(context.WithValue(ctx, fiFieldCopyDiagReasonKey{}, reason), tx, sourceBatchID, pendingSecurity, profile); err != nil {",
			"postgres_ingest.go")
		return replaceOrdered(s, "flushSecurity()", []string{
			"flushSecurity(\"buffer_limit\")",
			"flushSecurity(\"kind_change\")",
			"flushSecurity(\"chunk_end\")",
		}, "postgres_ingest.go")
	}); err != nil {
		panic(err)
	}
	if err := patch(root, "backlog_typed_window_postgres.go", func(s string) string {
		return replaceOne(s,
			"\tsetupElapsed := time.Since(windowStarted)\n",
			"\tsetupElapsed := time.Since(windowStarted)\n"+
				"\t// Experimental trace label is scoped to this one private W128 window.\n"+
				"\tctx = context.WithValue(ctx, fiFieldCopyDiagWindowKey{}, index)\n",
			"backlog_typed_window_postgres.go")
	}); err != nil {
		panic(err)
	}
	fmt.Println("FI FIELD COPY DIAG PATCH PASS: exact anchors, private archive only")
}
