// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Temporary FI collector work-directory diagnostic.
//
//go:build windows

package main

import (
	"fmt"
	"os"

	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
)

func main() {
	spoolDir, err :=
		spool.DefaultDir()

	if err != nil {
		fail(err)
	}

	workDir, err :=
		spool.CollectorWorkDir(
			spoolDir,
		)

	if err != nil {
		fail(err)
	}

	fmt.Printf(
		"ConfiguredSpool: %s\n",
		spoolDir,
	)

	fmt.Printf(
		"CollectorWork:  %s\n",
		workDir,
	)
}

func fail(err error) {
	fmt.Fprintf(
		os.Stderr,
		"ERROR: %v\n",
		err,
	)

	os.Exit(1)
}
