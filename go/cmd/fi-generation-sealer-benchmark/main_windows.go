// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Temporary FI generation-sealer benchmark.
//
//go:build windows

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Iron-Signal-Systems/fi/go/internal/generationsealer"
)

func main() {
	var (
		frozenDir  string
		generation string
		readMiB    uint64
		sealedDir  string
	)

	flag.StringVar(
		&frozenDir,
		"frozen-dir",
		"",
		"existing frozen FI generation directory",
	)

	flag.StringVar(
		&generation,
		"generation-id",
		"",
		"generation identity; defaults from frozen directory name",
	)

	flag.Uint64Var(
		&readMiB,
		"max-read-mib-sec",
		0,
		"optional source read ceiling in MiB/sec; 0 disables pacing",
	)

	flag.StringVar(
		&sealedDir,
		"sealed-dir",
		"",
		"directory for the sealed generation",
	)

	flag.Parse()

	if frozenDir == "" ||
		sealedDir == "" {
		fail(
			fmt.Errorf(
				"frozen-dir and sealed-dir are required",
			),
		)
	}

	if generation == "" {
		base :=
			filepath.Base(
				filepath.Clean(
					frozenDir,
				),
			)

		if !strings.HasPrefix(
			base,
			"generation-",
		) {
			fail(
				fmt.Errorf(
					"generation-id is required when frozen directory does not begin with generation-",
				),
			)
		}

		generation =
			strings.TrimPrefix(
				base,
				"generation-",
			)
	}

	maxReadBytes :=
		readMiB *
			1024 *
			1024

	fmt.Printf(
		"GenerationID:     %s\n",
		generation,
	)

	fmt.Printf(
		"FrozenDir:        %s\n",
		frozenDir,
	)

	fmt.Printf(
		"SealedDir:        %s\n",
		sealedDir,
	)

	fmt.Printf(
		"ReadCeilingMiB/s: %d\n",
		readMiB,
	)

	result, err :=
		generationsealer.Seal(
			context.Background(),
			generationsealer.Config{
				FrozenDir: frozenDir,

				GenerationID: generation,

				MaxReadBytesPerSecond: maxReadBytes,

				SealedDir: sealedDir,
			},
		)

	if err != nil {
		fail(err)
	}

	fmt.Printf(
		"Files:            %d\n",
		result.FileCount,
	)

	fmt.Printf(
		"SourceBytes:      %d\n",
		result.SourceBytes,
	)

	fmt.Printf(
		"CanonicalBytes:   %d\n",
		result.CanonicalBytes,
	)

	fmt.Printf(
		"CanonicalSHA256:  %s\n",
		result.CanonicalSHA256,
	)

	fmt.Printf(
		"EncodedBytes:     %d\n",
		result.EncodedBytes,
	)

	fmt.Printf(
		"EncodedSHA256:    %s\n",
		result.EncodedSHA256,
	)

	fmt.Printf(
		"SealedPath:       %s\n",
		result.SealedPath,
	)

	fmt.Printf(
		"Elapsed:          %s\n",
		result.Elapsed,
	)

	fmt.Println(
		"PASS: generation sealed without per-batch validation",
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
