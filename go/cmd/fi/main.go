// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
)

type walkOutput struct {
	Path        string            `json:"path"`
	Observation *ntfs.Observation `json:"observation,omitempty"`
	Error       string            `json:"error,omitempty"`
}

func main() {
	collectPath := flag.Bool("collect-path", false, "show complete NTFS collection")
	walkRoot := flag.Bool("walk-root", false, "recursively collect a governed NTFS root")
	identity := flag.Bool("identity", false, "show NTFS identity")
	metadata := flag.Bool("metadata", false, "show NTFS metadata")
	ads := flag.Bool("ads", false, "show streams and ADS")

	flag.Parse()

	modeCount := 0
	for _, selected := range []bool{
		*collectPath,
		*walkRoot,
		*identity,
		*metadata,
		*ads,
	} {
		if selected {
			modeCount++
		}
	}

	if modeCount != 1 {
		printUsage()
		os.Exit(2)
	}

	if *walkRoot {
		if flag.NArg() != 1 {
			printUsage()
			os.Exit(2)
		}

		runWalk(flag.Arg(0))
		return
	}

	if flag.NArg() != 2 {
		printUsage()
		os.Exit(2)
	}

	observation, err := ntfs.CollectPath(
		context.Background(),
		"manual-test",
		flag.Arg(0),
		flag.Arg(1),
	)
	if err != nil {
		fmt.Println("ERROR:", err)
		os.Exit(1)
	}

	var output any

	switch {
	case *collectPath:
		output = observation

	case *identity:
		output = struct {
			Volume any `json:"volume_identity"`
			Object any `json:"object_identity"`
			Path   any `json:"path_binding"`
		}{
			observation.VolumeIdentity,
			observation.ObjectIdentity,
			observation.PathBinding,
		}

	case *metadata:
		output = observation.Metadata

	case *ads:
		output = observation.StreamInventory
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(output); err != nil {
		fmt.Println("ERROR:", err)
		os.Exit(1)
	}
}

func runWalk(governedRoot string) {
	// Walk output is intentionally JSON Lines: one discovered filesystem object
	// per line. Large governed roots therefore do not require FI to construct or
	// retain one enormous JSON array in memory.
	encoder := json.NewEncoder(os.Stdout)

	err := ntfs.WalkGovernedRoot(
		context.Background(),
		"manual-test",
		governedRoot,
		func(
			path string,
			observation ntfs.Observation,
			collectErr error,
		) error {
			if collectErr != nil {
				return encoder.Encode(walkOutput{
					Path:  path,
					Error: collectErr.Error(),
				})
			}

			return encoder.Encode(walkOutput{
				Path:        path,
				Observation: &observation,
			})
		},
	)
	if err != nil {
		fmt.Println("ERROR:", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("usage:")
	fmt.Println(`  fi.exe -collect-path <governed-root> <target>`)
	fmt.Println(`  fi.exe -walk-root    <governed-root>`)
	fmt.Println(`  fi.exe -identity     <governed-root> <target>`)
	fmt.Println(`  fi.exe -metadata     <governed-root> <target>`)
	fmt.Println(`  fi.exe -ads          <governed-root> <target>`)
}
