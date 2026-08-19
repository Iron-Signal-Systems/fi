// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
)

func main() {
	collectPath := flag.Bool("collect-path", false, "show complete NTFS collection")
	identity := flag.Bool("identity", false, "show NTFS identity")
	metadata := flag.Bool("metadata", false, "show NTFS metadata")
	ads := flag.Bool("ads", false, "show streams and ADS")

	flag.Parse()

	modeCount := 0
	for _, selected := range []bool{*collectPath, *identity, *metadata, *ads} {
		if selected {
			modeCount++
		}
	}

	if modeCount != 1 || flag.NArg() != 2 {
		fmt.Println("usage:")
		fmt.Println(`  fi.exe -collect-path <governed-root> <target>`)
		fmt.Println(`  fi.exe -identity     <governed-root> <target>`)
		fmt.Println(`  fi.exe -metadata     <governed-root> <target>`)
		fmt.Println(`  fi.exe -ads          <governed-root> <target>`)
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
