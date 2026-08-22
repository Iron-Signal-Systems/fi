// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"syscall"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/process"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/smb"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/usn"
)

type walkOutput struct {
	Error                string            `json:"error,omitempty"`
	Observation          *ntfs.Observation `json:"observation,omitempty"`
	PathDisplay          string            `json:"path_display"`
	PathUTF16LEBase64URL string            `json:"path_utf16le_base64url"`
}

func main() {
	collectPath := flag.Bool("collect-path", false, "show complete NTFS collection")
	collectID := flag.Bool("collect-id", false, "show complete NTFS collection by NTFS object identity")
	walkRoot := flag.Bool("walk-root", false, "recursively collect a governed NTFS root")
	perfRoot := flag.Bool("perf-root", false, "measure FI collection on a governed NTFS root")
	identity := flag.Bool("identity", false, "show NTFS identity")
	metadata := flag.Bool("metadata", false, "show NTFS metadata")
	ads := flag.Bool("ads", false, "show streams and ADS")
	shares := flag.Bool("shares", false, "show local SMB share state and share security")
	collectorIdentity := flag.Bool("collector-identity", false, "show FI process identity and token facts")
	baselineRoot := flag.Bool("baseline-root", false, "collect FI process identity, local SMB shares, and one governed NTFS root")
	usnStateMode := flag.Bool("usn-state", false, "show current NTFS USN journal state for the governed-root volume")
	usnReadMode := flag.Bool("usn-read", false, "read one bounded NTFS USN journal batch from a starting USN")
	usnReobserveMode := flag.Bool("usn-reobserve", false, "read one bounded USN batch and freshly observe each distinct changed object by NTFS file ID")

	flag.Parse()

	modeCount := 0
	for _, selected := range []bool{
		*collectPath,
		*collectID,
		*walkRoot,
		*perfRoot,
		*identity,
		*metadata,
		*ads,
		*shares,
		*collectorIdentity,
		*baselineRoot,
		*usnStateMode,
		*usnReadMode,
		*usnReobserveMode,
	} {
		if selected {
			modeCount++
		}
	}

	if modeCount != 1 {
		printUsage()
		os.Exit(2)
	}

	switch {
	case *usnReobserveMode:
		if flag.NArg() != 2 {
			printUsage()
			os.Exit(2)
		}
		batch, err := usn.ReadAndReobserve(context.Background(), "manual-test", flag.Arg(0), flag.Arg(1))
		if err != nil {
			fmt.Fprintln(os.Stderr, "ERROR:", err)
			os.Exit(1)
		}
		writeIndentedJSON(batch)
		return

	case *usnStateMode:
		if flag.NArg() != 1 {
			printUsage()
			os.Exit(2)
		}
		state, err := usn.QueryJournal(context.Background(), "manual-test", flag.Arg(0))
		if err != nil {
			fmt.Fprintln(os.Stderr, "ERROR:", err)
			os.Exit(1)
		}
		writeIndentedJSON(state)
		return

	case *usnReadMode:
		if flag.NArg() != 2 {
			printUsage()
			os.Exit(2)
		}
		batch, err := usn.ReadJournal(context.Background(), "manual-test", flag.Arg(0), flag.Arg(1))
		if err != nil {
			fmt.Fprintln(os.Stderr, "ERROR:", err)
			os.Exit(1)
		}
		writeIndentedJSON(batch)
		return

	case *baselineRoot:
		if flag.NArg() != 1 {
			printUsage()
			os.Exit(2)
		}
		runBaselineRoot(flag.Arg(0))
		return

	case *collectorIdentity:
		if flag.NArg() != 0 {
			printUsage()
			os.Exit(2)
		}
		runCollectorIdentity()
		return

	case *shares:
		if flag.NArg() != 0 {
			printUsage()
			os.Exit(2)
		}
		runShares()
		return

	case *walkRoot:
		if flag.NArg() != 1 {
			printUsage()
			os.Exit(2)
		}
		runWalk(flag.Arg(0))
		return

	case *perfRoot:
		if flag.NArg() != 1 {
			printUsage()
			os.Exit(2)
		}
		runPerformance(flag.Arg(0))
		return

	case *collectID:
		if flag.NArg() != 3 {
			printUsage()
			os.Exit(2)
		}
		observation, err := ntfs.CollectFileReference(
			context.Background(),
			"manual-test",
			flag.Arg(0),
			records.NTFSObjectIdentity{
				MethodVersion:       ntfs.IdentityMethodVersion,
				FileReferenceNumber: flag.Arg(1),
				SequenceNumber:      flag.Arg(2),
			},
		)
		if err != nil {
			fmt.Fprintln(os.Stderr, "ERROR:", err)
			os.Exit(1)
		}
		writeIndentedJSON(observation)
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
		fmt.Fprintln(os.Stderr, "ERROR:", err)
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

	writeIndentedJSON(output)
}

func writeIndentedJSON(value any) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
}

func pathUTF16LEBase64URL(path string) (string, error) {
	units, err := syscall.UTF16FromString(path)
	if err != nil {
		return "", err
	}
	units = units[:len(units)-1]

	encoded := make([]byte, len(units)*2)
	for index, unit := range units {
		binary.LittleEndian.PutUint16(encoded[index*2:], unit)
	}
	return base64.RawURLEncoding.EncodeToString(encoded), nil
}

func printUsage() {
	fmt.Println("usage:")
	fmt.Println(`  fi.exe -collect-path       <governed-root> <target>`)
	fmt.Println(`  fi.exe -collect-id         <governed-root> <file-reference-number> <sequence-number>`)
	fmt.Println(`  fi.exe -walk-root          <governed-root>`)
	fmt.Println(`  fi.exe -perf-root          <governed-root>`)
	fmt.Println(`  fi.exe -identity           <governed-root> <target>`)
	fmt.Println(`  fi.exe -metadata           <governed-root> <target>`)
	fmt.Println(`  fi.exe -ads                <governed-root> <target>`)
	fmt.Println(`  fi.exe -shares`)
	fmt.Println(`  fi.exe -collector-identity`)
	fmt.Println(`  fi.exe -baseline-root      <governed-root>`)
	fmt.Println(`  fi.exe -usn-state          <governed-root>`)
	fmt.Println(`  fi.exe -usn-read           <governed-root> <start-usn>`)
	fmt.Println(`  fi.exe -usn-reobserve      <governed-root> <start-usn>`)
}

func runWalk(governedRoot string) {
	// Walk output is JSON Lines. PathDisplay is human convenience only. The exact
	// Windows path is PathUTF16LEBase64URL and is losslessly reconstructed from
	// the Go Windows WTF-8 string before JSON encoding.
	encoder := json.NewEncoder(os.Stdout)

	err := ntfs.WalkGovernedRoot(
		context.Background(),
		"manual-test",
		governedRoot,
		func(
			path string,
			observation ntfs.Observation,
			objectErr error,
		) error {
			exactPath, err := pathUTF16LEBase64URL(path)
			if err != nil {
				return err
			}

			output := walkOutput{
				PathDisplay:          path,
				PathUTF16LEBase64URL: exactPath,
			}
			if observation.ObservedAt != "" {
				output.Observation = &observation
			}
			if objectErr != nil {
				output.Error = objectErr.Error()
			}
			return encoder.Encode(output)
		},
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
}

func runShares() {
	snapshot, err := smb.CollectLocalShares(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}

	writeIndentedJSON(snapshot)
}

func runCollectorIdentity() {
	observation, err := process.CurrentIdentity()
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}

	writeIndentedJSON(observation)
}
