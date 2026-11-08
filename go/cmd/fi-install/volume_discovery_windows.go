// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/windows/volumediscovery"
)

const volumeDiscoveryReportVersion = "fi-volume-discovery/1"

// volumeInventoryCLI validates that the stand-alone inventory operation cannot
// be combined with installer flags that ask for planning or mutation. The
// default value of -apply is true in the existing installer; -list-volumes is
// intercepted *before* that behavior, but an explicitly supplied -apply flag
// is rejected to prevent an ambiguous administrator request.
func volumeInventoryCLI(flags *flag.FlagSet) error {
	if flags == nil {
		return errors.New("installer flag set is required")
	}
	var conflicting []string
	flags.Visit(func(item *flag.Flag) {
		if item.Name != "list-volumes" {
			conflicting = append(conflicting, "-"+item.Name)
		}
	})
	if flags.NArg() > 0 {
		return fmt.Errorf("-list-volumes does not accept positional arguments")
	}
	if len(conflicting) > 0 {
		sort.Strings(conflicting)
		return fmt.Errorf("-list-volumes is a stand-alone read-only action; conflicting flags: %v", conflicting)
	}
	return nil
}

type volumeInventoryReport struct {
	Version              string                        `json:"version"`
	ObservedAtUTC        string                        `json:"observed_at_utc"`
	Action               string                        `json:"action"`
	CollectionAuthorized bool                          `json:"collection_authorized"`
	Volumes              []volumediscovery.Snapshot    `json:"volumes"`
}

// writeVolumeInventory is intentionally injected with a native enumerator for
// deterministic failure-path tests. It performs no installer preflight,
// config load, AD/PKI access, service management, approval or USN read.
// Publishing a report does not authorize collection on any volume.
func writeVolumeInventory(
	ctx context.Context,
	output io.Writer,
	discover func(context.Context) ([]volumediscovery.Snapshot, error),
	clock func() time.Time,
) error {
	if ctx == nil || output == nil || discover == nil || clock == nil {
		return errors.New("volume inventory requires context, writer, discovery source and clock")
	}
	volumes, err := discover(ctx)
	if err != nil {
		return fmt.Errorf("read-only Windows volume discovery failed: %w", err)
	}
	if len(volumes) == 0 {
		return errors.New("read-only Windows volume discovery returned no volumes")
	}
	// A successful discovery contains only read-only observations. The
	// enrollment approval, native rediscovery and policy checks are still
	// separately required. Do not infer that Status=Eligible means approved.
	report := volumeInventoryReport{
		Version:              volumeDiscoveryReportVersion,
		ObservedAtUTC:        clock().UTC().Format(time.RFC3339Nano),
		Action:               "DiscoveryOnly",
		CollectionAuthorized: false,
		Volumes:              volumes,
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return fmt.Errorf("write read-only volume discovery report: %w", err)
	}
	return nil
}
