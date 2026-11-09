// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/config"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/volumediscovery"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/volumereview"
)

const (
	volumeDiscoveryReportVersion = "fi-volume-discovery/1"
	maxVolumeDeclarationBytes    = 1024 * 1024
)

var ErrVolumePreflightMismatch = errors.New("one or more declared volumes did not match native discovery")

// volumeInventoryCLI validates that the stand-alone read-only operation cannot
// be combined with installer flags that ask for planning or mutation. The
// default -apply=true is intercepted before old installer behavior; explicitly
// specifying -apply (even false) is rejected as ambiguous.
func volumeInventoryCLI(flags *flag.FlagSet) error {
	if flags == nil {
		return errors.New("installer flag set is required")
	}
	var conflicting []string
	flags.Visit(func(item *flag.Flag) {
		if item.Name != "list-volumes" && item.Name != "volume-config" &&
			item.Name != "inspect-policy-roots" {
			conflicting = append(conflicting, "-"+item.Name)
		}
	})
	if flags.NArg() > 0 {
		return errors.New("-list-volumes does not accept positional arguments")
	}
	if len(conflicting) > 0 {
		sort.Strings(conflicting)
		return fmt.Errorf("-list-volumes is a stand-alone read-only action; conflicting flags: %v", conflicting)
	}
	inspectionRequested, declarationProvided := false, false
	flags.Visit(func(item *flag.Flag) {
		if item.Name == "inspect-policy-roots" {
			inspectionRequested = true
		}
		if item.Name == "volume-config" {
			declarationProvided = true
		}
	})
	if inspectionRequested && !declarationProvided {
		return errors.New("-inspect-policy-roots requires an explicit -volume-config declaration")
	}
	return nil
}

// loadVolumeDeclaration only reads an operator-supplied regular file. It is
// neither a legacy operational config nor an approved installer transaction.
// Limiting size protects the read-only native discovery console path.
func loadVolumeDeclaration(path string) (config.VolumeConfig, error) {
	if path == "" {
		return config.VolumeConfig{}, errors.New("volume declaration path is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return config.VolumeConfig{}, fmt.Errorf("resolve volume declaration path: %w", err)
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return config.VolumeConfig{}, fmt.Errorf("inspect volume declaration: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > maxVolumeDeclarationBytes {
		return config.VolumeConfig{}, errors.New("volume declaration must be a regular file of at most 1 MiB")
	}
	file, err := os.Open(absolute)
	if err != nil {
		return config.VolumeConfig{}, fmt.Errorf("read volume declaration: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxVolumeDeclarationBytes+1))
	if err != nil {
		return config.VolumeConfig{}, fmt.Errorf("read bounded volume declaration: %w", err)
	}
	if len(data) > maxVolumeDeclarationBytes {
		return config.VolumeConfig{}, errors.New("volume declaration changed beyond 1 MiB while reading")
	}
	parsed, err := config.ParseVolumeV2(bytes.NewReader(data))
	if err != nil {
		return config.VolumeConfig{}, fmt.Errorf("validate volume declaration: %w", err)
	}
	return parsed, nil
}

type volumeInventoryReport struct {
	Version                    string                     `json:"version"`
	ObservedAtUTC              string                     `json:"observed_at_utc"`
	Action                     string                     `json:"action"`
	CollectionAuthorized       bool                       `json:"collection_authorized"`
	Volumes                    []volumediscovery.Snapshot `json:"volumes"`
	RequestedConfigSHA256      string                     `json:"requested_config_sha256,omitempty"`
	RequestedVolumePreflight   *volumediscovery.Preflight  `json:"requested_volume_preflight,omitempty"`
	RequestedScopeReview       *volumereview.Review         `json:"requested_scope_review,omitempty"`
	PolicyRootsInspected       bool                         `json:"policy_roots_inspected"`
	PolicyRootChecksComplete   bool                         `json:"policy_root_checks_complete"`
	PreflightBlocked           bool                         `json:"preflight_blocked"`
	PolicyRootInspections      []volumeRootInspection       `json:"policy_root_inspections,omitempty"`
}

// writeVolumeInventory is deliberately dependency-injected for failure-path
// tests. It never loads installed config, invokes the existing installer,
// changes a service, modifies SACLs/audit policy or reads a USN journal.
// A matching declaration is still only a *preflight*, never authority to
// perform privileged reads or to mutate Windows configuration.
func writeVolumeInventory(
	ctx context.Context,
	output io.Writer,
	discover func(context.Context) ([]volumediscovery.Snapshot, error),
	clock func() time.Time,
	requested *config.VolumeConfig,
) error {
	return writeVolumeInventoryWithRootInspection(ctx, output, discover, nil, clock, requested, false)
}

// writeVolumeInventoryWithRootInspection adds opt-in read-only native
// governed-root inspection while retaining the legacy read-only inventory
// semantics when the option is absent. The injected observer is only invoked
// for explicitly enrolled volumes with a matching native inventory identity.
func writeVolumeInventoryWithRootInspection(
	ctx context.Context,
	output io.Writer,
	discover func(context.Context) ([]volumediscovery.Snapshot, error),
	inspect rootAttestor,
	clock func() time.Time,
	requested *config.VolumeConfig,
	inspectRoots bool,
) error {
	if ctx == nil || output == nil || discover == nil || clock == nil {
		return errors.New("volume inventory requires context, writer, discovery source and clock")
	}
	if inspectRoots && (requested == nil || inspect == nil) {
		return errors.New("root inspection requires a v2 declaration and read-only native inspector")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if requested != nil {
		if _, err := config.CanonicalVolumeV2(*requested); err != nil {
			return fmt.Errorf("invalid volume declaration: %w", err)
		}
	}
	volumes, err := discover(ctx)
	if err != nil {
		return fmt.Errorf("read-only Windows volume discovery failed: %w", err)
	}
	if len(volumes) == 0 {
		return errors.New("read-only Windows volume discovery returned no volumes")
	}
	report := volumeInventoryReport{
		Version:              volumeDiscoveryReportVersion,
		ObservedAtUTC:        clock().UTC().Format(time.RFC3339Nano),
		Action:               "DiscoveryOnly",
		CollectionAuthorized: false,
		Volumes:              volumes,
	}
	var mismatch bool
	if requested != nil {
		preflight, err := volumediscovery.AssessEnrollment(*requested, volumes)
		if err != nil {
			return fmt.Errorf("read-only enrollment assessment failed: %w", err)
		}
		review, err := volumereview.Build(nil, *requested, volumes)
		if err != nil {
			return fmt.Errorf("read-only scope review failed: %w", err)
		}
		report.RequestedConfigSHA256 = review.RequestedConfigSHA256
		report.RequestedVolumePreflight = &preflight
		report.RequestedScopeReview = &review
		report.Action = "DiscoveryAndScopePreflightOnly"
		mismatch = review.BlocksMutation
	}
	if inspectRoots {
		report.Action = "DiscoveryScopeAndPolicyRootPreflightOnly"
		report.PolicyRootsInspected = true
		observations, complete, err := inspectRequestedPolicyRoots(
			ctx, *requested, report.RequestedVolumePreflight.Matches, inspect,
		)
		if err != nil {
			return fmt.Errorf("invalid policy root inspection preflight: %w", err)
		}
		report.PolicyRootInspections = observations
		report.PolicyRootChecksComplete = complete
		mismatch = mismatch || !complete
	}
	report.PreflightBlocked = mismatch
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return fmt.Errorf("write read-only volume discovery report: %w", err)
	}
	if mismatch {
		return ErrVolumePreflightMismatch
	}
	return nil
}
