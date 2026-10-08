// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	pfPolicyMarker = "# FI-MANAGED: ironsignal-fi-freebsd-pf-v1"
	pfPolicyRole   = "host-packet-filter-policy"
	pfPolicyTarget = "/etc/pf.conf"
)

type pfPolicyState string

const (
	pfPolicyAbsent           pfPolicyState = "ABSENT"
	pfPolicyForeignCollision pfPolicyState = "FOREIGN_COLLISION"
	pfPolicyOwnedDrift       pfPolicyState = "OWNED_DRIFT"
	pfPolicyOwnedMatch       pfPolicyState = "OWNED_MATCH"
	pfPolicyUnknown          pfPolicyState = "UNKNOWN"
)

type pfPolicySpec struct {
	Content []byte
	GID     uint64
	Mode    os.FileMode
	Target  string
	UID     uint64
}

// -----------------------------------------------------------------------------
// Public operations
// -----------------------------------------------------------------------------

func ApplyPFPolicy(
	config Config,
) error {
	probe := systemHostProbe{}

	if err := requireHostFileHost(
		config,
		probe,
	); err != nil {
		return err
	}

	spec, err := buildPFPolicySpec(
		config,
	)
	if err != nil {
		return err
	}

	state := classifyPFPolicy(
		spec,
	)

	switch state {
	case pfPolicyAbsent,
		pfPolicyOwnedMatch:

	case pfPolicyOwnedDrift:
		return fmt.Errorf(
			"FI-owned PF policy has drifted",
		)

	case pfPolicyForeignCollision:
		return fmt.Errorf(
			"existing unowned PF policy requires an explicit approved adoption path",
		)

	case pfPolicyUnknown:
		return fmt.Errorf(
			"persistent PF policy could not be classified safely",
		)

	default:
		return fmt.Errorf(
			"unexpected PF policy state: %s",
			state,
		)
	}

	if err := ensurePFValidationSubstrate(); err != nil {
		return fmt.Errorf(
			"prepare PF validation substrate: %w",
			err,
		)
	}

	if err := validatePFPolicyContent(
		spec.Content,
	); err != nil {
		return fmt.Errorf(
			"rendered PF policy failed validation: %w",
			err,
		)
	}

	if state == pfPolicyAbsent {
		mutator := systemPFPolicyMutator{}

		if err := mutator.PublishAbsent(
			spec,
		); err != nil {
			return err
		}
	}

	return verifyPFPolicySpec(
		spec,
	)
}

func VerifyPFPolicy(
	config Config,
) error {
	probe := systemHostProbe{}

	if err := requireHostFileHost(
		config,
		probe,
	); err != nil {
		return err
	}

	spec, err := buildPFPolicySpec(
		config,
	)
	if err != nil {
		return err
	}

	return verifyPFPolicySpec(
		spec,
	)
}

// -----------------------------------------------------------------------------
// Rendering
// -----------------------------------------------------------------------------

func buildPFPolicySpec(
	config Config,
) (pfPolicySpec, error) {
	content, err := renderPFPolicy(
		pfPolicyAsset,
		config,
	)
	if err != nil {
		return pfPolicySpec{}, err
	}

	return pfPolicySpec{
		Content: content,
		GID:     0,
		Mode:    0o644,
		Target:  pfPolicyTarget,
		UID:     0,
	}, nil
}

func pfAddressOnly(
	key string,
	config Config,
) (string, error) {
	prefix, err := netip.ParsePrefix(
		config.Value(key),
	)
	if err != nil {
		return "", fmt.Errorf(
			"%s is not a valid address prefix: %w",
			key,
			err,
		)
	}

	if !prefix.Addr().Is4() {
		return "", fmt.Errorf(
			"%s is not IPv4",
			key,
		)
	}

	return prefix.Addr().String(), nil
}

func renderPFPolicy(
	template string,
	config Config,
) ([]byte, error) {
	ingestIP, err := pfAddressOnly(
		"FI_INGEST_WORK_ADDRESS",
		config,
	)
	if err != nil {
		return nil, err
	}

	sorIP, err := pfAddressOnly(
		"FI_SOR_DB_WORK_ADDRESS",
		config,
	)
	if err != nil {
		return nil, err
	}

	values := map[string]string{
		"FI_HOST_ADMIN_IF": config.Value(
			"FI_HOST_ADMIN_IF",
		),
		"FI_INGEST_WORK_IP": ingestIP,
		"FI_MGMT_NETWORK": config.Value(
			"FI_MGMT_NETWORK",
		),
		"FI_SOR_DB_WORK_IP": sorIP,
		"FI_WORK_NETWORK": config.Value(
			"FI_WORK_NETWORK",
		),
	}

	unresolved := ""

	rendered := hostFileTokenPattern.ReplaceAllStringFunc(
		template,
		func(token string) string {
			key := token[1 : len(token)-1]

			value, exists := values[key]
			if !exists || value == "" {
				if unresolved == "" {
					unresolved = token
				}

				return token
			}

			return value
		},
	)

	if unresolved != "" {
		return nil, fmt.Errorf(
			"unresolved PF policy token: %s",
			unresolved,
		)
	}

	if token := hostFileTokenPattern.FindString(
		rendered,
	); token != "" {
		return nil, fmt.Errorf(
			"PF policy still contains template token: %s",
			token,
		)
	}

	content := []byte(rendered)

	if !containsExactLine(
		content,
		pfPolicyMarker,
	) {
		return nil, fmt.Errorf(
			"rendered PF policy lacks FI ownership marker",
		)
	}

	if !containsExactLine(
		content,
		"# FI-ROLE: "+pfPolicyRole,
	) {
		return nil, fmt.Errorf(
			"rendered PF policy lacks exact FI role",
		)
	}

	return content, nil
}

// -----------------------------------------------------------------------------
// Classification
// -----------------------------------------------------------------------------

func classifyPFPolicy(
	spec pfPolicySpec,
) pfPolicyState {
	info, err := os.Lstat(
		spec.Target,
	)

	switch {
	case err == nil:

	case os.IsNotExist(err):
		return pfPolicyAbsent

	default:
		return pfPolicyUnknown
	}

	if info.Mode()&os.ModeSymlink != 0 ||
		!info.Mode().IsRegular() {
		return pfPolicyForeignCollision
	}

	content, err := os.ReadFile(
		spec.Target,
	)
	if err != nil {
		return pfPolicyUnknown
	}

	if !containsExactLine(
		content,
		pfPolicyMarker,
	) {
		return pfPolicyForeignCollision
	}

	if !bytes.Equal(
		content,
		spec.Content,
	) {
		return pfPolicyOwnedDrift
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return pfPolicyUnknown
	}

	if uint64(stat.Uid) != spec.UID ||
		uint64(stat.Gid) != spec.GID ||
		!exactManagedFileMode(
			info.Mode(),
			spec.Mode,
		) ||
		uint64(stat.Nlink) != 1 {
		return pfPolicyOwnedDrift
	}

	return pfPolicyOwnedMatch
}

// -----------------------------------------------------------------------------
// PF validation substrate
// -----------------------------------------------------------------------------

func ensurePFValidationSubstrate() error {
	_, err := os.Stat(
		"/dev/pf",
	)

	switch {
	case err == nil:
		return nil

	case os.IsNotExist(err):

	default:
		return fmt.Errorf(
			"inspect /dev/pf: %w",
			err,
		)
	}

	command := exec.Command(
		"/sbin/kldload",
		"-n",
		"pf",
	)

	output, err := command.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(
			string(output),
		)

		if message == "" {
			return fmt.Errorf(
				"load PF kernel module: %w",
				err,
			)
		}

		return fmt.Errorf(
			"load PF kernel module: %s",
			message,
		)
	}

	info, err := os.Stat(
		"/dev/pf",
	)
	if err != nil {
		return fmt.Errorf(
			"PF module loaded but /dev/pf is unavailable: %w",
			err,
		)
	}

	if info.Mode()&os.ModeDevice == 0 {
		return fmt.Errorf(
			"/dev/pf is not a device",
		)
	}

	return nil
}

// -----------------------------------------------------------------------------
// Validation
// -----------------------------------------------------------------------------

func validatePFPolicyContent(
	content []byte,
) error {
	file, err := os.CreateTemp(
		"",
		"fi-pf-validate-*",
	)
	if err != nil {
		return fmt.Errorf(
			"create PF validation file: %w",
			err,
		)
	}

	path := file.Name()

	defer os.Remove(path)

	if _, err := file.Write(
		content,
	); err != nil {
		file.Close()

		return fmt.Errorf(
			"write PF validation file: %w",
			err,
		)
	}

	if err := file.Close(); err != nil {
		return fmt.Errorf(
			"close PF validation file: %w",
			err,
		)
	}

	return validatePFPolicyPath(
		path,
	)
}

func validatePFPolicyPath(
	path string,
) error {
	info, err := os.Lstat(
		path,
	)
	if err != nil {
		return fmt.Errorf(
			"inspect PF policy: %w",
			err,
		)
	}

	if info.Mode()&os.ModeSymlink != 0 ||
		!info.Mode().IsRegular() {
		return fmt.Errorf(
			"PF policy is not a regular file",
		)
	}

	content, err := os.ReadFile(
		path,
	)
	if err != nil {
		return fmt.Errorf(
			"read PF policy: %w",
			err,
		)
	}

	if !containsExactLine(
		content,
		pfPolicyMarker,
	) {
		return fmt.Errorf(
			"PF policy lacks FI ownership marker",
		)
	}

	if !containsExactLine(
		content,
		"# FI-ROLE: "+pfPolicyRole,
	) {
		return fmt.Errorf(
			"PF policy lacks exact FI role",
		)
	}

	command := exec.Command(
		"/sbin/pfctl",
		"-nf",
		path,
	)

	output, err := command.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(
			string(output),
		)

		if message == "" {
			return fmt.Errorf(
				"pfctl syntax validation failed: %w",
				err,
			)
		}

		return fmt.Errorf(
			"pfctl syntax validation failed: %s",
			message,
		)
	}

	return nil
}

func verifyPFPolicySpec(
	spec pfPolicySpec,
) error {
	state := classifyPFPolicy(
		spec,
	)

	if state != pfPolicyOwnedMatch {
		return fmt.Errorf(
			"persistent PF policy is not OWNED_MATCH: %s",
			state,
		)
	}

	if err := validatePFPolicyPath(
		spec.Target,
	); err != nil {
		return fmt.Errorf(
			"persistent PF policy failed validation: %w",
			err,
		)
	}

	return nil
}

// -----------------------------------------------------------------------------
// Mutation
// -----------------------------------------------------------------------------

type systemPFPolicyMutator struct{}

func (systemPFPolicyMutator) PublishAbsent(
	spec pfPolicySpec,
) error {
	state := classifyPFPolicy(
		spec,
	)

	if state != pfPolicyAbsent {
		return fmt.Errorf(
			"PF policy changed before creation: %s",
			state,
		)
	}

	if err := requireHostFileDirectory(
		filepath.Dir(spec.Target),
	); err != nil {
		return err
	}

	parent := filepath.Dir(
		spec.Target,
	)

	name := filepath.Base(
		spec.Target,
	)

	file, err := os.CreateTemp(
		parent,
		"."+name+".fi-pf.*",
	)
	if err != nil {
		return fmt.Errorf(
			"create temporary PF policy: %w",
			err,
		)
	}

	temp := file.Name()
	closed := false
	published := false

	defer func() {
		if !closed {
			file.Close()
		}

		if !published {
			os.Remove(temp)
		}
	}()

	if _, err := file.Write(
		spec.Content,
	); err != nil {
		return fmt.Errorf(
			"populate temporary PF policy: %w",
			err,
		)
	}

	if err := file.Chown(
		int(spec.UID),
		int(spec.GID),
	); err != nil {
		return fmt.Errorf(
			"set temporary PF ownership: %w",
			err,
		)
	}

	if err := file.Chmod(
		spec.Mode,
	); err != nil {
		return fmt.Errorf(
			"set temporary PF mode: %w",
			err,
		)
	}

	if err := file.Sync(); err != nil {
		return fmt.Errorf(
			"sync temporary PF policy: %w",
			err,
		)
	}

	if err := file.Close(); err != nil {
		return fmt.Errorf(
			"close temporary PF policy: %w",
			err,
		)
	}

	closed = true

	if err := validatePFPolicyPath(
		temp,
	); err != nil {
		return fmt.Errorf(
			"temporary PF policy failed validation: %w",
			err,
		)
	}

	tempSpec := spec
	tempSpec.Target = temp

	if state := classifyPFPolicy(
		tempSpec,
	); state != pfPolicyOwnedMatch {
		return fmt.Errorf(
			"temporary PF policy failed exact verification: %s",
			state,
		)
	}

	if state := classifyPFPolicy(
		spec,
	); state != pfPolicyAbsent {
		return fmt.Errorf(
			"PF policy changed before publication: %s",
			state,
		)
	}

	if err := os.Link(
		temp,
		spec.Target,
	); err != nil {
		return fmt.Errorf(
			"publish PF policy without overwrite: %w",
			err,
		)
	}

	if err := os.Remove(
		temp,
	); err != nil {
		return fmt.Errorf(
			"remove temporary PF publication link: %w",
			err,
		)
	}

	published = true

	return verifyPFPolicySpec(
		spec,
	)
}
