// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

type binaryUpdateCandidate struct {
	spec  applicationBinaryFileSpec
	prior []byte
	temp  string
}

// UpdateBinaries updates only the two approved FI application executables.
// An existing binary must match the independently approved prior bytes and
// metadata, or already match the new release. Each publication is atomic;
// a failed multi-file operation can be retried while services remain stopped.
func UpdateBinaries(config Config, releaseDirectory, priorDirectory string) error {
	if err := requireHostFileHost(config, systemHostProbe{}); err != nil {
		return err
	}
	if err := requireRootControlledBinaryRelease(releaseDirectory); err != nil {
		return err
	}
	plan, err := buildApplicationBinaryPlan(config, releaseDirectory)
	if err != nil {
		return err
	}
	return updateApplicationBinaryPlan(plan, priorDirectory, verifyBinaryUpdateQuiescence)
}

func updateApplicationBinaryPlan(
	plan applicationBinaryPlan,
	priorDirectory string,
	quiescent func() error,
) error {
	if quiescent == nil {
		return fmt.Errorf("binary update requires service-state verification")
	}
	if err := requireApprovedBinaryPriorDirectory(priorDirectory); err != nil {
		return err
	}
	if err := quiescent(); err != nil {
		return err
	}
	for _, parent := range plan.Parents {
		if state := classifyLifecycleParent(parent); state != lifecycleParentDirectoryMatch {
			return fmt.Errorf("binary update parent is not exact: %s (%s)", parent.Role, state)
		}
	}

	candidates := make([]binaryUpdateCandidate, 0, len(plan.Files))
	defer func() {
		for _, candidate := range candidates {
			if candidate.temp != "" {
				_ = os.Remove(candidate.temp)
			}
		}
	}()

	// Classify the complete layer and stage all candidates before replacing any file.
	for _, spec := range plan.Files {
		prior, err := readApprovedBinaryPrior(filepath.Join(priorDirectory, filepath.Base(spec.Target)))
		if err != nil {
			return fmt.Errorf("approved prior for %s: %w", spec.Role, err)
		}
		state := classifyApplicationBinaryFile(spec)
		switch state {
		case applicationBinaryFileOwnedMatch:
			// Retry after a partial update and exact no-op are both supported.
			continue
		case applicationBinaryFileForeignCollision:
			priorSpec := spec
			priorSpec.Content = prior
			if priorState := classifyApplicationBinaryFile(priorSpec); priorState != applicationBinaryFileOwnedMatch {
				return fmt.Errorf("installed binary %s does not match approved prior: %s", spec.Role, priorState)
			}
		default:
			return fmt.Errorf("unsafe installed binary %s: %s", spec.Role, state)
		}
		temp, err := stageBinaryUpdateCandidate(spec)
		if err != nil {
			return fmt.Errorf("stage updated binary %s: %w", spec.Role, err)
		}
		candidates = append(candidates, binaryUpdateCandidate{spec: spec, prior: prior, temp: temp})
	}

	// Revalidate prior and live state immediately before each atomic publication.
	for i := range candidates {
		candidate := &candidates[i]
		if err := quiescent(); err != nil {
			return err
		}
		priorNow, err := readApprovedBinaryPrior(filepath.Join(priorDirectory, filepath.Base(candidate.spec.Target)))
		if err != nil || !bytes.Equal(priorNow, candidate.prior) {
			return fmt.Errorf("approved prior changed: %s", candidate.spec.Role)
		}
		priorSpec := candidate.spec
		priorSpec.Content = candidate.prior
		if state := classifyApplicationBinaryFile(priorSpec); state != applicationBinaryFileOwnedMatch {
			return fmt.Errorf("installed binary changed before update %s: %s", candidate.spec.Role, state)
		}
		tempSpec := candidate.spec
		tempSpec.Target = candidate.temp
		if state := classifyApplicationBinaryFile(tempSpec); state != applicationBinaryFileOwnedMatch {
			return fmt.Errorf("staged update changed %s: %s", candidate.spec.Role, state)
		}
		if err := os.Rename(candidate.temp, candidate.spec.Target); err != nil {
			return fmt.Errorf("publish updated binary %s: %w", candidate.spec.Role, err)
		}
		candidate.temp = ""
		if err := syncHostFileDirectory(filepath.Dir(candidate.spec.Target)); err != nil {
			return fmt.Errorf("sync updated binary directory %s: %w", candidate.spec.Role, err)
		}
		if state := classifyApplicationBinaryFile(candidate.spec); state != applicationBinaryFileOwnedMatch {
			return fmt.Errorf("updated binary failed verification %s: %s", candidate.spec.Role, state)
		}
	}
	return verifyApplicationBinaryPlan(plan)
}

func stageBinaryUpdateCandidate(spec applicationBinaryFileSpec) (string, error) {
	if err := requireHostFileParent(spec.Target); err != nil {
		return "", err
	}
	file, err := os.CreateTemp(filepath.Dir(spec.Target), ".fi-binary-update-*")
	if err != nil {
		return "", err
	}
	path := file.Name()
	success := false
	defer func() {
		_ = file.Close()
		if !success {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(spec.Content); err != nil {
		return "", err
	}
	if err := file.Chown(int(spec.UID), int(spec.GID)); err != nil {
		return "", err
	}
	if err := file.Chmod(spec.Mode); err != nil {
		return "", err
	}
	if err := file.Sync(); err != nil {
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	tempSpec := spec
	tempSpec.Target = path
	if state := classifyApplicationBinaryFile(tempSpec); state != applicationBinaryFileOwnedMatch {
		return "", fmt.Errorf("temporary binary is not exact: %s", state)
	}
	success = true
	return path, nil
}

func requireRootControlledBinaryRelease(directory string) error {
	if err := requireExactPrivateDirectory(directory); err != nil {
		return fmt.Errorf("release directory: %w", err)
	}
	for _, name := range []string{"fi-receiver", "fi-ingest-worker"} {
		info, err := os.Lstat(filepath.Join(directory, name))
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o500 {
			return fmt.Errorf("release source must be a root-controlled 0500 regular file: %s", name)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || stat.Gid != 0 || stat.Nlink != 1 {
			return fmt.Errorf("release source metadata is not exact: %s", name)
		}
	}
	return nil
}

func requireApprovedBinaryPriorDirectory(directory string) error {
	if err := requireExactPrivateDirectory(directory); err != nil {
		return fmt.Errorf("approved prior directory: %w", err)
	}
	return nil
}

func requireExactPrivateDirectory(directory string) error {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return fmt.Errorf("requires a clean absolute path: %s", directory)
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		return fmt.Errorf("directory must be real and mode 0700: %s", directory)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Gid != uint32(os.Getegid()) {
		return fmt.Errorf("directory owner/group mismatch: %s", directory)
	}
	return nil
}

func readApprovedBinaryPrior(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf("approved prior must be a regular 0600 file: %s", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Gid != uint32(os.Getegid()) || stat.Nlink != 1 {
		return nil, fmt.Errorf("approved prior metadata mismatch: %s", path)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(content) == 0 {
		return nil, fmt.Errorf("approved prior is empty: %s", path)
	}
	return content, nil
}

func verifyBinaryUpdateQuiescence() error {
	for _, item := range []struct{ jail, service, process string }{
		{"fi-receiver", "fi_receiver", "fi-receiver"},
		{"fi-ingest", "fi_ingest_worker", "fi-ingest-worker"},
	} {
		cmd := exec.Command("/usr/sbin/jexec", item.jail, "/usr/sbin/service", item.service, "onestatus")
		output, err := cmd.CombinedOutput()
		expected := item.service + " is not running."
		if err == nil || strings.TrimSpace(string(output)) != expected {
			return fmt.Errorf("cannot prove %s is stopped: %s (%v)", item.service, strings.TrimSpace(string(output)), err)
		}
		exit, ok := err.(*exec.ExitError)
		if !ok || exit.ExitCode() != 1 {
			return fmt.Errorf("unexpected %s service status failure: %v", item.service, err)
		}
		cmd = exec.Command("/usr/sbin/jexec", item.jail, "/usr/bin/pgrep", "-x", item.process)
		output, err = cmd.CombinedOutput()
		if err == nil {
			return fmt.Errorf("%s process is still present", item.process)
		}
		exit, ok = err.(*exec.ExitError)
		if !ok || exit.ExitCode() != 1 || len(bytes.TrimSpace(output)) != 0 {
			return fmt.Errorf("cannot prove %s process is absent: %s (%v)", item.process, strings.TrimSpace(string(output)), err)
		}
	}
	return nil
}
