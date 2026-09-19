// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package spool

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const collectorQuarantineDirectorySuffix = "-collector-quarantine"

type startupQuarantine struct {
	dir string
}

func salvageStartupManifestOpensLocked(
	spoolDir string,
) error {
	publicationDir, workDir, err :=
		startupRecoveryDirectories(
			spoolDir,
		)
	if err != nil {
		return err
	}

	for _, dir := range []string{
		workDir,
		publicationDir,
	} {

		info, err :=
			os.Lstat(
				dir,
			)

		if errors.Is(
			err,
			os.ErrNotExist,
		) {
			continue
		}

		if err != nil {
			return err
		}

		if info.Mode()&os.ModeSymlink != 0 ||
			!info.IsDir() {
			return fmt.Errorf(
				"FI startup recovery directory %q is not a real directory",
				dir,
			)
		}

		entries, err :=
			os.ReadDir(
				dir,
			)
		if err != nil {
			return err
		}

		for _, entry := range entries {

			name :=
				entry.Name()

			if !strings.HasPrefix(
				name,
				"batch-",
			) ||
				!strings.HasSuffix(
					name,
					".manifest.json.open",
				) {
				continue
			}

			if entry.Type()&os.ModeSymlink != 0 ||
				!entry.Type().IsRegular() {
				return fmt.Errorf(
					"FI provisional manifest %q is not a regular file",
					name,
				)
			}

			openPath :=
				filepath.Join(
					dir,
					name,
				)

			finalPath :=
				strings.TrimSuffix(
					openPath,
					".open",
				)

			if _, err :=
				os.Lstat(
					finalPath,
				); err == nil {
				return fmt.Errorf(
					"FI provisional manifest %q conflicts with final manifest",
					name,
				)
			} else if !errors.Is(
				err,
				os.ErrNotExist,
			) {
				return err
			}

			verification, err :=
				VerifyManifest(
					openPath,
				)

			if err != nil ||
				!verification.Verified {
				continue
			}

			if err :=
				durableRename(
					openPath,
					finalPath,
				); err != nil {
				return fmt.Errorf(
					"salvage verified FI provisional manifest %q: %w",
					name,
					err,
				)
			}
		}
	}

	return nil
}

func quarantineStartupIncompleteArtifactsLocked(
	spoolDir string,
) error {
	publicationDir, workDir, err :=
		startupRecoveryDirectories(
			spoolDir,
		)
	if err != nil {
		return err
	}

	quarantine :=
		&startupQuarantine{}

	if err :=
		quarantineCollectorWorkResiduals(
			spoolDir,
			workDir,
			quarantine,
		); err != nil {
		return err
	}

	if err :=
		quarantinePublicationResiduals(
			spoolDir,
			publicationDir,
			quarantine,
		); err != nil {
		return err
	}

	return nil
}

func quarantineCollectorWorkResiduals(
	spoolDir string,
	workDir string,
	quarantine *startupQuarantine,
) error {
	info, err :=
		os.Lstat(
			workDir,
		)

	if errors.Is(
		err,
		os.ErrNotExist,
	) {
		return nil
	}

	if err != nil {
		return err
	}

	if info.Mode()&os.ModeSymlink != 0 ||
		!info.IsDir() {
		return errors.New(
			"FI collector work recovery path is not a real directory",
		)
	}

	entries, err :=
		os.ReadDir(
			workDir,
		)
	if err != nil {
		return err
	}

	for _, entry := range entries {

		if entry.Type()&os.ModeSymlink != 0 ||
			!entry.Type().IsRegular() {
			return fmt.Errorf(
				"FI collector work residual %q is not a regular file",
				entry.Name(),
			)
		}

		name :=
			entry.Name()

		switch {
		case strings.HasPrefix(
			name,
			"batch-",
		) &&
			strings.HasSuffix(
				name,
				".open",
			):

		case strings.HasPrefix(
			name,
			"batch-",
		) &&
			strings.HasSuffix(
				name,
				".jsonl",
			):

		default:
			return fmt.Errorf(
				"unexpected FI collector work artifact %q",
				name,
			)
		}

		if err :=
			quarantine.move(
				spoolDir,
				filepath.Join(
					workDir,
					name,
				),
				"work",
			); err != nil {
			return err
		}
	}

	return nil
}

func quarantinePublicationResiduals(
	spoolDir string,
	publicationDir string,
	quarantine *startupQuarantine,
) error {
	entries, err :=
		os.ReadDir(
			publicationDir,
		)
	if err != nil {
		return err
	}

	manifests :=
		make(
			map[string]struct{},
		)

	dataFiles :=
		make(
			map[string]struct{},
		)

	for _, entry := range entries {

		if entry.Type()&os.ModeSymlink != 0 ||
			!entry.Type().IsRegular() {
			return fmt.Errorf(
				"FI active spool artifact %q is not a regular file",
				entry.Name(),
			)
		}

		name :=
			entry.Name()

		switch {
		case strings.HasPrefix(
			name,
			"batch-",
		) &&
			strings.HasSuffix(
				name,
				".manifest.json",
			):
			manifests[name] =
				struct{}{}

		case strings.HasPrefix(
			name,
			"batch-",
		) &&
			strings.HasSuffix(
				name,
				".jsonl",
			):
			dataFiles[name] =
				struct{}{}

		case strings.HasPrefix(
			name,
			"batch-",
		) &&
			strings.HasSuffix(
				name,
				".open",
			):

		default:
			return fmt.Errorf(
				"unexpected FI active spool artifact %q",
				name,
			)
		}
	}

	for manifestName := range manifests {

		dataName :=
			strings.TrimSuffix(
				manifestName,
				".manifest.json",
			) +
				".jsonl"

		if _, ok :=
			dataFiles[dataName]; !ok {
			return fmt.Errorf(
				"published FI manifest %q has no matching data file",
				manifestName,
			)
		}
	}

	for _, entry := range entries {

		name :=
			entry.Name()

		switch {
		case strings.HasSuffix(
			name,
			".manifest.json",
		):
			continue

		case strings.HasSuffix(
			name,
			".jsonl",
		):
			manifestName :=
				strings.TrimSuffix(
					name,
					".jsonl",
				) +
					".manifest.json"

			if _, ok :=
				manifests[manifestName]; ok {
				continue
			}

		case strings.HasSuffix(
			name,
			".open",
		):

		default:
			continue
		}

		if err :=
			quarantine.move(
				spoolDir,
				filepath.Join(
					publicationDir,
					name,
				),
				"spool",
			); err != nil {
			return err
		}
	}

	return nil
}

func startupRecoveryDirectories(
	spoolDir string,
) (
	publicationDir string,
	workDir string,
	err error,
) {
	if spoolDir == "" ||
		!filepath.IsAbs(spoolDir) {
		return "", "", errors.New(
			"FI spool directory must be absolute",
		)
	}

	publicationDir, err =
		resolveDirectoryPath(
			filepath.Clean(
				spoolDir,
			),
		)
	if err != nil {
		return "", "", err
	}

	workDir, err =
		CollectorWorkDir(
			spoolDir,
		)
	if err != nil {
		return "", "", err
	}

	return publicationDir, workDir, nil
}

func collectorQuarantineRoot(
	spoolDir string,
) (
	string,
	error,
) {
	publicationDir, _, err :=
		startupRecoveryDirectories(
			spoolDir,
		)
	if err != nil {
		return "", err
	}

	return filepath.Join(
		filepath.Dir(
			publicationDir,
		),
		collectorWorkDirectoryPrefix+
			filepath.Base(
				publicationDir,
			)+
			collectorQuarantineDirectorySuffix,
	), nil
}

func (q *startupQuarantine) move(
	spoolDir string,
	source string,
	label string,
) error {
	if q == nil {
		return errors.New(
			"FI startup quarantine is nil",
		)
	}

	if q.dir == "" {
		root, err :=
			collectorQuarantineRoot(
				spoolDir,
			)
		if err != nil {
			return err
		}

		if err :=
			os.MkdirAll(
				root,
				0o700,
			); err != nil {
			return fmt.Errorf(
				"create FI collector quarantine root: %w",
				err,
			)
		}

		rootInfo, err :=
			os.Lstat(
				root,
			)
		if err != nil {
			return err
		}

		if rootInfo.Mode()&os.ModeSymlink != 0 ||
			!rootInfo.IsDir() {
			return errors.New(
				"FI collector quarantine root is not a real directory",
			)
		}

		recoveryID, err :=
			newBatchID()
		if err != nil {
			return err
		}

		q.dir =
			filepath.Join(
				root,
				"recovery-"+
					recoveryID,
			)

		if err :=
			os.Mkdir(
				q.dir,
				0o700,
			); err != nil {
			return fmt.Errorf(
				"create FI collector quarantine generation: %w",
				err,
			)
		}
	}

	destination :=
		filepath.Join(
			q.dir,
			label+
				"-"+
				filepath.Base(
					source,
				),
		)

	if err :=
		requirePublicationPathAbsent(
			destination,
		); err != nil {
		return err
	}

	if err :=
		durableRename(
			source,
			destination,
		); err != nil {
		return fmt.Errorf(
			"quarantine FI collector artifact %q: %w",
			source,
			err,
		)
	}

	return nil
}
