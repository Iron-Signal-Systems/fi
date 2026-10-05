// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"strings"
	"time"
)

// -----------------------------------------------------------------------------
// Jail installation contract
// -----------------------------------------------------------------------------

type jailDatasetSpec struct {
	Atime      string
	Canmount   string
	Devices    string
	Exec       string
	Mountpoint string
	Mounted    string
	Origin     string
	Readonly   string
	Role       string
	Setuid     string
	Target     string
}

type jailDatasetState string

const (
	jailDatasetAbsent           jailDatasetState = "ABSENT"
	jailDatasetForeignCollision jailDatasetState = "FOREIGN_COLLISION"
	jailDatasetOwnedDrift       jailDatasetState = "OWNED_DRIFT"
	jailDatasetOwnedMatch       jailDatasetState = "OWNED_MATCH"
	jailDatasetUnknown          jailDatasetState = "UNKNOWN"
)

type freeBSDBaseArtifact struct {
	SHA256 string
	URL    string
}

var freeBSDBaseArtifacts = map[string]freeBSDBaseArtifact{
	"amd64|15.1-RELEASE": {
		SHA256: "3768988b151c20f965679062b065c63a977d6bbb9f47fd83695ec2c40790c18f",
		URL:    "https://download.freebsd.org/releases/amd64/amd64/15.1-RELEASE/base.txz",
	},
}

// -----------------------------------------------------------------------------
// Public operations
// -----------------------------------------------------------------------------

func ApplyJailRoots(config Config) error {
	probe := systemHostProbe{}

	release, _, err := requireJailInstallHost(
		config,
		probe,
	)
	if err != nil {
		return err
	}

	substrate, err := jailSubstrateSpecs(
		config,
		release,
	)
	if err != nil {
		return err
	}

	for _, spec := range substrate {
		state := inspectJailDatasetState(
			probe,
			spec,
		)

		if state != jailDatasetOwnedMatch {
			return fmt.Errorf(
				"jail substrate prerequisite does not match: %s (%s)",
				spec.Target,
				state,
			)
		}
	}

	snapshots, err := probe.Run(
		"zfs",
		"list",
		"-H",
		"-t",
		"snapshot",
		"-o",
		"name",
	)
	if err != nil {
		return fmt.Errorf(
			"enumerate snapshots before jail-root apply: %w",
			err,
		)
	}

	snapshot := config.Value("FI_JAIL_TEMPLATE_SNAPSHOT")

	if !listContainsLine(
		snapshots,
		snapshot,
	) {
		return fmt.Errorf(
			"configured jail template snapshot is unavailable: %s",
			snapshot,
		)
	}

	specs := jailRootSpecs(config)

	if err := precheckJailDatasets(
		probe,
		specs,
	); err != nil {
		return fmt.Errorf(
			"production jail-root precheck failed: %w",
			err,
		)
	}

	mutator := systemJailMutator{}

	for _, spec := range specs {
		if err := applyJailRootOne(
			probe,
			mutator,
			spec,
			snapshot,
		); err != nil {
			return err
		}
	}

	return nil
}

func ApplyJailSubstrate(config Config) error {
	probe := systemHostProbe{}

	release, architecture, err := requireJailInstallHost(
		config,
		probe,
	)
	if err != nil {
		return err
	}

	specs, err := jailSubstrateSpecs(
		config,
		release,
	)
	if err != nil {
		return err
	}

	if err := precheckJailDatasets(
		probe,
		specs,
	); err != nil {
		return fmt.Errorf(
			"jail substrate precheck failed: %w",
			err,
		)
	}

	snapshots, err := probe.Run(
		"zfs",
		"list",
		"-H",
		"-t",
		"snapshot",
		"-o",
		"name",
	)
	if err != nil {
		return fmt.Errorf(
			"enumerate snapshots before jail substrate apply: %w",
			err,
		)
	}

	snapshot := config.Value("FI_JAIL_TEMPLATE_SNAPSHOT")
	snapshotExists := listContainsLine(
		snapshots,
		snapshot,
	)

	template := specs[len(specs)-1]

	templateState := inspectJailDatasetState(
		probe,
		template,
	)

	if snapshotExists &&
		templateState != jailDatasetOwnedMatch {
		return fmt.Errorf(
			"configured template snapshot exists but template dataset is not OWNED_MATCH: %s (%s)",
			template.Target,
			templateState,
		)
	}

	archivePath := ""

	if templateState == jailDatasetAbsent {
		artifactKey := architecture + "|" + release

		artifact, ok := freeBSDBaseArtifacts[artifactKey]
		if !ok {
			return fmt.Errorf(
				"no approved FreeBSD base artifact for %s",
				artifactKey,
			)
		}

		archivePath, err = downloadFreeBSDBase(artifact)
		if err != nil {
			return err
		}

		defer os.Remove(archivePath)
	}

	return applyJailSubstrate(
		config,
		probe,
		systemJailMutator{},
		specs,
		archivePath,
	)
}

// -----------------------------------------------------------------------------
// Apply orchestration
// -----------------------------------------------------------------------------

func applyJailRootOne(
	probe hostProbe,
	mutator systemJailMutator,
	spec jailDatasetSpec,
	snapshot string,
) error {
	state := inspectJailDatasetState(
		probe,
		spec,
	)

	switch state {
	case jailDatasetOwnedMatch:
		return nil

	case jailDatasetAbsent:
		if err := mutator.CloneDataset(
			spec,
			snapshot,
		); err != nil {
			return fmt.Errorf(
				"clone production jail root %s: %w",
				spec.Target,
				err,
			)
		}

	case jailDatasetOwnedDrift:
		return fmt.Errorf(
			"OWNED_DRIFT: FI jail root differs from requested state: %s",
			spec.Target,
		)

	case jailDatasetForeignCollision:
		return fmt.Errorf(
			"FOREIGN_COLLISION: jail-root destination is not authoritatively FI-owned: %s",
			spec.Target,
		)

	case jailDatasetUnknown:
		return fmt.Errorf(
			"UNKNOWN: unable to establish safe jail-root state: %s",
			spec.Target,
		)

	default:
		return fmt.Errorf(
			"invalid jail-root state for %s: %s",
			spec.Target,
			state,
		)
	}

	state = inspectJailDatasetState(
		probe,
		spec,
	)

	if state != jailDatasetOwnedMatch {
		return fmt.Errorf(
			"new production jail root did not verify as OWNED_MATCH: %s (%s)",
			spec.Target,
			state,
		)
	}

	return nil
}

func applyJailSubstrate(
	config Config,
	probe hostProbe,
	mutator systemJailMutator,
	specs []jailDatasetSpec,
	archivePath string,
) error {
	for _, spec := range specs[:len(specs)-1] {
		if err := applyJailSubstrateDataset(
			probe,
			mutator,
			spec,
		); err != nil {
			return err
		}
	}

	template := specs[len(specs)-1]

	state := inspectJailDatasetState(
		probe,
		template,
	)

	switch state {
	case jailDatasetOwnedMatch:
		// Template is already complete.

	case jailDatasetAbsent:
		if archivePath == "" {
			return fmt.Errorf(
				"approved FreeBSD base archive is unavailable for template creation",
			)
		}

		writable := template
		writable.Readonly = "off"

		if err := mutator.CreateDataset(
			writable,
		); err != nil {
			return fmt.Errorf(
				"create writable jail template dataset %s: %w",
				writable.Target,
				err,
			)
		}

		writableState := inspectJailDatasetState(
			probe,
			writable,
		)

		if writableState != jailDatasetOwnedMatch {
			return fmt.Errorf(
				"new writable jail template did not verify as OWNED_MATCH: %s (%s)",
				writable.Target,
				writableState,
			)
		}

		if err := mutator.ExtractBase(
			archivePath,
			writable.Mountpoint,
		); err != nil {
			return fmt.Errorf(
				"extract FreeBSD base into jail template: %w",
				err,
			)
		}

		if err := validateTemplateAnchors(
			writable.Mountpoint,
		); err != nil {
			return err
		}

		if err := mutator.SetReadonly(
			writable.Target,
		); err != nil {
			return fmt.Errorf(
				"make jail template readonly: %w",
				err,
			)
		}

		state = inspectJailDatasetState(
			probe,
			template,
		)

		if state != jailDatasetOwnedMatch {
			return fmt.Errorf(
				"completed jail template did not verify as OWNED_MATCH: %s (%s)",
				template.Target,
				state,
			)
		}

	case jailDatasetOwnedDrift:
		return fmt.Errorf(
			"OWNED_DRIFT: jail template differs from requested state: %s",
			template.Target,
		)

	case jailDatasetForeignCollision:
		return fmt.Errorf(
			"FOREIGN_COLLISION: jail template is not authoritatively FI-owned: %s",
			template.Target,
		)

	case jailDatasetUnknown:
		return fmt.Errorf(
			"UNKNOWN: unable to establish safe jail-template state: %s",
			template.Target,
		)

	default:
		return fmt.Errorf(
			"invalid jail-template state for %s: %s",
			template.Target,
			state,
		)
	}

	snapshot := config.Value("FI_JAIL_TEMPLATE_SNAPSHOT")

	snapshots, err := probe.Run(
		"zfs",
		"list",
		"-H",
		"-t",
		"snapshot",
		"-o",
		"name",
	)
	if err != nil {
		return fmt.Errorf(
			"enumerate snapshots before template snapshot creation: %w",
			err,
		)
	}

	if listContainsLine(
		snapshots,
		snapshot,
	) {
		return nil
	}

	state = inspectJailDatasetState(
		probe,
		template,
	)

	if state != jailDatasetOwnedMatch {
		return fmt.Errorf(
			"template snapshot creation requires OWNED_MATCH template: %s (%s)",
			template.Target,
			state,
		)
	}

	if err := mutator.CreateSnapshot(
		snapshot,
	); err != nil {
		return fmt.Errorf(
			"create configured jail template snapshot %s: %w",
			snapshot,
			err,
		)
	}

	snapshots, err = probe.Run(
		"zfs",
		"list",
		"-H",
		"-t",
		"snapshot",
		"-o",
		"name",
	)
	if err != nil {
		return fmt.Errorf(
			"enumerate snapshots after template snapshot creation: %w",
			err,
		)
	}

	if !listContainsLine(
		snapshots,
		snapshot,
	) {
		return fmt.Errorf(
			"new jail template snapshot did not verify: %s",
			snapshot,
		)
	}

	return nil
}

func applyJailSubstrateDataset(
	probe hostProbe,
	mutator systemJailMutator,
	spec jailDatasetSpec,
) error {
	state := inspectJailDatasetState(
		probe,
		spec,
	)

	switch state {
	case jailDatasetOwnedMatch:
		return nil

	case jailDatasetAbsent:
		if err := mutator.CreateDataset(spec); err != nil {
			return fmt.Errorf(
				"create jail substrate dataset %s: %w",
				spec.Target,
				err,
			)
		}

	case jailDatasetOwnedDrift:
		return fmt.Errorf(
			"OWNED_DRIFT: jail substrate dataset differs from requested state: %s",
			spec.Target,
		)

	case jailDatasetForeignCollision:
		return fmt.Errorf(
			"FOREIGN_COLLISION: jail substrate destination is not authoritatively FI-owned: %s",
			spec.Target,
		)

	case jailDatasetUnknown:
		return fmt.Errorf(
			"UNKNOWN: unable to establish safe jail substrate state: %s",
			spec.Target,
		)

	default:
		return fmt.Errorf(
			"invalid jail substrate state for %s: %s",
			spec.Target,
			state,
		)
	}

	state = inspectJailDatasetState(
		probe,
		spec,
	)

	if state != jailDatasetOwnedMatch {
		return fmt.Errorf(
			"new jail substrate dataset did not verify as OWNED_MATCH: %s (%s)",
			spec.Target,
			state,
		)
	}

	return nil
}

// -----------------------------------------------------------------------------
// Precheck
// -----------------------------------------------------------------------------

func precheckJailDatasets(
	probe hostProbe,
	specs []jailDatasetSpec,
) error {
	for _, spec := range specs {
		state := inspectJailDatasetState(
			probe,
			spec,
		)

		switch state {
		case jailDatasetAbsent,
			jailDatasetOwnedMatch:
			continue

		case jailDatasetOwnedDrift:
			return fmt.Errorf(
				"OWNED_DRIFT: dataset differs from requested state: %s",
				spec.Target,
			)

		case jailDatasetForeignCollision:
			return fmt.Errorf(
				"FOREIGN_COLLISION: destination is not authoritatively FI-owned: %s",
				spec.Target,
			)

		case jailDatasetUnknown:
			return fmt.Errorf(
				"UNKNOWN: unable to establish safe dataset state: %s",
				spec.Target,
			)

		default:
			return fmt.Errorf(
				"invalid jail dataset state for %s: %s",
				spec.Target,
				state,
			)
		}
	}

	return nil
}

// -----------------------------------------------------------------------------
// State inspection
// -----------------------------------------------------------------------------

func inspectJailDatasetState(
	probe hostProbe,
	spec jailDatasetSpec,
) jailDatasetState {
	filesystems, err := probe.Run(
		"zfs",
		"list",
		"-H",
		"-t",
		"filesystem",
		"-o",
		"name",
	)
	if err != nil {
		return jailDatasetUnknown
	}

	if !listContainsLine(
		filesystems,
		spec.Target,
	) {
		exists, err := probe.Lstat(spec.Mountpoint)
		if err != nil {
			return jailDatasetUnknown
		}

		if exists {
			return jailDatasetForeignCollision
		}

		return jailDatasetAbsent
	}

	managed, err := inspectLocalJailProperty(
		probe,
		spec.Target,
		"org.ironsignal.fi:managed",
		"1",
	)
	if err != nil {
		return jailDatasetUnknown
	}

	if !managed {
		return jailDatasetForeignCollision
	}

	required := []struct {
		name     string
		expected string
	}{
		{"org.ironsignal.fi:schema", "1"},
		{"org.ironsignal.fi:role", spec.Role},
		{"mountpoint", spec.Mountpoint},
		{"canmount", spec.Canmount},
		{"readonly", spec.Readonly},
		{"atime", spec.Atime},
		{"exec", spec.Exec},
		{"setuid", spec.Setuid},
		{"devices", spec.Devices},
	}

	for _, property := range required {
		matches, err := inspectLocalJailProperty(
			probe,
			spec.Target,
			property.name,
			property.expected,
		)
		if err != nil {
			return jailDatasetUnknown
		}

		if !matches {
			return jailDatasetOwnedDrift
		}
	}

	if spec.Origin != "" {
		origin, err := probe.Run(
			"zfs",
			"get",
			"-H",
			"-o",
			"value",
			"origin",
			spec.Target,
		)
		if err != nil {
			return jailDatasetUnknown
		}

		if strings.TrimSpace(origin) != spec.Origin {
			return jailDatasetOwnedDrift
		}
	}

	mounted, err := probe.Run(
		"zfs",
		"get",
		"-H",
		"-o",
		"value",
		"mounted",
		spec.Target,
	)
	if err != nil {
		return jailDatasetUnknown
	}

	if strings.TrimSpace(mounted) != spec.Mounted {
		return jailDatasetOwnedDrift
	}

	return jailDatasetOwnedMatch
}

func inspectLocalJailProperty(
	probe hostProbe,
	target string,
	property string,
	expected string,
) (bool, error) {
	result, err := probe.Run(
		"zfs",
		"get",
		"-H",
		"-o",
		"value,source",
		property,
		target,
	)
	if err != nil {
		return false, err
	}

	parts := strings.SplitN(
		strings.TrimSpace(result),
		"\t",
		2,
	)

	if len(parts) != 2 {
		return false, fmt.Errorf(
			"unexpected ZFS property response for %s on %s",
			property,
			target,
		)
	}

	return parts[0] == expected &&
		parts[1] == "local", nil
}

// -----------------------------------------------------------------------------
// Dataset specifications
// -----------------------------------------------------------------------------

func jailRootSpecs(config Config) []jailDatasetSpec {
	root := config.Value("FI_JAIL_DATASET_ROOT")
	snapshot := config.Value("FI_JAIL_TEMPLATE_SNAPSHOT")

	return []jailDatasetSpec{
		{
			Atime:      "off",
			Canmount:   "on",
			Devices:    "on",
			Exec:       "on",
			Mountpoint: config.Value("FI_RECEIVER_ROOT"),
			Mounted:    "yes",
			Origin:     snapshot,
			Readonly:   "off",
			Role:       "jail-root-receiver",
			Setuid:     "on",
			Target:     root + "/fi-receiver",
		},
		{
			Atime:      "off",
			Canmount:   "on",
			Devices:    "on",
			Exec:       "on",
			Mountpoint: config.Value("FI_INGEST_ROOT"),
			Mounted:    "yes",
			Origin:     snapshot,
			Readonly:   "off",
			Role:       "jail-root-ingest",
			Setuid:     "on",
			Target:     root + "/fi-ingest",
		},
		{
			Atime:      "off",
			Canmount:   "on",
			Devices:    "on",
			Exec:       "on",
			Mountpoint: config.Value("FI_SOR_DB_ROOT"),
			Mounted:    "yes",
			Origin:     snapshot,
			Readonly:   "off",
			Role:       "jail-root-sor-db",
			Setuid:     "on",
			Target:     root + "/fi-sor-db",
		},
	}
}

func jailSubstrateSpecs(
	config Config,
	release string,
) ([]jailDatasetSpec, error) {
	containersDataset := config.Value(
		"FI_JAIL_DATASET_ROOT",
	)
	containersMountpoint := config.Value(
		"FI_JAIL_ROOT_BASE",
	)

	jailsDataset := path.Dir(containersDataset)
	jailsMountpoint := path.Dir(containersMountpoint)

	if path.Base(containersDataset) != "containers" ||
		path.Base(containersMountpoint) != "containers" {
		return nil, fmt.Errorf(
			"configured jail container root does not use the accepted containers layout",
		)
	}

	snapshot := config.Value(
		"FI_JAIL_TEMPLATE_SNAPSHOT",
	)

	separator := strings.IndexByte(
		snapshot,
		'@',
	)
	if separator < 1 {
		return nil, fmt.Errorf(
			"configured jail template snapshot is invalid",
		)
	}

	templateDataset := snapshot[:separator]
	templatesDataset := path.Dir(templateDataset)

	if path.Base(templatesDataset) != "templates" ||
		path.Dir(templatesDataset) != jailsDataset {
		return nil, fmt.Errorf(
			"configured jail template dataset does not use the accepted templates layout",
		)
	}

	if path.Base(templateDataset) != release {
		return nil, fmt.Errorf(
			"configured template release %s does not match host release %s",
			path.Base(templateDataset),
			release,
		)
	}

	templatesMountpoint := path.Join(
		jailsMountpoint,
		"templates",
	)

	templateMountpoint := path.Join(
		templatesMountpoint,
		release,
	)

	return []jailDatasetSpec{
		{
			Atime:      "off",
			Canmount:   "on",
			Devices:    "off",
			Exec:       "off",
			Mountpoint: jailsMountpoint,
			Mounted:    "yes",
			Readonly:   "off",
			Role:       "jail-parent",
			Setuid:     "off",
			Target:     jailsDataset,
		},
		{
			Atime:      "off",
			Canmount:   "on",
			Devices:    "off",
			Exec:       "off",
			Mountpoint: containersMountpoint,
			Mounted:    "yes",
			Readonly:   "off",
			Role:       "jail-containers-parent",
			Setuid:     "off",
			Target:     containersDataset,
		},
		{
			Atime:      "off",
			Canmount:   "on",
			Devices:    "off",
			Exec:       "off",
			Mountpoint: templatesMountpoint,
			Mounted:    "yes",
			Readonly:   "off",
			Role:       "jail-templates-parent",
			Setuid:     "off",
			Target:     templatesDataset,
		},
		{
			Atime:      "off",
			Canmount:   "on",
			Devices:    "off",
			Exec:       "off",
			Mountpoint: templateMountpoint,
			Mounted:    "yes",
			Readonly:   "on",
			Role:       "jail-template",
			Setuid:     "off",
			Target:     templateDataset,
		},
	}, nil
}

// -----------------------------------------------------------------------------
// Host prerequisites
// -----------------------------------------------------------------------------

func requireJailInstallHost(
	config Config,
	probe hostProbe,
) (string, string, error) {
	if probe.EUID() != 0 {
		return "", "", fmt.Errorf(
			"jail installation requires root",
		)
	}

	kernel, err := probe.Run(
		"uname",
		"-s",
	)
	if err != nil {
		return "", "", fmt.Errorf(
			"inspect operating system before jail installation: %w",
			err,
		)
	}

	if strings.TrimSpace(kernel) != "FreeBSD" {
		return "", "", fmt.Errorf(
			"jail installation requires FreeBSD",
		)
	}

	hostname, err := probe.Run(
		"hostname",
	)
	if err != nil {
		return "", "", fmt.Errorf(
			"inspect hostname before jail installation: %w",
			err,
		)
	}

	hostname = strings.TrimSpace(hostname)

	if hostname != config.Value("FI_HOSTNAME") {
		return "", "", fmt.Errorf(
			"deployment hostname mismatch: expected %s, observed %s",
			config.Value("FI_HOSTNAME"),
			hostname,
		)
	}

	release, err := probe.Run(
		"freebsd-version",
	)
	if err != nil {
		return "", "", fmt.Errorf(
			"inspect FreeBSD release before jail installation: %w",
			err,
		)
	}

	release = freeBSDReleaseBase(
		strings.TrimSpace(release),
	)

	architecture, err := probe.Run(
		"uname",
		"-m",
	)
	if err != nil {
		return "", "", fmt.Errorf(
			"inspect architecture before jail installation: %w",
			err,
		)
	}

	architecture = strings.TrimSpace(architecture)

	if _, err := probe.Run(
		"zpool",
		"list",
		"-H",
		"-o",
		"name",
		config.Value("FI_ZPOOL"),
	); err != nil {
		return "", "", fmt.Errorf(
			"configured ZFS pool is unavailable before jail installation: %w",
			err,
		)
	}

	return release, architecture, nil
}

// -----------------------------------------------------------------------------
// Base release acquisition
// -----------------------------------------------------------------------------

func downloadFreeBSDBase(
	artifact freeBSDBaseArtifact,
) (string, error) {
	client := &http.Client{
		Timeout: 30 * time.Minute,
	}

	request, err := http.NewRequest(
		http.MethodGet,
		artifact.URL,
		nil,
	)
	if err != nil {
		return "", fmt.Errorf(
			"construct FreeBSD base request: %w",
			err,
		)
	}

	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf(
			"download approved FreeBSD base archive: %w",
			err,
		)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf(
			"download approved FreeBSD base archive returned HTTP %d",
			response.StatusCode,
		)
	}

	file, err := os.CreateTemp(
		"",
		"fi-freebsd-base-*.txz",
	)
	if err != nil {
		return "", fmt.Errorf(
			"create temporary FreeBSD base archive: %w",
			err,
		)
	}

	fileName := file.Name()
	keep := false

	defer func() {
		if !keep {
			file.Close()
			os.Remove(fileName)
		}
	}()

	hasher := sha256.New()

	const maximumArchiveSize = int64(512 << 20)

	copied, err := io.Copy(
		io.MultiWriter(
			file,
			hasher,
		),
		io.LimitReader(
			response.Body,
			maximumArchiveSize+1,
		),
	)
	if err != nil {
		return "", fmt.Errorf(
			"write downloaded FreeBSD base archive: %w",
			err,
		)
	}

	if copied > maximumArchiveSize {
		return "", fmt.Errorf(
			"downloaded FreeBSD base archive exceeds safety limit",
		)
	}

	actual := fmt.Sprintf(
		"%x",
		hasher.Sum(nil),
	)

	if actual != artifact.SHA256 {
		return "", fmt.Errorf(
			"FreeBSD base archive SHA-256 mismatch: expected %s, observed %s",
			artifact.SHA256,
			actual,
		)
	}

	if err := file.Sync(); err != nil {
		return "", fmt.Errorf(
			"sync downloaded FreeBSD base archive: %w",
			err,
		)
	}

	if err := file.Close(); err != nil {
		return "", fmt.Errorf(
			"close downloaded FreeBSD base archive: %w",
			err,
		)
	}

	keep = true

	return fileName, nil
}

// -----------------------------------------------------------------------------
// Template verification
// -----------------------------------------------------------------------------

func validateTemplateAnchors(root string) error {
	anchors := []string{
		"bin/sh",
		"etc/master.passwd",
		"usr/bin/env",
		"usr/sbin/service",
	}

	for _, relative := range anchors {
		target := path.Join(
			root,
			relative,
		)

		info, err := os.Stat(target)
		if err != nil {
			return fmt.Errorf(
				"required FreeBSD template anchor unavailable %s: %w",
				target,
				err,
			)
		}

		if !info.Mode().IsRegular() {
			return fmt.Errorf(
				"required FreeBSD template anchor is not a regular file: %s",
				target,
			)
		}
	}

	return nil
}

// -----------------------------------------------------------------------------
// System mutation
// -----------------------------------------------------------------------------

type systemJailMutator struct {
	execute func(
		string,
		...string,
	) ([]byte, error)
	lstat func(string) (bool, error)
}

func (mutator systemJailMutator) CloneDataset(
	spec jailDatasetSpec,
	snapshot string,
) error {
	if err := mutator.requireAbsentPath(
		spec.Mountpoint,
	); err != nil {
		return err
	}

	commandPath, err := systemCommandPath("zfs")
	if err != nil {
		return err
	}

	args := []string{
		"clone",
		"-o", "org.ironsignal.fi:managed=1",
		"-o", "org.ironsignal.fi:schema=1",
		"-o", "org.ironsignal.fi:role=" + spec.Role,
		"-o", "mountpoint=" + spec.Mountpoint,
		"-o", "canmount=" + spec.Canmount,
		"-o", "readonly=" + spec.Readonly,
		"-o", "atime=" + spec.Atime,
		"-o", "exec=" + spec.Exec,
		"-o", "setuid=" + spec.Setuid,
		"-o", "devices=" + spec.Devices,
		snapshot,
		spec.Target,
	}

	return mutator.runChecked(
		commandPath,
		args...,
	)
}

func (mutator systemJailMutator) CreateDataset(
	spec jailDatasetSpec,
) error {
	if err := mutator.requireAbsentPath(
		spec.Mountpoint,
	); err != nil {
		return err
	}

	commandPath, err := systemCommandPath("zfs")
	if err != nil {
		return err
	}

	args := []string{
		"create",
		"-o", "org.ironsignal.fi:managed=1",
		"-o", "org.ironsignal.fi:schema=1",
		"-o", "org.ironsignal.fi:role=" + spec.Role,
		"-o", "mountpoint=" + spec.Mountpoint,
		"-o", "canmount=" + spec.Canmount,
		"-o", "readonly=" + spec.Readonly,
		"-o", "atime=" + spec.Atime,
		"-o", "exec=" + spec.Exec,
		"-o", "setuid=" + spec.Setuid,
		"-o", "devices=" + spec.Devices,
		spec.Target,
	}

	return mutator.runChecked(
		commandPath,
		args...,
	)
}

func (mutator systemJailMutator) CreateSnapshot(
	snapshot string,
) error {
	commandPath, err := systemCommandPath("zfs")
	if err != nil {
		return err
	}

	return mutator.runChecked(
		commandPath,
		"snapshot",
		snapshot,
	)
}

func (mutator systemJailMutator) ExtractBase(
	archive string,
	destination string,
) error {
	return mutator.runChecked(
		"/usr/bin/tar",
		"-xpf",
		archive,
		"-C",
		destination,
	)
}

func (mutator systemJailMutator) SetReadonly(
	target string,
) error {
	commandPath, err := systemCommandPath("zfs")
	if err != nil {
		return err
	}

	return mutator.runChecked(
		commandPath,
		"set",
		"readonly=on",
		target,
	)
}

func (mutator systemJailMutator) requireAbsentPath(
	target string,
) error {
	lstat := mutator.lstat

	if lstat == nil {
		probe := systemHostProbe{}
		lstat = probe.Lstat
	}

	exists, err := lstat(target)
	if err != nil {
		return fmt.Errorf(
			"inspect jail mountpoint immediately before creation %s: %w",
			target,
			err,
		)
	}

	if exists {
		return fmt.Errorf(
			"FOREIGN_COLLISION: jail mountpoint path already exists immediately before creation: %s",
			target,
		)
	}

	return nil
}

func (mutator systemJailMutator) runChecked(
	commandPath string,
	args ...string,
) error {
	execute := mutator.execute

	if execute == nil {
		execute = func(
			executable string,
			arguments ...string,
		) ([]byte, error) {
			return exec.Command(
				executable,
				arguments...,
			).CombinedOutput()
		}
	}

	output, err := execute(
		commandPath,
		args...,
	)
	if err == nil {
		return nil
	}

	message := strings.TrimSpace(
		string(output),
	)

	if message == "" {
		return err
	}

	return fmt.Errorf(
		"%w: %s",
		err,
		message,
	)
}
