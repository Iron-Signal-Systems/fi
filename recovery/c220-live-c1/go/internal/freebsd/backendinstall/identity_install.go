// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// -----------------------------------------------------------------------------
// Jail-local identity contract
// -----------------------------------------------------------------------------

const (
	identityHome  = "/nonexistent"
	identityShell = "/usr/sbin/nologin"
)

type identitySpec struct {
	GID   uint64
	Group string
	Root  string
	UID   uint64
	User  string
}

type identityState string

const (
	identityAbsent           identityState = "ABSENT"
	identityForeignCollision identityState = "FOREIGN_COLLISION"
	identityOwnedDrift       identityState = "OWNED_DRIFT"
	identityOwnedMatch       identityState = "OWNED_MATCH"
	identityUnknown          identityState = "UNKNOWN"
)

type passwdRecord struct {
	GID      uint64
	Home     string
	Name     string
	Password string
	Shell    string
	UID      uint64
}

type groupRecord struct {
	GID  uint64
	Name string
}

// -----------------------------------------------------------------------------
// Public operation
// -----------------------------------------------------------------------------

func ApplyIdentities(config Config) error {
	probe := systemHostProbe{}

	if err := requireIdentityHost(
		config,
		probe,
	); err != nil {
		return err
	}

	specs, err := identitySpecs(config)
	if err != nil {
		return err
	}

	jailSpecs := jailRootSpecs(config)

	for _, jailSpec := range jailSpecs[:2] {
		state := inspectJailDatasetState(
			probe,
			jailSpec,
		)

		if state != jailDatasetOwnedMatch {
			return fmt.Errorf(
				"identity apply requires matching production jail root: %s (%s)",
				jailSpec.Target,
				state,
			)
		}
	}

	if err := requireHostIdentityClear(
		specs[0].UID,
		specs[0].GID,
	); err != nil {
		return err
	}

	for _, spec := range specs {
		state := inspectIdentityState(spec)

		switch state {
		case identityAbsent,
			identityOwnedMatch:
			continue

		case identityOwnedDrift:
			return fmt.Errorf(
				"OWNED_DRIFT: FI identity differs from requested state: %s",
				spec.User,
			)

		case identityForeignCollision:
			return fmt.Errorf(
				"FOREIGN_COLLISION: FI identity UID/GID collides with another identity: %s",
				spec.User,
			)

		case identityUnknown:
			return fmt.Errorf(
				"UNKNOWN: unable to establish safe identity state: %s",
				spec.User,
			)

		default:
			return fmt.Errorf(
				"invalid identity state for %s: %s",
				spec.User,
				state,
			)
		}
	}

	mutator := systemIdentityMutator{}

	for _, spec := range specs {
		if err := applyIdentityOne(
			mutator,
			spec,
		); err != nil {
			return err
		}
	}

	return nil
}

// -----------------------------------------------------------------------------
// Apply
// -----------------------------------------------------------------------------

func applyIdentityOne(
	mutator systemIdentityMutator,
	spec identitySpec,
) error {
	state := inspectIdentityState(spec)

	switch state {
	case identityOwnedMatch:
		return nil

	case identityAbsent:
		if err := mutator.Create(spec); err != nil {
			return fmt.Errorf(
				"create FI jail-local identity %s: %w",
				spec.User,
				err,
			)
		}

	case identityOwnedDrift:
		return fmt.Errorf(
			"OWNED_DRIFT: FI identity differs from requested state: %s",
			spec.User,
		)

	case identityForeignCollision:
		return fmt.Errorf(
			"FOREIGN_COLLISION: FI identity UID/GID collides with another identity: %s",
			spec.User,
		)

	case identityUnknown:
		return fmt.Errorf(
			"UNKNOWN: unable to establish safe identity state: %s",
			spec.User,
		)

	default:
		return fmt.Errorf(
			"invalid identity state for %s: %s",
			spec.User,
			state,
		)
	}

	state = inspectIdentityState(spec)

	if state != identityOwnedMatch {
		return fmt.Errorf(
			"new FI identity did not verify as OWNED_MATCH: %s (%s)",
			spec.User,
			state,
		)
	}

	return nil
}

// -----------------------------------------------------------------------------
// State inspection
// -----------------------------------------------------------------------------

func inspectIdentityState(
	spec identitySpec,
) identityState {
	users, err := readPasswdRecords(
		filepath.Join(
			spec.Root,
			"etc/master.passwd",
		),
	)
	if err != nil {
		return identityUnknown
	}

	groups, err := readGroupRecords(
		filepath.Join(
			spec.Root,
			"etc/group",
		),
	)
	if err != nil {
		return identityUnknown
	}

	usersByName := matchingUsers(
		users,
		func(record passwdRecord) bool {
			return record.Name == spec.User
		},
	)

	usersByUID := matchingUsers(
		users,
		func(record passwdRecord) bool {
			return record.UID == spec.UID
		},
	)

	groupsByName := matchingGroups(
		groups,
		func(record groupRecord) bool {
			return record.Name == spec.Group
		},
	)

	groupsByGID := matchingGroups(
		groups,
		func(record groupRecord) bool {
			return record.GID == spec.GID
		},
	)

	if len(usersByName) > 1 ||
		len(usersByUID) > 1 ||
		len(groupsByName) > 1 ||
		len(groupsByGID) > 1 {
		return identityUnknown
	}

	if len(usersByUID) == 1 &&
		usersByUID[0].Name != spec.User {
		return identityForeignCollision
	}

	if len(groupsByGID) == 1 &&
		groupsByGID[0].Name != spec.Group {
		return identityForeignCollision
	}

	if len(usersByName) == 0 &&
		len(groupsByName) == 0 {
		if len(usersByUID) == 0 &&
			len(groupsByGID) == 0 {
			return identityAbsent
		}

		return identityForeignCollision
	}

	if len(usersByName) != 1 ||
		len(groupsByName) != 1 {
		return identityOwnedDrift
	}

	user := usersByName[0]
	group := groupsByName[0]

	if user.UID != spec.UID ||
		user.GID != spec.GID ||
		group.GID != spec.GID ||
		user.Home != identityHome ||
		user.Shell != identityShell ||
		!strings.HasPrefix(
			user.Password,
			"*",
		) {
		return identityOwnedDrift
	}

	return identityOwnedMatch
}

// -----------------------------------------------------------------------------
// Identity database parsing
// -----------------------------------------------------------------------------

func matchingGroups(
	records []groupRecord,
	match func(groupRecord) bool,
) []groupRecord {
	result := make(
		[]groupRecord,
		0,
	)

	for _, record := range records {
		if match(record) {
			result = append(
				result,
				record,
			)
		}
	}

	return result
}

func matchingUsers(
	records []passwdRecord,
	match func(passwdRecord) bool,
) []passwdRecord {
	result := make(
		[]passwdRecord,
		0,
	)

	for _, record := range records {
		if match(record) {
			result = append(
				result,
				record,
			)
		}
	}

	return result
}

func readGroupRecords(
	target string,
) ([]groupRecord, error) {
	content, err := os.ReadFile(target)
	if err != nil {
		return nil, err
	}

	records := make(
		[]groupRecord,
		0,
	)

	for _, line := range strings.Split(
		string(content),
		"\n",
	) {
		if line == "" {
			continue
		}

		fields := strings.Split(
			line,
			":",
		)

		if len(fields) < 3 {
			return nil, fmt.Errorf(
				"malformed group entry",
			)
		}

		gid, err := strconv.ParseUint(
			fields[2],
			10,
			64,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"invalid group GID: %w",
				err,
			)
		}

		records = append(
			records,
			groupRecord{
				GID:  gid,
				Name: fields[0],
			},
		)
	}

	return records, nil
}

func readPasswdRecords(
	target string,
) ([]passwdRecord, error) {
	content, err := os.ReadFile(target)
	if err != nil {
		return nil, err
	}

	records := make(
		[]passwdRecord,
		0,
	)

	for _, line := range strings.Split(
		string(content),
		"\n",
	) {
		if line == "" {
			continue
		}

		fields := strings.Split(
			line,
			":",
		)

		if len(fields) < 10 {
			return nil, fmt.Errorf(
				"malformed master.passwd entry",
			)
		}

		uid, err := strconv.ParseUint(
			fields[2],
			10,
			64,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"invalid user UID: %w",
				err,
			)
		}

		gid, err := strconv.ParseUint(
			fields[3],
			10,
			64,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"invalid user GID: %w",
				err,
			)
		}

		records = append(
			records,
			passwdRecord{
				GID:      gid,
				Home:     fields[8],
				Name:     fields[0],
				Password: fields[1],
				Shell:    fields[9],
				UID:      uid,
			},
		)
	}

	return records, nil
}

// -----------------------------------------------------------------------------
// Specifications
// -----------------------------------------------------------------------------

func identitySpecs(
	config Config,
) ([]identitySpec, error) {
	uid, err := parsePositiveDecimal(
		"FI_RUNTIME_UID",
		config.Value("FI_RUNTIME_UID"),
	)
	if err != nil {
		return nil, err
	}

	gid, err := parsePositiveDecimal(
		"FI_RUNTIME_GID",
		config.Value("FI_RUNTIME_GID"),
	)
	if err != nil {
		return nil, err
	}

	return []identitySpec{
		{
			GID:   gid,
			Group: "fi-receiver",
			Root:  config.Value("FI_RECEIVER_ROOT"),
			UID:   uid,
			User:  "fi-receiver",
		},
		{
			GID:   gid,
			Group: "fi-ingest",
			Root:  config.Value("FI_INGEST_ROOT"),
			UID:   uid,
			User:  "fi-ingest",
		},
	}, nil
}

// -----------------------------------------------------------------------------
// Host guards
// -----------------------------------------------------------------------------

func requireHostIdentityClear(
	uid uint64,
	gid uint64,
) error {
	users, err := readPasswdRecords(
		"/etc/master.passwd",
	)
	if err != nil {
		return fmt.Errorf(
			"inspect host user database: %w",
			err,
		)
	}

	for _, user := range users {
		if user.Name == "fi-receiver" ||
			user.Name == "fi-ingest" ||
			user.UID == uid {
			return fmt.Errorf(
				"host FI runtime user name or configured UID is already in use",
			)
		}
	}

	groups, err := readGroupRecords(
		"/etc/group",
	)
	if err != nil {
		return fmt.Errorf(
			"inspect host group database: %w",
			err,
		)
	}

	for _, group := range groups {
		if group.Name == "fi-receiver" ||
			group.Name == "fi-ingest" ||
			group.GID == gid {
			return fmt.Errorf(
				"host FI runtime group name or configured GID is already in use",
			)
		}
	}

	return nil
}

func requireIdentityHost(
	config Config,
	probe hostProbe,
) error {
	if probe.EUID() != 0 {
		return fmt.Errorf(
			"identity operation requires root",
		)
	}

	kernel, err := probe.Run(
		"uname",
		"-s",
	)
	if err != nil {
		return fmt.Errorf(
			"inspect operating system before identity apply: %w",
			err,
		)
	}

	if strings.TrimSpace(kernel) != "FreeBSD" {
		return fmt.Errorf(
			"identity operation requires FreeBSD",
		)
	}

	hostname, err := probe.Run(
		"hostname",
	)
	if err != nil {
		return fmt.Errorf(
			"inspect hostname before identity apply: %w",
			err,
		)
	}

	hostname = strings.TrimSpace(hostname)

	if hostname != config.Value("FI_HOSTNAME") {
		return fmt.Errorf(
			"deployment hostname mismatch: expected %s, observed %s",
			config.Value("FI_HOSTNAME"),
			hostname,
		)
	}

	return nil
}

// -----------------------------------------------------------------------------
// System mutation
// -----------------------------------------------------------------------------

type systemIdentityMutator struct {
	execute func(
		string,
		...string,
	) ([]byte, error)
}

func (mutator systemIdentityMutator) Create(
	spec identitySpec,
) error {
	if err := mutator.run(
		"/usr/sbin/pw",
		"-R", spec.Root,
		"groupadd",
		"-n", spec.Group,
		"-g", strconv.FormatUint(
			spec.GID,
			10,
		),
	); err != nil {
		return fmt.Errorf(
			"create FI jail-local group %s: %w",
			spec.Group,
			err,
		)
	}

	if err := mutator.run(
		"/usr/sbin/pw",
		"-R", spec.Root,
		"useradd",
		"-n", spec.User,
		"-u", strconv.FormatUint(
			spec.UID,
			10,
		),
		"-g", spec.Group,
		"-d", identityHome,
		"-s", identityShell,
		"-w", "no",
	); err != nil {
		return fmt.Errorf(
			"create FI jail-local user %s: %w",
			spec.User,
			err,
		)
	}

	return nil
}

func (mutator systemIdentityMutator) run(
	executable string,
	args ...string,
) error {
	execute := mutator.execute

	if execute == nil {
		execute = func(
			path string,
			arguments ...string,
		) ([]byte, error) {
			return exec.Command(
				path,
				arguments...,
			).CombinedOutput()
		}
	}

	output, err := execute(
		executable,
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
