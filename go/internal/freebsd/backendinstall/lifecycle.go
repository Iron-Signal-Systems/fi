// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

const lifecycleMarker = "# FI-MANAGED: ironsignal-fi-freebsd-lifecycle-v1"

type lifecycleFileState string

const (
	lifecycleFileAbsent           lifecycleFileState = "ABSENT"
	lifecycleFileForeignCollision lifecycleFileState = "FOREIGN_COLLISION"
	lifecycleFileOwnedDrift       lifecycleFileState = "OWNED_DRIFT"
	lifecycleFileOwnedMatch       lifecycleFileState = "OWNED_MATCH"
	lifecycleFileUnknown          lifecycleFileState = "UNKNOWN"
)

type lifecycleFileSpec struct {
	Content []byte
	GID     uint64
	Mode    os.FileMode
	Role    string
	Target  string
	UID     uint64
}

type lifecycleParentState string

const (
	lifecycleParentAbsent           lifecycleParentState = "ABSENT"
	lifecycleParentDirectoryMatch   lifecycleParentState = "DIRECTORY_MATCH"
	lifecycleParentForeignCollision lifecycleParentState = "FOREIGN_COLLISION"
	lifecycleParentUnknown          lifecycleParentState = "UNKNOWN"
)

type lifecycleParentSpec struct {
	GID  uint64
	Mode os.FileMode
	Path string
	Role string
	UID  uint64
}

type lifecyclePlan struct {
	Files   []lifecycleFileSpec
	Parents []lifecycleParentSpec
}

// -----------------------------------------------------------------------------
// Public operations
// -----------------------------------------------------------------------------

func ApplyLifecycle(
	config Config,
) error {
	probe := systemHostProbe{}

	if err := requireHostFileHost(
		config,
		probe,
	); err != nil {
		return err
	}

	if err := VerifyHostNetwork(
		config,
	); err != nil {
		return fmt.Errorf(
			"host network prerequisite is not exact: %w",
			err,
		)
	}

	if err := VerifyPFPolicy(
		config,
	); err != nil {
		return fmt.Errorf(
			"persistent PF prerequisite is not exact: %w",
			err,
		)
	}

	if err := requireLifecycleGlobalJailPolicy(); err != nil {
		return err
	}

	plan, err := buildLifecyclePlan(
		config,
	)
	if err != nil {
		return err
	}

	if err := preclassifyLifecyclePlan(
		plan,
	); err != nil {
		return err
	}

	for _, spec := range plan.Parents {
		state := classifyLifecycleParent(
			spec,
		)

		switch state {
		case lifecycleParentDirectoryMatch:
			continue

		case lifecycleParentAbsent:
			if err := createLifecycleParent(
				spec,
			); err != nil {
				return fmt.Errorf(
					"create lifecycle parent %s: %w",
					spec.Role,
					err,
				)
			}

		case lifecycleParentForeignCollision:
			return fmt.Errorf(
				"lifecycle parent changed after preclassification: %s (FOREIGN_COLLISION)",
				spec.Role,
			)

		case lifecycleParentUnknown:
			return fmt.Errorf(
				"lifecycle parent changed after preclassification: %s (UNKNOWN)",
				spec.Role,
			)

		default:
			return fmt.Errorf(
				"invalid lifecycle parent state: %s (%s)",
				spec.Role,
				state,
			)
		}
	}

	for _, spec := range plan.Files {
		state := classifyLifecycleFile(
			spec,
		)

		switch state {
		case lifecycleFileOwnedMatch:
			continue

		case lifecycleFileAbsent:
			if err := publishLifecycleFile(
				spec,
			); err != nil {
				return fmt.Errorf(
					"publish lifecycle file %s: %w",
					spec.Role,
					err,
				)
			}

		case lifecycleFileOwnedDrift:
			return fmt.Errorf(
				"lifecycle file changed after preclassification: %s (OWNED_DRIFT)",
				spec.Role,
			)

		case lifecycleFileForeignCollision:
			return fmt.Errorf(
				"lifecycle file changed after preclassification: %s (FOREIGN_COLLISION)",
				spec.Role,
			)

		case lifecycleFileUnknown:
			return fmt.Errorf(
				"lifecycle file changed after preclassification: %s (UNKNOWN)",
				spec.Role,
			)

		default:
			return fmt.Errorf(
				"invalid lifecycle file state: %s (%s)",
				spec.Role,
				state,
			)
		}
	}

	return verifyLifecyclePlan(
		plan,
	)
}

func VerifyLifecycle(
	config Config,
) error {
	probe := systemHostProbe{}

	if err := requireHostFileHost(
		config,
		probe,
	); err != nil {
		return err
	}

	if err := VerifyHostNetwork(
		config,
	); err != nil {
		return fmt.Errorf(
			"host network prerequisite is not exact: %w",
			err,
		)
	}

	if err := VerifyPFPolicy(
		config,
	); err != nil {
		return fmt.Errorf(
			"persistent PF prerequisite is not exact: %w",
			err,
		)
	}

	if err := requireLifecycleGlobalJailPolicy(); err != nil {
		return err
	}

	plan, err := buildLifecyclePlan(
		config,
	)
	if err != nil {
		return err
	}

	return verifyLifecyclePlan(
		plan,
	)
}

// -----------------------------------------------------------------------------
// Plan construction
// -----------------------------------------------------------------------------

func buildLifecyclePlan(
	config Config,
) (lifecyclePlan, error) {
	pfSpec, err := buildPFPolicySpec(
		config,
	)
	if err != nil {
		return lifecyclePlan{}, err
	}

	pfDigest := sha256.Sum256(
		pfSpec.Content,
	)

	sorIP, err := pfAddressOnly(
		"FI_SOR_DB_WORK_ADDRESS",
		config,
	)
	if err != nil {
		return lifecyclePlan{}, err
	}

	fiPFRC, err := renderLifecycleFIPFConfig(
		lifecycleAssetFIPFRC,
		fmt.Sprintf(
			"%x",
			pfDigest,
		),
		sorIP,
	)
	if err != nil {
		return lifecyclePlan{}, err
	}

	parents := []lifecycleParentSpec{
		{
			GID:  0,
			Mode: 0o755,
			Path: "/usr/local/etc",
			Role: "local-etc-directory",
			UID:  0,
		},
		{
			GID:  0,
			Mode: 0o755,
			Path: "/usr/local/etc/rc.d",
			Role: "local-rc-directory",
			UID:  0,
		},
		{
			GID:  0,
			Mode: 0o755,
			Path: "/etc/rc.conf.d",
			Role: "rc-conf-directory",
			UID:  0,
		},
	}

	files := []lifecycleFileSpec{
		{
			Content: []byte(
				lifecycleAssetFIPFService,
			),
			GID:    0,
			Mode:   0o555,
			Role:   "fi-pf-controller",
			Target: "/usr/local/etc/rc.d/fi_pf",
			UID:    0,
		},
		{
			Content: []byte(
				lifecycleAssetFIJailsService,
			),
			GID:    0,
			Mode:   0o555,
			Role:   "fi-jails-controller",
			Target: "/usr/local/etc/rc.d/fi_jails",
			UID:    0,
		},
		{
			Content: fiPFRC,
			GID:     0,
			Mode:    0o644,
			Role:    "fi-pf-enable-policy",
			Target:  "/etc/rc.conf.d/fi_pf",
			UID:     0,
		},
		{
			Content: []byte(
				lifecycleAssetFIJailsRC,
			),
			GID:    0,
			Mode:   0o644,
			Role:   "fi-jails-enable-policy",
			Target: "/etc/rc.conf.d/fi_jails",
			UID:    0,
		},
		{
			Content: []byte(
				lifecycleAssetDevfsRC,
			),
			GID:    0,
			Mode:   0o644,
			Role:   "devfs-boot-policy",
			Target: "/etc/rc.conf.d/devfs",
			UID:    0,
		},
		{
			Content: []byte(
				lifecycleAssetPFRC,
			),
			GID:    0,
			Mode:   0o644,
			Role:   "pf-boot-policy",
			Target: "/etc/rc.conf.d/pf",
			UID:    0,
		},
	}

	for _, spec := range files {
		if !containsExactLine(
			spec.Content,
			lifecycleMarker,
		) {
			return lifecyclePlan{}, fmt.Errorf(
				"lifecycle asset lacks ownership marker: %s",
				spec.Role,
			)
		}

		if !containsExactLine(
			spec.Content,
			"# FI-ROLE: "+spec.Role,
		) {
			return lifecyclePlan{}, fmt.Errorf(
				"lifecycle asset lacks exact role: %s",
				spec.Role,
			)
		}
	}

	return lifecyclePlan{
		Files:   files,
		Parents: parents,
	}, nil
}

func renderLifecycleFIPFConfig(
	template string,
	policySHA256 string,
	sorIP string,
) ([]byte, error) {
	rendered := strings.NewReplacer(
		"@FI_PF_POLICY_SHA256@",
		policySHA256,
		"@FI_SOR_DB_WORK_IP@",
		sorIP,
	).Replace(
		template,
	)

	if token := hostFileTokenPattern.FindString(
		rendered,
	); token != "" {
		return nil, fmt.Errorf(
			"unresolved lifecycle token: %s",
			token,
		)
	}

	content := []byte(
		rendered,
	)

	if !containsExactLine(
		content,
		lifecycleMarker,
	) {
		return nil, fmt.Errorf(
			"rendered FI PF lifecycle config lacks ownership marker",
		)
	}

	if !containsExactLine(
		content,
		"# FI-ROLE: fi-pf-enable-policy",
	) {
		return nil, fmt.Errorf(
			"rendered FI PF lifecycle config lacks exact role",
		)
	}

	return content, nil
}

// -----------------------------------------------------------------------------
// Global jail authority
// -----------------------------------------------------------------------------

func requireLifecycleGlobalJailPolicy() error {
	jailEnable, err := lifecycleSysrcValue(
		"jail_enable",
	)
	if err != nil {
		return fmt.Errorf(
			"inspect global jail_enable policy: %w",
			err,
		)
	}

	jailList, err := lifecycleSysrcValue(
		"jail_list",
	)
	if err != nil {
		return fmt.Errorf(
			"inspect global jail_list policy: %w",
			err,
		)
	}

	return validateLifecycleGlobalJailPolicy(
		jailEnable,
		jailList,
	)
}

func lifecycleSysrcValue(
	key string,
) (string, error) {
	command := exec.Command(
		"/usr/sbin/sysrc",
		"-n",
		key,
	)

	output, err := command.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(
			string(output),
		)

		if message == "" {
			return "", err
		}

		return "", fmt.Errorf(
			"%s",
			message,
		)
	}

	return strings.TrimSpace(
		string(output),
	), nil
}

func validateLifecycleGlobalJailPolicy(
	jailEnable string,
	jailList string,
) error {
	normalized := strings.ToUpper(
		strings.TrimSpace(
			jailEnable,
		),
	)

	switch normalized {
	case "NO", "FALSE", "OFF", "0":
		return nil

	case "YES", "TRUE", "ON", "1":

	default:
		return fmt.Errorf(
			"global jail_enable has unrecognized value: %s",
			jailEnable,
		)
	}

	fields := strings.Fields(
		jailList,
	)

	if len(fields) == 0 {
		return fmt.Errorf(
			"enabled global jail policy selects _ALL and would claim FI production jails",
		)
	}

	for _, name := range fields {
		switch name {
		case "_ALL":
			return fmt.Errorf(
				"enabled global jail policy explicitly selects _ALL",
			)

		case "fi-sor-db",
			"fi-ingest",
			"fi-receiver":
			return fmt.Errorf(
				"enabled global jail policy already claims FI production jail: %s",
				name,
			)
		}
	}

	return nil
}

// -----------------------------------------------------------------------------
// Classification
// -----------------------------------------------------------------------------

func classifyLifecycleFile(
	spec lifecycleFileSpec,
) lifecycleFileState {
	info, err := os.Lstat(
		spec.Target,
	)

	switch {
	case err == nil:

	case os.IsNotExist(err):
		return lifecycleFileAbsent

	default:
		return lifecycleFileUnknown
	}

	if info.Mode()&os.ModeSymlink != 0 ||
		!info.Mode().IsRegular() {
		return lifecycleFileForeignCollision
	}

	content, err := os.ReadFile(
		spec.Target,
	)
	if err != nil {
		return lifecycleFileUnknown
	}

	if !containsExactLine(
		content,
		lifecycleMarker,
	) {
		return lifecycleFileForeignCollision
	}

	if !bytes.Equal(
		content,
		spec.Content,
	) {
		return lifecycleFileOwnedDrift
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return lifecycleFileUnknown
	}

	if uint64(stat.Uid) != spec.UID ||
		uint64(stat.Gid) != spec.GID ||
		!exactManagedFileMode(
			info.Mode(),
			spec.Mode,
		) ||
		uint64(stat.Nlink) != 1 {
		return lifecycleFileOwnedDrift
	}

	return lifecycleFileOwnedMatch
}

func classifyLifecycleParent(
	spec lifecycleParentSpec,
) lifecycleParentState {
	info, err := os.Lstat(
		spec.Path,
	)

	switch {
	case err == nil:

	case os.IsNotExist(err):
		return lifecycleParentAbsent

	default:
		return lifecycleParentUnknown
	}

	if info.Mode()&os.ModeSymlink != 0 ||
		!info.IsDir() {
		return lifecycleParentForeignCollision
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return lifecycleParentUnknown
	}

	if uint64(stat.Uid) != spec.UID ||
		uint64(stat.Gid) != spec.GID ||
		!exactManagedFileMode(
			info.Mode(),
			spec.Mode,
		) {
		return lifecycleParentForeignCollision
	}

	return lifecycleParentDirectoryMatch
}

func preclassifyLifecyclePlan(
	plan lifecyclePlan,
) error {
	for _, spec := range plan.Parents {
		state := classifyLifecycleParent(
			spec,
		)

		switch state {
		case lifecycleParentAbsent,
			lifecycleParentDirectoryMatch:

		case lifecycleParentForeignCollision:
			return fmt.Errorf(
				"unsafe lifecycle parent: %s (FOREIGN_COLLISION)",
				spec.Role,
			)

		case lifecycleParentUnknown:
			return fmt.Errorf(
				"unable to classify lifecycle parent: %s (UNKNOWN)",
				spec.Role,
			)

		default:
			return fmt.Errorf(
				"invalid lifecycle parent state: %s (%s)",
				spec.Role,
				state,
			)
		}
	}

	for _, spec := range plan.Files {
		state := classifyLifecycleFile(
			spec,
		)

		switch state {
		case lifecycleFileAbsent,
			lifecycleFileOwnedMatch:

		case lifecycleFileOwnedDrift:
			return fmt.Errorf(
				"FI-owned lifecycle file has drifted: %s",
				spec.Role,
			)

		case lifecycleFileForeignCollision:
			return fmt.Errorf(
				"existing unowned lifecycle file requires explicit approved adoption: %s",
				spec.Role,
			)

		case lifecycleFileUnknown:
			return fmt.Errorf(
				"unable to classify lifecycle file safely: %s",
				spec.Role,
			)

		default:
			return fmt.Errorf(
				"invalid lifecycle file state: %s (%s)",
				spec.Role,
				state,
			)
		}
	}

	return nil
}

// -----------------------------------------------------------------------------
// Mutation
// -----------------------------------------------------------------------------

func createLifecycleParent(
	spec lifecycleParentSpec,
) error {
	state := classifyLifecycleParent(
		spec,
	)

	if state != lifecycleParentAbsent {
		return fmt.Errorf(
			"lifecycle parent changed before creation: %s",
			state,
		)
	}

	parent := filepath.Dir(
		spec.Path,
	)

	info, err := os.Lstat(
		parent,
	)
	if err != nil {
		return fmt.Errorf(
			"inspect lifecycle parent container: %w",
			err,
		)
	}

	if info.Mode()&os.ModeSymlink != 0 ||
		!info.IsDir() {
		return fmt.Errorf(
			"lifecycle parent container is unsafe: %s",
			parent,
		)
	}

	if err := os.Mkdir(
		spec.Path,
		spec.Mode,
	); err != nil {
		return fmt.Errorf(
			"create lifecycle parent directory: %w",
			err,
		)
	}

	if err := os.Chown(
		spec.Path,
		int(spec.UID),
		int(spec.GID),
	); err != nil {
		return fmt.Errorf(
			"set lifecycle parent ownership: %w",
			err,
		)
	}

	if err := os.Chmod(
		spec.Path,
		spec.Mode,
	); err != nil {
		return fmt.Errorf(
			"set lifecycle parent mode: %w",
			err,
		)
	}

	state = classifyLifecycleParent(
		spec,
	)

	if state != lifecycleParentDirectoryMatch {
		return fmt.Errorf(
			"created lifecycle parent failed exact verification: %s",
			state,
		)
	}

	return nil
}

func publishLifecycleFile(
	spec lifecycleFileSpec,
) error {
	state := classifyLifecycleFile(
		spec,
	)

	if state != lifecycleFileAbsent {
		return fmt.Errorf(
			"lifecycle file changed before creation: %s",
			state,
		)
	}

	if err := requireHostFileParent(
		spec.Target,
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
		"."+name+".fi-lifecycle.*",
	)
	if err != nil {
		return fmt.Errorf(
			"create temporary lifecycle file: %w",
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
			os.Remove(
				temp,
			)
		}
	}()

	if _, err := file.Write(
		spec.Content,
	); err != nil {
		return fmt.Errorf(
			"populate temporary lifecycle file: %w",
			err,
		)
	}

	if spec.UID > uint64(^uint32(0)) ||
		spec.GID > uint64(^uint32(0)) {
		return fmt.Errorf(
			"lifecycle UID/GID exceeds supported range",
		)
	}

	if err := file.Chown(
		int(spec.UID),
		int(spec.GID),
	); err != nil {
		return fmt.Errorf(
			"set temporary lifecycle ownership: %w",
			err,
		)
	}

	if err := file.Chmod(
		spec.Mode,
	); err != nil {
		return fmt.Errorf(
			"set temporary lifecycle mode: %w",
			err,
		)
	}

	if err := file.Sync(); err != nil {
		return fmt.Errorf(
			"sync temporary lifecycle file: %w",
			err,
		)
	}

	if err := file.Close(); err != nil {
		return fmt.Errorf(
			"close temporary lifecycle file: %w",
			err,
		)
	}

	closed = true

	tempSpec := spec
	tempSpec.Target = temp

	if state := classifyLifecycleFile(
		tempSpec,
	); state != lifecycleFileOwnedMatch {
		return fmt.Errorf(
			"temporary lifecycle file failed exact verification: %s",
			state,
		)
	}

	if state := classifyLifecycleFile(
		spec,
	); state != lifecycleFileAbsent {
		return fmt.Errorf(
			"lifecycle file changed before publication: %s",
			state,
		)
	}

	if err := os.Link(
		temp,
		spec.Target,
	); err != nil {
		return fmt.Errorf(
			"publish lifecycle file without replacement: %w",
			err,
		)
	}

	if err := os.Remove(
		temp,
	); err != nil {
		return fmt.Errorf(
			"remove temporary lifecycle link: %w",
			err,
		)
	}

	published = true

	if state := classifyLifecycleFile(
		spec,
	); state != lifecycleFileOwnedMatch {
		return fmt.Errorf(
			"published lifecycle file failed exact verification: %s",
			state,
		)
	}

	return nil
}

// -----------------------------------------------------------------------------
// Verification
// -----------------------------------------------------------------------------

func verifyLifecyclePlan(
	plan lifecyclePlan,
) error {
	for _, spec := range plan.Parents {
		state := classifyLifecycleParent(
			spec,
		)

		if state != lifecycleParentDirectoryMatch {
			return fmt.Errorf(
				"lifecycle parent is not DIRECTORY_MATCH: %s (%s)",
				spec.Role,
				state,
			)
		}
	}

	for _, spec := range plan.Files {
		state := classifyLifecycleFile(
			spec,
		)

		if state != lifecycleFileOwnedMatch {
			return fmt.Errorf(
				"lifecycle file is not OWNED_MATCH: %s (%s)",
				spec.Role,
				state,
			)
		}
	}

	return nil
}
