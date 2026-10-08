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
	"runtime"
	"strings"
	"syscall"
)

// -----------------------------------------------------------------------------
// Network contract
// -----------------------------------------------------------------------------

const (
	hostNetworkMarker = "# FI-MANAGED: ironsignal-fi-freebsd-network-v1"

	hostNetworkNetifRole   = "host-network-netif-policy"
	hostNetworkRoutingRole = "host-network-routing-policy"

	hostNetworkNetifTarget   = "/etc/rc.conf.d/netif/90-fi"
	hostNetworkRoutingTarget = "/etc/rc.conf.d/routing/90-fi"
)

type hostNetworkBridgeSpec struct {
	Address string
	Name    string
}

type hostNetworkBridgeState string

const (
	hostNetworkBridgeAbsent  hostNetworkBridgeState = "ABSENT"
	hostNetworkBridgeForeign hostNetworkBridgeState = "FOREIGN_COLLISION"
	hostNetworkBridgeMatch   hostNetworkBridgeState = "OWNED_MATCH"
	hostNetworkBridgeUnknown hostNetworkBridgeState = "UNKNOWN"
)

type hostNetworkFileSpec struct {
	Content []byte
	GID     uint64
	Mode    os.FileMode
	Role    string
	Target  string
	UID     uint64
}

type hostNetworkFileState string

const (
	hostNetworkFileAbsent  hostNetworkFileState = "ABSENT"
	hostNetworkFileDrift   hostNetworkFileState = "OWNED_DRIFT"
	hostNetworkFileForeign hostNetworkFileState = "FOREIGN_COLLISION"
	hostNetworkFileMatch   hostNetworkFileState = "OWNED_MATCH"
	hostNetworkFileUnknown hostNetworkFileState = "UNKNOWN"
)

type hostNetworkParentSpec struct {
	GID  uint64
	Mode os.FileMode
	Path string
	UID  uint64
}

type hostNetworkParentState string

const (
	hostNetworkParentAbsent  hostNetworkParentState = "ABSENT"
	hostNetworkParentMatch   hostNetworkParentState = "SAFE_MATCH"
	hostNetworkParentUnknown hostNetworkParentState = "UNKNOWN"
	hostNetworkParentUnsafe  hostNetworkParentState = "UNSAFE"
)

type hostNetworkPlan struct {
	Bridges []hostNetworkBridgeSpec
	Files   []hostNetworkFileSpec
	Parents []hostNetworkParentSpec
}

// -----------------------------------------------------------------------------
// Public operations
// -----------------------------------------------------------------------------

func ApplyHostNetwork(
	config Config,
) error {
	if err := requireHostNetworkPlatform(
		config,
	); err != nil {
		return err
	}

	plan, err := buildHostNetworkPlan(
		config,
	)
	if err != nil {
		return err
	}

	parentStates := make(
		[]hostNetworkParentState,
		len(plan.Parents),
	)

	for index, spec := range plan.Parents {
		state := classifyHostNetworkParent(
			spec,
		)

		parentStates[index] = state

		switch state {
		case hostNetworkParentAbsent,
			hostNetworkParentMatch:

		case hostNetworkParentUnsafe:
			return fmt.Errorf(
				"network parent is unsafe: %s",
				spec.Path,
			)

		case hostNetworkParentUnknown:
			return fmt.Errorf(
				"network parent could not be classified: %s",
				spec.Path,
			)

		default:
			return fmt.Errorf(
				"unexpected network parent state for %s: %s",
				spec.Path,
				state,
			)
		}
	}

	fileStates := make(
		[]hostNetworkFileState,
		len(plan.Files),
	)

	for index, spec := range plan.Files {
		state := classifyHostNetworkFile(
			spec,
		)

		fileStates[index] = state

		switch state {
		case hostNetworkFileAbsent,
			hostNetworkFileMatch:

		case hostNetworkFileDrift:
			return fmt.Errorf(
				"FI-owned network policy has drifted: %s",
				spec.Target,
			)

		case hostNetworkFileForeign:
			return fmt.Errorf(
				"network policy has foreign collision: %s",
				spec.Target,
			)

		case hostNetworkFileUnknown:
			return fmt.Errorf(
				"network policy could not be classified: %s",
				spec.Target,
			)

		default:
			return fmt.Errorf(
				"unexpected network policy state for %s: %s",
				spec.Target,
				state,
			)
		}
	}

	bridgeStates := make(
		[]hostNetworkBridgeState,
		len(plan.Bridges),
	)

	needsMutation := false

	for index, spec := range plan.Bridges {
		state, err := inspectHostNetworkBridge(
			spec,
		)
		if err != nil {
			return err
		}

		bridgeStates[index] = state

		switch state {
		case hostNetworkBridgeAbsent:
			needsMutation = true

		case hostNetworkBridgeMatch:

		case hostNetworkBridgeForeign:
			return fmt.Errorf(
				"network bridge has foreign collision: %s",
				spec.Name,
			)

		case hostNetworkBridgeUnknown:
			return fmt.Errorf(
				"network bridge could not be classified: %s",
				spec.Name,
			)

		default:
			return fmt.Errorf(
				"unexpected network bridge state for %s: %s",
				spec.Name,
				state,
			)
		}
	}

	forwarding, err := inspectHostNetworkForwarding()
	if err != nil {
		return err
	}

	switch forwarding {
	case 0:
		needsMutation = true

	case 1:

	default:
		return fmt.Errorf(
			"unexpected IPv4 forwarding state: %d",
			forwarding,
		)
	}

	for _, state := range parentStates {
		if state == hostNetworkParentAbsent {
			needsMutation = true
		}
	}

	for _, state := range fileStates {
		if state == hostNetworkFileAbsent {
			needsMutation = true
		}
	}

	if needsMutation {
		if err := requireHostNetworkQuiescent(); err != nil {
			return err
		}
	}

	for index, spec := range plan.Bridges {
		if bridgeStates[index] != hostNetworkBridgeAbsent {
			continue
		}

		if err := createHostNetworkBridge(
			spec,
		); err != nil {
			return err
		}
	}

	if forwarding == 0 {
		if err := enableHostNetworkForwarding(); err != nil {
			return err
		}
	}

	if err := verifyHostNetworkRuntime(
		plan,
	); err != nil {
		return err
	}

	for index, spec := range plan.Parents {
		if parentStates[index] != hostNetworkParentAbsent {
			continue
		}

		if err := createHostNetworkParent(
			spec,
		); err != nil {
			return err
		}
	}

	for index, spec := range plan.Files {
		if fileStates[index] != hostNetworkFileAbsent {
			continue
		}

		if err := publishHostNetworkFile(
			spec,
		); err != nil {
			return err
		}
	}

	return verifyHostNetworkPlan(
		plan,
	)
}

func VerifyHostNetwork(
	config Config,
) error {
	if err := requireHostNetworkPlatform(
		config,
	); err != nil {
		return err
	}

	if err := requireHostNetworkJailsStopped(); err != nil {
		return err
	}

	plan, err := buildHostNetworkPlan(
		config,
	)
	if err != nil {
		return err
	}

	return verifyHostNetworkPlan(
		plan,
	)
}

// -----------------------------------------------------------------------------
// Plan
// -----------------------------------------------------------------------------

func buildHostNetworkPlan(
	config Config,
) (hostNetworkPlan, error) {
	mgmtNetwork, err := netip.ParsePrefix(
		config.Value("FI_MGMT_NETWORK"),
	)
	if err != nil {
		return hostNetworkPlan{}, fmt.Errorf(
			"parse FI_MGMT_NETWORK: %w",
			err,
		)
	}

	mgmtGateway, err := netip.ParseAddr(
		config.Value("FI_MGMT_GATEWAY"),
	)
	if err != nil {
		return hostNetworkPlan{}, fmt.Errorf(
			"parse FI_MGMT_GATEWAY: %w",
			err,
		)
	}

	mgmtAddress := netip.PrefixFrom(
		mgmtGateway,
		mgmtNetwork.Bits(),
	).String()

	workAddress := config.Value(
		"FI_WORK_HOST_ADDRESS",
	)

	netifContent := renderHostNetworkNetif(
		config.Value("FI_MGMT_BRIDGE"),
		mgmtAddress,
		config.Value("FI_WORK_BRIDGE"),
		workAddress,
	)

	routingContent := []byte(
		hostNetworkMarker + "\n" +
			"# FI-ROLE: " +
			hostNetworkRoutingRole +
			"\n\n" +
			"gateway_enable=\"YES\"\n",
	)

	return hostNetworkPlan{
		Bridges: []hostNetworkBridgeSpec{
			{
				Address: mgmtAddress,
				Name: config.Value(
					"FI_MGMT_BRIDGE",
				),
			},
			{
				Address: workAddress,
				Name: config.Value(
					"FI_WORK_BRIDGE",
				),
			},
		},
		Files: []hostNetworkFileSpec{
			{
				Content: netifContent,
				GID:     0,
				Mode:    0o644,
				Role:    hostNetworkNetifRole,
				Target:  hostNetworkNetifTarget,
				UID:     0,
			},
			{
				Content: routingContent,
				GID:     0,
				Mode:    0o644,
				Role:    hostNetworkRoutingRole,
				Target:  hostNetworkRoutingTarget,
				UID:     0,
			},
		},
		Parents: []hostNetworkParentSpec{
			{
				GID:  0,
				Mode: 0o755,
				Path: "/etc/rc.conf.d",
				UID:  0,
			},
			{
				GID:  0,
				Mode: 0o755,
				Path: "/etc/rc.conf.d/netif",
				UID:  0,
			},
			{
				GID:  0,
				Mode: 0o755,
				Path: "/etc/rc.conf.d/routing",
				UID:  0,
			},
		},
	}, nil
}

func renderHostNetworkNetif(
	mgmtBridge string,
	mgmtAddress string,
	workBridge string,
	workAddress string,
) []byte {
	return []byte(
		fmt.Sprintf(
			`%s
# FI-ROLE: %s

case " ${cloned_interfaces} " in
    *" %s "*)
        ;;
    *)
        if [ -n "${cloned_interfaces}" ]; then
            cloned_interfaces="${cloned_interfaces} %s"
        else
            cloned_interfaces="%s"
        fi
        ;;
esac

case " ${cloned_interfaces} " in
    *" %s "*)
        ;;
    *)
        cloned_interfaces="${cloned_interfaces} %s"
        ;;
esac

ifconfig_%s="inet %s up"
ifconfig_%s="inet %s up"
`,
			hostNetworkMarker,
			hostNetworkNetifRole,
			mgmtBridge,
			mgmtBridge,
			mgmtBridge,
			workBridge,
			workBridge,
			mgmtBridge,
			mgmtAddress,
			workBridge,
			workAddress,
		),
	)
}

// -----------------------------------------------------------------------------
// Safety
// -----------------------------------------------------------------------------

func requireHostNetworkJailsStopped() error {
	for _, jail := range []string{
		"fi-sor-db",
		"fi-ingest",
		"fi-receiver",
	} {
		command := exec.Command(
			"/usr/sbin/jls",
			"-j",
			jail,
			"jid",
		)

		output, err := command.CombinedOutput()
		if err == nil {
			return fmt.Errorf(
				"production jail is running: %s",
				jail,
			)
		}

		message := strings.ToLower(
			string(output),
		)

		if !strings.Contains(
			message,
			"not found",
		) {
			return fmt.Errorf(
				"unable to establish stopped state for %s: %s",
				jail,
				strings.TrimSpace(
					string(output),
				),
			)
		}
	}

	return nil
}

func requireHostNetworkPlatform(
	config Config,
) error {
	if runtime.GOOS != "freebsd" {
		return fmt.Errorf(
			"host network foundation requires FreeBSD",
		)
	}

	if os.Geteuid() != 0 {
		return fmt.Errorf(
			"host network foundation requires root",
		)
	}

	hostname, err := os.Hostname()
	if err != nil {
		return fmt.Errorf(
			"inspect hostname: %w",
			err,
		)
	}

	if hostname != config.Value("FI_HOSTNAME") {
		return fmt.Errorf(
			"configured host %q does not match current host %q",
			config.Value("FI_HOSTNAME"),
			hostname,
		)
	}

	return nil
}

func requireHostNetworkQuiescent() error {
	if err := requireHostNetworkJailsStopped(); err != nil {
		return err
	}

	if _, err := os.Lstat(
		"/etc/pf.conf",
	); err == nil {
		return fmt.Errorf(
			"persistent PF policy already exists before network foundation",
		)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf(
			"inspect /etc/pf.conf: %w",
			err,
		)
	}

	if _, err := os.Stat(
		"/dev/pf",
	); err == nil {
		command := exec.Command(
			"/sbin/pfctl",
			"-s",
			"Running",
		)

		if err := command.Run(); err == nil {
			return fmt.Errorf(
				"PF is already enabled at runtime before network foundation",
			)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf(
			"inspect /dev/pf: %w",
			err,
		)
	}

	return nil
}

// -----------------------------------------------------------------------------
// Bridge state
// -----------------------------------------------------------------------------

func classifyHostNetworkBridgeOutput(
	spec hostNetworkBridgeSpec,
	output string,
) hostNetworkBridgeState {
	lines := strings.Split(
		output,
		"\n",
	)

	addresses := make(
		[]string,
		0,
	)

	bridgeGroup := false
	members := 0
	up := false

	for _, line := range lines {
		fields := strings.Fields(
			line,
		)

		if len(fields) == 0 {
			continue
		}

		if strings.HasPrefix(
			fields[0],
			spec.Name+":",
		) {
			open := strings.Index(
				line,
				"<",
			)

			close := strings.Index(
				line,
				">",
			)

			if open >= 0 && close > open {
				for _, flag := range strings.Split(
					line[open+1:close],
					",",
				) {
					if flag == "UP" {
						up = true
					}
				}
			}
		}

		if fields[0] == "groups:" {
			for _, group := range fields[1:] {
				if group == "bridge" {
					bridgeGroup = true
				}
			}
		}

		if fields[0] == "member:" {
			members++
		}

		if fields[0] == "inet" &&
			len(fields) >= 2 {
			addresses = append(
				addresses,
				fields[1],
			)
		}
	}

	if !up ||
		!bridgeGroup ||
		members != 0 ||
		len(addresses) != 1 ||
		addresses[0] != spec.Address {
		return hostNetworkBridgeForeign
	}

	return hostNetworkBridgeMatch
}

func createHostNetworkBridge(
	spec hostNetworkBridgeSpec,
) error {
	state, err := inspectHostNetworkBridge(
		spec,
	)
	if err != nil {
		return err
	}

	if state != hostNetworkBridgeAbsent {
		return fmt.Errorf(
			"bridge changed before creation: %s (%s)",
			spec.Name,
			state,
		)
	}

	command := exec.Command(
		"/sbin/ifconfig",
		spec.Name,
		"create",
	)

	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf(
			"create bridge %s: %s",
			spec.Name,
			strings.TrimSpace(
				string(output),
			),
		)
	}

	command = exec.Command(
		"/sbin/ifconfig",
		spec.Name,
		"inet",
		spec.Address,
		"up",
	)

	output, err = command.CombinedOutput()
	if err != nil {
		return fmt.Errorf(
			"configure bridge %s: %s",
			spec.Name,
			strings.TrimSpace(
				string(output),
			),
		)
	}

	state, err = inspectHostNetworkBridge(
		spec,
	)
	if err != nil {
		return err
	}

	if state != hostNetworkBridgeMatch {
		return fmt.Errorf(
			"bridge failed post-create verification: %s (%s)",
			spec.Name,
			state,
		)
	}

	return nil
}

func inspectHostNetworkBridge(
	spec hostNetworkBridgeSpec,
) (hostNetworkBridgeState, error) {
	command := exec.Command(
		"/sbin/ifconfig",
		"-l",
	)

	output, err := command.Output()
	if err != nil {
		return hostNetworkBridgeUnknown, fmt.Errorf(
			"enumerate interfaces: %w",
			err,
		)
	}

	present := false

	for _, name := range strings.Fields(
		string(output),
	) {
		if name == spec.Name {
			present = true
			break
		}
	}

	if !present {
		return hostNetworkBridgeAbsent, nil
	}

	command = exec.Command(
		"/sbin/ifconfig",
		"-f",
		"inet:cidr",
		spec.Name,
	)

	output, err = command.CombinedOutput()
	if err != nil {
		return hostNetworkBridgeUnknown, fmt.Errorf(
			"inspect bridge %s: %s",
			spec.Name,
			strings.TrimSpace(
				string(output),
			),
		)
	}

	return classifyHostNetworkBridgeOutput(
		spec,
		string(output),
	), nil
}

// -----------------------------------------------------------------------------
// Forwarding
// -----------------------------------------------------------------------------

func enableHostNetworkForwarding() error {
	command := exec.Command(
		"/sbin/sysctl",
		"net.inet.ip.forwarding=1",
	)

	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf(
			"enable IPv4 forwarding: %s",
			strings.TrimSpace(
				string(output),
			),
		)
	}

	state, err := inspectHostNetworkForwarding()
	if err != nil {
		return err
	}

	if state != 1 {
		return fmt.Errorf(
			"IPv4 forwarding did not reach enabled state",
		)
	}

	return nil
}

func inspectHostNetworkForwarding() (int, error) {
	command := exec.Command(
		"/sbin/sysctl",
		"-n",
		"net.inet.ip.forwarding",
	)

	output, err := command.Output()
	if err != nil {
		return -1, fmt.Errorf(
			"inspect IPv4 forwarding: %w",
			err,
		)
	}

	switch strings.TrimSpace(
		string(output),
	) {
	case "0":
		return 0, nil

	case "1":
		return 1, nil

	default:
		return -1, fmt.Errorf(
			"unexpected IPv4 forwarding value: %q",
			strings.TrimSpace(
				string(output),
			),
		)
	}
}

// -----------------------------------------------------------------------------
// Parent directories
// -----------------------------------------------------------------------------

func classifyHostNetworkParent(
	spec hostNetworkParentSpec,
) hostNetworkParentState {
	info, err := os.Lstat(
		spec.Path,
	)

	switch {
	case err == nil:

	case os.IsNotExist(err):
		return hostNetworkParentAbsent

	default:
		return hostNetworkParentUnknown
	}

	if info.Mode()&os.ModeSymlink != 0 ||
		!info.IsDir() {
		return hostNetworkParentUnsafe
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return hostNetworkParentUnknown
	}

	if uint64(stat.Uid) != spec.UID ||
		uint64(stat.Gid) != spec.GID ||
		!exactManagedFileMode(
			info.Mode(),
			spec.Mode,
		) {
		return hostNetworkParentUnsafe
	}

	return hostNetworkParentMatch
}

func createHostNetworkParent(
	spec hostNetworkParentSpec,
) error {
	state := classifyHostNetworkParent(
		spec,
	)

	if state != hostNetworkParentAbsent {
		return fmt.Errorf(
			"network parent changed before creation: %s (%s)",
			spec.Path,
			state,
		)
	}

	if err := os.Mkdir(
		spec.Path,
		spec.Mode,
	); err != nil {
		return fmt.Errorf(
			"create network parent %s: %w",
			spec.Path,
			err,
		)
	}

	if err := os.Chown(
		spec.Path,
		int(spec.UID),
		int(spec.GID),
	); err != nil {
		return fmt.Errorf(
			"set network parent ownership %s: %w",
			spec.Path,
			err,
		)
	}

	state = classifyHostNetworkParent(
		spec,
	)

	if state != hostNetworkParentMatch {
		return fmt.Errorf(
			"network parent failed verification: %s (%s)",
			spec.Path,
			state,
		)
	}

	return nil
}

// -----------------------------------------------------------------------------
// Persistent files
// -----------------------------------------------------------------------------

func classifyHostNetworkFile(
	spec hostNetworkFileSpec,
) hostNetworkFileState {
	info, err := os.Lstat(
		spec.Target,
	)

	switch {
	case err == nil:

	case os.IsNotExist(err):
		return hostNetworkFileAbsent

	default:
		return hostNetworkFileUnknown
	}

	if info.Mode()&os.ModeSymlink != 0 ||
		!info.Mode().IsRegular() {
		return hostNetworkFileForeign
	}

	content, err := os.ReadFile(
		spec.Target,
	)
	if err != nil {
		return hostNetworkFileUnknown
	}

	if !hostNetworkContainsExactLine(
		content,
		hostNetworkMarker,
	) {
		return hostNetworkFileForeign
	}

	if !hostNetworkContainsExactLine(
		content,
		"# FI-ROLE: "+spec.Role,
	) {
		return hostNetworkFileDrift
	}

	if !bytes.Equal(
		content,
		spec.Content,
	) {
		return hostNetworkFileDrift
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return hostNetworkFileUnknown
	}

	if uint64(stat.Uid) != spec.UID ||
		uint64(stat.Gid) != spec.GID ||
		!exactManagedFileMode(
			info.Mode(),
			spec.Mode,
		) ||
		uint64(stat.Nlink) != 1 {
		return hostNetworkFileDrift
	}

	return hostNetworkFileMatch
}

func hostNetworkContainsExactLine(
	content []byte,
	expected string,
) bool {
	for _, line := range strings.Split(
		string(content),
		"\n",
	) {
		if line == expected {
			return true
		}
	}

	return false
}

func publishHostNetworkFile(
	spec hostNetworkFileSpec,
) error {
	state := classifyHostNetworkFile(
		spec,
	)

	if state != hostNetworkFileAbsent {
		return fmt.Errorf(
			"network file changed before creation: %s (%s)",
			spec.Target,
			state,
		)
	}

	parent := filepath.Dir(
		spec.Target,
	)

	info, err := os.Stat(
		parent,
	)
	if err != nil ||
		!info.IsDir() {
		return fmt.Errorf(
			"network file parent unavailable: %s",
			parent,
		)
	}

	file, err := os.CreateTemp(
		parent,
		"."+
			filepath.Base(spec.Target)+
			".fi-network.*",
	)
	if err != nil {
		return fmt.Errorf(
			"create temporary network file: %w",
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
			"populate temporary network file: %w",
			err,
		)
	}

	if err := file.Chown(
		int(spec.UID),
		int(spec.GID),
	); err != nil {
		return fmt.Errorf(
			"set temporary network ownership: %w",
			err,
		)
	}

	if err := file.Chmod(
		spec.Mode,
	); err != nil {
		return fmt.Errorf(
			"set temporary network mode: %w",
			err,
		)
	}

	if err := file.Sync(); err != nil {
		return fmt.Errorf(
			"sync temporary network file: %w",
			err,
		)
	}

	if err := file.Close(); err != nil {
		return fmt.Errorf(
			"close temporary network file: %w",
			err,
		)
	}

	closed = true

	tempSpec := spec
	tempSpec.Target = temp

	if state := classifyHostNetworkFile(
		tempSpec,
	); state != hostNetworkFileMatch {
		return fmt.Errorf(
			"temporary network file failed exact verification: %s",
			state,
		)
	}

	if state := classifyHostNetworkFile(
		spec,
	); state != hostNetworkFileAbsent {
		return fmt.Errorf(
			"network file changed before publication: %s (%s)",
			spec.Target,
			state,
		)
	}

	if err := os.Link(
		temp,
		spec.Target,
	); err != nil {
		return fmt.Errorf(
			"publish network file without overwrite: %w",
			err,
		)
	}

	if err := os.Remove(
		temp,
	); err != nil {
		return fmt.Errorf(
			"remove temporary network publication link: %w",
			err,
		)
	}

	published = true

	if state := classifyHostNetworkFile(
		spec,
	); state != hostNetworkFileMatch {
		return fmt.Errorf(
			"network file failed final verification: %s",
			state,
		)
	}

	return nil
}

// -----------------------------------------------------------------------------
// Verification
// -----------------------------------------------------------------------------

func verifyHostNetworkPlan(
	plan hostNetworkPlan,
) error {
	if err := verifyHostNetworkRuntime(
		plan,
	); err != nil {
		return err
	}

	for _, spec := range plan.Parents {
		state := classifyHostNetworkParent(
			spec,
		)

		if state != hostNetworkParentMatch {
			return fmt.Errorf(
				"network parent is not SAFE_MATCH: %s (%s)",
				spec.Path,
				state,
			)
		}
	}

	for _, spec := range plan.Files {
		state := classifyHostNetworkFile(
			spec,
		)

		if state != hostNetworkFileMatch {
			return fmt.Errorf(
				"network policy is not OWNED_MATCH: %s (%s)",
				spec.Target,
				state,
			)
		}
	}

	return nil
}

func verifyHostNetworkRuntime(
	plan hostNetworkPlan,
) error {
	for _, spec := range plan.Bridges {
		state, err := inspectHostNetworkBridge(
			spec,
		)
		if err != nil {
			return err
		}

		if state != hostNetworkBridgeMatch {
			return fmt.Errorf(
				"network bridge is not exact: %s (%s)",
				spec.Name,
				state,
			)
		}
	}

	forwarding, err := inspectHostNetworkForwarding()
	if err != nil {
		return err
	}

	if forwarding != 1 {
		return fmt.Errorf(
			"IPv4 forwarding is not enabled",
		)
	}

	return nil
}
