// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// -----------------------------------------------------------------------------
// Configuration contract
// -----------------------------------------------------------------------------

type Config struct {
	values map[string]string
}

var absolutePathPattern = regexp.MustCompile(`^/[A-Za-z0-9._/@:-]+$`)
var configLinePattern = regexp.MustCompile(`^FI_[A-Z0-9_]+="[^"]*"$`)
var configValuePattern = regexp.MustCompile(`^[A-Za-z0-9_./@:-]*$`)
var datasetPattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]+(/[A-Za-z0-9_.:-]+)+$`)
var dnsNamePattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$`)
var hostnamePattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$`)
var interfaceNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]+$`)
var poolNamePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.:-]*$`)
var runtimeSourcePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
var snapshotPattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]+(/[A-Za-z0-9_.:-]+)+@[A-Za-z0-9_.:-]+$`)

var allowedKeys = map[string]struct{}{
	"FI_CUSTODY_GENERATION_HOST":   {},
	"FI_CUSTODY_TRANSPORT_HOST":    {},
	"FI_DEVFS_RULESET":             {},
	"FI_HOSTNAME":                  {},
	"FI_HOST_ADMIN_ADDRESS":        {},
	"FI_HOST_ADMIN_GATEWAY":        {},
	"FI_HOST_ADMIN_IF":             {},
	"FI_HOST_DNS_SEARCH":           {},
	"FI_HOST_DNS_SERVER_1":         {},
	"FI_HOST_DNS_SERVER_2":         {},
	"FI_INGEST_CONFIG_HOST":        {},
	"FI_INGEST_FSTAB":              {},
	"FI_INGEST_MGMT_ADDRESS":       {},
	"FI_INGEST_MGMT_HOST_IF":       {},
	"FI_INGEST_MGMT_JAIL_IF":       {},
	"FI_INGEST_ROOT":               {},
	"FI_INGEST_WORK_ADDRESS":       {},
	"FI_INGEST_WORK_HOST_IF":       {},
	"FI_INGEST_WORK_JAIL_IF":       {},
	"FI_JAIL_DATASET_ROOT":         {},
	"FI_JAIL_ROOT_BASE":            {},
	"FI_JAIL_TEMPLATE_SNAPSHOT":    {},
	"FI_MGMT_BRIDGE":               {},
	"FI_MGMT_GATEWAY":              {},
	"FI_MGMT_NETWORK":              {},
	"FI_READY_HOST":                {},
	"FI_RECEIVER_CONFIG_HOST":      {},
	"FI_RECEIVER_DNS_SEARCH":       {},
	"FI_RECEIVER_DNS_SERVER":       {},
	"FI_RECEIVER_EXTERNAL_ADDRESS": {},
	"FI_RECEIVER_EXTERNAL_BRIDGE":  {},
	"FI_RECEIVER_EXTERNAL_GATEWAY": {},
	"FI_RECEIVER_EXTERNAL_HOST_IF": {},
	"FI_RECEIVER_EXTERNAL_IF":      {},
	"FI_RECEIVER_EXTERNAL_JAIL_IF": {},
	"FI_RECEIVER_EXTERNAL_NETWORK": {},
	"FI_RECEIVER_FSTAB":            {},
	"FI_RECEIVER_MGMT_ADDRESS":     {},
	"FI_RECEIVER_MGMT_HOST_IF":     {},
	"FI_RECEIVER_MGMT_JAIL_IF":     {},
	"FI_RECEIVER_ROOT":             {},
	"FI_RECEIVER_WORK_ADDRESS":     {},
	"FI_RECEIVER_WORK_HOST_IF":     {},
	"FI_RECEIVER_WORK_JAIL_IF":     {},
	"FI_RECORDED_HOST":             {},
	"FI_RUNTIME_GID":               {},
	"FI_RUNTIME_SOURCE_ID":         {},
	"FI_RUNTIME_UID":               {},
	"FI_SOR_DB_FSTAB":              {},
	"FI_SOR_DB_MGMT_ADDRESS":       {},
	"FI_SOR_DB_MGMT_HOST_IF":       {},
	"FI_SOR_DB_MGMT_JAIL_IF":       {},
	"FI_SOR_DB_ROOT":               {},
	"FI_SOR_DB_WORK_ADDRESS":       {},
	"FI_SOR_DB_WORK_HOST_IF":       {},
	"FI_SOR_DB_WORK_JAIL_IF":       {},
	"FI_SOR_POSTGRES_HOST":         {},
	"FI_WORK_BRIDGE":               {},
	"FI_WORK_NETWORK":              {},
	"FI_ZPOOL":                     {},
}

var requiredKeys = []string{
	"FI_CUSTODY_GENERATION_HOST",
	"FI_CUSTODY_TRANSPORT_HOST",
	"FI_DEVFS_RULESET",
	"FI_HOSTNAME",
	"FI_HOST_ADMIN_ADDRESS",
	"FI_HOST_ADMIN_GATEWAY",
	"FI_HOST_ADMIN_IF",
	"FI_HOST_DNS_SEARCH",
	"FI_HOST_DNS_SERVER_1",
	"FI_INGEST_CONFIG_HOST",
	"FI_INGEST_FSTAB",
	"FI_INGEST_MGMT_ADDRESS",
	"FI_INGEST_MGMT_HOST_IF",
	"FI_INGEST_MGMT_JAIL_IF",
	"FI_INGEST_ROOT",
	"FI_INGEST_WORK_ADDRESS",
	"FI_INGEST_WORK_HOST_IF",
	"FI_INGEST_WORK_JAIL_IF",
	"FI_JAIL_DATASET_ROOT",
	"FI_JAIL_ROOT_BASE",
	"FI_JAIL_TEMPLATE_SNAPSHOT",
	"FI_MGMT_BRIDGE",
	"FI_MGMT_GATEWAY",
	"FI_MGMT_NETWORK",
	"FI_READY_HOST",
	"FI_RECEIVER_CONFIG_HOST",
	"FI_RECEIVER_DNS_SEARCH",
	"FI_RECEIVER_DNS_SERVER",
	"FI_RECEIVER_EXTERNAL_ADDRESS",
	"FI_RECEIVER_EXTERNAL_BRIDGE",
	"FI_RECEIVER_EXTERNAL_GATEWAY",
	"FI_RECEIVER_EXTERNAL_HOST_IF",
	"FI_RECEIVER_EXTERNAL_IF",
	"FI_RECEIVER_EXTERNAL_JAIL_IF",
	"FI_RECEIVER_EXTERNAL_NETWORK",
	"FI_RECEIVER_FSTAB",
	"FI_RECEIVER_MGMT_ADDRESS",
	"FI_RECEIVER_MGMT_HOST_IF",
	"FI_RECEIVER_MGMT_JAIL_IF",
	"FI_RECEIVER_ROOT",
	"FI_RECEIVER_WORK_ADDRESS",
	"FI_RECEIVER_WORK_HOST_IF",
	"FI_RECEIVER_WORK_JAIL_IF",
	"FI_RECORDED_HOST",
	"FI_RUNTIME_GID",
	"FI_RUNTIME_SOURCE_ID",
	"FI_RUNTIME_UID",
	"FI_SOR_DB_FSTAB",
	"FI_SOR_DB_MGMT_ADDRESS",
	"FI_SOR_DB_MGMT_HOST_IF",
	"FI_SOR_DB_MGMT_JAIL_IF",
	"FI_SOR_DB_ROOT",
	"FI_SOR_DB_WORK_ADDRESS",
	"FI_SOR_DB_WORK_HOST_IF",
	"FI_SOR_DB_WORK_JAIL_IF",
	"FI_SOR_POSTGRES_HOST",
	"FI_WORK_BRIDGE",
	"FI_WORK_NETWORK",
	"FI_ZPOOL",
}

var vnetInterfaceKeys = []string{
	"FI_RECEIVER_EXTERNAL_HOST_IF",
	"FI_RECEIVER_EXTERNAL_JAIL_IF",
	"FI_RECEIVER_MGMT_HOST_IF",
	"FI_RECEIVER_MGMT_JAIL_IF",
	"FI_RECEIVER_WORK_HOST_IF",
	"FI_RECEIVER_WORK_JAIL_IF",
	"FI_INGEST_MGMT_HOST_IF",
	"FI_INGEST_MGMT_JAIL_IF",
	"FI_INGEST_WORK_HOST_IF",
	"FI_INGEST_WORK_JAIL_IF",
	"FI_SOR_DB_MGMT_HOST_IF",
	"FI_SOR_DB_MGMT_JAIL_IF",
	"FI_SOR_DB_WORK_HOST_IF",
	"FI_SOR_DB_WORK_JAIL_IF",
}

// -----------------------------------------------------------------------------
// Public operations
// -----------------------------------------------------------------------------

func LoadConfig(path string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open configuration: %w", err)
	}
	defer file.Close()

	config, err := ParseConfig(file)
	if err != nil {
		return Config{}, err
	}

	if err := ValidateConfig(config); err != nil {
		return Config{}, err
	}

	return config, nil
}

func ParseConfig(reader io.Reader) (Config, error) {
	values := make(map[string]string)

	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 1024*1024)

	lineNumber := 0

	for scanner.Scan() {
		lineNumber++

		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if !configLinePattern.MatchString(line) {
			return Config{}, fmt.Errorf(
				"line %d: invalid configuration syntax",
				lineNumber,
			)
		}

		separator := strings.IndexByte(line, '=')
		key := line[:separator]
		quotedValue := line[separator+1:]
		value := strings.TrimSuffix(
			strings.TrimPrefix(quotedValue, `"`),
			`"`,
		)

		if _, ok := allowedKeys[key]; !ok {
			return Config{}, fmt.Errorf(
				"line %d: unknown configuration key: %s",
				lineNumber,
				key,
			)
		}

		if _, exists := values[key]; exists {
			return Config{}, fmt.Errorf(
				"line %d: duplicate configuration key: %s",
				lineNumber,
				key,
			)
		}

		if !configValuePattern.MatchString(value) {
			return Config{}, fmt.Errorf(
				"line %d: unsafe or unsupported characters in %s",
				lineNumber,
				key,
			)
		}

		values[key] = value
	}

	if err := scanner.Err(); err != nil {
		return Config{}, fmt.Errorf("read configuration: %w", err)
	}

	return Config{values: values}, nil
}

func ValidateConfig(config Config) error {
	if err := validateRequired(config); err != nil {
		return err
	}

	if err := validateNames(config); err != nil {
		return err
	}

	if err := validateNumbers(config); err != nil {
		return err
	}

	if err := validateInterfaces(config); err != nil {
		return err
	}

	if err := validateNetworks(config); err != nil {
		return err
	}

	if err := validateStorageAndPaths(config); err != nil {
		return err
	}

	return nil
}

func (config Config) Value(key string) string {
	return config.values[key]
}

// -----------------------------------------------------------------------------
// Name validation
// -----------------------------------------------------------------------------

func validateDNSName(key string, value string) error {
	if len(value) > 253 {
		return fmt.Errorf("%s exceeds 253 characters", key)
	}

	if !dnsNamePattern.MatchString(value) {
		return fmt.Errorf(
			"%s is not an accepted DNS search domain: %s",
			key,
			value,
		)
	}

	if strings.Contains(value, "..") ||
		strings.Contains(value, ".-") ||
		strings.Contains(value, "-.") {
		return fmt.Errorf(
			"%s contains an invalid DNS label boundary: %s",
			key,
			value,
		)
	}

	for _, label := range strings.Split(value, ".") {
		if len(label) > 63 {
			return fmt.Errorf(
				"%s contains a DNS label longer than 63 characters: %s",
				key,
				value,
			)
		}
	}

	return nil
}

func validateHostname(value string) error {
	if len(value) > 253 {
		return fmt.Errorf("FI_HOSTNAME exceeds 253 characters")
	}

	if !hostnamePattern.MatchString(value) {
		return fmt.Errorf(
			"FI_HOSTNAME is not an accepted hostname: %s",
			value,
		)
	}

	if strings.Contains(value, "..") ||
		strings.Contains(value, ".-") ||
		strings.Contains(value, "-.") {
		return fmt.Errorf(
			"FI_HOSTNAME contains an invalid hostname label boundary: %s",
			value,
		)
	}

	for _, label := range strings.Split(value, ".") {
		if len(label) > 63 {
			return fmt.Errorf(
				"FI_HOSTNAME contains a label longer than 63 characters: %s",
				value,
			)
		}
	}

	return nil
}

func validateNames(config Config) error {
	if err := validateHostname(config.Value("FI_HOSTNAME")); err != nil {
		return err
	}

	if err := validateRuntimeSource(
		config.Value("FI_RUNTIME_SOURCE_ID"),
	); err != nil {
		return err
	}

	if err := validateDNSName(
		"FI_HOST_DNS_SEARCH",
		config.Value("FI_HOST_DNS_SEARCH"),
	); err != nil {
		return err
	}

	if err := validateDNSName(
		"FI_RECEIVER_DNS_SEARCH",
		config.Value("FI_RECEIVER_DNS_SEARCH"),
	); err != nil {
		return err
	}

	if !poolNamePattern.MatchString(config.Value("FI_ZPOOL")) {
		return fmt.Errorf(
			"FI_ZPOOL is not an accepted pool name: %s",
			config.Value("FI_ZPOOL"),
		)
	}

	return nil
}

func validateRuntimeSource(value string) error {
	if len(value) > 253 {
		return fmt.Errorf("FI_RUNTIME_SOURCE_ID exceeds 253 characters")
	}

	if !runtimeSourcePattern.MatchString(value) {
		return fmt.Errorf(
			"FI_RUNTIME_SOURCE_ID contains unsupported characters: %s",
			value,
		)
	}

	if strings.Contains(value, "..") {
		return fmt.Errorf(
			"FI_RUNTIME_SOURCE_ID contains an empty label: %s",
			value,
		)
	}

	return nil
}

// -----------------------------------------------------------------------------
// Numeric validation
// -----------------------------------------------------------------------------

func parsePositiveDecimal(key string, value string) (uint64, error) {
	number, err := strconv.ParseUint(value, 10, 64)
	if err != nil || number == 0 {
		return 0, fmt.Errorf(
			"%s must be a non-zero decimal integer",
			key,
		)
	}

	return number, nil
}

func validateNumbers(config Config) error {
	uid, err := parsePositiveDecimal(
		"FI_RUNTIME_UID",
		config.Value("FI_RUNTIME_UID"),
	)
	if err != nil {
		return err
	}

	if uid < 1000 || uid > 32000 {
		return fmt.Errorf(
			"FI_RUNTIME_UID must be between 1000 and 32000",
		)
	}

	gid, err := parsePositiveDecimal(
		"FI_RUNTIME_GID",
		config.Value("FI_RUNTIME_GID"),
	)
	if err != nil {
		return err
	}

	if gid < 1000 || gid > 32000 {
		return fmt.Errorf(
			"FI_RUNTIME_GID must be between 1000 and 32000",
		)
	}

	ruleset, err := parsePositiveDecimal(
		"FI_DEVFS_RULESET",
		config.Value("FI_DEVFS_RULESET"),
	)
	if err != nil {
		return err
	}

	if ruleset < 100 {
		return fmt.Errorf("FI_DEVFS_RULESET must be at least 100")
	}

	return nil
}

// -----------------------------------------------------------------------------
// Interface validation
// -----------------------------------------------------------------------------

func validateInterfaceName(key string, value string) error {
	if !interfaceNamePattern.MatchString(value) {
		return fmt.Errorf(
			"%s contains invalid interface-name characters",
			key,
		)
	}

	if len(value) > 15 {
		return fmt.Errorf(
			"%s exceeds the FreeBSD interface-name limit: %s",
			key,
			value,
		)
	}

	return nil
}

func validateInterfaces(config Config) error {
	interfaceKeys := []string{
		"FI_HOST_ADMIN_IF",
		"FI_MGMT_BRIDGE",
		"FI_WORK_BRIDGE",
		"FI_RECEIVER_EXTERNAL_IF",
		"FI_RECEIVER_EXTERNAL_BRIDGE",
	}

	interfaceKeys = append(interfaceKeys, vnetInterfaceKeys...)

	for _, key := range interfaceKeys {
		if err := validateInterfaceName(
			key,
			config.Value(key),
		); err != nil {
			return err
		}
	}

	distinctKeys := []string{
		"FI_RECEIVER_EXTERNAL_IF",
		"FI_RECEIVER_EXTERNAL_BRIDGE",
	}
	distinctKeys = append(distinctKeys, vnetInterfaceKeys...)

	if err := requireDistinct(
		config,
		"VNET interface names",
		distinctKeys,
	); err != nil {
		return err
	}

	hostAdmin := config.Value("FI_HOST_ADMIN_IF")
	mgmtBridge := config.Value("FI_MGMT_BRIDGE")
	workBridge := config.Value("FI_WORK_BRIDGE")
	receiverIF := config.Value("FI_RECEIVER_EXTERNAL_IF")
	receiverBridge := config.Value("FI_RECEIVER_EXTERNAL_BRIDGE")

	pairs := [][3]string{
		{"FI_HOST_ADMIN_IF", hostAdmin, receiverIF},
		{"FI_HOST_ADMIN_IF", hostAdmin, receiverBridge},
		{"FI_HOST_ADMIN_IF", hostAdmin, mgmtBridge},
		{"FI_HOST_ADMIN_IF", hostAdmin, workBridge},
		{"FI_RECEIVER_EXTERNAL_IF", receiverIF, mgmtBridge},
		{"FI_RECEIVER_EXTERNAL_IF", receiverIF, workBridge},
		{"FI_RECEIVER_EXTERNAL_IF", receiverIF, receiverBridge},
		{"FI_RECEIVER_EXTERNAL_BRIDGE", receiverBridge, mgmtBridge},
		{"FI_RECEIVER_EXTERNAL_BRIDGE", receiverBridge, workBridge},
		{"FI_MGMT_BRIDGE", mgmtBridge, workBridge},
	}

	for _, pair := range pairs {
		if pair[1] == pair[2] {
			return fmt.Errorf(
				"%s conflicts with another configured interface: %s",
				pair[0],
				pair[1],
			)
		}
	}

	reserved := map[string]struct{}{
		hostAdmin:      {},
		mgmtBridge:     {},
		workBridge:     {},
		receiverBridge: {},
	}

	for _, key := range vnetInterfaceKeys {
		value := config.Value(key)

		if _, exists := reserved[value]; exists {
			return fmt.Errorf(
				"%s conflicts with a reserved host interface: %s",
				key,
				value,
			)
		}
	}

	return nil
}

// -----------------------------------------------------------------------------
// Network validation
// -----------------------------------------------------------------------------

func parseIPv4Address(key string, value string) (netip.Addr, error) {
	address, err := netip.ParseAddr(value)
	if err != nil || !address.Is4() {
		return netip.Addr{}, fmt.Errorf(
			"%s is not an accepted IPv4 address: %s",
			key,
			value,
		)
	}

	return address, nil
}

func parseIPv4Prefix(
	key string,
	value string,
	requireNetwork bool,
) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil || !prefix.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf(
			"%s is not a valid IPv4 CIDR value: %s",
			key,
			value,
		)
	}

	if prefix.Bits() < 1 || prefix.Bits() > 32 {
		return netip.Prefix{}, fmt.Errorf(
			"%s has unsupported IPv4 prefix length: %s",
			key,
			value,
		)
	}

	if requireNetwork && prefix != prefix.Masked() {
		return netip.Prefix{}, fmt.Errorf(
			"%s is not a canonical network address: %s",
			key,
			value,
		)
	}

	return prefix, nil
}

func prefixesOverlap(
	left netip.Prefix,
	right netip.Prefix,
) bool {
	left = left.Masked()
	right = right.Masked()

	return left.Contains(right.Addr()) ||
		right.Contains(left.Addr())
}

func requireAddressInNetwork(
	networkKey string,
	network netip.Prefix,
	addressKey string,
	address netip.Addr,
) error {
	if !network.Contains(address) {
		return fmt.Errorf(
			"%s is not contained in %s",
			addressKey,
			networkKey,
		)
	}

	return nil
}

func validateNetworks(config Config) error {
	hostAdmin, err := parseIPv4Prefix(
		"FI_HOST_ADMIN_ADDRESS",
		config.Value("FI_HOST_ADMIN_ADDRESS"),
		false,
	)
	if err != nil {
		return err
	}

	mgmtNetwork, err := parseIPv4Prefix(
		"FI_MGMT_NETWORK",
		config.Value("FI_MGMT_NETWORK"),
		true,
	)
	if err != nil {
		return err
	}

	workNetwork, err := parseIPv4Prefix(
		"FI_WORK_NETWORK",
		config.Value("FI_WORK_NETWORK"),
		true,
	)
	if err != nil {
		return err
	}

	receiverNetwork, err := parseIPv4Prefix(
		"FI_RECEIVER_EXTERNAL_NETWORK",
		config.Value("FI_RECEIVER_EXTERNAL_NETWORK"),
		true,
	)
	if err != nil {
		return err
	}

	receiverAddress, err := parseIPv4Prefix(
		"FI_RECEIVER_EXTERNAL_ADDRESS",
		config.Value("FI_RECEIVER_EXTERNAL_ADDRESS"),
		false,
	)
	if err != nil {
		return err
	}

	if prefixesOverlap(
		mgmtNetwork,
		workNetwork,
	) {
		return fmt.Errorf(
			"management and workload networks overlap",
		)
	}

	if prefixesOverlap(
		receiverNetwork,
		mgmtNetwork,
	) ||
		prefixesOverlap(
			receiverNetwork,
			workNetwork,
		) {
		return fmt.Errorf(
			"receiver external network overlaps an FI internal network",
		)
	}

	hostGateway, err := parseIPv4Address(
		"FI_HOST_ADMIN_GATEWAY",
		config.Value("FI_HOST_ADMIN_GATEWAY"),
	)
	if err != nil {
		return err
	}

	if !hostAdmin.Masked().Contains(hostGateway) {
		return fmt.Errorf(
			"FI_HOST_ADMIN_GATEWAY is not contained in FI_HOST_ADMIN_ADDRESS network",
		)
	}

	if hostAdmin.Addr() == hostGateway {
		return fmt.Errorf(
			"FI_HOST_ADMIN_ADDRESS conflicts with FI_HOST_ADMIN_GATEWAY",
		)
	}

	if prefixesOverlap(
		hostAdmin.Masked(),
		mgmtNetwork,
	) {
		return fmt.Errorf(
			"FI_HOST_ADMIN_ADDRESS overlaps FI_MGMT_NETWORK",
		)
	}

	if prefixesOverlap(
		hostAdmin.Masked(),
		workNetwork,
	) {
		return fmt.Errorf(
			"FI_HOST_ADMIN_ADDRESS overlaps FI_WORK_NETWORK",
		)
	}

	receiverGateway, err := parseIPv4Address(
		"FI_RECEIVER_EXTERNAL_GATEWAY",
		config.Value("FI_RECEIVER_EXTERNAL_GATEWAY"),
	)
	if err != nil {
		return err
	}

	if receiverAddress.Masked() != receiverNetwork {
		return fmt.Errorf(
			"FI_RECEIVER_EXTERNAL_ADDRESS does not use FI_RECEIVER_EXTERNAL_NETWORK prefix",
		)
	}

	if err := requireAddressInNetwork(
		"FI_RECEIVER_EXTERNAL_NETWORK",
		receiverNetwork,
		"FI_RECEIVER_EXTERNAL_ADDRESS",
		receiverAddress.Addr(),
	); err != nil {
		return err
	}

	if err := requireAddressInNetwork(
		"FI_RECEIVER_EXTERNAL_NETWORK",
		receiverNetwork,
		"FI_RECEIVER_EXTERNAL_GATEWAY",
		receiverGateway,
	); err != nil {
		return err
	}

	if receiverAddress.Addr() == receiverGateway {
		return fmt.Errorf(
			"FI_RECEIVER_EXTERNAL_ADDRESS conflicts with FI_RECEIVER_EXTERNAL_GATEWAY",
		)
	}

	if hostAdmin.Addr() == receiverAddress.Addr() {
		return fmt.Errorf(
			"FI_HOST_ADMIN_ADDRESS conflicts with FI_RECEIVER_EXTERNAL_ADDRESS",
		)
	}

	if _, err := parseIPv4Address(
		"FI_HOST_DNS_SERVER_1",
		config.Value("FI_HOST_DNS_SERVER_1"),
	); err != nil {
		return err
	}

	if dns2 := config.Value("FI_HOST_DNS_SERVER_2"); dns2 != "" {
		second, err := parseIPv4Address(
			"FI_HOST_DNS_SERVER_2",
			dns2,
		)
		if err != nil {
			return err
		}

		first, _ := parseIPv4Address(
			"FI_HOST_DNS_SERVER_1",
			config.Value("FI_HOST_DNS_SERVER_1"),
		)

		if first == second {
			return fmt.Errorf(
				"FI_HOST_DNS_SERVER_2 duplicates FI_HOST_DNS_SERVER_1",
			)
		}
	}

	if _, err := parseIPv4Address(
		"FI_RECEIVER_DNS_SERVER",
		config.Value("FI_RECEIVER_DNS_SERVER"),
	); err != nil {
		return err
	}

	mgmtGateway, err := parseIPv4Address(
		"FI_MGMT_GATEWAY",
		config.Value("FI_MGMT_GATEWAY"),
	)
	if err != nil {
		return err
	}

	if err := requireAddressInNetwork(
		"FI_MGMT_NETWORK",
		mgmtNetwork,
		"FI_MGMT_GATEWAY",
		mgmtGateway,
	); err != nil {
		return err
	}

	addressContracts := []struct {
		key     string
		network netip.Prefix
		name    string
	}{
		{"FI_RECEIVER_MGMT_ADDRESS", mgmtNetwork, "FI_MGMT_NETWORK"},
		{"FI_RECEIVER_WORK_ADDRESS", workNetwork, "FI_WORK_NETWORK"},
		{"FI_INGEST_MGMT_ADDRESS", mgmtNetwork, "FI_MGMT_NETWORK"},
		{"FI_INGEST_WORK_ADDRESS", workNetwork, "FI_WORK_NETWORK"},
		{"FI_SOR_DB_MGMT_ADDRESS", mgmtNetwork, "FI_MGMT_NETWORK"},
		{"FI_SOR_DB_WORK_ADDRESS", workNetwork, "FI_WORK_NETWORK"},
	}

	seen := map[netip.Addr]string{
		mgmtGateway: "FI_MGMT_GATEWAY",
	}

	for _, contract := range addressContracts {
		prefix, err := parseIPv4Prefix(
			contract.key,
			config.Value(contract.key),
			false,
		)
		if err != nil {
			return err
		}

		if prefix.Masked() != contract.network {
			return fmt.Errorf(
				"%s does not use %s prefix",
				contract.key,
				contract.name,
			)
		}

		if err := requireAddressInNetwork(
			contract.name,
			contract.network,
			contract.key,
			prefix.Addr(),
		); err != nil {
			return err
		}

		if prior, exists := seen[prefix.Addr()]; exists {
			return fmt.Errorf(
				"jail interface addresses contain duplicate address: %s and %s",
				prior,
				contract.key,
			)
		}

		seen[prefix.Addr()] = contract.key
	}

	return nil
}

// -----------------------------------------------------------------------------
// Storage and path validation
// -----------------------------------------------------------------------------

func requireDistinct(
	config Config,
	description string,
	keys []string,
) error {
	seen := make(map[string]string)

	for _, key := range keys {
		value := config.Value(key)

		if prior, exists := seen[value]; exists {
			return fmt.Errorf(
				"%s contains duplicate value %s: %s and %s",
				description,
				value,
				prior,
				key,
			)
		}

		seen[value] = key
	}

	return nil
}

func validateAbsolutePath(key string, value string) error {
	if !absolutePathPattern.MatchString(value) {
		return fmt.Errorf(
			"%s is not an accepted absolute path: %s",
			key,
			value,
		)
	}

	if path.Clean(value) != value {
		return fmt.Errorf(
			"%s is not a canonical absolute path: %s",
			key,
			value,
		)
	}

	return nil
}

func validateStorageAndPaths(config Config) error {
	if !datasetPattern.MatchString(
		config.Value("FI_JAIL_DATASET_ROOT"),
	) {
		return fmt.Errorf(
			"FI_JAIL_DATASET_ROOT is not an accepted ZFS dataset name",
		)
	}

	if !snapshotPattern.MatchString(
		config.Value("FI_JAIL_TEMPLATE_SNAPSHOT"),
	) {
		return fmt.Errorf(
			"FI_JAIL_TEMPLATE_SNAPSHOT is not an accepted ZFS snapshot name",
		)
	}

	if !strings.HasPrefix(
		config.Value("FI_JAIL_DATASET_ROOT"),
		config.Value("FI_ZPOOL")+"/",
	) {
		return fmt.Errorf(
			"FI_JAIL_DATASET_ROOT is not beneath FI_ZPOOL",
		)
	}

	pathKeys := []string{
		"FI_JAIL_ROOT_BASE",
		"FI_RECEIVER_ROOT",
		"FI_INGEST_ROOT",
		"FI_SOR_DB_ROOT",
		"FI_CUSTODY_GENERATION_HOST",
		"FI_CUSTODY_TRANSPORT_HOST",
		"FI_RECORDED_HOST",
		"FI_READY_HOST",
		"FI_RECEIVER_CONFIG_HOST",
		"FI_INGEST_CONFIG_HOST",
		"FI_SOR_POSTGRES_HOST",
		"FI_RECEIVER_FSTAB",
		"FI_INGEST_FSTAB",
		"FI_SOR_DB_FSTAB",
	}

	for _, key := range pathKeys {
		if err := validateAbsolutePath(
			key,
			config.Value(key),
		); err != nil {
			return err
		}
	}

	if config.Value("FI_RECEIVER_FSTAB") != "/etc/fstab.fi-receiver" {
		return fmt.Errorf(
			"FI_RECEIVER_FSTAB must be /etc/fstab.fi-receiver",
		)
	}

	if config.Value("FI_INGEST_FSTAB") != "/etc/fstab.fi-ingest" {
		return fmt.Errorf(
			"FI_INGEST_FSTAB must be /etc/fstab.fi-ingest",
		)
	}

	if config.Value("FI_SOR_DB_FSTAB") != "/etc/fstab.fi-sor-db" {
		return fmt.Errorf(
			"FI_SOR_DB_FSTAB must be /etc/fstab.fi-sor-db",
		)
	}

	jailBase := strings.TrimSuffix(
		config.Value("FI_JAIL_ROOT_BASE"),
		"/",
	) + "/"

	for _, key := range []string{
		"FI_RECEIVER_ROOT",
		"FI_INGEST_ROOT",
		"FI_SOR_DB_ROOT",
	} {
		if !strings.HasPrefix(config.Value(key), jailBase) {
			return fmt.Errorf(
				"%s is not beneath FI_JAIL_ROOT_BASE",
				key,
			)
		}
	}

	if err := requireDistinct(
		config,
		"production jail roots",
		[]string{
			"FI_RECEIVER_ROOT",
			"FI_INGEST_ROOT",
			"FI_SOR_DB_ROOT",
		},
	); err != nil {
		return err
	}

	if err := requireDistinct(
		config,
		"host-side fstab paths",
		[]string{
			"FI_RECEIVER_FSTAB",
			"FI_INGEST_FSTAB",
			"FI_SOR_DB_FSTAB",
		},
	); err != nil {
		return err
	}

	return nil
}

// -----------------------------------------------------------------------------
// Required-value validation
// -----------------------------------------------------------------------------

func validateRequired(config Config) error {
	missing := make([]string, 0)

	for _, key := range requiredKeys {
		if config.Value(key) == "" {
			missing = append(missing, key)
		}
	}

	if len(missing) == 0 {
		return nil
	}

	sort.Strings(missing)

	return fmt.Errorf(
		"required configuration values are empty or absent: %s",
		strings.Join(missing, ", "),
	)
}
