// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package config

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// VolumeConfigVersion is deliberately separate from Config.Version11: the
// existing installer and collector are not authorized to interpret this model
// until their native volume discovery/approval contracts are implemented.
const VolumeConfigVersion = "2.0"

const (
	maxEnrollmentVolumes = 128
	maxRootPolicies      = 4096
)

// VolumeEnrollment records operator-requested volume scope. The GUID is only a
// locator until native discovery proves the expected 64-bit NTFS serial and
// current identity; configuration alone never authorizes an I/O operation.
type VolumeEnrollment struct {
	ID     string
	GUID   string
	Serial string
}

// RootPolicy names a *volume-relative* root. Runtime must resolve this root
// through an approved native volume handle and independently prove containment.
// PolicyDepth is requested, not authority to read protected objects by path.
type RootPolicy struct {
	ID           string
	VolumeID     string
	RelativeRoot string
	Depth        PolicyDepth
}

type PolicyDepth string

const (
	DepthMetadata PolicyDepth = "metadata"
	DepthSecurity PolicyDepth = "security"
	DepthContent  PolicyDepth = "content"
)

type VolumeConfig struct {
	Version  string
	Volumes  []VolumeEnrollment
	Policies []RootPolicy
}

type volumeFields struct {
	guid, serial string
	present      map[string]bool
}

type policyFields struct {
	volume, root, depth string
	present             map[string]bool
}

// ParseVolumeV2 parses the strict declaration layer of the volume-first model.
// It never opens a volume, enables auditing, mutates state or falls back to a
// root-centric configuration. Unknown/duplicated/incomplete directives fail.
// Native installation still requires operator approval and rediscovery.
func ParseVolumeV2(reader io.Reader) (VolumeConfig, error) {
	if reader == nil {
		return VolumeConfig{}, errors.New("volume configuration reader is required")
	}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 64*1024)
	versions := 0
	volumes := map[string]*volumeFields{}
	policies := map[string]*policyFields{}
	seen := map[string]bool{}
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if lineNo == 1 {
			line = strings.TrimPrefix(line, "\uFEFF")
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if versions == 0 {
			if line != "version_id: 2.0" {
				return VolumeConfig{}, fmt.Errorf("line %d: first directive must be version_id: 2.0", lineNo)
			}
			versions++
			continue
		}
		if strings.HasPrefix(line, "version_id") {
			return VolumeConfig{}, fmt.Errorf("line %d: duplicate version_id", lineNo)
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return VolumeConfig{}, fmt.Errorf("line %d: expected field = value", lineNo)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if value == "" {
			return VolumeConfig{}, fmt.Errorf("line %d: empty %q", lineNo, key)
		}
		if seen[key] {
			return VolumeConfig{}, fmt.Errorf("line %d: duplicate %q", lineNo, key)
		}
		seen[key] = true
		parts := strings.Split(key, ".")
		if len(parts) != 3 || !validVolumeConfigID(parts[1]) {
			return VolumeConfig{}, fmt.Errorf("line %d: unrecognized volume/policy field %q", lineNo, key)
		}
		switch parts[0] {
		case "volume":
			if parts[2] != "guid" && parts[2] != "serial" {
				return VolumeConfig{}, fmt.Errorf("line %d: unknown volume field %q", lineNo, key)
			}
			item := volumes[parts[1]]
			if item == nil {
				if len(volumes) >= maxEnrollmentVolumes {
					return VolumeConfig{}, errors.New("too many enrolled volumes")
				}
				item = &volumeFields{present: map[string]bool{}}
				volumes[parts[1]] = item
			}
			item.present[parts[2]] = true
			if parts[2] == "guid" {
				item.guid = value
			} else {
				item.serial = value
			}
		case "policy":
			if parts[2] != "volume" && parts[2] != "root" && parts[2] != "depth" {
				return VolumeConfig{}, fmt.Errorf("line %d: unknown policy field %q", lineNo, key)
			}
			item := policies[parts[1]]
			if item == nil {
				if len(policies) >= maxRootPolicies {
					return VolumeConfig{}, errors.New("too many governed policies")
				}
				item = &policyFields{present: map[string]bool{}}
				policies[parts[1]] = item
			}
			item.present[parts[2]] = true
			switch parts[2] {
			case "volume":
				item.volume = value
			case "root":
				item.root = value
			case "depth":
				item.depth = value
			}
		default:
			return VolumeConfig{}, fmt.Errorf("line %d: unknown field %q", lineNo, key)
		}
	}
	if err := scanner.Err(); err != nil {
		return VolumeConfig{}, fmt.Errorf("read volume config: %w", err)
	}
	if versions == 0 {
		return VolumeConfig{}, errors.New("missing version_id: 2.0")
	}
	if len(volumes) == 0 {
		return VolumeConfig{}, errors.New("at least one explicit volume enrollment is required")
	}

	out := VolumeConfig{Version: VolumeConfigVersion}
	for id, item := range volumes {
		if !item.present["guid"] || !item.present["serial"] {
			return VolumeConfig{}, fmt.Errorf("volume %q requires guid and serial", id)
		}
		guid, err := canonicalVolumeConfigGUID(item.guid)
		if err != nil {
			return VolumeConfig{}, fmt.Errorf("volume %q: %w", id, err)
		}
		if err := canonicalNonzeroDecimal(item.serial); err != nil {
			return VolumeConfig{}, fmt.Errorf("volume %q serial: %w", id, err)
		}
		out.Volumes = append(out.Volumes, VolumeEnrollment{ID: id, GUID: guid, Serial: item.serial})
	}
	sort.Slice(out.Volumes, func(i, j int) bool { return out.Volumes[i].ID < out.Volumes[j].ID })
	uniqueGUID := map[string]string{}
	for _, vol := range out.Volumes {
		if first, exists := uniqueGUID[vol.GUID]; exists {
			return VolumeConfig{}, fmt.Errorf("volumes %q and %q share the same GUID locator", first, vol.ID)
		}
		uniqueGUID[vol.GUID] = vol.ID
	}
	uniquePolicyRoots := map[string]string{}
	for id, item := range policies {
		if !item.present["volume"] || !item.present["root"] || !item.present["depth"] {
			return VolumeConfig{}, fmt.Errorf("policy %q requires volume, root, and depth", id)
		}
		if _, exists := volumes[item.volume]; !exists {
			return VolumeConfig{}, fmt.Errorf("policy %q references unenrolled volume %q", id, item.volume)
		}
		root, err := canonicalRelativeRoot(item.root)
		if err != nil {
			return VolumeConfig{}, fmt.Errorf("policy %q: %w", id, err)
		}
		depth := PolicyDepth(item.depth)
		if depth != DepthMetadata && depth != DepthSecurity && depth != DepthContent {
			return VolumeConfig{}, fmt.Errorf("policy %q: unsupported depth %q", id, item.depth)
		}
		// Two policies may intentionally overlap, but the exact same root on
		// the same volume must have one policy authority, not conflicting IDs.
		key := item.volume + "\x00" + strings.ToLower(root)
		if first, exists := uniquePolicyRoots[key]; exists {
			return VolumeConfig{}, fmt.Errorf("policies %q and %q assign the same root", first, id)
		}
		uniquePolicyRoots[key] = id
		out.Policies = append(out.Policies, RootPolicy{ID: id, VolumeID: item.volume, RelativeRoot: root, Depth: depth})
	}
	sort.Slice(out.Policies, func(i, j int) bool { return out.Policies[i].ID < out.Policies[j].ID })
	return out, nil
}

// CanonicalVolumeV2 serializes a *validated* policy in stable order. Installer
// approval must bind these bytes AND live native volume rediscovery; a digest
// of configuration text cannot prove that an installed volume is unchanged.
func CanonicalVolumeV2(value VolumeConfig) ([]byte, error) {
	if value.Version != VolumeConfigVersion {
		return nil, errors.New("unsupported volume configuration version")
	}
	var b strings.Builder
	b.WriteString("version_id: 2.0\n")
	volumes := append([]VolumeEnrollment(nil), value.Volumes...)
	policies := append([]RootPolicy(nil), value.Policies...)
	sort.Slice(volumes, func(i, j int) bool { return volumes[i].ID < volumes[j].ID })
	sort.Slice(policies, func(i, j int) bool { return policies[i].ID < policies[j].ID })
	for _, v := range volumes {
		fmt.Fprintf(&b, "volume.%s.guid = %s\nvolume.%s.serial = %s\n", v.ID, v.GUID, v.ID, v.Serial)
	}
	for _, p := range policies {
		fmt.Fprintf(&b, "policy.%s.volume = %s\npolicy.%s.root = %s\npolicy.%s.depth = %s\n", p.ID, p.VolumeID, p.ID, p.RelativeRoot, p.ID, p.Depth)
	}
	normalized := []byte(b.String())
	checked, err := ParseVolumeV2(bytes.NewReader(normalized))
	if err != nil {
		return nil, fmt.Errorf("validate canonical volume configuration: %w", err)
	}
	if !sameVolumeConfig(value, checked) {
		return nil, errors.New("volume config does not match canonical round-trip")
	}
	return normalized, nil
}

func sameVolumeConfig(a, b VolumeConfig) bool {
	if a.Version != b.Version || len(a.Volumes) != len(b.Volumes) || len(a.Policies) != len(b.Policies) {
		return false
	}
	leftV := append([]VolumeEnrollment(nil), a.Volumes...)
	leftP := append([]RootPolicy(nil), a.Policies...)
	sort.Slice(leftV, func(i, j int) bool { return leftV[i].ID < leftV[j].ID })
	sort.Slice(leftP, func(i, j int) bool { return leftP[i].ID < leftP[j].ID })
	for i := range leftV {
		if leftV[i] != b.Volumes[i] {
			return false
		}
	}
	for i := range leftP {
		if leftP[i] != b.Policies[i] {
			return false
		}
	}
	return true
}

func validVolumeConfigID(s string) bool {
	if len(s) == 0 || len(s) > 64 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func canonicalVolumeConfigGUID(value string) (string, error) {
	const prefix = `\\?\Volume{`
	const suffix = `}\`
	if len(value) != len(prefix)+36+len(suffix) || !strings.EqualFold(value[:min(len(value), len(prefix))], prefix) || !strings.HasSuffix(value, suffix) {
		return "", errors.New("volume guid must be an exact Windows volume GUID path")
	}
	guid := value[len(prefix) : len(prefix)+36]
	for i := 0; i < 36; i++ {
		c := guid[i]
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return "", errors.New("invalid GUID separator")
			}
			continue
		}
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return "", errors.New("invalid GUID hex digit")
		}
	}
	return prefix + strings.ToLower(guid) + suffix, nil
}

func canonicalNonzeroDecimal(s string) error {
	if len(s) == 0 || s[0] < '1' || s[0] > '9' {
		return errors.New("serial must be nonzero canonical unsigned decimal")
	}
	for i := 1; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return errors.New("serial must be canonical unsigned decimal")
		}
	}
	if _, err := strconv.ParseUint(s, 10, 64); err != nil {
		return err
	}
	return nil
}

func canonicalRelativeRoot(root string) (string, error) {
	if !utf8.ValidString(root) {
		return "", errors.New("policy root must be valid UTF-8")
	}
	for _, char := range root {
		if char < 0x20 || char == 0x7f {
			return "", errors.New("policy root contains a control character")
		}
	}
	if root == `\` {
		return root, nil
	}
	if !strings.HasPrefix(root, `\`) || strings.HasPrefix(root, `\\`) || strings.ContainsAny(root, `/:*?"<>|`) {
		return "", errors.New("policy root must be a volume-relative NTFS path")
	}
	if strings.HasSuffix(root, `\`) {
		return "", errors.New("policy root must not have a trailing separator")
	}
	for _, part := range strings.Split(root[1:], `\`) {
		if part == "" || part == "." || part == ".." || strings.TrimSpace(part) != part || strings.HasSuffix(part, ".") {
			return "", errors.New("policy root has an empty, ambiguous or traversal segment")
		}
	}
	return root, nil
}
