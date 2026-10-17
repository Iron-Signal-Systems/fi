// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"unsafe"

	"github.com/Iron-Signal-Systems/fi/go/internal/windows/auditpolicy"
	"golang.org/x/sys/windows"
)

const (
	fiSACLChangeMask       uint32 = 0x000D0156
	fiSACLReadMask         uint32 = 0x00000001
	fiSACLAuditACEType     uint8  = 2
	fiSACLObjectInherit    uint8  = 0x01
	fiSACLContainerInherit uint8  = 0x02
	fiSACLInheritOnly      uint8  = 0x08
	fiSACLSuccess          uint8  = 0x40
	fiSACLFailure          uint8  = 0x80

	fiChangeACE = "(AU;OICISAFA;0x000D0156;;;WD)"
	fiReadACE   = "(AU;OISAFAIO;0x00000001;;;WD)"
)

// fiSACLSnapshot retains the *SACL only*: the installer never edits the DACL.
// SDDL captures unrelated audit ACEs and inheritance/protection control bits.
type fiSACLSnapshot struct {
	path         string
	originalSDDL string
	sha256       string
	protected    bool
	present      bool
	control      uint16
	saclBytes    string
	hasChange    bool
	hasRead      bool
	// auditACEs captures complete native ACEs (including flags, mask and SID).
	// SDDL control metadata is kept separately; automatic inheritance may
	// normalize that metadata even when the audit entries are restored.
	auditACEs []string
}

// fiSACLAuditFlags tests the two FI root contracts without mistaking a read
// rule for a change rule. Existing sufficient audit ACEs must be retained.
func fiSACLAuditFlags(mask uint32, flags uint8, change bool) bool {
	required := fiSACLReadMask
	requiredFlags := fiSACLObjectInherit | fiSACLSuccess | fiSACLFailure
	if change {
		required = fiSACLChangeMask
		requiredFlags |= fiSACLContainerInherit
		if flags&fiSACLInheritOnly != 0 {
			return false
		}
	}
	return mask&required == required && flags&requiredFlags == requiredFlags
}

func fiSACLWithRequired(sddl string, addChange, addRead bool) (string, error) {
	if !addChange && !addRead {
		return sddl, nil
	}
	// GetNamedSecurityInfo is called for SACL_SECURITY_INFORMATION only.
	// Refuse any unrecognized descriptor framing instead of risking DACL edits.
	if sddl == "" {
		sddl = "S:"
	}
	if !strings.HasPrefix(sddl, "S:") || strings.Contains(sddl[2:], "D:") || strings.Contains(sddl[2:], "O:") || strings.Contains(sddl[2:], "G:") {
		return "", fmt.Errorf("SACL snapshot contains unexpected non-SACL descriptor sections")
	}
	if addChange {
		sddl += fiChangeACE
	}
	if addRead {
		sddl += fiReadACE
	}
	return sddl, nil
}

func fiSACLRoots(roots []string) ([]string, error) {
	found := make(map[string]string)
	for _, root := range roots {
		root = strings.TrimSpace(root)
		if root == "" || !filepath.IsAbs(root) || strings.HasPrefix(root, `\\`) {
			return nil, fmt.Errorf("invalid local governed root %q", root)
		}
		root = filepath.Clean(root)
		key := strings.ToLower(root)
		if _, ok := found[key]; !ok {
			found[key] = root
		}
	}
	keys := make([]string, 0, len(found))
	for key := range found {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for i := 1; i < len(keys); i++ {
		// Nested roots require a separate overlapping-inheritance transaction.
		// They must not be partially reconciled in one SACL transaction.
		for j := 0; j < i; j++ {
			if strings.HasPrefix(keys[i], strings.TrimRight(keys[j], `\`)+`\`) {
				return nil, fmt.Errorf("overlapping FI governed roots require explicit SACL inheritance handling: %s and %s", found[keys[j]], found[keys[i]])
			}
		}
	}
	result := make([]string, 0, len(keys))
	for _, key := range keys {
		result = append(result, found[key])
	}
	return result, nil
}

// fiQueryRootSACL temporarily enables an already-assigned privilege in the
// elevated installer process. FICollector's token is never modified.
func fiQueryRootSACL(path string) (fiSACLSnapshot, error) {
	snapshot := fiSACLSnapshot{path: path, auditACEs: []string{}}
	err := auditpolicy.WithSecurityPrivilege(func() error {
		descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.SACL_SECURITY_INFORMATION)
		if err != nil {
			return fmt.Errorf("GetNamedSecurityInfo SACL %s: %w", path, err)
		}
		control, _, err := descriptor.Control()
		if err != nil {
			return err
		}
		snapshot.protected = control&windows.SE_SACL_PROTECTED != 0
		snapshot.control = uint16(control)
		sacl, _, err := descriptor.SACL()
		if err != nil && !errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) {
			return err
		}
		snapshot.present = err == nil
		snapshot.originalSDDL = descriptor.String()
		if snapshot.present && !strings.HasPrefix(snapshot.originalSDDL, "S:") {
			return fmt.Errorf("SACL descriptor for %s could not be serialized without loss", path)
		}
		if !snapshot.present || sacl == nil {
			return nil
		}
		// x/sys/windows.ACL exposes AceCount but not the native AclSize.
		// An ACL begins with an 8-byte header; bytes [2:4] hold AclSize
		// as a little-endian uint16 (Windows ACL layout).
		aclHeader := unsafe.Slice((*byte)(unsafe.Pointer(sacl)), 8)
		aclSize := int(binary.LittleEndian.Uint16(aclHeader[2:4]))
		if aclSize < len(aclHeader) {
			return fmt.Errorf("invalid SACL ACL size for %s: %d", path, aclSize)
		}
		// Preserve the native ACL header, ACE order and bytes, rather than
		// relying on SDDL or a sorted multiset of audit ACEs.
		snapshot.saclBytes = hex.EncodeToString(unsafe.Slice(
			(*byte)(unsafe.Pointer(sacl)), aclSize,
		))
		if sacl.AceCount > 4096 {
			return fmt.Errorf("SACL ACE count for %s exceeds verification bound: %d", path, sacl.AceCount)
		}
		for i := uint32(0); i < uint32(sacl.AceCount); i++ {
			var ace *windows.ACCESS_ALLOWED_ACE
			if err := windows.GetAce(sacl, i, &ace); err != nil {
				return fmt.Errorf("SACL ACE %d for %s: %w", i, path, err)
			}
			if ace == nil || ace.Header.AceSize < 4 || ace.Header.AceSize > 8192 {
				return fmt.Errorf("invalid SACL ACE %d size for %s", i, path)
			}
			// GetAce points into the descriptor; capture a copy before it is freed.
			bytes := unsafe.Slice((*byte)(unsafe.Pointer(ace)), int(ace.Header.AceSize))
			snapshot.auditACEs = append(snapshot.auditACEs, hex.EncodeToString(bytes))
			if ace.Header.AceType != fiSACLAuditACEType || ace.Header.AceSize < 12 {
				continue
			}
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if sid.String() != "S-1-1-0" {
				continue
			}
			mask := uint32(ace.Mask)
			flags := ace.Header.AceFlags
			if fiSACLAuditFlags(mask, flags, true) {
				snapshot.hasChange = true
			}
			if fiSACLAuditFlags(mask, flags, false) {
				snapshot.hasRead = true
			}
		}
		return nil
	})
	if err == nil {
		// A sealed Approval 2 digest must cover native SACL bytes and
		// control bits, not merely the serialized SDDL spelling.
		fingerprint := fmt.Sprintf("present=%t control=%04x sddl=%s acl=%s",
			snapshot.present, snapshot.control, snapshot.originalSDDL, snapshot.saclBytes)
		hash := sha256.Sum256([]byte(fingerprint))
		snapshot.sha256 = hex.EncodeToString(hash[:])
	}
	return snapshot, err
}

// fiVerifySACLRollback fails closed on descriptor-control normalization,
// reordered ACEs, changed SACL presence or a changed binary ACL. SDDL equality
// alone is not evidence of native ACL byte equality.
func fiVerifySACLRollback(previous fiSACLSnapshot) error {
	current, err := fiQueryRootSACL(previous.path)
	if err != nil {
		return fmt.Errorf("read SACL after rollback %s: %w", previous.path, err)
	}
	if current.present != previous.present ||
		current.control != previous.control ||
		current.originalSDDL != previous.originalSDDL ||
		current.saclBytes != previous.saclBytes ||
		!slices.Equal(current.auditACEs, previous.auditACEs) {
		return fmt.Errorf("SACL not restored exactly for %s: present=%t/%t control=0x%04x/0x%04x nativeACLMatch=%t sddlMatch=%t orderedACEsMatch=%t",
			previous.path, previous.present, current.present,
			previous.control, current.control,
			current.saclBytes == previous.saclBytes,
			current.originalSDDL == previous.originalSDDL,
			slices.Equal(current.auditACEs, previous.auditACEs))
	}
	return nil
}

func fiSetRootSACL(path, sddl string, protect bool) error {
	return auditpolicy.WithSecurityPrivilege(func() error {
		if sddl == "" {
			sddl = "S:"
		}
		descriptor, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			return fmt.Errorf("parse SACL SDDL %s: %w", path, err)
		}
		sacl, _, err := descriptor.SACL()
		if err != nil && !errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) {
			return err
		}
		flags := windows.SECURITY_INFORMATION(windows.SACL_SECURITY_INFORMATION | windows.UNPROTECTED_SACL_SECURITY_INFORMATION)
		if protect {
			flags = windows.SECURITY_INFORMATION(windows.SACL_SECURITY_INFORMATION | windows.PROTECTED_SACL_SECURITY_INFORMATION)
		}
		if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, flags, nil, nil, nil, sacl); err != nil {
			return fmt.Errorf("SetNamedSecurityInfo SACL %s: %w", path, err)
		}
		return nil
	})
}

// planWindowsSACL runs after proposed operational configuration has been
// installed into the plan's report, so fresh-install roots are included.
func planWindowsSACL(plan *InstallPlan, report Report) {
	if !report.WindowsAudit.Known {
		return
	} // synthetic legacy reports only
	// An interrupted prior transaction must never be silently treated as
	// converged, even when root auditing now appears sufficient.
	pending, pendingErr := fiSACLPendingJournalPaths()
	if pendingErr != nil && !errors.Is(pendingErr, os.ErrNotExist) {
		plan.Actions = append(plan.Actions, PlanAction{Action: planActionBlocked, Authority: "WINDOWS SACL", Target: "pending SACL transaction", Detail: pendingErr.Error()})
		return
	}
	if len(pending) != 0 {
		plan.Actions = append(plan.Actions, PlanAction{Action: planActionBlocked, Authority: "WINDOWS SACL", Target: "pending SACL transaction", Detail: "interrupted SACL transaction requires recovery before a new installation: " + pending[0]})
		return
	}
	roots, err := fiSACLRoots(report.Config.GovernedRoots)
	if err != nil {
		plan.Actions = append(plan.Actions, PlanAction{Action: planActionBlocked, Authority: "WINDOWS SACL", Target: "governed root set", Detail: err.Error()})
		return
	}
	for _, root := range roots {
		snapshot, err := fiQueryRootSACL(root)
		if err != nil {
			plan.Actions = append(plan.Actions, PlanAction{Action: planActionBlocked, Authority: "WINDOWS SACL", Target: root, Detail: err.Error()})
			continue
		}
		action := planActionNoChange
		if !snapshot.hasChange || !snapshot.hasRead {
			action = planActionReconcile
		}
		plan.Actions = append(plan.Actions, PlanAction{
			Action: action, Authority: "WINDOWS SACL", Target: root,
			Detail: fmt.Sprintf("PERSISTENT HOST SECURITY PREREQUISITE (retained if FI install fails); prior_sacl_sha256=%s change=%t descendant_read=%t; add only missing Success/Failure audit ACEs; preserve DACL and unrelated SACL entries", snapshot.sha256, snapshot.hasChange, snapshot.hasRead),
		})
	}
}

// applyApproval2WindowsSACL applies the durable Windows Security prerequisites
// explicitly authorized by Approval 2. Unlike FI-owned service/configuration
// mutations, Windows SACL inheritance changes are not byte-exactly reversible
// with the supported named-security APIs. They MUST NOT be registered for
// transaction rollback. A failed installation retains these authorized audit
// rules; the next installation rediscovery plans only remaining differences.
//
// This function preflights ALL roots before the first mutation, then verifies
// each applied root. It never edits an object DACL or removes unrelated SACL
// ACEs. Stale approval, reparse roots, replaced objects, or unreadable SACLs
// block activation, while already-applied audit changes remain in place.
func applyApproval2WindowsSACL(plan InstallPlan) error {
	if err := fiSACLEnsureNoPending(); err != nil {
		return err
	}
	type proposedChange struct {
		path     string
		identity string
		before   fiSACLSnapshot
		desired  string
	}
	var changes []proposedChange
	for _, action := range plan.Actions {
		if action.Authority != "WINDOWS SACL" || !planActionMutates(action.Action) {
			continue
		}
		if action.Action != planActionReconcile {
			return fmt.Errorf("unsupported Windows SACL action %s for %s", action.Action, action.Target)
		}
		if err := fiSACLRejectReparse(action.Target); err != nil {
			return err
		}
		before, err := fiQueryRootSACL(action.Target)
		if err != nil {
			return err
		}
		if !strings.Contains(action.Detail, "prior_sacl_sha256="+before.sha256) {
			return fmt.Errorf("governed-root SACL changed after approved plan: %s", action.Target)
		}
		identity, err := fiSACLObjectIdentity(action.Target)
		if err != nil {
			return err
		}
		desired, err := fiSACLWithRequired(before.originalSDDL, !before.hasChange, !before.hasRead)
		if err != nil {
			return err
		}
		changes = append(changes, proposedChange{
			path: action.Target, identity: identity, before: before, desired: desired,
		})
	}
	if len(changes) == 0 {
		return nil
	}
	roots := make([]string, 0, len(changes))
	for _, change := range changes {
		roots = append(roots, change.path)
	}
	normalized, err := fiSACLRoots(roots)
	if err != nil {
		return err
	}
	if len(normalized) != len(roots) {
		return fmt.Errorf("duplicate Windows SACL action for a governed root")
	}
	for _, change := range changes {
		if err := fiSACLRejectReparse(change.path); err != nil {
			return err
		}
		identity, err := fiSACLObjectIdentity(change.path)
		if err != nil {
			return err
		}
		if identity != change.identity {
			return fmt.Errorf("governed root replaced after preflight; audit mutation blocked: %s", change.path)
		}
		before, err := fiQueryRootSACL(change.path)
		if err != nil {
			return err
		}
		if before.sha256 != change.before.sha256 {
			return fmt.Errorf("governed-root SACL changed during Approval 2: %s", change.path)
		}
		if err := fiSetRootSACL(change.path, change.desired, change.before.protected); err != nil {
			return fmt.Errorf("apply persistent governed-root audit prerequisite %s: %w; previously applied host audit prerequisites remain", change.path, err)
		}
		verified, err := fiQueryRootSACL(change.path)
		if err != nil {
			return fmt.Errorf("verify persistent governed-root audit prerequisite %s: %w", change.path, err)
		}
		if !verified.hasChange || !verified.hasRead || verified.protected != change.before.protected {
			return fmt.Errorf("persistent governed-root SACL verification failed %s: change=%t descendant_read=%t protection_unchanged=%t; audit changes retained for next approved convergence", change.path, verified.hasChange, verified.hasRead, verified.protected == change.before.protected)
		}
		// The newly added FI rules must not erase any preexisting root audit
		// ACE. Windows may reorder entries during inheritance propagation.
		remaining := make(map[string]int, len(verified.auditACEs))
		for _, ace := range verified.auditACEs {
			remaining[ace]++
		}
		for _, ace := range change.before.auditACEs {
			if remaining[ace] == 0 {
				return fmt.Errorf("preexisting root audit ACE changed during FI SACL reconcile %s; installation blocked, host security change retained for investigation", change.path)
			}
			remaining[ace]--
		}
	}
	return nil
}
