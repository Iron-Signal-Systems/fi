// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/windows"
)

const (
	fiSACLJournalVersion = "fi-windows-sacl-rollback/1"
	fiSACLJournalPrefix  = "fi-sacl-rollback-"
	fiSACLMaximumEntries = 1000000
	fiSACLMaximumBytes   = 512 << 20
)

type fiSACLJournalEntry struct {
	Path       string   `json:"path"`
	Identity   string   `json:"identity"`
	SDDL       string   `json:"sddl"`
	Control    uint16   `json:"control"`
	Present    bool     `json:"present"`
	Protected  bool     `json:"protected"`
	NativeACL  string   `json:"native_acl_hex"`
	OrderedACE []string `json:"ordered_aces_hex"`
	HasChange  bool     `json:"has_change"`
	HasRead    bool     `json:"has_read"`
}

type fiSACLJournal struct {
	Version       string               `json:"version"`
	TransactionID string               `json:"transaction_id"`
	Roots         []string             `json:"roots"`
	Entries       []fiSACLJournalEntry `json:"entries"`
}

type fiSACLJournalFile struct {
	SHA256  string        `json:"sha256"`
	Journal fiSACLJournal `json:"journal"`
}

func fiSACLKey(path string) string {
	return strings.ToLower(filepath.Clean(path))
}

func fiSACLObjectIdentity(path string) (string, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	h, err := windows.CreateFile(p, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return "", fmt.Errorf("open SACL target identity %s: %w", path, err)
	}
	defer windows.CloseHandle(h)
	var data windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &data); err != nil {
		return "", fmt.Errorf("read SACL target identity %s: %w", path, err)
	}
	return fmt.Sprintf("%08x:%08x:%08x", data.VolumeSerialNumber, data.FileIndexHigh, data.FileIndexLow), nil
}

func fiSACLRejectReparse(path string) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attributes, err := windows.GetFileAttributes(p)
	if err != nil {
		return fmt.Errorf("read object attributes %s: %w", path, err)
	}
	if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("SACL transactional subtree contains a reparse point: %s", path)
	}
	return nil
}

func fiSACLCaptureTrees(roots []string) (map[string]fiSACLJournalEntry, error) {
	entries := make(map[string]fiSACLJournalEntry)
	for _, root := range roots {
		if err := filepath.WalkDir(root, func(path string, de fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if err := fiSACLRejectReparse(path); err != nil {
				return err
			}
			key := fiSACLKey(path)
			if _, exists := entries[key]; exists {
				return fmt.Errorf("duplicate SACL subtree object: %s", path)
			}
			if len(entries) >= fiSACLMaximumEntries {
				return fmt.Errorf("SACL subtree exceeds %d-object bound", fiSACLMaximumEntries)
			}
			id, err := fiSACLObjectIdentity(path)
			if err != nil {
				return err
			}
			s, err := fiQueryRootSACL(path)
			if err != nil {
				return err
			}
			entries[key] = fiSACLJournalEntry{
				Path: path, Identity: id, SDDL: s.originalSDDL,
				Control: s.control, Present: s.present, Protected: s.protected,
				NativeACL: s.saclBytes, OrderedACE: append([]string(nil), s.auditACEs...),
				HasChange: s.hasChange, HasRead: s.hasRead,
			}
			return nil
		}); err != nil {
			return nil, fmt.Errorf("walk governed SACL subtree %s: %w", root, err)
		}
	}
	return entries, nil
}

func fiSACLJournalDirectory() (string, error) {
	programData := os.Getenv("ProgramData")
	if programData == "" || !filepath.IsAbs(programData) {
		return "", errors.New("ProgramData is not an absolute path")
	}
	path := filepath.Join(programData, "FI", "state")
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("FI persistent state must exist before SACL mutation: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("FI persistent state is not a non-symlink directory: %s", path)
	}
	if err := fiSACLRejectReparse(path); err != nil {
		return "", err
	}
	return path, nil
}

func fiSACLPendingJournalPaths() ([]string, error) {
	dir, err := fiSACLJournalDirectory()
	if err != nil {
		return nil, err
	}
	// Glob can silently ignore directory I/O failures. Recovery must instead
	// fail closed if pending journal discovery is unreadable.
	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("enumerate pending SACL journals: %w", err)
	}
	paths := make([]string, 0)
	for _, entry := range dirEntries {
		if strings.HasPrefix(entry.Name(), fiSACLJournalPrefix) {
			paths = append(paths, filepath.Join(dir, entry.Name()))
		}
	}
	sort.Strings(paths)
	return paths, nil
}

// Any remnant (including an interrupted partial file) blocks new mutations.
// The installer startup must recover pending complete journals BEFORE planning.
func fiSACLEnsureNoPending() error {
	paths, err := fiSACLPendingJournalPaths()
	if err != nil {
		return err
	}
	if len(paths) > 0 {
		return fmt.Errorf("incomplete SACL rollback transaction exists at %s; fail closed and recover before further Approval 2 changes", paths[0])
	}
	return nil
}

func fiSACLJournalChecksum(journal fiSACLJournal) (string, error) {
	data, err := json.Marshal(journal)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

func fiSACLHardenJournalFile(path string) error {
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil)
}

func fiSACLWriteJournal(transactionID string, roots []string, preimages map[string]fiSACLJournalEntry) (string, error) {
	if !validApproval2TransactionID(transactionID) {
		return "", fmt.Errorf("invalid SACL transaction ID: %q", transactionID)
	}
	if err := fiSACLEnsureNoPending(); err != nil {
		return "", err
	}
	dir, err := fiSACLJournalDirectory()
	if err != nil {
		return "", err
	}
	keys := make([]string, 0, len(preimages))
	for key := range preimages {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, k int) bool {
		// Parent first; restore root before its descendants.
		return len(keys[i]) < len(keys[k]) || (len(keys[i]) == len(keys[k]) && keys[i] < keys[k])
	})
	journal := fiSACLJournal{Version: fiSACLJournalVersion, TransactionID: transactionID, Roots: append([]string(nil), roots...)}
	for _, key := range keys {
		journal.Entries = append(journal.Entries, preimages[key])
	}
	checksum, err := fiSACLJournalChecksum(journal)
	if err != nil {
		return "", err
	}
	fileBytes, err := json.Marshal(fiSACLJournalFile{SHA256: checksum, Journal: journal})
	if err != nil {
		return "", err
	}
	if len(fileBytes) > fiSACLMaximumBytes {
		return "", fmt.Errorf("SACL journal would exceed %d byte bound", fiSACLMaximumBytes)
	}
	path := filepath.Join(dir, fiSACLJournalPrefix+transactionID+".json")
	tmp := path + ".incomplete"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	defer f.Close()
	// Harden the EMPTY journal before writing potentially sensitive SACL data.
	if err := fiSACLHardenJournalFile(tmp); err != nil {
		return "", err // Retain incomplete marker; no mutation has begun.
	}
	if _, err := f.Write(fileBytes); err != nil {
		return "", err
	}
	if err := f.Sync(); err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", err
	}
	return path, nil
}

func fiSACLReadJournal(path string) (fiSACLJournal, error) {
	if err := fiSACLRejectReparse(path); err != nil {
		return fiSACLJournal{}, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return fiSACLJournal{}, err
	}
	if info.Size() > fiSACLMaximumBytes || info.Size() <= 0 {
		return fiSACLJournal{}, fmt.Errorf("invalid SACL journal size: %d", info.Size())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fiSACLJournal{}, err
	}
	var entry fiSACLJournalFile
	if err := json.Unmarshal(data, &entry); err != nil {
		return fiSACLJournal{}, err
	}
	if entry.Journal.Version != fiSACLJournalVersion || !validApproval2TransactionID(entry.Journal.TransactionID) {
		return fiSACLJournal{}, errors.New("unsupported SACL rollback journal")
	}
	sum, err := fiSACLJournalChecksum(entry.Journal)
	if err != nil {
		return fiSACLJournal{}, err
	}
	if !strings.EqualFold(sum, entry.SHA256) {
		return fiSACLJournal{}, errors.New("SACL rollback journal checksum mismatch")
	}
	if filepath.Base(path) != fiSACLJournalPrefix+entry.Journal.TransactionID+".json" {
		return fiSACLJournal{}, errors.New("SACL rollback filename / transaction mismatch")
	}
	return entry.Journal, nil
}

func fiSACLRestoreJournal(path string) error {
	journal, err := fiSACLReadJournal(path)
	if err != nil {
		return fmt.Errorf("read pending SACL rollback journal: %w", err)
	}
	if len(journal.Roots) == 0 || len(journal.Entries) == 0 || len(journal.Entries) > fiSACLMaximumEntries {
		return errors.New("invalid SACL rollback journal root/object count")
	}
	approvedRoots, err := fiSACLRoots(journal.Roots)
	if err != nil {
		return err
	}
	// Verify all paths and identities BEFORE modifying any object.
	seen := make(map[string]struct{}, len(journal.Entries))
	for _, item := range journal.Entries {
		key := fiSACLKey(item.Path)
		if _, found := seen[key]; found {
			return fmt.Errorf("duplicate SACL journal entry %s", item.Path)
		}
		seen[key] = struct{}{}
		inScope := false
		for _, root := range approvedRoots {
			rootKey := fiSACLKey(root)
			if key == rootKey || strings.HasPrefix(key, strings.TrimRight(rootKey, `\`)+`\`) {
				inScope = true
				break
			}
		}
		if !inScope || item.Path != filepath.Clean(item.Path) {
			return fmt.Errorf("SACL journal contains out-of-scope path %q", item.Path)
		}
		if err := fiSACLRejectReparse(item.Path); err != nil {
			return err
		}
		identity, err := fiSACLObjectIdentity(item.Path)
		if err != nil {
			return err
		}
		if identity != item.Identity {
			return fmt.Errorf("SACL object identity changed; refuse restore %s", item.Path)
		}
	}
	// Objects created during this transaction have no original preimage.
	// Do not claim byte-exact rollback if their SACL state cannot be proven.
	current, err := fiSACLCaptureTrees(approvedRoots)
	if err != nil {
		return err
	}
	var failures []error
	if len(current) != len(seen) {
		failures = append(failures, fmt.Errorf("SACL subtree changed during transaction: captured=%d now=%d; exact original bytes of new objects unknown", len(seen), len(current)))
	}
	for key := range current {
		if _, ok := seen[key]; !ok {
			failures = append(failures, fmt.Errorf("new SACL subtree object %s has no rollback preimage", key))
		}
	}
	// Restore known objects even if new descendants appeared, but do not
	// erase the recovery journal or report an exact rollback on that basis.
	// A root-to-leaf walk restores inherited root state before each child.
	// If Windows normalizes a control bit, final exact verification detects it.
	for _, item := range journal.Entries {
		if err := fiSetRootSACL(item.Path, item.SDDL, item.Protected); err != nil {
			failures = append(failures, fmt.Errorf("restore %s: %w", item.Path, err))
		}
	}
	for _, item := range journal.Entries {
		expected := fiSACLSnapshot{path: item.Path, originalSDDL: item.SDDL,
			protected: item.Protected, present: item.Present, control: item.Control,
			saclBytes: item.NativeACL, auditACEs: item.OrderedACE}
		if err := fiVerifySACLRollback(expected); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func fiSACLRemoveJournal(path string) error {
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove resolved SACL rollback journal %s: %w", path, err)
	}
	return nil
}

// RecoverPendingWindowsSACLTransactions is retained as the installer startup
// entrypoint, but deliberately does NOT replay legacy exact-rollback journals.
// Live Windows testing demonstrated that doing so can change absent SACLs into
// present empty SACLs and corrupt the original descriptor contract. The
// approved durable-prerequisite design creates NO new rollback journal. A
// legacy journal is therefore always an unresolved migration artifact: fail
// closed, preserve it, and require explicit administrative investigation.
// Startup checking remains read-only and precedes discovery/first-run changes.
func RecoverPendingWindowsSACLTransactions() error {
	paths, err := fiSACLPendingJournalPaths()
	if err != nil {
		// New installations may have no FI state directory yet. An existing FI
		// root with missing state is never treated as equivalent to a new host.
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		programData := os.Getenv("ProgramData")
		if programData == "" || !filepath.IsAbs(programData) {
			return err
		}
		_, rootErr := os.Lstat(filepath.Join(programData, "FI"))
		if errors.Is(rootErr, fs.ErrNotExist) {
			return nil
		}
		if rootErr != nil {
			return fmt.Errorf("inspect FI persistent root before SACL recovery: %w", rootErr)
		}
		return fmt.Errorf("FI data root exists but SACL state is unavailable; installation blocked: %w", err)
	}
	if len(paths) == 0 {
		return nil
	}
	if len(paths) > 1 {
		return fmt.Errorf("multiple SACL rollback artifacts require investigation; no automatic restore attempted: %v", paths)
	}
	if !strings.HasSuffix(paths[0], ".json") {
		return fmt.Errorf("incomplete SACL journal marker requires investigation; no automatic restore attempted: %s", paths[0])
	}
	// Deliberately do not invoke fiSACLRestoreJournal: even a valid journal
	// cannot guarantee byte-exact restoration of Windows SACL presence state.
	return fmt.Errorf("legacy SACL rollback journal requires investigation (automatic restoration disabled; original retained): %s", paths[0])
}
