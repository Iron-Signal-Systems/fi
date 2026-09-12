//go:build linux

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package receivertrust

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const receiverServiceAccount = "fi-receiver"

type custodyIdentity struct {
	GIDs map[uint32]struct{}
	UID  uint32
}

type custodyPaths struct {
	BatchCRL         string
	BatchIssuer      string
	CertsDirectory   string
	EtcFI            string
	PKI              string
	PrivateDirectory string
	Receiver         string
	ReceiverCert     string
	ReceiverKey      string
	RootCA           string
	SourceRegistry   string
	TransportCRL     string
	TransportIssuer  string
	TrustDirectory   string
}

// InspectTrustCustodyValidation validates ownership, object type, runtime
// access, write protection, and symlink policy for installed receiver trust
// material.
func InspectTrustCustodyValidation() ValidationState {
	service, servicePrimaryGID, err := lookupCustodyIdentity(
		receiverServiceAccount,
	)
	if err != nil {
		return newValidationState("/etc/fi", err)
	}

	return newValidationState(
		"/etc/fi",
		validateTrustCustody(
			custodyPaths{
				BatchCRL:         BatchCRLPath,
				BatchIssuer:      BatchIssuerPath,
				CertsDirectory:   filepath.Dir(ReceiverCertPath),
				EtcFI:            "/etc/fi",
				PKI:              "/etc/fi/pki",
				PrivateDirectory: filepath.Dir(ReceiverKeyPath),
				Receiver:         "/etc/fi/pki/receiver",
				ReceiverCert:     ReceiverCertPath,
				ReceiverKey:      ReceiverKeyPath,
				RootCA:           RootCAPath,
				SourceRegistry:   SourceRegistryPath,
				TransportCRL:     TransportCRLPath,
				TransportIssuer:  TransportIssuerPath,
				TrustDirectory:   filepath.Dir(RootCAPath),
			},
			0,
			0,
			service,
			servicePrimaryGID,
		),
	)
}

func lookupCustodyIdentity(name string) (custodyIdentity, uint32, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return custodyIdentity{}, 0, errors.New(
			"receiver service account is required",
		)
	}

	account, err := user.Lookup(name)
	if err != nil {
		return custodyIdentity{}, 0, fmt.Errorf(
			"lookup receiver service account %q: %w",
			name,
			err,
		)
	}

	uid, err := parseCustodyID(account.Uid, "UID")
	if err != nil {
		return custodyIdentity{}, 0, err
	}

	primaryGID, err := parseCustodyID(account.Gid, "GID")
	if err != nil {
		return custodyIdentity{}, 0, err
	}

	gids := map[uint32]struct{}{
		primaryGID: {},
	}

	groupIDs, err := account.GroupIds()
	if err != nil {
		return custodyIdentity{}, 0, fmt.Errorf(
			"lookup receiver service supplementary groups: %w",
			err,
		)
	}

	for _, groupID := range groupIDs {
		gid, err := parseCustodyID(groupID, "supplementary GID")
		if err != nil {
			return custodyIdentity{}, 0, err
		}
		gids[gid] = struct{}{}
	}

	return custodyIdentity{
		GIDs: gids,
		UID:  uid,
	}, primaryGID, nil
}

func parseCustodyID(value string, label string) (uint32, error) {
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, fmt.Errorf(
			"parse receiver service %s %q: %w",
			label,
			value,
			err,
		)
	}

	return uint32(parsed), nil
}

func validateTrustCustody(
	paths custodyPaths,
	rootUID uint32,
	rootGID uint32,
	service custodyIdentity,
	servicePrimaryGID uint32,
) error {
	directories := []struct {
		path string
		gid  uint32
	}{
		{path: paths.EtcFI, gid: servicePrimaryGID},
		{path: paths.PKI, gid: rootGID},
		{path: paths.TrustDirectory, gid: servicePrimaryGID},
		{path: paths.Receiver, gid: rootGID},
		{path: paths.CertsDirectory, gid: servicePrimaryGID},
		{path: paths.PrivateDirectory, gid: servicePrimaryGID},
		{path: paths.SourceRegistry, gid: servicePrimaryGID},
	}

	for _, directory := range directories {
		if err := validateCustodyDirectory(
			directory.path,
			rootUID,
			directory.gid,
			service,
		); err != nil {
			return err
		}
	}

	publicFiles := []string{
		paths.RootCA,
		paths.TransportIssuer,
		paths.BatchIssuer,
		paths.TransportCRL,
		paths.BatchCRL,
		paths.ReceiverCert,
	}

	for _, path := range publicFiles {
		if err := validateCustodyFile(
			path,
			rootUID,
			servicePrimaryGID,
			service,
			false,
		); err != nil {
			return err
		}
	}

	if err := validateCustodyFile(
		paths.ReceiverKey,
		rootUID,
		servicePrimaryGID,
		service,
		true,
	); err != nil {
		return err
	}

	entries, err := os.ReadDir(paths.SourceRegistry)
	if err != nil {
		return fmt.Errorf(
			"read source registry custody %q: %w",
			paths.SourceRegistry,
			err,
		)
	}

	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".conf" {
			continue
		}

		if err := validateCustodyFile(
			filepath.Join(paths.SourceRegistry, entry.Name()),
			rootUID,
			servicePrimaryGID,
			service,
			true,
		); err != nil {
			return err
		}
	}

	for _, tree := range []string{
		paths.TrustDirectory,
		paths.CertsDirectory,
		paths.PrivateDirectory,
		paths.SourceRegistry,
	} {
		if err := validateNoCustodySymlinks(tree); err != nil {
			return err
		}
	}

	return nil
}

func validateCustodyDirectory(
	path string,
	expectedUID uint32,
	expectedGID uint32,
	service custodyIdentity,
) error {
	info, stat, err := custodyLstat(path)
	if err != nil {
		return err
	}

	if !info.IsDir() {
		return fmt.Errorf("trust custody path %q is not a directory", path)
	}

	if err := validateCustodyOwner(
		path,
		stat,
		expectedUID,
		expectedGID,
	); err != nil {
		return err
	}

	if err := validateCustodySpecialBits(path, info.Mode()); err != nil {
		return err
	}

	permissions := info.Mode().Perm()
	if permissions&0022 != 0 {
		return fmt.Errorf(
			"trust custody directory %q is group/world writable: mode=%04o",
			path,
			permissions,
		)
	}

	servicePermissions := custodyPermissionsForIdentity(
		stat,
		permissions,
		service,
	)

	if servicePermissions&0001 == 0 {
		return fmt.Errorf(
			"receiver service cannot traverse trust custody directory %q",
			path,
		)
	}

	if servicePermissions&0002 != 0 {
		return fmt.Errorf(
			"receiver service can write trust custody directory %q",
			path,
		)
	}

	return nil
}

func validateCustodyFile(
	path string,
	expectedUID uint32,
	expectedGID uint32,
	service custodyIdentity,
	restricted bool,
) error {
	info, stat, err := custodyLstat(path)
	if err != nil {
		return err
	}

	if !info.Mode().IsRegular() {
		return fmt.Errorf("trust custody path %q is not a regular file", path)
	}

	if err := validateCustodyOwner(
		path,
		stat,
		expectedUID,
		expectedGID,
	); err != nil {
		return err
	}

	if err := validateCustodySpecialBits(path, info.Mode()); err != nil {
		return err
	}

	permissions := info.Mode().Perm()
	if permissions&0022 != 0 {
		return fmt.Errorf(
			"trust custody file %q is group/world writable: mode=%04o",
			path,
			permissions,
		)
	}

	if permissions&0111 != 0 {
		return fmt.Errorf(
			"trust custody file %q is executable: mode=%04o",
			path,
			permissions,
		)
	}

	if restricted && permissions&0007 != 0 {
		return fmt.Errorf(
			"restricted trust custody file %q permits other-user access: mode=%04o",
			path,
			permissions,
		)
	}

	servicePermissions := custodyPermissionsForIdentity(
		stat,
		permissions,
		service,
	)

	if servicePermissions&0004 == 0 {
		return fmt.Errorf(
			"receiver service cannot read trust custody file %q",
			path,
		)
	}

	if servicePermissions&0002 != 0 {
		return fmt.Errorf(
			"receiver service can write trust custody file %q",
			path,
		)
	}

	return nil
}

func custodyLstat(
	path string,
) (fs.FileInfo, *syscall.Stat_t, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, nil, fmt.Errorf(
			"inspect trust custody path %q: %w",
			path,
			err,
		)
	}

	if info.Mode()&os.ModeSymlink != 0 {
		return nil, nil, fmt.Errorf(
			"trust custody path %q is a symbolic link",
			path,
		)
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return nil, nil, fmt.Errorf(
			"trust custody path %q has unavailable Linux ownership metadata",
			path,
		)
	}

	return info, stat, nil
}

func custodyPermissionsForIdentity(
	stat *syscall.Stat_t,
	permissions fs.FileMode,
	identity custodyIdentity,
) fs.FileMode {
	switch {
	case stat.Uid == identity.UID:
		return (permissions >> 6) & 0007
	default:
		if _, exists := identity.GIDs[stat.Gid]; exists {
			return (permissions >> 3) & 0007
		}
		return permissions & 0007
	}
}

func validateCustodyOwner(
	path string,
	stat *syscall.Stat_t,
	expectedUID uint32,
	expectedGID uint32,
) error {
	if stat.Uid != expectedUID {
		return fmt.Errorf(
			"trust custody path %q owner UID=%d, want %d",
			path,
			stat.Uid,
			expectedUID,
		)
	}

	if stat.Gid != expectedGID {
		return fmt.Errorf(
			"trust custody path %q group GID=%d, want %d",
			path,
			stat.Gid,
			expectedGID,
		)
	}

	return nil
}

func validateCustodySpecialBits(path string, mode fs.FileMode) error {
	if mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return fmt.Errorf(
			"trust custody path %q has special permission bits set",
			path,
		)
	}

	return nil
}

func validateNoCustodySymlinks(root string) error {
	return filepath.WalkDir(
		root,
		func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return fmt.Errorf(
					"walk trust custody tree %q: %w",
					path,
					err,
				)
			}

			if entry.Type()&os.ModeSymlink != 0 {
				return fmt.Errorf(
					"trust custody tree contains symbolic link %q",
					path,
				)
			}

			return nil
		},
	)
}
