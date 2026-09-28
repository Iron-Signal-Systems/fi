// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

const (
	packageManifestArchitectureAMD64 = "amd64"
	packageManifestPlatformWindows   = "windows"
	packageManifestProduct           = "FI Windows Source"
	packageManifestVersion           = "1.0"
)

type PackageManifest struct {
	Architecture string                `json:"architecture"`
	Files        []PackageManifestFile `json:"files"`
	Platform     string                `json:"platform"`
	Product      string                `json:"product"`
	ReleaseID    string                `json:"release_id"`
	Version      string                `json:"version"`
}

type PackageManifestFile struct {
	Name   string `json:"name"`
	Role   string `json:"role"`
	SHA256 string `json:"sha256"`
}

type PackageManifestFileState struct {
	ActualSHA256                           string
	ExpectedSHA256                         string
	InstalledPath                          string
	Match                                  bool
	Name                                   string
	PayloadAuthenticodeError               string
	PayloadAuthenticodeSignerAuthorized    bool
	PayloadAuthenticodeSignerCertSHA256    string
	PayloadAuthenticodeSignerID            string
	PayloadAuthenticodeSignerIdentityError string
	PayloadAuthenticodeSignerKnownNext     bool
	PayloadAuthenticodeSignerSPKISHA256    string
	PayloadAuthenticodeSignerSubject       string
	PayloadAuthenticodeTrusted             bool
	PayloadMatch                           bool
	PayloadPath                            string
	PayloadSHA256                          string
	Role                                   string
}

type PackageState struct {
	Architecture                             string
	AuthenticodeFilesTrusted                 bool
	AuthenticodeSignerIdentitiesComplete     bool
	AuthenticodeSignersAuthorized            bool
	Error                                    string
	Files                                    []PackageManifestFileState
	InstalledHashesMatch                     bool
	InstallerAuthenticodeError               string
	InstallerAuthenticodeSignerAuthorized    bool
	InstallerAuthenticodeSignerCertSHA256    string
	InstallerAuthenticodeSignerID            string
	InstallerAuthenticodeSignerIdentityError string
	InstallerAuthenticodeSignerKnownNext     bool
	InstallerAuthenticodeSignerSPKISHA256    string
	InstallerAuthenticodeSignerSubject       string
	InstallerAuthenticodeTrusted             bool
	InstallerPath                            string
	ManifestPath                             string
	ManifestSignature                        ManifestSignatureState
	ManifestSignaturePath                    string
	ManifestValid                            bool
	PayloadHashesMatch                       bool
	PayloadRoot                              string
	Platform                                 string
	Product                                  string
	ReleaseID                                string
	Root                                     string
	Version                                  string
}

func discoverPackage(report *Report) {
	executable, err := os.Executable()
	if err != nil {
		report.Package.Error = fmt.Sprintf(
			"resolve installer executable: %v",
			err,
		)
		report.addCheck(
			checkFail,
			"FI release manifest",
			report.Package.Error,
		)
		return
	}

	executable, err = filepath.Abs(executable)
	if err != nil {
		report.Package.Error = fmt.Sprintf(
			"resolve absolute installer executable path: %v",
			err,
		)
		report.addCheck(
			checkFail,
			"FI release manifest",
			report.Package.Error,
		)
		return
	}

	report.Package.InstallerPath = executable
	report.Package.Root = filepath.Dir(executable)
	report.Package.PayloadRoot = filepath.Join(
		report.Package.Root,
		"bin",
	)
	report.Package.ManifestPath = filepath.Join(
		report.Package.Root,
		"manifest.json",
	)
	report.Package.ManifestSignaturePath = filepath.Join(
		report.Package.Root,
		"manifest.p7s",
	)

	installerTrust := verifyAuthenticode(
		report.Package.InstallerPath,
	)
	report.Package.InstallerAuthenticodeTrusted = installerTrust.Trusted
	report.Package.InstallerAuthenticodeError = installerTrust.Error
	report.Package.InstallerAuthenticodeSignerCertSHA256 = installerTrust.SignerCertSHA256
	report.Package.InstallerAuthenticodeSignerIdentityError = installerTrust.SignerIdentityError
	report.Package.InstallerAuthenticodeSignerSPKISHA256 = installerTrust.SignerSPKISHA256
	report.Package.InstallerAuthenticodeSignerSubject = installerTrust.SignerSubject
	if installerTrust.Trusted {
		report.addCheck(
			checkPass,
			"FI installer Authenticode trust",
			report.Package.InstallerPath,
		)
	} else {
		report.addCheck(
			checkFail,
			"FI installer Authenticode trust",
			fmt.Sprintf(
				"%s: %s",
				report.Package.InstallerPath,
				valueOrNotKnown(installerTrust.Error),
			),
		)
	}

	if isSHA256Hex(installerTrust.SignerCertSHA256) &&
		isSHA256Hex(installerTrust.SignerSPKISHA256) {
		report.addCheck(
			checkPass,
			"FI installer Authenticode signer identity",
			fmt.Sprintf(
				"subject=%s cert_sha256=%s spki_sha256=%s",
				valueOrNotKnown(installerTrust.SignerSubject),
				installerTrust.SignerCertSHA256,
				installerTrust.SignerSPKISHA256,
			),
		)
	} else {
		detail := installerTrust.SignerIdentityError
		if detail == "" {
			detail = "Authenticode signer certificate/SPKI identity is not available"
		}
		report.addCheck(
			checkFail,
			"FI installer Authenticode signer identity",
			detail,
		)
	}

	manifest, err := loadPackageManifest(
		report.Package.ManifestPath,
	)
	if err != nil {
		report.Package.Error = err.Error()
		report.addCheck(
			checkFail,
			"FI release manifest",
			err.Error(),
		)
		return
	}

	report.Package.ManifestValid = true

	report.Package.ManifestSignature = verifyDetachedManifestSignature(
		report.Package.ManifestPath,
		report.Package.ManifestSignaturePath,
	)
	if report.Package.ManifestSignature.SignatureValid &&
		report.Package.ManifestSignature.SignerChainTrusted {
		report.addCheck(
			checkPass,
			"FI release manifest detached signature",
			manifestSignatureSummary(
				report.Package.ManifestSignature,
			),
		)
	} else {
		report.addCheck(
			checkFail,
			"FI release manifest detached signature",
			manifestSignatureSummary(
				report.Package.ManifestSignature,
			),
		)
	}

	report.Package.Architecture = manifest.Architecture
	report.Package.Platform = manifest.Platform
	report.Package.Product = manifest.Product
	report.Package.ReleaseID = manifest.ReleaseID
	report.Package.Version = manifest.Version

	report.addCheck(
		checkPass,
		"FI release manifest",
		fmt.Sprintf(
			"%s release_id=%s version=%s platform=%s architecture=%s files=%d",
			report.Package.ManifestPath,
			manifest.ReleaseID,
			manifest.Version,
			manifest.Platform,
			manifest.Architecture,
			len(manifest.Files),
		),
	)

	installed := make(map[string]BinaryState)
	for _, binary := range report.Binaries {
		installed[strings.ToLower(binary.Name)] = binary
	}

	installedAllMatch := true
	payloadAllMatch := true

	for _, file := range manifest.Files {
		state := PackageManifestFileState{
			ExpectedSHA256: file.SHA256,
			Name:           file.Name,
			PayloadPath: filepath.Join(
				report.Package.PayloadRoot,
				file.Name,
			),
			Role: file.Role,
		}

		payloadInfo, err := os.Lstat(state.PayloadPath)
		if err != nil {
			payloadAllMatch = false
			state.PayloadSHA256 = notKnown
			report.addCheck(
				checkFail,
				file.Role+" package payload manifest comparison",
				fmt.Sprintf(
					"%s: %v",
					state.PayloadPath,
					err,
				),
			)
		} else if payloadInfo.Mode()&os.ModeSymlink != 0 {
			payloadAllMatch = false
			state.PayloadSHA256 = notKnown
			report.addCheck(
				checkFail,
				file.Role+" package payload manifest comparison",
				fmt.Sprintf(
					"%s is a symbolic link/reparse-style indirection; FI release payload files must be regular files",
					state.PayloadPath,
				),
			)
		} else if !payloadInfo.Mode().IsRegular() {
			payloadAllMatch = false
			state.PayloadSHA256 = notKnown
			report.addCheck(
				checkFail,
				file.Role+" package payload manifest comparison",
				fmt.Sprintf(
					"%s is not a regular file",
					state.PayloadPath,
				),
			)
		} else {
			payloadSHA256, hashErr := fileSHA256(
				state.PayloadPath,
			)
			if hashErr != nil {
				payloadAllMatch = false
				state.PayloadSHA256 = notKnown
				report.addCheck(
					checkFail,
					file.Role+" package payload manifest comparison",
					hashErr.Error(),
				)
			} else {
				state.PayloadSHA256 = payloadSHA256
				state.PayloadMatch = strings.EqualFold(
					payloadSHA256,
					file.SHA256,
				)

				payloadTrust := verifyAuthenticode(
					state.PayloadPath,
				)
				state.PayloadAuthenticodeTrusted = payloadTrust.Trusted
				state.PayloadAuthenticodeError = payloadTrust.Error
				state.PayloadAuthenticodeSignerCertSHA256 = payloadTrust.SignerCertSHA256
				state.PayloadAuthenticodeSignerIdentityError = payloadTrust.SignerIdentityError
				state.PayloadAuthenticodeSignerSPKISHA256 = payloadTrust.SignerSPKISHA256
				state.PayloadAuthenticodeSignerSubject = payloadTrust.SignerSubject
				if payloadTrust.Trusted {
					report.addCheck(
						checkPass,
						file.Role+" package payload Authenticode trust",
						state.PayloadPath,
					)
				} else {
					report.addCheck(
						checkFail,
						file.Role+" package payload Authenticode trust",
						fmt.Sprintf(
							"%s: %s",
							state.PayloadPath,
							valueOrNotKnown(payloadTrust.Error),
						),
					)
				}

				if isSHA256Hex(payloadTrust.SignerCertSHA256) &&
					isSHA256Hex(payloadTrust.SignerSPKISHA256) {
					report.addCheck(
						checkPass,
						file.Role+" package payload Authenticode signer identity",
						fmt.Sprintf(
							"subject=%s cert_sha256=%s spki_sha256=%s",
							valueOrNotKnown(payloadTrust.SignerSubject),
							payloadTrust.SignerCertSHA256,
							payloadTrust.SignerSPKISHA256,
						),
					)
				} else {
					detail := payloadTrust.SignerIdentityError
					if detail == "" {
						detail = "Authenticode signer certificate/SPKI identity is not available"
					}
					report.addCheck(
						checkFail,
						file.Role+" package payload Authenticode signer identity",
						detail,
					)
				}

				if !state.PayloadMatch {
					payloadAllMatch = false
					report.addCheck(
						checkFail,
						file.Role+" package payload manifest comparison",
						fmt.Sprintf(
							"%s expected=%s actual=%s",
							state.PayloadPath,
							file.SHA256,
							payloadSHA256,
						),
					)
				} else {
					report.addCheck(
						checkPass,
						file.Role+" package payload manifest comparison",
						fmt.Sprintf(
							"%s SHA256=%s",
							state.PayloadPath,
							file.SHA256,
						),
					)
				}
			}
		}

		binary, found := installed[strings.ToLower(file.Role)]
		if !found {
			installedAllMatch = false
			state.ActualSHA256 = notKnown
			state.InstalledPath = notKnown
			report.Package.Files = append(
				report.Package.Files,
				state,
			)
			report.addCheck(
				checkFail,
				file.Role+" installed binary manifest comparison",
				"installed binary discovery state is unavailable",
			)
			continue
		}

		state.ActualSHA256 = binary.SHA256
		state.InstalledPath = binary.Path

		switch binary.Presence {
		case presenceAbsent:
			installedAllMatch = false
			report.Package.Files = append(
				report.Package.Files,
				state,
			)
			report.addCheck(
				checkInfo,
				file.Role+" installed binary manifest comparison",
				binary.Path+" is not present",
			)
			continue
		case presenceUnknown:
			installedAllMatch = false
			report.Package.Files = append(
				report.Package.Files,
				state,
			)
			report.addCheck(
				checkFail,
				file.Role+" installed binary manifest comparison",
				binary.Path+" presence/hash is unknown",
			)
			continue
		}

		state.Match = strings.EqualFold(
			binary.SHA256,
			file.SHA256,
		)

		if !state.Match {
			installedAllMatch = false
			report.addCheck(
				checkFail,
				file.Role+" installed binary manifest comparison",
				fmt.Sprintf(
					"%s expected=%s actual=%s",
					binary.Path,
					file.SHA256,
					binary.SHA256,
				),
			)
		} else {
			report.addCheck(
				checkPass,
				file.Role+" installed binary manifest comparison",
				fmt.Sprintf(
					"%s SHA256=%s",
					binary.Path,
					file.SHA256,
				),
			)
		}

		report.Package.Files = append(
			report.Package.Files,
			state,
		)
	}

	report.Package.InstalledHashesMatch = installedAllMatch
	report.Package.PayloadHashesMatch = payloadAllMatch

	authenticodeAllTrusted := report.Package.InstallerAuthenticodeTrusted
	authenticodeSignerIdentitiesComplete := isSHA256Hex(
		report.Package.InstallerAuthenticodeSignerCertSHA256,
	) && isSHA256Hex(
		report.Package.InstallerAuthenticodeSignerSPKISHA256,
	)
	for _, state := range report.Package.Files {
		if !state.PayloadAuthenticodeTrusted {
			authenticodeAllTrusted = false
		}
		if !isSHA256Hex(state.PayloadAuthenticodeSignerCertSHA256) ||
			!isSHA256Hex(state.PayloadAuthenticodeSignerSPKISHA256) {
			authenticodeSignerIdentitiesComplete = false
		}
	}
	report.Package.AuthenticodeFilesTrusted = authenticodeAllTrusted
	report.Package.AuthenticodeSignerIdentitiesComplete = authenticodeSignerIdentitiesComplete
}

func loadPackageManifest(
	path string,
) (PackageManifest, error) {
	file, err := os.Open(path)
	if err != nil {
		return PackageManifest{}, fmt.Errorf(
			"open FI release manifest %s: %w",
			path,
			err,
		)
	}
	defer file.Close()

	decoder := json.NewDecoder(
		io.LimitReader(file, 1<<20),
	)
	decoder.DisallowUnknownFields()

	var manifest PackageManifest
	if err := decoder.Decode(&manifest); err != nil {
		return PackageManifest{}, fmt.Errorf(
			"parse FI release manifest %s: %w",
			path,
			err,
		)
	}

	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return PackageManifest{}, fmt.Errorf(
				"parse FI release manifest %s: multiple JSON values are not allowed",
				path,
			)
		}
		return PackageManifest{}, fmt.Errorf(
			"parse FI release manifest %s trailing content: %w",
			path,
			err,
		)
	}

	if err := validatePackageManifest(manifest); err != nil {
		return PackageManifest{}, fmt.Errorf(
			"validate FI release manifest %s: %w",
			path,
			err,
		)
	}

	return manifest, nil
}

func validatePackageManifest(
	manifest PackageManifest,
) error {
	if manifest.Version != packageManifestVersion {
		return fmt.Errorf(
			"unsupported version %q; expected %q",
			manifest.Version,
			packageManifestVersion,
		)
	}
	if manifest.Product != packageManifestProduct {
		return fmt.Errorf(
			"unexpected product %q; expected %q",
			manifest.Product,
			packageManifestProduct,
		)
	}
	if manifest.Platform != packageManifestPlatformWindows {
		return fmt.Errorf(
			"unexpected platform %q; expected %q",
			manifest.Platform,
			packageManifestPlatformWindows,
		)
	}
	if manifest.Architecture != packageManifestArchitectureAMD64 {
		return fmt.Errorf(
			"unsupported architecture %q; expected %q",
			manifest.Architecture,
			packageManifestArchitectureAMD64,
		)
	}
	if runtime.GOARCH != manifest.Architecture {
		return fmt.Errorf(
			"installer architecture=%s manifest architecture=%s",
			runtime.GOARCH,
			manifest.Architecture,
		)
	}
	if strings.TrimSpace(manifest.ReleaseID) == "" {
		return fmt.Errorf(
			"release_id is required",
		)
	}

	expected := map[string]string{
		"ficollector": "fi.exe",
		"fiobjreader": "fi-obj.exe",
		"fisender":    "fi-sender.exe",
		"fiusnreader": "fi-usn.exe",
	}

	if len(manifest.Files) != len(expected) {
		return fmt.Errorf(
			"files must contain exactly %d FI runtime binaries; observed=%d",
			len(expected),
			len(manifest.Files),
		)
	}

	seenRoles := make(map[string]struct{})
	seenNames := make(map[string]struct{})

	for index, file := range manifest.Files {
		role := strings.ToLower(
			strings.TrimSpace(file.Role),
		)
		name := strings.ToLower(
			strings.TrimSpace(file.Name),
		)

		expectedName, ok := expected[role]
		if !ok {
			return fmt.Errorf(
				"files[%d] has unsupported role %q",
				index,
				file.Role,
			)
		}
		if name != expectedName {
			return fmt.Errorf(
				"files[%d] role=%s name=%q expected=%q",
				index,
				file.Role,
				file.Name,
				expectedName,
			)
		}
		if strings.ContainsAny(file.Name, `/\`) ||
			filepath.Base(file.Name) != file.Name {
			return fmt.Errorf(
				"files[%d] name=%q must be a bare file name",
				index,
				file.Name,
			)
		}
		if _, exists := seenRoles[role]; exists {
			return fmt.Errorf(
				"duplicate runtime role %q",
				file.Role,
			)
		}
		if _, exists := seenNames[name]; exists {
			return fmt.Errorf(
				"duplicate runtime file name %q",
				file.Name,
			)
		}
		seenRoles[role] = struct{}{}
		seenNames[name] = struct{}{}

		if !isSHA256Hex(file.SHA256) {
			return fmt.Errorf(
				"files[%d] role=%s has invalid SHA-256 %q",
				index,
				file.Role,
				file.SHA256,
			)
		}
	}

	return nil
}

func isSHA256Hex(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) != 64 {
		return false
	}
	for _, current := range value {
		switch {
		case current >= '0' && current <= '9':
		case current >= 'a' && current <= 'f':
		case current >= 'A' && current <= 'F':
		default:
			return false
		}
	}
	return true
}

func sortedPackageFiles(
	files []PackageManifestFileState,
) []PackageManifestFileState {
	result := append(
		[]PackageManifestFileState(nil),
		files...,
	)
	sort.Slice(
		result,
		func(left int, right int) bool {
			return result[left].Role < result[right].Role
		},
	)
	return result
}
