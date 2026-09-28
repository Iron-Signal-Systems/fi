// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	certStorePKILocalMachine = uint32(0x00020000)
	certStorePKIReadOnly     = uint32(0x00008000)
	certStorePKISystemW      = uintptr(10)
)

var (
	certificateTemplateInformationOID = asn1.ObjectIdentifier{
		1, 3, 6, 1, 4, 1, 311, 21, 7,
	}

	extendedKeyUsageOID = asn1.ObjectIdentifier{
		2, 5, 29, 37,
	}

	crypt32PKIDLL = windows.NewLazySystemDLL(
		"crypt32.dll",
	)

	certCloseStorePKIProc = crypt32PKIDLL.NewProc(
		"CertCloseStore",
	)
	certOpenStorePKIProc = crypt32PKIDLL.NewProc(
		"CertOpenStore",
	)
)

type certificateTemplateInformation struct {
	TemplateID   asn1.ObjectIdentifier
	MajorVersion int `asn1:"optional"`
	MinorVersion int `asn1:"optional"`
}

type localMachinePKICertificate struct {
	CertificateSHA256       string
	CommonName              string
	DNSNames                []string
	ExtendedKeyUsagePresent bool
	ExtKeyUsage             []x509.ExtKeyUsage
	KeyUsage                x509.KeyUsage
	NotAfter                string
	NotBefore               string
	PublicKeyAlgorithm      x509.PublicKeyAlgorithm
	PublicKeyBits           int
	TemplateOID             string
	UnknownExtKeyUsage      []string
}

func certificateExtensionPresent(
	certificate *x509.Certificate,
	oid asn1.ObjectIdentifier,
) bool {
	if certificate == nil {
		return false
	}

	for _, extension := range certificate.Extensions {
		if extension.Id.Equal(
			oid,
		) {
			return true
		}
	}

	return false
}

func certificateTemplateOID(
	certificate *x509.Certificate,
) (string, bool, error) {
	if certificate == nil {
		return "", false, errors.New(
			"certificate is required",
		)
	}

	for _, extension := range certificate.Extensions {
		if !extension.Id.Equal(
			certificateTemplateInformationOID,
		) {
			continue
		}

		var information certificateTemplateInformation

		rest, err := asn1.Unmarshal(
			extension.Value,
			&information,
		)
		if err != nil {
			return "", true, fmt.Errorf(
				"decode certificate template information extension: %w",
				err,
			)
		}

		if len(rest) != 0 {
			return "", true, fmt.Errorf(
				"certificate template information extension contains %d trailing bytes",
				len(rest),
			)
		}

		if len(information.TemplateID) == 0 {
			return "", true, errors.New(
				"certificate template information extension contains no template OID",
			)
		}

		return information.TemplateID.String(), true, nil
	}

	return "", false, nil
}

func certificateStateDifference(
	before []localMachinePKICertificate,
	after []localMachinePKICertificate,
) []localMachinePKICertificate {
	existing := make(
		map[string]struct{},
		len(before),
	)

	for _, certificate := range before {
		existing[strings.ToLower(
			certificate.CertificateSHA256,
		)] = struct{}{}
	}

	var added []localMachinePKICertificate

	for _, certificate := range after {
		if _, found := existing[strings.ToLower(
			certificate.CertificateSHA256,
		)]; found {
			continue
		}

		added = append(
			added,
			certificate,
		)
	}

	sort.Slice(
		added,
		func(left int, right int) bool {
			return added[left].CertificateSHA256 <
				added[right].CertificateSHA256
		},
	)

	return added
}

func snapshotLocalMachinePKICertificates(
	templateOIDs ...string,
) ([]localMachinePKICertificate, error) {
	expected := make(
		map[string]struct{},
		len(templateOIDs),
	)

	for _, oid := range templateOIDs {
		oid = strings.TrimSpace(oid)
		if oid == "" {
			return nil, errors.New(
				"certificate template OID is required",
			)
		}

		expected[oid] = struct{}{}
	}

	if len(expected) == 0 {
		return nil, errors.New(
			"at least one certificate template OID is required",
		)
	}

	store, err := openLocalMachinePKIStore()
	if err != nil {
		return nil, err
	}
	defer closeLocalMachinePKIStore(
		store,
	)

	var (
		previous *syscall.CertContext
		result   []localMachinePKICertificate
	)

	for {
		context, err := syscall.CertEnumCertificatesInStore(
			syscall.Handle(store),
			previous,
		)
		if err != nil {
			if errors.Is(
				err,
				syscall.Errno(0x80092004),
			) {
				break
			}

			return nil, fmt.Errorf(
				"enumerate LocalMachine\\MY certificates: %w",
				err,
			)
		}

		if context == nil {
			break
		}

		previous = context

		if context.EncodedCert == nil ||
			context.Length == 0 {
			continue
		}

		raw := append(
			[]byte(nil),
			unsafe.Slice(
				context.EncodedCert,
				int(context.Length),
			)...,
		)

		certificate, err := x509.ParseCertificate(
			raw,
		)
		if err != nil {
			continue
		}

		templateOID, present, err := certificateTemplateOID(
			certificate,
		)
		if err != nil {
			return nil, err
		}
		if !present {
			continue
		}

		if _, wanted := expected[templateOID]; !wanted {
			continue
		}

		publicKeyBits := 0

		if publicKey, ok := certificate.PublicKey.(*rsa.PublicKey); ok {
			publicKeyBits = publicKey.N.BitLen()
		}

		unknownExtKeyUsage := make(
			[]string,
			0,
			len(certificate.UnknownExtKeyUsage),
		)

		for _, oid := range certificate.UnknownExtKeyUsage {
			unknownExtKeyUsage = append(
				unknownExtKeyUsage,
				oid.String(),
			)
		}

		digest := sha256.Sum256(
			certificate.Raw,
		)

		result = append(
			result,
			localMachinePKICertificate{
				CertificateSHA256: hex.EncodeToString(
					digest[:],
				),
				CommonName: certificate.Subject.CommonName,
				DNSNames: append(
					[]string(nil),
					certificate.DNSNames...,
				),
				ExtendedKeyUsagePresent: certificateExtensionPresent(
					certificate,
					extendedKeyUsageOID,
				),
				ExtKeyUsage: append(
					[]x509.ExtKeyUsage(nil),
					certificate.ExtKeyUsage...,
				),
				KeyUsage: certificate.KeyUsage,
				NotAfter: certificate.NotAfter.UTC().Format(
					"2006-01-02T15:04:05Z",
				),
				NotBefore: certificate.NotBefore.UTC().Format(
					"2006-01-02T15:04:05Z",
				),
				PublicKeyAlgorithm: certificate.PublicKeyAlgorithm,
				PublicKeyBits:      publicKeyBits,
				TemplateOID:        templateOID,
				UnknownExtKeyUsage: unknownExtKeyUsage,
			},
		)
	}

	sort.Slice(
		result,
		func(left int, right int) bool {
			if result[left].TemplateOID !=
				result[right].TemplateOID {
				return result[left].TemplateOID <
					result[right].TemplateOID
			}

			return result[left].CertificateSHA256 <
				result[right].CertificateSHA256
		},
	)

	return result, nil
}

func closeLocalMachinePKIStore(
	store uintptr,
) {
	if store == 0 {
		return
	}

	_, _, _ = certCloseStorePKIProc.Call(
		store,
		0,
	)
}

func openLocalMachinePKIStore() (uintptr, error) {
	name, err := syscall.UTF16PtrFromString(
		"MY",
	)
	if err != nil {
		return 0, fmt.Errorf(
			"encode LocalMachine MY certificate store name: %w",
			err,
		)
	}

	store, _, callErr := certOpenStorePKIProc.Call(
		certStorePKISystemW,
		0,
		0,
		uintptr(
			certStorePKILocalMachine|
				certStorePKIReadOnly,
		),
		uintptr(
			unsafe.Pointer(
				name,
			),
		),
	)

	if store == 0 {
		if callErr != nil &&
			callErr != syscall.Errno(0) {
			return 0, fmt.Errorf(
				"open LocalMachine\\MY certificate store: %w",
				callErr,
			)
		}

		return 0, errors.New(
			"open LocalMachine\\MY certificate store failed",
		)
	}

	return store, nil
}
