// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportcrl

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

type LDAPSource struct {
	Attribute string
	BaseDN    string
	Filter    string
}

func ParseLDAPDistributionPoint(
	raw string,
) (LDAPSource, error) {
	parsed, err := url.Parse(
		strings.TrimSpace(raw),
	)
	if err != nil {
		return LDAPSource{}, fmt.Errorf(
			"parse LDAP CRL distribution point %q: %w",
			raw,
			err,
		)
	}

	if !strings.EqualFold(
		parsed.Scheme,
		"ldap",
	) {
		return LDAPSource{}, fmt.Errorf(
			"CRL distribution point scheme=%q is not LDAP",
			parsed.Scheme,
		)
	}

	if strings.TrimSpace(
		parsed.Host,
	) != "" {
		return LDAPSource{}, fmt.Errorf(
			"LDAP CRL distribution point host %q is not supported; FI uses its already authenticated domain-controller session",
			parsed.Host,
		)
	}

	baseDN := strings.TrimPrefix(
		strings.TrimSpace(
			parsed.Path,
		),
		"/",
	)
	if baseDN == "" {
		return LDAPSource{}, errors.New(
			"LDAP CRL distribution point base distinguished name is empty",
		)
	}

	fields := strings.Split(
		parsed.RawQuery,
		"?",
	)

	if len(fields) < 2 ||
		len(fields) > 4 {
		return LDAPSource{}, fmt.Errorf(
			"LDAP CRL distribution point contains %d query fields; expected attributes, scope, optional filter, and optional extensions",
			len(fields),
		)
	}

	attributes := strings.Split(
		fields[0],
		",",
	)

	if len(attributes) != 1 ||
		!strings.EqualFold(
			strings.TrimSpace(
				attributes[0],
			),
			"certificateRevocationList",
		) {
		return LDAPSource{}, fmt.Errorf(
			"LDAP CRL distribution point must request exactly certificateRevocationList; observed=%q",
			fields[0],
		)
	}

	if !strings.EqualFold(
		strings.TrimSpace(
			fields[1],
		),
		"base",
	) {
		return LDAPSource{}, fmt.Errorf(
			"LDAP CRL distribution point must use base scope; observed=%q",
			fields[1],
		)
	}

	filter :=
		"(objectClass=cRLDistributionPoint)"

	if len(fields) >= 3 &&
		strings.TrimSpace(
			fields[2],
		) != "" {
		observed := strings.TrimSpace(
			fields[2],
		)

		normalized := strings.TrimPrefix(
			observed,
			"(",
		)

		normalized = strings.TrimSuffix(
			normalized,
			")",
		)

		if !strings.EqualFold(
			normalized,
			"objectClass=cRLDistributionPoint",
		) {
			return LDAPSource{}, fmt.Errorf(
				"LDAP CRL distribution point filter %q is not the accepted AD CS cRLDistributionPoint filter",
				observed,
			)
		}
	}

	if len(fields) == 4 &&
		strings.TrimSpace(
			fields[3],
		) != "" {
		return LDAPSource{}, errors.New(
			"LDAP CRL distribution point extensions are not supported",
		)
	}

	return LDAPSource{
		Attribute: "certificateRevocationList",
		BaseDN:    baseDN,
		Filter:    filter,
	}, nil
}

func SelectDistributionPoint(
	distributionPoints []string,
) (string, error) {
	supported := make(
		[]string,
		0,
		len(distributionPoints),
	)

	seen := make(
		map[string]struct{},
	)

	for _, raw := range distributionPoints {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}

		if !SupportedDistributionPoint(raw) {
			continue
		}

		key := strings.ToLower(raw)
		if _, found := seen[key]; found {
			continue
		}

		seen[key] = struct{}{}
		supported = append(
			supported,
			raw,
		)
	}

	switch len(supported) {
	case 0:
		return "", errors.New(
			"transport certificate does not contain a supported HTTP, HTTPS, or AD LDAP CRL distribution point",
		)

	case 1:
		return supported[0], nil

	default:
		return "", fmt.Errorf(
			"transport certificate contains %d supported CRL distribution points; FI refuses ambiguous automatic CRL source selection: %v",
			len(supported),
			supported,
		)
	}
}

func SupportedDistributionPoint(
	raw string,
) bool {
	parsed, err := url.Parse(
		strings.TrimSpace(raw),
	)
	if err != nil {
		return false
	}

	switch strings.ToLower(
		strings.TrimSpace(parsed.Scheme),
	) {
	case "http", "https":
		return strings.TrimSpace(
			parsed.Host,
		) != ""

	case "ldap":
		if strings.TrimSpace(
			parsed.Path,
		) == "" ||
			parsed.Path == "/" {
			return false
		}

		queryParts := strings.Split(
			parsed.RawQuery,
			"?",
		)

		if len(queryParts) < 2 {
			return false
		}

		attributeFound := false

		for _, attribute := range strings.Split(
			queryParts[0],
			",",
		) {
			if strings.EqualFold(
				strings.TrimSpace(
					attribute,
				),
				"certificateRevocationList",
			) {
				attributeFound = true
				break
			}
		}

		if !attributeFound {
			return false
		}

		return strings.EqualFold(
			strings.TrimSpace(
				queryParts[1],
			),
			"base",
		)

	default:
		return false
	}
}
