// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// privateProjectionSchema is a non-authoritative test namespace. This helper
// does not install it and is not part of the production migration pipeline.
const privateProjectionSchema = "fi_recovery_projection"

var privateProjectionSchemaNames = regexp.MustCompile(`(?i)\bSCHEMA\s+fi\b`)
var privateProjectionAuthoritativeReference = regexp.MustCompile(`\bfi\.`)
var privateProjectionApprovedFiles = map[string]struct{}{
	"0001_relational.sql":                {},
	"0002_source_families.sql":           {},
	"0003_usn_relational_identity.sql":   {},
	"0004_security_field_name_index.sql": {},
	"0005_usn_capture_binding.sql":       {},
}

// RewritePrivateProjectionMigration is restricted to the five audited FI
// relational migrations. It is a FIXTURE constructor, not a general SQL
// rewriting API, and does not authorize migrations against the production SoR.
//
// Unlike CREATE TABLE ... LIKE, replaying original DDL preserves the complete
// FK graph, constraints, indexes and identity rules. The canonical "fi" schema
// is unchanged. The only expected unqualified "fi" is the database in the
// explicit GRANT CONNECT ON DATABASE fi statement.
func RewritePrivateProjectionMigration(filename, original string) (string, error) {
	if _, ok := privateProjectionApprovedFiles[filename]; !ok {
		return "", fmt.Errorf("FI private projection: unapproved migration %q", filename)
	}
	if !strings.Contains(original, "Copyright (c) 2026 John Joseph Wood") ||
		!privateProjectionAuthoritativeReference.MatchString(original) {
		return "", errors.New("FI private projection: canonical migration marker missing")
	}
	if strings.Contains(original, privateProjectionSchema) {
		return "", errors.New("FI private projection: source already references private schema")
	}
	out := privateProjectionSchemaNames.ReplaceAllString(original, "SCHEMA "+privateProjectionSchema)
	out = privateProjectionAuthoritativeReference.ReplaceAllString(out, privateProjectionSchema+".")
	if privateProjectionSchemaNames.MatchString(out) ||
		privateProjectionAuthoritativeReference.MatchString(out) {
		return "", errors.New("FI private projection: authoritative schema token survived rewrite")
	}
	if filename == "0001_relational.sql" &&
		!strings.Contains(out, "CREATE SCHEMA "+privateProjectionSchema+" AUTHORIZATION fi_owner;") {
		return "", errors.New("FI private projection: replacement schema creation absent")
	}
	return out, nil
}
