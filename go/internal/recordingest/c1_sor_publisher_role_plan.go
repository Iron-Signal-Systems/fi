//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Offline, administrator-reviewed canonical publisher role plan. Nothing
// automatically executes these DDL statements against the populated C220.
package recordingest

// C1CanonicalPublisherRolePlan creates a dedicated fi-sor-local authority.
// No password is embedded; administrators must configure Unix socket
// pg_hba/peer or an independently secured, fi-sor-only passfile.
// All SQL workers stay fi_ingest and NEVER get UPDATE on canonical fi.
func C1CanonicalPublisherRolePlan()[]string{
 return []string{
  "CREATE ROLE fi_c1_publisher LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION",
  "GRANT CONNECT ON DATABASE fi TO fi_c1_publisher",
  "GRANT USAGE ON SCHEMA fi,fi_c1_pending TO fi_c1_publisher",
  // PostgreSQL 18 MAINTAIN permits strong locks without SQL UPDATE/DELETE.
  // Unlike fi_ingest, this account is opened only for final publication.
  "GRANT SELECT,INSERT,MAINTAIN ON ALL TABLES IN SCHEMA fi TO fi_c1_publisher",
  "GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA fi TO fi_c1_publisher",
  "GRANT SELECT,MAINTAIN,TRUNCATE ON ALL TABLES IN SCHEMA fi_c1_pending TO fi_c1_publisher",
  "REVOKE ALL ON fi_c1_pending.generation_control FROM fi_c1_publisher",
  "GRANT SELECT,MAINTAIN,TRUNCATE ON fi_c1_pending.generation_control TO fi_c1_publisher",
  "ALTER DEFAULT PRIVILEGES FOR ROLE fi_owner IN SCHEMA fi GRANT SELECT,INSERT,MAINTAIN ON TABLES TO fi_c1_publisher",
  "ALTER DEFAULT PRIVILEGES FOR ROLE fi_owner IN SCHEMA fi GRANT USAGE,SELECT ON SEQUENCES TO fi_c1_publisher",
 }
}
