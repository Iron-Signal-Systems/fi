//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Direct canonical C1 SQL target for an ISOLATED disposable PostgreSQL clone.
// The parent/five-family projectors already author qualified fi.* SQL.
// Returning the ORIGINAL transaction preserves the existing canonical SQL,
// IDs, COPY, foreign keys, and PostgreSQL commit behavior without any second
// Pending-to-canonical relational insertion. Never select this target until
// the isolated-clone physical identity and signed-custody guards have passed.
package recordingest

import "github.com/jackc/pgx/v5"

// c1SQLProjectorTx is intentionally internal. Schema selection is performed
// by the C1 service after physical clone authorization; never by the sender.
// The ordinary governed-Pending runtime continues to use the established
// restricted privateProjectionTx SQL rewriter unchanged.
func c1SQLProjectorTx(tx pgx.Tx, schema string) pgx.Tx {
    if schema=="fi" {
        return tx
    }
    return privateProjectionTx{Tx:tx,schema:schema}
}
