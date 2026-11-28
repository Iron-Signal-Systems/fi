//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Export only the EXACT existing canonical FI migration bytes for a C1
// development-only offline private-projection schema constructor. No SQL
// mutation, new migration version or ordinary backend installer behavior.
package recordingest

import (
    "crypto/sha256"
    "encoding/hex"
    "errors"
)

type C1CanonicalMigration struct {
    Name string
    SQL string
    SHA256 string
}
func c1CanonicalSchemaMigrations()([]C1CanonicalMigration,error){
    original:=sorPostgreSQLDatabaseMigrationAssets()
    if len(original)!=7{return nil,errors.New("FI C1: frozen canonical migration count changed")}
    out:=make([]C1CanonicalMigration,0,len(original))
    for _,item:=range original{
        digest:=sha256.Sum256([]byte(item.SQL))
        if item.SQL==""||hex.EncodeToString(digest[:])!=item.SHA256{
            return nil,errors.New("FI C1: embedded canonical SQL migration checksum changed")
        }
        out=append(out,C1CanonicalMigration{Name:item.Name,SQL:item.SQL,SHA256:item.SHA256})
    }
    return out,nil
}
