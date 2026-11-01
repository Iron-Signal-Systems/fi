// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
 "context"
 "fmt"

 "github.com/jackc/pgx/v5"
)

// At each bounded private commit check only source rows from THIS window.
// The complete-generation verifier performs one full coverage scan at the end.
// Scanning all previous windows after every commit would grow quadratically
// for the 8,399-batch real signed backlog.
func verifyBacklogWindowProjectionCoverage(ctx context.Context, tx pgx.Tx,
 generationID int64,batches []PreparedBatch)error {
 if generationID<=0||len(batches)==0{return fmt.Errorf("FI backlog window coverage: missing generation or batches")}
 ids:=make([]string,len(batches))
 for i,b:=range batches{
  if b.BatchID==""{return fmt.Errorf("FI backlog window coverage: empty batch identity")}
  ids[i]=b.BatchID
 }
 var missing int64
 err:=tx.QueryRow(ctx,`
SELECT count(*)
FROM fi.source_record sr
JOIN fi.source_batch sb ON sb.source_batch_id=sr.source_batch_id
WHERE sb.recorded_generation_id=$1 AND sb.batch_id=ANY($2::text[])
 AND CASE sr.record_kind
    WHEN 'CollectorIdentity' THEN NOT EXISTS (SELECT 1 FROM fi.collector_identity x WHERE x.source_record_id=sr.source_record_id)
    WHEN 'DirectoryPrincipalSnapshot' THEN NOT EXISTS (SELECT 1 FROM fi.directory_principal_snapshot x WHERE x.source_record_id=sr.source_record_id)
    WHEN 'FileObservation' THEN NOT EXISTS (SELECT 1 FROM fi.file_observation x WHERE x.source_record_id=sr.source_record_id)
    WHEN 'LocalPrincipalSnapshot' THEN NOT EXISTS (SELECT 1 FROM fi.local_principal_snapshot x WHERE x.source_record_id=sr.source_record_id)
    WHEN 'NTFSCollectionError' THEN NOT EXISTS (SELECT 1 FROM fi.ntfs_collection_error x WHERE x.source_record_id=sr.source_record_id)
    WHEN 'SMBShareSnapshot' THEN NOT EXISTS (SELECT 1 FROM fi.smb_share_snapshot x WHERE x.source_record_id=sr.source_record_id)
    WHEN 'SupportingSourceCollectionError' THEN NOT EXISTS (SELECT 1 FROM fi.supporting_source_collection_error x WHERE x.source_record_id=sr.source_record_id)
    WHEN 'USNContinuityGap' THEN NOT EXISTS (SELECT 1 FROM fi.usn_continuity_gap x WHERE x.source_record_id=sr.source_record_id)
    WHEN 'USNObjectObservation' THEN NOT EXISTS (SELECT 1 FROM fi.usn_object_observation x WHERE x.source_record_id=sr.source_record_id)
    WHEN 'USNReadBoundary' THEN NOT EXISTS (SELECT 1 FROM fi.usn_read_boundary x WHERE x.source_record_id=sr.source_record_id)
    WHEN 'WindowsSecurityContinuityGap' THEN NOT EXISTS (SELECT 1 FROM fi.windows_security_continuity_gap x WHERE x.source_record_id=sr.source_record_id)
    WHEN 'WindowsSecurityCoverage' THEN NOT EXISTS (SELECT 1 FROM fi.windows_security_coverage x WHERE x.source_record_id=sr.source_record_id)
    WHEN 'WindowsSecurityEvent' THEN NOT EXISTS (SELECT 1 FROM fi.windows_security_event x WHERE x.source_record_id=sr.source_record_id)
    ELSE true
 END
`,generationID,ids).Scan(&missing)
 if err!=nil{return fmt.Errorf("FI backlog window coverage: %w",err)}
 if missing!=0{return fmt.Errorf("%w: private window missing %d typed roots",ErrSourceRecordRejected,missing)}
 return nil
}
