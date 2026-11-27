-- Copyright (c) 2026 John Joseph Wood. All rights reserved.
-- Use of this source code is governed by the File Intelligence (FI)
-- Source Review License, Version 1.0, found in the repository root LICENSE file.

-- Remove the unused Windows Security field-name lookup index.
-- Preserve all source events, fields, keys, and relationships.
--
-- This migration must execute outside a transaction block.

DROP INDEX CONCURRENTLY fi.windows_security_event_field_name_idx;
