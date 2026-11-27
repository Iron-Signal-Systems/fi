#!/bin/sh
# C220 READ ONLY telemetry availability/coverage gate. No FI or telemetry edits.
set -eu
[ "$(id -u)" -eq 0 ] && [ "$(hostname -s)" = c220 ] ||
 { echo "FI TELEMETRY GATE: physical root@c220 required" >&2; exit 1; }
[ "$#" -eq 1 ] && [ "$1" = --audit ] ||
 { echo "usage: sh fi_c1_c220_telemetry_acceptance.sh --audit" >&2; exit 1; }
echo "===== RUNNING TELEMETRY SERVICES ====="
service fi_telemetry_sample onestatus || exit 1
jexec fi-sor service fi_telemetry_sample onestatus || exit 1
jexec fi-sor service fi_telemetry_upload onestatus || exit 1
echo "===== FI TELEMETRY DATABASE/SCHEMA, FRESH SAMPLES, DELIVERY ====="
jexec -U postgres fi-sor psql -X -w -v ON_ERROR_STOP=1 \
  -P pager=off -h /var/db/fi/sor/run -p 5432 -d fi_telemetry <<'SQL'
BEGIN READ ONLY;
DO $telemetry_gate$
DECLARE
 host_count bigint; sor_count bigint; receipts bigint;
 first_sample timestamptz; last_sample timestamptz;
 last_receipt timestamptz;
BEGIN
 IF to_regclass('telemetry_v2.entry') IS NULL OR
    to_regclass('telemetry_v2.delivery_receipt') IS NULL THEN
   RAISE EXCEPTION 'telemetry_v2 database schema absent';
 END IF;
 SELECT count(*) FILTER (WHERE payload->'Data'->>'scope'='c220-host'),
        count(*) FILTER (WHERE payload->'Data'->>'scope'='fi-sor'),
        min(observed_at),max(observed_at)
 INTO host_count,sor_count,first_sample,last_sample
 FROM telemetry_v2.entry
 WHERE stream='samples' AND observed_at > now()-interval '15 minutes';
 SELECT count(*),max(delivered_at)
 INTO receipts,last_receipt
 FROM telemetry_v2.delivery_receipt;
 IF host_count<2 OR sor_count<2 OR
    -- Database samples arrive in 5-minute upload batches. Allow one
    -- bounded delivery delay; the separate receipt check still enforces
    -- successful live publication within the last seven minutes.
    last_sample<now()-interval '7 minutes' OR
    last_receipt IS NULL OR last_receipt<now()-interval '7 minutes' THEN
   RAISE EXCEPTION 'FI telemetry coverage incomplete: host=% sor=% newest=% last_delivery=%',
      host_count,sor_count,last_sample,last_receipt;
 END IF;
 RAISE NOTICE 'FI TELEMETRY COVERAGE PASS host_samples=% sor_samples=% first=% newest=% receipts=% latest_receipt=%',
  host_count,sor_count,first_sample,last_sample,receipts,last_receipt;
END $telemetry_gate$;
COMMIT;
SQL
echo "FI C220 TELEMETRY ACCEPTANCE PASS recent_samples=true live_delivery=true"
