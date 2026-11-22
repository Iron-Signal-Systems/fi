#!/bin/sh
# FI C1: real C220 existing-jail integration inventory.
# READ-ONLY: no jail start/restart, mount, service, SQL write or user creation.
set -eu
umask 077
fail(){ printf 'FI C1 JAIL CONTRACT STOP: %s\n' "$*" >&2; exit 1; }
[ "$(id -un)" = root ] && [ "$(hostname -s)" = c220 ] ||
  fail 'requires root on physical c220'

echo '===== ACTUAL C220 FI JAIL PATHS ====='
for jail in fi-ingest fi-sor fi-receiver; do
  jls -j "$jail" jid >/dev/null 2>&1 || fail "required existing jail not running: $jail"
done
if jls -j fi-sor-db jid >/dev/null 2>&1; then
  fail 'both fi-sor and fi-sor-db running: ambiguous C1 SoR ownership'
fi
jls -h jid name path

echo '===== EXISTING FI SERVICE IDENTITIES (NO CHANGES) ====='
jexec fi-ingest id fi-ingest || fail 'fi-ingest user missing'
if jexec fi-sor id fi-sor; then
  echo 'C1_SOR_RUNTIME_IDENTITY=PRESENT'
else
  echo 'C1_SOR_RUNTIME_IDENTITY=ABSENT'
fi
jexec fi-sor id postgres || fail 'existing PostgreSQL identity missing'
echo '===== EXACT FI JAIL CONFIG FILE REFERENCES ====='
# Show only jail and mount-management lines. Do not print full configs,
# PKI keys, PostgreSQL passwords or rc.conf secrets.
for f in /etc/jail.conf /etc/jail.conf.d/*.conf /usr/local/etc/jail.conf; do
  [ -f "$f" ] || continue
  echo "FILE=$f"
  grep -nE '^[[:space:]]*(include|[.]include|mount[.]fstab|mount[.]devfs|mount[.]nodevfs|mount[.]procfs|path[[:space:]]*=|exec[.]start|exec[.]stop|fi-ingest|fi-sor|fi-receiver|jail[.]conf)' "$f" || :
done
echo '===== HOST FSTAB PATHS (NO CONTENTS OR SECRETS) ====='
for f in /etc/fstab /etc/fstab.fi-ingest /etc/fstab.fi-sor \
         /etc/fstab.fi-sor-db /etc/jail.fstab.d/fi-ingest.fstab \
         /etc/jail.fstab.d/fi-sor.fstab /etc/jail.fstab.d/fi-sor-db.fstab; do
  if [ -f "$f" ]; then ls -ld "$f"; fi
done
echo '===== EXISTING FI CUSTODY AND HANDOFF MOUNTS ====='
mount -p | grep -E 'fi-c1-handoff|/fast/jails/roots/fi-(ingest|sor|receiver)/|/work/fi-c220-' || :
echo '===== FI SO R PostgreSQL CLUSTER AND PRIVATE-STAGE ABSENCE ====='
sock=/var/db/fi/sor/run
jexec -U postgres fi-sor pg_isready -h "$sock" -p 5432 >/dev/null ||
  fail 'actual SoR local PostgreSQL socket unavailable'
jexec -U postgres fi-sor psql -X -w -v ON_ERROR_STOP=1 -At \
  -h "$sock" -p 5432 -d fi <<'SQL'
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SELECT 'SQL_DATA_DIRECTORY='||current_setting('data_directory');
SELECT 'CANONICAL_GENERATIONS='||count(*) FROM fi.recorded_generation;
SELECT 'PRIVATE_STAGE_ABSENT='||
 (to_regnamespace('fi_recovery_projection') IS NULL AND
  to_regnamespace('fi_recovery') IS NULL)::text;
COMMIT;
SQL
echo 'FI C1 C220 EXISTING JAIL RUNTIME INVENTORY COMPLETE read_only=true'
