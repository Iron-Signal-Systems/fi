#!/bin/sh
# Explicit C220 telemetry-only PostgreSQL peer auth. No FI data modification.
# --audit never changes files. --apply saves original pg_hba.conf for rollback.
set -eu
umask 077
stop(){ echo "FI TELEMETRY PEER STOP: $*" >&2; exit 1; }
[ "$#" -eq 1 ] || stop 'usage: --audit|--apply'
case "$1" in --audit|--apply) mode=$1;;*) stop 'unknown mode';;esac
[ "$(hostname -s)" = c220 ] && [ "$(id -u)" -eq 0 ] &&
[ "$(uname -s)" = FreeBSD ] || stop "physical root@c220 required"
jls -j fi-sor >/dev/null || stop "fi-sor not running"
sor=/fast/jails/roots/fi-sor
sql(){ jexec -U postgres fi-sor psql -X -w -At -v ON_ERROR_STOP=1 \
    -h /var/db/fi/sor/run -p 5432 -d postgres -c "$1"; }
[ "$(sql "SELECT system_identifier::text FROM pg_control_system()")" = 7690295447535908318 ] ||
  stop 'wrong real PostgreSQL cluster'
hba=$(sql "SHOW hba_file")
[ "$hba" = /var/db/fi/sor/postgres/pg_hba.conf ] ||
  stop "unexpected pg_hba_file: $hba"
file=$sor$hba
[ -f "$file" ] && [ ! -L "$file" ] || stop 'unsafe PostgreSQL HBA file'
line1='local fi "fi-telemetry-monitor" peer'
line2='local fi_telemetry "fi-telemetry-recorder" peer'
[ "$(sql "SELECT count(*) FROM pg_roles WHERE rolname IN ('fi-telemetry-monitor','fi-telemetry-recorder')")" = 2 ] ||
  stop 'telemetry roles not staged'
jexec fi-sor id fi-telemetry-monitor >/dev/null ||
  stop 'fi-sor monitoring service account missing'
jexec fi-sor id fi-telemetry-recorder >/dev/null ||
  stop 'fi-sor recorder service account missing'
peer(){
 jexec -U fi-telemetry-monitor fi-sor psql -X -w -At \
  -h /var/db/fi/sor/run -p 5432 -d fi -c 'SELECT current_user' 2>/dev/null |
  grep -Fx fi-telemetry-monitor >/dev/null &&
 jexec -U fi-telemetry-recorder fi-sor psql -X -w -At \
  -h /var/db/fi/sor/run -p 5432 -d fi_telemetry -c 'SELECT current_user' 2>/dev/null |
  grep -Fx fi-telemetry-recorder >/dev/null
}
echo "===== TELEMETRY-ONLY PEER AUTH ====="
if peer;then
 echo "FI TELEMETRY PEER PASS already_enabled=true"
 exit 0
fi
echo "FI TELEMETRY PEER missing=true"
if [ "$mode" = --audit ];then
 echo "FI TELEMETRY PEER AUDIT COMPLETE read_only=true"
 exit 0
fi
if grep -F 'fi-telemetry-monitor' "$file" >/dev/null ||
   grep -F 'fi-telemetry-recorder' "$file" >/dev/null;then
 stop 'existing telemetry HBA entries present but peer failed; inspect manually'
fi
backup=/var/backups/fi-telemetry-hba-$(date -u '+%Y%m%dT%H%M%SZ')
install -d -o root -g wheel -m 0700 "$backup"
cp -p "$file" "$backup/pg_hba.conf"
tmp=$(mktemp "$file.telemetry.XXXXXXXX")
trap 'rm -f "$tmp"' EXIT HUP INT TERM
{
 printf '%s\n' "$line1" "$line2"
 cat "$backup/pg_hba.conf"
} > "$tmp"
chown postgres:postgres "$tmp"
chmod 0600 "$tmp"
mv -f "$tmp" "$file"
if [ "$(sql 'SELECT pg_reload_conf()')" != t ];then
 cp -p "$backup/pg_hba.conf" "$file"
 sql 'SELECT pg_reload_conf()' >/dev/null || :
 stop 'PG reload failed; original HBA restored'
fi
errs=$(sql "SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL")
if [ "$errs" != 0 ];then
 cp -p "$backup/pg_hba.conf" "$file"
 sql 'SELECT pg_reload_conf()' >/dev/null || :
 stop 'PG HBA parser errors; original HBA restored'
fi
n=0
while [ "$n" -lt 10 ]; do
 if peer;then
   echo "FI TELEMETRY PEER PASS new_rules=2 original_hba_backup=$backup/pg_hba.conf"
   exit 0
 fi
 n=$((n + 1))
 sleep 1
done
cp -p "$backup/pg_hba.conf" "$file"
sql 'SELECT pg_reload_conf()' >/dev/null || :
stop 'telemetry peer identities still denied; original HBA restored'
