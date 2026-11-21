#!/bin/sh
# FI C1 C220 host and existing backend telemetry discovery.
# READ-ONLY. Does not create/start jails, change database configuration,
# access secret passfiles, touch journal rows, or launch an acceptance run.
set -eu
umask 077
fail(){ printf 'FI C1 INVENTORY STOP: %s\n' "$*" >&2; exit 1; }
[ "$(id -un)" = root ] && [ "$(hostname -s)" = c220 ] ||
  fail 'requires root on physical c220'

echo '===== FREEBSD HOST / JAIL INVENTORY ====='
date -u '+observed_at_utc=%Y-%m-%dT%H:%M:%SZ'
uname -sr
jls -h jid name host.hostname path 2>&1 || :
for jailname in fi-sor-db fi-dev fi-receiver fi-ingest;do
  if jls -j "$jailname" jid >/dev/null 2>&1;then
    echo "JAIL_RUNNING name=$jailname"
  else
    echo "JAIL_NOT_RUNNING_OR_NOT_FOUND name=$jailname"
  fi
done

echo '===== FI JAIL CONFIG FILENAMES (NO SECRETS) ====='
for f in /etc/jail.conf /etc/jail.conf.d/*.conf;do
  [ -f "$f" ] && ls -ld "$f" || :
done

echo '===== FI SERVICE PROCESS NAMES ONLY ====='
for jailname in fi-sor-db fi-ingest fi-receiver fi-dev;do
  if jls -j "$jailname" jid >/dev/null 2>&1;then
    echo "JAIL_PROCESS_LIST name=$jailname"
    jexec "$jailname" ps -axo pid,user,comm 2>&1 | head -n 35 || :
  fi
done

echo '===== TELEMETRY PROJECT DIRECTORY NAMES ====='
for root in /home/jwood /var/tmp /fast;do
  [ -d "$root" ] || continue
  find "$root" -maxdepth 2 -type d -iname '*telemetry*' -print 2>/dev/null | head -n 30 || :
done

echo '===== C220 ZFS POOLS ====='
zpool list -H -o name,health,alloc,free 2>&1 || :

if jls -j fi-sor-db jid >/dev/null 2>&1;then
  echo '===== REAL DEVELOPMENT SOR POSTGRESQL READINESS ====='
  jexec -U postgres fi-sor-db pg_isready -h /var/db/fi/sor/run -p 5432 2>&1 || :
  echo '===== FI AND TELEMETRY DB PRESENCE (READ ONLY) ====='
  jexec -U postgres fi-sor-db psql -X -w -h /var/db/fi/sor/run -p 5432 -d postgres     -v ON_ERROR_STOP=1 -At -c \
    "SELECT datname FROM pg_database WHERE datname IN ('fi','fi_telemetry') ORDER BY datname" 2>&1 || :
  echo '===== EXISTING TELEMETRY SCHEMA AND COUNTS ====='
  if jexec -U postgres fi-sor-db psql -X -w -h /var/db/fi/sor/run -p 5432 -d fi_telemetry \
      -v ON_ERROR_STOP=1 -At -c "SELECT 1" >/dev/null 2>&1;then
    tables=$(jexec -U postgres fi-sor-db psql -X -w -h /var/db/fi/sor/run -p 5432 -d fi_telemetry \
      -v ON_ERROR_STOP=1 -At -c "SELECT (to_regclass('telemetry.entry') IS NOT NULL AND to_regclass('telemetry.delivery_receipt') IS NOT NULL)::int") || :
    if [ "$tables" = 1 ];then
      jexec -U postgres fi-sor-db psql -X -w -h /var/db/fi/sor/run -p 5432 -d fi_telemetry \
        -v ON_ERROR_STOP=1 -At -c \
        "BEGIN READ ONLY; SELECT 'entry='||(SELECT count(*) FROM telemetry.entry)::text||' receipts='||(SELECT count(*) FROM telemetry.delivery_receipt)::text; COMMIT;" || :
    else
      echo 'TELEMETRY TABLES ABSENT_OR_INCOMPLETE'
    fi
  else
    echo 'TELEMETRY DB ABSENT_OR_UNAVAILABLE'
  fi
else
  echo 'FI SOR DATABASE CHECK SKIPPED: fi-sor is not running under that name'
fi
echo '===== READ-ONLY C220 INVENTORY COMPLETE ====='
