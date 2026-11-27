#!/bin/sh
# FreeBSD fi-sor: normal signed READY intake, NOT the obsolete fi-ingest jail.
set -eu
umask 077
[ "$(id -u)" -ne 0 ] && [ "$(id -un)" = fi-sor ] ||
    { echo "FI C1 LIVE STOP: fi-sor identity required" >&2; exit 1; }
. /etc/rc.conf.d/fi_c1_sor
. /etc/rc.conf.d/fi_c1_sor_live
: "${fi_c1_sor_postgres_local:?worker socket DSN required}"
: "${fi_c1_sor_postgres_publisher_local:?publisher socket DSN required}"
: "${fi_c1_sor_custody_root:?custody required}"
: "${fi_c1_sor_recorded_root:?original recorded receipts required}"
: "${fi_c1_sor_live_sources:?explicit registered source roster required}"
: "${fi_c1_sor_live_ready_root:?original READY required}"
: "${fi_c1_sor_live_cache_root:?receiver cache required}"
: "${fi_c1_sor_live_staging_root:?disposable scratch required}"
[ "${FI_C1_LIVE_PREFLIGHT:-NO}" = YES ] || [ "$fi_c1_sor_live_enable" = YES ] ||
    { echo "FI C1 LIVE STOP: not enabled" >&2; exit 1; }
[ "${fi_c1_sor_reconcile_private_replay:-NO}" = NO ] ||
    { echo "FI C1 LIVE STOP: automatic Pending replay forbidden" >&2; exit 1; }
if [ -n "${fi_c1_sor_pgpass:-}" ]; then
    PGPASSFILE=$fi_c1_sor_pgpass
    export PGPASSFILE
fi
set -- -sources "$fi_c1_sor_live_sources" \
    -ready-root "$fi_c1_sor_live_ready_root" -ready-batch-size 16 \
    -custody-root "$fi_c1_sor_custody_root" \
    -recorded-root "$fi_c1_sor_recorded_root" \
    -receiver-verified-cache-root "$fi_c1_sor_live_cache_root" \
    -postgres-local "$fi_c1_sor_postgres_local" \
    -postgres-publisher-local "$fi_c1_sor_postgres_publisher_local" \
    -sql-workers-max 32 -staging-root "$fi_c1_sor_live_staging_root"
case "${fi_c1_sor_source_namespaces:-NO}" in
    YES) set -- "$@" -source-namespaces ;;
    NO) ;;
    *) echo "FI C1 LIVE STOP: source namespace configuration invalid" >&2; exit 1 ;;
esac
if [ "${FI_C1_LIVE_PREFLIGHT:-NO}" = YES ]; then
    exec /usr/local/sbin/fi-c1-sor-live "$@" -preflight
fi
exec /usr/local/sbin/fi-c1-sor-live "$@" -continuous -poll-interval 5s
