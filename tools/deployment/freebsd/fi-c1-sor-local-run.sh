#!/bin/sh
# FI C1 single-jail service runner. Must run as unprivileged fi-sor.
# The old two-jail SoR config remains the source of local SQL role/PGPASS
# credentials during the migration; no TLS/RAM or fi-ingest process is used.
set -eu
verify=NO
case "${1:-}" in
    --verify) [ "$#" -eq 1 ] || exit 1; verify=YES ;;
    "") [ "$#" -eq 0 ] || exit 1 ;;
    *) echo "FI C1 local runner: unsupported argument" >&2; exit 1 ;;
esac
[ "$(id -un)" = fi-sor ] ||
    { echo 'FI C1 local runner requires fi-sor identity' >&2; exit 1; }
old=/etc/rc.conf.d/fi_c1_sor
localconf=/etc/rc.conf.d/fi_c1_sor_local
[ -f "$old" ] && [ ! -L "$old" ] &&
[ -f "$localconf" ] && [ ! -L "$localconf" ] ||
    { echo 'FI C1 local runner: missing or unsafe configuration' >&2; exit 1; }
. "$old"
. "$localconf"
: "${fi_c1_sor_postgres_local:?}"
: "${fi_c1_sor_postgres_publisher_local:?}"
: "${fi_c1_sor_custody_root:?}"
: "${fi_c1_sor_recorded_root:?}"
: "${fi_c1_sor_local_sources:?}"
: "${fi_c1_sor_local_ready_root:?}"
: "${fi_c1_sor_local_stage_root:?}"
if [ -n "${fi_c1_sor_pgpass:-}" ]; then
    [ -f "$fi_c1_sor_pgpass" ] && [ ! -L "$fi_c1_sor_pgpass" ] &&
    [ -r "$fi_c1_sor_pgpass" ] &&
    [ "$(stat -f '%#Lp' "$fi_c1_sor_pgpass")" = 0600 ] ||
        { echo 'FI C1 local runner: unsafe fi-sor SCRAM passfile' >&2; exit 1; }
    PGPASSFILE=$fi_c1_sor_pgpass
    export PGPASSFILE
fi
set -- \
    -sources "$fi_c1_sor_local_sources" \
    -ready-root "$fi_c1_sor_local_ready_root" \
    -ready-batch-size "${fi_c1_sor_local_ready_batch_size:-16}" \
    -poll-interval "${fi_c1_sor_local_poll_interval:-5s}" \
    -custody-root "$fi_c1_sor_custody_root" \
    -recorded-root "$fi_c1_sor_recorded_root" \
    -postgres-local "$fi_c1_sor_postgres_local" \
    -postgres-publisher-local "$fi_c1_sor_postgres_publisher_local" \
    -sql-workers-max "${fi_c1_sor_local_sql_workers_max:-32}" \
    -staging-root "$fi_c1_sor_local_stage_root"
case "${fi_c1_sor_source_namespaces:-NO}" in
    YES) set -- "$@" -source-namespaces ;;
    NO) ;;
    *) echo 'FI C1 local runner: invalid original source namespace configuration' >&2; exit 1 ;;
esac
if [ "$verify" = YES ];then
    set -- "$@" -preflight
else
    set -- "$@" -continuous
fi
exec /usr/local/sbin/fi-c1-sor-local "$@"
