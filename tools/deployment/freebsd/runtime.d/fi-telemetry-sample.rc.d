#!/bin/sh
# PROVIDE: fi_telemetry_sample
# REQUIRE: LOGIN
# KEYWORD: shutdown
# Install on C220 host AND fi-sor jail with scope-specific rc.conf.
. /etc/rc.subr
name=fi_telemetry_sample
rcvar=fi_telemetry_sample_enable
load_rc_config "$name"
: "${fi_telemetry_sample_enable:=NO}"
: "${fi_telemetry_sample_source:=c220-host}"
: "${fi_telemetry_sample_spool:=/var/db/fi/telemetry/spool}"
: "${fi_telemetry_sample_revision:=UNCONFIGURED}"
: "${fi_telemetry_sample_gap_since:=}"
pidfile=/var/run/fi-telemetry-sample.pid
start_cmd=fi_telemetry_sample_start
stop_cmd=fi_telemetry_sample_stop
status_cmd=fi_telemetry_sample_status
fi_telemetry_sample_status(){
 [ -s "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null
}
fi_telemetry_sample_start(){
 [ "$fi_telemetry_sample_enable" = YES ] || return 1
 [ ! -e "$pidfile" ] || { echo "FI telemetry: stale/live PID requires audit" >&2; return 1; }
 [ -x /usr/local/sbin/fi-telemetry-backend ] || return 1
 [ -d "$fi_telemetry_sample_spool" ] && [ -d /var/log/fi ] || return 1
 # Credentials, if used, are available only through restricted rc.conf,
 # NEVER in the process argument list. Separate PG read-only monitor role.
 FI_TELEMETRY_MONITOR_DSN="${fi_telemetry_sample_monitor_dsn:-}"
 export FI_TELEMETRY_MONITOR_DSN
 /usr/sbin/daemon -u fi-telemetry -p "$pidfile" \
    -o /var/log/fi/fi-telemetry-sample.log \
    /usr/local/sbin/fi-telemetry-backend -mode collect \
    -spool "$fi_telemetry_sample_spool" \
    -source "$fi_telemetry_sample_source" \
    -revision "$fi_telemetry_sample_revision" \
    -gap-since "$fi_telemetry_sample_gap_since"
}
fi_telemetry_sample_stop(){
 fi_telemetry_sample_status || return 1
 kill -TERM "$(cat "$pidfile")"
}
run_rc_command "$1"
