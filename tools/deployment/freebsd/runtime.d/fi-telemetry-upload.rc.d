#!/bin/sh
# PROVIDE: fi_telemetry_upload
# REQUIRE: LOGIN postgresql
# KEYWORD: shutdown
# This uploader MUST be installed ONLY in the fi-sor jail.
. /etc/rc.subr
name=fi_telemetry_upload
rcvar=fi_telemetry_upload_enable
load_rc_config "$name"
: "${fi_telemetry_upload_enable:=NO}"
: "${fi_telemetry_upload_spool:=/var/db/fi/telemetry/spool}"
: "${fi_telemetry_upload_dsn:=}"
pidfile=/var/run/fi-telemetry-upload.pid
start_cmd=fi_telemetry_upload_start
stop_cmd=fi_telemetry_upload_stop
status_cmd=fi_telemetry_upload_status
fi_telemetry_upload_status(){
 [ -s "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null
}
fi_telemetry_upload_start(){
 [ "$fi_telemetry_upload_enable" = YES ] || return 1
 [ ! -e "$pidfile" ] || { echo "FI uploader: stale/live PID requires audit" >&2; return 1; }
 [ -x /usr/local/sbin/fi-telemetry-backend ] || return 1
 [ -d "$fi_telemetry_upload_spool" ] && [ -d /var/log/fi ] || return 1
 [ -n "$fi_telemetry_upload_dsn" ] || return 1
 # Recorder role has write access to fi_telemetry telemetry_v2 ONLY.
 FI_TELEMETRY_RECORDER_DSN=$fi_telemetry_upload_dsn
 export FI_TELEMETRY_RECORDER_DSN
 /usr/sbin/daemon -u fi-telemetry-recorder -p "$pidfile" \
    -o /var/log/fi/fi-telemetry-upload.log \
    /usr/local/sbin/fi-telemetry-backend -mode upload \
    -spool "$fi_telemetry_upload_spool"
}
fi_telemetry_upload_stop(){
 fi_telemetry_upload_status || return 1
 kill -TERM "$(cat "$pidfile")"
}
run_rc_command "$1"
