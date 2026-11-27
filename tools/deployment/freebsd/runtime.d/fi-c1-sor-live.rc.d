#!/bin/sh
# PROVIDE: fi_c1_sor_live
# REQUIRE: LOGIN postgresql
# KEYWORD: shutdown
. /etc/rc.subr
name=fi_c1_sor_live
rcvar=fi_c1_sor_live_enable
load_rc_config "$name"
: "${fi_c1_sor_live_enable:=NO}"
pidfile=/var/run/fi-c1-sor-live.pid
start_cmd=fi_c1_sor_live_start
stop_cmd=fi_c1_sor_live_stop
status_cmd=fi_c1_sor_live_status
fi_c1_sor_live_status() {
    if [ -s "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
        echo "FI C1 live running pid=$(cat "$pidfile")"
        return 0
    fi
    echo "FI C1 live not running"
    return 1
}
fi_c1_sor_live_start() {
    [ "$fi_c1_sor_live_enable" = YES ] || return 1
    if [ -e "$pidfile" ]; then
        echo "FI C1 LIVE STOP: existing PID file requires review" >&2
        return 1
    fi
    [ -x /usr/local/libexec/fi-c1-sor-live-run ] || return 1
    [ -x /usr/local/sbin/fi-c1-sor-live ] || return 1
    [ -d /var/log/fi ] || return 1
    # Preflight is run from the physical host with jexec -U fi-sor BEFORE
    # service activation; FreeBSD su -c selects a login class, not a command.
    # No -r: an ambiguous commit or independent B error must STOP intake,
    # leaving READY/custody intact for manual authoritative reconciliation.
    /usr/sbin/daemon -u fi-sor -p "$pidfile" \
        -o /var/log/fi/fi-c1-sor-live.log \
        /usr/local/libexec/fi-c1-sor-live-run
}
fi_c1_sor_live_stop() {
    fi_c1_sor_live_status >/dev/null 2>&1 || return 1
    kill -TERM "$(cat "$pidfile")"
    echo "FI C1 live termination requested"
}
run_rc_command "$1"
