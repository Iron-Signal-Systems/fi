#!/bin/sh
# PROVIDE: fi_c1_sor_local
# REQUIRE: NETWORKING
# KEYWORD: shutdown
#
# FI single-jail original C1. Disabled by default; never co-start the old
# fi_c1_sor two-jail server or any fi-ingest worker.
. /etc/rc.subr
name="fi_c1_sor_local"
rcvar="fi_c1_sor_local_enable"
load_rc_config "$name"
: ${fi_c1_sor_local_enable:="NO"}
command="/usr/sbin/daemon"
procname="/usr/sbin/daemon"
pidfile="/var/run/fi-c1-sor-local.pid"
required_files="/usr/local/sbin/fi-c1-sor-local /usr/local/libexec/fi-c1-sor-local-run /etc/rc.conf.d/fi_c1_sor_local /etc/rc.conf.d/fi_c1_sor"
command_args="-P ${pidfile} -u fi-sor -S -T fi-c1-sor-local /usr/local/libexec/fi-c1-sor-local-run"
run_rc_command "$1"
