#!/bin/sh
# FI C1 read-only FreeBSD C220 resource monitor. Ctrl+C finishes the capture.
# No PostgreSQL connection, ZFS change, FI input change, or benchmark kill.
set -eu
umask 077
[ "$(id -un)" = root ] && [ "$(hostname -s)" = c220 ] ||
    { echo 'Run as root on c220 only' >&2; exit 1; }
[ "$#" -le 1 ] || { echo 'Usage: sh script [new-output-directory]' >&2; exit 1; }
out=${1:-/var/tmp/fi-c1-resources-$(date -u '+%Y%m%dT%H%M%SZ')}
case "$out" in /var/tmp/fi-c1-resources-*) : ;; *) echo 'invalid output path' >&2; exit 1 ;; esac
[ ! -e "$out" ] && [ ! -L "$out" ] || { echo 'output exists' >&2; exit 1; }
mkdir -m 0700 "$out"
snap() {
    phase=$1
    {
        printf 'utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        uname -a
        sysctl hw.ncpu hw.physmem kern.cp_time 2>&1 || :
        sysctl vm.stats.vm.v_free_count vm.stats.vm.v_inactive_count \
            vm.stats.vm.v_wire_count vm.stats.vm.v_active_count \
            vm.stats.vm.v_cache_count 2>&1 || :
        swapinfo -k 2>&1 || :
        zpool list -p -o name,size,allocated,free,fragmentation,capacity,health fast work zroot 2>&1 || :
        zpool status -v fast work zroot 2>&1 || :
        zfs list -p -o name,used,avail,refer,mountpoint -r fast work zroot 2>&1 || :
    } > "$out/host_$phase.txt"
    sysctl -a 2>/dev/null | grep '^kstat\.zfs\.misc\.arcstats\.' > "$out/arc_$phase.txt" || :
}
snap before
pids=''
start_sampler() {
    label=$1; shift
    "$@" > "$out/$label.txt" 2>&1 &
    pids="$pids $!"
}
start_sampler vmstat vmstat -w 5
start_sampler physical_disks iostat -x -w 5
start_sampler zpool_vdev_io zpool iostat -v -p fast work zroot 5
start_sampler zpool_vdev_latency zpool iostat -l -v -p fast work zroot 5
start_sampler zpool_vdev_queues zpool iostat -q -v -p fast work zroot 5
(
    while :; do
        printf '\n### UTC %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        # Command names, not argv: do not capture credentials in DSNs.
        ps -ax -o pid,jid,comm,pcpu,rss,vsz,state 2>&1 || :
        sleep 5
    done
) > "$out/processes_5s.txt" 2>&1 &
pids="$pids $!"
(
    while :; do
        printf '\n### UTC %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        sysctl kern.cp_time 2>&1 || :
        sysctl vm.stats.vm.v_free_count vm.stats.vm.v_inactive_count \
            vm.stats.vm.v_wire_count vm.stats.vm.v_active_count \
            vm.stats.vm.v_cache_count 2>&1 || :
        swapinfo -k 2>&1 || :
        sysctl kstat.zfs.misc.arcstats.size kstat.zfs.misc.arcstats.hits \
            kstat.zfs.misc.arcstats.misses kstat.zfs.misc.arcstats.c \
            kstat.zfs.misc.arcstats.c_max 2>&1 || :
        sleep 5
    done
) > "$out/host_5s.txt" 2>&1 &
pids="$pids $!"
finish() {
    trap - 0 1 2 15
    for pid in $pids; do kill -TERM "$pid" 2>/dev/null || :; done
    for pid in $pids; do wait "$pid" 2>/dev/null || :; done
    snap after
    printf 'FI C1 RESOURCE TELEMETRY CAPTURED: %s\n' "$out"
    printf 'Bundle: tar -C /var/tmp -czf %s.tar.gz %s\n' "$out" "$(basename "$out")"
}
trap 'finish' 0
trap 'exit 130' 2
trap 'exit 143' 15
printf 'FI C1 TELEMETRY START UTC=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
printf 'Output: %s\nCtrl+C to finish and save snapshots.\n' "$out"
while :; do sleep 60; done
