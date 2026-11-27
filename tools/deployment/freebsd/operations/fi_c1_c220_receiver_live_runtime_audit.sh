#!/bin/sh
# Read-only C220 audit for current FI receiver live generation publication.
# No receiver restart, config edits, mounts, custody mutation or SQL writes.
set -eu
[ "$#" -eq 1 ] && [ "$1" = --audit ] || {
  echo 'usage: fi_c1_c220_receiver_live_runtime_audit.sh --audit' >&2
  exit 1
}
[ "$(id -u)" -eq 0 ] && [ "$(uname -s)" = FreeBSD ] &&
[ "$(hostname -s)" = c220 ] || {
  echo 'STOP: physical root@c220 on FreeBSD required' >&2
  exit 1
}
for jail in fi-receiver fi-sor;do
  jls -j "$jail" >/dev/null || {
    echo "STOP: jail $jail is not running" >&2
    exit 1
  }
done
echo '===== RECEIVER SERVICE STATUS (do not restart) ====='
jexec fi-receiver service fi_receiver onestatus 2>&1 || :
echo '===== RECEIVER PROCESS ARGUMENTS (live, not inferred from config) ====='
jexec fi-receiver ps -axww -o pid,ppid,user,command |
  grep -E 'fi-receiver|PID' || :
echo '===== EXPLICIT LIVE GENERATION FLAGS ====='
cmds=$(jexec fi-receiver ps -axww -o command=)
for arg in \
  '-transport-listen' \
  '-generation-enable' \
  '-generation-ready-root /var/db/fi/custody/ready' \
  '-generation-verified-cache-root /var/db/fi/verified-cache';do
  if printf '%s\n' "$cmds" | grep -F -- "$arg" >/dev/null;then
    echo "LIVE_FLAG_PASS: $arg"
  else
    echo "LIVE_FLAG_MISSING: $arg"
  fi
done
echo '===== INSTALLED RECEIVER CONFIGURATION (selected keys only) ====='
jexec fi-receiver /bin/sh -c '
  file=/etc/rc.conf.d/fi_receiver
  if [ -f "$file" ] && [ ! -L "$file" ];then
    grep -E "^fi_receiver_(enable|bind|generation_(custody_root|recorded_root|ready_root|verified_cache_root))=" "$file" || :
  else
    echo "BLOCKER: fi_receiver rc configuration missing or symlink"
  fi
'
echo '===== INSTALLED RECEIVER EXECUTABLE AND SUPERVISOR ====='
jexec fi-receiver ls -l /usr/local/sbin/fi-receiver /usr/local/libexec/fi-receiver-supervisor 2>&1 || :
echo '===== INSTALLED SUPERVISOR FLAG REFERENCES ====='
jexec fi-receiver /bin/sh -c '
  file=/usr/local/libexec/fi-receiver-supervisor
  if [ -f "$file" ] && [ ! -L "$file" ];then
    grep -n -E "generation-(enable|ready-root|verified-cache-root)" "$file" || :
  else
    echo "BLOCKER: receiver supervisor absent or symlink"
  fi
'
echo '===== VERIFIED CACHE AND READY MOUNT OBSERVATIONS ====='
mount -p | grep -E '/verified-cache |/custody/ready ' || :
echo '===== CACHE ACCESS AS SERVICE USERS ====='
if jexec -U fi-receiver fi-receiver test -w /var/db/fi/verified-cache;then
  echo 'RECEIVER_CACHE_WRITE_ACCESS=PASS'
else
  echo 'RECEIVER_CACHE_WRITE_ACCESS=FAIL'
fi
if jexec -U fi-sor fi-sor test -r /var/db/fi/verified-cache;then
  echo 'SOR_CACHE_READ_ACCESS=PASS'
else
  echo 'SOR_CACHE_READ_ACCESS=FAIL'
fi
echo '===== C1 LIVE SERVICE STATUS ====='
jexec fi-sor service fi_c1_sor_live onestatus 2>&1 || :
echo 'FI C1 RECEIVER RUNTIME AUDIT COMPLETE read_only=true no_restart=true'
