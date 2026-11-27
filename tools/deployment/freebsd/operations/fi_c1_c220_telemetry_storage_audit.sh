#!/bin/sh
# Read-only C220 telemetry spool permission-chain audit.
# Checks owner/group/mode of ancestors and effective access by service identities.
set -eu
[ "$#" -eq 1 ] && [ "$1" = --audit ] || {
 echo "usage: sh fi_c1_c220_telemetry_storage_audit.sh --audit" >&2; exit 1;
}
[ "$(id -u)" -eq 0 ] && [ "$(hostname -s)" = c220 ] &&
[ "$(uname -s)" = FreeBSD ] || {
 echo "FI TELEMETRY STORAGE AUDIT: requires physical root@c220 FreeBSD" >&2; exit 1;
}
jls -j fi-sor >/dev/null || {
 echo "FI TELEMETRY STORAGE AUDIT: fi-sor jail is not running" >&2; exit 1;
}
host_dirs='/fast /fast/data /fast/data/fi /fast/data/fi/telemetry /fast/data/fi/telemetry/spool'
jail_dirs='/var /var/db /var/db/fi /var/db/fi/telemetry /var/db/fi/telemetry/spool'
echo "===== HOST PATH METADATA (numeric identity and mode) ====="
for d in $host_dirs;do
 stat -f '%Sp uid=%u gid=%g %N' "$d" 2>&1 || :
done
echo "===== HOST EFFECTIVE PATH ACCESS: fi-telemetry ====="
su -m fi-telemetry -c '
 id
 for d in /fast /fast/data /fast/data/fi /fast/data/fi/telemetry /fast/data/fi/telemetry/spool;do
   if [ -x "$d" ];then
     echo "TRAVERSE PASS $d"
   else
     echo "TRAVERSE DENIED $d"
   fi
 done
 if [ -r /fast/data/fi/telemetry/spool ] &&
    [ -w /fast/data/fi/telemetry/spool ];then
   echo "HOST SPOOL READ/WRITE PASS"
 else
   echo "HOST SPOOL READ/WRITE DENIED"
 fi
' || echo "HOST IDENTITY PROBE FAILED"
echo "===== FI-SOR PATH METADATA (numeric identity and mode) ====="
for d in $jail_dirs;do
 jexec fi-sor stat -f '%Sp uid=%u gid=%g %N' "$d" 2>&1 || :
done
for account in fi-telemetry-monitor fi-telemetry-recorder;do
 echo "===== FI-SOR EFFECTIVE PATH ACCESS: $account ====="
 jexec -U "$account" fi-sor /bin/sh -c '
  id
  for d in /var /var/db /var/db/fi /var/db/fi/telemetry /var/db/fi/telemetry/spool;do
    if [ -x "$d" ];then
      echo "TRAVERSE PASS $d"
    else
      echo "TRAVERSE DENIED $d"
    fi
  done
  if [ -r /var/db/fi/telemetry/spool ] &&
     [ -w /var/db/fi/telemetry/spool ];then
    echo "JAIL SPOOL READ/WRITE PASS"
  else
    echo "JAIL SPOOL READ/WRITE DENIED"
  fi
 ' || echo "FI-SOR IDENTITY PROBE FAILED $account"
done
echo "===== TELEMETRY NULLFS MOUNT ====="
mount -p | grep -F '/fast/jails/roots/fi-sor/var/db/fi/telemetry/spool' || :
echo "FI TELEMETRY STORAGE AUDIT COMPLETE read_only=true"
