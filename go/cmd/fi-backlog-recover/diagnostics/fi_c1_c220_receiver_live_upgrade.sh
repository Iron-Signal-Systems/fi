#!/bin/sh
# C220 governed receiver verified-cache live upgrade. No custody/SQL edits.
# --stage only builds, prepares replacements, backs up exact live assets.
# --activate is the explicit receiver restart boundary with rollback.
set -eu
umask 077
fail(){ echo "FI RECEIVER UPGRADE STOP: $*" >&2; exit 1; }
[ "$#" -eq 2 ] || fail 'usage: --audit|--stage|--activate|--resume 40_CHAR_SHA'
case "$1" in --audit|--stage|--activate|--resume) mode=$1;;*) fail 'invalid action';;esac
pin=$2
case "$pin" in *[!0123456789abcdef]*|'') fail 'invalid commit SHA';;esac
[ "$(printf %s "$pin" | wc -c | tr -d ' ')" -eq 40 ] ||
 fail 'full 40-character GitHub SHA required'
[ "$(id -u)" = 0 ] && [ "$(hostname -s)" = c220 ] &&
[ "$(uname -s)" = FreeBSD ] || fail 'physical FreeBSD root@c220 required'
repo=/home/jwood/fi-c1-two-process-2a449f1a
branch=dev/c1-sor-single-jail-20261124
dev=/fast/jails/roots/fi-dev
recv=/fast/jails/roots/fi-receiver
sor=/fast/jails/roots/fi-sor
config=$recv/etc/rc.conf.d/fi_receiver
supervisor=$recv/usr/local/libexec/fi-receiver-supervisor
binary=$recv/usr/local/sbin/fi-receiver
stage=/var/backups/fi-receiver-upgrade-$pin
if [ "$mode" = --resume ] || [ "$mode" = --audit ];then
 # Reuse the FreeBSD-built assets already staged and tested before the
 # premature three-second listener-verification rollback.
 original_pin=1191110f8b721725484355b02bb7165d278718ba
 stage=/var/backups/fi-receiver-upgrade-$original_pin
fi
for jail in fi-dev fi-receiver fi-sor;do
 jls -j "$jail" >/dev/null || fail "jail missing: $jail"
done
jexec fi-receiver service fi_receiver onestatus ||
 fail 'receiver not running; requires a separate recovery path'
if jexec fi-sor service fi_c1_sor_live onestatus >/dev/null 2>&1;then
 fail 'C1 already running; refuse receiver upgrade'
fi
jexec -U jwood fi-dev git -C "$repo" fetch origin \
 "refs/heads/$branch:refs/remotes/origin/$branch"
[ "$(jexec -U jwood fi-dev git -C "$repo" \
  rev-parse "refs/remotes/origin/$branch")" = "$pin" ] ||
 fail 'GitHub branch moved'
if [ "$mode" = --resume ] || [ "$mode" = --audit ];then
 # Compare the entire repository, excluding only this deployment script,
 # which necessarily changed after the original receiver binary was built.
 # Earlier '-- go' erroneously included the diagnostic script itself.
 jexec -U jwood fi-dev git -C "$repo" diff --quiet "$original_pin" "$pin" \
   -- . ':(exclude)go/cmd/fi-backlog-recover/diagnostics/fi_c1_c220_receiver_live_upgrade.sh' ||
   fail 'repository changed outside receiver upgrade script; cannot reuse staged binary'
fi
if [ "$mode" = --audit ];then
 echo '===== CURRENT RECEIVER PROCESS AND LISTENER ====='
 jexec fi-receiver service fi_receiver onestatus 2>&1 || :
 jexec fi-receiver ps -axww -o pid,ppid,user,stat,etime,command |
   grep -E 'fi-receiver|PID' || :
 jexec fi-receiver sockstat -4 -l -P tcp |
   grep -F '172.20.23.21:8443' || :
 echo '===== INSTALLED RECEIVER ASSET MATCH ====='
 if [ -d "$stage" ] && [ ! -L "$stage" ];then
  for pair in "old-binary:$binary" "new-binary:$binary" \
    "old-supervisor:$supervisor" "new-supervisor:$supervisor" \
    "old-config:$config" "new-config:$config";do
   name=${pair%%:*};dest=${pair#*:}
   if [ -f "$stage/$name" ] && cmp -s "$stage/$name" "$dest";then
    echo "MATCH $name"
   fi
  done
 else
  echo "STAGE NOT FOUND: $stage"
 fi
 echo 'FI RECEIVER AUDIT COMPLETE read_only=true'
 exit 0
fi
# The prior upgrade's response ended during rollback. A still-running
# upgraded receiver must never be stopped for a second upgrade.
if [ "$mode" = --resume ] &&
 [ -d "$stage" ] && [ ! -L "$stage" ] &&
 cmp -s "$stage/new-binary" "$binary" &&
 cmp -s "$stage/new-supervisor" "$supervisor" &&
 cmp -s "$stage/new-config" "$config";then
 if jexec fi-receiver service fi_receiver onestatus >/dev/null 2>&1 &&
    jexec fi-receiver ps -axww -o command |
      grep -F -- '-generation-verified-cache-root /var/db/fi/verified-cache' >/dev/null &&
    jexec fi-receiver ps -axww -o command |
      grep -F -- '-generation-ready-root /var/db/fi/custody/ready' >/dev/null &&
    jexec fi-receiver sockstat -4 -l -P tcp |
      grep -F '172.20.23.21:8443' >/dev/null;then
   echo 'FI RECEIVER ALREADY UPDATED: verified-cache=true listener=true no_restart=true'
   exit 0
 fi
 fail 'new receiver assets installed but listener/worker not verified; stop instead of restarting'
fi
for f in "$config" "$supervisor" "$binary";do
 [ -f "$f" ] && [ ! -L "$f" ] || fail "missing/unsafe file: $f"
done
[ -x "$supervisor" ] && [ -x "$binary" ] ||
 fail 'receiver assets not executable'
[ "$(grep -c '^fi_receiver_enable=' "$config" || :)" -eq 1 ] &&
grep -Fx 'fi_receiver_enable="NO"' "$config" >/dev/null ||
 fail 'not the observed receiver boot configuration'
[ "$(grep -c '^fi_receiver_generation_verified_cache_root=' "$config" || :)" -eq 0 ] ||
 fail 'cache already configured; inspect rather than overwrite'
grep -Fx 'fi_receiver_bind="172.20.23.21:8443"' "$config" >/dev/null ||
 fail 'receiver bind changed'
grep -Fx 'fi_receiver_generation_ready_root="/var/db/fi/custody/ready"' "$config" >/dev/null ||
 fail 'receiver READY root changed'
grep -Fx 'fi_receiver_generation_max_canonical_bytes="75161927680"' "$config" >/dev/null ||
 fail 'receiver canonical 70GiB setting changed'
jexec fi-receiver ps -axww -o command |
 grep -F -- '-generation-ready-root /var/db/fi/custody/ready' >/dev/null ||
 fail 'live receiver changed'
if jexec fi-receiver ps -axww -o command |
 grep -F -- '-generation-verified-cache-root' >/dev/null;then
 fail 'cache already active in live receiver'
fi
check_mount(){
 mount -p | awk -v src="$1" -v dst="$2" -v access="$3" '
  $2==dst {
   found++; n=split($4,opts,",")
   for(i=1;i<=n;i++) if($1==src && $3=="nullfs" && opts[i]==access) ok++
  } END {exit !(found==1 && ok==1)}'
}
cache=/work/fi-c220-20261114/custody/verified-cache
check_mount "$cache" "$recv/var/db/fi/verified-cache" rw ||
 fail 'receiver cache RW mount missing'
check_mount "$cache" "$sor/var/db/fi/verified-cache" ro ||
 fail 'SoR cache RO mount missing'
jexec -U fi-receiver fi-receiver test -w /var/db/fi/verified-cache ||
 fail 'receiver cache access unavailable'
jexec -U fi-sor fi-sor test -r /var/db/fi/verified-cache ||
 fail 'SoR cache access unavailable'
publish(){
 from=$1;dest=$2
 tmp=$(mktemp "$dest.fi-upgrade.XXXXXXXX") || return 1
 if ! cp -p "$from" "$tmp" || ! mv -f "$tmp" "$dest";then
  rm -f "$tmp";return 1
 fi
}
if [ "$mode" = --stage ];then
 [ ! -e "$stage" ] && [ ! -L "$stage" ] ||
 fail "stage already exists: $stage"
 install -d -o root -g wheel -m 0700 "$stage"
 cp -p "$binary" "$stage/old-binary"
 cp -p "$supervisor" "$stage/old-supervisor"
 cp -p "$config" "$stage/old-config"
 echo '===== BUILD FREEBSD RECEIVER FROM PINNED GITHUB SOURCE ====='
 work=$(jexec -U jwood fi-dev mktemp -d /home/jwood/fi-receiver-stage.XXXXXXXX)
 jexec -U jwood fi-dev /bin/sh -c '
  set -eu
  repo=$1;pin=$2;work=$3
  git -C "$repo" archive "$pin" | tar -xf - -C "$work"
  cd "$work/go"
  go test -count=1 ./cmd/fi-receiver ./internal/transportreceiver
  go build -trimpath -o "$work/fi-receiver" ./cmd/fi-receiver
 ' sh "$repo" "$pin" "$work" || fail 'native FreeBSD build/tests failed'
 [ -s "$dev$work/fi-receiver" ] || fail 'built receiver absent'
 install -o root -g wheel -m 0555 "$dev$work/fi-receiver" "$stage/new-binary"
 jexec -U jwood fi-dev git -C "$repo" show \
  "$pin:tools/deployment/freebsd/runtime.d/fi-receiver-supervisor.sh" \
  > "$stage/new-supervisor"
 chown root:wheel "$stage/new-supervisor"
 chmod 0555 "$stage/new-supervisor"
 sh -n "$stage/new-supervisor"
 awk '
  /^fi_receiver_enable="NO"$/ {print "fi_receiver_enable=\"YES\"";next}
  {print}
  END {print "fi_receiver_generation_verified_cache_root=\"/var/db/fi/verified-cache\""}
 ' "$stage/old-config" > "$stage/new-config"
 chown "$(stat -f '%u:%g' "$config")" "$stage/new-config"
 chmod "0$(stat -f '%Lp' "$config")" "$stage/new-config"
 sh -n "$stage/new-config"
 grep -Fx 'fi_receiver_enable="YES"' "$stage/new-config" >/dev/null ||
 fail 'missing new boot enable'
 grep -Fx 'fi_receiver_generation_verified_cache_root="/var/db/fi/verified-cache"' \
 "$stage/new-config" >/dev/null || fail 'missing new cache root'
 [ "$(grep -c '^fi_receiver_generation_verified_cache_root=' "$stage/new-config")" -eq 1 ] ||
 fail 'duplicate cache root'
 sha256 -q "$stage/new-binary" > "$stage/new-binary.sha"
 sha256 -q "$stage/new-supervisor" > "$stage/new-supervisor.sha"
 echo "FI RECEIVER STAGED=$stage"
 echo "STAGED_BINARY_SHA256=$(cat "$stage/new-binary.sha")"
 echo 'STAGE PASS: old receiver remains running, installed files unchanged'
 exit 0
fi
[ -d "$stage" ] && [ ! -L "$stage" ] &&
[ "$(stat -f '%u:%g:%Lp' "$stage")" = '0:0:700' ] ||
 fail 'private root-owned stage missing'
for name in old-binary old-supervisor old-config new-binary new-supervisor \
 new-config new-binary.sha new-supervisor.sha;do
 [ -f "$stage/$name" ] && [ ! -L "$stage/$name" ] ||
 fail "missing staged file: $name"
done
cmp -s "$stage/old-binary" "$binary" &&
cmp -s "$stage/old-supervisor" "$supervisor" &&
cmp -s "$stage/old-config" "$config" ||
 fail 'installed receiver assets changed since stage'
[ "$(sha256 -q "$stage/new-binary")" = "$(cat "$stage/new-binary.sha")" ] &&
[ "$(sha256 -q "$stage/new-supervisor")" = "$(cat "$stage/new-supervisor.sha")" ] ||
 fail 'staged file checksum mismatch'
[ "$(cat "$stage/new-binary.sha")" = \
  '34a82462a0dc4f62c23410c5d2f94296a304d2663d4488181883f76fca3bb5da' ] ||
 fail 'staged binary is not the approved tested receiver'
jexec fi-receiver sockstat -4 -l -P tcp |
 grep -F '172.20.23.21:8443' >/dev/null ||
 fail 'existing receiver TCP listener missing; do not restart'
echo '===== CONTROLLED STOP OF ORIGINAL RECEIVER ====='
if ! jexec fi-receiver service fi_receiver onestop;then
 if ! jexec fi-receiver service fi_receiver onestatus >/dev/null 2>&1;then
  echo 'Receiver stop returned failure and process is absent: restoring service' >&2
  jexec fi-receiver service fi_receiver onestart || :
 fi
 fail 'receiver stop failed; original files unchanged'
fi
sleep 2
if jexec fi-receiver service fi_receiver onestatus >/dev/null 2>&1 ||
   jexec fi-receiver pgrep -u fi-receiver -f '^/usr/local/sbin/fi-receiver ' >/dev/null 2>&1;then
 fail 'old receiver still running; no files replaced'
fi
rollback(){
 echo '===== RECEIVER START FAILED: RESTORE ORIGINAL FILES =====' >&2
 jexec fi-receiver service fi_receiver onestop >/dev/null 2>&1 || :
 sleep 2
 publish "$stage/old-binary" "$binary" || :
 publish "$stage/old-supervisor" "$supervisor" || :
 publish "$stage/old-config" "$config" || :
 jexec fi-receiver service fi_receiver onestart || :
 if jexec fi-receiver service fi_receiver onestatus;then
  echo 'ROLLBACK PASS: original receiver restarted; C1 not started' >&2
 else
  echo 'ROLLBACK ALERT: original receiver restart not verified' >&2
 fi
}
if ! publish "$stage/new-binary" "$binary" ||
   ! publish "$stage/new-supervisor" "$supervisor" ||
   ! publish "$stage/new-config" "$config";then
 rollback
 fail 'file publication failed; original restoration attempted'
fi
echo '===== START UPDATED RECEIVER ====='
if ! jexec fi-receiver service fi_receiver onestart;then
 rollback
 fail 'updated receiver failed to start'
fi
# Receiver startup custody recovery precedes opening the listener.
# A three-second listener check caused the preceding false rollback.
# Check required flags and actual worker every poll. Do not roll back
# a live worker that is still performing startup recovery.
n=0
while [ "$n" -lt 150 ];do
  if ! jexec fi-receiver service fi_receiver onestatus >/dev/null 2>&1;then
    echo 'RECEIVER STARTUP: service exited before ready' >&2
    jexec fi-receiver tail -50 /var/log/messages || :
    rollback
    fail 'receiver service exited; rollback attempted'
  fi
  cmds=$(jexec fi-receiver ps -axww -o command)
  if ! printf '%s\n' "$cmds" |
       grep -F '/usr/local/sbin/fi-receiver -transport-listen' >/dev/null;then
    echo 'RECEIVER STARTUP: receiver process exited' >&2
    jexec fi-receiver tail -50 /var/log/messages || :
    rollback
    fail 'receiver child exited; rollback attempted'
  fi
  if ! printf '%s\n' "$cmds" |
       grep -F -- '-generation-verified-cache-root /var/db/fi/verified-cache' >/dev/null ||
     ! printf '%s\n' "$cmds" |
       grep -F -- '-generation-ready-root /var/db/fi/custody/ready' >/dev/null;then
    echo "$cmds" >&2
    rollback
    fail 'new receiver missing required live flags; rollback attempted'
  fi
  if jexec fi-receiver sockstat -4 -l -P tcp |
       grep -F '172.20.23.21:8443' >/dev/null;then
    sleep 3
    if jexec fi-receiver service fi_receiver onestatus >/dev/null 2>&1 &&
       jexec fi-receiver sockstat -4 -l -P tcp |
         grep -F '172.20.23.21:8443' >/dev/null;then
      echo 'FI C220 RECEIVER UPGRADE PASS cache_publication=true READY=true listener=true boot_enabled=true'
      echo "ORIGINAL_FILE_BACKUPS=$stage"
      exit 0
    fi
  fi
  n=$((n+1))
  if [ $((n % 10)) -eq 0 ];then
    echo "RECEIVER RECOVERY RUNNING: verified-cache flags present; listener pending check=$n"
  fi
  sleep 2
done
echo '===== RECEIVER STILL RUNNING BUT LISTENER NOT READY =====' >&2
jexec fi-receiver ps -axww -o pid,user,stat,etime,command >&2 || :
jexec fi-receiver tail -50 /var/log/messages >&2 || :
# Do not interrupt a still-active custody recovery to force a rollback.
fail 'startup not yet completed; no automatic rollback of live receiver; C1 remains disabled'
