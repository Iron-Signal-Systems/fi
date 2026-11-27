#!/bin/sh
# C220 receiver ONLY: replace live cache-rebuilding binary after approved tests.
# --stage builds/test and creates backups without stopping anything.
# --activate explicitly stops/replaces/starts receiver, preserving original
# working November receiver as fallback. No signed custody or SQL edits.
set -eu
umask 077
fail(){ echo "FI RECEIVER REPLACEMENT STOP: $*" >&2; exit 1; }
[ "$#" -eq 2 ] || fail 'usage: --stage|--activate FULL_SHA'
case "$1" in --stage|--activate) action=$1 ;; *) fail 'invalid action';;esac
pin=$2
case "$pin" in *[!0123456789abcdef]*|'') fail 'invalid SHA';;esac
[ "${#pin}" -eq 40 ] || fail 'full SHA required'
[ "$(id -u)" -eq 0 ] && [ "$(uname -s)" = FreeBSD ] &&
[ "$(hostname -s)" = c220 ] || fail 'physical FreeBSD root@c220 required'
repo=/home/jwood/fi-c1-two-process-2a449f1a
branch=dev/c1-sor-single-jail-20261124
dev=/fast/jails/roots/fi-dev
recv=/fast/jails/roots/fi-receiver
sor=/fast/jails/roots/fi-sor
exe=$recv/usr/local/sbin/fi-receiver
supervisor=$recv/usr/local/libexec/fi-receiver-supervisor
config=$recv/etc/rc.conf.d/fi_receiver
old=/var/backups/fi-receiver-upgrade-1191110f8b721725484355b02bb7165d278718ba
stage=/var/backups/fi-receiver-startup-$pin
socket=172.20.23.21:8443
for jail in fi-dev fi-receiver fi-sor; do
 jls -j "$jail" >/dev/null || fail "jail missing $jail"
done
if jexec fi-sor service fi_c1_sor_live onestatus >/dev/null 2>&1;then
 fail 'C1 live already running; cannot interrupt its receiver'
fi
jexec -U jwood fi-dev git -C "$repo" fetch origin \
 "refs/heads/$branch:refs/remotes/origin/$branch"
[ "$(jexec -U jwood fi-dev git -C "$repo" \
  rev-parse "refs/remotes/origin/$branch")" = "$pin" ] ||
 fail 'GitHub branch tip not equal to approved SHA'
for file in "$exe" "$supervisor" "$config" \
 "$old/old-binary" "$old/old-supervisor" "$old/old-config" \
 "$old/new-binary" "$old/new-supervisor" "$old/new-config";do
 [ -f "$file" ] && [ ! -L "$file" ] || fail "original receiver asset missing $file"
done
[ "$(sha256 -q "$old/new-binary")" = \
 '34a82462a0dc4f62c23410c5d2f94296a304d2663d4488181883f76fca3bb5da' ] ||
 fail 'live receiver backup does not match original accepted build'
cmp -s "$old/new-binary" "$exe" &&
cmp -s "$old/new-supervisor" "$supervisor" &&
cmp -s "$old/new-config" "$config" ||
 fail 'live receiver files do not match previously staged cache-publisher'
jexec fi-receiver service fi_receiver onestatus ||
 fail 'verified-cache receiver must be running before replacement'
jexec fi-receiver ps -axww -o command |
 grep -F -- '-generation-verified-cache-root /var/db/fi/verified-cache' >/dev/null ||
 fail 'live receiver flags changed'
for f in "$exe" "$supervisor" "$config";do
 [ ! -L "$f" ] || fail "symlinked receiver path $f"
done
check_mount(){
 mount -p | awk -v src="$1" -v dst="$2" -v access="$3" '
  $2==dst {
   count++; n=split($4,o,",");
   for(i=1;i<=n;i++) if($1==src&&$3=="nullfs"&&o[i]==access) ok++
  }END{exit !(count==1&&ok==1)}'
}
cache=/work/fi-c220-20261114/custody/verified-cache
check_mount "$cache" "$recv/var/db/fi/verified-cache" rw ||
 fail 'receiver verified-cache RW mount missing'
check_mount "$cache" "$sor/var/db/fi/verified-cache" ro ||
 fail 'SoR verified-cache RO mount missing'
jexec -U fi-receiver fi-receiver test -w /var/db/fi/verified-cache ||
 fail 'receiver cannot write verified cache'
jexec -U fi-sor fi-sor test -r /var/db/fi/verified-cache ||
 fail 'SoR cannot read verified cache'
publish(){
 from=$1; destination=$2
 tmp=$(mktemp "$destination.fi-startup.XXXXXXXX") || return 1
 if ! cp -p "$from" "$tmp" || ! mv -f "$tmp" "$destination";then
  rm -f "$tmp"; return 1
 fi
}
if [ "$action" = --stage ];then
 [ ! -e "$stage" ] && [ ! -L "$stage" ] || fail "stage already exists $stage"
 install -d -o root -g wheel -m 0700 "$stage"
 cp -p "$exe" "$stage/previous-binary"
 cp -p "$supervisor" "$stage/previous-supervisor"
 cp -p "$config" "$stage/previous-config"
 cp -p "$old/old-binary" "$stage/rollback-binary"
 cp -p "$old/old-supervisor" "$stage/rollback-supervisor"
 cp -p "$old/old-config" "$stage/rollback-config"
 echo '===== BUILD AND TEST RECEIVER ON FI-DEV (NO LIVE CHANGES) ====='
 work=$(jexec -U jwood fi-dev mktemp -d /home/jwood/fi-receiver-approved.XXXXXXXX)
 jexec -U jwood fi-dev /bin/sh -c '
   set -eu
   repo=$1; pin=$2; work=$3
   git -C "$repo" archive "$pin" | tar -xf - -C "$work"
   cd "$work/go"
   go test -count=1 ./internal/transportgeneration \
     ./internal/generationrecorder ./internal/transportreceiver ./cmd/fi-receiver
   go build -trimpath -o "$work/fi-receiver" ./cmd/fi-receiver
 ' sh "$repo" "$pin" "$work" || fail 'receiver tests/build failed; live unchanged'
 [ -s "$dev$work/fi-receiver" ] || fail 'built receiver not found'
 install -o root -g wheel -m 0555 "$dev$work/fi-receiver" "$stage/new-binary"
 sha256 -q "$stage/new-binary" > "$stage/new-binary.sha"
 echo "FI RECEIVER STARTUP STAGE PASS: $stage"
 echo "STAGED_SHA256=$(cat "$stage/new-binary.sha")"
 echo 'Existing receiver process remains untouched'
 exit 0
fi
[ -d "$stage" ] && [ ! -L "$stage" ] &&
[ "$(stat -f '%u:%g:%Lp' "$stage")" = 0:0:700 ] ||
 fail 'verified private stage missing'
for name in previous-binary previous-supervisor previous-config \
 rollback-binary rollback-supervisor rollback-config new-binary new-binary.sha;do
 [ -f "$stage/$name" ] && [ ! -L "$stage/$name" ] ||
 fail "missing staged asset $name"
done
cmp -s "$exe" "$stage/previous-binary" &&
cmp -s "$supervisor" "$stage/previous-supervisor" &&
cmp -s "$config" "$stage/previous-config" ||
 fail 'live receiver changed after staging'
[ "$(sha256 -q "$stage/new-binary")" = "$(cat "$stage/new-binary.sha")" ] ||
 fail 'new receiver binary changed since staging'
rollback(){
 echo '===== RECEIVER FAILED: RESTORE PREVIOUS LISTENING VERSION =====' >&2
 jexec fi-receiver service fi_receiver onestop >/dev/null 2>&1 || :
 sleep 2
 publish "$stage/rollback-binary" "$exe" &&
 publish "$stage/rollback-supervisor" "$supervisor" &&
 publish "$stage/rollback-config" "$config" ||
  { echo 'CRITICAL: backup restore failed' >&2; return 1; }
 jexec fi-receiver service fi_receiver onestart || :
 try=0
 while [ "$try" -lt 30 ];do
  if jexec fi-receiver service fi_receiver onestatus >/dev/null 2>&1 &&
     jexec fi-receiver sockstat -4 -l -P tcp |
       grep -F "$socket" >/dev/null;then
   echo 'RECEIVER ROLLBACK PASS: original receiver accepting connections'
   return 0
  fi
  try=$((try+1))
  sleep 2
 done
 echo 'CRITICAL: original receiver listener not verified after rollback' >&2
 return 1
}
echo '===== REPLACE ONLY RECEIVER EXECUTABLE ====='
jexec fi-receiver service fi_receiver onestop ||
 fail 'receiver refused to stop; installed files unchanged'
sleep 2
if jexec fi-receiver service fi_receiver onestatus >/dev/null 2>&1 ||
 jexec fi-receiver pgrep -u fi-receiver -f '^/usr/local/sbin/fi-receiver ' >/dev/null 2>&1;then
 fail 'old receiver still alive; installed files unchanged'
fi
if ! publish "$stage/new-binary" "$exe";then
 rollback || :
 fail 'receiver binary publication failed; rollback attempted'
fi
echo '===== START UPDATED RECEIVER; VERIFY ACTUAL LISTENER ====='
if ! jexec fi-receiver service fi_receiver onestart;then
 rollback || :
 fail 'receiver start failed; rollback attempted'
fi
n=0
while [ "$n" -lt 150 ];do
 if ! jexec fi-receiver service fi_receiver onestatus >/dev/null 2>&1;then
  rollback || :
  fail 'new receiver exited; rollback attempted'
 fi
 cmd=$(jexec fi-receiver ps -axww -o command)
 if ! printf '%s\n' "$cmd" |
   grep -F -- '-generation-verified-cache-root /var/db/fi/verified-cache' >/dev/null;then
  rollback || :
  fail 'new receiver missing verified-cache publication; rollback attempted'
 fi
 if jexec fi-receiver sockstat -4 -l -P tcp |
    grep -F "$socket" >/dev/null;then
  sleep 3
  if jexec fi-receiver service fi_receiver onestatus >/dev/null 2>&1 &&
     jexec fi-receiver sockstat -4 -l -P tcp |
       grep -F "$socket" >/dev/null;then
   echo 'FI RECEIVER STARTUP PASS: updated_binary=true verified_cache=true listener=true'
   echo "RECEIVER_RESTORE_BACKUPS=$stage"
   exit 0
  fi
 fi
 n=$((n+1))
 if [ $((n % 15)) -eq 0 ];then
  echo "RECEIVER RECOVERY: new process alive; listener not yet open, check=$n"
 fi
 sleep 2
done
echo 'RECEIVER RECOVERY CONTINUES: no premature forced rollback'
jexec fi-receiver ps -axww -o pid,user,stat,etime,command || :
fail 'new receiver is alive but listener unverified; C1 must remain disabled'
