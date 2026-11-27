#!/bin/sh
# C220 governed telemetry rebuild + normal C1 service; NO FI SQL reset.
# Staging is separate from explicit telemetry and ingest activation.
set -eu
umask 077
fail(){ echo "FI C220 INSTALL STOP: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] && [ "$(hostname -s)" = c220 ] &&
[ "$(uname -s)" = FreeBSD ] || fail "physical root@c220 required"
[ "$#" -eq 2 ] || fail "usage: --audit|--stage|--start-telemetry|--start-ingest FULL_SHA"
mode=$1; pin=$2
case "$mode" in --audit|--stage|--start-telemetry|--start-ingest) ;; *) fail "invalid mode";; esac
case "$pin" in *[!0123456789abcdef]*|'') fail "invalid SHA";; esac
[ "${#pin}" -eq 40 ] || fail "full 40-character SHA required"
repo=/home/jwood/fi-c1-two-process-2a449f1a
branch=dev/c1-sor-single-jail-20261124
dev=/fast/jails/roots/fi-dev
sor=/fast/jails/roots/fi-sor
runtime=tools/deployment/freebsd/runtime.d
spool=/fast/data/fi/telemetry/spool
dst=$sor/var/db/fi/telemetry/spool
fstab=/etc/jail.fstab.d/fi-c1-fi-sor.fstab
line="$spool $dst nullfs rw 0 0"
for jail in fi-dev fi-sor fi-receiver; do
  jls -j "$jail" >/dev/null || fail "required jail missing: $jail"
done
if jls -j fi-ingest >/dev/null 2>&1; then
  fail "obsolete fi-ingest jail must remain stopped"
fi
[ -f "$fstab" ] && [ ! -L "$fstab" ] || fail "fi-sor persistent fstab missing"
grep -F '/work/fi-c220-20261114/custody/generation ' "$fstab" |
  grep -F ' nullfs ro ' >/dev/null || fail "original custody RO fstab changed"
grep -F '/work/fi-c220-20261114/custody/recorded ' "$fstab" |
  grep -F ' nullfs ro ' >/dev/null || fail "recorded receipt RO fstab changed"
sql(){ jexec -U postgres fi-sor psql -X -w -At -v ON_ERROR_STOP=1 \
    -h /var/db/fi/sor/run -p 5432 -d fi -c "$1"; }
[ "$(sql "SELECT system_identifier::text FROM pg_control_system()")" = 7690295447535908318 ] ||
   fail "not the accepted real SoR"
asset(){ jexec -U jwood fi-dev git -C "$repo" show "$pin:$1"; }
if [ "$mode" = --audit ]; then
  echo "===== C220 TELEMETRY / NORMAL C1 STATUS ====="
  for svc in fi_telemetry_sample;do service "$svc" onestatus 2>&1 || :;done
  for svc in fi_telemetry_sample fi_telemetry_upload fi_c1_sor_live;do
    jexec fi-sor service "$svc" onestatus 2>&1 || :
  done
  echo "===== CUSTODY / TELEMETRY SCHEMA ====="
  ls -ld "$spool" "$dst" 2>&1 || :
  mount -p | grep -F "$dst" || :
  jexec -U postgres fi-sor psql -X -w -At \
    -h /var/db/fi/sor/run -p 5432 -d fi_telemetry \
    -c "SELECT to_regclass('telemetry_v2.entry')" || :
  echo "FI C220 AUDIT COMPLETE read_only=true"
  exit 0
fi
jexec -U jwood fi-dev git -C "$repo" fetch origin \
  "refs/heads/$branch:refs/remotes/origin/$branch"
[ "$(jexec -U jwood fi-dev git -C "$repo" rev-parse \
 "refs/remotes/origin/$branch")" = "$pin" ] || fail "branch moved"
install_same(){
  source=$1; target=$2; mode=$3
  if [ -e "$target" ] || [ -L "$target" ]; then
    [ -f "$target" ] && [ ! -L "$target" ] &&
      cmp -s "$source" "$target" || fail "existing file changed: $target"
  else
    install -o root -g wheel -m "$mode" "$source" "$target"
  fi
}
install_asset(){
  name=$1; target=$2; perms=$3
  tmp=$(mktemp /root/fi-c220-install.XXXXXXXX)
  asset "$runtime/$name" > "$tmp"
  case "$name" in *.sh|*.rc.d) sh -n "$tmp";; esac
  install_same "$tmp" "$target" "$perms"
  rm -f "$tmp"
}
ensure_group(){
  scope=$1
  if [ "$scope" = host ];then
    existing=$(pw groupshow -n fi-telemetry 2>/dev/null || :)
    if [ -z "$existing" ];then
      pw groupshow -g 46000 >/dev/null 2>&1 && fail "host GID 46000 collision"
      pw groupadd fi-telemetry -g 46000
    else
      [ "$(echo "$existing" | cut -d: -f3)" = 46000 ] || fail "host telemetry GID changed"
    fi
  else
    existing=$(jexec fi-sor pw groupshow -n fi-telemetry 2>/dev/null || :)
    if [ -z "$existing" ];then
      jexec fi-sor pw groupshow -g 46000 >/dev/null 2>&1 && fail "sor GID collision"
      jexec fi-sor pw groupadd fi-telemetry -g 46000
    else
      [ "$(echo "$existing" | cut -d: -f3)" = 46000 ] || fail "sor telemetry GID changed"
    fi
  fi
}
ensure_user(){
  scope=$1; name=$2; uid=$3
  if [ "$scope" = host ];then
    existing=$(pw usershow -n "$name" 2>/dev/null || :)
    if [ -z "$existing" ];then
      pw usershow -u "$uid" >/dev/null 2>&1 && fail "host UID collision: $uid"
      pw useradd "$name" -u "$uid" -g fi-telemetry \
         -d /nonexistent -s /usr/sbin/nologin -w no
    else
      [ "$(echo "$existing" | cut -d: -f3,4)" = "$uid:46000" ] ||
        fail "host user $name differs"
    fi
  else
    existing=$(jexec fi-sor pw usershow -n "$name" 2>/dev/null || :)
    if [ -z "$existing" ];then
      jexec fi-sor pw usershow -u "$uid" >/dev/null 2>&1 && fail "sor UID collision: $uid"
      jexec fi-sor pw useradd "$name" -u "$uid" -g fi-telemetry \
         -d /nonexistent -s /usr/sbin/nologin -w no
    else
      [ "$(echo "$existing" | cut -d: -f3,4)" = "$uid:46000" ] ||
        fail "sor user $name differs"
    fi
  fi
}
if [ "$mode" = --stage ];then
  echo "===== REPRODUCIBLE FI-DEV FREEBSD BUILD ====="
  work=$(jexec -U jwood fi-dev mktemp -d /home/jwood/fi-op-stage.XXXXXXXX)
  jexec -U jwood fi-dev /bin/sh -c '
   set -eu; repo=$1; pin=$2; work=$3
   git -C "$repo" archive "$pin" | tar -xf - -C "$work"
   cd "$work/go"
   go test -count=1 ./internal/telemetrybackend
   go test -tags fi_c1_sor_dev -count=1 \
     -run "^TestC1Direct|^TestC1NativeBDirect" ./internal/recordingest
   go build -trimpath -o "$work/fi-telemetry-backend" ./cmd/fi-telemetry-backend
   go build -trimpath -tags fi_c1_sor_dev -o "$work/fi-c1-sor-live" ./cmd/fi-c1-sor-local
  ' sh "$repo" "$pin" "$work" || fail "native FreeBSD tests/build failed"
  [ -s "$dev$work/fi-telemetry-backend" ] &&
  [ -s "$dev$work/fi-c1-sor-live" ] || fail "build output missing"
  echo "===== PROVISION DISTINCT TELEMETRY IDENTITIES ====="
  ensure_group host; ensure_group sor
  ensure_user host fi-telemetry 46000
  ensure_user sor fi-telemetry-monitor 46002
  ensure_user sor fi-telemetry-recorder 46001
  echo "===== PRIVATE FAST-POOL SPOOL AND NULLFS ====="
  install -d -o fi-telemetry -g fi-telemetry -m 2770 "$spool"
  chmod 2770 "$spool"
  [ ! -L "$dst" ] || fail "telemetry destination symlink"
  install -d -m 0755 "$dst"
  if mount -p | grep -F " $dst " >/dev/null;then
    mount -p | grep -F "$spool $dst nullfs rw" >/dev/null ||
       fail "foreign telemetry mount"
  else
    mount -t nullfs -o rw "$spool" "$dst"
  fi
  if ! grep -Fx "$line" "$fstab" >/dev/null;then
    ! grep -F " $dst " "$fstab" >/dev/null || fail "foreign fstab entry"
    printf '%s\n' "$line" >> "$fstab"
  fi
  echo "===== INSTALL DISABLED SERVICE ASSETS ====="
  install -d -m 0755 /usr/local/sbin /usr/local/etc/rc.d \
    /etc/rc.conf.d /var/log/fi "$sor/usr/local/sbin" \
    "$sor/usr/local/etc/rc.d" "$sor/usr/local/libexec" \
    "$sor/etc/rc.conf.d" "$sor/var/log/fi"
  install_same "$dev$work/fi-telemetry-backend" \
    /usr/local/sbin/fi-telemetry-backend 0555
  install_same "$dev$work/fi-telemetry-backend" \
    "$sor/usr/local/sbin/fi-telemetry-backend" 0555
  install_same "$dev$work/fi-c1-sor-live" \
    "$sor/usr/local/sbin/fi-c1-sor-live" 0555
  install_asset fi-telemetry-sample.rc.d /usr/local/etc/rc.d/fi_telemetry_sample 0555
  install_asset fi-telemetry-sample.rc.d "$sor/usr/local/etc/rc.d/fi_telemetry_sample" 0555
  install_asset fi-telemetry-upload.rc.d "$sor/usr/local/etc/rc.d/fi_telemetry_upload" 0555
  install_asset fi-c1-sor-live.rc.d "$sor/usr/local/etc/rc.d/fi_c1_sor_live" 0555
  install_asset fi-c1-sor-live-run.sh "$sor/usr/local/libexec/fi-c1-sor-live-run" 0555
  for rec in \
    "fi-telemetry-sample.rc.conf.example|/etc/rc.conf.d/fi_telemetry_sample|host" \
    "fi-telemetry-sample.rc.conf.example|$sor/etc/rc.conf.d/fi_telemetry_sample|sor" \
    "fi-telemetry-upload.rc.conf.example|$sor/etc/rc.conf.d/fi_telemetry_upload|other" \
    "fi-c1-sor-live.rc.conf.example|$sor/etc/rc.conf.d/fi_c1_sor_live|other"
  do
    name=$(printf '%s\n' "$rec" | cut -d '|' -f 1)
    dest=$(printf '%s\n' "$rec" | cut -d '|' -f 2)
    scope=$(printf '%s\n' "$rec" | cut -d '|' -f 3)
    tmp=$(mktemp /root/fi-c220-config.XXXXXXXX)
    asset "$runtime/$name" |
      sed "s/REPLACE_WITH_40_CHARACTER_DEPLOYED_COMMIT/$pin/" > "$tmp"
    if [ "$scope" = sor ];then
      sed -i '' -e 's/source="c220-host"/source="fi-sor"/' \
        -e 's/user="fi-telemetry"/user="fi-telemetry-monitor"/' \
        -e 's/^# fi_telemetry_sample_monitor_dsn=/fi_telemetry_sample_monitor_dsn=/' "$tmp"
    fi
    install_same "$tmp" "$dest" 0600
    rm -f "$tmp"
  done
  echo "===== ADDITIVE fi_telemetry SQL (PRESERVE HISTORICAL TABLES) ====="
  for sqlfile in fi-telemetry-v2-schema.sql fi-telemetry-v2-roles.sql;do
    tmp=$(mktemp /root/fi-c220-ddl.XXXXXXXX)
    asset "$runtime/$sqlfile" > "$tmp"
    jexec -U postgres fi-sor psql -X -w -v ON_ERROR_STOP=1 \
      -h /var/db/fi/sor/run -p 5432 -d fi_telemetry < "$tmp" ||
      fail "telemetry SQL setup failed: $sqlfile"
    rm -f "$tmp"
  done
  echo "FI C220 STAGE PASS: source installed, services disabled, original fi unchanged"
  echo "Next: verify fi-sor PG peer auth for the two dedicated telemetry roles"
  exit 0
fi
[ -x "$sor/usr/local/sbin/fi-c1-sor-live" ] || fail "C1 binary not staged"
if [ "$mode" = --start-telemetry ];then
  jexec -U fi-telemetry-monitor fi-sor psql -X -w -At \
    -h /var/db/fi/sor/run -p 5432 -d fi -c 'SELECT current_user' |
      grep -Fx 'fi-telemetry-monitor' >/dev/null ||
      fail "read-only monitor peer auth missing"
  jexec -U fi-telemetry-recorder fi-sor psql -X -w -At \
    -h /var/db/fi/sor/run -p 5432 -d fi_telemetry -c 'SELECT current_user' |
      grep -Fx 'fi-telemetry-recorder' >/dev/null ||
      fail "telemetry recorder peer auth missing"
  sysrc -f /etc/rc.conf.d/fi_telemetry_sample fi_telemetry_sample_enable=YES
  jexec fi-sor sysrc -f /etc/rc.conf.d/fi_telemetry_sample fi_telemetry_sample_enable=YES
  jexec fi-sor sysrc -f /etc/rc.conf.d/fi_telemetry_upload fi_telemetry_upload_enable=YES
  service fi_telemetry_sample onestart
  jexec fi-sor service fi_telemetry_sample onestart
  jexec fi-sor service fi_telemetry_upload onestart
  echo "FI TELEMETRY START REQUESTED: confirm samples AND SQL delivery before C1"
  exit 0
fi
if [ "$mode" = --start-ingest ];then
  gate=$(mktemp /root/fi-c220-gate.XXXXXXXX)
  trap 'rm -f "$gate"' EXIT
  asset "go/cmd/fi-backlog-recover/diagnostics/fi_c1_c220_telemetry_acceptance.sh" > "$gate"
  sh "$gate" --audit || fail "telemetry acceptance not complete; no C1 start"
  for svc in fi_c1_sor fi_c1_sor_local fi_ingest_worker;do
    jexec fi-sor service "$svc" onestatus >/dev/null 2>&1 &&
      fail "obsolete C1 service still active" || :
  done
  jexec -U fi-sor fi-sor env FI_C1_LIVE_PREFLIGHT=YES \
     /usr/local/libexec/fi-c1-sor-live-run ||
     fail "actual signed custody, receiver cache or SQL role preflight failed"
  jexec fi-sor sysrc -f /etc/rc.conf.d/fi_c1_sor_live fi_c1_sor_live_enable=YES
  jexec fi-sor service fi_c1_sor_live onestart
  jexec fi-sor service fi_c1_sor_live onestatus ||
     fail "C1 exited; preserve READY/Accepted, inspect log"
  echo "FI C1 LIVE INTAKE STARTED: prove one NEW signed sender Accepted generation"
fi
