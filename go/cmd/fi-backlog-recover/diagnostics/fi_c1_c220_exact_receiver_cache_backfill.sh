#!/bin/sh
# C220 exact-commit FreeBSD stage and historical receiver cache backfill.
# Never replaces the live receiver or starts SoR, writes SQL or alters READY.
set -eu
umask 077
fail(){ echo "FI C1 BACKFILL STOP: $*" >&2;exit 1; }
[ "$#" -eq 2 ] || fail 'usage: --stage|--backfill FULL_40_HEX_SHA'
action=$1
pin=$2
case "$action" in --stage|--backfill) ;; *) fail 'invalid action';; esac
case "$pin" in *[!0123456789abcdef]*|'') fail 'invalid SHA';; esac
[ "${#pin}" -eq 40 ] || fail 'exact SHA required'
[ "$(uname -s)" = FreeBSD ] && [ "$(hostname -s)" = c220 ] &&
[ "$(id -u)" -eq 0 ] || fail 'physical root@c220 FreeBSD required'
for j in fi-dev fi-receiver fi-sor;do
 jls -j "$j" >/dev/null 2>&1 || fail "missing jail $j"
done
if jls -j fi-ingest >/dev/null 2>&1;then fail 'obsolete ingest running';fi
for svc in fi_c1_sor_local fi_c1_sor;do
 if jexec fi-sor service "$svc" onestatus >/dev/null 2>&1;then
  fail "C1 service already active: $svc"
 fi
done
src=/work/fi-c220-20261114/custody/verified-cache
recv=/fast/jails/roots/fi-receiver/var/db/fi/verified-cache
sor=/fast/jails/roots/fi-sor/var/db/fi/verified-cache
for tuple in "$src $recv rw" "$src $sor ro";do
 set -- $tuple
 mount -p | awk -v a="$1" -v b="$2" -v o="$3" '
 $2==b{seen++;n=split($4,x,",");for(i=1;i<=n;i++)if($1==a&&$3=="nullfs"&&x[i]==o)ok++}
 END{exit !(seen==1&&ok==1)}' || fail "cache mount not correct: $2"
done
repo=/home/jwood/fi-c1-two-process-2a449f1a
branch=dev/c1-sor-single-jail-20261124
receiver_target=/fast/jails/roots/fi-receiver/usr/local/sbin/fi-receiver-backfill-$pin
sor_target=/fast/jails/roots/fi-sor/usr/local/sbin/fi-c1-sor-local-$pin
if [ "$action" = --stage ];then
 jexec -U jwood fi-dev git -C "$repo" fetch origin \
  "refs/heads/$branch:refs/remotes/origin/$branch" ||
  fail 'cannot fetch branch'
 [ "$(jexec -U jwood fi-dev git -C "$repo" rev-parse "refs/remotes/origin/$branch")" = "$pin" ] ||
  fail 'exact source branch pin changed'
 build=$(jexec -U jwood fi-dev mktemp -d /home/jwood/fi-c1-exact.XXXXXXXX) ||
  fail 'cannot create FreeBSD build directory'
 jexec -U jwood fi-dev /bin/sh -c '
  set -eu
  git -C "$1" archive "$2" | tar -xf - -C "$3"
  cd "$3/go"
  go test -count=1 ./internal/generationrecorder ./internal/transportreceiver
  go build -trimpath -o "$3/fi-receiver" ./cmd/fi-receiver
  go build -trimpath -tags fi_c1_sor_dev -o "$3/fi-c1-sor-local" ./cmd/fi-c1-sor-local
  test -s "$3/fi-receiver"
  test -s "$3/fi-c1-sor-local"
 ' sh "$repo" "$pin" "$build" || fail 'native receiver and C1 tests or build failed'
 for pair in \
  "/fast/jails/roots/fi-dev$build/fi-receiver $receiver_target" \
  "/fast/jails/roots/fi-dev$build/fi-c1-sor-local $sor_target";do
  set -- $pair
  [ -f "$1" ] && [ ! -L "$1" ] && [ -s "$1" ] || fail "invalid build artifact $1"
  if [ -e "$2" ] || [ -L "$2" ];then
   [ -f "$2" ] && [ ! -L "$2" ] &&
    [ "$(sha256 -q "$1")" = "$(sha256 -q "$2")" ] ||
    fail "existing staged executable differs: $2"
  else
   install -o root -g wheel -m 0555 "$1" "$2" || fail "cannot stage $2"
  fi
  echo "FI_C1_STAGED=$2 hash=$(sha256 -q "$2")"
 done
 echo "FI C1 STAGE PASS commit=$pin receiver_listener_unchanged=true sor_stopped=true sql_unchanged=true"
 exit 0
fi
[ -x "$receiver_target" ] && [ -x "$sor_target" ] ||
 fail 'first run --stage for this exact commit'
jexec fi-receiver service fi_receiver onestatus >/dev/null 2>&1 ||
 fail 'original receiver service not running'
echo '===== ONE SIGNED GENERATION RECEIVER AUTHENTICATED CACHE BACKFILL ====='
jexec -U fi-receiver fi-receiver /bin/sh -c '
 set -eu
 . /etc/rc.conf.d/fi_receiver
 : "${fi_receiver_bind:?}"
 : "${fi_receiver_custody_root:?}"
 : "${fi_receiver_max_data_bytes:?}"
 : "${fi_receiver_generation_custody_root:?}"
 : "${fi_receiver_generation_recorded_root:?}"
 : "${fi_receiver_generation_ready_root:?}"
 : "${fi_receiver_generation_max_canonical_bytes:?}"
 : "${fi_receiver_generation_max_encoded_bytes:?}"
 : "${fi_receiver_generation_max_manifest_bytes:?}"
 [ -w /var/db/fi/verified-cache ] || exit 1
 exec "$1" \
 -transport-listen -bind "$fi_receiver_bind" \
 -custody-root "$fi_receiver_custody_root" \
 -max-data-bytes "$fi_receiver_max_data_bytes" \
 -max-concurrent-connections "${fi_receiver_max_concurrent_connections:-8}" \
 -generation-enable \
 -generation-custody-root "$fi_receiver_generation_custody_root" \
 -generation-recorded-root "$fi_receiver_generation_recorded_root" \
 -generation-ready-root "$fi_receiver_generation_ready_root" \
 -generation-verified-cache-root /var/db/fi/verified-cache \
 -generation-max-canonical-bytes "$fi_receiver_generation_max_canonical_bytes" \
 -generation-max-encoded-bytes "$fi_receiver_generation_max_encoded_bytes" \
 -generation-max-manifest-bytes "$fi_receiver_generation_max_manifest_bytes" \
 -generation-cache-backfill-source "$2" \
 -generation-cache-backfill-generation "$3"
' sh "/usr/local/sbin/fi-receiver-backfill-$pin" \
 iss-fs-22a.iss.local 20261030T000032.061323100Z-3e38b2210771462c ||
 fail 'backfill not accepted by original signed receiver custody'
echo '===== PUBLISHED RECEIVER CACHE ====='
find "$src" -maxdepth 2 -name verified.json -type f -print
du -sh "$src"
echo "FI C1 BACKFILL PASS commit=$pin receiver_listener_unchanged=true sql_untouched=true"
