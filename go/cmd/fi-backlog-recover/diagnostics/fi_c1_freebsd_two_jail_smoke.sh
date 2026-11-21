#!/bin/sh
# FI C1: real TWO-JAIL FreeBSD 15.1 tmpfs/nullfs acceptance in a
# disposable GitHub Actions VM. No PostgreSQL and NO C220 mounts/writes.
set -eu
umask 077
fail(){ echo "FI C1 FREEBSD TWO-JAIL FAIL: $*" >&2; exit 1; }
[ "$(uname -s)" = FreeBSD ] || fail "FreeBSD kernel required"
[ "${GITHUB_ACTIONS:-}" = true ] || fail "disposable Actions VM authorization required"
[ "$(hostname -s)" != c220 ] || fail "PRODUCTION C220 HOST ABSOLUTELY FORBIDDEN"
[ "$(id -u)" -eq 0 ] || fail "root required in disposable FreeBSD VM"
command -v jail >/dev/null 2>&1 || fail "native FreeBSD jail tool missing"
command -v jexec >/dev/null 2>&1 || fail "native FreeBSD jexec missing"

base=$(mktemp -d /var/tmp/fi-c1-ci-two-jails.XXXXXXXX) ||
  fail "cannot create disposable jail test path"
host="$base/host-tmpfs"
ingest="$base/fi-ingest-root"
sor="$base/fi-sor-root"
ingest_name="fi_c1_ingest_smoke_$$"
sor_name="fi_c1_sor_smoke_$$"
ram_mounted=0
ingest_started=0
sor_started=0
mounts=""
cleanup(){
  # Remove disposable jails BEFORE their nullfs mounts; never reference a
  # host service or existing jail name. The test root is mktemp-created.
  if [ "$sor_started" -eq 1 ];then jail -r "$sor_name" || :;fi
  if [ "$ingest_started" -eq 1 ];then jail -r "$ingest_name" || :;fi
  for mounted in $mounts;do umount "$mounted" || :;done
  if [ "$ram_mounted" -eq 1 ];then umount "$host" || :;fi
  rm -rf "$base"
}
trap cleanup EXIT HUP INT TERM
mkdir -p "$host"
for root in "$ingest" "$sor";do
  mkdir -p "$root/bin" "$root/lib" "$root/libexec"     "$root/usr/lib" "$root/var/run/fi-c1-handoff"
done

mount -t tmpfs -o size=64m,nosuid,noexec,uid=0,gid=0,mode=0770   tmpfs "$host" || fail "cannot create host volatile tmpfs"
ram_mounted=1

# Build two minimal isolated jail roots using read-only host program and
# linker mounts. No synthetic second file-copy backend is introduced.
# Prepend each successful mount to the cleanup stack (reverse order).
mount_ro(){
  source="$1"
  target="$2"
  mount -t nullfs -o ro "$source" "$target" ||
    fail "read-only base userland mount $source"
  mounts="$target $mounts"
}
for root in "$ingest" "$sor";do
  mount_ro /bin "$root/bin"
  mount_ro /lib "$root/lib"
  mount_ro /libexec "$root/libexec"
  mount_ro /usr/lib "$root/usr/lib"
done
mount -t nullfs -o rw "$host" "$ingest/var/run/fi-c1-handoff" ||
  fail "ingest RAM producer nullfs"
mounts="$ingest/var/run/fi-c1-handoff $mounts"
mount -t nullfs -o ro "$host" "$sor/var/run/fi-c1-handoff" ||
  fail "SoR RAM read-only consumer nullfs"
mounts="$sor/var/run/fi-c1-handoff $mounts"

jail -c name="$ingest_name" path="$ingest" persist ||
  fail "cannot launch isolated fi-ingest test jail"
ingest_started=1
jail -c name="$sor_name" path="$sor" persist ||
  fail "cannot launch isolated fi-sor test jail"
sor_started=1

jexec "$ingest_name" /bin/sh -c   'printf "%s\n" "prepared-C1-signed-buffer" > /var/run/fi-c1-handoff/c1-test.ready' ||
    fail "ingest jail cannot publish RAM into host tmpfs"
got=$(jexec "$sor_name" /bin/sh -c   'read payload < /var/run/fi-c1-handoff/c1-test.ready; printf "%s" "$payload"') ||
    fail "fi-sor cannot read original producer buffer"
[ "$got" = "prepared-C1-signed-buffer" ] ||
  fail "fi-sor observed changed or missing producer data"

if jexec "$sor_name" /bin/sh -c   '(printf "%s\n" forbidden > /var/run/fi-c1-handoff/sor-forbidden.ready) 2>/dev/null';then
  fail "read-only fi-sor jail wrote to producer tmpfs"
fi
if jexec "$sor_name" /bin/sh -c   'rm /var/run/fi-c1-handoff/c1-test.ready 2>/dev/null';then
  fail "read-only fi-sor jail removed producer object"
fi
jexec "$ingest_name" /bin/sh -c   'rm /var/run/fi-c1-handoff/c1-test.ready' ||
    fail "ingest jail could not reclaim own committed buffer"
if jexec "$sor_name" /bin/sh -c   'test -e /var/run/fi-c1-handoff/c1-test.ready';then
  fail "fi-sor still sees object reclaimed by ingest jail"
fi

echo "FI C1 FREEBSD TWO-JAIL PASS native_jails=2 host_backing=tmpfs ingest_rw=true sor_ro=true producer_only_reclaim=true signed_custody_untouched=true pg_untouched=true"
