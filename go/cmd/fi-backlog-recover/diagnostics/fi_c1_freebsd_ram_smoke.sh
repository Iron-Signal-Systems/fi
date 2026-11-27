#!/bin/sh
# FI C1 FreeBSD 15.1 disposable VM: real tmpfs/nullfs semantics ONLY.
# NEVER run on C220 or any machine containing original signed custody.
# Does not create jails, edit fstab, start FI, or contact PostgreSQL.
set -eu
umask 077
fail(){ echo "FI C1 FREEBSD VM RAM SMOKE FAIL: $*" >&2; exit 1; }
[ "$(uname -s)" = FreeBSD ] || fail "requires FreeBSD"
[ "${GITHUB_ACTIONS:-}" = true ] || fail "requires explicitly isolated GitHub Actions VM"
[ "$(id -u)" -eq 0 ] || fail "requires FreeBSD VM root for test-only mounts"
base=$(mktemp -d /var/tmp/fi-c1-vm-nullfs.XXXXXXXX) || fail "cannot create disposable test root"
host="$base/host-tmpfs"
ingest="$base/fi-ingest"
sor="$base/fi-sor"
mkdir -p "$host" "$ingest" "$sor"
chmod 0770 "$host"
ram=0
rw=0
ro=0
cleanup(){
  # Cleanup is best-effort and strictly constrained to the disposable
  # mktemp-created VM root; never name any production mountpoint.
  if [ "$ro" -eq 1 ]; then umount "$sor" || :; fi
  if [ "$rw" -eq 1 ]; then umount "$ingest" || :; fi
  if [ "$ram" -eq 1 ]; then umount "$host" || :; fi
  rm -rf "$base"
}
trap cleanup EXIT HUP INT TERM
mount -t tmpfs -o size=64m,nosuid,noexec,uid=0,gid=0,mode=0770 tmpfs "$host" ||
  fail "host tmpfs creation"
ram=1
mount -t nullfs -o rw "$host" "$ingest" || fail "fi-ingest writable nullfs"
rw=1
mount -t nullfs -o ro "$host" "$sor" || fail "fi-sor read-only nullfs"
ro=1
mount -p | awk -v p="$host" '$2==p && $3=="tmpfs" {ok=1} END{exit !ok}' ||
  fail "host backing not tmpfs"
mount -p | awk -v p="$ingest" -v h="$host"   '$1==h && $2==p && $3=="nullfs" {ok=1} END{exit !ok}' ||
  fail "ingest not nullfs on exact host tmpfs source"
mount -p | awk -v p="$sor" -v h="$host"   '$1==h && $2==p && $3=="nullfs" && $4 ~ /(^|,)ro(,|$)/ {ok=1} END{exit !ok}' ||
  fail "SoR not read-only nullfs on exact host tmpfs source"
printf '%s\n' "prepared C1 object from ingest only" > "$ingest/c1-prepared-object.ready" ||
  fail "fi-ingest cannot publish prepared RAM"
cmp "$ingest/c1-prepared-object.ready" "$sor/c1-prepared-object.ready" >/dev/null ||
  fail "fi-sor cannot read exact producer RAM"
if (printf 'FORBIDDEN\n' > "$sor/unauthorized-sor-write") 2>/dev/null; then
  fail "SoR unexpectedly writable through read-only nullfs"
fi
if (rm "$sor/c1-prepared-object.ready") 2>/dev/null; then
  fail "SoR unexpectedly able to unlink producer RAM object"
fi
rm "$ingest/c1-prepared-object.ready" ||
  fail "producer cannot reclaim own committed RAM object"
[ ! -e "$sor/c1-prepared-object.ready" ] ||
  fail "SoR still sees committed RAM after producer reclaim"
echo "FI C1 FREEBSD VM RAM SMOKE PASS host_tmpfs=true ingest_nullfs_rw=true sor_nullfs_ro=true producer_only_cleanup=true no_fstab_changes=true no_canonical_sql=true"
