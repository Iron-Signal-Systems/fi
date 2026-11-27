#!/bin/sh
# Copyright (c) 2026 John Joseph Wood. All rights reserved.
# Use of this source code is governed by the File Intelligence (FI)
# Source Review License, Version 1.0, found in the repository root LICENSE file.
#
# C1 DEVELOPMENT build only, from the exact current branch. Produces the
# four native FreeBSD/amd64 worker/admin executables expected by the
# EXISTING guarded fi-backend-install apply-c1-binaries command.
# Does NOT touch C220, install into any jail, update SQL or enable service.
set -eu
umask 077
fail(){ printf 'FI C1 DEV BINARY STAGE STOP: %s\n' "$*" >&2; exit 1; }

[ "$#" -eq 1 ] || fail 'usage: sh tools/deployment/freebsd/build-fi-c1-dev.sh /absolute/new/staging-directory'
destination=$1
case "$destination" in
  /*) ;;
  *) fail 'staging destination must be absolute' ;;
esac
[ "$destination" != / ] && [ ! -e "$destination" ] && [ ! -L "$destination" ] ||
  fail 'staging destination must not exist; never overwrite binaries'
parent=$(dirname "$destination")
[ -d "$parent" ] && [ ! -L "$parent" ] ||
  fail 'staging parent must be a real existing directory'
root=$(CDPATH= cd "$(dirname "$0")/../../.." && pwd -P) ||
  fail 'cannot determine FI repository root'
[ -f "$root/go/go.mod" ] && [ -f "$root/LICENSE" ] ||
  fail 'source root is not the complete FI checkout'
[ "$(uname -s)" = FreeBSD ] && [ "$(uname -m)" = amd64 ] ||
  fail 'stage these exact native FreeBSD amd64 binaries from fi-dev'
git -C "$root" rev-parse --is-inside-work-tree | grep -qx true ||
  fail 'not a Git source checkout'
branch=$(git -C "$root" symbolic-ref --short HEAD) ||
  fail 'detached HEAD prohibited for C1 development deployment'
[ "$branch" = dev/c1-two-process-20261120 ] ||
  fail 'C1 binary build must use the accepted current development branch'
[ -z "$(git -C "$root" status --porcelain)" ] ||
  fail 'dirty development source cannot produce deployable C1 executables'
commit=$(git -C "$root" rev-parse HEAD) ||
  fail 'missing exact development commit SHA'
version=$(go version) || fail 'Go installation unavailable'
printf '%s\n' "$version" | grep -Eq '^go version go1[.]27[.]' ||
  fail 'FI C1 development must compile with Go 1.27.x'

stage=$(mktemp -d "$destination.tmp.XXXXXXXX") ||
  fail 'cannot create atomic development staging directory'
cleanup(){ [ -z "${stage:-}" ] || rm -rf "$stage"; }
trap cleanup EXIT HUP INT TERM

cd "$root/go"
for component in fi-c1-ingest-worker fi-c1-sor-worker fi-c1-private-schema fi-c1-host-preflight;do
    printf 'FI C1 BUILD %s source=%s\n' "$component" "$commit"
    CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 \
      go build -trimpath -tags fi_c1_sor_dev -o "$stage/$component" "./cmd/$component" ||
      fail "native C1 executable build failed: $component"
    chmod 0555 "$stage/$component" ||
      fail "cannot set immutable staged executable mode: $component"
    go version -m "$stage/$component" | grep -Eq 'GOOS=freebsd' ||
      fail "staged executable is not FreeBSD: $component"
    go version -m "$stage/$component" | grep -Eq 'GOARCH=amd64' ||
      fail "staged executable is not amd64: $component"
done
[ "$(git -C "$root" rev-parse HEAD)" = "$commit" ] &&
[ -z "$(git -C "$root" status --porcelain)" ] ||
  fail 'branch source changed during C1 build; reject release staging'
{
    printf 'FI_C1_DEVELOPMENT_BRANCH=%s\n' "$branch"
    printf 'FI_C1_COMMIT=%s\n' "$commit"
    printf 'FI_C1_TOOLCHAIN=%s\n' "$version"
    for component in fi-c1-ingest-worker fi-c1-sor-worker fi-c1-private-schema fi-c1-host-preflight;do
        printf 'SHA256_%s=%s\n' "$component" "$(sha256 -q "$stage/$component")"
    done
    printf 'C1_SERVICES_ENABLED=false\n'
    printf 'C220_CHANGED=false\n'
} > "$stage/BUILD-MANIFEST.txt"
chmod 0444 "$stage/BUILD-MANIFEST.txt"
chmod 0750 "$stage"
mv "$stage" "$destination" ||
  fail 'atomic native C1 binary stage publication failed'
stage=
printf 'FI C1 NATIVE DEVELOPMENT BINARY STAGE PASS path=%s source_commit=%s services_enabled=false c220_changed=false\n' \
  "$destination" "$commit"
