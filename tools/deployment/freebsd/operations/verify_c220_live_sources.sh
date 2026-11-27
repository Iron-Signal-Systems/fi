#!/bin/sh
set -eu

REPO=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)

RECEIVER=49609398d91e105fdeb74190a39bf2e390175996
TELEMETRY=0c2ffb6b32c40e19a3cdc4b0b1cc50e695889fae

RX_HASH=c0006e7de05c38eb4da4869de5c9b8ecb56663b4ea35ed44b7a248ca23375f8c
C1_HASH=54ea5cce0538ba0f65cd1d6effc78b695ed44bd2f8257aa14781bf1e58e558b2
TEL_HASH=dab1deb8cc39ded4c9b293e74bc8c39f30a61393828dc73899a8db560ccf3a11

[ "$(uname -s)" = FreeBSD ] || {
  echo 'STOP: FreeBSD required'; exit 1;
}

[ -f "$REPO/runtime/baselines/c220-20261127/c1/go/go.mod" ] || {
  echo 'STOP: accepted C1 source missing'; exit 1;
}

WORK=$(mktemp -d /home/jwood/fi-c220-build.XXXXXXXX)
mkdir -p "$WORK/receiver" "$WORK/telemetry" "$WORK/c1"

git -C "$REPO" archive "$RECEIVER" go |
  tar -xf - -C "$WORK/receiver"

git -C "$REPO" archive "$TELEMETRY" go |
  tar -xf - -C "$WORK/telemetry"

cp -R "$REPO/runtime/baselines/c220-20261127/c1/go" "$WORK/c1/go"

export GOTOOLCHAIN=auto

build_check() {
  name=$1
  source=$2
  command=$3
  tags=$4
  expected=$5

  (
    cd "$source"

    [ "$(go version | awk '{print $3}')" = go1.27.4 ] || {
      echo "STOP: incorrect Go toolchain for $name"
      exit 1
    }

    if [ "$tags" = none ]; then
      CGO_ENABLED=1 GOOS=freebsd GOARCH=amd64 GOAMD64=v1 \
        go build -buildvcs=false -trimpath \
        -o "$WORK/$name" "$command"
    else
      CGO_ENABLED=1 GOOS=freebsd GOARCH=amd64 GOAMD64=v1 \
        go build -buildvcs=false -trimpath -tags "$tags" \
        -o "$WORK/$name" "$command"
    fi
  )

  actual=$(sha256 -q "$WORK/$name")

  printf '%s expected=%s actual=%s\n' "$name" "$expected" "$actual"

  [ "$actual" = "$expected" ] || {
    echo "FAIL: $name differs from running C220"
    exit 1
  }

  echo "PASS: $name matches running C220"
}

build_check fi-receiver "$WORK/receiver/go" \
  ./cmd/fi-receiver none "$RX_HASH"

build_check fi-c1-sor-live "$WORK/c1/go" \
  ./cmd/fi-c1-sor-local fi_c1_sor_dev "$C1_HASH"

build_check fi-telemetry-backend "$WORK/telemetry/go" \
  ./cmd/fi-telemetry-backend none "$TEL_HASH"

echo "PASS: ALL THREE C220 BINARIES REPRODUCED"
echo "Build evidence: $WORK"
