#!/bin/sh
# Read-only CRL and FI trust readiness before C1 development SoR acceptance.
# C220 host root only. No CRL publication, service restart, credential read,
# PostgreSQL writes, or trust bypass.
set -eu
umask 077

fail() { echo "FI C1 CRL PREFLIGHT STOP: $*" >&2; exit 1; }
[ "$(id -un)" = root ] && [ "$(hostname -s)" = c220 ] ||
  fail "requires root on C220"
for j in fi-receiver fi-ingest fi-sor-db;do
  jls -j "$j" >/dev/null 2>&1 || fail "required jail not running: $j"
done

echo "===== CLOCK AND TRUST-PATH INVENTORY ====="
date -u '+observed_at_utc=%Y-%m-%dT%H:%M:%SZ'
echo "===== RECEIVER: ISSUER/CRL CRYPTOGRAPHIC TRUST STATUS ====="
# The FI receiver's installed own trust checker validates issuer matching,
# CRL signatures, ThisUpdate/NextUpdate and receiver serial revocation.
trust=$(jexec fi-receiver sh -c 'command -v fi-receiver >/dev/null 2>&1 && exec fi-receiver trust status' 2>&1) ||
  fail "installed fi-receiver trust status command failed: $trust"
printf '%s\n' "$trust"

check_valid(){
  label=$1
  printf '%s\n' "$trust" | grep -Eq "^[[:space:]]*$label[[:space:]]+VALID([[:space:]]|$)" ||
    fail "$label is not VALID in installed receiver trust status"
}
check_valid "Root CA"
check_valid "Transport issuing CA"
check_valid "Batch signing CA"
check_valid "Transport CRL"
check_valid "Batch signing CRL"
check_valid "Receiver certificate"
check_valid "Receiver hostname"
check_valid "Receiver revocation"
check_valid "Trust custody"
check_valid "Source registry"
printf '%s\n' "$trust" | grep -Eq '^[[:space:]]*Trust state[[:space:]]+READY([[:space:]]|$)' ||
  fail "complete receiver trust not READY"
echo "FI C1 RECEIVER TRUST PASS issuer_signature_freshness=true receiver_revocation=true registry=valid"

echo "===== RECEIVER: CRL DETAILS (PUBLIC CERTIFICATE DATA ONLY) ====="
jexec fi-receiver sh -s <<'JAIL'
set -eu
dir=/usr/local/etc/fi/pki/trust
for family in transport batch-signing;do
  crl="$dir/fi-$family-ca.crl.pem"
  issuer="$dir/fi-$family-ca.crt.pem"
  [ -s "$crl" ] && [ -s "$issuer" ] || {
    echo "FI C1 CRL FAIL: missing receiver $family issuer/CRL" >&2
    exit 1
  }
  echo "RECEIVER_CRL family=$family"
  openssl crl -in "$crl" -noout -issuer -lastupdate -nextupdate -crlnumber
  openssl crl -in "$crl" -noout -verify -CAfile "$issuer" >/dev/null ||
    { echo "FI C1 CRL FAIL: $family signature" >&2; exit 1; }
  echo "RECEIVER_CRL_SHA256 family=$family digest=$(sha256 -q "$crl")"
done
JAIL

echo "===== INGEST: INSTALLED BATCH CRL / ISSUER ====="
# These paths are the original FI batch-trust contract. A different mount or
# missing file is a blocker requiring inspection, not permission to copy files.
jexec fi-ingest sh -s <<'JAIL'
set -eu
dir=/usr/local/etc/fi/pki/trust
crl="$dir/fi-batch-signing-ca.crl.pem"
issuer="$dir/fi-batch-signing-ca.crt.pem"
root="$dir/fi-root-ca.crt.pem"
for p in "$crl" "$issuer" "$root";do
  [ -s "$p" ] || { echo "FI C1 CRL FAIL: ingest trust missing $p" >&2; exit 1; }
done
openssl crl -in "$crl" -noout -issuer -lastupdate -nextupdate -crlnumber
openssl crl -in "$crl" -noout -verify -CAfile "$issuer" >/dev/null ||
  { echo 'FI C1 CRL FAIL: ingest batch CRL signature' >&2; exit 1; }
echo "INGEST_BATCH_CRL_SHA256=$(sha256 -q "$crl")"
echo "INGEST_ROOT_SHA256=$(sha256 -q "$root")"
JAIL

echo "===== RECEIVER ↔ INGEST TRUST COMPARISON ====="
recvcrl=$(jexec fi-receiver sha256 -q /usr/local/etc/fi/pki/trust/fi-batch-signing-ca.crl.pem)
ingestcrl=$(jexec fi-ingest sha256 -q /usr/local/etc/fi/pki/trust/fi-batch-signing-ca.crl.pem)
recvroot=$(jexec fi-receiver sha256 -q /usr/local/etc/fi/pki/trust/fi-root-ca.crt.pem)
ingestroot=$(jexec fi-ingest sha256 -q /usr/local/etc/fi/pki/trust/fi-root-ca.crt.pem)
[ "$recvcrl" = "$ingestcrl" ] ||
  fail 'receiver and ingest have different batch-signing CRL bytes'
[ "$recvroot" = "$ingestroot" ] ||
  fail 'receiver and ingest have different pinned root CA bytes'
echo "FI C1 CRL TRUST MATCH PASS receiver_ingest_root=true receiver_ingest_batch_crl=true"
echo "FI C1 CRL PREFLIGHT PASS read_only=true service_restart=false publication=false"
