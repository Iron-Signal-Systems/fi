#!/bin/sh
# C220 real fi-ingest/fi-sor C1 volatile shared handoff: READ-ONLY plan.
# Does not mount, create directories/fstabs, edit jail.conf, restart jails,
# change database state or enable C1 services.
set -eu
fail(){ printf 'C1 C220 MOUNT PLAN STOP: %s\n' "$*" >&2; exit 1; }
[ "$(id -un)" = root ] && [ "$(hostname -s)" = c220 ] ||
  fail 'root on physical C220 required'
ingest=/fast/jails/roots/fi-ingest
sor=/fast/jails/roots/fi-sor
host_ram=/var/run/fi-c1-handoff
for j in fi-ingest fi-sor; do
  jls -j "$j" jid >/dev/null 2>&1 || fail "real jail not running: $j"
done
if jls -j fi-sor-db jid >/dev/null 2>&1; then
  fail 'unexpected fi-sor-db jail also running'
fi
for mapping in 'fi-ingest /fast/jails/roots/fi-ingest' 'fi-sor /fast/jails/roots/fi-sor'; do
  name=$(printf '%s\n' "$mapping" | cut -d' ' -f1)
  root=$(printf '%s\n' "$mapping" | cut -d' ' -f2)
  actual=$(jls -h jid name path | awk -v n="$name" '$2==n{print $3}')
  [ "$actual" = "$root" ] || fail "running jail path changed for $name"
done
[ "$(jexec fi-ingest id -u fi-ingest)" = 4100 ] ||
  fail 'fi-ingest UID changed'
[ "$(jexec fi-ingest id -g fi-ingest)" = 4100 ] ||
  fail 'fi-ingest GID changed'

for j in fi-ingest fi-sor; do
  conf="/etc/jail.conf.d/$j.conf"
  [ -f "$conf" ] && [ ! -L "$conf" ] ||
    fail "actual existing jail config missing or symlinked: $conf"
  if grep -Eq '^[[:space:]]*mount[.]fstab[[:space:]]*=' "$conf"; then
    fail "jail already has an fstab binding; audit actual config: $conf"
  fi
done
if mount -p | awk -v p="$host_ram" -v a="$ingest/var/run/fi-c1-handoff" -v b="$sor/var/run/fi-c1-handoff" \
    '$2==p||$2==a||$2==b {found=1} END {exit !found}'; then
  fail 'C1 RAM mount is already present; do not layer a second mount'
fi

printf '%s\n' '===== EXACT C220 C1 MOUNT PLAN (READ-ONLY, NOT APPLIED) ====='
printf '%s\n' 'Host /etc/fstab candidate (NOAUTO, needs ordered fi_c1_ram service):'
printf 'tmpfs %s tmpfs rw,noauto,nosuid,noexec,size=4g,uid=4100,gid=4100,mode=0770 0 0\n' "$host_ram"
printf '%s\n' 'Create NEW dedicated FI mount files ONLY after separate approval:'
printf '%s\n' '/etc/jail.fstab.d/fi-c1-fi-ingest.fstab:'
printf '%s %s/var/run/fi-c1-handoff nullfs rw 0 0\n' "$host_ram" "$ingest"
printf '%s\n' '/etc/jail.fstab.d/fi-c1-fi-sor.fstab:'
printf '%s %s/var/run/fi-c1-handoff nullfs ro 0 0\n' "$host_ram" "$sor"
# Independent fi-sor verifier B reopens the ORIGINAL receiver-signed
# custody object, recorded receipt, pinned trust, and source authorization.
# None of these are currently mapped into the physical fi-sor jail.
# The existing receiver/ingest source mounts are immutable inputs.
host_custody=/work/fi-c220-20261114/custody/generation
host_recorded=/work/fi-c220-20261114/custody/recorded
host_trust=/work/fi-c220-20261114/config/receiver/pki/trust
host_sources=/work/fi-c220-20261114/config/receiver/sources
printf '%s\n' 'Independent fi-sor verification: required ORIGINAL signed read-only mappings:'
for original in "$host_custody" "$host_recorded" "$host_trust" "$host_sources"; do
  if [ ! -d "$original" ] || [ -L "$original" ]; then
    fail "original receiver trust/custody source path absent or unsafe: $original"
  fi
done
printf '%s %s/var/db/fi/custody/generation nullfs ro 0 0\n' "$host_custody" "$sor"
printf '%s %s/var/db/fi/custody/recorded nullfs ro 0 0\n' "$host_recorded" "$sor"
printf '%s %s/usr/local/etc/fi/pki/trust nullfs ro 0 0\n' "$host_trust" "$sor"
printf '%s %s/usr/local/etc/fi/sources nullfs ro 0 0\n' "$host_sources" "$sor"
printf '%s\n' 'The above four RO mappings must be in the fi-sor mount plan,'
printf '%s\n' 'along with its RO RAM view. All original receiver objects remain authoritative.'
printf '%s\n' 'Insert ONE mount.fstab assignment into each existing config (not performed):'
printf '%s\n' '  /etc/jail.conf.d/fi-ingest.conf: mount.fstab = "/etc/jail.fstab.d/fi-c1-fi-ingest.fstab";'
printf '%s\n' '  /etc/jail.conf.d/fi-sor.conf: mount.fstab = "/etc/jail.fstab.d/fi-c1-fi-sor.fstab";'
printf '%s\n' '===== MANDATORY NON-ACTIVATION GATES ====='
printf '%s\n' 'Do not restart running jails: original custody/PG nullfs mounts are currently independent.'
printf '%s\n' 'Before enabling any C1 service, prove the host tmpfs startup ordering, all four signed SoR RO paths,'
printf '%s\n' 'Before enabling any C1 service, prove the host tmpfs startup ordering, original custody persistence,'
printf '%s\n' 'numeric fi-sor identity, noexec/nosuid flags and actual ingest-RW/SoR-RO nullfs mounts.'
printf '%s\n' 'C1 C220 RAM MOUNT PLAN COMPLETE read_only=true host_changes=false'
