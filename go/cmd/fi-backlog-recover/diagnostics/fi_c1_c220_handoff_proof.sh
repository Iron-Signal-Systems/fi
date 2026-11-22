#!/bin/sh
# C1 actual FreeBSD jail-to-jail filesystem proof.
# Writes ONE small ephemeral file to approved host-backed C1 tmpfs as the
# fi-ingest runtime user. Reads it as fi-sor, proves fi-sor cannot write,
# then removes it from fi-ingest. No PostgreSQL/custody/rc mutations.
set -eu
umask 077
fail(){ printf 'C1 C220 HANDOFF PROOF STOP: %s\n' "$*" >&2; exit 1; }
[ "$(id -un)" = root ] && [ "$(hostname -s)" = c220 ] ||
    fail 'physical C220 root required'
[ "$#" -eq 1 ] && [ "$1" = --prove ] ||
    fail 'usage: FI_C1_HANDOFF_PROOF_APPROVED=VOLATILE_ONE_FILE_ONLY sh script --prove'
[ "$(printenv FI_C1_HANDOFF_PROOF_APPROVED 2>/dev/null || :)" = VOLATILE_ONE_FILE_ONLY ] ||
    fail 'explicit volatile handoff proof approval required'
[ -x /var/tmp/fi-c1-host-preflight ] ||
    fail 'native statfs verification binary missing'
[ -f /var/tmp/fi_c1_c220_native_acceptance.sh ] ||
    fail 'native C220 acceptance runner missing'

# This is a mandatory safety predecessor: no write, even to RAM, before
# native statfs confirms tmpfs, all nullfs mount identities, RO and flags.
sh /var/tmp/fi_c1_c220_native_acceptance.sh --verify ||
    fail 'native seven-mount and original-custody verification incomplete'
path=
cleanup(){
    if [ -n "$path" ]; then
        jexec -U fi-ingest fi-ingest /bin/rm -f "$path" ||
            printf 'C1 C220 HANDOFF PROOF CLEANUP FAILURE: %s\n' "$path" >&2
    fi
}
trap cleanup 0
trap 'exit 1' 1 2 3 15

path=$(jexec -U fi-ingest fi-ingest /usr/bin/mktemp \
    /var/run/fi-c1-handoff/.fi-c1-only-proof.XXXXXXXX) ||
    fail 'cannot create uniquely named test file inside fi-ingest RAM'
case "$path" in
/var/run/fi-c1-handoff/.fi-c1-only-proof.*) ;;
*) fail 'unrecognized volatile file path returned by mktemp' ;;
esac

jexec -U fi-ingest fi-ingest /bin/sh -c '
    set -eu
    printf "C1-FREEBSD-VOLATILE-CROSS-JAIL-PROOF\n" > "$1"
    chmod 0600 "$1"
' sh "$path" || fail 'producer could not write volatile RAM as fi-ingest'
expected=$(jexec -U fi-ingest fi-ingest /sbin/sha256 -q "$path") ||
    fail 'producer could not hash created ephemeral file'
observed=$(jexec -U fi-sor fi-sor /sbin/sha256 -q "$path") ||
    fail 'SoR cannot read the identical source RAM object'
[ -n "$expected" ] && [ "$expected" = "$observed" ] ||
    fail 'producer/consumer RAM object hashes differ'
# Since the two jails deliberately share UID 4100, fi-sor has POSIX file
# ownership but MUST be prevented from writing by the ro nullfs mount.
if jexec -U fi-sor fi-sor /bin/sh -c '
    printf "THIS MUST FAIL" >> "$1"
' sh "$path" 2>/dev/null; then
    fail 'fi-sor RO mount unexpectedly allowed modifying ingest RAM'
fi
after=$(jexec -U fi-ingest fi-ingest /sbin/sha256 -q "$path") ||
    fail 'producer could not rehash ephemeral RAM object'
[ "$expected" = "$after" ] ||
    fail 'failed fi-sor write modified original volatile RAM content'
echo 'C1_C220_VOLATILE_HANDOFF_PROOF_PASS producer=fi-ingest consumer=fi-sor identical_hash=true sor_write_denied=true cleanup_on_exit=true'
