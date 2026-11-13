#!/bin/sh
# Two independent, sequential, real-signed FI H16 W3-W12 development trials.
# Root on fi-backend-b; each child runner creates its own private PostgreSQL
# clone and stops it cleanly. Never run two FI benchmarks concurrently.
# Both runners MUST have already been staged, hash checked, and owned by
# jwood under fi-dev. This coordinator does not edit a live source worktree,
# any jail configuration or the authoritative SoR.
set -eu
umask 077

die() { printf 'FI H16 AB10 PAIR STOP: %s\n' "$*" >&2; exit 1; }
[ "$(id -un)" = root ] || die 'must run as root on fi-backend-b'
[ "$#" -eq 1 ] && [ "$1" = h16 ] ||
    die 'usage: sh run_private_h16_ab10_pair_host.sh h16'

jailroot=$(jls -j fi-dev path) || die 'fi-dev jail unavailable'
combined="$jailroot/home/jwood/fi-h16-combined-ab10.sh"
five="$jailroot/home/jwood/fi-h16-five-ab10.sh"
[ -f "$combined" ] && [ -f "$five" ] ||
    die 'both ten-window runners must be staged inside fi-dev'

get_hash() {
    jexec -U jwood fi-dev git hash-object "$1"
}
[ "$(get_hash /home/jwood/fi-h16-combined-ab10.sh)" = "02888bfe0245ead876d52b9fecac2ea0a532361c" ] ||
    die 'combined ten-window runner differs from verified Git blob'
[ "$(get_hash /home/jwood/fi-h16-five-ab10.sh)" = "8ba5050b0c6500d22cb7ea2a1a4f51024faa4c5f" ] ||
    die 'five-lane ten-window runner differs from verified Git blob'

sh -n "$combined" && sh -n "$five" ||
    die 'a staged runner failed syntax verification'
printf 'FI H16 AB10 PAIR START combined_first=true five_second=true overlap=false\n'

# The combined runner enforces SQL/byte-level acceptance and stops its
# disposable clone. Any failure prevents the five-lane trial from starting.
sh "$combined" h16 || die 'combined W3-W12 failed; five-lane NOT started'
printf 'FI H16 AB10 PAIR COMBINED PASS private_clone_stopped=true\n'

# The fifth-lane trial starts only once the combined run has completed,
# including signed readback and metrics export. No shared SQL backend exists.
sh "$five" h16 || die 'five-lane W3-W12 failed'
printf 'FI H16 AB10 PAIR ACCEPTED combined_windows=10 five_windows=10 total_signed_replays=2 authoritative=0 accepted=0\n'
