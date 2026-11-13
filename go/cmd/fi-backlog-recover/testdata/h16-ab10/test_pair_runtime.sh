#!/bin/sh
# Execute the ACTUAL sequential coordinator with mocked host commands and
# inert child benchmarks. Catches runtime shell errors sh -n misses.
set -eu
pair=go/cmd/fi-backlog-recover/run_private_h16_ab10_pair_host.sh
[ -f "$pair" ] || exit 1
temp=$(mktemp -d)
trap 'rm -rf "$temp"' 0
mkdir -p "$temp/bin" "$temp/jail/home/jwood"
cat > "$temp/bin/id" <<'MOCK'
#!/bin/sh
[ "$1" = -un ] && { printf 'root\n'; exit 0; }
exit 2
MOCK
cat > "$temp/bin/jls" <<'MOCK'
#!/bin/sh
[ "$1" = -j ] && [ "$2" = fi-dev ] && [ "$3" = path ] || exit 2
printf '%s\n' "$FI_AB10_MOCK_JAIL"
MOCK
cat > "$temp/bin/jexec" <<'MOCK'
#!/bin/sh
case "$*" in
 *fi-h16-combined-ab10.sh*)
   if [ "$FI_AB10_MOCK_BAD_SHA" = 1 ]; then
      printf 'broken-hash\n'
   else
      printf '45d539d87c2c2d282360d82de210f68974eb70fb\n'
   fi ;;
 *fi-h16-five-ab10.sh*)
   printf '47380305f9da2e5616cac930189fbfac7aed8042\n' ;;
 *) exit 2 ;;
esac
MOCK
cat > "$temp/jail/home/jwood/fi-h16-combined-ab10.sh" <<'MOCK'
#!/bin/sh
printf 'combined\n' >> "$FI_AB10_MOCK_LOG"
[ "$FI_AB10_MOCK_COMBINED_FAIL" != 1 ]
MOCK
cat > "$temp/jail/home/jwood/fi-h16-five-ab10.sh" <<'MOCK'
#!/bin/sh
printf 'five\n' >> "$FI_AB10_MOCK_LOG"
MOCK
chmod +x "$temp/bin/"* "$temp/jail/home/jwood/"*
FI_AB10_MOCK_JAIL="$temp/jail";export FI_AB10_MOCK_JAIL
FI_AB10_MOCK_LOG="$temp/actions.log";export FI_AB10_MOCK_LOG
FI_AB10_MOCK_BAD_SHA=0;export FI_AB10_MOCK_BAD_SHA
FI_AB10_MOCK_COMBINED_FAIL=0;export FI_AB10_MOCK_COMBINED_FAIL
PATH="$temp/bin:$PATH";export PATH
# Good path must execute both exactly once, in proper order.
sh "$pair" h16 > "$temp/good.log"
printf 'combined\nfive\n' > "$temp/expected.log"
cmp "$temp/actions.log" "$temp/expected.log" ||
    { echo 'FI PAIR SMOKE FAIL: nonsequential success path' >&2; exit 1; }
# Bad first hash must stop before starting ANY trial.
: > "$temp/actions.log"
FI_AB10_MOCK_BAD_SHA=1;export FI_AB10_MOCK_BAD_SHA
if sh "$pair" h16 > "$temp/badsha.log" 2>&1; then
    echo 'FI PAIR SMOKE FAIL: hash mismatch accepted' >&2; exit 1
fi
[ ! -s "$temp/actions.log" ] ||
    { echo 'FI PAIR SMOKE FAIL: started with bad hash' >&2; exit 1; }
grep -Fq 'combined ten-window runner differs' "$temp/badsha.log" || exit 1
FI_AB10_MOCK_BAD_SHA=0;export FI_AB10_MOCK_BAD_SHA
# Failure of combined must prevent the second benchmark from starting.
FI_AB10_MOCK_COMBINED_FAIL=1;export FI_AB10_MOCK_COMBINED_FAIL
if sh "$pair" h16 > "$temp/failfirst.log" 2>&1; then
    echo 'FI PAIR SMOKE FAIL: failed combined accepted' >&2; exit 1
fi
printf 'combined\n' > "$temp/expected.log"
cmp "$temp/actions.log" "$temp/expected.log" ||
    { echo 'FI PAIR SMOKE FAIL: five ran after failed combined' >&2; exit 1; }
grep -Fq 'five-lane NOT started' "$temp/failfirst.log" || exit 1
printf 'FI H16 AB10 PAIR RUNTIME SHELL PASS serial=true bad_sha_stops=true first_failure_stops=true\n'
