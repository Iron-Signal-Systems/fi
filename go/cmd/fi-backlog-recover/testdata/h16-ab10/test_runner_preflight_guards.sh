#!/bin/sh
# Execute the ACTUAL immutable verifier hash guards extracted verbatim from
# BOTH host runners. Syntax-only sh -n cannot detect a missing closing
# bracket when a shell newline splits a [ comparison.
# No FreeBSD host, database, credential or signed FI backlog is required.
set -eu
repo=$(pwd)
validator=go/cmd/fi-backlog-recover/testdata/h16-ab10/validate_signed_ab10.sh
[ -f "$validator" ] || exit 1
expected=16cc4ff9a850a0a52d23b54e4f9212644ddd3c1e
[ "$(git hash-object "$validator")" = "$expected" ] ||
    { echo 'FI AB10 PRECHECK TEST STOP: source verifier changed without runner pins' >&2; exit 1; }
work=$(mktemp -d)
trap 'rm -rf "$work"' 0 1 2 3 15
root="$work"
combinedrepo="$repo"
cp "$validator" "$work/ab10_validate.sh"
export root combinedrepo

for variant in combined five_lane; do
    if [ "$variant" = combined ]; then
        runner=go/cmd/fi-backlog-recover/run_private_h16_combined_ab10_host.sh
    else
        runner=go/cmd/fi-backlog-recover/run_private_h16_five_lane_ab10_host.sh
    fi
    [ -f "$runner" ] || exit 1
    sh -n "$runner"
    # Audit all lines beginning POSIX [ tests, not merely the known bad
    # verifier check. Each needs its closing ] on the same line or a
    # trailing backslash that deliberately continues the shell command.
    awk '
      /^[[:space:]]*\[[[:space:]]/ {
        if ($0 !~ /\][[:space:]]*($|\|\||&&|;)/ &&
            $0 !~ /\\[[:space:]]*$/) {
          printf "FI AB10 MALFORMED BRACKET TEST line=%d text=%s\n",NR,$0 > "/dev/stderr"
          bad=1
        }
      }
      END {if(bad)exit 2}
    ' "$runner" || exit 1

    # Include the exact real command text from the jailed preflight.
    # This catches a newline after '=' at runtime, rather than testing a
    # separate, manually rewritten version that could hide the same bug.
    awk '
      /^\[ "\$\(git -C / && /hash-object.*ab10_validate.sh/ {grab=1}
      grab {
        print
        if (/AB10 postrun source hash mismatch/) {
          found=1
          exit
        }
      }
      END {if(!found)exit 2}
    ' "$runner" > "$work/$variant.guard" ||
        { echo 'FI AB10 guard extraction failed' >&2; exit 1; }
    [ "$(grep -c 'AB10 postrun source hash mismatch' "$work/$variant.guard")" -eq 1 ] ||
        exit 1

    # Correct original Git bytes must pass.
    ROOT="$root" COMBINEDREPO="$combinedrepo" GUARD="$work/$variant.guard" sh -c '
      set -eu
      root=$ROOT
      combinedrepo=$COMBINEDREPO
      fail() { printf "FI AB10 GUARD FAIL: %s\n" "$*" >&2; exit 1; }
      . "$GUARD"
    ' || { echo "FI AB10 runtime guard rejected correct blob: $variant" >&2; exit 1; }

    # Replacing just the script contents must be rejected before SQL clone.
    printf 'corruption\n' >> "$work/ab10_validate.sh"
    if ROOT="$root" COMBINEDREPO="$combinedrepo" GUARD="$work/$variant.guard" sh -c '
      set -eu
      root=$ROOT
      combinedrepo=$COMBINEDREPO
      fail() { printf "FI AB10 GUARD FAIL: %s\n" "$*" >&2; exit 1; }
      . "$GUARD"
    ' > "$work/bad-$variant.log" 2>&1; then
        echo "FI AB10 guard accepted corrupt verifier: $variant" >&2
        exit 1
    fi
    grep -Fq 'AB10 postrun source hash mismatch' "$work/bad-$variant.log" ||
        { echo 'FI AB10 corrupt verifier failed for wrong reason' >&2; exit 1; }
    cp "$validator" "$work/ab10_validate.sh"
    printf 'FI H16 AB10 RUNNER PREFLIGHT RUNTIME PASS variant=%s valid_hash=true corrupted_hash_rejected=true shell_brackets_valid=true\n' "$variant"
done
