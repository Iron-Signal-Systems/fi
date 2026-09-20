FI Phase 2 - 250K Randomized Nested Onboarding Harness
=========================================================

Status
------

These files are preserved as the exact Phase 2 250K campaign tooling used for
the 2026-09-19 engineering/resilience campaign.

The original strict clean 250K onboarding acceptance was intentionally
interrupted during fault injection and remains:

    INTERRUPTED - NOT A CLEAN PASS

The campaign nevertheless produced accepted Phase 2 resilience and performance
characterization, documented in:

    docs/performance/PHASE-2-250K-RANDOM-NESTED-ONBOARDING-REPORT.md
    docs/performance/PHASE-2-GATE-2-CLOSEOUT.md

The two PowerShell scripts below are preserved unchanged from the executed
campaign versions:

    25A-FileServer-Onboarding250K-RandomNested.ps1
    SHA256 D8B4A379EE420DF2738CB1202599B1BD550716AA3EA82C9514DA568C4732351F

    25B-FileServer-Onboarding250K-LiveStats.ps1
    SHA256 6D531F791FE1415480EC01DCE1CAA1BFCCBDEE2EFB2CB54932B75E4D9F82B043

25A is deliberately hard-gated to the exact ISS-FS-01 lab identities and
executable hashes used by the original campaign. That gate is historical
provenance, not a claim that the script should run unchanged against later FI
builds.

Files
-----

25A-FileServer-Onboarding250K-RandomNested.ps1
    Full 250,000-file initial-onboarding campaign harness.

25B-FileServer-Onboarding250K-LiveStats.ps1
    Independent five-second live resource viewer. It does not depend on the
    report or campaign CSV. Run it in a second Administrator PowerShell window.

Dataset
-------

Exactly 250,000 generated payload files.

Default deterministic seed:

    decimal 7966157670060267791
    hex     0x6E8D7A31C4B2190F

For that exact seed, the deterministic generator plans:

    422,969,503,185 bytes
    393.921046690 GiB

The later live governed-tree count reached 250,004 files after four deliberate
manual semantic-validation probes were introduced. Those probes were not
generator output.

File-size distribution:

    5%   0 .. 16 KiB
    50%  16 KiB .. 256 KiB
    30%  256 KiB .. 2 MiB
    12%  2 MiB .. 8 MiB
    3%   8 MiB .. 32 MiB

Directory shape:

    20,000 generated directories
    depth 1 through 15
    weighted toward realistic mid-depth branches
    irregular parent selection
    ~5% of leaves intentionally empty
    65% of files placed in a hot 20% subset of usable leaves
    two reserved depth-15 mutation targets

Safety / custody
----------------

25A is LAB-ONLY and intentionally destructive to the disposable Y:\FI-Lab
dataset.

It is hard-gated to ISS-FS-01, exact service identities, and exact deployed
executable hashes.

Before rebuilding the lab tree it:

    1. reads and saves the exact Y:\FI-Lab SDDL including SACL;
    2. stops FI;
    3. waits for published source-spool manifests to drain under the real sender;
    4. stops the sender task;
    5. archives the prior FI state/spool under Y:\FI-Archive;
    6. deletes only the exact disposable Y:\FI-Lab dataset;
    7. recreates the lab root/state/spool;
    8. restores the prior root owner/group/DACL/SACL; and
    9. restores the configured junction layout.

It does not delete receiver custody, change Git/GitHub, alter FI service
definitions, change service accounts, or modify certificate stores.

Live / CSV measurements every five seconds
------------------------------------------

Host CPU
Host RAM load and available RAM
FICollector CPU + working set
FIUSNReader CPU + working set
fi-sender CPU + working set

Y: logical:

    read MiB/s
    write MiB/s
    read latency
    write latency
    queue length

Network:

    host aggregate active-interface receive MiB/s
    host aggregate active-interface transmit MiB/s
    approximate aggregate link utilization
    errors/discards
    TCP connection count to the configured receiver

Network counters are host-level. They are not FI-only attribution.

Campaign behavior
-----------------

The main campaign prints each five-second sample live and writes
`samples-5s.csv`.

The initial harness treats loss of the FICollector process as a campaign failure.
That is why the intentional collector-kill exercise interrupted the strict clean
acceptance harness. Independent telemetry continued outside the harness and was
used for the retained before/down/after resilience measurements.

The campaign also exposed cross-root scheduling behavior that was later
remediated in commit `41906af`. The original 25A script is intentionally
preserved unchanged and still binds the pre-remediation executable hashes used by
the original run.

Run
---

RUN ON: ISS-FS-01 - Administrator PowerShell

Historical main campaign invocation:

    cd C:\FI-Test\phase2-250k
    .\25A-FileServer-Onboarding250K-RandomNested.ps1

Independent live viewer:

    cd C:\FI-Test\phase2-250k
    .\25B-FileServer-Onboarding250K-LiveStats.ps1

Ctrl-C stops only the independent viewer.

Repository role
---------------

These files are retained so the Phase 2 engineering record includes the actual
campaign tooling, not only the resulting reports.

They are historical lab validation tools, not general production deployment
scripts.
