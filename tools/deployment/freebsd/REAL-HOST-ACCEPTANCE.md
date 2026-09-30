# FI FreeBSD Real-Host Acceptance

This document defines final real-host acceptance for the FI FreeBSD backend
deployment layer.

Offline render, classification, collision, no-clobber, and lifecycle tests do
not replace this acceptance.

The real host must prove that the rendered and applied state behaves correctly
under the actual FreeBSD kernel, devfs, jail, VNET, interface, routing, and rc
environment.

## Safety boundary

The administrative interface and administrative address are outside FI
mutation authority.

For the current receiver host:

    administrative interface: vtnet0
    administrative IPv4:      192.168.1.218/24

FI must never:

- detach the administrative interface;
- rename the administrative interface;
- move it into a jail;
- add it to an FI bridge;
- remove its administrative address;
- replace its administrative route;
- use it as the receiver dedicated external interface.

The dedicated receiver external interface is:

    vtnet1

When the receiver jail is stopped, `vtnet1` must be host-owned and must not:

- carry an FI layer-3 address;
- carry an FI route;
- be a member of the management bridge;
- be a member of the workload bridge.

When the receiver jail is running, only `fi-receiver` may receive `vtnet1`.

`fi-ingest` and `fi-sor-db` must never receive the dedicated external
interface.

## Production topology

Host:

    vtnet0      administrative network
    vtnet1      dedicated receiver external interface
    bridge10    FI management bridge, 10.77.10.1/24
    bridge20    FI workload bridge, 10.77.20.1/24

Production jail addresses:

    fi-receiver
        external    192.168.1.219/24
        management  10.77.10.20/24
        workload    10.77.20.20/24

    fi-ingest
        management  10.77.10.21/24
        workload    10.77.20.21/24

    fi-sor-db
        management  10.77.10.22/24
        workload    10.77.20.22/24

Receiver default route:

    192.168.1.1 through vtnet1

Ingest and System-of-Record default route:

    10.77.10.1 through their management VNET interface

## Production lifecycle

FI does not own the global FreeBSD jail service policy.

FI must not change:

    jail_enable
    jail_parallel_start
    jail_list
    jail_reverse_stop

FI production lifecycle authority is:

    /usr/local/etc/rc.d/fi_jails
    /etc/rc.conf.d/fi_jails
    /etc/rc.conf.d/devfs/90-fi

The production startup order is:

    fi-sor-db
    fi-ingest
    fi-receiver

The production shutdown order is:

    fi-receiver
    fi-ingest
    fi-sor-db

The explicit jail dependency chain is:

    fi-sor-db
        -> fi-ingest
        -> fi-receiver

## Phase 0 - administrative prerequisites

Do not begin production mutation unless:

- administrative access through `vtnet0` is stable;
- the intended host identity is confirmed;
- the production configuration has been reviewed;
- a second administrative session or console path is available;
- the current Git commit is recorded;
- the worktree used for deployment is clean;
- the real-host baseline snapshot has been captured.

A host reboot is not part of the initial apply sequence.

Reboot persistence acceptance must not be attempted unless a working console
or equivalent out-of-band recovery path is available.

## Phase 1 - baseline

Capture the host state before any production mutation.

At minimum record:

- hostname and FreeBSD version;
- administrative interface state;
- dedicated receiver interface state;
- management bridge state;
- workload bridge state;
- IPv4 routing table;
- running jails;
- global jail rc policy;
- devfs rc policy;
- in-kernel devfs ruleset list;
- existing FI production destination files.

The baseline must show that no production FI jail is running before the first
controlled deployment acceptance unless an earlier accepted deployment is
being revalidated.

## Phase 2 - preflight and deterministic render

Run the production preflight and render the exact desired state before
mutation.

Reject the deployment before mutation if any required production resource is:

- a foreign collision;
- FI-owned but drifted where replacement is not explicitly allowed;
- unknown because inspection failed;
- located on the wrong host;
- inconsistent with the reviewed configuration.

The rendered plan must contain no unresolved FI tokens.

## Phase 3 - configuration apply

Apply the implemented layers in contract order:

    1. ZFS hierarchy
    2. jail roots
    3. jail-local identities
    4. jail-local filesystem directories
    5. in-kernel dedicated production devfs ruleset
    6. deterministic host files
    7. lifecycle files

Each layer must pass its own verification before the next layer is accepted.

Lifecycle-file installation itself must not:

- start a jail;
- stop a jail;
- reload a running service;
- move an interface;
- alter a route;
- alter a bridge;
- mutate the running devfs ruleset.

The in-kernel devfs apply operation is a separate earlier layer and must
already have passed its own acceptance.

## Phase 4 - post-configuration quiescent proof

Before production jail activation, capture host state again.

The comparison with the baseline must prove:

- administrative connectivity remains intact;
- `vtnet0` remains host-owned and unchanged by FI;
- `vtnet1` remains host-owned;
- `vtnet1` has not gained an FI address;
- `vtnet1` has not joined bridge10 or bridge20;
- no production FI jail was started by configuration installation;
- global jail-service policy remains site-owned;
- the three lifecycle files match reviewed desired state;
- the dedicated production devfs ruleset is exact.

## Phase 5 - controlled first start

Start FI through the dedicated FI lifecycle controller.

Do not start the three production jails independently for initial acceptance.

The controller must establish:

    fi-sor-db
    fi-ingest
    fi-receiver

in that order.

After startup prove:

- all three production jails exist;
- no unexpected FI jail exists;
- the System of Record has only its intended VNET interfaces;
- ingest has only its intended VNET interfaces;
- receiver has its management, workload, and dedicated external interfaces;
- receiver owns `vtnet1`;
- receiver external IPv4 is exactly 192.168.1.219/24;
- receiver default route is exactly through 192.168.1.1;
- ingest default route uses its management path;
- System-of-Record default route uses its management path;
- the host administrative interface remains healthy;
- the host administrative route remains healthy.

## Phase 6 - controlled first stop

Stop FI through the dedicated FI lifecycle controller.

The controller must stop:

    fi-receiver
    fi-ingest
    fi-sor-db

in that order.

After shutdown prove:

- none of the three production FI jails is running;
- FI-created epair attachments are gone;
- `vtnet1` has returned to the host;
- `vtnet1` carries no FI layer-3 address;
- `vtnet1` carries no FI route;
- `vtnet1` is not a member of bridge10;
- `vtnet1` is not a member of bridge20;
- `vtnet0` and 192.168.1.218/24 remain intact.

The return of `vtnet1` to a clean host state is a mandatory acceptance gate.

## Phase 7 - restart repeatability

Repeat one complete FI start and stop cycle.

The second cycle must require no repair or cleanup from the first cycle.

Accept only if:

- startup succeeds without stale epair/interface collisions;
- jail network state is identical to the first accepted start;
- shutdown succeeds without manual intervention;
- the dedicated physical interface again returns cleanly;
- no stale FI epair remains;
- administrative connectivity remains intact.

## Phase 8 - persistence acceptance

Persistent boot acceptance is separate from first live activation.

Before a reboot:

- all previous phases must be accepted;
- a working local console or equivalent out-of-band path must exist;
- the reboot must occur in an approved maintenance window.

After reboot prove:

- `/etc/devfs.rules.fi` is loaded through the persistent devfs policy;
- the FI production ruleset is exact;
- `fi_jails` participates in rc ordering as reviewed;
- the three FI production jails start in the intended dependency order;
- receiver obtains the dedicated external interface;
- all expected network state is correct;
- administrative access remains intact.

Then perform one controlled stop/start cycle after reboot and repeat the
dedicated-interface return proof.

## Phase 9 - acceptance result

Real-host acceptance is complete only when all mandatory checks pass.

Record:

- Git commit deployed;
- configuration file used;
- host identity;
- FreeBSD version;
- acceptance date;
- pre-apply snapshot;
- post-configuration snapshot;
- running snapshot;
- stopped snapshot;
- restart snapshot;
- reboot snapshot when persistence acceptance is performed.

A failed mandatory check leaves the real-host gate open.
