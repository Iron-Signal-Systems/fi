// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

// Code generated from the accepted FreeBSD PF policy template. DO NOT EDIT.

package backendinstall

// Source: tools/deployment/freebsd/pf.d/fi.pf.conf.template
// SHA256: 07b6955a10e3e2822b57d1b955e40da2a4210903b5661b19304e07a725e4994b
const pfPolicyAsset = `# FI-MANAGED: ironsignal-fi-freebsd-pf-v1
# FI-ROLE: host-packet-filter-policy

ext_if   = "@FI_HOST_ADMIN_IF@"
mgmt_net = "@FI_MGMT_NETWORK@"
work_net = "@FI_WORK_NETWORK@"

# NAT only the jail management network.
nat on $ext_if inet from $mgmt_net to any -> ($ext_if)

# Only ingest may initiate PostgreSQL traffic to the System of Record.
pass in quick inet proto tcp from @FI_INGEST_WORK_IP@ to @FI_SOR_DB_WORK_IP@ port 5432 keep state

# All other inbound PostgreSQL paths to the System of Record are denied.
block drop in quick inet proto tcp from any to @FI_SOR_DB_WORK_IP@ port 5432

# The FI workload network is not allowed to route off its own subnet.
block drop in quick inet from $work_net to ! $work_net

# Preserve current permissive behavior outside the FI isolation contract.
pass all
`
