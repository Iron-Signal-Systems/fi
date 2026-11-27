// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Iron-Signal-Systems/fi/go/internal/freebsd/backendinstall"
)

type invocation struct {
	applicationBinaryRelease string
	approvedPriorBinaries    string
	approvedPriorHostFiles   string
	approvedPriorRuntime     string
	command                  string
	configPath               string
}

// -----------------------------------------------------------------------------
// Command line
// -----------------------------------------------------------------------------

func configPath(
	args []string,
	input io.Reader,
	output io.Writer,
) (string, error) {
	switch len(args) {
	case 0:
		fmt.Fprint(
			output,
			"Configuration file: ",
		)

		reader := bufio.NewReader(input)

		value, err := reader.ReadString('\n')
		if err != nil && len(value) == 0 {
			return "", fmt.Errorf(
				"read configuration path: %w",
				err,
			)
		}

		value = strings.TrimSpace(value)
		if value == "" {
			return "", fmt.Errorf(
				"configuration path cannot be empty",
			)
		}

		return value, nil

	case 1:
		value := strings.TrimSpace(args[0])
		if value == "" {
			return "", fmt.Errorf(
				"configuration path cannot be empty",
			)
		}

		return value, nil

	default:
		return "", fmt.Errorf(
			"expected zero or one configuration-file argument",
		)
	}
}

func parseInvocation(
	args []string,
	input io.Reader,
	output io.Writer,
) (invocation, error) {
	if len(args) == 0 {
		path, err := configPath(
			nil,
			input,
			output,
		)

		return invocation{
			command:    "validate",
			configPath: path,
		}, err
	}

	switch args[0] {
	case "update-binaries":
		if len(args) != 4 {
			return invocation{}, fmt.Errorf(
				"usage: fi-backend-install update-binaries <configuration-file> <release-directory> <approved-prior-binaries-directory>",
			)
		}
		return invocation{
			command:                  args[0],
			configPath:               args[1],
			applicationBinaryRelease: args[2],
			approvedPriorBinaries:    args[3],
		}, nil

	case "apply-binaries", "verify-binaries", "apply-c1-binaries", "verify-c1-binaries":
		if len(args) != 3 {
			return invocation{}, fmt.Errorf(
				"usage: fi-backend-install %s <configuration-file> <release-directory>",
				args[0],
			)
		}

		return invocation{
			applicationBinaryRelease: args[2],
			command:                  args[0],
			configPath:               args[1],
		}, nil

	case "adopt-runtime", "update-runtime":
		if len(args) != 3 {
			return invocation{}, fmt.Errorf(
				"usage: fi-backend-install %s <configuration-file> <approved-prior-runtime-directory>",
				args[0],
			)
		}

		return invocation{
			approvedPriorRuntime: args[2],
			command:              args[0],
			configPath:           args[1],
		}, nil

	case "update-host-files":
		if len(args) != 3 {
			return invocation{}, fmt.Errorf(
				"usage: fi-backend-install update-host-files <configuration-file> <approved-prior-host-files-directory>",
			)
		}

		return invocation{
			approvedPriorHostFiles: args[2],
			command:                args[0],
			configPath:             args[1],
		}, nil

	case "apply-devfs", "apply-directories", "apply-host-files", "apply-identities", "apply-jail-roots", "apply-jail-substrate", "apply-sor-package", "apply-sor-postgresql", "initialize-sor-postgresql", "initialize-sor-database", "upgrade-sor-database", "upgrade-legacy-sor-database", "upgrade-m61-usn", "apply-zfs-hierarchy", "apply-zfs-root", "check-host-update", "inspect-host-update", "preflight", "validate", "verify-devfs", "verify-host-files", "verify-sor-postgresql", "verify-sor-database", "apply-network", "verify-network", "apply-pf", "verify-pf", "apply-c1-sor-identity", "verify-c1-sor-identity", "apply-c1-runtime", "verify-c1-runtime", "apply-lifecycle", "verify-lifecycle", "apply-runtime", "verify-runtime", "plan-c1-ram-mounts", "audit-c1-ram-mounts", "apply-c1-ram-fstab", "apply-c1-ram-host-runtime", "verify-c1-ram-host-runtime":
		path, err := configPath(
			args[1:],
			input,
			output,
		)

		return invocation{
			command:    args[0],
			configPath: path,
		}, err

	default:
		if len(args) != 1 {
			return invocation{}, fmt.Errorf(
				"usage: fi-backend-install [validate|preflight|apply-zfs-root|apply-zfs-hierarchy|apply-jail-substrate|apply-jail-roots|apply-identities|apply-directories|apply-sor-package|apply-sor-postgresql|initialize-sor-postgresql|initialize-sor-database|upgrade-sor-database|upgrade-legacy-sor-database|verify-sor-postgresql|verify-sor-database|apply-devfs|verify-devfs|apply-host-files|update-host-files|verify-host-files|check-host-update|inspect-host-update|apply-network|verify-network|apply-pf|verify-pf|apply-lifecycle|verify-lifecycle|apply-binaries|verify-binaries|update-binaries|apply-runtime|verify-runtime|adopt-runtime|update-runtime] [configuration-file]",
			)
		}

		return invocation{
			command:    "validate",
			configPath: args[0],
		}, nil
	}
}

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------

func main() {
	fmt.Fprintln(
		os.Stdout,
		"FI Backend Installer",
	)
	fmt.Fprintln(os.Stdout)

	request, err := parseInvocation(
		os.Args[1:],
		os.Stdin,
		os.Stdout,
	)
	if err != nil {
		fmt.Fprintf(
			os.Stderr,
			"FI INSTALLER INPUT BLOCKED: %v\n",
			err,
		)
		os.Exit(1)
	}

	config, err := backendinstall.LoadConfig(
		request.configPath,
	)
	if err != nil {
		fmt.Fprintf(
			os.Stderr,
			"FI CONFIGURATION BLOCKED: %v\n",
			err,
		)
		os.Exit(1)
	}

	switch request.command {
	case "apply-zfs-root":
		_, err := backendinstall.DiscoverHost(
			config,
		)
		if err != nil {
			fmt.Fprintf(
				os.Stderr,
				"FI HOST PREFLIGHT BLOCKED: %v\n",
				err,
			)
			os.Exit(1)
		}

		if err := backendinstall.ApplyFIRoot(
			config,
		); err != nil {
			fmt.Fprintf(
				os.Stderr,
				"FI ZFS ROOT APPLY BLOCKED: %v\n",
				err,
			)
			os.Exit(1)
		}

		fmt.Fprintln(
			os.Stdout,
			"FI ZFS root apply complete.",
		)

	case "apply-zfs-hierarchy":
		_, err := backendinstall.DiscoverHost(
			config,
		)
		if err != nil {
			fmt.Fprintf(
				os.Stderr,
				"FI HOST PREFLIGHT BLOCKED: %v\n",
				err,
			)
			os.Exit(1)
		}

		if err := backendinstall.ApplyFIHierarchy(
			config,
		); err != nil {
			fmt.Fprintf(
				os.Stderr,
				"FI ZFS HIERARCHY APPLY BLOCKED: %v\n",
				err,
			)
			os.Exit(1)
		}

		fmt.Fprintln(
			os.Stdout,
			"FI ZFS hierarchy apply complete.",
		)

	case "apply-jail-substrate":
		if err := backendinstall.ApplyJailSubstrate(
			config,
		); err != nil {
			fmt.Fprintf(
				os.Stderr,
				"FI JAIL SUBSTRATE APPLY BLOCKED: %v\n",
				err,
			)
			os.Exit(1)
		}

		fmt.Fprintln(
			os.Stdout,
			"FI jail substrate apply complete.",
		)

	case "inspect-host-update":
		report, err := backendinstall.InspectHostUpdate(
			config,
		)
		if err != nil {
			fmt.Fprintf(
				os.Stderr,
				"FI HOST UPDATE INSPECTION BLOCKED: %v\n",
				err,
			)
			os.Exit(1)
		}

		if err := report.WriteText(
			os.Stdout,
		); err != nil {
			fmt.Fprintf(
				os.Stderr,
				"FI HOST UPDATE REPORT FAILED: %v\n",
				err,
			)
			os.Exit(1)
		}

	case "check-host-update":
		report, err := backendinstall.CheckHostUpdate(
			config,
		)
		if err != nil {
			fmt.Fprintf(
				os.Stderr,
				"FI HOST UPDATE CHECK BLOCKED: %v\n",
				err,
			)
			os.Exit(1)
		}

		if err := report.WriteText(
			os.Stdout,
		); err != nil {
			fmt.Fprintf(
				os.Stderr,
				"FI HOST UPDATE REPORT FAILED: %v\n",
				err,
			)
			os.Exit(1)
		}

		if !report.Current {
			os.Exit(2)
		}

	case "apply-sor-postgresql":
		if err := backendinstall.ApplySORPostgreSQL(
			config,
		); err != nil {
			fmt.Fprintf(
				os.Stderr,
				"FI SOR POSTGRESQL POLICY APPLY BLOCKED: %v\n",
				err,
			)
			os.Exit(1)
		}

		fmt.Fprintln(
			os.Stdout,
			"FI System-of-Record PostgreSQL policy apply complete.",
		)

	case "initialize-sor-postgresql":
		if err := backendinstall.InitializeSORPostgreSQL(
			config,
		); err != nil {
			fmt.Fprintf(
				os.Stderr,
				"FI SOR POSTGRESQL INITIALIZATION BLOCKED: %v\n",
				err,
			)
			os.Exit(1)
		}

		fmt.Fprintln(
			os.Stdout,
			"FI System-of-Record PostgreSQL initialization complete.",
		)

	case "initialize-sor-database":
		if err := backendinstall.InitializeSORPostgreSQLDatabase(
			config,
		); err != nil {
			fmt.Fprintf(
				os.Stderr,
				"FI SOR DATABASE INITIALIZATION BLOCKED: %v\n",
				err,
			)
			os.Exit(1)
		}

		fmt.Fprintln(
			os.Stdout,
			"FI System-of-Record PostgreSQL database initialization complete.",
		)

	case "upgrade-sor-database":
		if err := backendinstall.UpgradeSORPostgreSQLDatabase(config); err != nil {
			fmt.Fprintf(os.Stderr, "FI SOR DATABASE UPGRADE BLOCKED: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stdout, "FI System-of-Record PostgreSQL database upgrade complete.")

	case "upgrade-m61-usn":
		if err := backendinstall.UpgradeM61USNCaptureBinding(config); err != nil {
			fmt.Fprintf(os.Stderr, "FI M6.1 SOR UPGRADE BLOCKED: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stdout, "FI M6.1 SOR USN binding upgrade complete.")

	case "upgrade-legacy-sor-database":
		if err := backendinstall.UpgradeLegacySORPostgreSQLDatabase(config); err != nil {
			fmt.Fprintf(os.Stderr, "FI LEGACY SOR DATABASE UPGRADE BLOCKED: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stdout, "FI legacy System-of-Record index upgrade complete.")

	case "verify-sor-postgresql":
		if err := backendinstall.VerifySORPostgreSQL(
			config,
		); err != nil {
			fmt.Fprintf(
				os.Stderr,
				"FI SOR POSTGRESQL POLICY VERIFY BLOCKED: %v\n",
				err,
			)
			os.Exit(1)
		}

		fmt.Fprintln(
			os.Stdout,
			"FI System-of-Record PostgreSQL policy verification complete.",
		)

	case "verify-sor-database":
		if err := backendinstall.VerifySORPostgreSQLDatabase(
			config,
		); err != nil {
			fmt.Fprintf(
				os.Stderr,
				"FI SOR DATABASE VERIFY BLOCKED: %v\n",
				err,
			)
			os.Exit(1)
		}

		fmt.Fprintln(
			os.Stdout,
			"FI System-of-Record PostgreSQL database verification complete.",
		)

	case "apply-pf":
		if err := backendinstall.ApplyPFPolicy(
			config,
		); err != nil {
			fmt.Fprintf(
				os.Stderr,
				"FI PF APPLY BLOCKED: %v\n",
				err,
			)
			os.Exit(1)
		}

		fmt.Fprintln(
			os.Stdout,
			"FI persistent PF policy apply complete.",
		)

	case "verify-pf":
		if err := backendinstall.VerifyPFPolicy(
			config,
		); err != nil {
			fmt.Fprintf(
				os.Stderr,
				"FI PF VERIFY BLOCKED: %v\n",
				err,
			)
			os.Exit(1)
		}

		fmt.Fprintln(
			os.Stdout,
			"FI persistent PF policy verification complete.",
		)

	case "apply-lifecycle":
		if err := backendinstall.ApplyLifecycle(
			config,
		); err != nil {
			fmt.Fprintf(
				os.Stderr,
				"FI LIFECYCLE APPLY BLOCKED: %v\n",
				err,
			)
			os.Exit(1)
		}

		fmt.Fprintln(
			os.Stdout,
			"FI FreeBSD lifecycle apply complete.",
		)

	case "verify-lifecycle":
		if err := backendinstall.VerifyLifecycle(
			config,
		); err != nil {
			fmt.Fprintf(
				os.Stderr,
				"FI LIFECYCLE VERIFY BLOCKED: %v\n",
				err,
			)
			os.Exit(1)
		}

		fmt.Fprintln(
			os.Stdout,
			"FI FreeBSD lifecycle verification complete.",
		)

	case "apply-c1-ram-host-runtime":
        if err:=backendinstall.ApplyC1RAMHostRuntime(config);err!=nil{
            fmt.Fprintf(os.Stderr,"FI C1 RAM HOST RUNTIME APPLY BLOCKED: %v\n",err)
            os.Exit(1)
        }
        fmt.Fprintln(os.Stdout,"FI C1 RAM host startup service installed OFF; no mount or jail started.")

    case "verify-c1-ram-host-runtime":
        if err:=backendinstall.VerifyC1RAMHostRuntime(config);err!=nil{
            fmt.Fprintf(os.Stderr,"FI C1 RAM HOST RUNTIME VERIFY BLOCKED: %v\n",err)
            os.Exit(1)
        }
        fmt.Fprintln(os.Stdout,"FI C1 RAM host startup service verified OFF.")

    case "apply-c1-ram-fstab":
        if err:=backendinstall.ApplyC1RAMFSTABPlan(config);err!=nil{
            fmt.Fprintf(os.Stderr,"FI C1 RAM FSTAB APPLY BLOCKED: %v\n",err)
            os.Exit(1)
        }
        fmt.Fprintln(os.Stdout,"FI C1 RAM fstab entries installed and verified; host tmpfs and C1 jail services remain OFF.")

    case "audit-c1-ram-mounts":
        // READ ONLY: require exact existing host/jail fstab entries and
        // distinguish a missing mount from a foreign/writable collision.
        plan,err:=backendinstall.RenderC1RAMMountPlan(config)
        if err!=nil{
            fmt.Fprintf(os.Stderr,"FI C1 RAM FSTAB AUDIT BLOCKED: %v\n",err)
            os.Exit(1)
        }
        state,err:=backendinstall.InspectC1RAMFSTABPlan(plan)
        if err!=nil{
            fmt.Fprintf(os.Stderr,"FI C1 RAM FSTAB AUDIT BLOCKED: %v\n",err)
            os.Exit(1)
        }
        fmt.Fprintf(os.Stdout,"FI C1 RAM FSTAB host=%s ingest=%s sor=%s\n",state.Host,state.Ingest,state.SoR)
        if state.Host!=backendinstall.C1FSTABExact||
            state.Ingest!=backendinstall.C1FSTABExact||
            state.SoR!=backendinstall.C1FSTABExact{
            fmt.Fprintln(os.Stderr,"FI C1 RAM FSTAB AUDIT INCOMPLETE: one or more exact mount entries missing; no host changes")
            os.Exit(2)
        }
        fmt.Fprintln(os.Stdout,"FI C1 RAM FSTAB AUDIT PASS (entries only; live mounts still require host preflight)")

    case "plan-c1-ram-mounts":
        // READ ONLY: the host must verify actual jail roots and install
        // exact entries separately. This command cannot mount tmpfs,
        // mutate fstab, enable services, or contact PostgreSQL.
        plan,err:=backendinstall.RenderC1RAMMountPlan(config)
        if err!=nil{
            fmt.Fprintf(os.Stderr,"FI C1 RAM MOUNT PLAN BLOCKED: %v\n",err)
            os.Exit(1)
        }
        fmt.Fprintln(os.Stdout,"FI C1 HOST tmpfs (append only after separate mount review):")
        fmt.Fprintln(os.Stdout,plan.HostFSTABEntry)
        fmt.Fprintln(os.Stdout,"FI C1 fi-ingest fstab:",plan.IngestFSTAB)
        fmt.Fprintln(os.Stdout,plan.IngestEntry)
        fmt.Fprintln(os.Stdout,"FI C1 fi-sor read-only fstab:",plan.SoRFSTAB)
        fmt.Fprintln(os.Stdout,plan.SoREntry)
        fmt.Fprintln(os.Stdout,"NO HOST MUTATIONS; NO C1 SERVICE ACTIVATION")

    case "apply-c1-binaries":
        if err := backendinstall.ApplyC1DevelopmentBinaries(config,request.applicationBinaryRelease);err!=nil{
            fmt.Fprintf(os.Stderr,"FI C1 DEVELOPMENT BINARIES APPLY BLOCKED: %v\n",err)
            os.Exit(1)
        }
        fmt.Fprintln(os.Stdout,"FI C1 development workers installed (NOT activated).")

    case "verify-c1-binaries":
        if err := backendinstall.VerifyC1DevelopmentBinaries(config,request.applicationBinaryRelease);err!=nil{
            fmt.Fprintf(os.Stderr,"FI C1 DEVELOPMENT BINARIES VERIFY BLOCKED: %v\n",err)
            os.Exit(1)
        }
        fmt.Fprintln(os.Stdout,"FI C1 development worker binary verification complete.")

    
    case "apply-c1-runtime":
        if err:=backendinstall.ApplyC1DevelopmentRuntime(config);err!=nil{
            fmt.Fprintf(os.Stderr,"FI C1 RUNTIME APPLY BLOCKED: %v\n",err)
            os.Exit(1)
        }
        fmt.Fprintln(os.Stdout,"FI C1 jail rc scripts staged; both services disabled.")

    case "verify-c1-runtime":
        if err:=backendinstall.VerifyC1DevelopmentRuntime(config);err!=nil{
            fmt.Fprintf(os.Stderr,"FI C1 RUNTIME VERIFY BLOCKED: %v\n",err)
            os.Exit(1)
        }
        fmt.Fprintln(os.Stdout,"FI C1 jail service runtime verification complete.")

    case "apply-c1-sor-identity":
        if err:=backendinstall.ApplyC1SoRIdentity(config);err!=nil{
            fmt.Fprintf(os.Stderr,"FI C1 SOR IDENTITY APPLY BLOCKED: %v\n",err)
            os.Exit(1)
        }
        fmt.Fprintln(os.Stdout,"FI C1 fi-sor identity created/verified; service remains disabled.")

    case "verify-c1-sor-identity":
        if err:=backendinstall.VerifyC1SoRIdentity(config);err!=nil{
            fmt.Fprintf(os.Stderr,"FI C1 SOR IDENTITY VERIFY BLOCKED: %v\n",err)
            os.Exit(1)
        }
        fmt.Fprintln(os.Stdout,"FI C1 fi-sor service identity verified.")

case "apply-binaries":
		if err := backendinstall.ApplyBinaries(
			config,
			request.applicationBinaryRelease,
		); err != nil {
			fmt.Fprintf(
				os.Stderr,
				"FI APPLICATION BINARY APPLY BLOCKED: %v\n",
				err,
			)
			os.Exit(1)
		}

		fmt.Fprintln(
			os.Stdout,
			"FI FreeBSD application binary apply complete.",
		)

	case "update-binaries":
		if err := backendinstall.UpdateBinaries(
			config,
			request.applicationBinaryRelease,
			request.approvedPriorBinaries,
		); err != nil {
			fmt.Fprintf(os.Stderr, "FI APPLICATION BINARY UPDATE BLOCKED: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stdout, "FI FreeBSD application binary update complete.")

	case "verify-binaries":
		if err := backendinstall.VerifyBinaries(
			config,
			request.applicationBinaryRelease,
		); err != nil {
			fmt.Fprintf(
				os.Stderr,
				"FI APPLICATION BINARY VERIFY BLOCKED: %v\n",
				err,
			)
			os.Exit(1)
		}

		fmt.Fprintln(
			os.Stdout,
			"FI FreeBSD application binary verification complete.",
		)

	case "adopt-runtime":
		if err := backendinstall.AdoptRuntime(
			config,
			request.approvedPriorRuntime,
		); err != nil {
			fmt.Fprintf(
				os.Stderr,
				"FI RUNTIME ADOPTION BLOCKED: %v\n",
				err,
			)
			os.Exit(1)
		}

		fmt.Fprintln(
			os.Stdout,
			"FI FreeBSD application runtime adoption complete.",
		)

	case "update-runtime":
		if err := backendinstall.UpdateRuntime(
			config,
			request.approvedPriorRuntime,
		); err != nil {
			fmt.Fprintf(
				os.Stderr,
				"FI RUNTIME UPDATE BLOCKED: %v\n",
				err,
			)
			os.Exit(1)
		}

		fmt.Fprintln(
			os.Stdout,
			"FI FreeBSD application runtime update complete.",
		)

	case "apply-runtime":
		if err := backendinstall.ApplyRuntime(
			config,
		); err != nil {
			fmt.Fprintf(
				os.Stderr,
				"FI RUNTIME APPLY BLOCKED: %v\n",
				err,
			)
			os.Exit(1)
		}

		fmt.Fprintln(
			os.Stdout,
			"FI FreeBSD application runtime apply complete.",
		)

	case "verify-runtime":
		if err := backendinstall.VerifyRuntime(
			config,
		); err != nil {
			fmt.Fprintf(
				os.Stderr,
				"FI RUNTIME VERIFY BLOCKED: %v\n",
				err,
			)
			os.Exit(1)
		}

		fmt.Fprintln(
			os.Stdout,
			"FI FreeBSD application runtime verification complete.",
		)

	case "apply-host-files":
		if err := backendinstall.ApplyHostFiles(
			config,
		); err != nil {
			fmt.Fprintf(
				os.Stderr,
				"FI HOST-FILE APPLY BLOCKED: %v\n",
				err,
			)
			os.Exit(1)
		}

		fmt.Fprintln(
			os.Stdout,
			"FI FreeBSD host-file apply complete.",
		)

	case "update-host-files":
		if err := backendinstall.UpdateHostFiles(
			config,
			request.approvedPriorHostFiles,
		); err != nil {
			fmt.Fprintf(
				os.Stderr,
				"FI HOST-FILE UPDATE BLOCKED: %v\n",
				err,
			)
			os.Exit(1)
		}

		fmt.Fprintln(
			os.Stdout,
			"FI FreeBSD host-file update complete.",
		)

	case "verify-host-files":
		if err := backendinstall.VerifyHostFiles(
			config,
		); err != nil {
			fmt.Fprintf(
				os.Stderr,
				"FI HOST-FILE VERIFY BLOCKED: %v\n",
				err,
			)
			os.Exit(1)
		}

		fmt.Fprintln(
			os.Stdout,
			"FI FreeBSD host-file verification complete.",
		)

	case "apply-devfs":
		if err := backendinstall.ApplyDevfs(
			config,
		); err != nil {
			fmt.Fprintf(
				os.Stderr,
				"FI DEVFS APPLY BLOCKED: %v\n",
				err,
			)
			os.Exit(1)
		}

		fmt.Fprintln(
			os.Stdout,
			"FI production devfs ruleset apply complete.",
		)

	case "verify-devfs":
		if err := backendinstall.VerifyDevfs(
			config,
		); err != nil {
			fmt.Fprintf(
				os.Stderr,
				"FI DEVFS VERIFY BLOCKED: %v\n",
				err,
			)
			os.Exit(1)
		}

		fmt.Fprintln(
			os.Stdout,
			"FI production devfs ruleset verification complete.",
		)

	case "apply-sor-package":
		if err := backendinstall.ApplySORPackage(
			config,
		); err != nil {
			fmt.Fprintf(
				os.Stderr,
				"FI SOR PACKAGE APPLY BLOCKED: %v\n",
				err,
			)
			os.Exit(1)
		}

		fmt.Fprintln(
			os.Stdout,
			"FI SOR PostgreSQL package apply complete.",
		)

	case "apply-directories":
		if err := backendinstall.ApplyDirectories(
			config,
		); err != nil {
			fmt.Fprintf(
				os.Stderr,
				"FI DIRECTORY APPLY BLOCKED: %v\n",
				err,
			)
			os.Exit(1)
		}

		fmt.Fprintln(
			os.Stdout,
			"FI filesystem directory apply complete.",
		)

	case "apply-identities":
		if err := backendinstall.ApplyIdentities(
			config,
		); err != nil {
			fmt.Fprintf(
				os.Stderr,
				"FI IDENTITY APPLY BLOCKED: %v\n",
				err,
			)
			os.Exit(1)
		}

		fmt.Fprintln(
			os.Stdout,
			"FI jail-local identity apply complete.",
		)

	case "apply-jail-roots":
		if err := backendinstall.ApplyJailRoots(
			config,
		); err != nil {
			fmt.Fprintf(
				os.Stderr,
				"FI JAIL ROOT APPLY BLOCKED: %v\n",
				err,
			)
			os.Exit(1)
		}

		fmt.Fprintln(
			os.Stdout,
			"FI production jail-root apply complete.",
		)

	case "preflight":
		report, err := backendinstall.DiscoverHost(
			config,
		)
		if err != nil {
			fmt.Fprintf(
				os.Stderr,
				"FI HOST PREFLIGHT BLOCKED: %v\n",
				err,
			)
			os.Exit(1)
		}

		if err := report.WriteText(
			os.Stdout,
		); err != nil {
			fmt.Fprintf(
				os.Stderr,
				"FI HOST PREFLIGHT OUTPUT FAILED: %v\n",
				err,
			)
			os.Exit(2)
		}

	case "apply-network":
		if err := backendinstall.ApplyHostNetwork(
			config,
		); err != nil {
			fmt.Fprintf(
				os.Stderr,
				"FI HOST NETWORK APPLY BLOCKED: %v\n",
				err,
			)
			os.Exit(1)
		}

		fmt.Fprintln(
			os.Stdout,
			"FI host network foundation apply complete.",
		)

	case "verify-network":
		if err := backendinstall.VerifyHostNetwork(
			config,
		); err != nil {
			fmt.Fprintf(
				os.Stderr,
				"FI HOST NETWORK VERIFY BLOCKED: %v\n",
				err,
			)
			os.Exit(1)
		}

		fmt.Fprintln(
			os.Stdout,
			"FI host network foundation verification complete.",
		)

	case "validate":
		printConfigSummary(
			os.Stdout,
			config,
		)

	default:
		fmt.Fprintf(
			os.Stderr,
			"FI INSTALLER INTERNAL ERROR: unsupported command: %s\n",
			request.command,
		)
		os.Exit(2)
	}
}

// -----------------------------------------------------------------------------
// Configuration output
// -----------------------------------------------------------------------------

func printConfigSummary(
	output io.Writer,
	config backendinstall.Config,
) {
	fmt.Fprintln(output)
	fmt.Fprintln(
		output,
		"Configuration accepted:",
	)

	fmt.Fprintf(
		output,
		"    host:               %s\n",
		config.Value("FI_HOSTNAME"),
	)

	fmt.Fprintf(
		output,
		"    host admin:         %s %s\n",
		config.Value("FI_HOST_ADMIN_IF"),
		config.Value("FI_HOST_ADMIN_ADDRESS"),
	)

	fmt.Fprintf(
		output,
		"    host gateway:       %s\n",
		config.Value("FI_HOST_ADMIN_GATEWAY"),
	)

	fmt.Fprintf(
		output,
		"    receiver external:  %s %s\n",
		config.Value("FI_RECEIVER_EXTERNAL_IF"),
		config.Value("FI_RECEIVER_EXTERNAL_ADDRESS"),
	)

	fmt.Fprintf(
		output,
		"    receiver gateway:   %s\n",
		config.Value("FI_RECEIVER_EXTERNAL_GATEWAY"),
	)

	fmt.Fprintln(output)
	fmt.Fprintln(
		output,
		"PREVALIDATION ONLY: no host state has been modified.",
	)
}
