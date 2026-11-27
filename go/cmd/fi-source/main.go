// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

// fi-source coordinates enrollment of an already-authorized file server into
// the receiver and ingest registries of an existing FreeBSD FI backend.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"syscall"

	"github.com/Iron-Signal-Systems/fi/go/internal/receivertrust"
	"github.com/Iron-Signal-Systems/fi/go/internal/transporttrust"
)

const (
	receiverDir = "/var/db/fi/config/receiver"
	ingestDir   = "/var/db/fi/config/ingest"
	lockPath    = "/var/run/fi-source.lock"
)

var sourceIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$`)

type sourceFile struct {
	name    string
	content []byte
	config  transporttrust.SourceConfig
}

type enrollmentPlan struct {
	source       sourceFile
	receiverPath string
	ingestPath   string
	receiverNew  bool
	ingestNew    bool
}

type backend struct {
	receiver string
	ingest   string
}

func installedBackend() backend { return backend{receiver: receiverDir, ingest: ingestDir} }

func main() {
	if runtime.GOOS != "freebsd" {
		fatal(errors.New("fi-source operates on a FreeBSD FI backend host only"))
	}
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	b := installedBackend()
	command := os.Args[1]
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	config := flags.String("config", "", "existing FI version 2.0 source .conf")
	source := flags.String("source", "", "canonical source ID")
	refresh := flags.String("refresh", "", "explicitly restart after recovery: receiver, ingest, or both (add only)")
	if err := flags.Parse(os.Args[2:]); err != nil {
		fatal(err)
	}
	if flags.NArg() != 0 {
		fatal(errors.New("unexpected arguments"))
	}

	switch command {
	case "plan", "add":
		if *source != "" || *config == "" || (command == "plan" && *refresh != "") {
			fatal(errors.New("-config is required; -source is not accepted here"))
		}
		// Plan and add both build the same side-effect-free verified plan.
		candidate, err := readSourceFile(*config)
		if err != nil {
			fatal(err)
		}
		plan, err := b.plan(candidate)
		if err != nil {
			fatal(err)
		}
		printPlan(plan)
		if command == "plan" {
			return
		}
		if os.Geteuid() != 0 {
			fatal(errors.New("fi-source add requires root on the backend host"))
		}
		release, err := acquireLock(lockPath)
		if err != nil {
			fatal(err)
		}
		defer release()
		// Recompute after acquiring the exclusive host enrollment lock.
		plan, err = b.plan(candidate)
		if err != nil {
			fatal(err)
		}
		if err := b.add(plan, *refresh); err != nil {
			fatal(err)
		}
	case "status":
		if *config != "" || *refresh != "" || !sourceIDPattern.MatchString(*source) {
			fatal(errors.New("status requires -source ID"))
		}
		if err := b.status(*source); err != nil {
			fatal(err)
		}
	case "list":
		if *config != "" || *source != "" || *refresh != "" {
			fatal(errors.New("list takes no flags"))
		}
		if err := b.list(); err != nil {
			fatal(err)
		}
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: fi-source plan -config FILE | add -config FILE [-refresh receiver|ingest|both] | status -source ID | list")
}

func fatal(err error) { fmt.Fprintln(os.Stderr, "FI SOURCE ERROR:", err); os.Exit(1) }

func readSourceFile(path string) (sourceFile, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return sourceFile{}, fmt.Errorf("FI source file must use a clean absolute path: %q", path)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return sourceFile{}, err
	}
	if !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > 1024*1024 {
		return sourceFile{}, fmt.Errorf("source configuration must be a nonempty regular file <=1 MiB: %s", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return sourceFile{}, err
	}
	config, err := transporttrust.ParseSourceConfig(bytes.NewReader(data))
	if err != nil {
		return sourceFile{}, fmt.Errorf("source config: %w", err)
	}
	id := config.Authorization.SourceID
	if !sourceIDPattern.MatchString(id) || id == "." || id == ".." {
		return sourceFile{}, fmt.Errorf("unsafe source ID %q", id)
	}
	if !config.Authorization.Enabled {
		return sourceFile{}, fmt.Errorf("source %s must be enabled for enrollment", id)
	}
	return sourceFile{name: id + ".conf", content: data, config: config}, nil
}

func checkSourceDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("source registry not an actual directory: %s", path)
	}
	if info.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("source registry is group/world writable: %s", path)
	}
	return nil
}

func sourceRegistry(root string) string { return filepath.Join(root, "sources") }

func readRegistry(root string) (map[string]sourceFile, error) {
	dir := sourceRegistry(root)
	if err := checkSourceDirectory(dir); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	found := make(map[string]sourceFile)
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".conf") {
			return nil, fmt.Errorf("unexpected registry object: %s", entry.Name())
		}
		file, err := readSourceFileAllowDisabled(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		if entry.Name() != file.name {
			return nil, fmt.Errorf("filename/source ID mismatch: %s", entry.Name())
		}
		folded := strings.ToLower(file.config.Authorization.SourceID)
		if _, exists := found[folded]; exists {
			return nil, fmt.Errorf("duplicate source ID: %s", file.name)
		}
		found[folded] = file
	}
	return found, nil
}

func readSourceFileAllowDisabled(path string) (sourceFile, error) {
	// Installed disabled entries must still be structurally valid.
	info, err := os.Lstat(path)
	if err != nil {
		return sourceFile{}, err
	}
	if !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > 1024*1024 {
		return sourceFile{}, fmt.Errorf("invalid registry file %s", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return sourceFile{}, err
	}
	config, err := transporttrust.ParseSourceConfig(bytes.NewReader(data))
	if err != nil {
		return sourceFile{}, fmt.Errorf("parse %s: %w", path, err)
	}
	id := config.Authorization.SourceID
	if !sourceIDPattern.MatchString(id) || id == "." || id == ".." {
		return sourceFile{}, fmt.Errorf("unsafe source ID in %s", path)
	}
	return sourceFile{name: id + ".conf", content: data, config: config}, nil
}

func (b backend) plan(candidate sourceFile) (enrollmentPlan, error) {
	// Verify BOTH existing registries, installed issuing CAs, and proposed
	// resulting inventories before writing even one byte.
	recv, err := readRegistry(b.receiver)
	if err != nil {
		return enrollmentPlan{}, err
	}
	ing, err := readRegistry(b.ingest)
	if err != nil {
		return enrollmentPlan{}, err
	}
	key := strings.ToLower(candidate.config.Authorization.SourceID)
	recvExisting, recvPresent := recv[key]
	ingestExisting, ingestPresent := ing[key]
	if recvPresent && !bytes.Equal(recvExisting.content, candidate.content) {
		return enrollmentPlan{}, fmt.Errorf("receiver has different source registration; refusing overwrite: %s", candidate.name)
	}
	if ingestPresent && !bytes.Equal(ingestExisting.content, candidate.content) {
		return enrollmentPlan{}, fmt.Errorf("ingest has different source registration; refusing overwrite: %s", candidate.name)
	}
	if !recvPresent {
		recv[key] = candidate
	}
	if !ingestPresent {
		ing[key] = candidate
	}
	if err := validateRegistryPins(recv, b.receiver, true); err != nil {
		return enrollmentPlan{}, fmt.Errorf("receiver registry: %w", err)
	}
	if err := validateRegistryPins(ing, b.ingest, false); err != nil {
		return enrollmentPlan{}, fmt.Errorf("ingest registry: %w", err)
	}
	return enrollmentPlan{source: candidate,
		receiverPath: filepath.Join(sourceRegistry(b.receiver), candidate.name),
		ingestPath:   filepath.Join(sourceRegistry(b.ingest), candidate.name),
		receiverNew:  !recvPresent, ingestNew: !ingestPresent,
	}, nil
}

func validateRegistryPins(files map[string]sourceFile, root string, requireTransport bool) error {
	batch, err := certificateFingerprint(filepath.Join(root, "pki/trust/fi-batch-signing-ca.crt.pem"))
	if err != nil {
		return err
	}
	transport := ""
	if requireTransport {
		transport, err = certificateFingerprint(filepath.Join(root, "pki/trust/fi-transport-ca.crt.pem"))
		if err != nil {
			return err
		}
	}
	batchIDs := make(map[string]string)
	transportIDs := make(map[string]string)
	for _, f := range files {
		a := f.config.Authorization
		if !strings.EqualFold(a.BatchSigning.IssuingCASHA256, batch) {
			return fmt.Errorf("batch issuer mismatch for %s", a.SourceID)
		}
		if requireTransport && !strings.EqualFold(a.Transport.IssuingCASHA256, transport) {
			return fmt.Errorf("transport issuer mismatch for %s", a.SourceID)
		}
		bfp := strings.ToLower(strings.ReplaceAll(a.BatchSigning.CertificateSHA256, ":", ""))
		tfp := strings.ToLower(strings.ReplaceAll(a.Transport.CertificateSHA256, ":", ""))
		if prev, found := batchIDs[bfp]; found {
			return fmt.Errorf("duplicate batch certificate: %s and %s", prev, a.SourceID)
		}
		if prev, found := transportIDs[tfp]; found {
			return fmt.Errorf("duplicate transport certificate: %s and %s", prev, a.SourceID)
		}
		batchIDs[bfp] = a.SourceID
		transportIDs[tfp] = a.SourceID
	}
	return nil
}

func certificateFingerprint(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("issuer is not regular file: %s", path)
	}
	cert, err := receivertrust.LoadCertificate(path)
	if err != nil {
		return "", err
	}
	if len(cert.Raw) == 0 {
		return "", fmt.Errorf("empty issuer DER: %s", path)
	}
	digest := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(digest[:]), nil
}

func printPlan(plan enrollmentPlan) {
	fmt.Printf("Source: %s\n", plan.source.config.Authorization.SourceID)
	fmt.Printf("Receiver: %s\n", action(plan.receiverNew))
	fmt.Printf("Ingest:   %s\n", action(plan.ingestNew))
	fmt.Printf("Receiver configuration: %s\n", plan.receiverPath)
	fmt.Printf("Ingest configuration:   %s\n", plan.ingestPath)
	fmt.Printf("SHA256: %x\n", sha256.Sum256(plan.source.content))
}

func action(needsAdd bool) string {
	if needsAdd {
		return "ADD (no overwrite)"
	}
	return "PRESERVE (exact match)"
}

// publishNoClobber never overwrites an existing source configuration, even if
// another administrator publishes one between the initial plan and apply.
func publishNoClobber(destination string, content []byte) error {
	parent := filepath.Dir(destination)
	if err := checkSourceDirectory(parent); err != nil {
		return err
	}
	f, err := os.CreateTemp(parent, ".fi-source-stage-*")
	if err != nil {
		return err
	}
	temp := f.Name()
	defer os.Remove(temp)
	defer f.Close()
	if _, err := f.Write(content); err != nil {
		return err
	}
	parentInfo, err := os.Lstat(parent)
	if err != nil {
		return err
	}
	owner, ok := parentInfo.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 {
		return fmt.Errorf("registry must be host-root owned: %s", parent)
	}
	if err := f.Chown(0, int(owner.Gid)); err != nil {
		return err
	}
	if err := f.Chmod(0640); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Link(temp, destination); err != nil {
		return fmt.Errorf("create source without overwrite: %w", err)
	}
	dir, err := os.Open(parent)
	if err != nil {
		return err
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return err
	}
	return nil
}

func verifyDestination(path string, contents []byte) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0640 {
		return fmt.Errorf("source file mode invalid: %s", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	parentInfo, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return err
	}
	parentStat, okParent := parentInfo.Sys().(*syscall.Stat_t)
	if !ok || !okParent || stat.Uid != 0 || stat.Gid != parentStat.Gid || stat.Nlink != 1 {
		return fmt.Errorf("source file identity invalid: %s", path)
	}
	disk, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(disk, contents) {
		return fmt.Errorf("source changed on disk: %s", path)
	}
	return nil
}

func runJail(jail string, args ...string) (string, error) {
	argv := append([]string{jail}, args...)
	cmd := exec.Command("/usr/sbin/jexec", argv...)
	raw, err := cmd.CombinedOutput()
	if err != nil {
		return string(raw), fmt.Errorf("jexec %s: %w: %s", jail, err, strings.TrimSpace(string(raw)))
	}
	return string(raw), nil
}

// activationTargets returns only services that require reloading for newly
// published registrations, plus services the operator explicitly requests.
// Empty refresh never restarts an already-registered source's services.
func activationTargets(p enrollmentPlan, refresh string) (bool, bool, error) {
	receiver, ingest := p.receiverNew, p.ingestNew
	switch refresh {
	case "":
	case "receiver":
		receiver = true
	case "ingest":
		ingest = true
	case "both":
		receiver, ingest = true, true
	default:
		return false, false, fmt.Errorf("invalid -refresh %q: use receiver, ingest, or both", refresh)
	}
	return receiver, ingest, nil
}

// activateService repairs a stopped service with onestart instead of assuming
// restart is valid. The preflight deliberately permits an unhealthy service
// only when that exact service is being explicitly refreshed.
type jailCommand func(string, ...string) (string, error)

func activateService(jail, service string) error {
	return activateServiceWith(runJail, jail, service)
}

func activateServiceWith(run jailCommand, jail, service string) error {
	_, statusErr := run(jail, "service", service, "onestatus")
	verb := "restart"
	if statusErr != nil {
		verb = "onestart"
	}
	if _, err := run(jail, "service", service, verb); err != nil {
		return fmt.Errorf("%s %s failed: %w", service, verb, err)
	}
	if _, err := run(jail, "service", service, "onestatus"); err != nil {
		return fmt.Errorf("%s not healthy after %s: %w", service, verb, err)
	}
	return nil
}

func (b backend) add(p enrollmentPlan, refresh string) error {
	restartReceiver, restartIngest, err := activationTargets(p, refresh)
	if err != nil {
		return err
	}
	if !p.receiverNew && !p.ingestNew && !restartReceiver && !restartIngest {
		fmt.Println("REGISTRATIONS MATCH: no files changed; no services restarted")
		fmt.Println("RUNTIME ACTIVATION UNVERIFIED: a previous failed restart may require 'add -config FILE -refresh ingest|receiver|both'")
		return nil
	}
	// Check services before making persistent changes or restarting anything.
	for _, item := range []struct {
		jail, service string
		refreshing    bool
	}{
		{"fi-receiver", "fi_receiver", restartReceiver},
		{"fi-ingest", "fi_ingest_worker", restartIngest},
	} {
		if item.refreshing {
			// A stopped service is allowed only if this operation is
			// explicitly tasked with restoring that service.
			continue
		}
		if _, err := runJail(item.jail, "service", item.service, "onestatus"); err != nil {
			return fmt.Errorf("preflight unaffected service health: %w", err)
		}
	}
	if p.receiverNew {
		if err := publishNoClobber(p.receiverPath, p.source.content); err != nil {
			return err
		}
		if err := verifyDestination(p.receiverPath, p.source.content); err != nil {
			return err
		}
	}
	if p.ingestNew {
		if err := publishNoClobber(p.ingestPath, p.source.content); err != nil {
			return fmt.Errorf("PARTIAL ENROLLMENT: receiver may be registered; ingest publish failed: %w; rerun add after correcting the cause", err)
		}
		if err := verifyDestination(p.ingestPath, p.source.content); err != nil {
			return fmt.Errorf("PARTIAL ENROLLMENT: verify ingest config: %w", err)
		}
	}
	// Confirm that the jail sees the exact host-published content (nullfs).
	for _, item := range []struct{ jail string }{{"fi-receiver"}, {"fi-ingest"}} {
		out, err := runJail(item.jail, "/sbin/sha256", "-q", "/usr/local/etc/fi/sources/"+p.source.name)
		if err != nil {
			return fmt.Errorf("PARTIAL ENROLLMENT: jail visibility: %w", err)
		}
		expected := fmt.Sprintf("%x", sha256.Sum256(p.source.content))
		if strings.TrimSpace(out) != expected {
			return fmt.Errorf("PARTIAL ENROLLMENT: %s sees different config", item.jail)
		}
	}
	// Receiver trust validation is read-only and performed before restarting.
	trust, err := runJail("fi-receiver", "/usr/local/sbin/fi-receiver", "trust", "status")
	if err != nil || !trustIsReady(trust) {
		return fmt.Errorf("PARTIAL ENROLLMENT: receiver trust failed (no services restarted): %v\n%s", err, trust)
	}
	if restartReceiver {
		if err := activateService("fi-receiver", "fi_receiver"); err != nil {
			return fmt.Errorf("PARTIAL ACTIVATION: receiver not healthy: %w; after correction rerun add with -refresh receiver", err)
		}
	}
	if restartIngest {
		if err := activateService("fi-ingest", "fi_ingest_worker"); err != nil {
			return fmt.Errorf("PARTIAL ACTIVATION: ingest not healthy: %w; after correction rerun add with -refresh ingest", err)
		}
	}
	fmt.Printf("REGISTRATIONS APPLIED/VERIFIED: %s; requested service refresh complete. PostgreSQL acceptance must still be verified.\n", p.source.config.Authorization.SourceID)
	return nil
}

func acquireLock(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("FI source enrollment already running: %w", err)
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }, nil
}

func (b backend) list() error {
	r, err := readRegistry(b.receiver)
	if err != nil {
		return err
	}
	i, err := readRegistry(b.ingest)
	if err != nil {
		return err
	}
	keys := make(map[string]bool)
	for k := range r {
		keys[k] = true
	}
	for k := range i {
		keys[k] = true
	}
	ids := make([]string, 0, len(keys))
	for k := range keys {
		ids = append(ids, k)
	}
	sort.Strings(ids)
	for _, k := range ids {
		name := ""
		state := "INCONSISTENT"
		a, inReceiver := r[k]
		c, inIngest := i[k]
		if inReceiver {
			name = a.config.Authorization.SourceID
		} else {
			name = c.config.Authorization.SourceID
		}
		if inReceiver && inIngest && bytes.Equal(a.content, c.content) {
			state = "REGISTERED"
		}
		if inReceiver && !inIngest {
			state = "INGEST MISSING"
		}
		if !inReceiver && inIngest {
			state = "RECEIVER MISSING"
		}
		fmt.Printf("%-45s %s\n", name, state)
	}
	return nil
}

func (b backend) status(source string) error {
	r, err := readRegistry(b.receiver)
	if err != nil {
		return err
	}
	i, err := readRegistry(b.ingest)
	if err != nil {
		return err
	}
	key := strings.ToLower(source)
	a, x := r[key]
	c, y := i[key]
	fmt.Printf("Source: %s\n", source)
	fmt.Printf("Receiver registered: %t\n", x)
	fmt.Printf("Ingest registered:   %t\n", y)
	if x && y {
		fmt.Printf("Configs identical:   %t\n", bytes.Equal(a.content, c.content))
	}
	if !x || !y || !bytes.Equal(a.content, c.content) {
		return errors.New("source enrollment incomplete or mismatched")
	}
	return nil
}

func trustIsReady(output string) bool {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "Trust" && fields[1] == "state" && fields[2] == "READY" {
			return true
		}
	}
	return false
}
