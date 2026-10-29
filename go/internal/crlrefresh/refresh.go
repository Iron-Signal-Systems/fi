// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

// Package crlrefresh retrieves Microsoft AD CS base CRLs and publishes only
// verified, non-rollback replacements for the FI FreeBSD trust store.
// The caller owns scheduling and activation of refreshed trust in live services.
package crlrefresh

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	MaximumBytes = 4 << 20
	FetchTimeout = 15 * time.Second
)

var deltaCRLOID = asn1.ObjectIdentifier{2, 5, 29, 27}

// Target pins the retrieval URL to an already-installed, independently trusted
// issuing CA. URL selection is operator-controlled, never redirected or guessed.
type Target struct {
	Name          string
	URL           string
	IssuerPath    string
	InstalledPath string
}

// Result describes an accepted CRL. Changed means an on-disk publication was made.
type Result struct {
	Name       string
	Number     string
	NextUpdate time.Time
	Changed    bool
}

type candidate struct {
	target  Target
	newPEM  []byte
	parsed  *x509.RevocationList
	prior   []byte
	info    os.FileInfo
	changed bool
	staged  string
}

// Refresh fetches and verifies ALL sources before publishing ANY replacement.
// Individual renames are atomic; a crash between files can leave different,
// independently valid generations, never an unverified CRL. It does not reload
// CRLs already held in memory by the receiver or ingest worker.
func Refresh(ctx context.Context, targets []Target, at time.Time) ([]Result, error) {
	if ctx == nil || at.IsZero() || len(targets) == 0 {
		return nil, errors.New("context, current time, and CRL targets are required")
	}
	seen := make(map[string]bool, len(targets))
	pending := make([]candidate, 0, len(targets))
	defer func() {
		for _, c := range pending {
			if c.staged != "" {
				_ = os.Remove(c.staged)
			}
		}
	}()

	// A bad second CRL must not cause publication of a good first CRL.
	for _, target := range targets {
		if target.Name == "" || target.URL == "" || target.IssuerPath == "" || target.InstalledPath == "" {
			return nil, errors.New("CRL target name, URL, issuer and installed path are required")
		}
		if seen[target.InstalledPath] {
			return nil, fmt.Errorf("duplicate CRL target %q", target.InstalledPath)
		}
		seen[target.InstalledPath] = true
		c, err := prepare(ctx, target, at)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", target.Name, err)
		}
		pending = append(pending, c)
	}
	// Stage every changed file before updating a single trust path.
	for i := range pending {
		if !pending[i].changed {
			continue
		}
		staged, err := stage(&pending[i])
		if err != nil {
			return nil, fmt.Errorf("%s: stage: %w", pending[i].target.Name, err)
		}
		pending[i].staged = staged
	}
	results := make([]Result, 0, len(pending))
	for i := range pending {
		c := &pending[i]
		if c.changed {
			if err := unchanged(c); err != nil {
				return results, fmt.Errorf("%s: prior changed: %w", c.target.Name, err)
			}
			if err := os.Rename(c.staged, c.target.InstalledPath); err != nil {
				return results, fmt.Errorf("%s: publish: %w", c.target.Name, err)
			}
			c.staged = ""
			if err := syncDirectory(filepath.Dir(c.target.InstalledPath)); err != nil {
				return results, fmt.Errorf("%s: sync published directory: %w", c.target.Name, err)
			}
		}
		results = append(results, Result{
			Name: c.target.Name, Number: c.parsed.Number.String(),
			NextUpdate: c.parsed.NextUpdate, Changed: c.changed,
		})
	}
	return results, nil
}

func prepare(ctx context.Context, t Target, at time.Time) (candidate, error) {
	if err := securePath(t.InstalledPath); err != nil {
		return candidate{}, err
	}
	if err := securePath(t.IssuerPath); err != nil {
		return candidate{}, err
	}
	issuerBytes, err := os.ReadFile(t.IssuerPath)
	if err != nil {
		return candidate{}, fmt.Errorf("read issuer: %w", err)
	}
	issuerBlock, extra := pem.Decode(issuerBytes)
	if issuerBlock == nil || issuerBlock.Type != "CERTIFICATE" || len(extra) != 0 {
		return candidate{}, errors.New("issuer must contain one PEM certificate")
	}
	issuer, err := x509.ParseCertificate(issuerBlock.Bytes)
	if err != nil {
		return candidate{}, fmt.Errorf("parse issuer: %w", err)
	}
	raw, err := retrieve(ctx, t.URL)
	if err != nil {
		return candidate{}, err
	}
	fresh, err := parseCRL(raw)
	if err != nil {
		return candidate{}, fmt.Errorf("parse retrieved CRL: %w", err)
	}
	if err := verify(fresh, issuer, at, true); err != nil {
		return candidate{}, fmt.Errorf("verify retrieved CRL: %w", err)
	}
	prior, err := os.ReadFile(t.InstalledPath)
	if err != nil {
		return candidate{}, fmt.Errorf("read installed CRL: %w", err)
	}
	previous, err := parseCRL(prior)
	if err != nil {
		return candidate{}, fmt.Errorf("parse installed CRL: %w", err)
	}
	// The previous CRL may be expired, but still must have been authentic.
	if err := verify(previous, issuer, at, false); err != nil {
		return candidate{}, fmt.Errorf("verify installed CRL: %w", err)
	}
	if fresh.Number.Cmp(previous.Number) < 0 || fresh.ThisUpdate.Before(previous.ThisUpdate) {
		return candidate{}, errors.New("CRL rollback rejected")
	}
	if fresh.Number.Cmp(previous.Number) == 0 && !bytes.Equal(fresh.Raw, previous.Raw) {
		return candidate{}, errors.New("same CRL number with different content rejected")
	}
	if fresh.Number.Cmp(previous.Number) > 0 && !fresh.NextUpdate.After(previous.NextUpdate) {
		return candidate{}, errors.New("new CRL does not advance nextUpdate")
	}
	info, err := os.Lstat(t.InstalledPath)
	if err != nil {
		return candidate{}, err
	}
	if err := validFile(info); err != nil {
		return candidate{}, err
	}
	return candidate{target: t, newPEM: pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: fresh.Raw}),
		parsed: fresh, prior: prior, info: info, changed: !bytes.Equal(fresh.Raw, previous.Raw)}, nil
}

func verify(crl *x509.RevocationList, issuer *x509.Certificate, at time.Time, fresh bool) error {
	if crl.Number == nil || crl.Number.Sign() < 0 {
		return errors.New("CRL number is missing or invalid")
	}
	for _, ext := range crl.Extensions {
		if ext.Id.Equal(deltaCRLOID) {
			return errors.New("delta CRL is unsupported; base CRL required")
		}
	}
	if !bytes.Equal(crl.RawIssuer, issuer.RawSubject) {
		return errors.New("CRL issuer mismatch")
	}
	if err := crl.CheckSignatureFrom(issuer); err != nil {
		return fmt.Errorf("invalid CRL signature: %w", err)
	}
	if crl.ThisUpdate.IsZero() || crl.NextUpdate.IsZero() || !crl.NextUpdate.After(crl.ThisUpdate) {
		return errors.New("invalid CRL update window")
	}
	if fresh && (crl.ThisUpdate.After(at) || !crl.NextUpdate.After(at)) {
		return errors.New("retrieved CRL is not currently valid")
	}
	return nil
}

func parseCRL(raw []byte) (*x509.RevocationList, error) {
	if len(raw) == 0 || len(raw) > MaximumBytes {
		return nil, errors.New("CRL byte length invalid")
	}
	if block, rest := pem.Decode(raw); block != nil {
		if block.Type != "X509 CRL" || len(rest) != 0 {
			return nil, errors.New("invalid CRL PEM encoding")
		}
		raw = block.Bytes
	}
	return x509.ParseRevocationList(raw)
}

func retrieve(ctx context.Context, source string) ([]byte, error) {
	parsed, err := url.Parse(source)
	if err != nil {
		return nil, err
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https":
	default:
		return nil, errors.New("CRL source must use HTTP or HTTPS")
	}
	if parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" || parsed.RawQuery != "" {
		return nil, errors.New("invalid CRL source URL")
	}
	limitedCtx, cancel := context.WithTimeout(ctx, FetchTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(limitedCtx, http.MethodGet, source, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Timeout:       FetchTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("fetch CRL: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CRL HTTP status %d", response.StatusCode)
	}
	if response.ContentLength > MaximumBytes {
		return nil, errors.New("CRL exceeds maximum size")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, MaximumBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data) > MaximumBytes {
		return nil, errors.New("invalid CRL download size")
	}
	return data, nil
}

// Trust files must remain in a controlled directory with no symlink at the
// file or immediate parent. Running as root is enforced by the CLI.
func securePath(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("unclean absolute trust path: %q", path)
	}
	dir, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return err
	}
	if !dir.IsDir() || dir.Mode().Perm()&0022 != 0 {
		return errors.New("trust directory must be real and non-writable to group/other")
	}
	file, err := os.Lstat(path)
	if err != nil {
		return err
	}
	return validFile(file)
}

func validFile(info os.FileInfo) error {
	if !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Mode().Perm()&0111 != 0 {
		return errors.New("trust file is not a regular, non-writable, non-executable file")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Nlink != 1 {
		return errors.New("trust file metadata or hard-link count invalid")
	}
	return nil
}

func stage(c *candidate) (string, error) {
	dir := filepath.Dir(c.target.InstalledPath)
	file, err := os.CreateTemp(dir, ".fi-crl-stage-*")
	if err != nil {
		return "", err
	}
	path := file.Name()
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err = file.Write(c.newPEM); err != nil {
		return "", err
	}
	priorStat := c.info.Sys().(*syscall.Stat_t)
	if st, exists := fileStat(file); !exists || st.Uid != priorStat.Uid || st.Gid != priorStat.Gid {
		if err = file.Chown(int(priorStat.Uid), int(priorStat.Gid)); err != nil {
			return "", err
		}
	}
	if err = file.Chmod(c.info.Mode().Perm()); err != nil {
		return "", err
	}
	if err = file.Sync(); err != nil {
		return "", err
	}
	if err = file.Close(); err != nil {
		return "", err
	}
	ok = true
	return path, nil
}

func fileStat(file *os.File) (*syscall.Stat_t, bool) {
	info, err := file.Stat()
	if err != nil {
		return nil, false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return st, ok
}

func unchanged(c *candidate) error {
	if err := securePath(c.target.InstalledPath); err != nil {
		return err
	}
	info, err := os.Lstat(c.target.InstalledPath)
	if err != nil {
		return err
	}
	original := c.info.Sys().(*syscall.Stat_t)
	current := info.Sys().(*syscall.Stat_t)
	if !os.SameFile(info, c.info) || info.Mode() != c.info.Mode() || original.Uid != current.Uid || original.Gid != current.Gid {
		return errors.New("installed CRL identity or permissions changed")
	}
	raw, err := os.ReadFile(c.target.InstalledPath)
	if err != nil {
		return err
	}
	if !bytes.Equal(raw, c.prior) {
		return errors.New("installed CRL contents changed")
	}
	return nil
}

func syncDirectory(dir string) error {
	file, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}
