// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package crlrefresh

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var fixedTime = time.Date(2026, 10, 28, 21, 0, 0, 0, time.UTC)

type fixture struct {
	cert      *x509.Certificate
	key       *rsa.PrivateKey
	dir       string
	issuer    string
	installed string
}

func createFixture(t *testing.T) fixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "FI Test Issuer"},
		NotBefore: fixedTime.Add(-48 * time.Hour), NotAfter: fixedTime.Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	issuer := filepath.Join(dir, "issuer.pem")
	installed := filepath.Join(dir, "installed.pem")
	if err := os.WriteFile(issuer, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		t.Fatal(err)
	}
	return fixture{cert: cert, key: key, dir: dir, issuer: issuer, installed: installed}
}

func (f fixture) crl(t *testing.T, number int64, start, end time.Time, extra ...pkix.Extension) []byte {
	t.Helper()
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(number), ThisUpdate: start, NextUpdate: end, ExtraExtensions: extra,
	}, f.cert, f.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func (f fixture) setInstalled(t *testing.T, der []byte) []byte {
	t.Helper()
	encoded := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
	if err := os.WriteFile(f.installed, encoded, 0640); err != nil {
		t.Fatal(err)
	}
	return encoded
}

func serveCRL(t *testing.T, raw []byte) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(raw) }))
	t.Cleanup(server.Close)
	return server
}

func TestRefreshPublishesVerifiedNewerCRL(t *testing.T) {
	f := createFixture(t)
	old := f.crl(t, 1, fixedTime.Add(-48*time.Hour), fixedTime.Add(-24*time.Hour))
	f.setInstalled(t, old)
	newCRL := f.crl(t, 2, fixedTime.Add(-time.Hour), fixedTime.Add(48*time.Hour))
	s := serveCRL(t, newCRL)
	target := Target{Name: "transport", URL: s.URL + "/cert.crl", IssuerPath: f.issuer, InstalledPath: f.installed}
	results, err := Refresh(context.Background(), []Target{target}, fixedTime)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Number != "2" || !results[0].Changed {
		t.Fatalf("unexpected result %+v", results)
	}
	published, err := os.ReadFile(f.installed)
	if err != nil {
		t.Fatal(err)
	}
	if block, _ := pem.Decode(published); block == nil || !bytes.Equal(block.Bytes, newCRL) {
		t.Fatal("new CRL not published")
	}
	info, err := os.Stat(f.installed)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0640 {
		t.Fatalf("permissions changed to %o", info.Mode().Perm())
	}
	results, err = Refresh(context.Background(), []Target{target}, fixedTime)
	if err != nil || len(results) != 1 || results[0].Changed {
		t.Fatalf("idempotent refresh: %+v %v", results, err)
	}
}

func TestRefreshRejectsRollbackAndSignatureForgery(t *testing.T) {
	f := createFixture(t)
	prior := f.setInstalled(t, f.crl(t, 2, fixedTime.Add(-2*time.Hour), fixedTime.Add(48*time.Hour)))
	fake := createFixture(t)
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"rollback", f.crl(t, 1, fixedTime.Add(-time.Hour), fixedTime.Add(72*time.Hour))},
		{"forged signer", fake.crl(t, 3, fixedTime.Add(-time.Hour), fixedTime.Add(72*time.Hour))},
		{"expired", f.crl(t, 3, fixedTime.Add(-72*time.Hour), fixedTime.Add(-time.Hour))},
		{"delta", f.crl(t, 3, fixedTime.Add(-time.Hour), fixedTime.Add(72*time.Hour), pkix.Extension{Id: deltaCRLOID, Value: []byte{0x02, 0x01, 0x01}})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := serveCRL(t, tc.data)
			_, err := Refresh(context.Background(), []Target{{Name: "test", URL: s.URL, IssuerPath: f.issuer, InstalledPath: f.installed}}, fixedTime)
			if err == nil {
				t.Fatal("bad CRL accepted")
			}
			got, _ := os.ReadFile(f.installed)
			if !bytes.Equal(got, prior) {
				t.Fatal("installed CRL modified after rejection")
			}
		})
	}
}

func TestRefreshPrevalidatesEveryTarget(t *testing.T) {
	one := createFixture(t)
	two := createFixture(t)
	before := one.setInstalled(t, one.crl(t, 1, fixedTime.Add(-24*time.Hour), fixedTime.Add(24*time.Hour)))
	two.setInstalled(t, two.crl(t, 1, fixedTime.Add(-24*time.Hour), fixedTime.Add(24*time.Hour)))
	good := serveCRL(t, one.crl(t, 2, fixedTime.Add(-time.Hour), fixedTime.Add(48*time.Hour)))
	bad := serveCRL(t, []byte("not a CRL"))
	_, err := Refresh(context.Background(), []Target{
		{Name: "transport", URL: good.URL, IssuerPath: one.issuer, InstalledPath: one.installed},
		{Name: "batch", URL: bad.URL, IssuerPath: two.issuer, InstalledPath: two.installed},
	}, fixedTime)
	if err == nil {
		t.Fatal("second invalid target accepted")
	}
	after, _ := os.ReadFile(one.installed)
	if !bytes.Equal(after, before) {
		t.Fatal("first CRL modified despite rejected second CRL")
	}
}

func TestRefreshRejectsRedirectAndOversizedReply(t *testing.T) {
	f := createFixture(t)
	before := f.setInstalled(t, f.crl(t, 1, fixedTime.Add(-24*time.Hour), fixedTime.Add(24*time.Hour)))
	redirected := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://other.example/CRL", http.StatusFound)
	}))
	defer redirected.Close()
	tooLarge := serveCRL(t, bytes.Repeat([]byte{'a'}, MaximumBytes+1))
	for _, s := range []string{redirected.URL, tooLarge.URL} {
		_, err := Refresh(context.Background(), []Target{{Name: "transport", URL: s, IssuerPath: f.issuer, InstalledPath: f.installed}}, fixedTime)
		if err == nil {
			t.Fatal("unsafe response accepted")
		}
		data, _ := os.ReadFile(f.installed)
		if !bytes.Equal(data, before) {
			t.Fatal("installed CRL changed")
		}
	}
}

func TestRefreshRefusesSymlinkTrustPath(t *testing.T) {
	f := createFixture(t)
	real := f.installed
	f.setInstalled(t, f.crl(t, 1, fixedTime.Add(-24*time.Hour), fixedTime.Add(24*time.Hour)))
	f.installed = filepath.Join(f.dir, "link")
	if err := os.Symlink(real, f.installed); err != nil {
		t.Fatal(err)
	}
	s := serveCRL(t, f.crl(t, 2, fixedTime.Add(-time.Hour), fixedTime.Add(48*time.Hour)))
	_, err := Refresh(context.Background(), []Target{{Name: "transport", URL: s.URL, IssuerPath: f.issuer, InstalledPath: f.installed}}, fixedTime)
	if err == nil || !strings.Contains(err.Error(), "regular") {
		t.Fatalf("symlink should be rejected: %v", err)
	}
}
