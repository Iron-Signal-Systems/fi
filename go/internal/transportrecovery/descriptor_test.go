package transportrecovery

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportencoding"
	"github.com/Iron-Signal-Systems/fi/go/internal/transporttrust"
)

func TestSignedRecoveryRoundTrip(t *testing.T) {
	key, cert := testSigningCertificate(t, "iss-fs-01.iss.local")
	descriptor := testDescriptor()
	signed, err := NewSignedRecovery(descriptor, cert, key)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := cert.PublicKey.(*rsa.PublicKey)
	if err := VerifySignedRecoverySignature(signed, publicKey); err != nil {
		t.Fatal(err)
	}

	signed.Descriptor.MemberCount++
	if err := VerifySignedRecoverySignature(signed, publicKey); err == nil {
		t.Fatal("tampered descriptor unexpectedly verified")
	}
}

func testDescriptor() Descriptor {
	return Descriptor{
		Version:           DescriptorVersion,
		SourceID:          "iss-fs-01.iss.local",
		RecoveryID:        "20260915T000000.000000000Z-0011223344556677",
		MemberCount:       2,
		RecordCount:       4,
		CanonicalBytes:    100,
		CanonicalSHA256:   "11" + repeatHex("00", 31),
		DataEncoding:      transportencoding.DataEncodingZstd,
		EncodedDataBytes:  50,
		EncodedDataSHA256: "22" + repeatHex("00", 31),
		IndexSHA256:       "33" + repeatHex("00", 31),
		FirstBatchID:      "20260915T000001.000000000Z-0000000000000001",
		LastBatchID:       "20260915T000002.000000000Z-0000000000000002",
	}
}

func testSigningCertificate(t *testing.T, commonName string) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         commonName,
			OrganizationalUnit: []string{transporttrust.BatchSigningOrganizationalUnit},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, certificate
}

func repeatHex(value string, count int) string {
	result := ""
	for i := 0; i < count; i++ {
		result += value
	}
	return result
}
