package transportrecovery

import (
	"bytes"
	"testing"
)

func TestBundleHeaderRoundTrip(t *testing.T) {
	key, cert := testSigningCertificate(t, "iss-fs-01.iss.local")
	signed, err := NewSignedRecovery(testDescriptor(), cert, key)
	if err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	if err := WriteBundleHeader(&wire, signed, 128, signed.Descriptor.EncodedDataBytes); err != nil {
		t.Fatal(err)
	}
	header, err := ReadBundleHeader(&wire)
	if err != nil {
		t.Fatal(err)
	}
	if header.Signed.Descriptor != signed.Descriptor || header.IndexBytes != 128 {
		t.Fatal("bundle header mismatch")
	}
}
