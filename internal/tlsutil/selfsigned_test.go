package tlsutil

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureSelfSignedCreatesPair(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, err := EnsureSelfSigned(dir, nil)
	if err != nil {
		t.Fatalf("EnsureSelfSigned: %v", err)
	}
	if certPath == "" || keyPath == "" {
		t.Fatal("empty paths")
	}

	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	block, _ := pem.Decode(certBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("certificate is not a PEM CERTIFICATE block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cert.Subject.Organization[0] != "adblockerpro" {
		t.Errorf("org = %q", cert.Subject.Organization)
	}

	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	keyBlock, _ := pem.Decode(keyBytes)
	if keyBlock == nil || keyBlock.Type != "EC PRIVATE KEY" {
		t.Fatal("key is not a PEM EC PRIVATE KEY block")
	}

	// The key is the only credential in the pair and must be owner-only.
	fi, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("key mode = %o, want 600", fi.Mode().Perm())
	}
	fi, err = os.Stat(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Errorf("cert mode = %o, want 644", fi.Mode().Perm())
	}
}

func TestEnsureSelfSignedIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	c1, k1, err := EnsureSelfSigned(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	c2, k2, err := EnsureSelfSigned(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c1 != c2 || k1 != k2 {
		t.Error("paths changed across calls")
	}
	b1, _ := os.ReadFile(k1)
	b2, _ := os.ReadFile(k2)
	if string(b1) != string(b2) {
		t.Error("key bytes changed across calls")
	}
}

func TestInvalidCertIsRenewed(t *testing.T) {
	dir := t.TempDir()
	// Corrupt the cert to make valid() fail.
	_, keyPath, err := EnsureSelfSigned(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "dashboard.crt")
	if err := os.WriteFile(certPath, []byte("garbage"), 0o644); err != nil {
		t.Fatal(err)
	}
	c2, k2, err := EnsureSelfSigned(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c2 != certPath || k2 != keyPath {
		t.Error("paths changed after renewal")
	}
	fi, err := os.Stat(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() == 0 {
		t.Error("cert was empty after renewal")
	}
}

func TestFingerprintMatchesCert(t *testing.T) {
	dir := t.TempDir()
	certPath, _, err := EnsureSelfSigned(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	fp, err := Fingerprint(certPath)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	if len(fp) < 8 {
		t.Errorf("fingerprint too short: %q", fp)
	}
}
