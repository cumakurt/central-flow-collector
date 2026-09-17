package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIsLoopbackBind(t *testing.T) {
	for _, h := range []string{"127.0.0.1", "::1", "[::1]", "localhost"} {
		if !isLoopbackBind(h) {
			t.Errorf("isLoopbackBind(%q) = false", h)
		}
	}
	for _, h := range []string{"0.0.0.0", "::", "192.0.2.10", "example.test"} {
		if isLoopbackBind(h) {
			t.Errorf("isLoopbackBind(%q) = true", h)
		}
	}
}

func TestValidateTLSMaterial(t *testing.T) {
	d := t.TempDir()
	cert, key := writeTestCertificate(t, d, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err := validateTLSMaterial(cert, key); err != nil {
		t.Fatalf("valid pair rejected: %v", err)
	}
	if err := validateTLSMaterial("", ""); err == nil {
		t.Fatal("missing TLS material accepted")
	}
	if err := validateTLSMaterial(cert, filepath.Join(d, "missing.key")); err == nil {
		t.Fatal("missing TLS key accepted")
	}
}

func TestValidateTLSMaterialRejectsExpiredCertificate(t *testing.T) {
	d := t.TempDir()
	cert, key := writeTestCertificate(t, d, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
	if err := validateTLSMaterial(cert, key); err == nil {
		t.Fatal("expired certificate accepted")
	}
}

func writeTestCertificate(t *testing.T, dir string, notBefore, notAfter time.Time) (string, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test.local"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	cf, err := os.Create(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatal(err)
	}
	if err := cf.Close(); err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	kf, err := os.OpenFile(keyPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(kf, &pem.Block{Type: "PRIVATE KEY", Bytes: kb}); err != nil {
		t.Fatal(err)
	}
	if err := kf.Close(); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func TestEnsureDataDirAccessCreatesAndCleansProbe(t *testing.T) {
	d := t.TempDir()
	if err := ensureDataDirAccess(d); err != nil {
		t.Fatalf("ensureDataDirAccess: %v", err)
	}
	entries, err := os.ReadDir(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".write-probe-") {
			t.Fatalf("write probe was not cleaned up: %s", e.Name())
		}
	}
}
