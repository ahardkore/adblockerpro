// Package tlsutil generates the self-signed certificate the dashboard uses
// when HTTPS is switched on, so a Raspberry Pi with no public hostname can
// still serve the UI (and DNS-over-HTTPS) over TLS.
package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// EnsureSelfSigned returns paths to a certificate and key in dir, creating
// them if they are missing or already expired. hosts are extra DNS names and
// IP addresses to include; every local address is added automatically.
func EnsureSelfSigned(dir string, hosts []string) (certPath, keyPath string, err error) {
	certPath = filepath.Join(dir, "dashboard.crt")
	keyPath = filepath.Join(dir, "dashboard.key")

	if valid(certPath) {
		if _, err := os.Stat(keyPath); err == nil {
			return certPath, keyPath, nil
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", "", err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", err
	}

	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"adblockerpro"},
			CommonName:   "adblockerpro",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	for _, h := range append(hosts, localNames()...) {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else if h != "" {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}
	certOut, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return "", "", err
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		certOut.Close()
		return "", "", err
	}
	if err := certOut.Close(); err != nil {
		return "", "", err
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", err
	}
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return "", "", err
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		keyOut.Close()
		return "", "", err
	}
	if err := keyOut.Close(); err != nil {
		return "", "", err
	}
	return certPath, keyPath, nil
}

func valid(certPath string) bool {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return false
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	// Renew a month before expiry.
	return time.Now().Before(cert.NotAfter.AddDate(0, -1, 0))
}

// localNames collects this machine's addresses and hostname for the SAN
// list, so https://<pi-ip>:8443 and https://raspberrypi.local both work.
func localNames() []string {
	out := []string{"localhost", "127.0.0.1", "::1", "adblockerpro", "adblockerpro.local"}
	if host, err := os.Hostname(); err == nil && host != "" {
		out = append(out, host, host+".local", host+".lan")
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return out
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			out = append(out, ipnet.IP.String())
		}
	}
	return out
}

// Fingerprint returns a short SHA-256 fingerprint of the certificate, shown
// in the dashboard so you can confirm the one your browser warns about.
func Fingerprint(certPath string) (string, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return "", fmt.Errorf("tlsutil: %s is not PEM", certPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(cert.Raw)
	out := make([]byte, 0, len(sum)*3)
	const hexDigits = "0123456789abcdef"
	for i, b := range sum[:] {
		if i > 0 {
			out = append(out, ':')
		}
		out = append(out, hexDigits[b>>4], hexDigits[b&0x0f])
	}
	return string(out), nil
}
