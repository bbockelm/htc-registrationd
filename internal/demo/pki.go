package demo

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// certLifetime is how long the demo CA and certificates are valid. They are
// regenerated when they are within a day of expiring.
const certLifetime = 30 * 24 * time.Hour

// pki is the demo certificate authority in <dir>/pki.
type pki struct {
	dir    string
	caFile string
	cert   *x509.Certificate
	key    *ecdsa.PrivateKey
}

// loadOrCreatePKI loads the CA in dir, or creates one when it is missing or
// close to expiry. A new CA invalidates every certificate it issued, so they
// are removed.
func loadOrCreatePKI(dir string) (*pki, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	p := &pki{dir: dir, caFile: filepath.Join(dir, "ca.pem")}
	keyFile := filepath.Join(dir, "ca.key")
	if pair, err := tls.LoadX509KeyPair(p.caFile, keyFile); err == nil {
		if c, err := x509.ParseCertificate(pair.Certificate[0]); err == nil && fresh(c) {
			if k, ok := pair.PrivateKey.(*ecdsa.PrivateKey); ok {
				p.cert, p.key = c, k
				return p, nil
			}
		}
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "*.crt"))
	for _, m := range matches {
		_ = os.Remove(m)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano()),
		Subject:               pkix.Name{CommonName: "htc-registrationd demo CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(certLifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	if p.cert, err = x509.ParseCertificate(der); err != nil {
		return nil, err
	}
	p.key = key
	if err := writeKey(keyFile, key); err != nil {
		return nil, err
	}
	if err := writePEM(p.caFile, "CERTIFICATE", der, 0o644); err != nil {
		return nil, err
	}
	return p, nil
}

// fresh reports whether c is valid for at least another day.
func fresh(c *x509.Certificate) bool {
	now := time.Now()
	return now.After(c.NotBefore) && now.Add(24*time.Hour).Before(c.NotAfter)
}

// serverCert returns the certificate and key files for a server-auth
// certificate naming the DNS names and IP addresses, issuing one when it is
// missing, close to expiry, or not from this CA.
func (p *pki) serverCert(name string, dnsNames []string, ips []net.IP) (certFile, keyFile string, err error) {
	certFile = filepath.Join(p.dir, name+".crt")
	keyFile = filepath.Join(p.dir, name+".key")
	if pair, err := tls.LoadX509KeyPair(certFile, keyFile); err == nil {
		if c, err := x509.ParseCertificate(pair.Certificate[0]); err == nil && fresh(c) && c.CheckSignatureFrom(p.cert) == nil {
			return certFile, keyFile, nil
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		return "", "", err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		DNSNames:     dnsNames,
		IPAddresses:  ips,
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(certLifetime - time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.cert, &key.PublicKey, p.key)
	if err != nil {
		return "", "", err
	}
	if err := writeKey(keyFile, key); err != nil {
		return "", "", err
	}
	if err := writePEM(certFile, "CERTIFICATE", der, 0o644); err != nil {
		return "", "", err
	}
	return certFile, keyFile, nil
}

func writeKey(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	return writePEM(path, "EC PRIVATE KEY", der, 0o600)
}

func writePEM(path, typ string, der []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), mode); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return errors.Join(err, os.Remove(tmp))
	}
	return nil
}
