package webui

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// certReloadInterval is how often the serving certificate is re-read.
const certReloadInterval = time.Minute

// certReloader serves the current TLS keypair, re-reading it as it changes
// so a renewed certificate takes effect without a restart.
//
// The swap is all-or-nothing. A renewal writes the certificate and the key
// as two files, so a read between the two writes sees a new certificate
// with the old key (or half a PEM). tls.X509KeyPair rejects both, since it
// checks that the key matches the certificate, and the keypair already in
// use keeps being served until a later read finds a matching pair.
//
// Change is detected by comparing the bytes read with the bytes in use,
// which does not depend on timestamp granularity.
type certReloader struct {
	certFile string
	keyFile  string
	interval time.Duration
	read     func(string) ([]byte, error)
	log      *slog.Logger
	now      func() time.Time

	mu        sync.RWMutex
	cert      *tls.Certificate
	certPEM   []byte
	keyPEM    []byte
	lastCheck time.Time
}

// newCertReloader loads the keypair once and fails if it cannot.
func newCertReloader(certFile, keyFile string, read func(string) ([]byte, error), log *slog.Logger) (*certReloader, error) {
	r := &certReloader{
		certFile: certFile,
		keyFile:  keyFile,
		interval: certReloadInterval,
		read:     read,
		log:      log,
		now:      time.Now,
	}
	certPEM, keyPEM, cert, err := r.load()
	if err != nil {
		return nil, err
	}
	r.cert, r.certPEM, r.keyPEM, r.lastCheck = cert, certPEM, keyPEM, r.now()
	return r, nil
}

func (r *certReloader) load() ([]byte, []byte, *tls.Certificate, error) {
	certPEM, err := r.read(r.certFile)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("reading TLS certificate %s: %w", r.certFile, err)
	}
	keyPEM, err := r.read(r.keyFile)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("reading TLS key %s: %w", r.keyFile, err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("TLS keypair (%s, %s): %w", r.certFile, r.keyFile, err)
	}
	return certPEM, keyPEM, &cert, nil
}

// GetCertificate is the tls.Config hook. It checks the files at most once
// per interval and never fails a handshake over a reload problem.
func (r *certReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.RLock()
	cert, last := r.cert, r.lastCheck
	r.mu.RUnlock()
	if r.now().Sub(last) < r.interval {
		return cert, nil
	}
	return r.refresh(false), nil
}

// refresh re-reads the files and swaps in a changed keypair that parses.
// force skips the interval check (reconfig).
func (r *certReloader) refresh(force bool) *tls.Certificate {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !force && r.now().Sub(r.lastCheck) < r.interval {
		return r.cert
	}
	r.lastCheck = r.now()
	certPEM, keyPEM, cert, err := r.load()
	if err != nil {
		r.log.Warn("webui: TLS keypair could not be reloaded; continuing with the one in use", "err", err)
		return r.cert
	}
	if bytes.Equal(certPEM, r.certPEM) && bytes.Equal(keyPEM, r.keyPEM) {
		return r.cert
	}
	r.cert, r.certPEM, r.keyPEM = cert, certPEM, keyPEM
	r.log.Info("webui: TLS keypair reloaded", "cert", r.certFile, "key", r.keyFile)
	return r.cert
}
