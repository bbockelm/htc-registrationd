// Package secret generates the random secrets the registration protocol
// exchanges (nonces, request ids, refresh secrets) and the hashes the
// registrar stores in their place.
//
// Every secret is uniformly random, so a single unsalted SHA-256 is a sound
// way to store it: there is no dictionary to attack, and the hash reveals
// nothing about the value. Comparisons go through crypto/subtle.
package secret

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

const (
	// SecretBytes is the size of nonces and refresh secrets: 256 bits.
	SecretBytes = 32
	// IDBytes is the size of request and registration ids: 128 bits.
	IDBytes = 16
)

// New returns n random bytes, base64url-encoded without padding.
func New(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("secret: reading random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// NewSecret returns a fresh 256-bit secret.
func NewSecret() (string, error) { return New(SecretBytes) }

// NewID returns a fresh 128-bit id.
func NewID() (string, error) { return New(IDBytes) }

// Hash returns the hex SHA-256 of s, the form in which the registrar stores a
// secret.
func Hash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// Equal reports whether a and b are equal, in time independent of where they
// differ. It is meant for hashes and secrets of equal length; a length
// mismatch returns false (and leaks only the length).
func Equal(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// Matches reports whether plain hashes to stored, in constant time. An empty
// stored hash never matches.
func Matches(plain, stored string) bool {
	if stored == "" {
		return false
	}
	return Equal(Hash(plain), stored)
}
