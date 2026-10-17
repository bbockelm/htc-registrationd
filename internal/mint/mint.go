// Package mint signs the IDTOKENs the registrar issues: sub = <name>@<domain>,
// iss = the trust domain, a condor:/<LEVEL> scope per authorization limit, a
// lifetime, a back-dated nbf and a random jti.
//
// The signing path is byte-identical to cedar's security.GenerateJWT, which
// matches C++ Condor_Auth_Passwd: the key file is unscrambled (XOR 0xdeadbeef),
// a POOL key is doubled, the HMAC key is HKDF-SHA256(key, salt "htcondor",
// info "master jwt"), and the token is HS256 over header.payload. It adds what
// GenerateJWT cannot: an nbf claim back-dated by NotBeforeLeeway (copied from
// golang-htcondor's webapi minter), and it returns the jti so the registrar can
// record it.
//
// The key is read through droppriv.OpenAsRoot: credentials are always read as
// root, since the daemon has dropped to the condor account and the key is
// root-owned 0600. As HTCondor's read_secure_file(SECURE_FILE_VERIFY_ALL)
// does, the file must be owned by the process's real uid (root when started
// by a root master) and not be accessible to group or others.
// CreateKeyIfMissing creates that file, in the format HTCondor writes, when
// it does not exist.
package mint

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/bbockelm/golang-htcondor/droppriv"
	"golang.org/x/crypto/hkdf"
)

// NotBeforeLeeway back-dates nbf to absorb clock skew between the registrar
// and the collectors that verify the token.
const NotBeforeLeeway = 10 * time.Second

// Token is a minted IDTOKEN and the claims the registrar records.
type Token struct {
	Raw       string
	JTI       string
	Subject   string
	Issuer    string
	IssuedAt  time.Time
	NotBefore time.Time
	Expiry    time.Time
	Scope     string
}

// Minter signs tokens for registered CE names.
type Minter struct {
	// KeyDir is SEC_PASSWORD_DIRECTORY.
	KeyDir string
	// PoolKeyFile is SEC_TOKEN_POOL_SIGNING_KEY_FILE, the file of the POOL
	// key, which HTCondor reads from there rather than from KeyDir.
	PoolKeyFile string
	// KeyID is the signing key's file name in KeyDir and the token's kid
	// (HTC_REGISTRATIOND_SIGNING_KEY, default "ce-registration"); for "POOL"
	// the file is PoolKeyFile.
	KeyID string
	// Issuer is the iss claim (TRUST_DOMAIN).
	Issuer string
	// Domain is appended to the CE name to form sub
	// (HTC_REGISTRATIOND_IDENTITY_DOMAIN, default UID_DOMAIN).
	Domain string
	// Limits are the authorization levels the token is limited to
	// (HTC_REGISTRATIOND_TOKEN_LIMITS, default ADVERTISE_SCHEDD).
	Limits []string
	// Lifetime is the token lifetime (HTC_REGISTRATIOND_TOKEN_LIFETIME).
	Lifetime time.Duration
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// ReadKey reads the scrambled key file; nil means readSecure (as root,
	// with HTCondor's owner and mode checks).
	ReadKey func(path string) ([]byte, error)
}

// Subject returns the sub claim minted for a CE name.
func (m *Minter) Subject(name string) string {
	if m.Domain == "" {
		return name
	}
	return name + "@" + m.Domain
}

// Check verifies the signing key can be read and is non-empty, so a
// misconfiguration surfaces at startup rather than at the first request.
func (m *Minter) Check() error {
	_, err := m.signingKey()
	return err
}

// readSecure reads a key file as root, refusing it unless it passes
// HTCondor's read_secure_file checks.
func readSecure(path string) ([]byte, error) {
	f, err := droppriv.OpenAsRoot(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	if err := checkSecure(f); err != nil {
		return nil, err
	}
	return io.ReadAll(f)
}

func (m *Minter) signingKey() ([]byte, error) {
	path, err := m.KeyFile()
	if err != nil {
		return nil, err
	}
	read := m.ReadKey
	if read == nil {
		read = readSecure
	}
	scrambled, err := read(path)
	if err != nil {
		return nil, fmt.Errorf("mint: reading signing key %s: %w", path, err)
	}
	if len(scrambled) == 0 {
		return nil, fmt.Errorf("mint: signing key %s is empty", path)
	}
	key := scramble(scrambled)
	// HTCondor doubles the POOL key before HKDF; named keys are used as-is.
	if m.KeyID == PoolKeyID {
		key = append(key, key...)
	}
	return key, nil
}

// Mint signs a token for the CE name.
func (m *Minter) Mint(name string) (*Token, error) {
	if m.Lifetime <= 0 {
		return nil, fmt.Errorf("mint: token lifetime must be positive")
	}
	key, err := m.signingKey()
	if err != nil {
		return nil, err
	}
	now := time.Now
	if m.Now != nil {
		now = m.Now
	}
	iat := now().Truncate(time.Second)

	jtiBytes := make([]byte, 16)
	if _, err := rand.Read(jtiBytes); err != nil {
		return nil, fmt.Errorf("mint: generating jti: %w", err)
	}
	tok := &Token{
		JTI:       hex.EncodeToString(jtiBytes),
		Subject:   m.Subject(name),
		Issuer:    m.Issuer,
		IssuedAt:  iat,
		NotBefore: iat.Add(-NotBeforeLeeway),
		Expiry:    iat.Add(m.Lifetime),
	}

	header, err := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT", "kid": m.KeyID})
	if err != nil {
		return nil, fmt.Errorf("mint: header: %w", err)
	}
	payload := map[string]any{
		"sub": tok.Subject,
		"jti": tok.JTI,
		"iat": tok.IssuedAt.Unix(),
		"nbf": tok.NotBefore.Unix(),
		"exp": tok.Expiry.Unix(),
	}
	if m.Issuer != "" {
		payload["iss"] = m.Issuer
	}
	if len(m.Limits) > 0 {
		scopes := make([]string, len(m.Limits))
		for i, l := range m.Limits {
			scopes[i] = "condor:/" + l
		}
		tok.Scope = strings.Join(scopes, " ")
		payload["scope"] = tok.Scope
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("mint: payload: %w", err)
	}

	signData := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body)
	jwtKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, key, []byte("htcondor"), []byte("master jwt")), jwtKey); err != nil {
		return nil, fmt.Errorf("mint: deriving JWT key: %w", err)
	}
	mac := hmac.New(sha256.New, jwtKey)
	mac.Write([]byte(signData))
	tok.Raw = signData + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return tok, nil
}

// Claims are the unverified claims of a token, for a holder (the CE) that
// cannot verify the signature but wants to sanity-check what it received.
type Claims struct {
	Subject  string `json:"sub"`
	Issuer   string `json:"iss"`
	Scope    string `json:"scope"`
	JTI      string `json:"jti"`
	IssuedAt int64  `json:"iat"`
	Expiry   int64  `json:"exp"`
	KeyID    string `json:"-"`
}

// ParseUnverified decodes a JWT's claims without checking its signature.
func ParseUnverified(raw string) (*Claims, error) {
	parts := strings.Split(strings.TrimSpace(raw), ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("mint: not a JWT (%d parts)", len(parts))
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("mint: header: %w", err)
	}
	var h struct {
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(hb, &h); err != nil {
		return nil, fmt.Errorf("mint: header: %w", err)
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("mint: payload: %w", err)
	}
	var c Claims
	if err := json.Unmarshal(pb, &c); err != nil {
		return nil, fmt.Errorf("mint: payload: %w", err)
	}
	c.KeyID = h.Kid
	return &c, nil
}
