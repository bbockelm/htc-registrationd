package registrar

import (
	"context"
	"crypto/rand"
	"fmt"
	"strings"
)

// NamePolicy decides whether a callback-mode request may register a name
// (HTC_REGISTRATIOND_CALLBACK_NAMES). Callback mode alone
// proves only that the CE holds a publicly trusted certificate for the name;
// a policy can require more.
type NamePolicy interface {
	// AllowCallbackName returns whether name may be registered by callback,
	// and a reason to report when it may not.
	AllowCallbackName(ctx context.Context, name string) (bool, string, error)
}

// AnyName is the "any" policy: any name the CE proves with its certificate.
type AnyName struct{}

// AllowCallbackName implements NamePolicy.
func (AnyName) AllowCallbackName(context.Context, string) (bool, string, error) { return true, "", nil }

// AuthzNames is the "authz" policy: the name must also be known to an
// authorization backend (mapfile or OSG Topology). Those backends come in a
// later milestone; until one is configured, every name is refused.
type AuthzNames struct {
	// Known, when set, reports whether a backend knows the name.
	Known func(ctx context.Context, name string) (bool, error)
}

// AllowCallbackName implements NamePolicy.
func (a AuthzNames) AllowCallbackName(ctx context.Context, name string) (bool, string, error) {
	if a.Known == nil {
		return false, "HTC_REGISTRATIOND_CALLBACK_NAMES = authz, but no authorization backend is configured", nil
	}
	ok, err := a.Known(ctx, name)
	if err != nil {
		return false, "", err
	}
	if !ok {
		return false, fmt.Sprintf("%s is not known to the authorization backend", name), nil
	}
	return true, "", nil
}

// ApproverPolicy re-checks, at each renewal, that a registration's original
// approver may still approve its name (HTC_REGISTRATIOND_RECHECK_APPROVER).
type ApproverPolicy interface {
	StillAuthorized(ctx context.Context, approver Identity, name string) (bool, error)
}

// TrustCEDARApprovers keeps CEDAR (ADMINISTRATOR) approvals valid: their
// authority is the ALLOW_ADMINISTRATOR list, not a per-name backend. Other
// approver kinds are passed to Backend, or allowed when it is nil (no OIDC
// approver can exist before the web UI does).
type TrustCEDARApprovers struct {
	Backend ApproverPolicy
}

// StillAuthorized implements ApproverPolicy.
func (p TrustCEDARApprovers) StillAuthorized(ctx context.Context, approver Identity, name string) (bool, error) {
	if approver.Kind == "cedar" || p.Backend == nil {
		return true, nil
	}
	return p.Backend.StillAuthorized(ctx, approver, name)
}

// NormalizeName is the form every CE name is stored and compared in: lower
// case. Names are DNS names, which compare without regard to case (as
// HTCondor's host-based authorization and TLS name checks do), so
// CE.Example.EDU and ce.example.edu are one name: revoking either revokes
// both. Every name is normalized where it enters (a request, an admin
// command, the command line, configuration) and the store normalizes again.
func NormalizeName(name string) string { return strings.ToLower(name) }

// ValidName checks a requested CE name. It must equal the Scheduler ad's Name
// (the collector requires Name == the authenticated user's name part), and in
// callback mode it is a TLS server name, so it is held
// to host-name syntax: 1-253 characters of letters, digits, '.', '-' and '_',
// in non-empty labels that do not start or end with '-'.
func ValidName(name string) error {
	if name == "" || len(name) > 253 {
		return fmt.Errorf("name must be 1-253 characters")
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return fmt.Errorf("name %q has an empty or over-long label", name)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("name %q has a label starting or ending with '-'", name)
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_' {
				return fmt.Errorf("name %q contains %q", name, r)
			}
		}
	}
	return nil
}

// userCodeAlphabet is RFC 8628 §6.1's consonant-only alphabet: no vowels (so
// no words) and no easily confused characters.
const userCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"

// NewUserCode returns a random user code, XXXX-XXXX.
func NewUserCode() (string, error) {
	const n = 8
	out := make([]byte, 0, n+1)
	buf := make([]byte, 16)
	for len(out) < n+1 {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		for _, b := range buf {
			// Rejection sampling keeps the draw uniform: 240 = 12 * 20.
			if b >= 240 {
				continue
			}
			if len(out) == 4 {
				out = append(out, '-')
			}
			out = append(out, userCodeAlphabet[int(b)%len(userCodeAlphabet)])
			if len(out) == n+1 {
				break
			}
		}
	}
	return string(out), nil
}

// NormalizeUserCode upper-cases a typed code and puts the dash back, so
// "wdjbmjht", "WDJB MJHT" and "wdjb-mjht" all find WDJB-MJHT.
func NormalizeUserCode(s string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		if r >= 'A' && r <= 'Z' {
			b.WriteRune(r)
		}
	}
	c := b.String()
	if len(c) != 8 {
		return c
	}
	return c[:4] + "-" + c[4:]
}
