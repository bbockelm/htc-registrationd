// Package authz decides which OIDC principals may approve a CE name in
// approval mode, and which CE names are known for callback mode. The
// decisions come from registrar administrators (HTC_REGISTRATIOND_ADMINS) and
// from the backends named by HTC_REGISTRATIOND_AUTHZ: a mapfile and OSG
// Topology.
package authz

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/bbockelm/htc-registrationd/internal/registrar"
)

// Decision is the answer to "may this principal approve this name?".
type Decision struct {
	Allowed bool
	// Reason states the fact behind the decision, shown to the user:
	// "Administrative Contact (Primary) for resource X in OSG Topology",
	// "Allowed by the registrar's map file", or why the principal is not
	// authorized.
	Reason string
	// Source locates the configuration behind the decision (a map file
	// and line), for the audit log only; it is never shown in the UI.
	Source string
}

// Audit is the decision's reason with its source, for logs and records.
func (d Decision) Audit() string {
	if d.Source == "" {
		return d.Reason
	}
	return d.Reason + " (" + d.Source + ")"
}

// Backend is one source of authorization.
type Backend interface {
	// Name is the backend's HTC_REGISTRATIOND_AUTHZ keyword.
	Name() string
	// Decide reports whether principal may approve name. An error means
	// the backend could not answer (for example, stale data); it is not a
	// denial.
	Decide(ctx context.Context, principal, name string) (Decision, error)
	// Known reports whether the backend explicitly names name, which
	// callback mode requires when HTC_REGISTRATIOND_CALLBACK_NAMES = authz.
	Known(ctx context.Context, name string) (bool, error)
}

// Policy is registrar administrators plus an ordered list of backends. A
// principal may approve a name if it is an administrator or any backend
// allows it; the first allow wins.
type Policy struct {
	backends []Backend
	admins   atomic.Pointer[map[string]bool]
	// issuer, when set, is the OIDC issuer of "<issuer>,<sub>" principals.
	// Configuration (ADMINS, the mapfile) names users by the bare subject.
	issuer string
	// Set by FromConfig, for Start and Reconfig.
	mapfile  *Mapfile
	topology *Topology
}

// NewPolicy returns a policy over backends, in order.
func NewPolicy(backends []Backend, admins []string) *Policy {
	p := &Policy{backends: backends}
	p.SetAdmins(admins)
	return p
}

// SetSubjectIssuer declares that principals have the form
// "<issuer>,<sub>" for the given issuer, and that administrators and
// backends name users by the bare subject. A principal from any other
// issuer matches nothing in configuration. An empty issuer means principals
// are used as they are.
func (p *Policy) SetSubjectIssuer(issuer string) {
	p.issuer = strings.TrimRight(issuer, "/")
}

// ConfigName returns the name configuration (ADMINS, the mapfile) uses for
// principal, and false when no configuration can name it (a principal from
// another issuer).
func (p *Policy) ConfigName(principal string) (string, bool) {
	if p.issuer == "" {
		return principal, principal != ""
	}
	iss, sub, ok := strings.Cut(principal, ",")
	if !ok || strings.TrimRight(iss, "/") != p.issuer || sub == "" {
		return "", false
	}
	return sub, true
}

// SetAdmins replaces the administrators, named as configuration names them.
func (p *Policy) SetAdmins(admins []string) {
	m := make(map[string]bool, len(admins))
	for _, a := range admins {
		if a = strings.TrimSpace(a); a != "" {
			m[a] = true
		}
	}
	p.admins.Store(&m)
}

// IsAdmin reports whether principal is a registrar administrator.
func (p *Policy) IsAdmin(principal string) bool {
	name, ok := p.ConfigName(principal)
	return ok && p.isAdminName(name)
}

// isAdminName reports whether name, as configuration names users, is an
// administrator.
func (p *Policy) isAdminName(name string) bool {
	m := p.admins.Load()
	return m != nil && (*m)[name]
}

// HasAdmins reports whether any administrator is configured.
func (p *Policy) HasAdmins() bool {
	m := p.admins.Load()
	return m != nil && len(*m) > 0
}

// Backends returns the configured backends' names, in order.
func (p *Policy) Backends() []string {
	out := make([]string, 0, len(p.backends))
	for _, b := range p.backends {
		out = append(out, b.Name())
	}
	return out
}

// Decide reports whether principal may approve name. Administrators and
// backends see the principal as configuration names it (see
// SetSubjectIssuer and ConfigName). When no backend allows
// it and at least one could not answer, the error is returned so a caller
// does not mistake an outage for a denial.
func (p *Policy) Decide(ctx context.Context, principal, name string) (Decision, error) {
	if principal == "" {
		return Decision{Reason: "No identity"}, nil
	}
	user, ok := p.ConfigName(principal)
	if !ok {
		return Decision{Reason: "Signed in through an identity provider this registrar does not use"}, nil
	}
	if p.isAdminName(user) {
		return Decision{Allowed: true, Reason: "Registrar administrator"}, nil
	}
	if len(p.backends) == 0 {
		return Decision{Reason: "No authorization source is configured on this registrar"}, nil
	}
	var reasons, sources []string
	var errs []error
	for _, b := range p.backends {
		d, err := b.Decide(ctx, user, name)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", b.Name(), err))
			continue
		}
		if d.Allowed {
			return d, nil
		}
		if d.Reason != "" {
			reasons = append(reasons, d.Reason)
		}
		if d.Source != "" {
			sources = append(sources, d.Source)
		}
	}
	if len(errs) > 0 {
		return Decision{}, errors.Join(errs...)
	}
	return Decision{Reason: strings.Join(reasons, "; "), Source: strings.Join(sources, "; ")}, nil
}

// Known reports whether any backend explicitly names name. When none does
// and at least one could not answer, the error is returned.
func (p *Policy) Known(ctx context.Context, name string) (bool, error) {
	var errs []error
	for _, b := range p.backends {
		ok, err := b.Known(ctx, name)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", b.Name(), err))
			continue
		}
		if ok {
			return true, nil
		}
	}
	return false, errors.Join(errs...)
}

// StillAuthorized implements registrar.ApproverPolicy for web (OIDC)
// approvals: the approver must still be an administrator or allowed by a
// backend. Other identity kinds are not this policy's to vouch for.
func (p *Policy) StillAuthorized(ctx context.Context, approver registrar.Identity, name string) (bool, error) {
	if approver.Kind != IdentityKind {
		return false, nil
	}
	d, err := p.Decide(ctx, approver.Principal, name)
	if err != nil {
		return false, err
	}
	return d.Allowed, nil
}

// IdentityKind is the registrar.Identity kind of a web (OIDC) approver.
const IdentityKind = "oidc"
