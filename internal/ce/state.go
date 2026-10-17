package ce

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/bbockelm/htc-registrationd/internal/atomicfile"
)

// File names in the state directory.
const (
	RegistrationFile = "registration.json" // secrets; mode 0600
	StatusFile       = "status.json"
	ApprovalURLFile  = "approval-url"
)

// State is registration.json: everything the CE must remember across a
// restart. Every write is an atomic overwrite, so the file always holds one
// consistent version of {RegistrationId, current, pending}.
type State struct {
	// Method is the method of the request or registration in progress.
	Method    string `json:"method,omitempty"`
	Name      string `json:"name,omitempty"`
	Registrar string `json:"registrar,omitempty"`

	// An approval-mode request awaiting a decision. RequestID and Nonce are
	// persisted before the approval URL is published, so a restart resumes
	// polling the same request.
	RequestID               string `json:"request_id,omitempty"`
	Nonce                   string `json:"nonce,omitempty"`
	UserCode                string `json:"user_code,omitempty"`
	VerificationURI         string `json:"verification_uri,omitempty"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	RequestExpires          int64  `json:"request_expires,omitempty"`
	PollInterval            int64  `json:"poll_interval,omitempty"`

	// An approval-mode registration: its id and the refresh secrets in
	// plain text (the registrar keeps only their hashes).
	RegistrationID string `json:"registration_id,omitempty"`
	Current        string `json:"current,omitempty"`
	Pending        string `json:"pending,omitempty"`

	// The installed token (never the token itself, which lives in tokens.d).
	TokenIssuedAt    int64 `json:"token_issued_at,omitempty"`
	TokenExpiry      int64 `json:"token_expiry,omitempty"`
	TokenInstalledAt int64 `json:"token_installed_at,omitempty"`
	// TokenRenewAt is when the installed token is due for renewal, drawn
	// once per token with jitter so a fleet of CEs does not renew in step.
	TokenRenewAt int64 `json:"token_renew_at,omitempty"`
	// TokenFile is where the token was installed, so a changed token
	// directory leaves no stale copy behind.
	TokenFile string `json:"token_file,omitempty"`
	// LastReconfig is when the local master last reconfigured after a
	// token install.
	LastReconfig int64 `json:"last_reconfig,omitempty"`
	// TokenGeneration counts token installs; ReconfiguredGeneration is the
	// newest install the local master has been told about. While the first
	// is ahead, the daemon keeps retrying the reconfig, whether the install
	// came from a renewal, a callback that finished after its request gave
	// up, or before a crash.
	TokenGeneration        int64 `json:"token_generation,omitempty"`
	ReconfiguredGeneration int64 `json:"reconfigured_generation,omitempty"`
}

// NeedsReconfig reports whether a token was installed after the local
// master's last reconfig.
func (s State) NeedsReconfig() bool { return s.TokenGeneration > s.ReconfiguredGeneration }

// Newest returns the refresh secret to present: pending if set, else current.
func (s *State) Newest() string {
	if s.Pending != "" {
		return s.Pending
	}
	return s.Current
}

// HasToken reports whether a token is installed and unexpired at now.
func (s *State) HasToken(now time.Time) bool {
	return s.TokenExpiry != 0 && now.Before(time.Unix(s.TokenExpiry, 0))
}

// RenewAt returns when the installed token is due for renewal: TokenRenewAt
// when it was drawn at install, else fraction of the way through its
// lifetime.
func (s *State) RenewAt(fraction float64) time.Time {
	if s.TokenRenewAt != 0 {
		return time.Unix(s.TokenRenewAt, 0)
	}
	issued, exp := time.Unix(s.TokenIssuedAt, 0), time.Unix(s.TokenExpiry, 0)
	if s.TokenIssuedAt == 0 || !exp.After(issued) {
		return exp
	}
	return issued.Add(time.Duration(float64(exp.Sub(issued)) * fraction))
}

// clearRequest forgets an approval-mode request.
func (s *State) clearRequest() {
	s.RequestID, s.Nonce, s.UserCode = "", "", ""
	s.VerificationURI, s.VerificationURIComplete = "", ""
	s.RequestExpires, s.PollInterval = 0, 0
}

// clearRegistration forgets an approval-mode registration's secrets.
func (s *State) clearRegistration() {
	s.RegistrationID, s.Current, s.Pending = "", "", ""
}

// LoadState reads registration.json; a missing file is an empty state.
func LoadState(dir string) (*State, error) {
	data, err := os.ReadFile(filepath.Join(dir, RegistrationFile)) //nolint:gosec // G304: our own state directory.
	if errors.Is(err, fs.ErrNotExist) {
		return &State{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", RegistrationFile, err)
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", RegistrationFile, err)
	}
	if s.TokenGeneration == 0 && s.TokenInstalledAt != 0 {
		// Written before generations were kept: reconfigure unless the last
		// reconfig was after the install.
		s.TokenGeneration = 1
		if s.LastReconfig > s.TokenInstalledAt {
			s.ReconfiguredGeneration = 1
		}
	}
	return &s, nil
}

// SaveState atomically writes registration.json, mode 0600.
func SaveState(dir string, s *State) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.WriteFile(filepath.Join(dir, RegistrationFile), append(data, '\n'), 0o600)
}

// Status is status.json and the REG_STATUS reply: what an operator wants to
// know. It carries no secrets.
type Status struct {
	State          string `json:"state"`
	Method         string `json:"method,omitempty"`
	Name           string `json:"name,omitempty"`
	Registrar      string `json:"registrar,omitempty"`
	RegistrationID string `json:"registration_id,omitempty"`
	TokenFile      string `json:"token_file,omitempty"`
	TokenExpiry    int64  `json:"token_expiry,omitempty"`
	NextRenewal    int64  `json:"next_renewal,omitempty"`
	LastSuccess    int64  `json:"last_success,omitempty"`
	LastError      string `json:"last_error,omitempty"`
	LastErrorTime  int64  `json:"last_error_time,omitempty"`
	ApprovalURL    string `json:"approval_url,omitempty"`
	UserCode       string `json:"user_code,omitempty"`
	RequestExpires int64  `json:"request_expires,omitempty"`
	LastPingTime   int64  `json:"last_ping_time,omitempty"`
	LastPingResult string `json:"last_ping_result,omitempty"`
	UpdatedAt      int64  `json:"updated_at"`
}

// States reported in Status.State.
const (
	StateIdle            = "idle"
	StateRequesting      = "requesting"
	StateCallbackPending = "callback-pending"
	StateApprovalPending = "approval-pending"
	StateRegistered      = "registered"
	StateError           = "error"
)

// SaveStatus atomically writes status.json, mode 0644.
func SaveStatus(dir string, st *Status) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.WriteFile(filepath.Join(dir, StatusFile), append(data, '\n'), 0o644)
}
