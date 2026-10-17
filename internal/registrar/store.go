package registrar

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"time"

	// glebarez/go-sqlite is the modernc.org/sqlite-derived pure-Go engine.
	// golang-htcondor's daemon package already links it (for the session
	// cache), and both it and modernc.org/sqlite register the driver name
	// "sqlite", so linking modernc.org/sqlite as well would panic at init.
	_ "github.com/glebarez/go-sqlite"

	"github.com/bbockelm/htc-registrationd/internal/mint"
	"github.com/bbockelm/htc-registrationd/internal/protocol"
	"github.com/bbockelm/htc-registrationd/internal/secret"
)

// Request statuses.
const (
	ReqCallbackPending = "callback-pending"
	ReqPending         = "pending"
	ReqApproved        = "approved"
	ReqDenied          = "denied"
	ReqExpired         = "expired"
	ReqIssued          = "issued" // callback: token delivered and acknowledged
	ReqFailed          = "failed" // callback: no token delivered
	ReqClaimed         = "claimed"
)

// Registration statuses.
const (
	RegPendingAck = "pending-ack" // callback: token sent, acknowledgement not yet received
	RegActive     = "active"
	RegRevoked    = "revoked"
	RegExpired    = "expired" // past HTC_REGISTRATIOND_MAX_REGISTRATION_AGE
)

// Identity is an approver: an authenticated CEDAR user, or (later) an OIDC
// principal.
type Identity struct {
	Kind      string // "cedar" or "oidc"
	Principal string
}

func (i Identity) String() string { return i.Kind + ":" + i.Principal }

// ParseIdentity reverses Identity.String.
func ParseIdentity(s string) Identity {
	k, p, ok := strings.Cut(s, ":")
	if !ok {
		return Identity{Principal: s}
	}
	return Identity{Kind: k, Principal: p}
}

// RequestRecord is a row of the requests table.
type RequestRecord struct {
	Number          int64
	Name            string
	Method          string
	SourceIP        string
	CallbackAddress string
	CEVersion       string
	UserCode        string
	Status          string
	CreatedAt       time.Time
	ExpiresAt       time.Time
	DecidedAt       time.Time
	DecidedBy       string
	Reason          string
	RegistrationID  string
	PollInterval    time.Duration
	LastPollAt      time.Time
	nonceHash       string
}

// RegistrationRecord is a row of the registrations table.
type RegistrationRecord struct {
	ID            string
	Name          string
	Method        string
	Status        string
	Approver      string
	RequestNumber int64
	SourceIP      string
	CreatedAt     time.Time
	UpdatedAt     time.Time
	LastIssuedAt  time.Time
	TokenExpiry   time.Time
	RevokedAt     time.Time
	RevokedBy     string
	RevokeReason  string
	secrets       SecretState
}

// Store is the registrar's SQLite database: requests, registrations and
// issued_tokens. Secrets, nonces and request ids are stored only as hashes.
//
// The database is opened with a single connection, so transactions are
// serialized: two REG_RENEWs racing on one registration cannot both read the
// same secret state.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

const schema = `
CREATE TABLE IF NOT EXISTS requests (
	id               INTEGER PRIMARY KEY AUTOINCREMENT,
	request_id_hash  TEXT NOT NULL UNIQUE,
	nonce_hash       TEXT NOT NULL,
	name             TEXT NOT NULL,
	method           TEXT NOT NULL,
	source_ip        TEXT NOT NULL DEFAULT '',
	source_net       TEXT NOT NULL DEFAULT '',
	callback_address TEXT NOT NULL DEFAULT '',
	ce_version       TEXT NOT NULL DEFAULT '',
	user_code        TEXT UNIQUE,
	status           TEXT NOT NULL,
	created_at       INTEGER NOT NULL,
	expires_at       INTEGER NOT NULL,
	decided_at       INTEGER NOT NULL DEFAULT 0,
	decided_by       TEXT NOT NULL DEFAULT '',
	reason           TEXT NOT NULL DEFAULT '',
	registration_id  TEXT NOT NULL DEFAULT '',
	poll_interval    INTEGER NOT NULL DEFAULT 5,
	last_poll_at     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS requests_status ON requests(status, expires_at);
CREATE TABLE IF NOT EXISTS registrations (
	registration_id TEXT PRIMARY KEY,
	name            TEXT NOT NULL,
	method          TEXT NOT NULL,
	status          TEXT NOT NULL,
	approver        TEXT NOT NULL DEFAULT '',
	request_number  INTEGER NOT NULL DEFAULT 0,
	source_ip       TEXT NOT NULL DEFAULT '',
	created_at      INTEGER NOT NULL,
	updated_at      INTEGER NOT NULL,
	last_issued_at  INTEGER NOT NULL DEFAULT 0,
	token_expiry    INTEGER NOT NULL DEFAULT 0,
	current_hash    TEXT NOT NULL DEFAULT '',
	pending_hash    TEXT NOT NULL DEFAULT '',
	retired_hashes  TEXT NOT NULL DEFAULT '[]',
	replaced_hashes TEXT NOT NULL DEFAULT '[]',
	reissues        INTEGER NOT NULL DEFAULT 0,
	revoked_at      INTEGER NOT NULL DEFAULT 0,
	revoked_by      TEXT NOT NULL DEFAULT '',
	revoke_reason   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS registrations_name ON registrations(name, method, status);
CREATE TABLE IF NOT EXISTS issued_tokens (
	jti             TEXT PRIMARY KEY,
	registration_id TEXT NOT NULL,
	name            TEXT NOT NULL,
	subject         TEXT NOT NULL,
	method          TEXT NOT NULL,
	reason          TEXT NOT NULL,
	issued_at       INTEGER NOT NULL,
	expires_at      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS issued_tokens_registration ON issued_tokens(registration_id);
CREATE INDEX IF NOT EXISTS issued_tokens_expires ON issued_tokens(expires_at);
`

// addedColumns are columns added after the first release, created on an
// older database by migrate.
var addedColumns = []struct{ table, column, decl string }{
	{"requests", "source_net", "TEXT NOT NULL DEFAULT ''"},
	{"registrations", "replaced_hashes", "TEXT NOT NULL DEFAULT '[]'"},
	{"registrations", "reissues", "INTEGER NOT NULL DEFAULT 0"},
}

// migrate brings an older database up to the current schema: it adds missing
// columns, lower-cases names (names compare without regard to case, and
// every name is lower-cased at intake), and fills in source_net.
func migrate(ctx context.Context, db *sql.DB) error {
	for _, c := range addedColumns {
		var n int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?`,
			c.table, c.column).Scan(&n); err != nil {
			return fmt.Errorf("store: inspecting %s: %w", c.table, err)
		}
		if n == 0 {
			if _, err := db.ExecContext(ctx, `ALTER TABLE `+c.table+` ADD COLUMN `+c.column+` `+c.decl); err != nil {
				return fmt.Errorf("store: adding %s.%s: %w", c.table, c.column, err)
			}
		}
	}
	for _, q := range []string{
		`UPDATE requests SET name = lower(name) WHERE name != lower(name)`,
		`UPDATE registrations SET name = lower(name) WHERE name != lower(name)`,
		`UPDATE issued_tokens SET name = lower(name) WHERE name != lower(name)`,
	} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("store: lower-casing names: %w", err)
		}
	}
	rows, err := db.QueryContext(ctx, `SELECT id, source_ip FROM requests WHERE source_net = '' AND source_ip != ''`)
	if err != nil {
		return fmt.Errorf("store: reading request sources: %w", err)
	}
	type src struct {
		id int64
		ip string
	}
	var fix []src
	for rows.Next() {
		var s src
		if err := rows.Scan(&s.id, &s.ip); err != nil {
			_ = rows.Close()
			return err
		}
		fix = append(fix, s)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, s := range fix {
		if _, err := db.ExecContext(ctx, `UPDATE requests SET source_net = ? WHERE id = ?`, SourceNet(s.ip), s.id); err != nil {
			return fmt.Errorf("store: setting source_net: %w", err)
		}
	}
	return nil
}

// OpenStore opens (creating if needed) the database at path.
func OpenStore(path string, now func() time.Time) (*Store, error) {
	if now == nil {
		now = time.Now
	}
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(10000)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "synchronous(FULL)")
	q.Add("_pragma", "foreign_keys(1)")
	db, err := sql.Open("sqlite", "file:"+path+"?"+q.Encode())
	if err != nil {
		return nil, fmt.Errorf("store: opening %s: %w", path, err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(context.Background(), schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: creating schema in %s: %w", path, err)
	}
	if err := migrate(context.Background(), db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db, now: now}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// DB returns the database, for components that keep their own tables beside
// the registrar's (the web UI's sessions). It has a single connection: a
// caller must not hold a transaction open while calling the Store.
func (s *Store) DB() *sql.DB { return s.db }

func unix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func fromUnix(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(n, 0)
}

// tx runs fn in a transaction, committing if it returns nil. The commit
// happens before the caller sends any reply.
func (s *Store) tx(ctx context.Context, fn func(*sql.Tx) error) error {
	t, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	if err := fn(t); err != nil {
		_ = t.Rollback()
		return err
	}
	if err := t.Commit(); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	return nil
}

// NewRequest describes a request to record.
type NewRequest struct {
	RequestIDHash   string
	NonceHash       string
	Name            string
	Method          string
	SourceIP        string
	CallbackAddress string
	CEVersion       string
	UserCode        string // approval only
	Status          string
	TTL             time.Duration
	PollInterval    time.Duration
	// MaxPerSource and MaxTotal, when positive, cap live (pending or
	// callback-pending, unexpired) requests from the source's network
	// (SourceNet) and in total. The count and the insert are one transaction.
	MaxPerSource int
	MaxTotal     int
}

// ErrUserCodeTaken reports a user-code collision; the caller draws another.
var ErrUserCodeTaken = errors.New("user code already in use")

// CapError reports a request refused by the pending-request caps.
type CapError struct {
	PerSource bool   // the per-network cap, not the global one
	Net       string // the source network counted
}

func (e *CapError) Error() string {
	if e.PerSource {
		return "too many pending requests from " + e.Net
	}
	return "too many pending requests"
}

// SourceNet is the network a source address is counted under for the
// per-source cap: an IPv6 address's /64 (one site or one host can hold a
// whole /64) and an IPv4 address itself.
func SourceNet(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	a = a.Unmap().WithZone("")
	if a.Is4() {
		return a.String()
	}
	p, err := a.Prefix(64)
	if err != nil {
		return a.String()
	}
	return p.String()
}

// CreateRequest records a new request and returns its number. It refuses
// with a *CapError when the request would exceed r's caps. A CEVersion that
// is not a plain version string is recorded as empty.
func (s *Store) CreateRequest(ctx context.Context, r NewRequest) (int64, error) {
	if !validCEVersion(r.CEVersion) {
		r.CEVersion = ""
	}
	var number int64
	err := s.tx(ctx, func(t *sql.Tx) error {
		now := s.now()
		srcNet := SourceNet(r.SourceIP)
		if r.MaxPerSource > 0 || r.MaxTotal > 0 {
			var perSource, total int
			if err := t.QueryRowContext(ctx, `SELECT
				COALESCE(SUM(CASE WHEN source_net = ? THEN 1 ELSE 0 END), 0), COUNT(*)
				FROM requests WHERE status IN (?, ?) AND expires_at > ?`,
				srcNet, ReqPending, ReqCallbackPending, now.Unix()).Scan(&perSource, &total); err != nil {
				return fmt.Errorf("store: counting pending requests: %w", err)
			}
			if r.MaxPerSource > 0 && perSource >= r.MaxPerSource {
				return &CapError{PerSource: true, Net: srcNet}
			}
			if r.MaxTotal > 0 && total >= r.MaxTotal {
				return &CapError{}
			}
		}
		var code any
		if r.UserCode != "" {
			code = r.UserCode
		}
		res, err := t.ExecContext(ctx, `INSERT INTO requests
			(request_id_hash, nonce_hash, name, method, source_ip, source_net, callback_address, ce_version,
			 user_code, status, created_at, expires_at, poll_interval)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			r.RequestIDHash, r.NonceHash, NormalizeName(r.Name), r.Method, r.SourceIP, srcNet, r.CallbackAddress,
			r.CEVersion, code, r.Status, now.Unix(), now.Add(r.TTL).Unix(), int64(r.PollInterval/time.Second))
		if err != nil {
			if r.UserCode != "" && strings.Contains(err.Error(), "UNIQUE") && strings.Contains(err.Error(), "user_code") {
				return ErrUserCodeTaken
			}
			return fmt.Errorf("store: inserting request: %w", err)
		}
		number, err = res.LastInsertId()
		return err
	})
	if err != nil {
		return 0, err
	}
	return number, nil
}

const requestCols = `id, name, method, source_ip, callback_address, ce_version, COALESCE(user_code, ''),
	status, created_at, expires_at, decided_at, decided_by, reason, registration_id,
	poll_interval, last_poll_at, nonce_hash`

type scanner interface{ Scan(dest ...any) error }

func scanRequest(row scanner) (*RequestRecord, error) {
	var r RequestRecord
	var created, expires, decided, pollInterval, lastPoll int64
	if err := row.Scan(&r.Number, &r.Name, &r.Method, &r.SourceIP, &r.CallbackAddress, &r.CEVersion,
		&r.UserCode, &r.Status, &created, &expires, &decided, &r.DecidedBy, &r.Reason, &r.RegistrationID,
		&pollInterval, &lastPoll, &r.nonceHash); err != nil {
		return nil, err
	}
	r.CreatedAt, r.ExpiresAt, r.DecidedAt = fromUnix(created), fromUnix(expires), fromUnix(decided)
	r.PollInterval, r.LastPollAt = time.Duration(pollInterval)*time.Second, fromUnix(lastPoll)
	return &r, nil
}

// ErrNotFound reports a missing request or registration.
var ErrNotFound = errors.New("not found")

// RequestByNumber returns a request by its number.
func (s *Store) RequestByNumber(ctx context.Context, n int64) (*RequestRecord, error) {
	r, err := scanRequest(s.db.QueryRowContext(ctx, `SELECT `+requestCols+` FROM requests WHERE id = ?`, n))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return r, err
}

// RequestByUserCode returns a request by its (normalized) user code.
func (s *Store) RequestByUserCode(ctx context.Context, code string) (*RequestRecord, error) {
	r, err := scanRequest(s.db.QueryRowContext(ctx, `SELECT `+requestCols+` FROM requests WHERE user_code = ?`, code))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return r, err
}

// FinishRequest sets a request's final status (callback outcomes).
func (s *Store) FinishRequest(ctx context.Context, n int64, status, reason, registrationID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE requests SET status = ?, reason = ?, registration_id = ?, decided_at = ?
		WHERE id = ?`, status, reason, registrationID, s.now().Unix(), n)
	if err != nil {
		return fmt.Errorf("store: finishing request %d: %w", n, err)
	}
	return nil
}

// ErrNotPending reports a decision on a request that is not awaiting one.
var ErrNotPending = errors.New("request is not pending approval")

// Decide approves or denies a pending, unexpired approval-mode request.
func (s *Store) Decide(ctx context.Context, n int64, approve bool, by Identity, reason string) error {
	_, err := s.DecideChecked(ctx, n, approve, by, reason, DecideOptions{})
	return err
}

// DecideOptions are the checks an approval from the command line makes.
type DecideOptions struct {
	// ExpectName, when set, is the name the approver expects the request to
	// carry; a request for another name is refused with a *NameMismatchError.
	ExpectName string
	// RefuseActive refuses (with an *ActiveRegistrationError) to approve a
	// request whose name already has an active registration, unless Replace
	// is set; Replace revokes the name's active approval-mode registrations
	// in the same transaction.
	RefuseActive bool
	Replace      bool
}

// NameMismatchError reports an approval naming a different CE than the
// request carries.
type NameMismatchError struct{ Request, Expected string }

func (e *NameMismatchError) Error() string {
	return fmt.Sprintf("the request is for %s, not %s", e.Request, e.Expected)
}

// ActiveRegistrationError reports an approval for a name that already has an
// active registration.
type ActiveRegistrationError struct {
	Name string
	IDs  []string
}

func (e *ActiveRegistrationError) Error() string {
	return fmt.Sprintf("%s already has an active registration (%s); approve with --replace to replace it",
		e.Name, strings.Join(e.IDs, ", "))
}

// DecideChecked is Decide with opts' checks. It returns the registrations
// revoked by Replace.
func (s *Store) DecideChecked(ctx context.Context, n int64, approve bool, by Identity, reason string,
	opts DecideOptions) ([]*RegistrationRecord, error) {
	var replaced []*RegistrationRecord
	err := s.tx(ctx, func(t *sql.Tx) error {
		r, err := scanRequest(t.QueryRowContext(ctx, `SELECT `+requestCols+` FROM requests WHERE id = ?`, n))
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		now := s.now()
		if r.Method != protocol.MethodApproval || r.Status != ReqPending {
			return fmt.Errorf("%w (status %s)", ErrNotPending, r.Status)
		}
		if !now.Before(r.ExpiresAt) {
			return fmt.Errorf("%w (expired)", ErrNotPending)
		}
		if approve && opts.ExpectName != "" && NormalizeName(opts.ExpectName) != r.Name {
			return &NameMismatchError{Request: r.Name, Expected: NormalizeName(opts.ExpectName)}
		}
		if approve && opts.RefuseActive {
			active, err := activeRegistrations(ctx, t, r.Name)
			if err != nil {
				return err
			}
			if len(active) > 0 && !opts.Replace {
				e := &ActiveRegistrationError{Name: r.Name}
				for _, a := range active {
					e.IDs = append(e.IDs, a.Method+" "+a.ID)
				}
				return e
			}
			for _, a := range active {
				if a.Method != protocol.MethodApproval {
					continue // revoking a callback registration would bar the name from callback
				}
				if err := revokeTx(ctx, t, a.ID, now, by.String(), fmt.Sprintf("replaced by request %d", n)); err != nil {
					return err
				}
				a.Status = RegRevoked
				replaced = append(replaced, a)
			}
		}
		status := ReqDenied
		if approve {
			status = ReqApproved
		}
		_, err = t.ExecContext(ctx, `UPDATE requests SET status = ?, decided_at = ?, decided_by = ?, reason = ?
			WHERE id = ?`, status, now.Unix(), by.String(), reason, n)
		return err
	})
	if err != nil {
		return nil, err
	}
	return replaced, nil
}

func activeRegistrations(ctx context.Context, t *sql.Tx, name string) ([]*RegistrationRecord, error) {
	rows, err := t.QueryContext(ctx, `SELECT `+registrationCols+` FROM registrations WHERE name = ? AND status IN (?, ?)`,
		NormalizeName(name), RegActive, RegPendingAck)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []*RegistrationRecord
	for rows.Next() {
		r, err := scanRegistration(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func revokeTx(ctx context.Context, t *sql.Tx, regID string, now time.Time, by, reason string) error {
	_, err := t.ExecContext(ctx, `UPDATE registrations SET status = ?, revoked_at = ?, revoked_by = ?,
		revoke_reason = ?, updated_at = ? WHERE registration_id = ?`,
		RegRevoked, now.Unix(), by, reason, now.Unix(), regID)
	return err
}

// MintFunc mints a token for a CE name.
type MintFunc func(name string) (*mint.Token, error)

func insertIssued(ctx context.Context, t *sql.Tx, regID, name, method, reason string, tok *mint.Token) error {
	_, err := t.ExecContext(ctx, `INSERT INTO issued_tokens
		(jti, registration_id, name, subject, method, reason, issued_at, expires_at) VALUES (?,?,?,?,?,?,?,?)`,
		tok.JTI, regID, name, tok.Subject, method, reason, tok.IssuedAt.Unix(), tok.Expiry.Unix())
	if err != nil {
		return fmt.Errorf("store: recording token %s: %w", tok.JTI, err)
	}
	return nil
}

// PollResult is the outcome of a REG_POLL.
type PollResult struct {
	Status   string // a protocol.Status* value
	Interval time.Duration
	Request  *RequestRecord
	// Set when Status is approved.
	RegistrationID string
	Token          *mint.Token
	RefreshSecret  string
}

// PollOptions are the registrar policies Poll applies.
type PollOptions struct {
	// UnclaimedTTL is how long an approved request may go unclaimed.
	UnclaimedTTL time.Duration
	// SlowDownStep is added to a request's interval when it polls too early.
	SlowDownStep time.Duration
}

// Poll answers REG_POLL. An approved,
// unclaimed request yields a freshly minted token and a new first secret,
// which replaces the registration's pending secret; once the CE has proven a
// secret with REG_RENEW the request is claimed and polling it yields nothing.
//
// Polling an approved request is throttled like polling a pending one: a poll
// sooner than the request's interval is told to slow down. Each re-mint for a
// request that already minted (an honest CE re-polls only when it lost the
// reply) also grows the interval, so a holder of the request id and nonce
// cannot mint a token per interval for long.
func (s *Store) Poll(ctx context.Context, requestID, nonce string, opts PollOptions, mintFn MintFunc) (*PollResult, error) {
	var out *PollResult
	err := s.tx(ctx, func(t *sql.Tx) error {
		r, err := scanRequest(t.QueryRowContext(ctx, `SELECT `+requestCols+` FROM requests
			WHERE request_id_hash = ? AND method = ?`, secret.Hash(requestID), protocol.MethodApproval))
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if !secret.Matches(nonce, r.nonceHash) {
			return ErrNotFound
		}
		now := s.now()
		out = &PollResult{Request: r, Interval: r.PollInterval}

		// Rate: a poll sooner than the interval is told to slow down, and the
		// interval grows (RFC 8628 §3.5).
		if !r.LastPollAt.IsZero() && now.Sub(r.LastPollAt) < r.PollInterval &&
			(r.Status == ReqPending || r.Status == ReqApproved) {
			out.Interval = r.PollInterval + opts.SlowDownStep
			out.Status = protocol.StatusSlowDown
			_, err := t.ExecContext(ctx, `UPDATE requests SET poll_interval = ?, last_poll_at = ? WHERE id = ?`,
				int64(out.Interval/time.Second), now.Unix(), r.Number)
			return err
		}
		if _, err := t.ExecContext(ctx, `UPDATE requests SET last_poll_at = ? WHERE id = ?`, now.Unix(), r.Number); err != nil {
			return err
		}

		switch r.Status {
		case ReqPending:
			if !now.Before(r.ExpiresAt) {
				out.Status = protocol.StatusExpired
				_, err := t.ExecContext(ctx, `UPDATE requests SET status = ? WHERE id = ?`, ReqExpired, r.Number)
				return err
			}
			out.Status = protocol.StatusPending
			return nil
		case ReqDenied:
			out.Status = protocol.StatusDenied
			return nil
		case ReqExpired:
			out.Status = protocol.StatusExpired
			return nil
		case ReqClaimed:
			out.Status = protocol.StatusClaimed
			return nil
		case ReqApproved:
		default:
			out.Status = protocol.StatusExpired
			return nil
		}

		return s.pollApproved(ctx, t, r, now, opts, mintFn, out)
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// pollApproved answers a poll of an approved request: it mints the first
// token, or re-mints one for a re-poll before the first renewal.
func (s *Store) pollApproved(ctx context.Context, t *sql.Tx, r *RequestRecord, now time.Time, opts PollOptions,
	mintFn MintFunc, out *PollResult) error {
	// Approved. Unclaimed requests are kept for UnclaimedTTL.
	if opts.UnclaimedTTL > 0 && now.Sub(r.DecidedAt) > opts.UnclaimedTTL {
		out.Status = protocol.StatusExpired
		_, err := t.ExecContext(ctx, `UPDATE requests SET status = ? WHERE id = ?`, ReqExpired, r.Number)
		return err
	}
	regID := r.RegistrationID
	if regID != "" {
		reg, err := scanRegistration(t.QueryRowContext(ctx, `SELECT `+registrationCols+` FROM registrations
			WHERE registration_id = ?`, regID))
		if err != nil {
			return fmt.Errorf("store: registration %s of request %d: %w", regID, r.Number, err)
		}
		switch reg.Status {
		case RegActive:
		case RegRevoked:
			out.Status = protocol.StatusRevoked
			return nil
		default:
			out.Status = protocol.StatusExpired
			return nil
		}
		if reg.secrets.Current != "" {
			// The CE already proved a secret; re-polling must not mint.
			out.Status = protocol.StatusClaimed
			_, err := t.ExecContext(ctx, `UPDATE requests SET status = ? WHERE id = ?`, ReqClaimed, r.Number)
			return err
		}
		// A re-mint: grow the interval the next one must wait.
		out.Interval = r.PollInterval + opts.SlowDownStep
		if _, err := t.ExecContext(ctx, `UPDATE requests SET poll_interval = ? WHERE id = ?`,
			int64(out.Interval/time.Second), r.Number); err != nil {
			return err
		}
	}

	tok, err := mintFn(r.Name)
	if err != nil {
		return err
	}
	first, err := secret.NewSecret()
	if err != nil {
		return err
	}
	if regID == "" {
		if regID, err = secret.NewID(); err != nil {
			return err
		}
		_, err = t.ExecContext(ctx, `INSERT INTO registrations
			(registration_id, name, method, status, approver, request_number, source_ip,
			 created_at, updated_at, last_issued_at, token_expiry, pending_hash)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
			regID, r.Name, protocol.MethodApproval, RegActive, r.DecidedBy, r.Number, r.SourceIP,
			now.Unix(), now.Unix(), now.Unix(), tok.Expiry.Unix(), secret.Hash(first))
		if err != nil {
			return fmt.Errorf("store: creating registration: %w", err)
		}
		if _, err := t.ExecContext(ctx, `UPDATE requests SET registration_id = ? WHERE id = ?`, regID, r.Number); err != nil {
			return err
		}
	} else {
		// Re-poll before the first REG_RENEW: re-mint and replace pending.
		// The replaced first secret is not recorded as superseded: only
		// the holder of the request id and nonce could have received it,
		// and presenting it is a plain reject.
		_, err = t.ExecContext(ctx, `UPDATE registrations SET pending_hash = ?, updated_at = ?,
			last_issued_at = ?, token_expiry = ? WHERE registration_id = ?`,
			secret.Hash(first), now.Unix(), now.Unix(), tok.Expiry.Unix(), regID)
		if err != nil {
			return err
		}
	}
	if err := insertIssued(ctx, t, regID, r.Name, protocol.MethodApproval, "poll", tok); err != nil {
		return err
	}
	out.Status = protocol.StatusApproved
	out.RegistrationID, out.Token, out.RefreshSecret = regID, tok, first
	return nil
}

const registrationCols = `registration_id, name, method, status, approver, request_number, source_ip,
	created_at, updated_at, last_issued_at, token_expiry, current_hash, pending_hash, retired_hashes,
	replaced_hashes, reissues, revoked_at, revoked_by, revoke_reason`

func scanRegistration(row scanner) (*RegistrationRecord, error) {
	var r RegistrationRecord
	var created, updated, issued, expiry, revoked int64
	var retired, replaced string
	if err := row.Scan(&r.ID, &r.Name, &r.Method, &r.Status, &r.Approver, &r.RequestNumber, &r.SourceIP,
		&created, &updated, &issued, &expiry, &r.secrets.Current, &r.secrets.Pending, &retired,
		&replaced, &r.secrets.Reissues, &revoked, &r.RevokedBy, &r.RevokeReason); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(retired), &r.secrets.Retired); err != nil {
		return nil, fmt.Errorf("store: registration %s: retired hashes: %w", r.ID, err)
	}
	if err := json.Unmarshal([]byte(replaced), &r.secrets.Replaced); err != nil {
		return nil, fmt.Errorf("store: registration %s: replaced hashes: %w", r.ID, err)
	}
	r.CreatedAt, r.UpdatedAt = fromUnix(created), fromUnix(updated)
	r.LastIssuedAt, r.TokenExpiry, r.RevokedAt = fromUnix(issued), fromUnix(expiry), fromUnix(revoked)
	return &r, nil
}

// Registration returns a registration by id.
func (s *Store) Registration(ctx context.Context, id string) (*RegistrationRecord, error) {
	r, err := scanRegistration(s.db.QueryRowContext(ctx, `SELECT `+registrationCols+` FROM registrations
		WHERE registration_id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return r, err
}

// Secrets returns a registration's secret state (hashes), for tests and
// diagnostics.
func (r *RegistrationRecord) Secrets() SecretState { return r.secrets }

// RenewOptions are the registrar policies Renew applies.
type RenewOptions struct {
	// MaxAge, when positive, caps a registration's age
	// (HTC_REGISTRATIOND_MAX_REGISTRATION_AGE).
	MaxAge time.Duration
	// IdleLifetime, when positive, is how long a refresh secret stays usable
	// after the registration's last successful issuance
	// (HTC_REGISTRATIOND_REFRESH_IDLE_LIFETIME). It is independent of the
	// token's lifetime: an expired token is renewed like any other.
	IdleLifetime time.Duration
	// MaxReissues, when positive, is how many consecutive reissues (the
	// current secret presented, the pending one never proven) a
	// registration may have; one more revokes it
	// (HTC_REGISTRATIOND_MAX_REISSUES).
	MaxReissues int
	// Recheck, when set, is asked whether the original approver may still
	// approve the name (HTC_REGISTRATIOND_RECHECK_APPROVER).
	Recheck func(ctx context.Context, approver Identity, name string) (bool, error)
}

// RenewError is a refused renewal.
type RenewError struct {
	Code   int // a protocol.Err* value
	Reason string
}

func (e *RenewError) Error() string { return e.Reason }

// RenewResult is a successful renewal.
type RenewResult struct {
	Action        RenewAction
	Registration  *RegistrationRecord
	Token         *mint.Token
	RefreshSecret string // the new pending secret
}

// expiredBy returns why reg has expired at now under opts' age limits, or "".
func expiredBy(reg *RegistrationRecord, now time.Time, opts RenewOptions) string {
	if opts.MaxAge > 0 && now.Sub(reg.CreatedAt) > opts.MaxAge {
		return "registration exceeded its maximum age"
	}
	lastUse := reg.LastIssuedAt
	if lastUse.IsZero() {
		lastUse = reg.CreatedAt
	}
	if opts.IdleLifetime > 0 && now.Sub(lastUse) > opts.IdleLifetime {
		return "the refresh secret was not used for too long"
	}
	return ""
}

func marshalHashes(list []string) (string, error) {
	if list == nil {
		return "[]", nil
	}
	b, err := json.Marshal(list)
	return string(b), err
}

// Renew answers REG_RENEW: it classifies the presented
// secret against the registration's current / pending / superseded hashes and
// applies the result in one transaction, which commits before the caller
// replies. A superseded secret, or one reissue too many, revokes the
// registration.
func (s *Store) Renew(ctx context.Context, regID, presented string, opts RenewOptions, mintFn MintFunc) (*RenewResult, error) {
	var out *RenewResult
	var refusal error
	err := s.tx(ctx, func(t *sql.Tx) error {
		reg, err := scanRegistration(t.QueryRowContext(ctx, `SELECT `+registrationCols+` FROM registrations
			WHERE registration_id = ? AND method = ?`, regID, protocol.MethodApproval))
		if errors.Is(err, sql.ErrNoRows) {
			refusal = &RenewError{Code: protocol.ErrUnknown, Reason: "unknown registration"}
			return nil
		}
		if err != nil {
			return err
		}
		now := s.now()
		switch reg.Status {
		case RegActive:
		case RegRevoked:
			refusal = &RenewError{Code: protocol.ErrRevoked, Reason: "registration is revoked"}
			return nil
		default:
			refusal = &RenewError{Code: protocol.ErrExpired, Reason: "registration is " + reg.Status}
			return nil
		}

		revoke := func(reason, reply string) error {
			if err := revokeTx(ctx, t, reg.ID, now, "registrar", reason); err != nil {
				return err
			}
			reg.Status, reg.RevokeReason = RegRevoked, reason
			refusal = &RenewError{Code: protocol.ErrRevoked, Reason: reply}
			out = &RenewResult{Action: RenewReuse, Registration: reg}
			return nil
		}
		action := Classify(reg.secrets, presented)
		switch action {
		case RenewReject:
			refusal = &RenewError{Code: protocol.ErrUnknown, Reason: "refresh secret does not match"}
			return nil
		case RenewReuse:
			return revoke("reuse of a superseded refresh secret",
				"a superseded refresh secret was presented; the registration is revoked")
		}

		// Policies that refuse without consuming the secret.
		if why := expiredBy(reg, now, opts); why != "" {
			if _, err := t.ExecContext(ctx, `UPDATE registrations SET status = ?, updated_at = ? WHERE registration_id = ?`,
				RegExpired, now.Unix(), reg.ID); err != nil {
				return err
			}
			refusal = &RenewError{Code: protocol.ErrExpired, Reason: why}
			return nil
		}
		if action == RenewReissue && opts.MaxReissues > 0 && reg.secrets.Reissues >= opts.MaxReissues {
			err := revoke(fmt.Sprintf("the current refresh secret was presented %d times in a row without the pending one being proven",
				reg.secrets.Reissues+1),
				"too many renewals with the current refresh secret; the registration is revoked")
			out.Action = RenewReissue
			return err
		}
		if opts.Recheck != nil {
			ok, err := opts.Recheck(ctx, ParseIdentity(reg.Approver), reg.Name)
			if err != nil {
				return fmt.Errorf("re-checking approver %s: %w", reg.Approver, err)
			}
			if !ok {
				refusal = &RenewError{Code: protocol.ErrNotAuthorized,
					Reason: fmt.Sprintf("approver %s is no longer authorized for %s", reg.Approver, reg.Name)}
				return nil
			}
		}

		tok, err := mintFn(reg.Name)
		if err != nil {
			return err
		}
		next, err := secret.NewSecret()
		if err != nil {
			return err
		}
		st := Apply(reg.secrets, action, secret.Hash(next))
		retired, err := marshalHashes(st.Retired)
		if err != nil {
			return err
		}
		replaced, err := marshalHashes(st.Replaced)
		if err != nil {
			return err
		}
		_, err = t.ExecContext(ctx, `UPDATE registrations SET current_hash = ?, pending_hash = ?, retired_hashes = ?,
			replaced_hashes = ?, reissues = ?, updated_at = ?, last_issued_at = ?, token_expiry = ?
			WHERE registration_id = ?`,
			st.Current, st.Pending, retired, replaced, st.Reissues, now.Unix(), now.Unix(), tok.Expiry.Unix(), reg.ID)
		if err != nil {
			return fmt.Errorf("store: updating registration %s: %w", reg.ID, err)
		}
		if err := insertIssued(ctx, t, reg.ID, reg.Name, protocol.MethodApproval, "renew-"+action.String(), tok); err != nil {
			return err
		}
		// The first proven secret claims the approved request.
		if reg.RequestNumber != 0 {
			if _, err := t.ExecContext(ctx, `UPDATE requests SET status = ? WHERE id = ? AND status = ?`,
				ReqClaimed, reg.RequestNumber, ReqApproved); err != nil {
				return err
			}
		}
		reg.secrets = st
		reg.LastIssuedAt, reg.TokenExpiry = now, tok.Expiry
		out = &RenewResult{Action: action, Registration: reg, Token: tok, RefreshSecret: next}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if refusal != nil {
		if out != nil {
			return out, refusal
		}
		return nil, refusal
	}
	return out, nil
}

// CallbackRegistration returns the callback-mode registration for name,
// creating it (in RegPendingAck) if there is none, and records the token about
// to be delivered. It refuses a name whose callback registration is revoked.
func (s *Store) CallbackRegistration(ctx context.Context, requestNumber int64, name, sourceIP string, tok *mint.Token) (string, error) {
	var regID string
	name = NormalizeName(name)
	err := s.tx(ctx, func(t *sql.Tx) error {
		now := s.now()
		reg, err := scanRegistration(t.QueryRowContext(ctx, `SELECT `+registrationCols+` FROM registrations
			WHERE name = ? AND method = ? ORDER BY created_at DESC LIMIT 1`, name, protocol.MethodCallback))
		switch {
		case errors.Is(err, sql.ErrNoRows):
			if regID, err = secret.NewID(); err != nil {
				return err
			}
			_, err = t.ExecContext(ctx, `INSERT INTO registrations
				(registration_id, name, method, status, request_number, source_ip, created_at, updated_at)
				VALUES (?,?,?,?,?,?,?,?)`, regID, name, protocol.MethodCallback, RegPendingAck, requestNumber,
				sourceIP, now.Unix(), now.Unix())
			if err != nil {
				return fmt.Errorf("store: creating callback registration: %w", err)
			}
		case err != nil:
			return err
		case reg.Status == RegRevoked:
			return &RenewError{Code: protocol.ErrRevoked, Reason: fmt.Sprintf("registrations for %s are revoked", name)}
		default:
			regID = reg.ID
		}
		return insertIssued(ctx, t, regID, name, protocol.MethodCallback, "callback", tok)
	})
	return regID, err
}

// CallbackAcknowledged marks a callback registration active after the CE
// acknowledged the token, and the request issued.
func (s *Store) CallbackAcknowledged(ctx context.Context, requestNumber int64, regID, sourceIP string, tok *mint.Token) error {
	return s.tx(ctx, func(t *sql.Tx) error {
		now := s.now().Unix()
		if _, err := t.ExecContext(ctx, `UPDATE registrations SET status = ?, updated_at = ?, last_issued_at = ?,
			token_expiry = ?, request_number = ?, source_ip = ? WHERE registration_id = ? AND status != ?`,
			RegActive, now, tok.IssuedAt.Unix(), tok.Expiry.Unix(), requestNumber, sourceIP, regID, RegRevoked); err != nil {
			return err
		}
		_, err := t.ExecContext(ctx, `UPDATE requests SET status = ?, registration_id = ?, decided_at = ? WHERE id = ?`,
			ReqIssued, regID, now, requestNumber)
		return err
	})
}

// NameRevoked reports whether name's callback registration is revoked.
func (s *Store) NameRevoked(ctx context.Context, name string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM registrations WHERE name = ? AND method = ? AND status = ?`,
		NormalizeName(name), protocol.MethodCallback, RegRevoked).Scan(&n)
	return n > 0, err
}

// Revoke revokes a registration by id, or every non-revoked registration of a
// name, and returns the revoked records.
func (s *Store) Revoke(ctx context.Context, regID, name string, by Identity, reason string) ([]*RegistrationRecord, error) {
	if (regID == "") == (name == "") {
		return nil, fmt.Errorf("store: revoke needs exactly one of a registration id or a name")
	}
	var out []*RegistrationRecord
	err := s.tx(ctx, func(t *sql.Tx) error {
		q := `SELECT ` + registrationCols + ` FROM registrations WHERE status != ? AND `
		arg := regID
		if regID != "" {
			q += `registration_id = ?`
		} else {
			q += `name = ?`
			arg = NormalizeName(name)
		}
		rows, err := t.QueryContext(ctx, q, RegRevoked, arg)
		if err != nil {
			return err
		}
		for rows.Next() {
			r, err := scanRegistration(rows)
			if err != nil {
				_ = rows.Close()
				return err
			}
			out = append(out, r)
		}
		if err := rows.Close(); err != nil {
			return err
		}
		now := s.now()
		for _, r := range out {
			if err := revokeTx(ctx, t, r.ID, now, by.String(), reason); err != nil {
				return err
			}
			r.Status = RegRevoked
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, ErrNotFound
	}
	return out, nil
}

// ListRequests returns requests created since the given time, newest first.
func (s *Store) ListRequests(ctx context.Context, since time.Time) ([]*RequestRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+requestCols+` FROM requests WHERE created_at >= ? ORDER BY id DESC`, unix(since))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []*RequestRecord
	for rows.Next() {
		r, err := scanRequest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListRegistrations returns every registration, newest first.
func (s *Store) ListRegistrations(ctx context.Context) ([]*RegistrationRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+registrationCols+` FROM registrations ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []*RegistrationRecord
	for rows.Next() {
		r, err := scanRegistration(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// IssuedTokenCount returns how many tokens were issued for a registration.
func (s *Store) IssuedTokenCount(ctx context.Context, regID string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM issued_tokens WHERE registration_id = ?`, regID).Scan(&n)
	return n, err
}

// MaintainOptions are Maintain's retention policies.
type MaintainOptions struct {
	// Retain is how long finished requests are kept (0: forever).
	Retain time.Duration
	// UnclaimedTTL expires approved requests not claimed within it.
	UnclaimedTTL time.Duration
	// TokenRetention is how long an issued token is kept on record past its
	// expiry (0: forever).
	TokenRetention time.Duration
}

// Maintain expires pending requests past their TTL and approved requests
// unclaimed past UnclaimedTTL, deletes finished requests older than Retain,
// and deletes issued-token records expired for longer than TokenRetention.
// Registrations are kept.
func (s *Store) Maintain(ctx context.Context, opts MaintainOptions) error {
	now := s.now()
	if _, err := s.db.ExecContext(ctx, `UPDATE requests SET status = ? WHERE status IN (?, ?) AND expires_at <= ?`,
		ReqExpired, ReqPending, ReqCallbackPending, now.Unix()); err != nil {
		return fmt.Errorf("store: expiring requests: %w", err)
	}
	if opts.UnclaimedTTL > 0 {
		if _, err := s.db.ExecContext(ctx, `UPDATE requests SET status = ? WHERE status = ? AND decided_at < ?`,
			ReqExpired, ReqApproved, now.Add(-opts.UnclaimedTTL).Unix()); err != nil {
			return fmt.Errorf("store: expiring unclaimed requests: %w", err)
		}
	}
	if opts.Retain > 0 {
		if _, err := s.db.ExecContext(ctx, `DELETE FROM requests WHERE status IN (?, ?, ?, ?, ?) AND created_at < ?`,
			ReqExpired, ReqDenied, ReqFailed, ReqIssued, ReqClaimed, now.Add(-opts.Retain).Unix()); err != nil {
			return fmt.Errorf("store: purging requests: %w", err)
		}
	}
	if opts.TokenRetention > 0 {
		if _, err := s.db.ExecContext(ctx, `DELETE FROM issued_tokens WHERE expires_at < ?`,
			now.Add(-opts.TokenRetention).Unix()); err != nil {
			return fmt.Errorf("store: purging issued tokens: %w", err)
		}
	}
	return nil
}
