package webui

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/bbockelm/htc-registrationd/internal/secret"
)

// Sessions and in-flight logins live in the registrar's database. Session
// ids and login states are stored only as hashes; the cookie carries the
// value.
const sessionSchema = `
CREATE TABLE IF NOT EXISTS web_sessions (
	id_hash      TEXT PRIMARY KEY,
	principal    TEXT NOT NULL,
	display_name TEXT NOT NULL DEFAULT '',
	csrf         TEXT NOT NULL,
	created_at   INTEGER NOT NULL,
	last_seen_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS web_logins (
	state_hash TEXT PRIMARY KEY,
	verifier   TEXT NOT NULL,
	next       TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL
);
`

// loginTTL bounds how long a login may take at the identity provider.
const loginTTL = 10 * time.Minute

// touchEvery limits how often a session's last-seen time is written.
const touchEvery = time.Minute

// session is a logged-in browser.
type session struct {
	Principal   string
	DisplayName string
	CSRF        string
	CreatedAt   time.Time
	LastSeen    time.Time
}

type sessionStore struct {
	db       *sql.DB
	now      func() time.Time
	idle     time.Duration
	lifetime time.Duration
}

var errNoSession = errors.New("no session")

func newSessionStore(ctx context.Context, db *sql.DB, now func() time.Time, idle, lifetime time.Duration) (*sessionStore, error) {
	if _, err := db.ExecContext(ctx, sessionSchema); err != nil {
		return nil, fmt.Errorf("webui: creating session tables: %w", err)
	}
	return &sessionStore{db: db, now: now, idle: idle, lifetime: lifetime}, nil
}

// create starts a session and returns its id (the cookie value).
func (s *sessionStore) create(ctx context.Context, principal, display string) (string, *session, error) {
	id, err := secret.NewSecret()
	if err != nil {
		return "", nil, err
	}
	csrf, err := secret.NewSecret()
	if err != nil {
		return "", nil, err
	}
	now := s.now()
	_, err = s.db.ExecContext(ctx, `INSERT INTO web_sessions
		(id_hash, principal, display_name, csrf, created_at, last_seen_at) VALUES (?,?,?,?,?,?)`,
		secret.Hash(id), principal, display, csrf, now.Unix(), now.Unix())
	if err != nil {
		return "", nil, fmt.Errorf("webui: creating session: %w", err)
	}
	return id, &session{Principal: principal, DisplayName: display, CSRF: csrf, CreatedAt: now, LastSeen: now}, nil
}

// get returns the live session with id, refreshing its idle timer. An
// idle or over-age session is deleted and errNoSession returned.
func (s *sessionStore) get(ctx context.Context, id string) (*session, error) {
	if id == "" {
		return nil, errNoSession
	}
	h := secret.Hash(id)
	var sess session
	var created, seen int64
	err := s.db.QueryRowContext(ctx, `SELECT principal, display_name, csrf, created_at, last_seen_at
		FROM web_sessions WHERE id_hash = ?`, h).Scan(&sess.Principal, &sess.DisplayName, &sess.CSRF, &created, &seen)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNoSession
	}
	if err != nil {
		return nil, err
	}
	sess.CreatedAt, sess.LastSeen = time.Unix(created, 0), time.Unix(seen, 0)
	now := s.now()
	if now.Sub(sess.LastSeen) > s.idle || now.Sub(sess.CreatedAt) > s.lifetime {
		_, _ = s.db.ExecContext(ctx, `DELETE FROM web_sessions WHERE id_hash = ?`, h)
		return nil, errNoSession
	}
	if now.Sub(sess.LastSeen) >= touchEvery {
		if _, err := s.db.ExecContext(ctx, `UPDATE web_sessions SET last_seen_at = ? WHERE id_hash = ?`,
			now.Unix(), h); err != nil {
			return nil, err
		}
		sess.LastSeen = now
	}
	return &sess, nil
}

// remove ends the session with id.
func (s *sessionStore) remove(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM web_sessions WHERE id_hash = ?`, secret.Hash(id))
	return err
}

// saveLogin records an authorization request in flight.
func (s *sessionStore) saveLogin(ctx context.Context, state, verifier, next string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO web_logins (state_hash, verifier, next, created_at) VALUES (?,?,?,?)`,
		secret.Hash(state), verifier, next, s.now().Unix())
	if err != nil {
		return fmt.Errorf("webui: recording login: %w", err)
	}
	return nil
}

// takeLogin returns and deletes the login with state. Each state is good
// for one callback, within loginTTL.
func (s *sessionStore) takeLogin(ctx context.Context, state string) (verifier, next string, err error) {
	h := secret.Hash(state)
	var created int64
	err = s.db.QueryRowContext(ctx, `SELECT verifier, next, created_at FROM web_logins WHERE state_hash = ?`, h).
		Scan(&verifier, &next, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", errNoSession
	}
	if err != nil {
		return "", "", err
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM web_logins WHERE state_hash = ?`, h); err != nil {
		return "", "", err
	}
	if s.now().Sub(time.Unix(created, 0)) > loginTTL {
		return "", "", errNoSession
	}
	return verifier, next, nil
}

// prune deletes expired sessions and abandoned logins.
func (s *sessionStore) prune(ctx context.Context) error {
	now := s.now()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM web_sessions WHERE last_seen_at < ? OR created_at < ?`,
		now.Add(-s.idle).Unix(), now.Add(-s.lifetime).Unix()); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM web_logins WHERE created_at < ?`, now.Add(-loginTTL).Unix())
	return err
}
