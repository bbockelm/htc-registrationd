package registrar

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bbockelm/cedar/security"

	"github.com/bbockelm/htc-registrationd/internal/protocol"
	"github.com/bbockelm/htc-registrationd/internal/secret"
	"github.com/bbockelm/htc-registrationd/internal/ssrf"
)

func (f *storeFixture) newRequest(t *testing.T, name string) (string, string, int64) {
	t.Helper()
	id, _ := secret.NewID()
	nonce, _ := secret.NewSecret()
	code, _ := NewUserCode()
	n, err := f.store.CreateRequest(context.Background(), NewRequest{RequestIDHash: secret.Hash(id),
		NonceHash: secret.Hash(nonce), Name: name, Method: protocol.MethodApproval, SourceIP: "128.104.1.10", UserCode: code,
		Status: ReqPending, TTL: time.Hour, PollInterval: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return id, nonce, n
}

// Names compare without regard to case: a revoked name stays revoked in any
// spelling, and a request is stored lower-cased.
func TestNamesCaseInsensitive(t *testing.T) {
	f := newStoreFixture(t)
	ctx := context.Background()
	tok, _ := f.minter.Mint("ce.example.edu")
	regID, err := f.store.CallbackRegistration(ctx, 1, "ce.example.edu", "128.104.1.10", tok)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.CallbackAcknowledged(ctx, 1, regID, "128.104.1.10", tok); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Revoke(ctx, "", "CE.Example.EDU", Identity{Kind: "cedar", Principal: "admin"}, "test"); err != nil {
		t.Fatalf("revoking by another spelling: %v", err)
	}
	if ok, _ := f.store.NameRevoked(ctx, "CE.EXAMPLE.edu"); !ok {
		t.Fatal("the revoked name is not revoked in another spelling")
	}
	if _, err := f.store.CallbackRegistration(ctx, 2, "Ce.Example.Edu", "128.104.1.10", tok); err == nil {
		t.Fatal("a token was issued by callback for a revoked name in another spelling")
	}
	_, _, n := f.newRequest(t, "CE2.Example.EDU")
	r, _ := f.store.RequestByNumber(ctx, n)
	if r.Name != "ce2.example.edu" {
		t.Fatalf("request stored as %q", r.Name)
	}
}

// An older database with mixed-case names is lower-cased when opened.
func TestMigrationLowercasesNames(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registrar.db")
	st, err := OpenStore(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().ExecContext(context.Background(), `INSERT INTO registrations (registration_id, name, method, status, created_at, updated_at)
		VALUES ('r1', 'CE.Example.EDU', 'callback', 'revoked', 1, 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().ExecContext(context.Background(), `INSERT INTO requests (request_id_hash, nonce_hash, name, method, source_ip, status,
		created_at, expires_at) VALUES ('h', 'n', 'CE.Example.EDU', 'approval', '2607:f388:1:2:3::4', 'pending', 1, 2)`); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	st, err = OpenStore(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	if ok, _ := st.NameRevoked(context.Background(), "ce.example.edu"); !ok {
		t.Fatal("the mixed-case revoked name was not migrated")
	}
	var net string
	if err := st.DB().QueryRowContext(context.Background(), `SELECT source_net FROM requests WHERE request_id_hash = 'h'`).Scan(&net); err != nil {
		t.Fatal(err)
	}
	if net != "2607:f388:1:2::/64" {
		t.Fatalf("source_net %q", net)
	}
}

func TestSourceNet(t *testing.T) {
	for in, want := range map[string]string{
		"128.104.1.10":            "128.104.1.10",
		"::ffff:128.104.1.10":     "128.104.1.10",
		"2607:f388:1:2:3:4:5:6":   "2607:f388:1:2::/64",
		"2607:f388:1:2:ffff::1":   "2607:f388:1:2::/64",
		"fe80::1%en0":             "fe80::/64",
		"not-an-address":          "not-an-address",
		"2607:f388:1:3:3:4:5:6":   "2607:f388:1:3::/64",
		"[2607:f388:1:2:3:4:5:6]": "[2607:f388:1:2:3:4:5:6]",
	} {
		if got := SourceNet(in); got != want {
			t.Errorf("SourceNet(%q) = %q, want %q", in, got, want)
		}
	}
}

// The per-source cap counts an IPv6 /64 as one source, and the count and the
// insert are one transaction, so concurrent requests cannot overshoot it.
func TestCapsBySourceNet(t *testing.T) {
	f := newStoreFixture(t)
	ctx := context.Background()
	create := func(src string) error {
		id, _ := secret.NewID()
		_, err := f.store.CreateRequest(ctx, NewRequest{RequestIDHash: secret.Hash(id), NonceHash: "n", Name: "ce.test",
			Method: protocol.MethodCallback, SourceIP: src, Status: ReqCallbackPending, TTL: time.Minute,
			MaxPerSource: 3, MaxTotal: 5})
		return err
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if create(fmt.Sprintf("2607:f388:1:2::%x", i+1)) == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if ok != 3 {
		t.Fatalf("%d requests from one /64 accepted, want 3", ok)
	}
	var capErr *CapError
	if err := create("2607:f388:1:2:abcd::1"); !errors.As(err, &capErr) || !capErr.PerSource {
		t.Fatalf("a fourth from the /64: %v", err)
	}
	if err := create("2607:f388:1:3::1"); err != nil {
		t.Fatalf("another /64: %v", err)
	}
	if err := create("128.104.1.10"); err != nil {
		t.Fatalf("an IPv4 source: %v", err)
	}
	if err := create("128.104.1.11"); !errors.As(err, &capErr) || capErr.PerSource {
		t.Fatalf("past the global cap: %v", err)
	}
}

// Approving from the command line names the CE, which must match the
// request, and refuses a name with an active registration unless replacing.
func TestDecideChecked(t *testing.T) {
	f := newStoreFixture(t)
	ctx := context.Background()
	admin := Identity{Kind: "cedar", Principal: "admin"}
	_, _, n := f.newRequest(t, "ce.example.edu")

	var mismatch *NameMismatchError
	if _, err := f.store.DecideChecked(ctx, n, true, admin, "", DecideOptions{ExpectName: "evil.example.edu",
		RefuseActive: true}); !errors.As(err, &mismatch) || mismatch.Request != "ce.example.edu" {
		t.Fatalf("approving under another name: %v", err)
	}
	if r, _ := f.store.RequestByNumber(ctx, n); r.Status != ReqPending {
		t.Fatalf("a refused approval changed the request: %s", r.Status)
	}
	if _, err := f.store.DecideChecked(ctx, n, true, admin, "", DecideOptions{ExpectName: "CE.Example.EDU",
		RefuseActive: true}); err != nil {
		t.Fatalf("approving with the name in another case: %v", err)
	}

	// The CE claims it; a second request for the name meets an active
	// registration.
	reqID, nonce, _ := f.rekeyRequest(t, n)
	p := f.poll(t, reqID, nonce)
	_, _, n2 := f.newRequest(t, "ce.example.edu")
	var active *ActiveRegistrationError
	if _, err := f.store.DecideChecked(ctx, n2, true, admin, "", DecideOptions{ExpectName: "ce.example.edu",
		RefuseActive: true}); !errors.As(err, &active) || !strings.Contains(err.Error(), p.RegistrationID) {
		t.Fatalf("approving a name with an active registration: %v", err)
	}
	replaced, err := f.store.DecideChecked(ctx, n2, true, admin, "", DecideOptions{ExpectName: "ce.example.edu",
		RefuseActive: true, Replace: true})
	if err != nil || len(replaced) != 1 || replaced[0].ID != p.RegistrationID {
		t.Fatalf("replacing: %v %v", replaced, err)
	}
	if _, status := f.secrets(t, p.RegistrationID); status != RegRevoked {
		t.Fatalf("the replaced registration is %s", status)
	}
	// Denying needs no name.
	_, _, n3 := f.newRequest(t, "other.example.edu")
	if err := f.store.Decide(ctx, n3, false, admin, "no"); err != nil {
		t.Fatal(err)
	}
}

// rekeyRequest gives request n a request id and nonce the test knows.
func (f *storeFixture) rekeyRequest(t *testing.T, n int64) (string, string, int64) {
	t.Helper()
	id, _ := secret.NewID()
	nonce, _ := secret.NewSecret()
	if _, err := f.store.DB().ExecContext(context.Background(), `UPDATE requests SET request_id_hash = ?, nonce_hash = ? WHERE id = ?`,
		secret.Hash(id), secret.Hash(nonce), n); err != nil {
		t.Fatal(err)
	}
	return id, nonce, n
}

// Maintain expires approved requests nobody claimed, purges old finished
// requests, and drops issued-token records long past their expiry.
func TestMaintain(t *testing.T) {
	f := newStoreFixture(t)
	ctx := context.Background()
	opts := MaintainOptions{Retain: 7 * 24 * time.Hour, UnclaimedTTL: 24 * time.Hour, TokenRetention: 7 * 24 * time.Hour}
	reqID, nonce, n := f.approvedRequest(t)
	p := f.poll(t, reqID, nonce) // a token on record; the request stays approved, unclaimed

	f.clock.Advance(25 * time.Hour)
	if err := f.store.Maintain(ctx, opts); err != nil {
		t.Fatal(err)
	}
	if r, _ := f.store.RequestByNumber(ctx, n); r.Status != ReqExpired {
		t.Fatalf("approved request unclaimed past the TTL is %s, want expired", r.Status)
	}
	if c, _ := f.store.IssuedTokenCount(ctx, p.RegistrationID); c != 1 {
		t.Fatalf("issued tokens %d before their expiry + retention", c)
	}
	f.clock.Advance(10 * 24 * time.Hour)
	if err := f.store.Maintain(ctx, opts); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.RequestByNumber(ctx, n); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old expired request kept: %v", err)
	}
	if c, _ := f.store.IssuedTokenCount(ctx, p.RegistrationID); c != 0 {
		t.Fatalf("issued tokens %d long past expiry, want 0", c)
	}
	if _, err := f.store.Registration(ctx, p.RegistrationID); err != nil {
		t.Fatalf("the registration was removed: %v", err)
	}
}

// Polling an approved request whose registration expired reports expired,
// not revoked.
func TestPollReportsExpiredRegistration(t *testing.T) {
	f := newStoreFixture(t)
	reqID, nonce, _ := f.approvedRequest(t)
	p := f.poll(t, reqID, nonce)
	if _, err := f.store.DB().ExecContext(context.Background(), `UPDATE registrations SET status = ? WHERE registration_id = ?`,
		RegExpired, p.RegistrationID); err != nil {
		t.Fatal(err)
	}
	f.clock.Advance(time.Minute)
	if r := f.poll(t, reqID, nonce); r.Status != protocol.StatusExpired {
		t.Fatalf("poll status %s, want expired", r.Status)
	}
	if _, err := f.store.DB().ExecContext(context.Background(), `UPDATE registrations SET status = ? WHERE registration_id = ?`,
		RegRevoked, p.RegistrationID); err != nil {
		t.Fatal(err)
	}
	f.clock.Advance(time.Minute)
	if r := f.poll(t, reqID, nonce); r.Status != protocol.StatusRevoked {
		t.Fatalf("poll status %s, want revoked", r.Status)
	}
}

// Polling an approved request is throttled: an early poll mints nothing and
// is told to slow down, and every re-mint grows the interval.
func TestApprovedPollThrottled(t *testing.T) {
	f := newStoreFixture(t)
	ctx := context.Background()
	opts := PollOptions{UnclaimedTTL: 24 * time.Hour, SlowDownStep: 5 * time.Second}
	reqID, nonce, _ := f.approvedRequest(t)
	first := f.poll(t, reqID, nonce)
	f.clock.Advance(time.Second)
	r, err := f.store.Poll(ctx, reqID, nonce, opts, f.minter.Mint)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != protocol.StatusSlowDown || r.Token != nil {
		t.Fatalf("an early poll of an approved request: %s, token %v", r.Status, r.Token != nil)
	}
	if c, _ := f.store.IssuedTokenCount(ctx, first.RegistrationID); c != 1 {
		t.Fatalf("issued %d tokens, want 1", c)
	}
	// Re-polls after the interval re-mint (a lost reply), each growing it.
	var last time.Duration
	for i := 0; i < 3; i++ {
		f.clock.Advance(time.Hour)
		r, err := f.store.Poll(ctx, reqID, nonce, opts, f.minter.Mint)
		if err != nil || r.Status != protocol.StatusApproved {
			t.Fatalf("re-poll %d: %v %v", i, r, err)
		}
		if r.Interval <= last {
			t.Fatalf("re-poll %d: interval %s did not grow past %s", i, r.Interval, last)
		}
		last = r.Interval
	}
}

// Callback back-off is charged to the name and the requesting network: a
// requester failing callbacks for a name does not lock out the name's CE,
// and a success clears every network's back-off for the name.
func TestCallbackBackoffPerSource(t *testing.T) {
	f := newStoreFixture(t)
	svc, err := New(Config{
		Minter:           f.minter,
		SSRF:             ssrf.New(nil),
		CallbackSecurity: func() *security.SecurityConfig { return &security.SecurityConfig{} },
		Now:              f.clock.Now,
	}, f.store)
	if err != nil {
		t.Fatal(err)
	}
	attacker := callbackKeyFor("ce.example.edu", "2607:f388:dead::1")
	sibling := callbackKeyFor("ce.example.edu", "2607:f388:dead::2")
	ce := callbackKeyFor("ce.example.edu", "128.104.1.10")
	for i := 0; i < 5; i++ {
		svc.recordCallback(attacker, false)
	}
	if !svc.backedOff(attacker) || !svc.backedOff(sibling) {
		t.Fatal("the failing network (or its /64) is not backed off")
	}
	if svc.backedOff(ce) {
		t.Fatal("another network's failures locked the name's CE out")
	}
	if !svc.claimInflight(attacker) || !svc.claimInflight(ce) {
		t.Fatal("one network's callback in flight blocked another's")
	}
	svc.releaseInflight(attacker)
	svc.releaseInflight(ce)
	svc.recordCallback(ce, true)
	if svc.backedOff(attacker) {
		t.Fatal("a successful callback did not clear the name's back-off")
	}
	// The back-off expires.
	svc.recordCallback(attacker, false)
	f.clock.Advance(2 * time.Hour)
	if svc.backedOff(attacker) {
		t.Fatal("the back-off did not expire")
	}
}

// Reconfigure replaces the tunables a running service uses.
func TestServiceReconfigure(t *testing.T) {
	f := newStoreFixture(t)
	svc, err := New(Config{
		Minter:           f.minter,
		SSRF:             ssrf.New(nil),
		CallbackSecurity: func() *security.SecurityConfig { return &security.SecurityConfig{} },
		Tunables:         Tunables{PollInterval: 7 * time.Second},
	}, f.store)
	if err != nil {
		t.Fatal(err)
	}
	if got := svc.t(); got.PollInterval != 7*time.Second || got.MaxReissues != 5 ||
		got.RefreshIdleLifetime != 30*24*time.Hour {
		t.Fatalf("initial tunables %+v", got)
	}
	svc.Reconfigure(Tunables{PollInterval: 9 * time.Second, MaxReissues: 2, CallbackTimeout: time.Minute})
	if got := svc.t(); got.PollInterval != 9*time.Second || got.MaxReissues != 2 || got.CallbackTimeout != time.Minute ||
		got.ApprovalTTL != 30*time.Minute {
		t.Fatalf("reconfigured tunables %+v", got)
	}
}
