package registrar

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/bbockelm/cedar/security"

	"github.com/bbockelm/htc-registrationd/internal/mint"
	"github.com/bbockelm/htc-registrationd/internal/protocol"
	"github.com/bbockelm/htc-registrationd/internal/secret"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type storeFixture struct {
	store  *Store
	clock  *fakeClock
	minter *mint.Minter
}

func newStoreFixture(t *testing.T) *storeFixture {
	t.Helper()
	dir := t.TempDir()
	clock := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	st, err := OpenStore(filepath.Join(dir, "registrar.db"), clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	keyDir := t.TempDir()
	if err := security.GenerateSigningKey(filepath.Join(keyDir, "ce-registration")); err != nil {
		t.Fatal(err)
	}
	m := &mint.Minter{
		KeyDir: keyDir, KeyID: "ce-registration", Issuer: "pool.test", Domain: "users.test",
		Limits: []string{"ADVERTISE_SCHEDD"}, Lifetime: 72 * time.Hour,
		ReadKey: os.ReadFile, // test keys are the test user's
	}
	return &storeFixture{store: st, clock: clock, minter: m}
}

// approvedRequest records an approval request and approves it, returning the
// request id and nonce the CE holds.
func (f *storeFixture) approvedRequest(t *testing.T) (requestID, nonce string, number int64) {
	t.Helper()
	ctx := context.Background()
	requestID, _ = secret.NewID()
	nonce, _ = secret.NewSecret()
	code, _ := NewUserCode()
	number, err := f.store.CreateRequest(ctx, NewRequest{
		RequestIDHash: secret.Hash(requestID), NonceHash: secret.Hash(nonce), Name: "ce.example.edu",
		Method: protocol.MethodApproval, SourceIP: "192.0.2.10", UserCode: code, Status: ReqPending,
		TTL: 30 * time.Minute, PollInterval: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.Decide(ctx, number, true, Identity{Kind: "cedar", Principal: "admin@pool.test"}, ""); err != nil {
		t.Fatal(err)
	}
	return requestID, nonce, number
}

func (f *storeFixture) poll(t *testing.T, requestID, nonce string) *PollResult {
	t.Helper()
	f.clock.Advance(10 * time.Second) // stay clear of slow-down
	res, err := f.store.Poll(context.Background(), requestID, nonce,
		PollOptions{UnclaimedTTL: 24 * time.Hour, SlowDownStep: 5 * time.Second}, f.minter.Mint)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func (f *storeFixture) renew(regID, presented string) (*RenewResult, error) {
	return f.store.Renew(context.Background(), regID, presented, RenewOptions{}, f.minter.Mint)
}

func (f *storeFixture) secrets(t *testing.T, regID string) (SecretState, string) {
	t.Helper()
	reg, err := f.store.Registration(context.Background(), regID)
	if err != nil {
		t.Fatal(err)
	}
	return reg.Secrets(), reg.Status
}

func (f *storeFixture) verify(t *testing.T, raw string) {
	t.Helper()
	if _, err := security.VerifyIDToken(raw, &security.SecurityConfig{TokenSigningKeyDir: f.minter.KeyDir}); err != nil {
		t.Fatalf("minted token does not verify: %v", err)
	}
}

// TestRenewTable exercises every REG_RENEW case (presented secret matches
// pending, current, a retired secret, or nothing) against the store, starting from a registration with current, pending and
// retired secrets all populated.
func TestRenewTable(t *testing.T) {
	cases := []struct {
		name       string
		present    func(old, cur, pend string) string
		wantAction RenewAction
		wantErr    int // protocol error code, 0 for success
		wantStatus string
		check      func(t *testing.T, before, after SecretState, presented, issued string)
	}{
		{
			name:       "matches pending: promote",
			present:    func(_, _, pend string) string { return pend },
			wantAction: RenewPromote, wantStatus: RegActive,
			check: func(t *testing.T, before, after SecretState, presented, issued string) {
				if after.Current != secret.Hash(presented) {
					t.Error("current is not the presented (pending) secret")
				}
				if after.Pending != secret.Hash(issued) {
					t.Error("pending is not the newly issued secret")
				}
				if len(after.Retired) != len(before.Retired)+1 || after.Retired[len(after.Retired)-1] != before.Current {
					t.Error("old current was not retired")
				}
			},
		},
		{
			name:       "matches current: reissue, current stays valid",
			present:    func(_, cur, _ string) string { return cur },
			wantAction: RenewReissue, wantStatus: RegActive,
			check: func(t *testing.T, before, after SecretState, _, issued string) {
				if after.Current != before.Current {
					t.Error("current changed")
				}
				if after.Pending != secret.Hash(issued) || after.Pending == before.Pending {
					t.Error("pending was not replaced by the new secret")
				}
				if len(after.Retired) != len(before.Retired) {
					t.Error("retired changed")
				}
			},
		},
		{
			name:       "matches retired: revoke",
			present:    func(old, _, _ string) string { return old },
			wantAction: RenewReuse, wantErr: protocol.ErrRevoked, wantStatus: RegRevoked,
		},
		{
			name:       "matches nothing: reject",
			present:    func(_, _, _ string) string { return "never-issued-secret-never-issued-secret" },
			wantAction: RenewReject, wantErr: protocol.ErrUnknown, wantStatus: RegActive,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newStoreFixture(t)
			reqID, nonce, _ := f.approvedRequest(t)
			p := f.poll(t, reqID, nonce)
			regID, s1 := p.RegistrationID, p.RefreshSecret
			r1, err := f.renew(regID, s1) // current=s1, pending=s2
			if err != nil {
				t.Fatal(err)
			}
			r2, err := f.renew(regID, r1.RefreshSecret) // retired=[s1], current=s2, pending=s3
			if err != nil {
				t.Fatal(err)
			}
			old, cur, pend := s1, r1.RefreshSecret, r2.RefreshSecret
			before, _ := f.secrets(t, regID)

			presented := tc.present(old, cur, pend)
			res, err := f.renew(regID, presented)
			after, status := f.secrets(t, regID)
			if status != tc.wantStatus {
				t.Errorf("registration status %s, want %s", status, tc.wantStatus)
			}
			if tc.wantErr != 0 {
				var rerr *RenewError
				if !errors.As(err, &rerr) || rerr.Code != tc.wantErr {
					t.Fatalf("err = %v, want code %d", err, tc.wantErr)
				}
				if tc.wantAction == RenewReject && (after.Current != before.Current || after.Pending != before.Pending) {
					t.Error("a rejected renewal changed the secrets")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if res.Action != tc.wantAction {
				t.Errorf("action %s, want %s", res.Action, tc.wantAction)
			}
			f.verify(t, res.Token.Raw)
			tc.check(t, before, after, presented, res.RefreshSecret)
		})
	}
}

// TestClassifyTable is the pure decision table, including the empty states a
// registration passes through before its first proof.
func TestClassifyTable(t *testing.T) {
	h := secret.Hash
	st := SecretState{Current: h("cur"), Pending: h("pend"), Retired: []string{h("old1"), h("old2")}}
	cases := []struct {
		st      SecretState
		present string
		want    RenewAction
	}{
		{st, "pend", RenewPromote},
		{st, "cur", RenewReissue},
		{st, "old1", RenewReuse},
		{st, "old2", RenewReuse},
		{st, "other", RenewReject},
		{SecretState{Pending: h("first")}, "first", RenewPromote}, // first issuance
		{SecretState{Pending: h("first")}, "", RenewReject},       // empty never matches empty current
		{SecretState{Current: h("cur")}, "cur", RenewReissue},     // no pending
		{SecretState{}, "anything", RenewReject},                  // empty state
		{SecretState{Current: h("x"), Pending: h("x")}, "x", RenewPromote},
	}
	for i, tc := range cases {
		if got := Classify(tc.st, tc.present); got != tc.want {
			t.Errorf("case %d: Classify(%q) = %s, want %s", i, tc.present, got, tc.want)
		}
	}
	// Apply on promote with no prior current retires nothing.
	got := Apply(SecretState{Pending: h("first")}, RenewPromote, h("next"))
	if got.Current != h("first") || got.Pending != h("next") || len(got.Retired) != 0 {
		t.Errorf("first promotion: %+v", got)
	}
}

// ceState is the CE's registration.json for the crash tests: what it has
// durably stored.
type ceState struct {
	regID, current, pending string
	installedToken          string
}

// newest is the secret the CE presents: pending if set, else current.
func (c *ceState) newest() string {
	if c.pending != "" {
		return c.pending
	}
	return c.current
}

// crashPoint names where a renewal is interrupted.
type crashPoint int

const (
	noCrash             crashPoint = iota
	replyLost                      // registrar committed, reply lost
	crashBeforePersist             // CE received the reply, crashed before step 2
	crashBeforeInstall             // after step 2 (secrets stored), before the token install
	crashBeforeReconfig            // after the token install, before reconfig
)

// ceRenew runs the CE side of one renewal (present the newest stored secret,
// store {current: presented, pending: new}, install the token), interrupted at
// crash. It returns the registrar's error, if any.
func ceRenew(f *storeFixture, ce *ceState, crash crashPoint) error {
	presented := ce.newest()
	res, err := f.renew(ce.regID, presented)
	if err != nil {
		return err
	}
	switch crash {
	case replyLost, crashBeforePersist:
		return nil // nothing durable changed on the CE
	}
	ce.current, ce.pending = presented, res.RefreshSecret // step 2
	if crash == crashBeforeInstall {
		return nil
	}
	ce.installedToken = res.Token.Raw // step 3
	return nil
}

// TestCrashInjection walks every crash point (reply lost, crash before the CE
// persists the reply, crash before the token install, crash before the
// reconfig) and asserts
// that no crash revokes, and that the next ordinary renewal converges: the CE
// gets a token and the registrar's current/pending matches what the CE stored.
func TestCrashInjection(t *testing.T) {
	for _, crash := range []crashPoint{replyLost, crashBeforePersist, crashBeforeInstall, crashBeforeReconfig} {
		t.Run([]string{"", "reply-lost", "before-persist", "before-install", "before-reconfig"}[crash], func(t *testing.T) {
			f := newStoreFixture(t)
			reqID, nonce, _ := f.approvedRequest(t)
			p := f.poll(t, reqID, nonce)
			ce := &ceState{regID: p.RegistrationID, pending: p.RefreshSecret, installedToken: p.Token.Raw}

			// A healthy renewal first, so the crash happens with current,
			// pending and retired all populated.
			if err := ceRenew(f, ce, noCrash); err != nil {
				t.Fatal(err)
			}
			if err := ceRenew(f, ce, crash); err != nil {
				t.Fatalf("interrupted renewal: %v", err)
			}
			// Restart: the CE presents what it durably holds.
			ce.installedToken = ""
			if err := ceRenew(f, ce, noCrash); err != nil {
				t.Fatalf("renewal after %v crash was refused: %v", crash, err)
			}
			if ce.installedToken == "" {
				t.Fatal("no token after recovery")
			}
			f.verify(t, ce.installedToken)
			st, status := f.secrets(t, ce.regID)
			if status != RegActive {
				t.Fatalf("registration %s after recovery", status)
			}
			if st.Current != secret.Hash(ce.current) || st.Pending != secret.Hash(ce.pending) {
				t.Fatal("registrar and CE did not converge")
			}
			// And it keeps working.
			for i := 0; i < 3; i++ {
				if err := ceRenew(f, ce, noCrash); err != nil {
					t.Fatalf("renewal %d after recovery: %v", i, err)
				}
			}
		})
	}
}

// TestCrashStorm interrupts many consecutive renewals at every crash point in
// turn, including back-to-back crashes, and asserts the invariant: the secret
// the CE most recently stored is always current or pending on the registrar,
// never retired, so nothing ever revokes.
func TestCrashStorm(t *testing.T) {
	f := newStoreFixture(t)
	reqID, nonce, _ := f.approvedRequest(t)
	p := f.poll(t, reqID, nonce)
	ce := &ceState{regID: p.RegistrationID, pending: p.RefreshSecret}
	seq := []crashPoint{replyLost, replyLost, crashBeforePersist, noCrash, crashBeforeInstall,
		crashBeforeInstall, replyLost, crashBeforeReconfig, crashBeforePersist, crashBeforeInstall, noCrash}
	for i, crash := range append(seq, seq...) {
		if err := ceRenew(f, ce, crash); err != nil {
			t.Fatalf("step %d (%v): %v", i, crash, err)
		}
		st, status := f.secrets(t, ce.regID)
		if status != RegActive {
			t.Fatalf("step %d: registration %s", i, status)
		}
		h := secret.Hash(ce.newest())
		if h != st.Current && h != st.Pending {
			t.Fatalf("step %d: the CE's newest stored secret is neither current nor pending", i)
		}
		// The invariant is about the newest stored secret only: after a lost
		// reply the CE's older "current" may legitimately be retired, which is
		// harmless because the CE never presents it while its newest works.
		for _, r := range st.Retired {
			if r == h {
				t.Fatalf("step %d: the CE's newest stored secret was retired", i)
			}
		}
	}
}

// TestFirstIssuanceCrash covers the first poll's crash points: reply lost
// (re-poll re-mints), CE stored the first secret but crashed before the
// install (REG_RENEW with it promotes), and that re-polling stops after the
// first proof.
func TestFirstIssuanceCrash(t *testing.T) {
	f := newStoreFixture(t)
	reqID, nonce, number := f.approvedRequest(t)

	lost := f.poll(t, reqID, nonce) // reply lost
	again := f.poll(t, reqID, nonce)
	if again.Status != protocol.StatusApproved {
		t.Fatalf("re-poll status %s", again.Status)
	}
	if again.RegistrationID != lost.RegistrationID {
		t.Fatal("re-poll created a second registration")
	}
	if again.RefreshSecret == lost.RefreshSecret {
		t.Fatal("re-poll did not issue a new first secret")
	}
	f.verify(t, again.Token.Raw)
	// The lost secret was replaced, not retired: presenting it is a plain
	// reject, never a revocation.
	if _, err := f.renew(again.RegistrationID, lost.RefreshSecret); err == nil {
		t.Fatal("a replaced first secret was accepted")
	}
	if _, status := f.secrets(t, again.RegistrationID); status != RegActive {
		t.Fatalf("status %s after presenting a replaced first secret", status)
	}

	// The CE stores the second one, crashes before installing, restarts and
	// renews with it.
	ce := &ceState{regID: again.RegistrationID, pending: again.RefreshSecret}
	if err := ceRenew(f, ce, noCrash); err != nil {
		t.Fatal(err)
	}
	if res := f.poll(t, reqID, nonce); res.Status != protocol.StatusClaimed {
		t.Fatalf("poll after the first proof: %s, want claimed", res.Status)
	}
	r, err := f.store.RequestByNumber(context.Background(), number)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != ReqClaimed {
		t.Fatalf("request status %s, want claimed", r.Status)
	}
}

// TestTheftRevokes: a copied state file raced against the real CE ends with
// one side presenting a retired secret, which revokes the registration.
func TestTheftRevokes(t *testing.T) {
	f := newStoreFixture(t)
	reqID, nonce, _ := f.approvedRequest(t)
	p := f.poll(t, reqID, nonce)
	victim := &ceState{regID: p.RegistrationID, pending: p.RefreshSecret}
	if err := ceRenew(f, victim, noCrash); err != nil {
		t.Fatal(err)
	}
	thief := *victim // copies registration.json

	// The thief renews twice; its second renewal retires the secret the real
	// CE holds as current.
	if err := ceRenew(f, &thief, noCrash); err != nil {
		t.Fatal(err)
	}
	if err := ceRenew(f, &thief, noCrash); err != nil {
		t.Fatal(err)
	}
	// The real CE's newest secret is the thief's retired one.
	err := ceRenew(f, victim, noCrash)
	var rerr *RenewError
	if !errors.As(err, &rerr) || rerr.Code != protocol.ErrRevoked {
		t.Fatalf("err = %v, want revoked", err)
	}
	if _, status := f.secrets(t, victim.regID); status != RegRevoked {
		t.Fatalf("status %s, want revoked", status)
	}
	// Once revoked, nobody renews.
	if err := ceRenew(f, &thief, noCrash); err == nil {
		t.Fatal("the thief renewed a revoked registration")
	}
}

func TestPollStates(t *testing.T) {
	f := newStoreFixture(t)
	ctx := context.Background()
	opts := PollOptions{UnclaimedTTL: 24 * time.Hour, SlowDownStep: 5 * time.Second}

	newReq := func(ttl time.Duration) (string, string, int64) {
		id, _ := secret.NewID()
		nonce, _ := secret.NewSecret()
		code, _ := NewUserCode()
		n, err := f.store.CreateRequest(ctx, NewRequest{RequestIDHash: secret.Hash(id), NonceHash: secret.Hash(nonce),
			Name: "ce.example.edu", Method: protocol.MethodApproval, UserCode: code, Status: ReqPending,
			TTL: ttl, PollInterval: 5 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		return id, nonce, n
	}

	id, nonce, n := newReq(30 * time.Minute)
	if r := f.poll(t, id, nonce); r.Status != protocol.StatusPending {
		t.Fatalf("status %s, want pending", r.Status)
	}
	// Too soon: slow down, and the interval grows.
	f.clock.Advance(time.Second)
	r, err := f.store.Poll(ctx, id, nonce, opts, f.minter.Mint)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != protocol.StatusSlowDown || r.Interval != 10*time.Second {
		t.Fatalf("status %s interval %s, want slow-down 10s", r.Status, r.Interval)
	}
	// Wrong nonce looks like an unknown request.
	if _, err := f.store.Poll(ctx, id, "wrong-nonce-wrong-nonce-wrong-nonce", opts, f.minter.Mint); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong nonce: %v", err)
	}
	if err := f.store.Decide(ctx, n, false, Identity{Kind: "cedar", Principal: "admin"}, "not ours"); err != nil {
		t.Fatal(err)
	}
	if r := f.poll(t, id, nonce); r.Status != protocol.StatusDenied {
		t.Fatalf("status %s, want denied", r.Status)
	}
	if err := f.store.Decide(ctx, n, true, Identity{Kind: "cedar", Principal: "admin"}, ""); !errors.Is(err, ErrNotPending) {
		t.Fatalf("approving a denied request: %v", err)
	}

	// Expiry while pending.
	id, nonce, n = newReq(time.Minute)
	f.clock.Advance(2 * time.Minute)
	if r := f.poll(t, id, nonce); r.Status != protocol.StatusExpired {
		t.Fatalf("status %s, want expired", r.Status)
	}
	if err := f.store.Decide(ctx, n, true, Identity{Kind: "cedar", Principal: "admin"}, ""); !errors.Is(err, ErrNotPending) {
		t.Fatalf("approving an expired request: %v", err)
	}

	// Approved but unclaimed for longer than the TTL.
	id, nonce, n = newReq(30 * time.Minute)
	if err := f.store.Decide(ctx, n, true, Identity{Kind: "cedar", Principal: "admin"}, ""); err != nil {
		t.Fatal(err)
	}
	f.clock.Advance(25 * time.Hour)
	if r := f.poll(t, id, nonce); r.Status != protocol.StatusExpired {
		t.Fatalf("status %s, want expired (unclaimed)", r.Status)
	}
}

func TestRenewPolicies(t *testing.T) {
	f := newStoreFixture(t)
	ctx := context.Background()
	reqID, nonce, _ := f.approvedRequest(t)
	p := f.poll(t, reqID, nonce)

	// The approver is re-checked, and a refusal consumes nothing.
	var asked Identity
	deny := RenewOptions{Recheck: func(_ context.Context, who Identity, _ string) (bool, error) {
		asked = who
		return false, nil
	}}
	_, err := f.store.Renew(ctx, p.RegistrationID, p.RefreshSecret, deny, f.minter.Mint)
	var rerr *RenewError
	if !errors.As(err, &rerr) || rerr.Code != protocol.ErrNotAuthorized {
		t.Fatalf("err = %v, want not authorized", err)
	}
	if asked.Kind != "cedar" || asked.Principal != "admin@pool.test" {
		t.Fatalf("recheck asked about %+v", asked)
	}
	if _, err := f.renew(p.RegistrationID, p.RefreshSecret); err != nil {
		t.Fatalf("secret was consumed by a refused renewal: %v", err)
	}
}

func TestRevokeAndCallbackRegistration(t *testing.T) {
	f := newStoreFixture(t)
	ctx := context.Background()
	tok, err := f.minter.Mint("ce.example.edu")
	if err != nil {
		t.Fatal(err)
	}
	regID, err := f.store.CallbackRegistration(ctx, 1, "ce.example.edu", "192.0.2.10", tok)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.CallbackAcknowledged(ctx, 1, regID, "192.0.2.10", tok); err != nil {
		t.Fatal(err)
	}
	tok2, _ := f.minter.Mint("ce.example.edu")
	again, err := f.store.CallbackRegistration(ctx, 2, "ce.example.edu", "192.0.2.10", tok2)
	if err != nil || again != regID {
		t.Fatalf("second callback issuance: %s %v, want reuse of %s", again, err, regID)
	}
	if n, _ := f.store.IssuedTokenCount(ctx, regID); n != 2 {
		t.Fatalf("issued tokens %d, want 2", n)
	}
	revoked, err := f.store.Revoke(ctx, "", "ce.example.edu", Identity{Kind: "cedar", Principal: "admin"}, "test")
	if err != nil || len(revoked) != 1 {
		t.Fatalf("revoke: %v %d", err, len(revoked))
	}
	if ok, _ := f.store.NameRevoked(ctx, "ce.example.edu"); !ok {
		t.Fatal("name not reported revoked")
	}
	tok3, _ := f.minter.Mint("ce.example.edu")
	if _, err := f.store.CallbackRegistration(ctx, 3, "ce.example.edu", "192.0.2.10", tok3); err == nil {
		t.Fatal("issued by callback for a revoked name")
	}
	if _, err := f.store.Revoke(ctx, "", "ce.example.edu", Identity{}, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second revoke: %v", err)
	}
}

func TestMaxRegistrationAge(t *testing.T) {
	f := newStoreFixture(t)
	reqID, nonce, _ := f.approvedRequest(t)
	p := f.poll(t, reqID, nonce)
	f.clock.Advance(48 * time.Hour)
	_, err := f.store.Renew(context.Background(), p.RegistrationID, p.RefreshSecret,
		RenewOptions{MaxAge: 24 * time.Hour}, f.minter.Mint)
	var rerr *RenewError
	if !errors.As(err, &rerr) || rerr.Code != protocol.ErrExpired {
		t.Fatalf("err = %v, want expired", err)
	}
	if _, status := f.secrets(t, p.RegistrationID); status != RegExpired {
		t.Fatalf("status %s", status)
	}
}

func TestUserCodes(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		c, err := NewUserCode()
		if err != nil {
			t.Fatal(err)
		}
		if len(c) != 9 || c[4] != '-' {
			t.Fatalf("code %q is not XXXX-XXXX", c)
		}
		for j, r := range c {
			if j == 4 {
				continue
			}
			if !containsRune(userCodeAlphabet, r) {
				t.Fatalf("code %q has %q outside the alphabet", c, r)
			}
		}
		seen[c] = true
	}
	if len(seen) < 195 {
		t.Fatalf("only %d distinct codes in 200", len(seen))
	}
	for in, want := range map[string]string{"wdjbmjht": "WDJB-MJHT", "WDJB MJHT": "WDJB-MJHT", " wdjb-mjht ": "WDJB-MJHT"} {
		if got := NormalizeUserCode(in); got != want {
			t.Errorf("NormalizeUserCode(%q) = %q", in, got)
		}
	}
}

func containsRune(s string, r rune) bool {
	for _, c := range s {
		if c == r {
			return true
		}
	}
	return false
}

func TestValidName(t *testing.T) {
	for _, ok := range []string{"ce.example.edu", "CE-1.example.edu", "hosted_ce.example.org", "localhost"} {
		if err := ValidName(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", ".example.edu", "a..b", "-ce.example.edu", "ce-.edu", "ce example", "ce@example", "a/b"} {
		if err := ValidName(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestCEVersionIsValidated(t *testing.T) {
	f := newStoreFixture(t)
	ctx := context.Background()
	for i, tc := range []struct {
		in, want string
	}{
		{"25.0.1", "25.0.1"},
		{"v0.3.0-4-gabc1234-dirty", "v0.3.0-4-gabc1234-dirty"},
		{"1.2+build_7", "1.2+build_7"},
		{"", ""},
		{"25.0.1 htc-registrationd/0.3", ""},
		{"$CondorVersion: 25.0.0 $", ""},
		{"1.0\nRequested from 192.0.2.1", ""},
		{"1.0<b>", ""},
		{"0123456789012345678901234567890123", ""}, // 34 characters
		{"25.0.1\u00a0", ""},
	} {
		code := fmt.Sprintf("CEVR-%04d", i)
		n, err := f.store.CreateRequest(ctx, NewRequest{RequestIDHash: "rid-" + code, NonceHash: "n", Name: "ce.test",
			Method: "approval", CEVersion: tc.in, UserCode: code, Status: ReqPending, TTL: time.Hour})
		if err != nil {
			t.Fatal(err)
		}
		r, err := f.store.RequestByUserCode(ctx, code)
		if err != nil || r.Number != n {
			t.Fatalf("%q: %+v, %v", tc.in, r, err)
		}
		if r.CEVersion != tc.want {
			t.Errorf("CEVersion %q stored as %q, want %q", tc.in, r.CEVersion, tc.want)
		}
	}
}
