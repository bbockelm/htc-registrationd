package registrar

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bbockelm/cedar/security"

	"github.com/bbockelm/htc-registrationd/internal/ssrf"
)

// A callback sinful whose host is a name passes CheckSinful unresolved; the
// address it resolves to is refused by the SSRF policy running as cedar's
// dial hook, before any connection is made, for both a direct and a
// shared-port address.
func TestCallbackDialRefusedByHook(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var accepted atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			_ = c.Close()
		}
	}()
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)

	f := newStoreFixture(t)
	policy := ssrf.New(nil)
	policy.LocalAddrs = func() ([]netip.Addr, error) { return nil, nil }
	svc, err := New(Config{
		Minter:                 f.minter,
		SSRF:                   policy,
		Names:                  AnyName{},
		CallbackSecurity:       func() *security.SecurityConfig { return &security.SecurityConfig{} },
		CallbackConnectTimeout: 5 * time.Second,
		Now:                    f.clock.Now,
	}, f.store)
	if err != nil {
		t.Fatal(err)
	}

	for _, sinful := range []string{
		"<localhost:" + port + ">",
		"<localhost:" + port + "?sock=htc_registrationd>",
	} {
		target, err := policy.CheckSinful(sinful)
		if err != nil {
			t.Fatalf("%s: CheckSinful refused it (%v); the dial hook is what this test exercises", sinful, err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		cc, err := svc.dialCallback(ctx, target, "ce.test")
		cancel()
		if err == nil {
			_ = cc.close()
			t.Fatalf("%s: callback dial to loopback succeeded", sinful)
		}
		var denied *ssrf.DeniedError
		if !errors.As(err, &denied) || !denied.Addr.IsLoopback() {
			t.Fatalf("%s: dial error %v is not the policy's loopback denial", sinful, err)
		}
	}
	if n := accepted.Load(); n != 0 {
		t.Fatalf("the listener accepted %d connection(s); the hook must refuse before connecting", n)
	}
}
