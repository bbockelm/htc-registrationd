package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/bbockelm/htc-registrationd/internal/demo"
	"github.com/bbockelm/htc-registrationd/internal/demo/idp"
)

// runIDP serves the demo identity provider by itself, over HTTPS, for a
// registrar the demo does not run (the root integration test's).
func runIDP(args []string) int {
	fs := flag.NewFlagSet("idp", flag.ExitOnError)
	listen := fs.String("listen", ":8443", "address to serve HTTPS on")
	issuer := fs.String("issuer", "", "issuer URL, the https:// URL this provider is reached at")
	clientID := fs.String("client-id", demo.ClientID, "the registered client's id")
	secretFile := fs.String("client-secret-file", "", "file holding the client secret")
	redirect := fs.String("redirect-uri", "", "the client's redirect URI")
	cert := fs.String("cert", "", "TLS certificate file")
	key := fs.String("key", "", "TLS key file")
	_ = fs.Parse(args)
	if *issuer == "" || *secretFile == "" || *redirect == "" || *cert == "" || *key == "" {
		fs.Usage()
		return 2
	}
	secret, err := os.ReadFile(*secretFile)
	if err != nil {
		fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(*cert, *key)
	if err != nil {
		fatal(err)
	}
	var users []idp.User
	for _, u := range demo.Users {
		users = append(users, idp.User{Sub: u.Sub})
	}
	p := idp.New(idp.Config{
		Issuer: *issuer, ClientID: *clientID, ClientSecret: strings.TrimSpace(string(secret)),
		RedirectURI: *redirect, Users: users, EmailDomain: "example.org",
		Logger: slog.New(slog.NewTextHandler(os.Stderr, nil)),
	})
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", *listen)
	if err != nil {
		fatal(err)
	}
	srv := &http.Server{
		Handler:           p.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}},
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	fmt.Fprintf(os.Stderr, "identity provider %s on %s\n", *issuer, ln.Addr())
	if err := srv.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fatal(err)
	}
	return 0
}
