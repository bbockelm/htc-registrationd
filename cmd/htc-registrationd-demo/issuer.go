package main

import (
	"flag"
	"log/slog"
	"os"
	"time"

	"github.com/bbockelm/htc-registrationd/internal/demo/tokenissuer"
)

// runIssuer serves a SciToken issuer over HTTPS, for the root integration
// test's factory.
func runIssuer(args []string) int {
	fs := flag.NewFlagSet("scitoken-issuer", flag.ExitOnError)
	listen := fs.String("listen", ":8444", "address to serve HTTPS on")
	issuer := fs.String("issuer", "", "issuer URL, the https:// URL this issuer is reached at")
	cert := fs.String("cert", "", "TLS certificate file")
	key := fs.String("key", "", "TLS key file")
	lifetime := fs.Duration("lifetime", 20*time.Minute, "default token lifetime")
	_ = fs.Parse(args)
	if *issuer == "" || *cert == "" || *key == "" {
		fs.Usage()
		return 2
	}
	iss, err := tokenissuer.New(tokenissuer.Config{Issuer: *issuer, Lifetime: *lifetime,
		Logger: slog.New(slog.NewTextHandler(os.Stderr, nil))})
	if err != nil {
		fatal(err)
	}
	return serveHTTPS(*listen, *cert, *key, iss.Handler(), "SciToken issuer "+*issuer)
}
