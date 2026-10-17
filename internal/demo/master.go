package demo

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
)

// startMaster serves DC_RECONFIG_FULL for a CE in place of its
// condor_master: a CE daemon sends it after installing a token, so the
// master re-reads tokens.d. The demo calls onReconfig instead.
func (d *Demo) startMaster(ctx context.Context, ce *CE, onReconfig func()) error {
	raw, err := os.ReadFile(ce.Config())
	if err != nil {
		return err
	}
	cfg, err := config.NewFromReaderWithOptions(strings.NewReader(string(raw)), config.ConfigOptions{Subsystem: "MASTER"})
	if err != nil {
		return fmt.Errorf("%s master: %w", ce.Key, err)
	}
	sc, err := htcondor.GetServerSecurityConfig(cfg, commands.DC_RECONFIG_FULL, "DEFAULT")
	if err != nil {
		return fmt.Errorf("%s master: %w", ce.Key, err)
	}
	sc.Authentication = security.SecurityRequired
	srv := cedarserver.New(sc)
	srv.Authorizer = func(perm, _, user string) bool {
		name, _, _ := strings.Cut(user, "@")
		return perm == "ADMINISTRATOR" && (name == d.user || name == d.daemonUser)
	}
	srv.Handle(commands.DC_RECONFIG_FULL, func(context.Context, *cedarserver.Conn) error {
		onReconfig()
		return nil
	}, "ADMINISTRATOR")
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:"+strconv.Itoa(ce.master))
	if err != nil {
		return fmt.Errorf("%s master: %w", ce.Key, err)
	}
	go func() { _ = srv.Serve(d.run, ln) }()
	return nil
}
