package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/security"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"

	"github.com/bbockelm/htc-registrationd/internal/ce"
	"github.com/bbockelm/htc-registrationd/internal/protocol"
)

const cliUsage = `usage: htc-registration [-addr SINFUL] [-debug] <command> [args]

On the CE:
  status                 show this CE's registration state (REG_STATUS, READ)
  renew                  renew now (REG_RENEW_NOW, ADMINISTRATOR)
  request --approval     not yet implemented; set HTC_REGISTRATIOND_METHOD = approval

On the registrar:
  list                   list requests and registrations
  approve CODE           approve a pending request by user code (or request number)
  deny CODE [REASON]     deny a pending request
  revoke NAME [REASON]   revoke every registration of NAME
  revoke --id ID [REASON] revoke one registration

The daemon's address comes from -addr or its address file
(HTC_REGISTRATIOND_ADDRESS_FILE, default $(LOG)/.htc_registrationd_address).
`

func runCLI(args []string) int {
	fs := flag.NewFlagSet("htc-registration", flag.ContinueOnError)
	addr := fs.String("addr", "", "daemon address (sinful); default: the address file")
	debug := fs.Bool("debug", false, "log the CEDAR handshake to stderr")
	fs.Usage = func() { fmt.Fprint(os.Stderr, cliUsage) }
	if err := fs.Parse(args); err != nil {
		return 2
	}
	level := slog.LevelWarn
	if *debug {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
	rest := fs.Args()
	if len(rest) == 0 {
		fs.Usage()
		return 2
	}
	cfg, err := config.New()
	if err != nil {
		fmt.Fprintln(os.Stderr, "htc-registration: loading config:", err)
		return 1
	}
	if *addr == "" {
		path := htcondor.AddressFilePath(cfg, Subsys)
		a, err := htcondor.ReadAddressFile(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, "htc-registration: no -addr and no readable address file:", err)
			return 1
		}
		*addr = a
	}
	c := &cli{cfg: cfg, addr: *addr, out: os.Stdout}
	if err := c.dispatch(rest); err != nil {
		fmt.Fprintln(os.Stderr, "htc-registration:", err)
		return 1
	}
	return 0
}

type cli struct {
	cfg  *config.Config
	addr string
	out  io.Writer
}

func (c *cli) dispatch(args []string) error {
	cmd, rest := args[0], args[1:]
	reason := func(i int) string { return strings.Join(rest[min(i, len(rest)):], " ") }
	switch cmd {
	case "status":
		return c.status()
	case "renew":
		return c.simple(protocol.RegRenewNow, nil)
	case "request":
		return fmt.Errorf("request is not implemented yet; set HTC_REGISTRATIOND_METHOD = approval and run renew")
	case "list":
		return c.list()
	case "approve", "deny":
		if len(rest) == 0 {
			return fmt.Errorf("%s needs a user code or request number", cmd)
		}
		t := &protocol.AdminTarget{UserCode: rest[0], Reason: reason(1)}
		var n int64
		if _, err := fmt.Sscanf(rest[0], "%d", &n); err == nil && n > 0 {
			t = &protocol.AdminTarget{RequestNumber: n, Reason: reason(1)}
		}
		if cmd == "approve" {
			return c.simple(protocol.RegAdminApprove, t)
		}
		return c.simple(protocol.RegAdminDeny, t)
	case "revoke":
		if len(rest) == 0 {
			return fmt.Errorf("revoke needs a name or --id ID")
		}
		if rest[0] == "--id" {
			if len(rest) < 2 {
				return fmt.Errorf("--id needs a registration id")
			}
			return c.simple(protocol.RegAdminRevoke, &protocol.AdminTarget{RegistrationID: rest[1], Reason: reason(2)})
		}
		return c.simple(protocol.RegAdminRevoke, &protocol.AdminTarget{Name: rest[0], Reason: reason(1)})
	}
	return fmt.Errorf("unknown command %q", cmd)
}

func (c *cli) connect(ctx context.Context, cmd int) (*client.HTCondorClient, error) {
	sc, err := htcondor.GetSecurityConfig(c.cfg, cmd, "CLIENT")
	if err != nil {
		return nil, err
	}
	sc.PeerName = c.addr
	// Everything but REG_STATUS acts at ADMINISTRATOR, which no
	// unauthenticated identity should hold; do not let OPTIONAL+OPTIONAL
	// negotiate the authentication away.
	if cmd != protocol.RegStatus {
		sc.Authentication = security.SecurityRequired
	} else if sc.Authentication == security.SecurityOptional {
		sc.Authentication = security.SecurityPreferred
	}
	cl, err := client.ConnectAndAuthenticate(ctx, c.addr, sc)
	if err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", c.addr, err)
	}
	return cl, nil
}

func (c *cli) simple(cmd int, req any) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cl, err := c.connect(ctx, cmd)
	if err != nil {
		return err
	}
	defer func() { _ = cl.Close() }()
	if req != nil {
		if err := protocol.Send(ctx, cl.GetStream(), req); err != nil {
			return err
		}
	}
	var ack protocol.Ack
	if err := protocol.Recv(ctx, cl.GetStream(), &ack); err != nil {
		return err
	}
	if ack.Status != protocol.StatusOK {
		return replyError(ack.Status, ack.Error)
	}
	if ack.Hint != "" {
		_, _ = fmt.Fprintln(c.out, ack.Hint)
	}
	return nil
}

func replyError(status string, e protocol.Error) error {
	if err := e.AsError(); err != nil {
		return err
	}
	return fmt.Errorf("unexpected status %q", status)
}

func fmtTime(unix int64) string {
	if unix == 0 {
		return "-"
	}
	return time.Unix(unix, 0).Local().Format(time.RFC3339)
}

func (c *cli) status() error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cl, err := c.connect(ctx, protocol.RegStatus)
	if err != nil {
		return err
	}
	defer func() { _ = cl.Close() }()
	var s ce.StatusReply
	if err := protocol.Recv(ctx, cl.GetStream(), &s); err != nil {
		return err
	}
	w := tabwriter.NewWriter(c.out, 0, 4, 2, ' ', 0)
	rows := [][2]string{
		{"State", s.State}, {"Name", s.Name}, {"Method", s.Method}, {"Registrar", s.Registrar},
		{"Registration", s.RegistrationID}, {"Token file", s.TokenFile},
		{"Token expires", fmtTime(s.TokenExpiry)}, {"Next renewal", fmtTime(s.NextRenewal)},
		{"Last success", fmtTime(s.LastSuccess)},
	}
	if s.ApprovalURL != "" {
		rows = append(rows, [2]string{"APPROVAL URL", s.ApprovalURL}, [2]string{"User code", s.UserCode},
			[2]string{"Request expires", fmtTime(s.RequestExpires)})
	}
	if s.LastError != "" {
		rows = append(rows, [2]string{"Last error", s.LastError + " (" + fmtTime(s.LastErrorTime) + ")"})
	}
	if s.LastPingResult != "" {
		rows = append(rows, [2]string{"View host check", s.LastPingResult + " (" + fmtTime(s.LastPingTime) + ")"})
	}
	for _, r := range rows {
		if r[1] == "" {
			r[1] = "-"
		}
		_, _ = fmt.Fprintf(w, "%s:\t%s\n", r[0], r[1])
	}
	return w.Flush()
}

func (c *cli) list() error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cl, err := c.connect(ctx, protocol.RegAdminList)
	if err != nil {
		return err
	}
	defer func() { _ = cl.Close() }()
	var reqs, regs []*classad.ClassAd
	for {
		ad, err := protocol.RecvAd(ctx, cl.GetStream())
		if err != nil {
			return err
		}
		if end, ok := ad.EvaluateAttrBool(protocol.AttrEnd); ok && end {
			break
		}
		if s, _ := ad.EvaluateAttrString(protocol.AttrStatus); s == protocol.StatusError {
			msg, _ := ad.EvaluateAttrString(protocol.AttrErrorString)
			return fmt.Errorf("%s", msg)
		}
		if k, _ := ad.EvaluateAttrString("Kind"); k == "registration" {
			regs = append(regs, ad)
		} else {
			reqs = append(reqs, ad)
		}
	}
	str := func(ad *classad.ClassAd, a string) string {
		if v, ok := ad.EvaluateAttrString(a); ok && v != "" {
			return v
		}
		return "-"
	}
	num := func(ad *classad.ClassAd, a string) int64 { v, _ := ad.EvaluateAttrInt(a); return v }
	w := tabwriter.NewWriter(c.out, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "REQUEST\tNAME\tMETHOD\tSTATUS\tCODE\tSOURCE\tCREATED\tDECIDED BY")
	for _, ad := range reqs {
		_, _ = fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", num(ad, protocol.AttrRequestNumber),
			str(ad, protocol.AttrName), str(ad, protocol.AttrMethod), str(ad, protocol.AttrStatus),
			str(ad, protocol.AttrUserCode), str(ad, "SourceIP"), fmtTime(num(ad, "CreatedAt")), str(ad, "DecidedBy"))
	}
	_, _ = fmt.Fprintln(w, "\nREGISTRATION\tNAME\tMETHOD\tSTATUS\tAPPROVER\tLAST ISSUED\tTOKEN EXPIRES")
	for _, ad := range regs {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", str(ad, protocol.AttrRegistrationID),
			str(ad, protocol.AttrName), str(ad, protocol.AttrMethod), str(ad, protocol.AttrStatus),
			str(ad, "Approver"), fmtTime(num(ad, "LastIssuedAt")), fmtTime(num(ad, "TokenExpiry")))
	}
	return w.Flush()
}
