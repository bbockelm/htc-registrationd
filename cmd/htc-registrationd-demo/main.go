// Command htc-registrationd-demo runs htc-registrationd on one machine: a
// registrar with its web UI, a mock OpenID provider, two CEs, and, when an
// HTCondor installation is found, a condor_collector configured as an
// HTCondor-CE CE-Collector. Run it with "make demo".
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/bbockelm/htc-registrationd/internal/demo"
)

const usage = `usage: htc-registrationd-demo [flags] [command]

Commands:
  run                      start the demo (the default)
  status                   both CEs' registration state and the registrar's list
  cli DAEMON ARGS...       run htc-registration against registrar, ce1 or ce2
  advertise CE NAME        advertise a Scheduler ad named NAME to the demo
                           collector with CE's (ce1, ce2) installed token

Flags:
`

func main() {
	fs := flag.NewFlagSet("htc-registrationd-demo", flag.ExitOnError)
	dir := fs.String("dir", ".demo", "demo state directory")
	daemon := fs.String("daemon", "bin/htc-registrationd", "the htc-registrationd binary")
	condorBin := fs.String("condor-bin", "", "directory holding condor_collector (default: $CONDOR_BIN, then PATH)")
	noCollector := fs.Bool("no-collector", false, "do not start an HTCondor collector")
	lifetime := fs.Duration("token-lifetime", 10*time.Minute, "token lifetime; CEs renew at half of it")
	readyFile := fs.String("ready-file", "", "once the demo is up, write its URLs, files and ce2's approval code to this file as JSON (default DIR/ready.json)")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, usage)
		fs.PrintDefaults()
	}
	_ = fs.Parse(os.Args[1:])
	// cedar logs each handshake step at INFO through the default logger.
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})))
	d, err := demo.New(demo.Options{Dir: *dir, Daemon: *daemon, CondorBin: *condorBin, NoCollector: *noCollector,
		TokenLifetime: *lifetime})
	if err != nil {
		fatal(err)
	}
	args := fs.Args()
	cmd := "run"
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "run":
		if *readyFile == "" {
			*readyFile = filepath.Join(d.Root(), demo.ReadyFile)
		}
		os.Exit(run(d, *readyFile))
	case "status":
		os.Exit(status(d, *daemon))
	case "cli":
		if len(args) < 2 {
			fatal(errors.New("usage: cli DAEMON ARG [ARG ...]"))
		}
		os.Exit(cli(d, *daemon, args[0], args[1:]...))
	case "advertise":
		if len(args) != 2 {
			fatal(errors.New("usage: advertise CE NAME"))
		}
		res, err := d.Advertise(context.Background(), args[0], args[1])
		if err != nil {
			fatal(err)
		}
		fmt.Println(res)
	default:
		fs.Usage()
		os.Exit(2)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "htc-registrationd-demo:", err)
	os.Exit(1)
}

func run(d *demo.Demo, readyFile string) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// A file left by an earlier run must not be taken for this one.
	if err := os.Remove(readyFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		fatal(err)
	}
	d.Say("starting; state in %s", d.Root())
	if err := d.Start(ctx); err != nil {
		if ctx.Err() == nil {
			fmt.Fprintln(os.Stderr, "htc-registrationd-demo:", err)
			return 1
		}
		return 0
	}
	d.PrintBanner()
	if err := d.WriteReady(readyFile); err != nil {
		d.Say("writing %s: %v; stopping the demo", readyFile, err)
		d.Stop()
		return 1
	}
	err := d.Wait(ctx)
	if err != nil {
		d.Say("%v; stopping the demo", err)
	} else {
		d.Say("stopping")
	}
	d.Stop()
	_ = os.Remove(readyFile)
	d.Say("stopped; state kept in %s", d.Root())
	if err != nil {
		return 1
	}
	return 0
}

func cli(d *demo.Demo, daemon, target string, args ...string) int {
	env, err := d.CLIEnv(target)
	if err != nil {
		fatal(err)
	}
	cmd := exec.Command(daemon, append([]string{"cli"}, args...)...) //nolint:gosec,noctx // the demo's own daemon binary, run in the foreground
	cmd.Env = env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode()
		}
		fatal(err)
	}
	return 0
}

func status(d *demo.Demo, daemon string) int {
	rc := 0
	for _, c := range d.CEs() {
		fmt.Printf("== %s (%s, %s mode)\n", c.Key, c.Name, c.Method)
		if n := cli(d, daemon, c.Key, "status"); n != 0 {
			rc = n
		}
		fmt.Println()
	}
	fmt.Println("== registrar")
	if n := cli(d, daemon, "registrar", "list"); n != 0 {
		rc = n
	}
	return rc
}
