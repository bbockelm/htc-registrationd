package demo

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// output serializes prefixed lines from every process onto one writer.
type output struct {
	mu    sync.Mutex
	w     io.Writer
	width int
}

func (o *output) line(prefix, text string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	_, _ = fmt.Fprintf(o.w, "%-*s | %s\n", o.width, prefix, text)
}

// block writes text as is, between the prefixed lines.
func (o *output) block(text string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	_, _ = io.WriteString(o.w, text)
}

// prefixWriter turns written bytes into prefixed lines.
type prefixWriter struct {
	out    *output
	prefix string
	buf    bytes.Buffer
}

func (p *prefixWriter) Write(b []byte) (int, error) {
	p.buf.Write(b)
	for {
		i := bytes.IndexByte(p.buf.Bytes(), '\n')
		if i < 0 {
			break
		}
		line := strings.TrimRight(string(p.buf.Next(i+1)), "\r\n")
		if line != "" {
			p.out.line(p.prefix, line)
		}
	}
	return len(b), nil
}

// tail follows a log file from its current end (or from the start, when
// fromStart is set), writing each new line with prefix, until ctx ends. A
// file that shrinks (rotation) is read again from the start.
func tail(ctx context.Context, path string, fromStart bool, out *output, prefix string, filter func(string) string) {
	var off int64
	if !fromStart {
		if st, err := os.Stat(path); err == nil {
			off = st.Size()
		}
	}
	var partial []byte
	t := time.NewTicker(200 * time.Millisecond)
	defer t.Stop()
	for {
		if st, err := os.Stat(path); err == nil {
			if st.Size() < off {
				off, partial = 0, nil
			}
			if st.Size() > off {
				if f, err := os.Open(path); err == nil { //nolint:gosec // the demo's own log files
					if _, err := f.Seek(off, io.SeekStart); err == nil {
						r := bufio.NewReader(f)
						for {
							chunk, err := r.ReadBytes('\n')
							off += int64(len(chunk))
							if err != nil {
								partial = append(partial, chunk...)
								break
							}
							line := strings.TrimRight(string(append(partial, chunk...)), "\r\n")
							partial = nil
							if filter != nil {
								line = filter(line)
							}
							if line != "" {
								out.line(prefix, line)
							}
						}
					}
					_ = f.Close()
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// process is a child process of the demo.
type process struct {
	name string
	cmd  *exec.Cmd
	done chan struct{}
	err  error
}

// childEnv is the environment for a child: this process's, without any
// HTCondor variable that would point it at another configuration, plus
// extra.
func childEnv(extra ...string) []string {
	var env []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		u := strings.ToUpper(k)
		if strings.HasPrefix(u, "CONDOR_") || strings.HasPrefix(u, "_CONDOR_") {
			continue
		}
		env = append(env, kv)
	}
	return append(env, extra...)
}

// start runs a child with its stdout and stderr written to out under the
// child's name, and records its pid in pidDir.
func start(name, pidDir string, out *output, env []string, path string, args ...string) (*process, error) {
	cmd := exec.Command(path, args...) //nolint:gosec,noctx // the demo's own daemon and HTCondor binaries; stopped by signal, not context
	cmd.Env = env
	pw := &prefixWriter{out: out, prefix: name}
	cmd.Stdout, cmd.Stderr = pw, pw
	setProcessGroup(cmd)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting %s: %w", name, err)
	}
	p := &process{name: name, cmd: cmd, done: make(chan struct{})}
	pidFile := filepath.Join(pidDir, name+".pid")
	_ = os.WriteFile(pidFile, []byte(strconv.Itoa(cmd.Process.Pid)+"\n"), 0o600)
	go func() {
		p.err = cmd.Wait()
		_ = os.Remove(pidFile)
		close(p.done)
	}()
	return p, nil
}

// exited reports whether the process has exited.
func (p *process) exited() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

// stop asks the process to exit and kills it if it has not within grace.
func (p *process) stop(grace time.Duration) {
	if p.exited() {
		return
	}
	terminate(p.cmd)
	select {
	case <-p.done:
	case <-time.After(grace):
		kill(p.cmd)
		<-p.done
	}
}

// killStale stops processes a previous demo run left behind, recorded by
// pid file in pidDir, when they still run one of the demo's programs.
func killStale(pidDir string, programs ...string) {
	files, _ := filepath.Glob(filepath.Join(pidDir, "*.pid"))
	for _, f := range files {
		b, err := os.ReadFile(f) //nolint:gosec // the demo's own pid files
		_ = os.Remove(f)
		if err != nil {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
		if err != nil || pid <= 1 {
			continue
		}
		if comm := processName(pid); comm != "" {
			base := filepath.Base(comm)
			for _, prog := range programs {
				// Linux truncates the command name to 15 bytes.
				if base == prog || (len(base) >= 15 && strings.HasPrefix(prog, base)) {
					killPid(pid)
					break
				}
			}
		}
	}
}
