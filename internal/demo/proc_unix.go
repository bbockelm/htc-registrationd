//go:build unix

package demo

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// setProcessGroup puts the child in its own process group, so a Ctrl-C at
// the terminal reaches only the demo, which then stops the children in
// order.
func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func terminate(cmd *exec.Cmd) { _ = cmd.Process.Signal(syscall.SIGTERM) }

func kill(cmd *exec.Cmd) { _ = cmd.Process.Kill() }

func killPid(pid int) {
	_ = syscall.Kill(pid, syscall.SIGTERM)
	for range 50 {
		if syscall.Kill(pid, 0) != nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
}

// processName is the command name of a running process, or "".
func processName(pid int) string {
	if syscall.Kill(pid, 0) != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ps", "-p", strconv.Itoa(pid), "-o", "comm=").Output() //nolint:gosec // ps with a numeric pid
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
