//go:build !unix

package demo

import "os/exec"

func setProcessGroup(*exec.Cmd) {}

func terminate(cmd *exec.Cmd) { _ = cmd.Process.Kill() }

func kill(cmd *exec.Cmd) { _ = cmd.Process.Kill() }

func killPid(int) {}

func processName(int) string { return "" }
