// Package testpriv lets a test run as root do what a daemon under a root
// condor_master does: drop to an unprivileged effective uid, keeping root in
// the saved set so credentials can still be read as root.
package testpriv

import (
	"os"
	"runtime"
	"sync"
	"testing"

	"github.com/bbockelm/golang-htcondor/droppriv"
)

// User is the account tests drop to.
const User = "nobody"

// Drop skips the test unless it runs as root on Linux, then drops the
// process's effective uid and gid to User until the test ends or restore is
// called. It returns the dropped-to uid and gid. Tests that call it must not
// run in parallel with others: the effective uid is the process's.
func Drop(t *testing.T) (uid, gid int, restore func()) {
	t.Helper()
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("needs root on Linux")
	}
	mgr, err := droppriv.NewManager(droppriv.Config{Enabled: true, CondorUser: User})
	if err != nil {
		t.Fatalf("droppriv: %v", err)
	}
	if err := mgr.Start(); err != nil {
		t.Fatalf("dropping to %s: %v", User, err)
	}
	var once sync.Once
	restore = func() {
		once.Do(func() {
			if err := mgr.Stop(); err != nil {
				t.Errorf("restoring root: %v", err)
			}
		})
	}
	t.Cleanup(restore)
	if os.Geteuid() == 0 {
		t.Fatal("still root after dropping privileges")
	}
	return os.Geteuid(), os.Getegid(), restore
}
