//go:build !windows

package mint

import (
	"fmt"
	"os"
	"syscall"
)

// checkSecure is read_secure_file's SECURE_FILE_VERIFY_ALL check for a file
// read as root: the file must be owned by the real uid (getuid(), which stays
// root while a daemon started by a root master runs with a dropped effective
// uid) and grant nothing to group or others.
func checkSecure(f *os.File) error {
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("mint: stat %s: %w", f.Name(), err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("mint: stat %s: no owner information", f.Name())
	}
	if want := os.Getuid(); int(st.Uid) != want {
		return fmt.Errorf("mint: signing key %s must be owned by uid %d, is owned by uid %d", f.Name(), want, st.Uid)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("mint: signing key %s must not be accessible by group or others, has mode %04o", f.Name(), perm)
	}
	return nil
}
