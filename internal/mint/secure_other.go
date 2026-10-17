//go:build windows

package mint

import "os"

// checkSecure is a no-op on Windows, as read_secure_file's checks are.
func checkSecure(*os.File) error { return nil }
