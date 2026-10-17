// Package atomicfile replaces files so that a reader sees either the old
// contents or the new, never a partial file, and so that the replacement
// survives a crash once WriteFile returns: the data is written to a temporary
// file in the same directory, fsynced, renamed over the target, and the
// directory is fsynced so the rename itself is durable.
//
// Every state file the CE daemon keeps, and the token it installs, goes
// through here, so a crash never leaves a torn registration.json, status.json,
// approval-url or token file. A crash can leave the temporary file behind;
// RemoveTemps clears those at startup.
package atomicfile

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// hook, when non-nil, is called at named points of WriteFile. Tests use it to
// simulate a crash between steps.
var hook func(step string) error

// tempPattern is the os.CreateTemp pattern of path's temporary files.
func tempPattern(base string) string { return "." + base + ".tmp-*" }

// WriteFile atomically replaces path with data, leaving it with mode perm.
//
// Once the rename has happened the new contents are what a reader sees, so a
// failure to fsync the directory afterwards is logged and WriteFile still
// succeeds: reporting it as a failure would leave the caller holding the old
// state in memory while the file holds the new one. Only the rename's
// durability across a power loss is in doubt.
func WriteFile(path string, data []byte, perm fs.FileMode) (err error) {
	dir, base := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	tmp, err := os.CreateTemp(dir, tempPattern(base))
	if err != nil {
		return fmt.Errorf("atomicfile: creating temporary file for %s: %w", path, err)
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()
	// CreateTemp makes the file 0600; set the requested mode before any data
	// lands, so a secret is never briefly readable at a wider mode.
	if err = tmp.Chmod(perm); err != nil {
		return fmt.Errorf("atomicfile: chmod %s: %w", tmpName, err)
	}
	if _, err = tmp.Write(data); err != nil {
		return fmt.Errorf("atomicfile: writing %s: %w", tmpName, err)
	}
	if err = tmp.Sync(); err != nil {
		return fmt.Errorf("atomicfile: fsync %s: %w", tmpName, err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("atomicfile: closing %s: %w", tmpName, err)
	}
	if hook != nil {
		if err = hook("before-rename"); err != nil {
			return err
		}
	}
	if err = os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("atomicfile: renaming %s to %s: %w", tmpName, path, err)
	}
	if serr := syncDir(dir); serr != nil {
		slog.Warn("atomicfile: the file was replaced, but the directory fsync failed", "file", path, "err", serr)
	}
	return nil
}

// RemoveTemps removes the temporary files a crash in WriteFile(path, ...)
// can leave beside path. Nothing else in the directory is touched.
func RemoveTemps(path string) error {
	dir, base := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	matches, err := filepath.Glob(filepath.Join(dir, tempPattern(base)))
	if err != nil {
		return err
	}
	var errs []error
	for _, m := range matches {
		if !strings.HasPrefix(filepath.Base(m), "."+base+".tmp-") {
			continue
		}
		if err := os.Remove(m); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Remove removes path (absence is not an error) and fsyncs its directory, so
// the removal is durable once Remove returns.
func Remove(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("atomicfile: removing %s: %w", path, err)
	}
	dir := filepath.Dir(path)
	return SyncDir(dir)
}

// syncDir is SyncDir, replaceable by tests.
var syncDir = SyncDir

// SyncDir fsyncs a directory so a rename or removal in it is durable.
func SyncDir(dir string) error {
	d, err := os.Open(dir) //nolint:gosec // G304: dir is the directory of a path this process chose to write.
	if err != nil {
		return fmt.Errorf("atomicfile: opening directory %s: %w", dir, err)
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("atomicfile: fsync directory %s: %w", dir, err)
	}
	return nil
}
