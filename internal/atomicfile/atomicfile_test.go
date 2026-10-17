package atomicfile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileReplacesAndSetsMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "registration.json")
	if err := WriteFile(path, []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(path, []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path) //nolint:gosec // test temp file
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "two" {
		t.Fatalf("contents %q, want two", got)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o, want 600", st.Mode().Perm())
	}
	assertNoTemps(t, dir)
}

// A crash before the rename leaves the old file intact, and no temporary file
// survives a failed write.
func TestWriteFileFailureLeavesOldContents(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	crash := errors.New("simulated crash")
	hook = func(string) error { return crash }
	t.Cleanup(func() { hook = nil })
	if err := WriteFile(path, []byte("new"), 0o600); !errors.Is(err, crash) {
		t.Fatalf("err = %v, want the simulated crash", err)
	}
	got, err := os.ReadFile(path) //nolint:gosec // test temp file
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "old" {
		t.Fatalf("contents %q, want old", got)
	}
	assertNoTemps(t, dir)
}

func TestRemove(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "approval-url")
	if err := WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("file still present: %v", err)
	}
	if err := Remove(path); err != nil {
		t.Fatalf("removing an absent file: %v", err)
	}
}

func assertNoTemps(t *testing.T, dir string) {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if len(e.Name()) > 0 && e.Name()[0] == '.' {
			t.Errorf("temporary file left behind: %s", e.Name())
		}
	}
}

// A failed directory fsync after the rename is not a failure: the new file is
// in place, and reporting an error would leave the caller's memory and the
// file disagreeing.
func TestDirSyncFailureAfterRename(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	orig := syncDir
	syncDir = func(string) error { return errors.New("injected fsync failure") }
	t.Cleanup(func() { syncDir = orig })
	if err := WriteFile(path, []byte("new"), 0o600); err != nil {
		t.Fatalf("WriteFile reported %v after the rename succeeded", err)
	}
	if b, _ := os.ReadFile(path); string(b) != "new" { //nolint:gosec // test temp file
		t.Fatalf("contents %q", b)
	}
}

// RemoveTemps removes a crash's leftover temporary files of one target and
// nothing else.
func TestRemoveTemps(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "50-htc-registration")
	keep := []string{"50-htc-registration", "other-token", ".other-token.tmp-123", "50-htc-registration.tmp-1"}
	gone := []string{".50-htc-registration.tmp-123", ".50-htc-registration.tmp-abc"}
	for _, n := range append(append([]string(nil), keep...), gone...) {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := RemoveTemps(path); err != nil {
		t.Fatal(err)
	}
	for _, n := range keep {
		if _, err := os.Stat(filepath.Join(dir, n)); err != nil {
			t.Errorf("%s was removed", n)
		}
	}
	for _, n := range gone {
		if _, err := os.Stat(filepath.Join(dir, n)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s was kept", n)
		}
	}
}
