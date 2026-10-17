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
