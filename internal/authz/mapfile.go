package authz

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/bbockelm/golang-htcondor/mapfile"
)

// MapfileMethod is the mapfile method of OIDC principals.
const MapfileMethod = "OIDC"

// Mapfile authorizes from an HTCondor-format map file. Each line
//
//	OIDC <principal> <name>[,<name>...]
//
// lets principal (literal, or /regex/) approve the listed CE names. A name
// is literal or a path.Match glob, compared without regard to case. As in
// every HTCondor map file, the first line whose principal matches wins, so
// a principal's names belong on one line.
//
// Only literal names are Known: a glob cannot vouch for a specific name
// in callback mode.
//
// The file is re-read when its modification time or size changes (checked
// at most once per CheckInterval) and on Reload. A failed re-read keeps the
// last good map.
type Mapfile struct {
	// CheckInterval bounds how often the file is stat'ed (default 1 s).
	CheckInterval time.Duration
	Logger        *slog.Logger
	Now           func() time.Time

	mu        sync.Mutex
	path      string
	snap      *mapSnapshot
	checkedAt time.Time
	// failed is the stat of the last version that would not load, so a
	// broken file is reported once rather than at every check.
	failed fileStamp
}

type fileStamp struct {
	mtime int64 // UnixNano
	size  int64
}

// statFailed marks a file that could not be stat'ed.
var statFailed = fileStamp{size: -1}

type mapSnapshot struct {
	mf    *mapfile.MapFile
	stamp fileStamp
	// lines matches principals to the line that wins, for Reason.
	lines []lineMatcher
	known map[string]bool
}

type lineMatcher struct {
	entry mapfile.Entry
	re    *regexp.Regexp
}

// NewMapfile loads path. A file that does not load at startup is an error.
func NewMapfile(path string, log *slog.Logger) (*Mapfile, error) {
	if log == nil {
		log = slog.Default()
	}
	m := &Mapfile{path: path, Logger: log, Now: time.Now, CheckInterval: time.Second}
	snap, err := loadMapfile(path)
	if err != nil {
		return nil, err
	}
	m.snap, m.checkedAt = snap, m.Now()
	return m, nil
}

// Name implements Backend.
func (*Mapfile) Name() string { return "mapfile" }

// Path returns the file in use.
func (m *Mapfile) Path() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.path
}

func stat(path string) (fileStamp, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return fileStamp{}, err
	}
	return fileStamp{mtime: fi.ModTime().UnixNano(), size: fi.Size()}, nil
}

func loadMapfile(p string) (*mapSnapshot, error) {
	st, err := stat(p)
	if err != nil {
		return nil, fmt.Errorf("authorization mapfile: %w", err)
	}
	mf, err := mapfile.Load(p)
	if err != nil {
		return nil, fmt.Errorf("authorization mapfile: %w", err)
	}
	snap := &mapSnapshot{mf: mf, stamp: st, known: map[string]bool{}}
	for _, e := range mf.Entries(MapfileMethod) {
		lm := lineMatcher{entry: e}
		if e.Regex {
			flags := ""
			if e.IgnoreCase {
				flags += "i"
			}
			if e.Ungreedy {
				flags += "U"
			}
			src := e.Principal
			if flags != "" {
				src = "(?" + flags + ")" + src
			}
			// mapfile.Load has already compiled this pattern; a failure
			// here only costs the line number in Reason.
			lm.re, _ = regexp.Compile(src)
		}
		snap.lines = append(snap.lines, lm)
		for _, n := range splitNames(e.Canonicalization) {
			if !isGlob(n) {
				snap.known[strings.ToLower(n)] = true
			}
		}
	}
	return snap, nil
}

// Reload re-reads the file now, switching to newPath when it is not empty.
// On failure the last good map stays in use and the error is returned.
func (m *Mapfile) Reload(newPath string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.path
	if newPath != "" {
		p = newPath
	}
	snap, err := loadMapfile(p)
	m.checkedAt = m.Now()
	if err != nil {
		m.Logger.Error("authz: keeping the last good mapfile", "path", p, "err", err)
		return err
	}
	m.path, m.snap, m.failed = p, snap, fileStamp{}
	m.Logger.Info("authz: mapfile loaded", "path", p, "lines", len(snap.lines))
	return nil
}

// current returns the map in use, re-reading the file if it changed.
func (m *Mapfile) current() *mapSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.Now()
	if now.Sub(m.checkedAt) < m.CheckInterval {
		return m.snap
	}
	m.checkedAt = now
	st, err := stat(m.path)
	if err != nil {
		if m.failed != statFailed {
			m.Logger.Error("authz: cannot stat the mapfile; keeping the last good map", "path", m.path, "err", err)
		}
		m.failed = statFailed
		return m.snap
	}
	if st == m.snap.stamp {
		if m.failed == statFailed {
			m.failed = fileStamp{}
		}
		return m.snap
	}
	if st == m.failed {
		return m.snap
	}
	snap, err := loadMapfile(m.path)
	if err != nil {
		m.failed = st
		m.Logger.Error("authz: the changed mapfile does not load; keeping the last good map", "path", m.path, "err", err)
		return m.snap
	}
	m.snap, m.failed = snap, fileStamp{}
	m.Logger.Info("authz: mapfile reloaded", "path", m.path, "lines", len(snap.lines))
	return m.snap
}

// splitNames splits a canonicalization into names.
func splitNames(canon string) []string {
	var out []string
	for _, n := range strings.Split(canon, ",") {
		if n = strings.TrimSpace(n); n != "" {
			out = append(out, n)
		}
	}
	return out
}

func isGlob(n string) bool { return strings.ContainsAny(n, `*?[\`) }

// matchName reports whether name matches pattern (literal or path.Match
// glob), without regard to case. A malformed pattern matches nothing.
func matchName(pattern, name string) bool {
	pattern, name = strings.ToLower(pattern), strings.ToLower(name)
	if !isGlob(pattern) {
		return pattern == name
	}
	ok, err := path.Match(pattern, name)
	return err == nil && ok
}

// winningLine returns the line whose principal matches first, in file
// order, as the map file's lookup does.
func (s *mapSnapshot) winningLine(principal string) (mapfile.Entry, bool) {
	for _, l := range s.lines {
		switch {
		case !l.entry.Regex && l.entry.Principal == principal:
			return l.entry, true
		case l.entry.Regex && l.re != nil && l.re.MatchString(principal):
			return l.entry, true
		}
	}
	return mapfile.Entry{}, false
}

func (m *Mapfile) lineRef(e mapfile.Entry, ok bool) string {
	if !ok {
		return "a mapfile line"
	}
	if e.File == "" || e.File == m.Path() {
		return fmt.Sprintf("mapfile line %d", e.Line)
	}
	return fmt.Sprintf("%s line %d", e.File, e.Line)
}

// Decide implements Backend.
func (m *Mapfile) Decide(_ context.Context, principal, name string) (Decision, error) {
	snap := m.current()
	if snap == nil {
		return Decision{}, errors.New("no mapfile is loaded")
	}
	canon, ok := snap.mf.Map(MapfileMethod, principal)
	if !ok {
		return Decision{Reason: "No mapfile line matches your identity"}, nil
	}
	e, found := snap.winningLine(principal)
	ref := m.lineRef(e, found)
	for _, n := range splitNames(canon) {
		if matchName(n, name) {
			return Decision{Allowed: true, Reason: ref}, nil
		}
	}
	return Decision{Reason: fmt.Sprintf("%s does not list %s", capitalize(ref), name)}, nil
}

// Known implements Backend.
func (m *Mapfile) Known(_ context.Context, name string) (bool, error) {
	snap := m.current()
	if snap == nil {
		return false, errors.New("no mapfile is loaded")
	}
	return snap.known[strings.ToLower(name)], nil
}

func capitalize(s string) string {
	if s == "" || s[0] < 'a' || s[0] > 'z' {
		return s
	}
	return string(s[0]-'a'+'A') + s[1:]
}
