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
// \N in the names is replaced by the regex's group N (\0 is the whole
// match, or the principal on a literal line). Substituted text is part of
// a name, never a separator or a pattern: a line whose substituted text
// contains a comma, a glob character or a backslash allows nothing.
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

// mapSnapshot is one loaded version of the file. mapfile.MapFile parses
// it; the OIDC lines are matched here, as MapFile.Map matches them, because
// Map returns only the substituted text and authorization must know which
// parts of it came from the principal.
type mapSnapshot struct {
	stamp fileStamp
	// lines are the OIDC lines in file order.
	lines []lineMatcher
	// literals maps a literal principal to the index in lines of the first
	// literal line for it.
	literals map[string]int
	known    map[string]bool
}

type lineMatcher struct {
	entry mapfile.Entry
	// re is set on a regular-expression line.
	re *regexp.Regexp
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
	snap := &mapSnapshot{stamp: st, literals: map[string]int{}, known: map[string]bool{}}
	for _, e := range mf.Entries(MapfileMethod) {
		lm := lineMatcher{entry: e}
		if e.Regex {
			// The same flags mapfile.Load compiled the pattern with.
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
			if lm.re, err = regexp.Compile(src); err != nil {
				return nil, fmt.Errorf("authorization mapfile: %s line %d: %w", e.File, e.Line, err)
			}
		} else if _, dup := snap.literals[e.Principal]; !dup {
			snap.literals[e.Principal] = len(snap.lines)
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

// match returns the line that wins for principal and its groups for \N,
// as MapFile.Map chooses them: the first regular-expression line that
// matches and comes before the principal's first literal line, else that
// literal line (whose \0 is the principal).
func (s *mapSnapshot) match(principal string) (*lineMatcher, []string, bool) {
	lit, haveLit := s.literals[principal]
	for i := range s.lines {
		if haveLit && i > lit {
			break
		}
		if l := &s.lines[i]; l.re != nil {
			if groups, ok := regexGroups(l.re, principal); ok {
				return l, groups, true
			}
		}
	}
	if haveLit {
		return &s.lines[lit], []string{principal}, true
	}
	return nil, nil, false
}

// regexGroups searches principal with re and returns the groups as
// MapFile.Map substitutes them: up to the highest group that took part in
// the match, with groups that did not take part empty.
func regexGroups(re *regexp.Regexp, principal string) ([]string, bool) {
	loc := re.FindStringSubmatchIndex(principal)
	if loc == nil {
		return nil, false
	}
	n := len(loc) / 2
	for n > 1 && loc[2*(n-1)] < 0 {
		n--
	}
	groups := make([]string, n)
	for i := range n {
		if loc[2*i] >= 0 {
			groups[i] = principal[loc[2*i]:loc[2*i+1]]
		}
	}
	return groups, true
}

// unsafeSubstitution are the characters substituted text may not contain:
// the name separator and everything isGlob and path.Match treat specially.
const unsafeSubstitution = `,*?[\`

// substitute replaces \N in canon with group N, as MapFile.Map does (a
// backslash before anything else is kept with the character after it, and
// a trailing backslash is dropped). It reports false when a substituted
// group contains a character from unsafeSubstitution, so text from the
// principal can only ever be matched literally.
func substitute(canon string, groups []string) (string, bool) {
	if strings.IndexByte(canon, '\\') < 0 {
		return canon, true
	}
	var b strings.Builder
	for i := 0; i < len(canon); i++ {
		c := canon[i]
		if c != '\\' {
			b.WriteByte(c)
			continue
		}
		i++
		if i == len(canon) {
			break
		}
		if d := int(canon[i]) - '0'; d >= 0 && d <= 9 && d < len(groups) {
			if strings.ContainsAny(groups[d], unsafeSubstitution) {
				return "", false
			}
			b.WriteString(groups[d])
			continue
		}
		b.WriteByte('\\')
		b.WriteByte(canon[i])
	}
	return b.String(), true
}

// Decide implements Backend. The UI shows Reason; Source names the file
// and line for the audit log.
func (m *Mapfile) Decide(_ context.Context, principal, name string) (Decision, error) {
	snap := m.current()
	if snap == nil {
		return Decision{}, errors.New("no mapfile is loaded")
	}
	l, groups, ok := snap.match(principal)
	if !ok {
		return Decision{Reason: "The registrar's map file does not name you"}, nil
	}
	src := fmt.Sprintf("%s line %d", l.entry.File, l.entry.Line)
	notListed := Decision{Reason: "The registrar's map file does not allow you to approve " + name, Source: src}
	canon, ok := substitute(l.entry.Canonicalization, groups)
	if !ok {
		m.Logger.Warn("authz: refusing a mapfile substitution with a comma, glob character or backslash",
			"line", src, "principal", principal)
		return notListed, nil
	}
	for _, n := range splitNames(canon) {
		if matchName(n, name) {
			return Decision{Allowed: true, Reason: "Allowed by the registrar's map file", Source: src}, nil
		}
	}
	return notListed, nil
}

// Known implements Backend.
func (m *Mapfile) Known(_ context.Context, name string) (bool, error) {
	snap := m.current()
	if snap == nil {
		return false, errors.New("no mapfile is loaded")
	}
	return snap.known[strings.ToLower(name)], nil
}
