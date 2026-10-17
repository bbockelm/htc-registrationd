// Package knobs reads htc-registrationd's HTC_REGISTRATIOND_* configuration
// values with typed defaults.
package knobs

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Getter is the read side of golang-htcondor's *config.Config.
type Getter interface {
	Get(key string) (string, bool)
}

// Prefix is the prefix of every knob this daemon owns.
const Prefix = "HTC_REGISTRATIOND_"

// String returns key's trimmed value, or def when unset or empty.
func String(cfg Getter, key, def string) string {
	if cfg == nil {
		return def
	}
	if v, ok := cfg.Get(key); ok {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return def
}

// Bool returns key as a boolean (true/false/yes/no/1/0, case-insensitive), or
// def when unset. An unparseable value is an error.
func Bool(cfg Getter, key string, def bool) (bool, error) {
	v := String(cfg, key, "")
	if v == "" {
		return def, nil
	}
	switch strings.ToLower(v) {
	case "true", "yes", "1", "t", "y", "on":
		return true, nil
	case "false", "no", "0", "f", "n", "off":
		return false, nil
	}
	return def, fmt.Errorf("%s: %q is not a boolean", key, v)
}

// Int returns key as an integer, or def when unset.
func Int(cfg Getter, key string, def int) (int, error) {
	v := String(cfg, key, "")
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def, fmt.Errorf("%s: %q is not an integer", key, v)
	}
	return n, nil
}

// Duration returns key as a duration. A bare integer is seconds, as HTCondor
// time knobs are; a Go duration string ("72h", "30m") is also accepted.
func Duration(cfg Getter, key string, def time.Duration) (time.Duration, error) {
	v := String(cfg, key, "")
	if v == "" {
		return def, nil
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		return time.Duration(n) * time.Second, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def, fmt.Errorf("%s: %q is neither seconds nor a duration", key, v)
	}
	return d, nil
}

// List splits key's value on commas and white space.
func List(cfg Getter, key string, def []string) []string {
	v := String(cfg, key, "")
	if v == "" {
		return def
	}
	return strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' })
}

// Map is an in-memory Getter for tests and defaults.
type Map map[string]string

// Get implements Getter, case-insensitively as HTCondor config is.
func (m Map) Get(key string) (string, bool) {
	if v, ok := m[key]; ok {
		return v, true
	}
	for k, v := range m {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return "", false
}
