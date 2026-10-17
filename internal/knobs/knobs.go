// Package knobs reads htc-registrationd's HTC_REGISTRATIOND_* configuration
// values with typed defaults.
package knobs

import (
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"
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

// Bool returns key as a boolean the way HTCondor's param_boolean reads one,
// or def when unset. An invalid value is logged as an error (HTCondor may
// treat it as fatal) and does not stop the daemon.
//
// It ports param_boolean / string_is_boolean_param (condor_config.cpp).
// golang-htcondor's config.StringIsBooleanParam and (*Config).GetBool are the
// same port; once the golang-htcondor this module depends on has them, this
// function can call those instead.
func Bool(cfg Getter, key string, def bool) bool {
	v := String(cfg, key, "")
	if v == "" {
		return def
	}
	result, valid := StringIsBooleanParam(v, def)
	if !valid {
		slog.Error(fmt.Sprintf("%s in the configuration is not a valid boolean (%q); please set it to True or False",
			key, v), "using", result)
	}
	return result
}

// StringIsBooleanParam is HTCondor's string_is_boolean_param. A value is
// true, false, 1 or 0 (case-insensitive) followed only by white space, or else
// an old-syntax ClassAd expression that evaluates to a boolean or a number
// (non-zero is true). It returns the value and whether s was valid. When s is
// not valid, the result is def, except that a valid literal prefix
// ("truex", "0 0") yields that literal, as in HTCondor.
func StringIsBooleanParam(s string, def bool) (result bool, valid bool) {
	result = def
	rest := ""
	lower := strings.ToLower(s)
	switch {
	case strings.HasPrefix(lower, "true"):
		result, rest, valid = true, s[4:], true
	case strings.HasPrefix(lower, "1"):
		result, rest, valid = true, s[1:], true
	case strings.HasPrefix(lower, "false"):
		result, rest, valid = false, s[5:], true
	case strings.HasPrefix(lower, "0"):
		result, rest, valid = false, s[1:], true
	}
	if valid && strings.TrimLeft(rest, " \t\n\r\v\f") == "" {
		return result, true
	}
	expr, err := classad.ParseExprOld(s)
	if err != nil {
		return result, false
	}
	val := expr.Eval(classad.New())
	switch {
	case val.IsBool():
		b, _ := val.BoolValue()
		return b, true
	case val.IsInteger():
		n, _ := val.IntValue()
		return n != 0, true
	case val.IsReal():
		f, _ := val.RealValue()
		return f != 0, true
	}
	return result, false
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
