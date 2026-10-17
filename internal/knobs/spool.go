package knobs

import (
	"path/filepath"
	"strings"
)

// SpoolWarning returns a warning when stateDir lies under $(SPOOL) but
// condor_preen would consider it stray: preen keeps a top-level spool entry
// only if some VALID_SPOOL_FILES (or SYSTEM_VALID_SPOOL_FILES) entry is a
// prefix of its name. It returns "" when there is nothing to warn about.
func SpoolWarning(cfg Getter, stateDir string) string {
	spool := String(cfg, "SPOOL", "")
	if spool == "" || stateDir == "" {
		return ""
	}
	rel, err := filepath.Rel(filepath.Clean(spool), filepath.Clean(stateDir))
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return ""
	}
	top := strings.Split(rel, string(filepath.Separator))[0]
	valid := append(List(cfg, "VALID_SPOOL_FILES", nil), List(cfg, "SYSTEM_VALID_SPOOL_FILES", nil)...)
	for _, v := range valid {
		if strings.HasPrefix(top, v) {
			return ""
		}
	}
	return "the state directory " + stateDir + " is under SPOOL but VALID_SPOOL_FILES does not cover " + top +
		"; condor_preen may delete it. Add: VALID_SPOOL_FILES = $(VALID_SPOOL_FILES) " + top
}
