package registrar

import "github.com/bbockelm/htc-registrationd/internal/secret"

// SecretState is a registration's refresh-secret state, as hashes. Renewal
// uses a refresh secret, never the IDTOKEN, so a stolen IDTOKEN cannot be
// renewed. The registrar keeps:
//
//   - Current: the secret last proven by the CE ("" before the first proof);
//   - Pending: the newest secret issued but not yet proven ("" for none);
//   - Retired: secrets superseded by a newer proven one;
//   - Replaced: pending secrets dropped by a reissue before anyone proved them;
//   - Reissues: consecutive reissues since the last promotion.
//
// A REG_RENEW presenting S: S == pending promotes (retired += current,
// current = pending, issue a new pending); S == current reissues (the CE never
// stored or never received the last reply: replaced += pending, issue a new
// pending, current stays valid); S in retired or replaced revokes the
// registration (reuse of a superseded secret); anything else is rejected. The
// transaction commits before the reply is sent.
//
// Crash-safety invariant: the secret the CE most recently stored durably is
// always current or pending here, never retired or replaced. A secret is
// retired only when the CE proves possession of a newer one, and the CE
// presents a newer one only after storing it. A pending secret is replaced
// only when its predecessor (current) is presented, and an honest CE, which
// is serialized and always presents the newest secret it stored, presents
// current only when it never stored that pending: the reply carrying it was
// lost, or the CE crashed before storing it. So a lost reply, a CE crash
// before it stores the reply, or a crash between storing and installing the
// token never revokes: the CE re-presents what it holds and converges.
//
// A copied state file racing the real CE ends with one side presenting a
// retired or replaced secret: the copy presenting the saved current replaces
// the real CE's pending, which the real CE presents next. A copy that only
// ever presents current while the real CE is away is bounded by the reissue
// cap (RenewOptions.MaxReissues).
type SecretState struct {
	Current  string
	Pending  string
	Retired  []string
	Replaced []string
	Reissues int
}

// MaxSupersededHashes bounds the retired and replaced lists: the newest are
// kept. A secret older than that is rejected rather than detected as reuse.
const MaxSupersededHashes = 64

// RenewAction is what a REG_RENEW presenting a secret does to the state.
type RenewAction int

const (
	// RenewReject means the secret matches nothing. No state change.
	RenewReject RenewAction = iota
	// RenewPromote means the secret is the pending one: retired += current,
	// current = pending, and a new pending is issued.
	RenewPromote
	// RenewReissue means the secret is the current one, so the CE never stored (or
	// never received) the last response. A new pending replaces the old one,
	// which is recorded as replaced; current stays valid.
	RenewReissue
	// RenewReuse means the secret was superseded (retired or replaced). The
	// registration is revoked.
	RenewReuse
)

func (a RenewAction) String() string {
	switch a {
	case RenewPromote:
		return "promote"
	case RenewReissue:
		return "reissue"
	case RenewReuse:
		return "reuse"
	}
	return "reject"
}

// Classify decides what presenting secret does, comparing hashes in constant
// time. Pending is checked before current so that a (vanishingly unlikely)
// equal pair behaves as a promotion; every superseded hash is compared even
// after a match, so the time taken does not depend on which one matched.
func Classify(st SecretState, presented string) RenewAction {
	h := secret.Hash(presented)
	if st.Pending != "" && secret.Equal(h, st.Pending) {
		return RenewPromote
	}
	if st.Current != "" && secret.Equal(h, st.Current) {
		return RenewReissue
	}
	reused := false
	for _, list := range [][]string{st.Retired, st.Replaced} {
		for _, r := range list {
			if secret.Equal(h, r) {
				reused = true
			}
		}
	}
	if reused {
		return RenewReuse
	}
	return RenewReject
}

// appendBounded returns list + h, keeping the newest MaxSupersededHashes.
func appendBounded(list []string, h string) []string {
	out := append(append([]string(nil), list...), h)
	if len(out) > MaxSupersededHashes {
		out = out[len(out)-MaxSupersededHashes:]
	}
	return out
}

// Apply returns the state after action, with newPending the hash of the
// freshly issued secret. RenewReject and RenewReuse leave the secrets as they
// are (reuse revokes the registration instead).
func Apply(st SecretState, action RenewAction, newPending string) SecretState {
	switch action {
	case RenewPromote:
		retired := append([]string(nil), st.Retired...)
		if st.Current != "" {
			retired = appendBounded(retired, st.Current)
		}
		return SecretState{Current: st.Pending, Pending: newPending, Retired: retired,
			Replaced: append([]string(nil), st.Replaced...)}
	case RenewReissue:
		replaced := append([]string(nil), st.Replaced...)
		if st.Pending != "" {
			replaced = appendBounded(replaced, st.Pending)
		}
		return SecretState{Current: st.Current, Pending: newPending, Retired: append([]string(nil), st.Retired...),
			Replaced: replaced, Reissues: st.Reissues + 1}
	}
	return st
}
