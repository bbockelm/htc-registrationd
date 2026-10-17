package registrar

import "github.com/bbockelm/htc-registrationd/internal/secret"

// SecretState is a registration's refresh-secret state, as hashes. Renewal
// uses a refresh secret, never the IDTOKEN, so a stolen IDTOKEN cannot be
// renewed. The registrar keeps:
//
//   - Current: the secret last proven by the CE ("" before the first proof);
//   - Pending: the newest secret issued but not yet proven ("" for none);
//   - Retired: every secret superseded by a newer proven one.
//
// A REG_RENEW presenting S: S == pending promotes (retired += current,
// current = pending, issue a new pending); S == current reissues (the CE never
// stored or never received the last reply: issue a new pending to replace the
// old, current stays valid); S in retired revokes the registration (reuse of a
// superseded secret); anything else is rejected. The transaction commits
// before the reply is sent.
//
// Crash-safety invariant: the secret the CE most recently stored durably is
// always current or pending here, never retired. A secret is retired only when
// the CE proves possession of a newer one, and the CE presents a newer one
// only after storing it. So a lost reply, a CE crash before it stores the
// reply, or a crash between storing and installing the token never revokes:
// the CE re-presents what it holds and converges. Only a copied state file
// racing the real CE can make one side present a retired secret.
type SecretState struct {
	Current string
	Pending string
	Retired []string
}

// RenewAction is what a REG_RENEW presenting a secret does to the state.
type RenewAction int

const (
	// RenewReject means the secret matches nothing. No state change.
	RenewReject RenewAction = iota
	// RenewPromote means the secret is the pending one: retired += current,
	// current = pending, and a new pending is issued.
	RenewPromote
	// RenewReissue means the secret is the current one, so the CE never stored (or
	// never received) the last response. A new pending replaces the old one;
	// current stays valid.
	RenewReissue
	// RenewReuse means the secret was superseded by a newer proven one. The
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
// equal pair behaves as a promotion; every retired hash is compared even after
// a match, so the time taken does not depend on which one matched.
func Classify(st SecretState, presented string) RenewAction {
	h := secret.Hash(presented)
	if st.Pending != "" && secret.Equal(h, st.Pending) {
		return RenewPromote
	}
	if st.Current != "" && secret.Equal(h, st.Current) {
		return RenewReissue
	}
	reused := false
	for _, r := range st.Retired {
		if secret.Equal(h, r) {
			reused = true
		}
	}
	if reused {
		return RenewReuse
	}
	return RenewReject
}

// Apply returns the state after action, with newPending the hash of the
// freshly issued secret. RenewReject and RenewReuse leave the secrets as they
// are (reuse revokes the registration instead).
func Apply(st SecretState, action RenewAction, newPending string) SecretState {
	switch action {
	case RenewPromote:
		retired := append([]string(nil), st.Retired...)
		if st.Current != "" {
			retired = append(retired, st.Current)
		}
		return SecretState{Current: st.Pending, Pending: newPending, Retired: retired}
	case RenewReissue:
		return SecretState{Current: st.Current, Pending: newPending, Retired: append([]string(nil), st.Retired...)}
	}
	return st
}
