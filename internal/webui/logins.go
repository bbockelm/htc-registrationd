package webui

import (
	"container/list"
	"sync"
	"time"
)

// loginTTL bounds how long a login may take at the identity provider.
const loginTTL = 10 * time.Minute

// maxPendingLogins bounds the logins in flight.
const maxPendingLogins = 10000

// loginStore holds the logins in flight (state, PKCE verifier, page to
// return to) in memory, so starting a login writes nothing to disk. It
// keeps at most max; when full, the oldest is dropped. A dropped login, or
// one lost to a restart, only means its user starts again.
type loginStore struct {
	now func() time.Time
	max int

	mu      sync.Mutex
	byState map[string]*list.Element
	// order holds *pendingLogin, oldest first.
	order *list.List
}

type pendingLogin struct {
	state    string
	verifier string
	next     string
	created  time.Time
}

func newLoginStore(now func() time.Time, maxLogins int) *loginStore {
	return &loginStore{now: now, max: maxLogins, byState: map[string]*list.Element{}, order: list.New()}
}

// save records a login in flight.
func (l *loginStore) save(state, verifier, next string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	for e := l.order.Front(); e != nil; e = l.order.Front() {
		p := e.Value.(*pendingLogin)
		if l.order.Len() < l.max && now.Sub(p.created) <= loginTTL {
			break
		}
		l.order.Remove(e)
		delete(l.byState, p.state)
	}
	if old := l.byState[state]; old != nil {
		l.order.Remove(old)
	}
	l.byState[state] = l.order.PushBack(&pendingLogin{state: state, verifier: verifier, next: next, created: now})
}

// take returns and forgets the login with state. Each state is good for one
// callback, within loginTTL.
func (l *loginStore) take(state string) (verifier, next string, ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.byState[state]
	if e == nil {
		return "", "", false
	}
	l.order.Remove(e)
	delete(l.byState, state)
	p := e.Value.(*pendingLogin)
	if l.now().Sub(p.created) > loginTTL {
		return "", "", false
	}
	return p.verifier, p.next, true
}

// len is the number of logins held.
func (l *loginStore) len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.order.Len()
}
