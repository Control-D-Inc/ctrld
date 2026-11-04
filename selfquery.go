package ctrld

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// ErrSelfLoop is the error of a plain DNS exchange whose query came back to
// ctrld's own listener instead of reaching the server it was sent to.
//
// In DNS intercept mode the OS redirects outbound port 53 traffic to ctrld,
// and only ctrld's own sockets are meant to be exempt. When that exemption
// does not apply, ctrld's query to a LAN resolver is delivered to its own
// listener, which forwards it again. Recognizing the returned query ends that
// recursion at the first step.
var ErrSelfLoop = errors.New("query returned to ctrld's own listener")

// Kinds of outbound query, recorded so a self loop report can name the path
// that looped without naming a server or a domain.
const (
	SelfQueryKindLegacy = "legacy"
	SelfQueryKindOS     = "os_resolver"
)

// selfQueryKey identifies one outbound query as it arrives back at the
// listener. The source port and transport are deliberately not part of it:
// a network extension that takes over ctrld's socket re-sends the query from
// its own socket, so the copy keeps the DNS message but not the port.
type selfQueryKey struct {
	id    uint16
	name  string
	qtype uint16
}

// selfQuestionKey is selfQueryKey without the message ID. A copy that matches
// only on it is reported as suspected, never acted on: a client can ask the
// same name while ctrld's query for it is in flight.
type selfQuestionKey struct {
	name  string
	qtype uint16
}

type selfQueryEntry struct {
	kind     string
	upstream string
	looped   atomic.Bool
}

// SelfQueryMatch describes an outbound query that came back to the listener.
type SelfQueryMatch struct {
	Kind string
	// UpstreamUID is the UID of the upstream config that sent the query, empty
	// for the OS resolver.
	UpstreamUID string
	// Suspected is set when the copy matched an in-flight question but not
	// its message ID. The exchange is left alone in that case.
	Suspected bool
}

// selfQueryTable holds the outbound queries waiting for an answer. Several
// exchanges can share a key: the OS resolver sends one message to each of its
// nameservers at once.
type selfQueryTable struct {
	mu        sync.Mutex
	byID      map[selfQueryKey][]*selfQueryEntry
	questions map[selfQuestionKey]int
}

var selfQueries = &selfQueryTable{
	byID:      make(map[selfQueryKey][]*selfQueryEntry),
	questions: make(map[selfQuestionKey]int),
}

// SelfQueryStats counts tracked exchanges, and those whose socket reported a
// zero local port after connecting. On macOS a zero local port is what a
// socket taken over by a network extension reports, so the ratio tells a
// diverted host apart from a host with a plain pf problem.
type SelfQueryStats struct {
	Sent          uint64
	LocalPortZero uint64
}

var (
	selfQueriesSent          atomic.Uint64
	selfQueriesLocalPortZero atomic.Uint64
)

// ReadSelfQueryStats returns the counters since the process started.
func ReadSelfQueryStats() SelfQueryStats {
	return SelfQueryStats{Sent: selfQueriesSent.Load(), LocalPortZero: selfQueriesLocalPortZero.Load()}
}

func newSelfQueryKey(msg *dns.Msg) (selfQueryKey, bool) {
	if msg == nil || len(msg.Question) != 1 {
		return selfQueryKey{}, false
	}
	q := msg.Question[0]
	return selfQueryKey{id: msg.Id, name: strings.ToLower(dns.Fqdn(q.Name)), qtype: q.Qtype}, true
}

func (k selfQueryKey) question() selfQuestionKey {
	return selfQuestionKey{name: k.name, qtype: k.qtype}
}

func (t *selfQueryTable) add(key selfQueryKey, e *selfQueryEntry) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.byID[key] = append(t.byID[key], e)
	t.questions[key.question()]++
}

func (t *selfQueryTable) remove(key selfQueryKey, e *selfQueryEntry) {
	t.mu.Lock()
	defer t.mu.Unlock()
	entries := t.byID[key]
	for i, v := range entries {
		if v == e {
			entries = append(entries[:i], entries[i+1:]...)
			break
		}
	}
	if len(entries) == 0 {
		delete(t.byID, key)
	} else {
		t.byID[key] = entries
	}
	q := key.question()
	if t.questions[q] <= 1 {
		delete(t.questions, q)
	} else {
		t.questions[q]--
	}
}

// lookup reports whether exchanges wait under key, or failing that, whether
// the question alone is in flight.
func (t *selfQueryTable) lookup(key selfQueryKey) (exact, question bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.byID[key]) > 0 {
		return true, true
	}
	return false, t.questions[key.question()] > 0
}

// mark fails every exchange waiting under key and returns the first one.
func (t *selfQueryTable) mark(key selfQueryKey) *selfQueryEntry {
	t.mu.Lock()
	defer t.mu.Unlock()
	entries := t.byID[key]
	for _, e := range entries {
		e.looped.Store(true)
	}
	if len(entries) == 0 {
		return nil
	}
	return entries[0]
}

// MatchSelfQuery reports whether msg, received by the listener from remote,
// is one of ctrld's own outbound queries that is still waiting for an
// answer. A match also fails that exchange with ErrSelfLoop, so the sender
// does not take the listener's reply as the server's answer.
//
// Only a remote address of this host can match: a redirected packet keeps a
// local source address, whichever local socket re-sent it.
func MatchSelfQuery(remote net.Addr, msg *dns.Msg) (SelfQueryMatch, bool) {
	key, ok := newSelfQueryKey(msg)
	if !ok {
		return SelfQueryMatch{}, false
	}
	// The table lookup comes first: it misses for nearly every query, so the
	// address check runs only on a candidate.
	exact, question := selfQueries.lookup(key)
	if !question || !isLocalSource(remote) {
		return SelfQueryMatch{}, false
	}
	if exact {
		if e := selfQueries.mark(key); e != nil {
			return SelfQueryMatch{Kind: e.kind, UpstreamUID: e.upstream}, true
		}
	}
	return SelfQueryMatch{Suspected: true}, true
}

// isLocalSource reports whether addr belongs to this host.
func isLocalSource(addr net.Addr) bool {
	var ip net.IP
	switch a := addr.(type) {
	case *net.UDPAddr:
		ip = a.IP
	case *net.TCPAddr:
		ip = a.IP
	default:
		return false
	}
	ap, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	ap = ap.Unmap()
	if ap.IsLoopback() {
		return true
	}
	return hasLocalAddr(ap)
}

// hasLocalAddr is a seam for tests; production reads the host's addresses.
var hasLocalAddr = func(ip netip.Addr) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if p, ok := a.(*net.IPNet); ok {
			if ap, ok := netip.AddrFromSlice(p.IP); ok && ap.Unmap() == ip {
				return true
			}
		}
	}
	return false
}

func localPort(addr net.Addr) (int, bool) {
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a.Port, true
	case *net.TCPAddr:
		return a.Port, true
	}
	return 0, false
}

// exchangeTracked is dns.Client.ExchangeContext with the query registered
// for MatchSelfQuery while it waits for an answer.
//
// The query goes out with a fresh message ID. A forwarded query otherwise
// keeps the client's ID, and a stub resolver retransmits with that same ID
// when the first try is slow, so the client's retry would look exactly like
// ctrld's own query coming back. With a fresh ID only a copy of what ctrld
// sent matches exactly; a client retry matches only the question, which is
// served normally. The answer is given back under the caller's ID.
func exchangeTracked(ctx context.Context, c *dns.Client, msg *dns.Msg, address, kind, upstreamUID string) (*dns.Msg, time.Duration, error) {
	conn, err := c.DialContext(ctx, address)
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()
	selfQueriesSent.Add(1)
	if port, ok := localPort(conn.LocalAddr()); ok && port == 0 {
		selfQueriesLocalPortZero.Add(1)
	}
	q := msg.Copy()
	// Never the caller's own ID: that is exactly what a retry would carry.
	for q.Id = dns.Id(); q.Id == msg.Id; q.Id = dns.Id() {
	}
	key, tracked := newSelfQueryKey(q)
	var entry *selfQueryEntry
	if tracked {
		entry = &selfQueryEntry{kind: kind, upstream: upstreamUID}
		selfQueries.add(key, entry)
		defer selfQueries.remove(key, entry)
	}
	answer, rtt, err := c.ExchangeWithConnContext(ctx, q, conn)
	if entry != nil && entry.looped.Load() {
		return nil, rtt, ErrSelfLoop
	}
	if answer != nil {
		answer.Id = msg.Id
	}
	return answer, rtt, err
}
