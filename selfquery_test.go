package ctrld

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func trackForTest(msg *dns.Msg) func() bool {
	key, _ := newSelfQueryKey(msg)
	e := &selfQueryEntry{kind: SelfQueryKindLegacy, upstream: "uid"}
	selfQueries.add(key, e)
	return func() bool {
		selfQueries.remove(key, e)
		return e.looped.Load()
	}
}

// A query from this host for the same name but another message ID is only
// suspected: it is served, and the exchange is left alone.
func TestSelfQueryIDMismatchIsOnlySuspected(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("dup.example.", dns.TypeA)
	release := trackForTest(m)
	other := m.Copy()
	other.Id = m.Id + 1
	match, ok := MatchSelfQuery(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40000}, other)
	if !ok || !match.Suspected {
		t.Fatalf("match = %+v %v, want suspected", match, ok)
	}
	if release() {
		t.Fatal("a suspected copy failed the exchange")
	}
	// From a LAN address even an exact copy is not a loop.
	release = trackForTest(m)
	if _, ok := MatchSelfQuery(&net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 40000}, m); ok {
		t.Fatal("matched a copy from a non-local address")
	}
	if release() {
		t.Fatal("a non-local copy failed the exchange")
	}
}

// slowServer answers every query after delay and records the IDs it saw.
func slowServer(t *testing.T, delay time.Duration) (string, chan uint16) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ids := make(chan uint16, 8)
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, m *dns.Msg) {
		ids <- m.Id
		time.Sleep(delay)
		a := new(dns.Msg)
		a.SetReply(m)
		a.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 1)}}
		_ = w.WriteMsg(a)
	})}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = srv.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String(), ids
}

// A stub resolver retransmits with the client's message ID while ctrld's
// forward of the first try is still waiting on a slow server. That retry
// must not be taken for ctrld's own query: it is not matched exactly, the
// genuine exchange completes, and the caller gets the answer under its ID.
func TestSelfQueryClientRetryWhileForwardIsSlow(t *testing.T) {
	server, ids := slowServer(t, 300*time.Millisecond)
	client := new(dns.Msg)
	client.SetQuestion("slow.example.", dns.TypeA)
	client.Id = 4242

	type result struct {
		answer *dns.Msg
		err    error
	}
	done := make(chan result, 1)
	go func() {
		a, _, err := exchangeTracked(context.Background(), &dns.Client{Net: "udp", Timeout: 3 * time.Second}, client, server, SelfQueryKindLegacy, "uid")
		done <- result{a, err}
	}()
	var sentID uint16
	select {
	case sentID = <-ids:
	case <-time.After(2 * time.Second):
		t.Fatal("the forward never reached the server")
	}
	if sentID == client.Id {
		t.Errorf("the forward kept the client's message ID %d", client.Id)
	}

	retry := client.Copy() // same ID, same question, from loopback
	match, ok := MatchSelfQuery(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 50000}, retry)
	if ok && !match.Suspected {
		t.Fatalf("a client retry was taken for ctrld's own query: %+v", match)
	}

	r := <-done
	if r.err != nil {
		t.Fatalf("the genuine exchange failed: %v", r.err)
	}
	if r.answer == nil || r.answer.Id != client.Id || len(r.answer.Answer) != 1 {
		t.Fatalf("answer = %v, want one record under ID %d", r.answer, client.Id)
	}

	// A copy of what ctrld actually sent still matches exactly.
	echo := client.Copy()
	echo.Id = sentID
	go func() {
		_, _, _ = exchangeTracked(context.Background(), &dns.Client{Net: "udp", Timeout: 3 * time.Second}, client, server, SelfQueryKindLegacy, "uid")
	}()
	sentID = <-ids
	echo.Id = sentID
	match, ok = MatchSelfQuery(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 50001}, echo)
	if !ok || match.Suspected || match.UpstreamUID != "uid" {
		t.Fatalf("a copy of ctrld's own query did not match exactly: %+v %v", match, ok)
	}
}
