package cli

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
)

// LAN name fallback (issue #674).
//
// Without ctrld, the Windows DNS Client looks a name up in DNS first. When DNS
// answers NXDOMAIN for a single-label name, or a .local name, it falls back to
// NetBIOS (single labels) and mDNS (<label>.local). The NRPT catch-all rule that
// Intercept mode installs stops that fallback for every name it covers, and NRPT
// cannot exclude a name, so on a network whose only local names live in
// NetBIOS or mDNS those names stop resolving.
//
// ctrld therefore does the fallback itself, in the place Windows would have:
// only for a LAN hostname query the OS resolver answered NXDOMAIN, only in
// Intercept mode on Windows, and only over the protocols Windows has enabled.
// A miss leaves the NXDOMAIN untouched, so every flow that works today is
// unchanged.
const (
	// lanFallbackTimeout bounds one fallback lookup. Windows' own NetBIOS
	// broadcast lookup gives up after about 2.25s (3 x 750ms); one second
	// leaves room inside the DNS Client's own retry schedule while a LAN
	// responder typically answers within milliseconds.
	lanFallbackTimeout = 1500 * time.Millisecond
	// lanFallbackNBNSRetry is the gap between NetBIOS broadcasts, as Windows'
	// BcastNameQueryTimeout default.
	lanFallbackNBNSRetry = 750 * time.Millisecond
	// lanFallbackMissTTL keeps a name nobody answered from being broadcast
	// again for every A/AAAA pair and DNS Client retry.
	lanFallbackMissTTL = 10 * time.Second
	// lanFallbackAnswerTTL is the TTL of a synthesized answer. Kept short:
	// NetBIOS/mDNS answers are unauthenticated and LAN addresses change.
	lanFallbackAnswerTTL = 60
)

// lanFallbackAdapter is one up IPv4 adapter the fallback may query on.
type lanFallbackAdapter struct {
	ifIndex   int
	prefix    netip.Prefix // adapter address with its on-link prefix
	netbios   bool         // NetBIOS over TCP/IP is in effect on this adapter
	multicast bool         // the adapter sends multicast (mDNS)
	// suffixes are the DNS suffixes the DNS Client appends on this adapter,
	// lower case without the trailing dot.
	suffixes []string
}

// broadcast returns the subnet broadcast address of the adapter.
func (a lanFallbackAdapter) broadcast() netip.Addr {
	b := a.prefix.Masked().Addr().As4()
	host := uint32(1)<<(32-a.prefix.Bits()) - 1
	v := binary.BigEndian.Uint32(b[:]) | host
	binary.BigEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}

// onLink reports whether addr is a plausible responder for this adapter. An
// answer from outside the adapter's subnet is not a LAN host and is dropped.
func (a lanFallbackAdapter) onLink(addr netip.Addr) bool {
	return a.prefix.Masked().Contains(addr.Unmap())
}

// lanFallbackPlatform is what the fallback needs from the OS. The Windows
// implementation reads the adapters and the DNS Client settings; tests
// substitute fakes.
type lanFallbackPlatform struct {
	adapters    func() []lanFallbackAdapter
	mdnsEnabled func() bool
	nbns        func(ctx context.Context, a lanFallbackAdapter, name string) (netip.Addr, error)
	mdns        func(ctx context.Context, a lanFallbackAdapter, name string) (netip.Addr, error)
}

type lanNameFallback struct {
	platform lanFallbackPlatform
	timeout  time.Duration
	now      func() time.Time

	sf     singleflight.Group
	mu     sync.Mutex
	misses map[string]time.Time
}

func newLanNameFallback(platform lanFallbackPlatform) *lanNameFallback {
	return &lanNameFallback{
		platform: platform,
		timeout:  lanFallbackTimeout,
		now:      time.Now,
		misses:   make(map[string]time.Time),
	}
}

// lanFallbackTarget is what to ask for one query name.
type lanFallbackTarget struct {
	netbios string // NetBIOS name, empty when NetBIOS does not apply
	mdns    string // mDNS name (<label>.local), empty when mDNS does not apply
}

// lanFallbackTargetFor maps the name ctrld received to the names Windows would
// have asked for. The DNS Client appends a connection suffix before asking DNS
// (QA-NBONLY reaches ctrld as qa-nbonly.lan), so a name is stripped only of a
// suffix an adapter really uses. Anything else with more than one label is a
// real DNS name and gets no fallback.
func lanFallbackTargetFor(qname string, adapters []lanFallbackAdapter) (lanFallbackTarget, bool) {
	name := strings.ToLower(strings.TrimSuffix(qname, "."))
	if name == "" {
		return lanFallbackTarget{}, false
	}
	label := ""
	switch {
	case !strings.Contains(name, "."):
		label = name
	case strings.Count(name, ".") == 1 && strings.HasSuffix(name, ".local"):
		// <label>.local is an mDNS name. Windows does not try NetBIOS for it.
		l := strings.TrimSuffix(name, ".local")
		if !validLanLabel(l) {
			return lanFallbackTarget{}, false
		}
		return lanFallbackTarget{mdns: name}, true
	default:
		for _, a := range adapters {
			for _, s := range a.suffixes {
				if s == "" || !strings.HasSuffix(name, "."+s) {
					continue
				}
				if l := strings.TrimSuffix(name, "."+s); !strings.Contains(l, ".") {
					label = l
				}
			}
		}
	}
	if !validLanLabel(label) {
		return lanFallbackTarget{}, false
	}
	t := lanFallbackTarget{mdns: label + ".local"}
	// A NetBIOS name is at most 15 characters.
	if len(label) <= 15 {
		t.netbios = strings.ToUpper(label)
	}
	return t, true
}

func validLanLabel(l string) bool {
	if l == "" || len(l) > 63 || l[0] == '-' || l[0] == '_' {
		return false
	}
	for _, c := range l {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// resolve returns the IPv4 address of qname from NetBIOS or mDNS, or false
// when neither applies or nobody answered in time.
func (f *lanNameFallback) resolve(ctx context.Context, qname string) (netip.Addr, string, bool) {
	adapters := f.platform.adapters()
	target, ok := lanFallbackTargetFor(qname, adapters)
	if !ok {
		return netip.Addr{}, "", false
	}
	key := target.netbios + "|" + target.mdns
	if f.recentMiss(key) {
		return netip.Addr{}, "", false
	}
	type result struct {
		addr  netip.Addr
		proto string
	}
	// Concurrent A/AAAA lookups and DNS Client retries for one name share a
	// single set of broadcasts.
	v, _, _ := f.sf.Do(key, func() (any, error) {
		lctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), f.timeout)
		defer cancel()
		results := make(chan result, 2*len(adapters))
		var wg sync.WaitGroup
		mdnsOn := target.mdns != "" && f.platform.mdnsEnabled()
		for _, a := range adapters {
			if target.netbios != "" && a.netbios {
				wg.Add(1)
				go func(a lanFallbackAdapter) {
					defer wg.Done()
					if addr, err := f.platform.nbns(lctx, a, target.netbios); err == nil && a.onLink(addr) {
						results <- result{addr, "NetBIOS"}
					}
				}(a)
			}
			if mdnsOn && a.multicast {
				wg.Add(1)
				go func(a lanFallbackAdapter) {
					defer wg.Done()
					if addr, err := f.platform.mdns(lctx, a, target.mdns); err == nil && a.onLink(addr) {
						results <- result{addr, "mDNS"}
					}
				}(a)
			}
		}
		go func() { wg.Wait(); close(results) }()
		select {
		case r, ok := <-results:
			if ok {
				return r, nil
			}
		case <-lctx.Done():
		}
		return result{}, nil
	})
	r := v.(result)
	if !r.addr.IsValid() {
		f.noteMiss(key)
		return netip.Addr{}, "", false
	}
	return r.addr, r.proto, true
}

func (f *lanNameFallback) recentMiss(key string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.now()
	for k, exp := range f.misses {
		if !now.Before(exp) {
			delete(f.misses, k)
		}
	}
	_, ok := f.misses[key]
	return ok
}

func (f *lanNameFallback) noteMiss(key string) {
	f.mu.Lock()
	f.misses[key] = f.now().Add(lanFallbackMissTTL)
	f.mu.Unlock()
}

// answer turns a fallback address into a reply to msg: an A record for an A
// query, and NODATA for AAAA, because the name exists but NetBIOS and the
// mDNS A lookup only yield IPv4. Answering AAAA with NXDOMAIN would tell the
// DNS Client the name does not exist.
func lanFallbackAnswer(msg *dns.Msg, addr netip.Addr) *dns.Msg {
	answer := new(dns.Msg)
	answer.SetReply(msg)
	answer.Compress = true
	q := msg.Question[0]
	if q.Qtype == dns.TypeA {
		answer.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: lanFallbackAnswerTTL},
			A:   addr.AsSlice(),
		}}
	}
	return answer
}

// nbnsQueryPacket builds a NetBIOS name query (RFC 1002 4.2.12) for the
// workstation/file-server name record of name.
func nbnsQueryPacket(id uint16, name string) []byte {
	raw := []byte(strings.ToUpper(name))
	if len(raw) > 15 {
		raw = raw[:15]
	}
	padded := make([]byte, 16)
	copy(padded, raw)
	for i := len(raw); i < 15; i++ {
		padded[i] = ' '
	}
	padded[15] = 0x00
	pkt := make([]byte, 12, 50)
	binary.BigEndian.PutUint16(pkt[0:], id)
	binary.BigEndian.PutUint16(pkt[2:], 0x0110) // query, recursion desired, broadcast
	binary.BigEndian.PutUint16(pkt[4:], 1)      // QDCOUNT
	pkt = append(pkt, 32)
	for _, b := range padded {
		pkt = append(pkt, 'A'+b>>4, 'A'+b&0x0f)
	}
	pkt = append(pkt, 0)
	pkt = binary.BigEndian.AppendUint16(pkt, 0x0020) // NB
	pkt = binary.BigEndian.AppendUint16(pkt, 0x0001) // IN
	return pkt
}

var errNoLanAnswer = errors.New("no usable answer")

// parseNBNSResponse returns the first IPv4 address of a positive name query
// response matching id and name.
func parseNBNSResponse(pkt []byte, id uint16, name string) (netip.Addr, error) {
	if len(pkt) < 12 || binary.BigEndian.Uint16(pkt[0:]) != id {
		return netip.Addr{}, errNoLanAnswer
	}
	flags := binary.BigEndian.Uint16(pkt[2:])
	if flags&0x8000 == 0 || flags&0x000f != 0 || binary.BigEndian.Uint16(pkt[6:]) == 0 {
		return netip.Addr{}, errNoLanAnswer
	}
	want := nbnsQueryPacket(id, name)[12 : 12+34]
	off := 12
	if len(pkt) < off+34+10 || string(pkt[off:off+34]) != string(want) {
		return netip.Addr{}, errNoLanAnswer
	}
	off += 34
	if binary.BigEndian.Uint16(pkt[off:]) != 0x0020 {
		return netip.Addr{}, errNoLanAnswer
	}
	rdlen := int(binary.BigEndian.Uint16(pkt[off+8:]))
	off += 10
	if rdlen < 6 || len(pkt) < off+rdlen {
		return netip.Addr{}, errNoLanAnswer
	}
	// Each entry: 2 bytes of NB flags, then the IPv4 address.
	addr := netip.AddrFrom4([4]byte(pkt[off+2 : off+6]))
	if !addr.IsValid() || addr.IsUnspecified() {
		return netip.Addr{}, errNoLanAnswer
	}
	return addr, nil
}

// nbnsExchange broadcasts a NetBIOS name query from pc to target and waits for
// a matching answer, resending at lanFallbackNBNSRetry like Windows does.
func nbnsExchange(ctx context.Context, pc net.PacketConn, target netip.AddrPort, name string, accept func(netip.Addr) bool) (netip.Addr, error) {
	id := uint16(time.Now().UnixNano())
	pkt := nbnsQueryPacket(id, name)
	dst := net.UDPAddrFromAddrPort(target)
	return lanExchange(ctx, pc, func() error {
		_, err := pc.WriteTo(pkt, dst)
		return err
	}, lanFallbackNBNSRetry, func(b []byte, src netip.Addr) (netip.Addr, error) {
		if !accept(src) {
			return netip.Addr{}, errNoLanAnswer
		}
		return parseNBNSResponse(b, id, name)
	})
}

// mdnsExchange sends a one-shot mDNS query (RFC 6762 5.1) for the A record of
// name. The query comes from an ephemeral port, so responders answer it by
// unicast to that port.
func mdnsExchange(ctx context.Context, pc net.PacketConn, target netip.AddrPort, name string, accept func(netip.Addr) bool) (netip.Addr, error) {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), dns.TypeA)
	q.Id = uint16(time.Now().UnixNano())
	q.RecursionDesired = false
	pkt, err := q.Pack()
	if err != nil {
		return netip.Addr{}, err
	}
	dst := net.UDPAddrFromAddrPort(target)
	return lanExchange(ctx, pc, func() error {
		_, err := pc.WriteTo(pkt, dst)
		return err
	}, 0, func(b []byte, src netip.Addr) (netip.Addr, error) {
		if !accept(src) {
			return netip.Addr{}, errNoLanAnswer
		}
		m := new(dns.Msg)
		if err := m.Unpack(b); err != nil || !m.Response || m.Rcode != dns.RcodeSuccess {
			return netip.Addr{}, errNoLanAnswer
		}
		for _, rr := range append(m.Answer, m.Extra...) {
			a, ok := rr.(*dns.A)
			if !ok || !strings.EqualFold(a.Hdr.Name, dns.Fqdn(name)) {
				continue
			}
			if addr, ok := netip.AddrFromSlice(a.A.To4()); ok && !addr.IsUnspecified() {
				return addr, nil
			}
		}
		return netip.Addr{}, errNoLanAnswer
	})
}

// lanExchange sends, optionally resends every retry, and reads replies until
// parse accepts one or ctx ends.
func lanExchange(ctx context.Context, pc net.PacketConn, send func() error, retry time.Duration, parse func([]byte, netip.Addr) (netip.Addr, error)) (netip.Addr, error) {
	if err := send(); err != nil {
		return netip.Addr{}, err
	}
	deadline, _ := ctx.Deadline()
	nextSend := time.Time{}
	if retry > 0 {
		nextSend = time.Now().Add(retry)
	}
	buf := make([]byte, 1500)
	for {
		if ctx.Err() != nil {
			return netip.Addr{}, ctx.Err()
		}
		readUntil := deadline
		if !nextSend.IsZero() && (readUntil.IsZero() || nextSend.Before(readUntil)) {
			readUntil = nextSend
		}
		_ = pc.SetReadDeadline(readUntil)
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				if !nextSend.IsZero() && !time.Now().Before(nextSend) {
					if err := send(); err != nil {
						return netip.Addr{}, err
					}
					nextSend = time.Now().Add(retry)
				}
				continue
			}
			return netip.Addr{}, err
		}
		ua, ok := from.(*net.UDPAddr)
		if !ok {
			continue
		}
		src, _ := netip.AddrFromSlice(ua.IP)
		if addr, err := parse(buf[:n], src.Unmap()); err == nil {
			return addr, nil
		}
	}
}

// lanNameFallbackAnswer answers a LAN hostname query the OS resolver answered
// NXDOMAIN, when NetBIOS or mDNS knows the name. It returns nil when the
// fallback does not apply or finds nothing, and the caller keeps the NXDOMAIN.
func (p *prog) lanNameFallbackAnswer(ctx context.Context, msg *dns.Msg) *dns.Msg {
	if !dnsIntercept || msg == nil || len(msg.Question) == 0 {
		return nil
	}
	p.lanFallbackOnce.Do(func() {
		if p.lanFallback == nil {
			p.lanFallback = newPlatformLanNameFallback()
		}
	})
	if p.lanFallback == nil {
		return nil
	}
	addr, proto, ok := p.lanFallback.resolve(ctx, msg.Question[0].Name)
	if !ok {
		return nil
	}
	mainLog.Load().Debug().Msgf("lan name fallback: %s answered by %s: %s", msg.Question[0].Name, proto, addr)
	return lanFallbackAnswer(msg, addr)
}
