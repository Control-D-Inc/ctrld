package dnscache

import (
	"fmt"
	"net"
	"strings"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/miekg/dns"
)

// Cacher is the interface for caching DNS response.
type Cacher interface {
	Get(Key) *Value
	Add(Key, *Value)
	Purge()
}

// Key is the caching key for DNS message.
//
// ECS partitions the cache by EDNS Client Subnet so an answer resolved for one
// subnet is never served to a client in a different subnet. Answer records are
// scoped to the network that generated them (RFC 7871 §7.3), so they must not
// be shared across subnets even when the question is otherwise identical.
type Key struct {
	Qtype    uint16
	Qclass   uint16
	Name     string
	Upstream string
	ECS      string
}

type Value struct {
	Expire time.Time
	Msg    *dns.Msg
}

var _ Cacher = (*LRUCache)(nil)

// LRUCache implements Cacher interface.
type LRUCache struct {
	cacher *lru.ARCCache[Key, *Value]
}

// Get looks up key's value from cache.
func (l *LRUCache) Get(key Key) *Value {
	v, _ := l.cacher.Get(key)
	return v
}

// Add adds a value to cache.
func (l *LRUCache) Add(key Key, value *Value) {
	l.cacher.Add(key, value)
}

// Purge clears the cache.
func (l *LRUCache) Purge() {
	l.cacher.Purge()
}

// NewLRUCache creates a new LRUCache instance with given size.
func NewLRUCache(size int) (*LRUCache, error) {
	cacher, err := lru.NewARC[Key, *Value](size)
	return &LRUCache{cacher: cacher}, err
}

// NewKey creates a new cache key for given DNS message.
func NewKey(msg *dns.Msg, upstream string) Key {
	q := msg.Question[0]
	return Key{Qtype: q.Qtype, Qclass: q.Qclass, Name: normalizeQname(q.Name), Upstream: upstream, ECS: CanonicalECS(msg)}
}

// CanonicalECS returns a canonical string form of the EDNS Client Subnet (ECS,
// EDNS option 8) carried by msg, suitable for partitioning cache and
// singleflight keys. A request with no ECS option returns "", so all ECS-less
// queries share one partition and behave as before.
//
// A request that DOES carry an ECS option is never mapped to "", even at SOURCE
// PREFIX-LENGTH 0: the /0 query is forwarded with an ECS option, may draw
// different upstream data than an ECS-less query, and its answer (with the
// echoed option) must not be served to a client that sent no ECS — RFC 7871
// §7.3.1 requires /0-cached data to remain distinguishable. The family is part
// of the token, so an IPv4 /0 and an IPv6 /0 stay distinct too.
//
// The address is masked to its source prefix length so only the significant
// subnet bits contribute to the key: two clients in the same subnet share a
// partition, while different subnets (or address families) never do. The
// response-only SCOPE PREFIX-LENGTH is deliberately excluded — it is not part of
// what the client asked for.
func CanonicalECS(msg *dns.Msg) string {
	opt := msg.IsEdns0()
	if opt == nil {
		return ""
	}
	for _, o := range opt.Option {
		e, ok := o.(*dns.EDNS0_SUBNET)
		if !ok {
			continue
		}
		bits := int(e.SourceNetmask)
		total := 128
		zero := net.IPv6zero
		if e.Family == 1 {
			total = 32
			zero = net.IPv4zero
		}
		addr := e.Address
		if len(addr) == 0 {
			// A /0 request commonly carries an empty address; normalize it to
			// the family zero so its token is stable regardless of encoding.
			addr = zero
		}
		masked := addr
		if bits <= total {
			if m := addr.Mask(net.CIDRMask(bits, total)); m != nil {
				masked = m
			}
		}
		return fmt.Sprintf("%d/%d/%s", e.Family, e.SourceNetmask, masked.String())
	}
	return ""
}

// NewValue creates a new cache value for given DNS message.
func NewValue(msg *dns.Msg, expire time.Time) *Value {
	return &Value{
		Expire: expire,
		Msg:    msg,
	}
}

func normalizeQname(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	for i := 0; i < len(name); i++ {
		c := name[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		b.WriteByte(c)
	}
	return b.String()
}
