package dnscache

import (
	"strings"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/miekg/dns"
)

// Cacher is the interface for caching DNS response.
type Cacher interface {
	Get(Key) *Value
	Add(Key, *Value)
}

// Key is the caching key for DNS message.
type Key struct {
	Qtype  uint16
	Qclass uint16
	Name   string
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

func (l *LRUCache) Get(key Key) *Value {
	v, _ := l.cacher.Get(key)
	return v
}

func (l *LRUCache) Add(key Key, value *Value) {
	l.cacher.Add(key, value)
}

// NewLRUCache creates a new LRUCache instance with given size.
func NewLRUCache(size int) (*LRUCache, error) {
	cacher, err := lru.NewARC[Key, *Value](size)
	return &LRUCache{cacher: cacher}, err
}

// NewKey creates a new cache key for given DNS message.
func NewKey(msg *dns.Msg) Key {
	q := msg.Question[0]
	return Key{Qtype: q.Qtype, Qclass: q.Qclass, Name: normalizeQname(q.Name)}
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
