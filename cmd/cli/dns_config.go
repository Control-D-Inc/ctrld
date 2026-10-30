package cli

import (
	"bufio"
	"errors"
	"io"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// dnsConfigFastInterval is the poll period that follows a network event.
	dnsConfigFastInterval = 15 * time.Second

	// dnsConfigSlowInterval is the poll period of a quiet host.
	dnsConfigSlowInterval = 5 * time.Minute

	// dnsConfigFastWindow is how long the fast period lasts. A resolver change
	// that follows a network event arrives late, after the OS settles.
	dnsConfigFastWindow = 10 * time.Minute
)

// scutilTablePrefix starts a resolver table. macOS prints the table for scoped
// queries after the main one, with the same line.
const scutilTablePrefix = "DNS configuration"

// scutilResolverPrefix starts one resolver block inside a table.
const scutilResolverPrefix = "resolver #"

// scutilDNSOutputLimit bounds the text of one read. A resolver table of a host
// is a few kilobytes, so a larger output does not come from a table.
const scutilDNSOutputLimit = 1 << 20

// errSCUtilDNSTooLarge ends a read that passed the bound.
var errSCUtilDNSTooLarge = errors.New("scutil --dns output is too large")

// dnsResolverEntry is one resolver of the DNS configuration of the host.
type dnsResolverEntry struct {
	Order         int
	Nameservers   []string
	IfIndex       int
	Interface     string
	Flags         string
	SearchDomains []string
	Reachable     string
	// Scoped marks a resolver of the table for scoped queries, which serves one
	// interface. A second service keeps its own resolver there while the
	// unscoped table stays the same.
	Scoped bool
	// Action tells what the diff saw: added, changed, or removed. A resolver
	// without nameservers looks the same whether it came or went, so the event
	// needs the word.
	Action string
}

// The actions of a changed resolver.
const (
	resolverActionAdded   = "added"
	resolverActionChanged = "changed"
	resolverActionRemoved = "removed"
)

// parseSCUtilDNS reads the resolver tables of "scutil --dns": the unscoped
// table that answers a query of the host, then the table for scoped queries
// with one resolver per interface. Both tables count, because a second
// service can change its resolver while the unscoped table stays the same.
//
// A read that ends early or passes the bound gives an error and no table. A
// part of a table looks like resolvers that went away, and the caller must
// keep the table of the read before instead.
func parseSCUtilDNS(r io.Reader) ([]dnsResolverEntry, error) {
	var entries []dnsResolverEntry
	scoped := false
	var entry *dnsResolverEntry
	closeEntry := func() {
		if entry == nil {
			return
		}
		entry.Scoped = scoped
		entries = append(entries, *entry)
		entry = nil
	}
	read := 0
	scanner := bufio.NewScanner(io.LimitReader(r, scutilDNSOutputLimit+1))
	for scanner.Scan() {
		read += len(scanner.Bytes()) + 1
		if read > scutilDNSOutputLimit {
			return nil, errSCUtilDNSTooLarge
		}
		line := strings.TrimSpace(scanner.Text())
		switch {
		case strings.HasPrefix(line, scutilTablePrefix):
			closeEntry()
			scoped = strings.Contains(line, "scoped")
		case strings.HasPrefix(line, scutilResolverPrefix):
			closeEntry()
			entry = &dnsResolverEntry{}
		case entry != nil:
			applySCUtilField(entry, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	closeEntry()
	return entries, nil
}

func applySCUtilField(entry *dnsResolverEntry, line string) {
	name, value, ok := strings.Cut(line, ":")
	if !ok {
		return
	}
	name, value = strings.TrimSpace(name), strings.TrimSpace(value)
	switch {
	case strings.HasPrefix(name, "nameserver["):
		entry.Nameservers = append(entry.Nameservers, value)
	case strings.HasPrefix(name, "search domain["):
		entry.SearchDomains = append(entry.SearchDomains, value)
	case name == "if_index":
		entry.IfIndex, entry.Interface = parseSCUtilIfIndex(value)
	case name == "flags":
		entry.Flags = value
	case name == "reach":
		entry.Reachable = scutilBracketText(value)
	case name == "order":
		entry.Order, _ = strconv.Atoi(value)
	}
}

// parseSCUtilIfIndex reads an "if_index" value of the form "14 (en0)".
func parseSCUtilIfIndex(value string) (int, string) {
	number, name, _ := strings.Cut(value, " ")
	index, _ := strconv.Atoi(number)
	return index, scutilBracketText(name)
}

// scutilBracketText returns the text in brackets, where scutil puts the
// readable form of a number.
func scutilBracketText(value string) string {
	start := strings.Index(value, "(")
	end := strings.LastIndex(value, ")")
	if start < 0 || end < start {
		return ""
	}
	return value[start+1 : end]
}

// resolverKey identifies one resolver across two reads. An unscoped resolver
// has an order, and several can share it, so the count of earlier entries
// with that order completes the key. A scoped resolver has no order line and
// serves one interface, so its interface index is its identity. The two
// tables are two key spaces.
type resolverKey struct {
	scoped     bool
	order      int
	ifIndex    int
	occurrence int
}

func resolverKeys(entries []dnsResolverEntry) []resolverKey {
	counts := make(map[resolverKey]int, len(entries))
	keys := make([]resolverKey, len(entries))
	for i, entry := range entries {
		base := resolverKey{scoped: entry.Scoped, order: entry.Order}
		if entry.Scoped {
			base = resolverKey{scoped: true, ifIndex: entry.IfIndex}
		}
		key := base
		key.occurrence = counts[base]
		keys[i] = key
		counts[base]++
	}
	return keys
}

func equalResolverEntry(a, b dnsResolverEntry) bool {
	return a.IfIndex == b.IfIndex &&
		a.Interface == b.Interface &&
		a.Flags == b.Flags &&
		a.Reachable == b.Reachable &&
		slices.Equal(a.Nameservers, b.Nameservers) &&
		slices.Equal(a.SearchDomains, b.SearchDomains)
}

// diffResolverTables returns the resolvers that differ between two reads. A
// resolver that vanished comes back without nameservers, so the journal shows
// that the host dropped it.
func diffResolverTables(before, after []dnsResolverEntry) []dnsResolverEntry {
	beforeKeys, afterKeys := resolverKeys(before), resolverKeys(after)
	previous := make(map[resolverKey]dnsResolverEntry, len(before))
	for i, key := range beforeKeys {
		previous[key] = before[i]
	}
	current := make(map[resolverKey]struct{}, len(after))
	for _, key := range afterKeys {
		current[key] = struct{}{}
	}
	var changed []dnsResolverEntry
	for i, key := range afterKeys {
		known, ok := previous[key]
		if ok && equalResolverEntry(known, after[i]) {
			continue
		}
		entry := after[i]
		entry.Action = resolverActionChanged
		if !ok {
			entry.Action = resolverActionAdded
		}
		changed = append(changed, entry)
	}
	for i, key := range beforeKeys {
		if _, ok := current[key]; ok {
			continue
		}
		vanished := before[i]
		vanished.Nameservers = nil
		vanished.Action = resolverActionRemoved
		changed = append(changed, vanished)
	}
	return changed
}

// dnsConfigPoller reads the DNS configuration of the host on a timer and
// reports the resolvers that changed since the read before.
type dnsConfigPoller struct {
	run          func() ([]dnsResolverEntry, error)
	now          func() time.Time
	mu           sync.Mutex
	last         []dnsResolverEntry
	lastActivity time.Time
	started      bool
	readFailed   bool
	// kick wakes a loop that waits on the slow delay. One pending signal is
	// enough, so a storm of events does not queue polls.
	kick chan struct{}
}

func newDNSConfigPoller(run func() ([]dnsResolverEntry, error)) *dnsConfigPoller {
	return &dnsConfigPoller{run: run, now: time.Now, kick: make(chan struct{}, 1)}
}

// noteActivity keeps the poll fast for a while after the network moved, and
// wakes a loop that waits on the slow delay.
func (p *dnsConfigPoller) noteActivity(now time.Time) {
	p.markActivity(now)
	select {
	case p.kick <- struct{}{}:
	default:
	}
}

// markActivity records the time of the last network event.
func (p *dnsConfigPoller) markActivity(now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.lastActivity = now
}

func (p *dnsConfigPoller) nextDelay(now time.Time) time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.lastActivity.IsZero() || now.Sub(p.lastActivity) >= dnsConfigFastWindow {
		return dnsConfigSlowInterval
	}
	return dnsConfigFastInterval
}

// pollOnce returns the resolvers that changed. The first table is the baseline
// of the process and reports no change. A failed read keeps the table of the
// read before, so a short failure does not report the whole table twice. The
// first failure and the read that ends it log once, so a host whose read
// never works says so.
func (p *dnsConfigPoller) pollOnce(now time.Time) []dnsResolverEntry {
	table, err := p.run()
	p.mu.Lock()
	defer p.mu.Unlock()
	if err != nil {
		if !p.readFailed {
			mainLog.Load().Warn().Err(err).Msg("DNS configuration read failed; the journal keeps the last table")
		}
		p.readFailed = true
		return nil
	}
	if p.readFailed {
		mainLog.Load().Info().Msg("DNS configuration read works again")
		p.readFailed = false
	}
	if !p.started {
		p.started = true
		p.last = table
		return nil
	}
	changed := diffResolverTables(p.last, table)
	p.last = table
	return changed
}

// dnsConfigDelayFn lets a test shorten the wait between two polls.
var dnsConfigDelayFn = (*dnsConfigPoller).nextDelay

// startLoop runs the poll loop and returns a channel that closes when the loop
// returns. A caller joins that channel before it reads the log.
func (p *dnsConfigPoller) startLoop(stop <-chan struct{}, emit func([]dnsResolverEntry)) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.loop(stop, emit)
	}()
	return done
}

// loop polls until stop closes. The read starts a subprocess on macOS, so the
// delay follows the last activity and a quiet host pays little. The start of a
// run counts as activity, because the table of the host settles after the
// daemon comes up, and the read at entry is the baseline of the process.
func (p *dnsConfigPoller) loop(stop <-chan struct{}, emit func([]dnsResolverEntry)) {
	now := p.now()
	p.markActivity(now)
	p.pollOnce(now)
	delay := dnsConfigDelayFn(p, now)
	deadline := now.Add(delay)
	timer := time.NewTimer(delay)
	defer timer.Stop()
	for {
		select {
		case <-stop:
			return
		case <-p.kick:
			// noteActivity set the time just now, so the delay is the fast one.
			// A kick only moves a deadline closer; a storm of kicks must not
			// push the read back again and again.
			now := p.now()
			wanted := now.Add(dnsConfigDelayFn(p, now))
			if !wanted.Before(deadline) {
				continue
			}
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(wanted.Sub(now))
			deadline = wanted
			continue
		case <-timer.C:
		}
		now := p.now()
		if changed := p.pollOnce(now); len(changed) > 0 {
			emit(changed)
		}
		delay := dnsConfigDelayFn(p, now)
		deadline = now.Add(delay)
		timer.Reset(delay)
	}
}
