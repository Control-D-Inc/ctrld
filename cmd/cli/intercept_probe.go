package cli

// Interception probe registry.
//
// A probe sends a DNS query for a unique synthetic domain through the OS resolver and
// waits for ctrld's own handler to receive it. That is the only way to tell "the rules are
// present" from "the rules are actually redirecting packets", and both the macOS pf path
// and the Windows NRPT path use it.
//
// Each attempt registers its own domain, so overlapping probes cannot cancel each other,
// and deregistration only removes the entry it owns.

// registerInterceptProbe registers domain and returns the channel it will be signalled on
// plus the function that removes the registration.
//
//lint:ignore U1000 used on darwin (pf probes) and windows (NRPT probes)
func (p *prog) registerInterceptProbe(domain string) (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)

	p.interceptProbeMu.Lock()
	current, _ := p.interceptProbes.Load().(map[string]chan struct{})
	next := make(map[string]chan struct{}, len(current)+1)
	for k, v := range current {
		next[k] = v
	}
	next[domain] = ch
	p.interceptProbes.Store(next)
	p.interceptProbeMu.Unlock()

	return ch, func() {
		p.interceptProbeMu.Lock()
		defer p.interceptProbeMu.Unlock()
		current, _ := p.interceptProbes.Load().(map[string]chan struct{})
		// Only drop the entry while it is still this attempt's channel. A later probe
		// that reused the domain owns the slot now, and clearing it would make that one
		// wait out its timeout for a query it already received.
		if existing, ok := current[domain]; !ok || existing != ch {
			return
		}
		next := make(map[string]chan struct{}, len(current))
		for k, v := range current {
			if k != domain {
				next[k] = v
			}
		}
		p.interceptProbes.Store(next)
	}
}

// signalInterceptProbe reports whether domain is a pending probe, signalling its waiter
// when it is. Called from the DNS handler for every query, so the common case is a nil or
// empty map and no allocation.
func (p *prog) signalInterceptProbe(domain string) bool {
	probes, _ := p.interceptProbes.Load().(map[string]chan struct{})
	if len(probes) == 0 {
		return false
	}
	ch, ok := probes[domain]
	if !ok {
		return false
	}
	select {
	case ch <- struct{}{}:
	default:
		// Buffered channel already holds a signal: the waiter has what it needs.
	}
	return true
}
