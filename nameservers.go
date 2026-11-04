package ctrld

import (
	"context"

	"github.com/Control-D-Inc/ctrld/internal/resolvconffile"
)

type dnsFn func(ctx context.Context) []string

// nameservers returns DNS nameservers from system settings.
func nameservers(ctx context.Context) []string {
	return nameserversFrom(ctx, dnsFns())
}

// quickNameservers is nameservers without waiting for the system to publish
// them: a source that finds none returns at once instead of retrying.
func quickNameservers(ctx context.Context) []string {
	return nameserversFrom(ctx, quickDNSFns())
}

func nameserversFrom(ctx context.Context, fns []dnsFn) []string {
	var dns []string
	seen := make(map[string]bool)
	ch := make(chan []string)

	for _, fn := range fns {
		go func(fn dnsFn) {
			ch <- fn(ctx)
		}(fn)
	}
	for range fns {
		for _, ns := range <-ch {
			if seen[ns] {
				continue
			}
			seen[ns] = true
			dns = append(dns, ns)
		}
	}

	return dns
}

// CurrentNameserversFromResolvconf returns the current nameservers set from /etc/resolv.conf file.
func CurrentNameserversFromResolvconf() []string {
	return resolvconffile.NameServers()
}
