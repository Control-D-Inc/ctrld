package ctrld

import (
	"context"

	"github.com/Control-D-Inc/ctrld/internal/resolvconffile"
)

type dnsFn func(ctx context.Context) []string

// nameservers returns DNS nameservers from system settings.
func nameservers(ctx context.Context) []string {
	var dns []string
	seen := make(map[string]bool)
	ch := make(chan []string)
	fns := dnsFns()

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
