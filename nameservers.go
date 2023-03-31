package ctrld

import "net"

type dnsFn func() []string

func nameservers() []string {
	var dns []string
	seen := make(map[string]bool)
	ch := make(chan []string)
	fns := dnsFns()

	for _, fn := range fns {
		go func(fn dnsFn) {
			ch <- fn()
		}(fn)
	}
	for range fns {
		for _, ns := range <-ch {
			if seen[ns] {
				continue
			}
			seen[ns] = true
			dns = append(dns, net.JoinHostPort(ns, "53"))
		}
	}

	return dns
}
