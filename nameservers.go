package ctrld

type dnsFn func() []string

// nameservers returns DNS nameservers from system settings.
func nameservers() []string {
	return nameserversFrom(dnsFns())
}

// quickNameservers is nameservers without waiting for the system to publish
// them: a source that finds none returns at once instead of retrying.
func quickNameservers() []string {
	return nameserversFrom(quickDNSFns())
}

func nameserversFrom(fns []dnsFn) []string {
	var dns []string
	seen := make(map[string]bool)
	ch := make(chan []string)

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
			dns = append(dns, ns)
		}
	}

	return dns
}
