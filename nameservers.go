package ctrld

type dnsFn func() []string

// nameservers returns DNS nameservers from system settings.
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
			dns = append(dns, ns)
		}
	}

	return dns
}
