//go:build !darwin

package ctrld

// quickDNSFns is dnsFns: no other platform's sources retry.
func quickDNSFns() []dnsFn {
	return dnsFns()
}
