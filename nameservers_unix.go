//go:build unix

package ctrld

func nameservers() []string {
	return osNameservers()
}
