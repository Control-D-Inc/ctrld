//go:build !linux && !darwin && !freebsd

package cli

// allocateIP allocates an IP address on the specified interface
func allocateIP(ip string) error {
	return nil
}

// deAllocateIP deallocates an IP address from the specified interface
func deAllocateIP(ip string) error {
	return nil
}
