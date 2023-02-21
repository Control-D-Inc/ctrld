//go:build !linux && !darwin && !freebsd

package main

// TODO(cuonglm): implement.
func allocateIP(ip string) error {
	return nil
}

// TODO(cuonglm): implement.
func deAllocateIP(ip string) error {
	return nil
}
