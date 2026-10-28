//go:build !darwin

package cli

// removeCtrldGroup is a no-op: the _ctrld group exists only on macOS.
func removeCtrldGroup() {}
