//go:build !windows && !darwin

package ctrld

// SelfDiscover reports whether ctrld should only do self discover.
func SelfDiscover() bool { return false }
