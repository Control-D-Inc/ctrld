//go:build !windows

package cli

var supportedSelfDelete = true

// selfDeleteExe performs self-deletion on non-Windows platforms
func selfDeleteExe() error { return nil }
