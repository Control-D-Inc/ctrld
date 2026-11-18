//go:build !darwin

package cli

import "github.com/Control-D-Inc/ctrld"

// addSelfLoopHostContext adds nothing off macOS: the pf group exemption that
// a self loop points at exists only there.
func addSelfLoopHostContext(*ctrld.LogEvent) {}
