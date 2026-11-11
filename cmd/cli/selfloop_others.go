//go:build !darwin

package cli

import "github.com/rs/zerolog"

// addSelfLoopHostContext adds nothing off macOS: the pf group exemption that
// a self loop points at exists only there.
func addSelfLoopHostContext(*zerolog.Event) {}
