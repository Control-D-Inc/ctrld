//go:build !darwin

package cli

import "context"

func delegatedLogSendCLI() bool                       { return false }
func runDelegatedLogSend(context.Context, bool) error { return nil }
func (p *prog) startLogSendServer()                   {}
