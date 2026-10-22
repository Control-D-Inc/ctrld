//go:build !darwin

package cli

import "context"

func delegatedLogSendCLI() bool                 { return false }
func runDelegatedLogSend(context.Context, bool) {}
func (p *prog) startLogSendServer()             {}
