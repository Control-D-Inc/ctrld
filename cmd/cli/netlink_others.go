//go:build !linux

package cli

import "context"

func (p *prog) watchLinkState(ctx context.Context) {}
