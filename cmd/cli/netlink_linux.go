package cli

import (
	"context"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/Control-D-Inc/ctrld"
)

func (p *prog) watchLinkState(ctx context.Context) {
	ch := make(chan netlink.LinkUpdate)
	done := make(chan struct{})
	defer close(done)
	if err := netlink.LinkSubscribe(ch, done); err != nil {
		mainLog.Load().Warn().Err(err).Msg("could not subscribe link")
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case lu := <-ch:
			if lu.Change == 0xFFFFFFFF {
				continue
			}
			if lu.Change&unix.IFF_UP != 0 {
				mainLog.Load().Debug().Msgf("link state changed, re-bootstrapping")
				for _, uc := range p.cfg.Upstream {
					uc.ReBootstrap(ctrld.LoggerCtx(ctx, mainLog.Load()))
				}
			}
		}
	}
}
