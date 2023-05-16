package main

import (
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func (p *prog) watchLinkState() {
	ch := make(chan netlink.LinkUpdate)
	done := make(chan struct{})
	defer close(done)
	if err := netlink.LinkSubscribe(ch, done); err != nil {
		mainLog.Warn().Err(err).Msg("could not subscribe link")
		return
	}
	for lu := range ch {
		if lu.Change == 0xFFFFFFFF {
			continue
		}
		if lu.Change&unix.IFF_UP != 0 {
			mainLog.Debug().Msgf("link state changed, re-bootstrapping")
			for _, uc := range p.cfg.Upstream {
				uc.ReBootstrap()
			}
		}
	}
}
