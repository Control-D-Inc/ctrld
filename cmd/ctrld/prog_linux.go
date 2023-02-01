package main

import "github.com/kardianos/service"

func (p *prog) preRun() {
	if !service.Interactive() {
		p.setDNS()
	}
}
