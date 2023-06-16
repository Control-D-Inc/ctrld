package main

import (
	"github.com/kardianos/service"
)

func (p *prog) preRun() {
	if !service.Interactive() {
		p.setDNS()
	}
	p.onStopped = append(p.onStopped, func() {
		if !service.Interactive() {
			p.resetDNS()
		}
	})
}

func setDependencies(svc *service.Config) {}

func setWorkingDirectory(svc *service.Config, dir string) {
	svc.WorkingDirectory = dir
}
