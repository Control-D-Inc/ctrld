package main

import (
	"github.com/kardianos/service"
)

func (p *prog) preRun() {
	if !service.Interactive() {
		p.setDNS()
	}
}

func setDependencies(svc *service.Config) {}

func setWorkingDirectory(svc *service.Config, dir string) {
	svc.WorkingDirectory = dir
}

func (p *prog) preStop() {
	if !service.Interactive() {
		p.resetDNS()
	}
}
