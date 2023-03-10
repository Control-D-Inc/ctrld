package main

import (
	"os"

	"github.com/kardianos/service"
)

func (p *prog) preRun() {
	if !service.Interactive() {
		p.setDNS()
	}
}

func setDependencies(svc *service.Config) {
	// TODO(cuonglm): remove once https://github.com/kardianos/service/issues/359 fixed.
	_ = os.MkdirAll("/usr/local/etc/rc.d", 0755)
}

func setWorkingDirectory(svc *service.Config, dir string) {}
