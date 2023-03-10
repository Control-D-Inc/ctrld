//go:build !linux && !freebsd

package main

import "github.com/kardianos/service"

func (p *prog) preRun() {}

func setDependencies(svc *service.Config) {}

func setWorkingDirectory(svc *service.Config, dir string) {
	// WorkingDirectory is not supported on Windows.
	svc.WorkingDirectory = dir
}
