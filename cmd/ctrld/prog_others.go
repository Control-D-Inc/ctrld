//go:build !linux
// +build !linux

package main

import "github.com/kardianos/service"

func (p *prog) preRun() {}

func setDependencies(svc *service.Config) {}
