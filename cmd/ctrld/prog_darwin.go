package main

import (
	"github.com/kardianos/service"
)

func setDependencies(svc *service.Config) {}

func setWorkingDirectory(svc *service.Config, dir string) {
	svc.WorkingDirectory = dir
}
