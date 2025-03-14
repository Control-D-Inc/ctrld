//go:build !linux && !freebsd && !darwin && !windows

package cli

import "github.com/kardianos/service"

func setDependencies(svc *service.Config) {}

func setWorkingDirectory(svc *service.Config, dir string) {
	// WorkingDirectory is not supported on Windows.
	svc.WorkingDirectory = dir
}
