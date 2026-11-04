package cli

import "github.com/kardianos/service"

// setDependencies sets service dependencies for Windows
func setDependencies(svc *service.Config) {}

// setWorkingDirectory sets the working directory for the service
func setWorkingDirectory(svc *service.Config, dir string) {
	// WorkingDirectory is not supported on Windows.
	svc.WorkingDirectory = dir
}
