package cli

import "github.com/kardianos/service"

func setDependencies(svc *service.Config) {
	if hasLocalDnsServerRunning() {
		svc.Dependencies = []string{"DNS"}
	}
}

func setWorkingDirectory(svc *service.Config, dir string) {
	// WorkingDirectory is not supported on Windows.
	svc.WorkingDirectory = dir
}
