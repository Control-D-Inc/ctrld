package cli

import (
	"os"

	"github.com/kardianos/service"
)

// setDependencies sets service dependencies for FreeBSD
func setDependencies(svc *service.Config) {
	// TODO(cuonglm): remove once https://github.com/kardianos/service/issues/359 fixed.
	_ = os.MkdirAll("/usr/local/etc/rc.d", 0755)
}

// setWorkingDirectory sets the working directory for the service
func setWorkingDirectory(svc *service.Config, dir string) {}
