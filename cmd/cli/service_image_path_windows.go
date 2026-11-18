//go:build windows

package cli

import (
	"os"

	"golang.org/x/sys/windows/registry"
)

// installedServiceDirMatches reports whether this executable is the installed service
// binary, by comparing its directory with the one in the service's registered ImagePath.
//
// socketDir() on Windows is relative to the running executable, so a ctrld-client.exe run from
// somewhere else - a download directory, a build tree - looks for the control socket in
// its own directory and never finds the installed daemon's. A failed probe from there
// says nothing about the service's health, and reporting "not ready" for it would tell
// monitoring to restart a healthy service.
//
// Anything unreadable answers true, keeping the previous behaviour: readiness stays
// verifiable unless there is positive evidence of a different install.
func installedServiceDirMatches() bool {
	self, err := os.Executable()
	if err != nil {
		return true
	}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\`+ctrldServiceName, registry.QUERY_VALUE)
	if err != nil {
		return true
	}
	defer key.Close()
	imagePath, _, err := key.GetStringValue("ImagePath")
	if err != nil {
		return true
	}
	installed := serviceBinaryFromImagePath(imagePath)
	if installed == "" {
		return true
	}
	return sameExecutableDir(installed, self)
}
