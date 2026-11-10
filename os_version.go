package ctrld

import (
	"runtime"

	"github.com/cuonglm/osinfo"
)

// osinfoNew is osinfo.New. Tests replace it, because on macOS it starts
// sw_vers with an absolute path that a fake in PATH cannot catch.
var osinfoNew = osinfo.New

// OSVersion returns the name and the version of the OS, such as "darwin 15.1".
// On mobile it reads the version without a system tool.
func OSVersion() string {
	if isMobile() {
		return runtime.GOOS + " " + sandboxOSVersion()
	}
	return osinfoNew().String()
}

// osDist returns the distribution of the OS, such as "15.1" on macOS. On
// mobile it reads the version without a system tool.
func osDist() string {
	if isMobile() {
		return sandboxOSVersion()
	}
	return osinfoNew().Dist
}
