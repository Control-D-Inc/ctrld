package ctrld

import (
	"github.com/cuonglm/osinfo"
	"golang.org/x/sys/unix"
)

// sandboxOSVersion reads the OS version from the kernel. An app in the iOS
// sandbox can read it, but cannot start sw_vers.
func sandboxOSVersion() string {
	version, err := unix.Sysctl("kern.osproductversion")
	if err != nil || version == "" {
		return osinfo.UnknownRelease
	}
	return version
}
