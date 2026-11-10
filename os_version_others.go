//go:build !darwin

package ctrld

import "github.com/cuonglm/osinfo"

// sandboxOSVersion is only used on iOS.
func sandboxOSVersion() string {
	return osinfo.UnknownRelease
}
