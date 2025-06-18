package ctrld

// IsDesktopPlatform indicates if ctrld is running on a desktop platform,
// currently defined as macOS or Windows workstation.
func IsDesktopPlatform() bool {
	return true
}

// SelfDiscover reports whether ctrld should only do self discover.
func SelfDiscover() bool { return true }
