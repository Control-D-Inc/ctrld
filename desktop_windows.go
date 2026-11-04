package ctrld

import "golang.org/x/sys/windows"

// IsDesktopPlatform indicates if ctrld is running on a desktop platform,
// currently defined as macOS or Windows workstation.
func IsDesktopPlatform() bool {
	return isWindowsWorkStation()
}

// SelfDiscover reports whether ctrld should only do self discover.
func SelfDiscover() bool {
	return isWindowsWorkStation()
}

// isWindowsWorkStation reports whether ctrld was run on a Windows workstation machine.
func isWindowsWorkStation() bool {
	// From https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-osversioninfoexa
	const VER_NT_WORKSTATION = 0x0000001
	osvi := windows.RtlGetVersion()
	return osvi.ProductType == VER_NT_WORKSTATION
}
