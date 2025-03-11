package ctrld

import (
	"golang.org/x/sys/windows"
)

// isWindowsWorkStation reports whether ctrld was run on a Windows workstation machine.
func isWindowsWorkStation() bool {
	// From https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-osversioninfoexa
	const VER_NT_WORKSTATION = 0x0000001
	osvi := windows.RtlGetVersion()
	return osvi.ProductType == VER_NT_WORKSTATION
}

// SelfDiscover reports whether ctrld should only do self discover.
func SelfDiscover() bool {
	return isWindowsWorkStation()
}
