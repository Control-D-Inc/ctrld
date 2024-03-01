package cli

import "strings"

// Copied from https://gist.github.com/Ultraporing/fe52981f678be6831f747c206a4861cb

// Mac Address parts to look for, and identify non-physical devices. There may be more, update me!
var macAddrPartsToFilter = []string{
	"00:03:FF",       // Microsoft Hyper-V, Virtual Server, Virtual PC
	"0A:00:27",       // VirtualBox
	"00:00:00:00:00", // Teredo Tunneling Pseudo-Interface
	"00:50:56",       // VMware ESX 3, Server, Workstation, Player
	"00:1C:14",       // VMware ESX 3, Server, Workstation, Player
	"00:0C:29",       // VMware ESX 3, Server, Workstation, Player
	"00:05:69",       // VMware ESX 3, Server, Workstation, Player
	"00:1C:42",       // Microsoft Hyper-V, Virtual Server, Virtual PC
	"00:0F:4B",       // Virtual Iron 4
	"00:16:3E",       // Red Hat Xen, Oracle VM, XenSource, Novell Xen
	"08:00:27",       // Sun xVM VirtualBox
	"7A:79",          // Hamachi
}

// Filters the possible physical interface address by comparing it to known popular VM Software addresses
// and Teredo Tunneling Pseudo-Interface.
//
//lint:ignore U1000 use in net_windows.go
func isPhysicalInterface(addr string) bool {
	for _, macPart := range macAddrPartsToFilter {
		if strings.HasPrefix(strings.ToLower(addr), strings.ToLower(macPart)) {
			return false
		}
	}
	return true
}
