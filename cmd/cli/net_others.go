//go:build !darwin && !windows && !linux

package cli

import (
	"net"
)

// patchNetIfaceName patches network interface names on non-Linux/Darwin platforms
func patchNetIfaceName(iface *net.Interface) (bool, error) { return true, nil }

// validInterface checks if an interface is valid on non-Linux/Darwin platforms
func validInterface(iface *net.Interface, validIfacesMap map[string]struct{}) bool { return true }
