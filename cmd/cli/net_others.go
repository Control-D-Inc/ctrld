//go:build !darwin && !windows

package cli

import "net"

func patchNetIfaceName(iface *net.Interface) error { return nil }

func validInterface(iface *net.Interface, validIfacesMap map[string]struct{}) bool { return true }

func validInterfacesMap() map[string]struct{} { return nil }
