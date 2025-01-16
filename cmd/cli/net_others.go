//go:build !darwin && !windows

package cli

import "net"

func patchNetIfaceName(iface *net.Interface) (bool, error) { return true, nil }

func validInterface(iface *net.Interface, validIfacesMap map[string]struct{}) bool { return true }

func validInterfacesMap() map[string]struct{} { return nil }
