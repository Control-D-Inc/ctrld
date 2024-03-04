//go:build !darwin && !windows

package cli

import "net"

func patchNetIfaceName(iface *net.Interface) error { return nil }

func validInterface(iface *net.Interface) bool { return true }
