//go:build !darwin

package cli

import "net"

func patchNetIfaceName(iface *net.Interface) error { return nil }
