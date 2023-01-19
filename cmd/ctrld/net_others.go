//go:build !darwin

package main

import "net"

func patchNetIfaceName(iface *net.Interface) error { return nil }
