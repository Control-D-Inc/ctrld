package cli

import (
	"bufio"
	"bytes"
	"net"
	"strings"
)

func patchNetIfaceName(iface *net.Interface) error {
	return nil
}

// validInterface reports whether the *net.Interface is a valid one.
// On Windows, only physical interfaces are considered valid.
func validInterface(iface *net.Interface, validIfacesMap map[string]struct{}) bool {
	_, ok := validIfacesMap[iface.Name]
	return ok
}

// validInterfacesMap returns a set of all physical interfaces.
func validInterfacesMap() map[string]struct{} {
	out, err := powershell("Get-NetAdapter -Physical | Select-Object -ExpandProperty Name")
	if err != nil {
		return nil
	}
	m := make(map[string]struct{})
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		ifaceName := strings.TrimSpace(scanner.Text())
		m[ifaceName] = struct{}{}
	}
	return m
}
