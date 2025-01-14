package cli

import (
	"io"
	"log"
	"net"
	"os"

	"github.com/microsoft/wmi/pkg/base/host"
	"github.com/microsoft/wmi/pkg/base/instance"
	"github.com/microsoft/wmi/pkg/base/query"
	"github.com/microsoft/wmi/pkg/constant"
	"github.com/microsoft/wmi/pkg/hardware/network/netadapter"
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
	m := make(map[string]struct{})
	for _, ifaceName := range validInterfaces() {
		m[ifaceName] = struct{}{}
	}
	return m
}

// validInterfaces returns a list of all physical interfaces.
func validInterfaces() []string {
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)
	whost := host.NewWmiLocalHost()
	q := query.NewWmiQuery("MSFT_NetAdapter")
	instances, err := instance.GetWmiInstancesFromHost(whost, string(constant.StadardCimV2), q)
	if err != nil {
		mainLog.Load().Err(err).Msg("failed to get wmi network adapter")
		return nil
	}
	defer instances.Close()
	var adapters []string
	for _, i := range instances {
		adapter, err := netadapter.NewNetworkAdapter(i)
		if err != nil {
			mainLog.Load().Err(err).Msg("failed to get network adapter")
			continue
		}
		// From: https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/hh968170(v=vs.85)
		//
		// "Indicates if a connector is present on the network adapter. This value is set to TRUE
		// if this is a physical adapter or FALSE if this is not a physical adapter."
		physical, err := adapter.GetPropertyConnectorPresent()
		if err != nil {
			mainLog.Load().Err(err).Msg("failed to get network adapter connector present property")
			continue
		}
		if !physical {
			continue
		}
		ifaceIdx, err := adapter.GetInterfaceIndex()
		if err != nil {
			mainLog.Load().Err(err).Msg("failed to get interface index")
			continue
		}
		iff, err := net.InterfaceByIndex(int(ifaceIdx))
		if err != nil {
			mainLog.Load().Err(err).Msg("failed to get interface")
			continue
		}
		adapters = append(adapters, iff.Name)
	}
	return adapters
}
