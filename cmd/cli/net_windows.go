package cli

import (
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/microsoft/wmi/pkg/base/host"
	"github.com/microsoft/wmi/pkg/base/instance"
	"github.com/microsoft/wmi/pkg/base/query"
	"github.com/microsoft/wmi/pkg/constant"
	"github.com/microsoft/wmi/pkg/hardware/network/netadapter"
)

// adapterInfo holds what one WMI query knows about a network adapter.
type adapterInfo struct {
	Name             string
	Description      string
	Virtual          bool
	ConnectorPresent bool
	Hardware         bool
}

// Every network change reads the adapter set, so one query serves a window.
const adapterCacheTTL = time.Minute

var (
	adapterCacheMu sync.Mutex
	adapterCache   []adapterInfo
	// The set before the last read still names the adapter that went away,
	// so a removed adapter keeps its class in the journal.
	adapterCachePrevious []adapterInfo
	adapterCacheReadAt   time.Time

	// Tests replace these seams to avoid a WMI query.
	readAdaptersFn    = readAdapters
	adapterCacheNowFn = time.Now
)

func patchNetIfaceName(iface *net.Interface) (bool, error) {
	return true, nil
}

// validInterface reports whether the *net.Interface is a valid one.
// On Windows, only physical interfaces are considered valid.
func validInterface(iface *net.Interface, validIfacesMap map[string]struct{}) bool {
	_, ok := validIfacesMap[iface.Name]
	return ok
}

// adapters returns the adapter set of the host, from the cache while it is
// younger than the window. The query runs under the mutex, so two callers
// start one query.
func adapters() []adapterInfo {
	adapterCacheMu.Lock()
	defer adapterCacheMu.Unlock()
	now := adapterCacheNowFn()
	if !adapterCacheReadAt.IsZero() && now.Sub(adapterCacheReadAt) < adapterCacheTTL {
		return adapterCache
	}
	read := readAdaptersFn()
	// A failing query waits for the window too, so it starts no query storm.
	adapterCacheReadAt = now
	if read == nil {
		// Keep the last good read, so a failed query loses no adapter.
		return adapterCache
	}
	adapterCachePrevious, adapterCache = adapterCache, read
	return read
}

// refreshInterfaceMeta drops the read window. The cache still describes the
// adapter that appeared or went away, and the next lookup reads the set.
func refreshInterfaceMeta() {
	adapterCacheMu.Lock()
	defer adapterCacheMu.Unlock()
	adapterCacheReadAt = time.Time{}
}

// tunnelAdapterWords name the VPN drivers of Windows. The description is the
// only signal, because WMI describes a tunnel adapter as an Ethernet adapter.
var tunnelAdapterWords = []string{"tap", "wintun", "wireguard", "vpn"}

// adapterClass names the kind of an adapter. WMI marks a software adapter
// virtual and gives it no connector.
func adapterClass(adapter adapterInfo) string {
	switch {
	case tunnelAdapter(adapter.Description):
		return "tunnel"
	case adapter.Virtual && !adapter.ConnectorPresent:
		return "virtual"
	}
	return "hardware"
}

// tunnelAdapter reports a description that names a VPN driver.
func tunnelAdapter(description string) bool {
	lower := strings.ToLower(description)
	for _, word := range tunnelAdapterWords {
		if strings.Contains(lower, word) {
			return true
		}
	}
	return false
}

// platformInterfaceMeta returns the Windows class and adapter description of
// an interface. Windows has no service name.
func platformInterfaceMeta(name string) (class, hardwarePort, service string) {
	adapter, known := adapterByName(name)
	if !known {
		return "", "", ""
	}
	return adapterClass(adapter), adapter.Description, ""
}

// adapterByName finds an adapter in the current set, or in the set before the
// last read. An adapter that went away keeps its names that way.
func adapterByName(name string) (adapterInfo, bool) {
	if adapter, known := findAdapter(adapters(), name); known {
		return adapter, true
	}
	adapterCacheMu.Lock()
	defer adapterCacheMu.Unlock()
	return findAdapter(adapterCachePrevious, name)
}

func findAdapter(set []adapterInfo, name string) (adapterInfo, bool) {
	for _, adapter := range set {
		if adapter.Name == name {
			return adapter, true
		}
	}
	return adapterInfo{}, false
}

// platformVirtualInterfaces returns the adapters that carry no traffic of the
// host network.
func platformVirtualInterfaces() map[string]struct{} {
	virtual := make(map[string]struct{})
	for _, adapter := range adapters() {
		if adapterClass(adapter) != "virtual" {
			continue
		}
		virtual[adapter.Name] = struct{}{}
	}
	return virtual
}

// readAdapters runs one WMI query for every network adapter. It returns nil
// when the query fails.
func readAdapters() []adapterInfo {
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)
	whost := host.NewWmiLocalHost()
	q := query.NewWmiQuery("MSFT_NetAdapter")
	instances, err := instance.GetWmiInstancesFromHost(whost, string(constant.StadardCimV2), q)
	if instances != nil {
		defer instances.Close()
	}
	if err != nil {
		mainLog.Load().Warn().Err(err).Msg("failed to get wmi network adapter")
		return nil
	}
	var read []adapterInfo
	for _, i := range instances {
		adapter, err := netadapter.NewNetworkAdapter(i)
		if err != nil {
			mainLog.Load().Warn().Err(err).Msg("failed to get network adapter")
			continue
		}
		info, ok := readAdapterInfo(adapter)
		if !ok {
			continue
		}
		read = append(read, info)
	}
	return read
}

// readAdapterInfo reads the properties of one adapter. It reports false when a
// property that decides validity is unreadable.
func readAdapterInfo(adapter *netadapter.NetworkAdapter) (adapterInfo, bool) {
	name, err := adapter.GetPropertyName()
	if err != nil {
		mainLog.Load().Warn().Err(err).Msg("failed to get interface name")
		return adapterInfo{}, false
	}

	// From: https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/hh968170(v=vs.85)
	//
	// "Indicates if a connector is present on the network adapter. This value is set to TRUE
	// if this is a physical adapter or FALSE if this is not a physical adapter."
	connectorPresent, err := adapter.GetPropertyConnectorPresent()
	if err != nil {
		mainLog.Load().Debug().Str("method", "readAdapterInfo").Str("interface", name).Msg("failed to get network adapter connector present property")
		return adapterInfo{}, false
	}

	// Check if it's a hardware interface. Checking only for connector present is not enough
	// because some interfaces are not physical but have a connector.
	hardware, err := adapter.GetPropertyHardwareInterface()
	if err != nil {
		mainLog.Load().Debug().Str("method", "readAdapterInfo").Str("interface", name).Msg("failed to get network adapter hardware interface property")
		return adapterInfo{}, false
	}

	info := adapterInfo{Name: name, ConnectorPresent: connectorPresent, Hardware: hardware}
	// The class and the description describe the adapter only, so an
	// unreadable one costs no validity.
	info.Description, _ = adapter.GetPropertyInterfaceDescription()
	info.Virtual, _ = adapter.GetPropertyVirtual()
	return info, true
}
