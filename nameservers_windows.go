package ctrld

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/microsoft/wmi/pkg/base/host"
	"github.com/microsoft/wmi/pkg/base/instance"
	"github.com/microsoft/wmi/pkg/base/query"
	"github.com/microsoft/wmi/pkg/constant"
	"github.com/microsoft/wmi/pkg/hardware/network/netadapter"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"tailscale.com/net/netmon"
)

const (
	maxDNSAdapterRetries                 = 5
	retryDelayDNSAdapter                 = 1 * time.Second
	defaultDNSAdapterTimeout             = 10 * time.Second
	minDNSServers                        = 1 // Minimum number of DNS servers we want to find
	NetSetupUnknown               uint32 = 0
	NetSetupWorkgroup             uint32 = 1
	NetSetupDomain                uint32 = 2
	NetSetupCloudDomain           uint32 = 3
	DS_FORCE_REDISCOVERY                 = 0x00000001
	DS_DIRECTORY_SERVICE_REQUIRED        = 0x00000010
	DS_BACKGROUND_ONLY                   = 0x00000100
	DS_IP_REQUIRED                       = 0x00000200
	DS_IS_DNS_NAME                       = 0x00020000
	DS_RETURN_DNS_NAME                   = 0x40000000
)

type DomainControllerInfo struct {
	DomainControllerName        *uint16
	DomainControllerAddress     *uint16
	DomainControllerAddressType uint32
	DomainGuid                  windows.GUID
	DomainName                  *uint16
	DnsForestName               *uint16
	Flags                       uint32
	DcSiteName                  *uint16
	ClientSiteName              *uint16
}

func dnsFns() []dnsFn {
	return []dnsFn{dnsFromAdapter}
}

func dnsFromAdapter(ctx context.Context) []string {
	ctx, cancel := context.WithTimeout(context.Background(), defaultDNSAdapterTimeout)
	defer cancel()

	var ns []string
	var err error

	logger := LoggerFromCtx(ctx)

	for i := 0; i < maxDNSAdapterRetries; i++ {
		if ctx.Err() != nil {
			logger.Debug().Msgf("dnsFromAdapter lookup cancelled or timed out, attempt %d", i)
			return nil
		}

		ns, err = getDNSServers(ctx)
		if err == nil && len(ns) >= minDNSServers {
			if i > 0 {
				logger.Debug().Msgf("Successfully got DNS servers after %d attempts, found %d servers", i+1, len(ns))
			}
			return ns
		}

		// if osResolver is not initialized, this is likely a command line run
		// and ctrld is already on the interface, abort retries
		if or == nil {
			return ns
		}

		if err != nil {
			logger.Debug().Msgf("Failed to get DNS servers, attempt %d: %v", i+1, err)
		} else {
			logger.Debug().Msgf("Got insufficient DNS servers, retrying, found %d servers", len(ns))
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(retryDelayDNSAdapter):
		}
	}

	logger.Debug().Msgf("Failed to get sufficient DNS servers after all attempts, max_retries=%d", maxDNSAdapterRetries)

	return ns
}

func getDNSServers(ctx context.Context) ([]string, error) {
	// Check context before making the call
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	// Get DNS servers from adapters (existing method)
	flags := winipcfg.GAAFlagIncludeGateways |
		winipcfg.GAAFlagIncludePrefix

	aas, err := winipcfg.GetAdaptersAddresses(syscall.AF_UNSPEC, flags)
	if err != nil {
		return nil, fmt.Errorf("getting adapters: %w", err)
	}

	logger := LoggerFromCtx(ctx)
	logger.Debug().Msgf("Found network adapters, count=%d", len(aas))

	// Try to get domain controller info if domain-joined
	var dcServers []string
	isDomain := checkDomainJoined(ctx)
	if isDomain {
		domainName, err := getLocalADDomain()
		if err != nil {
			logger.Debug().Msgf("Failed to get local AD domain: %v", err)
		} else {
			// Load netapi32.dll
			netapi32 := windows.NewLazySystemDLL("netapi32.dll")
			dsDcName := netapi32.NewProc("DsGetDcNameW")

			var info *DomainControllerInfo
			flags := uint32(DS_RETURN_DNS_NAME | DS_IP_REQUIRED | DS_IS_DNS_NAME)

			domainUTF16, err := windows.UTF16PtrFromString(domainName)
			if err != nil {
				logger.Debug().Msgf("Failed to convert domain name to UTF16: %v", err)
			} else {
				logger.Debug().Msgf("Attempting to get DC for domain: %s with flags: 0x%x", domainName, flags)

				// Call DsGetDcNameW with domain name
				ret, _, err := dsDcName.Call(
					0,                                    // ComputerName - can be NULL
					uintptr(unsafe.Pointer(domainUTF16)), // DomainName
					0,                                    // DomainGuid - not needed
					0,                                    // SiteName - not needed
					uintptr(flags),                       // Flags
					uintptr(unsafe.Pointer(&info)))       // DomainControllerInfo - output

				if ret != 0 {
					switch ret {
					case 1355: // ERROR_NO_SUCH_DOMAIN
						logger.Debug().Msgf("Domain not found: %s (%d)", domainName, ret)
					case 1311: // ERROR_NO_LOGON_SERVERS
						logger.Debug().Msgf("No logon servers available for domain: %s (%d)", domainName, ret)
					case 1004: // ERROR_DC_NOT_FOUND
						logger.Debug().Msgf("Domain controller not found for domain: %s (%d)", domainName, ret)
					case 1722: // RPC_S_SERVER_UNAVAILABLE
						logger.Debug().Msgf("RPC server unavailable for domain: %s (%d)", domainName, ret)
					default:
						logger.Debug().Msgf("Failed to get domain controller info for domain %s: %d, %v", domainName, ret, err)
					}
				} else if info != nil {
					defer windows.NetApiBufferFree((*byte)(unsafe.Pointer(info)))

					if info.DomainControllerAddress != nil {
						dcAddr := windows.UTF16PtrToString(info.DomainControllerAddress)
						dcAddr = strings.TrimPrefix(dcAddr, "\\\\")
						logger.Debug().Msgf("Found domain controller address: %s", dcAddr)
						if ip := net.ParseIP(dcAddr); ip != nil {
							dcServers = append(dcServers, ip.String())
							logger.Debug().Msgf("Added domain controller DNS servers: %v", dcServers)
						}
					} else {
						logger.Debug().Msg("No domain controller address found")
					}
				}
			}
		}
	}

	// Continue with existing adapter DNS collection
	ns := make([]string, 0, len(aas)*2)
	seen := make(map[string]bool)
	addressMap := make(map[string]struct{})

	// Collect all local IPs
	for _, aa := range aas {
		if aa.OperStatus != winipcfg.IfOperStatusUp {
			logger.Debug().Msgf("Skipping adapter %s - not up, status: %d", aa.FriendlyName(), aa.OperStatus)
			continue
		}

		// Skip if software loopback or other non-physical types
		// This is to avoid the "Loopback Pseudo-Interface 1" issue we see on windows
		if aa.IfType == winipcfg.IfTypeSoftwareLoopback {
			logger.Debug().Msgf("Skipping %s (software loopback)", aa.FriendlyName())
			continue
		}

		logger.Debug().Msgf("Processing adapter %s", aa.FriendlyName())

		for a := aa.FirstUnicastAddress; a != nil; a = a.Next {
			ip := a.Address.IP().String()
			addressMap[ip] = struct{}{}
			logger.Debug().Msgf("Added local IP %s from adapter %s", ip, aa.FriendlyName())
		}
	}

	validInterfacesMap := ValidInterfaces(ctx)

	// Collect DNS servers
	for _, aa := range aas {
		if aa.OperStatus != winipcfg.IfOperStatusUp {
			continue
		}

		// Skip if software loopback or other non-physical types
		// This is to avoid the "Loopback Pseudo-Interface 1" issue we see on windows
		if aa.IfType == winipcfg.IfTypeSoftwareLoopback {
			logger.Debug().Msgf("Skipping %s (software loopback)", aa.FriendlyName())
			continue
		}

		// if not in the validInterfacesMap, skip
		if _, ok := validInterfacesMap[aa.FriendlyName()]; !ok {
			logger.Debug().Msgf("Skipping %s (not in validInterfacesMap)", aa.FriendlyName())
			continue
		}

		for dns := aa.FirstDNSServerAddress; dns != nil; dns = dns.Next {
			ip := dns.Address.IP()
			if ip == nil {
				logger.Debug().Msgf("Skipping nil IP from adapter %s", aa.FriendlyName())
				continue
			}

			ipStr := ip.String()
			l := logger.Debug().
				Str("ip", ipStr).
				Str("adapter", aa.FriendlyName())

			if ip.IsLoopback() {
				l.Msg("Skipping loopback IP")
				continue
			}
			if seen[ipStr] {
				l.Msg("Skipping duplicate IP")
				continue
			}
			if _, ok := addressMap[ipStr]; ok {
				l.Msg("Skipping local interface IP")
				continue
			}

			seen[ipStr] = true
			ns = append(ns, ipStr)
			l.Msg("Added DNS server")
		}
	}

	// Add DC servers if they're not already in the list
	for _, dcServer := range dcServers {
		if !seen[dcServer] {
			seen[dcServer] = true
			ns = append(ns, dcServer)
			logger.Debug().Msgf("Added additional domain controller DNS server: %s", dcServer)
		}
	}

	// if we have static DNS servers saved for the current default route, we should add them to the list
	drIfaceName, err := netmon.DefaultRouteInterface()
	if err != nil {
		logger.Debug().Msgf("Failed to get default route interface: %v", err)
	} else {
		drIface, err := net.InterfaceByName(drIfaceName)
		if err != nil {
			logger.Debug().Msgf("Failed to get interface by name %s: %v", drIfaceName, err)
		} else {
			staticNs, file := SavedStaticNameserversAndPath(drIface)
			logger.Debug().Msgf("static dns servers from %s: %v", file, staticNs)
			if len(staticNs) > 0 {
				logger.Debug().Msgf("Adding static DNS servers from %s: %v", drIfaceName, staticNs)
				ns = append(ns, staticNs...)
			}
		}
	}

	if len(ns) == 0 {
		return nil, fmt.Errorf("no valid DNS servers found")
	}

	logger.Debug().Msgf("DNS server discovery completed, count=%d, servers=%v (including %d DC servers)", len(ns), ns, len(dcServers))
	return ns, nil
}

// CurrentNameserversFromResolvconf returns a nil slice of strings.
func currentNameserversFromResolvconf() []string {
	return nil
}

// checkDomainJoined checks if the machine is joined to an Active Directory domain
// Returns whether it's domain joined and the domain name if available
func checkDomainJoined(ctx context.Context) bool {
	logger := LoggerFromCtx(ctx)

	var domain *uint16
	var status uint32

	err := windows.NetGetJoinInformation(nil, &domain, &status)
	if err != nil {
		logger.Debug().Msgf("Failed to get domain join status: %v", err)
		return false
	}
	defer windows.NetApiBufferFree((*byte)(unsafe.Pointer(domain)))

	domainName := windows.UTF16PtrToString(domain)
	logger.Debug().Msgf(
		"Domain join status: domain=%s status=%d (Unknown=0, Workgroup=1, Domain=2, CloudDomain=3)",
		domainName,
		status,
	)

	// Consider domain or cloud domain as domain-joined
	isDomain := status == NetSetupDomain || status == NetSetupCloudDomain
	logger.Debug().Msgf(
		"Is domain joined? status=%d, traditional=%v, cloud=%v, result=%v",
		status,
		status == NetSetupDomain,
		status == NetSetupCloudDomain,
		isDomain,
	)

	return isDomain
}

// getLocalADDomain uses Microsoft's WMI wrappers (github.com/microsoft/wmi/pkg/*)
// to query the Domain field from Win32_ComputerSystem instead of a direct go-ole call.
func getLocalADDomain() (string, error) {
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)
	// 1) Check environment variable
	envDomain := os.Getenv("USERDNSDOMAIN")
	if envDomain != "" {
		return strings.TrimSpace(envDomain), nil
	}

	// 2) Query WMI via the microsoft/wmi library
	whost := host.NewWmiLocalHost()
	q := query.NewWmiQuery("Win32_ComputerSystem")
	instances, err := instance.GetWmiInstancesFromHost(whost, string(constant.CimV2), q)
	if instances != nil {
		defer instances.Close()
	}
	if err != nil {
		return "", fmt.Errorf("WMI query failed: %v", err)
	}

	// If no results, return an error
	if len(instances) == 0 {
		return "", fmt.Errorf("no rows returned from Win32_ComputerSystem")
	}

	// We only care about the first row
	domainVal, err := instances[0].GetProperty("Domain")
	if err != nil {
		return "", fmt.Errorf("machine does not appear to have a domain set: %v", err)
	}

	domainName := strings.TrimSpace(fmt.Sprintf("%v", domainVal))
	if domainName == "" {
		return "", fmt.Errorf("machine does not appear to have a domain set")
	}
	return domainName, nil
}

// ValidInterfaces returns a map of valid network interface names as keys with empty struct values.
// It filters interfaces to include only physical, hardware-based adapters using WMI queries.
func ValidInterfaces(ctx context.Context) map[string]struct{} {
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	//load the logger
	logger := LoggerFromCtx(ctx)

	whost := host.NewWmiLocalHost()
	q := query.NewWmiQuery("MSFT_NetAdapter")
	instances, err := instance.GetWmiInstancesFromHost(whost, string(constant.StadardCimV2), q)
	if instances != nil {
		defer instances.Close()
	}
	if err != nil {
		logger.Warn().Msgf("failed to get wmi network adapter: %v", err)
		return nil
	}
	var adapters []string
	for _, i := range instances {
		adapter, err := netadapter.NewNetworkAdapter(i)
		if err != nil {
			logger.Warn().Msgf("failed to get network adapter: %v", err)
			continue
		}

		name, err := adapter.GetPropertyName()
		if err != nil {
			logger.Warn().Msgf("failed to get interface name: %v", err)
			continue
		}

		// From: https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/hh968170(v=vs.85)
		//
		// "Indicates if a connector is present on the network adapter. This value is set to TRUE
		// if this is a physical adapter or FALSE if this is not a physical adapter."
		physical, err := adapter.GetPropertyConnectorPresent()
		if err != nil {
			logger.Debug().Msgf("failed to get network adapter connector present property: %v", err)
			continue
		}
		if !physical {
			logger.Debug().Msgf("skipping non-physical adapter: %s", name)
			continue
		}

		// Check if it's a hardware interface. Checking only for connector present is not enough
		// because some interfaces are not physical but have a connector.
		hardware, err := adapter.GetPropertyHardwareInterface()
		if err != nil {
			logger.Debug().Msgf("failed to get network adapter hardware interface property: %v", err)
			continue
		}
		if !hardware {
			logger.Debug().Msgf("skipping non-hardware interface: %s", name)
			continue
		}

		adapters = append(adapters, name)
	}

	m := make(map[string]struct{})
	for _, ifaceName := range adapters {
		m[ifaceName] = struct{}{}
	}
	return m
}
