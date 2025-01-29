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

	"github.com/StackExchange/wmi"
	"github.com/microsoft/wmi/pkg/base/host"
	"github.com/microsoft/wmi/pkg/base/instance"
	"github.com/microsoft/wmi/pkg/base/query"
	"github.com/microsoft/wmi/pkg/constant"
	"github.com/microsoft/wmi/pkg/hardware/network/netadapter"
	"github.com/rs/zerolog"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

const (
	maxRetries                           = 5
	retryDelay                           = 1 * time.Second
	defaultTimeout                       = 5 * time.Second
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

func dnsFromAdapter() []string {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	var ns []string
	var err error

	//load the logger
	logger := zerolog.New(io.Discard)
	if ProxyLogger.Load() != nil {
		logger = *ProxyLogger.Load()
	}

	for i := 0; i < maxRetries; i++ {
		if ctx.Err() != nil {
			Log(context.Background(), logger.Debug(),
				"dnsFromAdapter lookup cancelled or timed out, attempt %d", i)
			return nil
		}

		ns, err = getDNSServers(ctx)
		if err == nil && len(ns) >= minDNSServers {
			if i > 0 {
				Log(context.Background(), logger.Debug(),
					"Successfully got DNS servers after %d attempts, found %d servers", i+1, len(ns))
			}
			return ns
		}

		// Log the specific failure reason
		if err != nil {
			Log(context.Background(), logger.Debug(),
				"Failed to get DNS servers, attempt %d: %v", i+1, err)
		} else {
			Log(context.Background(), logger.Debug(),
				"Got insufficient DNS servers, retrying, found %d servers", len(ns))
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(retryDelay):
		}
	}

	Log(context.Background(), logger.Debug(),
		"Failed to get sufficient DNS servers after all attempts, max_retries=%d", maxRetries)
	return ns // Return whatever we got, even if insufficient
}

func getDNSServers(ctx context.Context) ([]string, error) {
	//load the logger
	logger := zerolog.New(io.Discard)
	if ProxyLogger.Load() != nil {
		logger = *ProxyLogger.Load()
	}
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

	Log(context.Background(), logger.Debug(),
		"Found network adapters, count=%d", len(aas))

	// Try to get domain controller info if domain-joined
	var dcServers []string
	isDomain := checkDomainJoined()
	if isDomain {

		domainName, err := getLocalADDomain()
		if err != nil {
			Log(context.Background(), logger.Debug(),
				"Failed to get local AD domain: %v", err)

		} else {

			// Load netapi32.dll
			netapi32 := windows.NewLazySystemDLL("netapi32.dll")
			dsDcName := netapi32.NewProc("DsGetDcNameW")

			var info *DomainControllerInfo

			flags := uint32(DS_RETURN_DNS_NAME |
				DS_IP_REQUIRED |
				DS_IS_DNS_NAME)

			// Convert domain name to UTF16 pointer
			domainUTF16, err := windows.UTF16PtrFromString(domainName)
			if err != nil {
				Log(context.Background(), logger.Debug(),
					"Failed to convert domain name to UTF16: %v", err)
			} else {
				Log(context.Background(), logger.Debug(),
					"Attempting to get DC for domain: %s with flags: 0x%x", domainName, flags)

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
						Log(context.Background(), logger.Debug(),
							"Domain not found: %s (%d)", domainName, ret)
					case 1311: // ERROR_NO_LOGON_SERVERS
						Log(context.Background(), logger.Debug(),
							"No logon servers available for domain: %s (%d)", domainName, ret)
					case 1004: // ERROR_DC_NOT_FOUND
						Log(context.Background(), logger.Debug(),
							"Domain controller not found for domain: %s (%d)", domainName, ret)
					case 1722: // RPC_S_SERVER_UNAVAILABLE
						Log(context.Background(), logger.Debug(),
							"RPC server unavailable for domain: %s (%d)", domainName, ret)
					default:
						Log(context.Background(), logger.Debug(),
							"Failed to get domain controller info for domain %s: %d, %v", domainName, ret, err)
					}
				} else if info != nil {
					defer windows.NetApiBufferFree((*byte)(unsafe.Pointer(info)))

					// Get DC address
					if info.DomainControllerAddress != nil {
						dcAddr := windows.UTF16PtrToString(info.DomainControllerAddress)
						dcAddr = strings.TrimPrefix(dcAddr, "\\\\")

						Log(context.Background(), logger.Debug(),
							"Found domain controller address: %s", dcAddr)

						// Try to resolve DC
						if ip := net.ParseIP(dcAddr); ip != nil {
							dcServers = append(dcServers, ip.String())
							Log(context.Background(), logger.Debug(),
								"Added domain controller DNS servers: %v", dcServers)
						}
					} else {
						Log(context.Background(), logger.Debug(),
							"No domain controller address found")
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
			Log(context.Background(), logger.Debug(),
				"Skipping adapter %s - not up, status: %d", aa.FriendlyName(), aa.OperStatus)
			continue
		}

		// Skip if software loopback or other non-physical types
		// This is to avoid the "Loopback Pseudo-Interface 1" issue we see on windows
		if aa.IfType == winipcfg.IfTypeSoftwareLoopback {
			Log(context.Background(), logger.Debug(),
				"Skipping %s (software loopback)", aa.FriendlyName())
			continue
		}

		Log(context.Background(), logger.Debug(),
			"Processing adapter %s", aa.FriendlyName())

		for a := aa.FirstUnicastAddress; a != nil; a = a.Next {
			ip := a.Address.IP().String()
			addressMap[ip] = struct{}{}
			Log(context.Background(), logger.Debug(),
				"Added local IP %s from adapter %s", ip, aa.FriendlyName())
		}
	}

	validInterfacesMap := validInterfaces()

	// Collect DNS servers
	for _, aa := range aas {
		if aa.OperStatus != winipcfg.IfOperStatusUp {
			continue
		}

		// Skip if software loopback or other non-physical types
		// This is to avoid the "Loopback Pseudo-Interface 1" issue we see on windows
		if aa.IfType == winipcfg.IfTypeSoftwareLoopback {
			Log(context.Background(), logger.Debug(),
				"Skipping %s (software loopback)", aa.FriendlyName())
			continue
		}

		// if not in the validInterfacesMap, skip
		if _, ok := validInterfacesMap[aa.FriendlyName()]; !ok {
			Log(context.Background(), logger.Debug(),
				"Skipping %s (not in validInterfacesMap)", aa.FriendlyName())
			continue
		}

		for dns := aa.FirstDNSServerAddress; dns != nil; dns = dns.Next {
			ip := dns.Address.IP()
			if ip == nil {
				Log(context.Background(), logger.Debug(),
					"Skipping nil IP from adapter %s", aa.FriendlyName())
				continue
			}

			ipStr := ip.String()
			logger := logger.Debug().
				Str("ip", ipStr).
				Str("adapter", aa.FriendlyName())

			if ip.IsLoopback() {
				logger.Msg("Skipping loopback IP")
				continue
			}

			if seen[ipStr] {
				logger.Msg("Skipping duplicate IP")
				continue
			}

			if _, ok := addressMap[ipStr]; ok {
				logger.Msg("Skipping local interface IP")
				continue
			}

			seen[ipStr] = true
			ns = append(ns, ipStr)
			logger.Msg("Added DNS server")
		}
	}

	// Add DC servers if they're not already in the list
	for _, dcServer := range dcServers {
		if !seen[dcServer] {
			seen[dcServer] = true
			ns = append(ns, dcServer)
			Log(context.Background(), logger.Debug(),
				"Added additional domain controller DNS server: %s", dcServer)
		}
	}

	if len(ns) == 0 {
		return nil, fmt.Errorf("no valid DNS servers found")
	}

	Log(context.Background(), logger.Debug(),
		"DNS server discovery completed, count=%d, servers=%v (including %d DC servers)",
		len(ns), ns, len(dcServers))
	return ns, nil
}

func nameserversFromResolvconf() []string {
	return nil
}

// checkDomainJoined checks if the machine is joined to an Active Directory domain
// Returns whether it's domain joined and the domain name if available
func checkDomainJoined() bool {
	//load the logger
	logger := zerolog.New(io.Discard)
	if ProxyLogger.Load() != nil {
		logger = *ProxyLogger.Load()
	}
	var domain *uint16
	var status uint32

	err := windows.NetGetJoinInformation(nil, &domain, &status)
	if err != nil {
		Log(context.Background(), logger.Debug(),
			"Failed to get domain join status: %v", err)
		return false
	}
	defer windows.NetApiBufferFree((*byte)(unsafe.Pointer(domain)))

	domainName := windows.UTF16PtrToString(domain)
	Log(context.Background(), logger.Debug(),
		"Domain join status: domain=%s status=%d (Unknown=0, Workgroup=1, Domain=2, CloudDomain=3)", domainName, status)

	// Consider both traditional and cloud domains as valid domain joins
	isDomain := status == NetSetupDomain || status == NetSetupCloudDomain
	Log(context.Background(), logger.Debug(),
		"Is domain joined? status=%d, traditional=%v, cloud=%v, result=%v",
		status,
		status == NetSetupDomain,
		status == NetSetupCloudDomain,
		isDomain)

	return isDomain
}

// Win32_ComputerSystem is the minimal struct for WMI query
type Win32_ComputerSystem struct {
	Domain string
}

// getLocalADDomain tries to detect the AD domain in two ways:
//  1. USERDNSDOMAIN env var (often set in AD logon sessions)
//  2. WMI Win32_ComputerSystem.Domain
func getLocalADDomain() (string, error) {
	// 1) Check environment variable
	envDomain := os.Getenv("USERDNSDOMAIN")
	if envDomain != "" {
		return strings.TrimSpace(envDomain), nil
	}

	// 2) Check WMI (requires Windows + admin privileges or sufficient access)
	var result []Win32_ComputerSystem
	err := wmi.Query("SELECT Domain FROM Win32_ComputerSystem", &result)
	if err != nil {
		return "", fmt.Errorf("WMI query failed: %v", err)
	}
	if len(result) == 0 {
		return "", fmt.Errorf("no rows returned from Win32_ComputerSystem")
	}

	domain := strings.TrimSpace(result[0].Domain)
	if domain == "" {
		return "", fmt.Errorf("machine does not appear to have a domain set")
	}
	return domain, nil
}

// validInterfaces returns a list of all physical interfaces.
// this is a duplicate of what is in net_windows.go, we should
// clean this up so there is only one version
func validInterfaces() map[string]struct{} {
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	//load the logger
	logger := zerolog.New(io.Discard)
	if ProxyLogger.Load() != nil {
		logger = *ProxyLogger.Load()
	}

	whost := host.NewWmiLocalHost()
	q := query.NewWmiQuery("MSFT_NetAdapter")
	instances, err := instance.GetWmiInstancesFromHost(whost, string(constant.StadardCimV2), q)
	if err != nil {
		Log(context.Background(), logger.Warn(),
			"failed to get wmi network adapter: %v", err)
		return nil
	}
	defer instances.Close()
	var adapters []string
	for _, i := range instances {
		adapter, err := netadapter.NewNetworkAdapter(i)
		if err != nil {
			Log(context.Background(), logger.Warn(),
				"failed to get network adapter: %v", err)
			continue
		}

		name, err := adapter.GetPropertyName()
		if err != nil {
			Log(context.Background(), logger.Warn(),
				"failed to get interface name: %v", err)
			continue
		}

		// From: https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/hh968170(v=vs.85)
		//
		// "Indicates if a connector is present on the network adapter. This value is set to TRUE
		// if this is a physical adapter or FALSE if this is not a physical adapter."
		physical, err := adapter.GetPropertyConnectorPresent()
		if err != nil {
			Log(context.Background(), logger.Debug(),
				"failed to get network adapter connector present property: %v", err)
			continue
		}
		if !physical {
			Log(context.Background(), logger.Debug(),
				"skipping non-physical adapter: %s", name)
			continue
		}

		// Check if it's a hardware interface. Checking only for connector present is not enough
		// because some interfaces are not physical but have a connector.
		hardware, err := adapter.GetPropertyHardwareInterface()
		if err != nil {
			Log(context.Background(), logger.Debug(),
				"failed to get network adapter hardware interface property: %v", err)
			continue
		}
		if !hardware {
			Log(context.Background(), logger.Debug(),
				"skipping non-hardware interface: %s", name)
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
