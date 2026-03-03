package ctrld

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/microsoft/wmi/pkg/base/host"
	"github.com/microsoft/wmi/pkg/base/instance"
	"github.com/microsoft/wmi/pkg/base/query"
	"github.com/microsoft/wmi/pkg/constant"
	"github.com/microsoft/wmi/pkg/hardware/network/netadapter"
	"github.com/miekg/dns"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"tailscale.com/net/netmon"

	"github.com/Control-D-Inc/ctrld/internal/system"
)

const (
	maxDNSAdapterRetries     = 5
	retryDelayDNSAdapter     = 1 * time.Second
	defaultDNSAdapterTimeout = 10 * time.Second
	minDNSServers            = 1 // Minimum number of DNS servers we want to find

	DS_FORCE_REDISCOVERY          = 0x00000001
	DS_DIRECTORY_SERVICE_REQUIRED = 0x00000010
	DS_BACKGROUND_ONLY            = 0x00000100
	DS_IP_REQUIRED                = 0x00000200
	DS_IS_DNS_NAME                = 0x00020000
	DS_RETURN_DNS_NAME            = 0x40000000

	// AD DC retry constants
	dcRetryInitialDelay = 1 * time.Second
	dcRetryMaxDelay     = 30 * time.Second
	dcRetryMaxAttempts  = 10

	// DsGetDcName error codes
	errNoSuchDomain   uintptr = 1355
	errNoLogonServers uintptr = 1311
	errDCNotFound     uintptr = 1004
	errRPCUnavailable uintptr = 1722
	errConnReset      uintptr = 10054
	errNetUnreachable uintptr = 1231
)

var (
	dcRetryMu     sync.Mutex
	dcRetryCancel context.CancelFunc

	// Lazy-loaded netapi32 for DsGetDcNameW calls.
	netapi32DLL  = windows.NewLazySystemDLL("netapi32.dll")
	dsGetDcNameW = netapi32DLL.NewProc("DsGetDcNameW")
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
	ctx, cancel := context.WithTimeout(context.Background(), defaultDNSAdapterTimeout)
	defer cancel()

	var ns []string
	var err error

	logger := *ProxyLogger.Load()

	for i := 0; i < maxDNSAdapterRetries; i++ {
		if ctx.Err() != nil {
			Log(context.Background(), logger.Debug(),
				"dnsFromAdapter lookup cancelled or timed out, attempt %d", i)
			return nil
		}

		ns, err = getDNSServers(ctx)
		if err == nil && len(ns) >= minDNSServers {
			if i > 0 {
				Log(context.Background(), logger.Debug(),
					"Successfully got DNS servers after %d attempts, found %d servers",
					i+1, len(ns))
			}
			return ns
		}

		// if osResolver is not initialized, this is likely a command line run
		// and ctrld is already on the interface, abort retries
		if or == nil {
			return ns
		}

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
		case <-time.After(retryDelayDNSAdapter):
		}
	}

	Log(context.Background(), logger.Debug(),
		"Failed to get sufficient DNS servers after all attempts, max_retries=%d", maxDNSAdapterRetries)
	return ns
}

func getDNSServers(ctx context.Context) ([]string, error) {
	logger := *ProxyLogger.Load()

	// Cancel any in-flight DC retry from a previous network state.
	cancelDCRetry()

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
	var adDomain string
	isDomain := checkDomainJoined()
	if isDomain {
		domainName, err := system.GetActiveDirectoryDomain()
		if err != nil {
			Log(ctx, logger.Debug(),
				"Failed to get local AD domain: %v", err)
		} else {
			adDomain = domainName
			// Load netapi32.dll
			var info *DomainControllerInfo
			flags := uint32(DS_RETURN_DNS_NAME | DS_IP_REQUIRED | DS_IS_DNS_NAME)

			domainUTF16, err := windows.UTF16PtrFromString(domainName)
			if err != nil {
				Log(ctx, logger.Debug(), "Failed to convert domain name to UTF16: %v", err)
			} else {
				Log(ctx, logger.Debug(),
					"Attempting to get DC for domain: %s with flags: 0x%x", domainName, flags)

				// Call DsGetDcNameW with domain name
				ret, _, err := dsGetDcNameW.Call(
					0,                                    // ComputerName - can be NULL
					uintptr(unsafe.Pointer(domainUTF16)), // DomainName
					0,                                    // DomainGuid - not needed
					0,                                    // SiteName - not needed
					uintptr(flags),                       // Flags
					uintptr(unsafe.Pointer(&info)))       // DomainControllerInfo - output

				if ret != 0 {
					switch ret {
					case errNoSuchDomain:
						Log(ctx, logger.Debug(),
							"Domain not found: %s (%d)", domainName, ret)
					case errNoLogonServers:
						Log(ctx, logger.Debug(),
							"No logon servers available for domain: %s (%d)", domainName, ret)
					case errDCNotFound:
						Log(ctx, logger.Debug(),
							"Domain controller not found for domain: %s (%d)", domainName, ret)
					case errRPCUnavailable:
						Log(ctx, logger.Debug(),
							"RPC server unavailable for domain: %s (%d)", domainName, ret)
					default:
						Log(ctx, logger.Debug(),
							"Failed to get domain controller info for domain %s: %d, %v", domainName, ret, err)
					}
					// Start background retry for transient DC errors.
					if isTransientDCError(ret) {
						Log(ctx, logger.Info(),
							"AD DC detection failed with transient error %d for %s, starting background retry", ret, domainName)
						startDCRetry(domainName)
					}
				} else if info != nil {
					defer windows.NetApiBufferFree((*byte)(unsafe.Pointer(info)))

					if info.DomainControllerAddress != nil {
						dcAddr := windows.UTF16PtrToString(info.DomainControllerAddress)
						dcAddr = strings.TrimPrefix(dcAddr, "\\\\")
						Log(ctx, logger.Debug(),
							"Found domain controller address: %s", dcAddr)

						if ip := net.ParseIP(dcAddr); ip != nil {
							dcServers = append(dcServers, ip.String())
							Log(ctx, logger.Debug(),
								"Added domain controller DNS servers: %v", dcServers)
						}
					} else {
						Log(ctx, logger.Debug(), "No domain controller address found")
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
			Log(ctx, logger.Debug(),
				"Skipping adapter %s - not up, status: %d", aa.FriendlyName(), aa.OperStatus)
			continue
		}

		// Skip if software loopback or other non-physical types
		// This is to avoid the "Loopback Pseudo-Interface 1" issue we see on windows
		if aa.IfType == winipcfg.IfTypeSoftwareLoopback {
			Log(ctx, logger.Debug(), "Skipping %s (software loopback)", aa.FriendlyName())
			continue
		}

		Log(ctx, logger.Debug(), "Processing adapter %s", aa.FriendlyName())

		for a := aa.FirstUnicastAddress; a != nil; a = a.Next {
			ip := a.Address.IP().String()
			addressMap[ip] = struct{}{}
			Log(ctx, logger.Debug(), "Added local IP %s from adapter %s", ip, aa.FriendlyName())
		}
	}

	validInterfacesMap := validInterfaces()

	if isDomain && adDomain == "" {
		Log(ctx, logger.Warn(), "The machine is joined domain, but domain name is empty")
	}
	checkDnsSuffix := isDomain && adDomain != ""
	// Collect DNS servers
	for _, aa := range aas {
		if aa.OperStatus != winipcfg.IfOperStatusUp {
			continue
		}

		// Skip if software loopback or other non-physical types
		// This is to avoid the "Loopback Pseudo-Interface 1" issue we see on windows
		if aa.IfType == winipcfg.IfTypeSoftwareLoopback {
			Log(ctx, logger.Debug(), "Skipping %s (software loopback)", aa.FriendlyName())
			continue
		}

		_, valid := validInterfacesMap[aa.FriendlyName()]
		if !valid && checkDnsSuffix {
			for suffix := aa.FirstDNSSuffix; suffix != nil; suffix = suffix.Next {
				// For non-physical adapters but have the DNS suffix that matches the domain name,
				// (or vice versa) consider it valid. This can happen when remote VPN machines.
				ds := strings.TrimSpace(suffix.String())
				if dns.IsSubDomain(adDomain, ds) || dns.IsSubDomain(ds, adDomain) {
					Log(ctx, logger.Debug(), "Found valid interface %s with DNS suffix %s", aa.FriendlyName(), suffix.String())
					valid = true
					break
				}
			}
		}
		// if not a valid interface, skip it
		if !valid {
			Log(ctx, logger.Debug(), "Skipping %s (not in validInterfacesMap)", aa.FriendlyName())
			continue
		}

		for dns := aa.FirstDNSServerAddress; dns != nil; dns = dns.Next {
			ip := dns.Address.IP()
			if ip == nil {
				Log(ctx, logger.Debug(), "Skipping nil IP from adapter %s", aa.FriendlyName())
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
			Log(ctx, logger.Debug(), "Added additional domain controller DNS server: %s", dcServer)
		}
	}

	// if we have static DNS servers saved for the current default route, we should add them to the list
	drIfaceName, err := netmon.DefaultRouteInterface()
	if err != nil {
		Log(ctx, logger.Debug(), "Failed to get default route interface: %v", err)
	} else {
		drIface, err := net.InterfaceByName(drIfaceName)
		if err != nil {
			Log(ctx, logger.Debug(), "Failed to get interface by name %s: %v", drIfaceName, err)
		} else {
			staticNs, file := SavedStaticNameservers(drIface)
			Log(ctx, logger.Debug(), "static dns servers from %s: %v", file, staticNs)
			if len(staticNs) > 0 {
				Log(ctx, logger.Debug(), "Adding static DNS servers from %s: %v", drIfaceName, staticNs)
				ns = append(ns, staticNs...)
			}
		}
	}

	if len(ns) == 0 {
		return nil, fmt.Errorf("no valid DNS servers found")
	}

	Log(ctx, logger.Debug(), "DNS server discovery completed, count=%d, servers=%v (including %d DC servers)",
		len(ns), ns, len(dcServers))
	return ns, nil
}

// currentNameserversFromResolvconf returns a nil slice of strings.
func currentNameserversFromResolvconf() []string {
	return nil
}

// checkDomainJoined checks if the machine is joined to an Active Directory domain
// Returns whether it's domain joined and the domain name if available
func checkDomainJoined() bool {
	logger := *ProxyLogger.Load()

	status, err := system.DomainJoinedStatus()
	if err != nil {
		logger.Debug().Msgf("Failed to get domain joined status: %v", err)
		return false
	}
	isDomain := status == syscall.NetSetupDomainName
	logger.Debug().Msg("Domain join status: (UnknownStatus=0, Unjoined=1, WorkgroupName=2, DomainName=3)")
	logger.Debug().Msgf("Is domain joined? status=%d, result=%v", status, isDomain)

	return isDomain
}

// isTransientDCError returns true if the DsGetDcName error code indicates
// a transient failure that may succeed on retry.
func isTransientDCError(code uintptr) bool {
	switch code {
	case errConnReset, errRPCUnavailable, errNoLogonServers, errDCNotFound, errNetUnreachable:
		return true
	default:
		return false
	}
}

// cancelDCRetry cancels any in-flight DC retry goroutine.
func cancelDCRetry() {
	dcRetryMu.Lock()
	defer dcRetryMu.Unlock()
	if dcRetryCancel != nil {
		dcRetryCancel()
		dcRetryCancel = nil
	}
}

// startDCRetry spawns a background goroutine that retries DsGetDcName with
// exponential backoff. On success it appends the DC IP to the OS resolver.
func startDCRetry(domainName string) {
	dcRetryMu.Lock()
	// Cancel any previous retry.
	if dcRetryCancel != nil {
		dcRetryCancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	dcRetryCancel = cancel
	dcRetryMu.Unlock()

	go func() {
		logger := *ProxyLogger.Load()
		delay := dcRetryInitialDelay

		for attempt := 1; attempt <= dcRetryMaxAttempts; attempt++ {
			select {
			case <-ctx.Done():
				Log(context.Background(), logger.Debug(), "AD DC retry cancelled for domain %s", domainName)
				return
			case <-time.After(delay):
			}

			Log(ctx, logger.Debug(),
				"AD DC retry attempt %d/%d for domain %s (delay was %v)",
				attempt, dcRetryMaxAttempts, domainName, delay)

			dcIP, errCode := tryGetDCAddress(domainName)
			if dcIP != "" {
				Log(context.Background(), logger.Info(),
					"AD DC retry succeeded: found DC at %s for domain %s (attempt %d)",
					dcIP, domainName, attempt)
				if AppendOsResolverNameservers([]string{dcIP}) {
					Log(context.Background(), logger.Info(),
						"Added DC %s to OS resolver nameservers", dcIP)
				} else {
					Log(context.Background(), logger.Warn(),
						"AD DC retry: OS resolver not initialized, DC IP %s was not added", dcIP)
				}
				return
			}

			// Permanent error or unexpected empty result — stop retrying.
			if errCode != 0 && !isTransientDCError(errCode) {
				Log(context.Background(), logger.Debug(),
					"AD DC retry stopping: permanent error %d for domain %s", errCode, domainName)
				return
			}
			if errCode == 0 {
				// DsGetDcName returned success but no usable address — don't retry.
				Log(context.Background(), logger.Debug(),
					"AD DC retry stopping: DsGetDcName returned no address for domain %s", domainName)
				return
			}

			// Exponential backoff.
			delay *= 2
			if delay > dcRetryMaxDelay {
				delay = dcRetryMaxDelay
			}
		}

		Log(ctx, logger.Warn(),
			"AD DC retry exhausted %d attempts for domain %s", dcRetryMaxAttempts, domainName)
	}()
}

// tryGetDCAddress attempts a single DsGetDcName call and returns the DC IP on success,
// or empty string and the error code on failure.
func tryGetDCAddress(domainName string) (string, uintptr) {
	logger := *ProxyLogger.Load()

	var info *DomainControllerInfo
	// Use DS_FORCE_REDISCOVERY on retries to bypass the DC locator cache,
	// which may have cached the initial transient failure.
	flags := uint32(DS_RETURN_DNS_NAME | DS_IP_REQUIRED | DS_IS_DNS_NAME | DS_FORCE_REDISCOVERY)

	domainUTF16, err := windows.UTF16PtrFromString(domainName)
	if err != nil {
		Log(context.Background(), logger.Debug(),
			"Failed to convert domain name to UTF16: %v", err)
		return "", 0
	}

	ret, _, _ := dsGetDcNameW.Call(
		0,
		uintptr(unsafe.Pointer(domainUTF16)),
		0,
		0,
		uintptr(flags),
		uintptr(unsafe.Pointer(&info)))

	if ret != 0 {
		Log(context.Background(), logger.Debug(),
			"DsGetDcName retry failed for %s: error %d", domainName, ret)
		return "", ret
	}

	if info == nil {
		return "", 0
	}
	defer windows.NetApiBufferFree((*byte)(unsafe.Pointer(info)))

	if info.DomainControllerAddress == nil {
		return "", 0
	}

	dcAddr := windows.UTF16PtrToString(info.DomainControllerAddress)
	dcAddr = strings.TrimPrefix(dcAddr, "\\\\")
	if ip := net.ParseIP(dcAddr); ip != nil {
		return ip.String(), 0
	}
	return "", 0
}

// validInterfaces returns a list of all physical interfaces.
// this is a duplicate of what is in net_windows.go, we should
// clean this up so there is only one version
func validInterfaces() map[string]struct{} {
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	//load the logger
	logger := *ProxyLogger.Load()

	whost := host.NewWmiLocalHost()
	q := query.NewWmiQuery("MSFT_NetAdapter")
	instances, err := instance.GetWmiInstancesFromHost(whost, string(constant.StadardCimV2), q)
	if instances != nil {
		defer instances.Close()
	}
	if err != nil {
		Log(context.Background(), logger.Warn(),
			"failed to get wmi network adapter: %v", err)
		return nil
	}
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
