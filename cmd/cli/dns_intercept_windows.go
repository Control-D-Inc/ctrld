//go:build windows

package cli

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"os/exec"
	"runtime"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/Control-D-Inc/ctrld"
)

// DNS Intercept Mode — Windows Implementation (WFP)
//
// This file implements DNS interception using Windows Filtering Platform (WFP).
// WFP is a kernel-level network filtering framework that allows applications to
// inspect and modify network traffic at various layers of the TCP/IP stack.
//
// Strategy:
//   - Create a WFP sublayer at maximum priority (weight 0xFFFF)
//   - Add PERMIT filters (weight 10) for DNS to localhost (ctrld's listener)
//   - Add BLOCK filters (weight 1) for all other outbound DNS
//   - Dynamically add/remove PERMIT filters for VPN DNS server exemptions
//
// This means even if VPN software overwrites adapter DNS settings, the OS
// cannot reach those DNS servers on port 53 — all DNS must flow through ctrld.
//
// Key advantages over macOS pf:
//   - WFP filters are per-process kernel objects — other apps can't wipe them
//   - No watchdog or stabilization needed
//   - Connection-level filtering — no packet state/return-path complications
//   - Full IPv4 + IPv6 support
//
// See docs/wfp-dns-intercept.md for architecture diagrams and debugging tips.

// WFP GUIDs and constants for DNS interception.
// These are defined by Microsoft's Windows Filtering Platform API.
var (
	// ctrldSubLayerGUID is a unique GUID for ctrld's WFP sublayer.
	// Generated specifically for ctrld DNS intercept mode.
	ctrldSubLayerGUID = windows.GUID{
		Data1: 0x7a4e5b6c,
		Data2: 0x3d2f,
		Data3: 0x4a1e,
		Data4: [8]byte{0x9b, 0x8c, 0x1d, 0x2e, 0x3f, 0x4a, 0x5b, 0x6c},
	}

	// Well-known WFP layer GUIDs from Microsoft documentation.
	// FWPM_LAYER_ALE_AUTH_CONNECT_V4: filters outbound IPv4 connection attempts.
	fwpmLayerALEAuthConnectV4 = windows.GUID{
		Data1: 0xc38d57d1,
		Data2: 0x05a7,
		Data3: 0x4c33,
		Data4: [8]byte{0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82},
	}
	// FWPM_LAYER_ALE_AUTH_CONNECT_V6: filters outbound IPv6 connection attempts.
	fwpmLayerALEAuthConnectV6 = windows.GUID{
		Data1: 0x4a72393b,
		Data2: 0x319f,
		Data3: 0x44bc,
		Data4: [8]byte{0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4},
	}

	// FWPM_CONDITION_IP_REMOTE_PORT: condition matching on remote port.
	fwpmConditionIPRemotePort = windows.GUID{
		Data1: 0xc35a604d,
		Data2: 0xd22b,
		Data3: 0x4e1a,
		Data4: [8]byte{0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b},
	}
	// FWPM_CONDITION_IP_REMOTE_ADDRESS: condition matching on remote address.
	fwpmConditionIPRemoteAddress = windows.GUID{
		Data1: 0xb235ae9a,
		Data2: 0x1d64,
		Data3: 0x49b8,
		Data4: [8]byte{0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45},
	}
	// FWPM_CONDITION_IP_PROTOCOL: condition matching on IP protocol.
	fwpmConditionIPProtocol = windows.GUID{
		Data1: 0x3971ef2b,
		Data2: 0x623e,
		Data3: 0x4f9a,
		Data4: [8]byte{0x8c, 0xb1, 0x6e, 0x79, 0xb8, 0x06, 0xb9, 0xa7},
	}
)

const (
	// WFP action constants. These combine a base action with the TERMINATING flag.
	// See: https://docs.microsoft.com/en-us/windows/win32/api/fwptypes/ne-fwptypes-fwp_action_type
	fwpActionFlagTerminating uint32 = 0x00001000
	fwpActionBlock           uint32 = 0x00000001 | fwpActionFlagTerminating // 0x00001001
	fwpActionPermit          uint32 = 0x00000002 | fwpActionFlagTerminating // 0x00001002

	// FWP_MATCH_EQUAL is the match type for exact value comparison.
	fwpMatchEqual uint32 = 0 // FWP_MATCH_EQUAL

	// FWP_DATA_TYPE constants for condition values.
	// Enum starts at FWP_EMPTY=0, so FWP_UINT8=1, etc.
	// See: https://learn.microsoft.com/en-us/windows/win32/api/fwptypes/ne-fwptypes-fwp_data_type
	fwpUint8           uint32 = 1     // FWP_UINT8
	fwpUint16          uint32 = 2     // FWP_UINT16
	fwpUint32          uint32 = 3     // FWP_UINT32
	fwpByteArray16Type uint32 = 11    // FWP_BYTE_ARRAY16_TYPE
	fwpV4AddrMask      uint32 = 0x100 // FWP_V4_ADDR_MASK (after FWP_SINGLE_DATA_TYPE_MAX=0xff)

	// IP protocol numbers.
	ipprotoUDP uint8 = 17
	ipprotoTCP uint8 = 6

	// DNS port.
	dnsPort uint16 = 53
)

// WFP API structures. These mirror the C structures from fwpmtypes.h and fwptypes.h.
// We define them here because golang.org/x/sys/windows doesn't include WFP types.
//
// IMPORTANT: These struct layouts must match the C ABI exactly (64-bit Windows).
// Field alignment and padding are critical. Any mismatch will cause access violations
// or silent corruption. The layouts below are for AMD64 only.
// If issues arise, verify against the Windows SDK headers with offsetof() checks.

// fwpmSession0 represents FWPM_SESSION0 for opening a WFP engine handle.
type fwpmSession0 struct {
	sessionKey           windows.GUID
	displayData          fwpmDisplayData0
	flags                uint32
	txnWaitTimeoutInMSec uint32
	processId            uint32
	sid                  *windows.SID
	username             *uint16
	kernelMode           int32   // Windows BOOL is int32, not Go bool
	_                    [4]byte // padding to next 8-byte boundary
}

// fwpmDisplayData0 represents FWPM_DISPLAY_DATA0 for naming WFP objects.
type fwpmDisplayData0 struct {
	name        *uint16
	description *uint16
}

// fwpmSublayer0 represents FWPM_SUBLAYER0 for creating a WFP sublayer.
type fwpmSublayer0 struct {
	subLayerKey  windows.GUID
	displayData  fwpmDisplayData0
	flags        uint32
	_            [4]byte // padding
	providerKey  *windows.GUID
	providerData fwpByteBlob
	weight       uint16
	_            [6]byte // padding
}

// fwpByteBlob represents FWP_BYTE_BLOB for raw data blobs.
type fwpByteBlob struct {
	size uint32
	_    [4]byte // padding
	data *byte
}

// fwpmFilter0 represents FWPM_FILTER0 for adding WFP filters.
type fwpmFilter0 struct {
	filterKey       windows.GUID
	displayData     fwpmDisplayData0
	flags           uint32
	_               [4]byte // padding
	providerKey     *windows.GUID
	providerData    fwpByteBlob
	layerKey        windows.GUID
	subLayerKey     windows.GUID
	weight          fwpValue0
	numFilterConds  uint32
	_               [4]byte // padding
	filterCondition *fwpmFilterCondition0
	action          fwpmAction0
	// After action is a union of UINT64 (rawContext) and GUID (providerContextKey).
	// GUID is 16 bytes, UINT64 is 8 bytes. Union size = 16 bytes.
	rawContext      uint64 // first 8 bytes of the union
	_rawContextPad  uint64 // remaining 8 bytes (unused, for GUID alignment)
	reserved        *windows.GUID
	filterId        uint64
	effectiveWeight fwpValue0
}

// fwpValue0 represents FWP_VALUE0, a tagged union for filter weights and values.
type fwpValue0 struct {
	valueType uint32
	_         [4]byte // padding
	value     uint64  // union: uint8/uint16/uint32/uint64/pointer
}

// fwpmFilterCondition0 represents FWPM_FILTER_CONDITION0 for filter match conditions.
type fwpmFilterCondition0 struct {
	fieldKey  windows.GUID
	matchType uint32
	_         [4]byte // padding
	condValue fwpConditionValue0
}

// fwpConditionValue0 represents FWP_CONDITION_VALUE0, the value to match against.
type fwpConditionValue0 struct {
	valueType uint32
	_         [4]byte // padding
	value     uint64  // union
}

// fwpV4AddrAndMask represents FWP_V4_ADDR_AND_MASK for subnet matching.
// Both addr and mask are in host byte order.
type fwpV4AddrAndMask struct {
	addr uint32
	mask uint32
}

// fwpmAction0 represents FWPM_ACTION0 for specifying what happens on match.
// Size: 20 bytes (uint32 + GUID). No padding needed — GUID has 4-byte alignment.
type fwpmAction0 struct {
	actionType uint32
	filterType windows.GUID // union: filterType or calloutKey
}

// wfpState holds the state of the WFP DNS interception filters.
// It tracks the engine handle and all filter IDs for cleanup on shutdown.
// All filter IDs are stored so we can remove them individually without
// needing to enumerate the sublayer's filters via WFP API.
//
// The engine handle is opened once at startup and kept for the lifetime
// of the ctrld process. Filter additions/removals happen through this handle.
type wfpState struct {
	engineHandle  uintptr
	filterIDv4UDP uint64
	filterIDv4TCP uint64
	filterIDv6UDP uint64
	filterIDv6TCP uint64
	// Permit filter IDs for localhost traffic (prevent blocking ctrld's own listener).
	permitIDv4UDP uint64
	permitIDv4TCP uint64
	permitIDv6UDP uint64
	permitIDv6TCP uint64
	// Dynamic permit filter IDs for VPN DNS server IPs.
	vpnPermitFilterIDs []uint64
	// Static permit filter IDs for RFC1918/CGNAT subnet ranges.
	// These allow VPN DNS servers on private IPs to work without dynamic exemptions.
	subnetPermitFilterIDs []uint64
	// nrptActive tracks whether the NRPT catch-all rule was successfully added.
	// Used by stopDNSIntercept to know whether cleanup is needed.
	nrptActive bool
	// listenerIP is the actual IP address ctrld is listening on (e.g., "127.0.0.1"
	// or "127.0.0.2" on AD DC). Used by NRPT rule creation and health monitor to
	// ensure NRPT points to the correct address.
	listenerIP string
	// stopCh is used to shut down the NRPT health monitor goroutine.
	stopCh chan struct{}
}

// Lazy-loaded WFP DLL procedures.
var (
	fwpuclntDLL                  = windows.NewLazySystemDLL("fwpuclnt.dll")
	procFwpmEngineOpen0          = fwpuclntDLL.NewProc("FwpmEngineOpen0")
	procFwpmEngineClose0         = fwpuclntDLL.NewProc("FwpmEngineClose0")
	procFwpmSubLayerAdd0         = fwpuclntDLL.NewProc("FwpmSubLayerAdd0")
	procFwpmSubLayerDeleteByKey0 = fwpuclntDLL.NewProc("FwpmSubLayerDeleteByKey0")
	procFwpmFilterAdd0           = fwpuclntDLL.NewProc("FwpmFilterAdd0")
	procFwpmFilterDeleteById0    = fwpuclntDLL.NewProc("FwpmFilterDeleteById0")
	procFwpmSubLayerGetByKey0    = fwpuclntDLL.NewProc("FwpmSubLayerGetByKey0")
	procFwpmFreeMemory0          = fwpuclntDLL.NewProc("FwpmFreeMemory0")
)

// Lazy-loaded dnsapi.dll for flushing the DNS Client cache after NRPT changes.
var (
	dnsapiDLL                 = windows.NewLazySystemDLL("dnsapi.dll")
	procDnsFlushResolverCache = dnsapiDLL.NewProc("DnsFlushResolverCache")
)

// Lazy-loaded userenv.dll for triggering Group Policy refresh so DNS Client
// picks up new NRPT registry entries without waiting for the next GP cycle.
var (
	userenvDLL          = windows.NewLazySystemDLL("userenv.dll")
	procRefreshPolicyEx = userenvDLL.NewProc("RefreshPolicyEx")
)

// NRPT (Name Resolution Policy Table) Registry Constants
//
// NRPT tells the Windows DNS Client service where to send queries for specific
// namespaces. We add a catch-all rule ("." matches everything) that directs all
// DNS queries to ctrld's listener (typically 127.0.0.1, but may be 127.0.0.x on AD DC).
//
// This complements the WFP block filters:
//   - NRPT: tells Windows DNS Client to send queries to ctrld (positive routing)
//   - WFP:  blocks any DNS that somehow bypasses NRPT (enforcement backstop)
//
// Without NRPT, WFP blocks outbound DNS but doesn't redirect it — applications
// would just see DNS failures instead of getting answers from ctrld.
const (
	// nrptBaseKey is the GP registry path where Windows stores NRPT policy rules.
	nrptBaseKey = `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig`
	// nrptDirectKey is the local service store path. The DNS Client reads NRPT
	// from both locations, but on some machines (including stock Win11) it only
	// honors the direct path. This is the same path Add-DnsClientNrptRule uses.
	nrptDirectKey = `SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig`
	// nrptRuleName is the name of our specific rule key under the GP path.
	nrptRuleName = `CtrldCatchAll`
	// nrptDirectRuleName is the key name for the direct service store path.
	// The DNS Client requires direct-path rules to use GUID-in-braces format.
	// Using a plain name like "CtrldCatchAll" makes the rule visible in
	// Get-DnsClientNrptRule but DNS Client won't apply it for resolution
	// (Get-DnsClientNrptPolicy returns empty). This is a deterministic GUID
	// so we can reliably find and clean up our own rule.
	nrptDirectRuleName = `{B2E9A3C1-7F4D-4A8E-9D6B-5C1E0F3A2B8D}`
)

// addNRPTCatchAllRule creates an NRPT catch-all rule that directs all DNS queries
// to the specified listener IP.
//
// Windows NRPT has two registry paths with all-or-nothing precedence:
//   - GP path: SOFTWARE\Policies\...\DnsPolicyConfig (Group Policy)
//   - Local path: SYSTEM\CurrentControlSet\...\DnsPolicyConfig (service store)
//
// If ANY rules exist in the GP path (from IT policy, VPN, MDM, etc.), DNS Client
// enters "GP mode" and ignores ALL local-path rules entirely. Conversely, if the
// GP path is empty/absent, DNS Client reads from the local path only.
//
// Strategy (matching Tailscale's approach):
//   - Always write to the local path (baseline for non-domain machines).
//   - Check if OTHER software has GP rules. If yes, also write to the GP path
//     so our rule isn't invisible. If no, clean our stale GP rules and delete the
//     empty GP key to stay in "local mode".
//   - After GP writes, call RefreshPolicyEx to activate.
func addNRPTCatchAllRule(listenerIP string) error {
	// Always write to local/direct service store path.
	if err := writeNRPTRule(nrptDirectKey+`\`+nrptDirectRuleName, listenerIP); err != nil {
		return fmt.Errorf("failed to write NRPT local path rule: %w", err)
	}

	// Check if other software has GP NRPT rules. If so, we must also write
	// to the GP path — otherwise DNS Client's "GP mode" hides our local rule.
	if otherGPRulesExist() {
		mainLog.Load().Info().Msg("DNS intercept: other GP NRPT rules detected — also writing to GP path")
		if err := writeNRPTRule(nrptBaseKey+`\`+nrptRuleName, listenerIP); err != nil {
			mainLog.Load().Warn().Err(err).Msg("DNS intercept: failed to write NRPT GP rule (local rule still active if GP clears)")
		}
	} else {
		// No other GP rules — clean our stale GP entry and delete the empty
		// GP parent key so DNS Client stays in "local mode".
		cleanGPPath()
	}
	return nil
}

// otherGPRulesExist checks if non-ctrld NRPT rules exist in the GP path.
// When other software (IT policy, VPN, MDM) has GP rules, DNS Client enters
// "GP mode" and ignores ALL local-path rules.
func otherGPRulesExist() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, nrptBaseKey, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return false // GP key doesn't exist — no GP rules.
	}
	names, err := k.ReadSubKeyNames(-1)
	k.Close()
	if err != nil {
		return false
	}
	for _, name := range names {
		if name != nrptRuleName { // Not our CtrldCatchAll
			return true
		}
	}
	return false
}

// cleanGPPath removes our CtrldCatchAll rule from the GP path and deletes
// the GP DnsPolicyConfig parent key if no other rules remain. Removing the
// empty GP key is critical: its mere existence forces DNS Client into "GP mode"
// where local-path rules are ignored.
func cleanGPPath() {
	// Delete our specific rule.
	registry.DeleteKey(registry.LOCAL_MACHINE, nrptBaseKey+`\`+nrptRuleName)

	// If the GP parent key is now empty, delete it entirely to exit "GP mode".
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, nrptBaseKey, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return // Key doesn't exist — clean state.
	}
	names, err := k.ReadSubKeyNames(-1)
	k.Close()
	if err != nil || len(names) > 0 {
		if len(names) > 0 {
			mainLog.Load().Debug().Strs("remaining", names).Msg("DNS intercept: GP path has other rules, leaving parent key")
		}
		return
	}
	// Empty — delete it to exit "GP mode".
	if err := registry.DeleteKey(registry.LOCAL_MACHINE, nrptBaseKey); err == nil {
		mainLog.Load().Info().Msg("DNS intercept: deleted empty GP DnsPolicyConfig key (exits GP mode)")
	}
}

// writeNRPTRule writes a single NRPT catch-all rule at the given registry keyPath.
func writeNRPTRule(keyPath, listenerIP string) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, keyPath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("failed to create NRPT registry key %q: %w", keyPath, err)
	}
	defer k.Close()

	// Name (REG_MULTI_SZ): namespace patterns to match. "." = catch-all.
	if err := k.SetStringsValue("Name", []string{"."}); err != nil {
		return fmt.Errorf("failed to set NRPT Name value: %w", err)
	}
	// GenericDNSServers (REG_SZ): DNS server(s) to use for matching queries.
	if err := k.SetStringValue("GenericDNSServers", listenerIP); err != nil {
		return fmt.Errorf("failed to set NRPT GenericDNSServers value: %w", err)
	}
	// ConfigOptions (REG_DWORD): 0x8 = use standard DNS resolution (no DirectAccess).
	if err := k.SetDWordValue("ConfigOptions", 0x8); err != nil {
		return fmt.Errorf("failed to set NRPT ConfigOptions value: %w", err)
	}
	// Version (REG_DWORD): 0x2 = NRPT rule version 2.
	if err := k.SetDWordValue("Version", 0x2); err != nil {
		return fmt.Errorf("failed to set NRPT Version value: %w", err)
	}
	// Match the exact fields Add-DnsClientNrptRule creates. The DNS Client CIM
	// provider writes these as empty strings; their absence may cause the service
	// to skip the rule on some Windows builds.
	k.SetStringValue("Comment", "")
	k.SetStringValue("DisplayName", "")
	k.SetStringValue("IPSECCARestriction", "")
	return nil
}

// removeNRPTCatchAllRule deletes the ctrld NRPT catch-all registry key and
// cleans up the empty parent key if no other NRPT rules remain.
//
// The empty parent cleanup is critical: an empty DnsPolicyConfig key causes
// DNS Client to cache a "no rules" state. On next start, DNS Client ignores
// newly written rules because it still has the cached empty state. By deleting
// the empty parent on stop, we ensure a clean slate for the next start.
func removeNRPTCatchAllRule() error {
	// Remove our GUID-named rule from local/direct path.
	if err := registry.DeleteKey(registry.LOCAL_MACHINE, nrptDirectKey+`\`+nrptDirectRuleName); err != nil {
		if err != registry.ErrNotExist {
			return fmt.Errorf("failed to delete NRPT local rule: %w", err)
		}
	}
	deleteEmptyParentKey(nrptDirectKey)
	// Clean up legacy rules from earlier builds (plain name in direct path, GP path rules).
	registry.DeleteKey(registry.LOCAL_MACHINE, nrptDirectKey+`\`+nrptRuleName)
	cleanGPPath()
	return nil
}

// deleteEmptyParentKey removes a registry key if it exists but has no subkeys.
func deleteEmptyParentKey(keyPath string) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return
	}
	names, err := k.ReadSubKeyNames(-1)
	k.Close()
	if err != nil || len(names) > 0 {
		return
	}
	registry.DeleteKey(registry.LOCAL_MACHINE, keyPath)
}

// nrptCatchAllRuleExists checks whether our NRPT catch-all rule exists
// in either the local or GP path.
func nrptCatchAllRuleExists() bool {
	for _, path := range []string{
		nrptDirectKey + `\` + nrptDirectRuleName,
		nrptBaseKey + `\` + nrptRuleName,
	} {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
		if err == nil {
			k.Close()
			return true
		}
	}
	return false
}

// refreshNRPTPolicy triggers a machine Group Policy refresh so the DNS Client
// service picks up new/changed NRPT registry entries immediately. Without this,
// NRPT changes only take effect on the next GP cycle (default: 90 minutes).
//
// Uses RefreshPolicyEx(bMachine=TRUE, dwOptions=RP_FORCE=1) from userenv.dll.
// See: https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-refreshpolicyex
func refreshNRPTPolicy() {
	if err := userenvDLL.Load(); err != nil {
		mainLog.Load().Debug().Err(err).Msg("DNS intercept: userenv.dll not available, falling back to gpupdate")
		if out, err := exec.Command("gpupdate", "/target:computer", "/force").CombinedOutput(); err != nil {
			mainLog.Load().Debug().Msgf("DNS intercept: gpupdate failed: %v: %s", err, string(out))
		} else {
			mainLog.Load().Debug().Msg("DNS intercept: triggered GP refresh via gpupdate")
		}
		return
	}
	if err := procRefreshPolicyEx.Find(); err != nil {
		mainLog.Load().Debug().Err(err).Msg("DNS intercept: RefreshPolicyEx not found, falling back to gpupdate")
		exec.Command("gpupdate", "/target:computer", "/force").Run()
		return
	}
	// RefreshPolicyEx(BOOL bMachine, DWORD dwOptions)
	// bMachine=1 (TRUE) = refresh computer policy, dwOptions=1 (RP_FORCE) = force refresh
	ret, _, _ := procRefreshPolicyEx.Call(1, 1)
	if ret != 0 {
		mainLog.Load().Debug().Msg("DNS intercept: triggered machine GP refresh via RefreshPolicyEx")
	} else {
		mainLog.Load().Debug().Msg("DNS intercept: RefreshPolicyEx returned FALSE, falling back to gpupdate")
		exec.Command("gpupdate", "/target:computer", "/force").Run()
	}
}

// flushDNSCache flushes the Windows DNS Client resolver cache and triggers a
// Group Policy refresh so NRPT changes take effect immediately.
// Uses DnsFlushResolverCache from dnsapi.dll + RefreshPolicyEx from userenv.dll.
func flushDNSCache() {
	// Step 1: Refresh GP so DNS Client loads the new NRPT rules from registry.
	refreshNRPTPolicy()

	// Step 2: Flush the DNS cache so stale entries from pre-NRPT resolution are cleared.
	if err := dnsapiDLL.Load(); err == nil {
		if err := procDnsFlushResolverCache.Find(); err == nil {
			ret, _, _ := procDnsFlushResolverCache.Call()
			if ret != 0 {
				mainLog.Load().Debug().Msg("DNS intercept: flushed DNS resolver cache via DnsFlushResolverCache")
				return
			}
		}
	}
	// Fallback: use ipconfig /flushdns.
	if out, err := exec.Command("ipconfig", "/flushdns").CombinedOutput(); err != nil {
		mainLog.Load().Debug().Msgf("DNS intercept: ipconfig /flushdns failed: %v: %s", err, string(out))
	} else {
		mainLog.Load().Debug().Msg("DNS intercept: flushed DNS resolver cache via ipconfig /flushdns")
	}
}

// startDNSIntercept activates WFP-based DNS interception on Windows.
// It creates a WFP sublayer and adds filters that block all outbound DNS (port 53)
// traffic except to localhost (127.0.0.1/::1), ensuring all DNS queries must go
// through ctrld's local listener. This eliminates the race condition with VPN
// software that overwrites interface DNS settings.
//
// The approach:
//  1. Permit outbound DNS to 127.0.0.1/::1 (ctrld's listener)
//  2. Block all other outbound DNS (port 53 UDP+TCP)
//
// This means even if a VPN overwrites DNS settings to its own servers,
// the OS cannot reach those servers on port 53 — queries fail and fall back
// to ctrld via the loopback address.
func (p *prog) startDNSIntercept() error {
	// Resolve the actual listener IP. On AD DC / Windows Server with a local DNS
	// server, ctrld may have fallen back to 127.0.0.x:53 instead of 127.0.0.1:53.
	// NRPT must point to whichever address ctrld is actually listening on.
	listenerIP := "127.0.0.1"
	if lc := p.cfg.FirstListener(); lc != nil && lc.IP != "" && lc.IP != "0.0.0.0" && lc.IP != "::" {
		listenerIP = lc.IP
	} else if lc != nil && (lc.IP == "0.0.0.0" || lc.IP == "::") {
		mainLog.Load().Warn().Str("configured_ip", lc.IP).
			Msg("DNS intercept: listener configured with wildcard IP, using 127.0.0.1 for NRPT rules")
	}

	state := &wfpState{
		stopCh:     make(chan struct{}),
		listenerIP: listenerIP,
	}

	// Step 1: Add NRPT catch-all rule (both dns and hard modes).
	// NRPT must succeed before proceeding with WFP in hard mode.
	mainLog.Load().Info().Msgf("DNS intercept: initializing (mode: %s)", interceptMode)
	logNRPTParentKeyState("pre-write")

	// Two-phase empty parent key recovery: if the GP DnsPolicyConfig key exists
	// but is empty, DNS Client has cached a "no rules" state and won't accept
	// new rules even after they're written. Delete the empty key and signal DNS
	// Client to reset before writing our rule.
	// Two-phase recovery handles its own 2s signaling burst internally.
	cleanEmptyNRPTParent()

	if err := addNRPTCatchAllRule(listenerIP); err != nil {
		return fmt.Errorf("dns intercept: failed to add NRPT catch-all rule: %w", err)
	}
	logNRPTParentKeyState("post-write")
	state.nrptActive = true
	refreshNRPTPolicy()
	sendParamChange()
	flushDNSCache()
	mainLog.Load().Info().Msgf("DNS intercept: NRPT catch-all rule active — all DNS queries directed to %s", listenerIP)

	// Step 2: In hard mode, also set up WFP filters to block non-local DNS.
	if hardIntercept {
		if err := p.startWFPFilters(state); err != nil {
			// Roll back NRPT since WFP failed.
			mainLog.Load().Error().Err(err).Msg("DNS intercept: WFP setup failed, rolling back NRPT")
			_ = removeNRPTCatchAllRule()
			flushDNSCache()
			state.nrptActive = false
			return fmt.Errorf("dns intercept: WFP setup failed: %w", err)
		}
	} else {
		mainLog.Load().Info().Msg("DNS intercept: dns mode — NRPT only, no WFP filters (graceful)")
	}

	p.dnsInterceptState = state

	// Start periodic NRPT health monitor.
	go p.nrptHealthMonitor(state)

	// Verify NRPT is actually working (async — doesn't block startup).
	// This catches the race condition where RefreshPolicyEx returns before
	// the DNS Client service has loaded the NRPT rule from registry.
	go p.nrptProbeAndHeal()

	return nil
}

// startWFPFilters opens the WFP engine and adds all block/permit filters.
// Called only in hard intercept mode.
func (p *prog) startWFPFilters(state *wfpState) error {
	mainLog.Load().Info().Msg("DNS intercept: initializing Windows Filtering Platform (WFP)")

	var engineHandle uintptr
	session := fwpmSession0{}
	sessionName, _ := windows.UTF16PtrFromString("ctrld DNS Intercept")
	session.displayData.name = sessionName

	// RPC_C_AUTHN_DEFAULT (0xFFFFFFFF) lets the system pick the appropriate
	// authentication service. RPC_C_AUTHN_NONE (0) returns ERROR_NOT_SUPPORTED
	// on some Windows configurations (e.g., Parallels VMs).
	const rpcCAuthnDefault = 0xFFFFFFFF
	r1, _, _ := procFwpmEngineOpen0.Call(
		0,
		uintptr(rpcCAuthnDefault),
		0,
		uintptr(unsafe.Pointer(&session)),
		uintptr(unsafe.Pointer(&engineHandle)),
	)
	if r1 != 0 {
		return fmt.Errorf("FwpmEngineOpen0 failed: HRESULT 0x%x", r1)
	}
	mainLog.Load().Info().Msgf("DNS intercept: WFP engine opened (handle: 0x%x)", engineHandle)

	// Clean up any stale sublayer from a previous unclean shutdown.
	// If ctrld crashed or was killed, the non-dynamic WFP session may have left
	// orphaned filters. Deleting the sublayer removes all its child filters.
	r1, _, _ = procFwpmSubLayerDeleteByKey0.Call(
		engineHandle,
		uintptr(unsafe.Pointer(&ctrldSubLayerGUID)),
	)
	if r1 == 0 {
		mainLog.Load().Info().Msg("DNS intercept: cleaned up stale WFP sublayer from previous session")
	}
	// r1 != 0 means sublayer didn't exist — that's fine, nothing to clean up.

	sublayer := fwpmSublayer0{
		subLayerKey: ctrldSubLayerGUID,
		weight:      0xFFFF,
	}
	sublayerName, _ := windows.UTF16PtrFromString("ctrld DNS Intercept Sublayer")
	sublayerDesc, _ := windows.UTF16PtrFromString("Blocks outbound DNS except to ctrld listener. Prevents VPN DNS conflicts.")
	sublayer.displayData.name = sublayerName
	sublayer.displayData.description = sublayerDesc

	r1, _, _ = procFwpmSubLayerAdd0.Call(
		engineHandle,
		uintptr(unsafe.Pointer(&sublayer)),
		0,
	)
	if r1 != 0 {
		procFwpmEngineClose0.Call(engineHandle)
		return fmt.Errorf("FwpmSubLayerAdd0 failed: HRESULT 0x%x", r1)
	}
	mainLog.Load().Info().Msg("DNS intercept: WFP sublayer created (weight: 0xFFFF — maximum priority)")

	state.engineHandle = engineHandle

	permitFilters := []struct {
		name    string
		layer   windows.GUID
		proto   uint8
		idField *uint64
	}{
		{"Permit DNS to localhost (IPv4/UDP)", fwpmLayerALEAuthConnectV4, ipprotoUDP, &state.permitIDv4UDP},
		{"Permit DNS to localhost (IPv4/TCP)", fwpmLayerALEAuthConnectV4, ipprotoTCP, &state.permitIDv4TCP},
		{"Permit DNS to localhost (IPv6/UDP)", fwpmLayerALEAuthConnectV6, ipprotoUDP, &state.permitIDv6UDP},
		{"Permit DNS to localhost (IPv6/TCP)", fwpmLayerALEAuthConnectV6, ipprotoTCP, &state.permitIDv6TCP},
	}

	for _, pf := range permitFilters {
		filterID, err := p.addWFPPermitLocalhostFilter(engineHandle, pf.name, pf.layer, pf.proto)
		if err != nil {
			p.cleanupWFPFilters(state)
			return fmt.Errorf("failed to add permit filter %q: %w", pf.name, err)
		}
		*pf.idField = filterID
		mainLog.Load().Debug().Msgf("DNS intercept: added permit filter %q (ID: %d)", pf.name, filterID)
	}

	blockFilters := []struct {
		name    string
		layer   windows.GUID
		proto   uint8
		idField *uint64
	}{
		{"Block outbound DNS (IPv4/UDP)", fwpmLayerALEAuthConnectV4, ipprotoUDP, &state.filterIDv4UDP},
		{"Block outbound DNS (IPv4/TCP)", fwpmLayerALEAuthConnectV4, ipprotoTCP, &state.filterIDv4TCP},
		{"Block outbound DNS (IPv6/UDP)", fwpmLayerALEAuthConnectV6, ipprotoUDP, &state.filterIDv6UDP},
		{"Block outbound DNS (IPv6/TCP)", fwpmLayerALEAuthConnectV6, ipprotoTCP, &state.filterIDv6TCP},
	}

	for _, bf := range blockFilters {
		filterID, err := p.addWFPBlockDNSFilter(engineHandle, bf.name, bf.layer, bf.proto)
		if err != nil {
			p.cleanupWFPFilters(state)
			return fmt.Errorf("failed to add block filter %q: %w", bf.name, err)
		}
		*bf.idField = filterID
		mainLog.Load().Debug().Msgf("DNS intercept: added block filter %q (ID: %d)", bf.name, filterID)
	}

	// Add static permit filters for RFC1918 + CGNAT ranges (UDP + TCP).
	// This allows VPN DNS servers on private IPs (MagicDNS upstreams, F5, Windscribe, etc.)
	// to work without dynamic per-server exemptions.
	privateRanges := []struct {
		name string
		addr uint32 // host byte order
		mask uint32 // host byte order
	}{
		{"10.0.0.0/8", 0x0A000000, 0xFF000000},
		{"172.16.0.0/12", 0xAC100000, 0xFFF00000},
		{"192.168.0.0/16", 0xC0A80000, 0xFFFF0000},
		{"100.64.0.0/10", 0x64400000, 0xFFC00000}, // CGNAT (includes Tailscale)
	}
	for _, r := range privateRanges {
		for _, proto := range []struct {
			num  uint8
			name string
		}{{ipprotoUDP, "UDP"}, {ipprotoTCP, "TCP"}} {
			filterName := fmt.Sprintf("Permit DNS to %s (%s)", r.name, proto.name)
			filterID, err := p.addWFPPermitSubnetFilter(engineHandle, filterName, proto.num, r.addr, r.mask)
			if err != nil {
				mainLog.Load().Warn().Err(err).Msgf("DNS intercept: failed to add subnet permit for %s/%s", r.name, proto.name)
				continue
			}
			state.subnetPermitFilterIDs = append(state.subnetPermitFilterIDs, filterID)
			mainLog.Load().Debug().Msgf("DNS intercept: added subnet permit %q (ID: %d)", filterName, filterID)
		}
	}
	mainLog.Load().Info().Msgf("DNS intercept: %d subnet permit filters active (RFC1918 + CGNAT)", len(state.subnetPermitFilterIDs))

	mainLog.Load().Info().Msgf("DNS intercept: WFP filters active — all outbound DNS (port 53) blocked except to localhost and private ranges. "+
		"Filter IDs: v4UDP=%d, v4TCP=%d, v6UDP=%d, v6TCP=%d (block), "+
		"v4UDP=%d, v4TCP=%d, v6UDP=%d, v6TCP=%d (permit localhost)",
		state.filterIDv4UDP, state.filterIDv4TCP, state.filterIDv6UDP, state.filterIDv6TCP,
		state.permitIDv4UDP, state.permitIDv4TCP, state.permitIDv6UDP, state.permitIDv6TCP)

	return nil
}

// addWFPBlockDNSFilter adds a WFP filter that blocks outbound DNS traffic (port 53)
// for the given protocol (UDP or TCP) on the specified layer (V4 or V6).
func (p *prog) addWFPBlockDNSFilter(engineHandle uintptr, name string, layerKey windows.GUID, proto uint8) (uint64, error) {
	filterName, _ := windows.UTF16PtrFromString("ctrld: " + name)

	conditions := make([]fwpmFilterCondition0, 2)

	conditions[0] = fwpmFilterCondition0{
		fieldKey:  fwpmConditionIPProtocol,
		matchType: fwpMatchEqual,
	}
	conditions[0].condValue.valueType = fwpUint8
	conditions[0].condValue.value = uint64(proto)

	conditions[1] = fwpmFilterCondition0{
		fieldKey:  fwpmConditionIPRemotePort,
		matchType: fwpMatchEqual,
	}
	conditions[1].condValue.valueType = fwpUint16
	conditions[1].condValue.value = uint64(dnsPort)

	filter := fwpmFilter0{
		layerKey:        layerKey,
		subLayerKey:     ctrldSubLayerGUID,
		numFilterConds:  2,
		filterCondition: &conditions[0],
	}
	filter.displayData.name = filterName
	filter.weight.valueType = fwpUint8
	filter.weight.value = 1
	filter.action.actionType = fwpActionBlock

	var filterID uint64
	r1, _, _ := procFwpmFilterAdd0.Call(
		engineHandle,
		uintptr(unsafe.Pointer(&filter)),
		0,
		uintptr(unsafe.Pointer(&filterID)),
	)
	runtime.KeepAlive(conditions)
	if r1 != 0 {
		return 0, fmt.Errorf("FwpmFilterAdd0 failed: HRESULT 0x%x", r1)
	}
	return filterID, nil
}

// addWFPPermitLocalhostFilter adds a WFP filter that permits outbound DNS to localhost.
// This ensures ctrld's listener at 127.0.0.1/::1 can receive DNS queries.
//
// TODO: On AD DC where ctrld listens on 127.0.0.x, this filter should match
// the actual listener IP instead of hardcoded 127.0.0.1. Currently hard mode
// is unlikely on AD DC (NRPT dns mode is preferred), but if needed, this must
// be parameterized like addNRPTCatchAllRule.
// These filters have higher weight than block filters so they're matched first.
func (p *prog) addWFPPermitLocalhostFilter(engineHandle uintptr, name string, layerKey windows.GUID, proto uint8) (uint64, error) {
	filterName, _ := windows.UTF16PtrFromString("ctrld: " + name)

	ipv6Loopback := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}

	conditions := make([]fwpmFilterCondition0, 3)

	conditions[0] = fwpmFilterCondition0{
		fieldKey:  fwpmConditionIPProtocol,
		matchType: fwpMatchEqual,
	}
	conditions[0].condValue.valueType = fwpUint8
	conditions[0].condValue.value = uint64(proto)

	conditions[1] = fwpmFilterCondition0{
		fieldKey:  fwpmConditionIPRemotePort,
		matchType: fwpMatchEqual,
	}
	conditions[1].condValue.valueType = fwpUint16
	conditions[1].condValue.value = uint64(dnsPort)

	conditions[2] = fwpmFilterCondition0{
		fieldKey:  fwpmConditionIPRemoteAddress,
		matchType: fwpMatchEqual,
	}
	if layerKey == fwpmLayerALEAuthConnectV4 {
		conditions[2].condValue.valueType = fwpUint32
		conditions[2].condValue.value = 0x7F000001
	} else {
		conditions[2].condValue.valueType = fwpByteArray16Type
		conditions[2].condValue.value = uint64(uintptr(unsafe.Pointer(&ipv6Loopback)))
	}

	filter := fwpmFilter0{
		layerKey:        layerKey,
		subLayerKey:     ctrldSubLayerGUID,
		numFilterConds:  3,
		filterCondition: &conditions[0],
	}
	filter.displayData.name = filterName
	filter.weight.valueType = fwpUint8
	filter.weight.value = 10
	filter.action.actionType = fwpActionPermit

	var filterID uint64
	r1, _, _ := procFwpmFilterAdd0.Call(
		engineHandle,
		uintptr(unsafe.Pointer(&filter)),
		0,
		uintptr(unsafe.Pointer(&filterID)),
	)
	runtime.KeepAlive(&ipv6Loopback)
	runtime.KeepAlive(conditions)
	if r1 != 0 {
		return 0, fmt.Errorf("FwpmFilterAdd0 failed: HRESULT 0x%x", r1)
	}
	return filterID, nil
}

// addWFPPermitSubnetFilter adds a WFP filter that permits outbound DNS to a given
// IPv4 subnet (addr/mask in host byte order). Used to exempt RFC1918 and CGNAT ranges
// so VPN DNS servers on private IPs are not blocked.
func (p *prog) addWFPPermitSubnetFilter(engineHandle uintptr, name string, proto uint8, addr, mask uint32) (uint64, error) {
	filterName, _ := windows.UTF16PtrFromString("ctrld: " + name)

	addrMask := fwpV4AddrAndMask{addr: addr, mask: mask}

	conditions := make([]fwpmFilterCondition0, 3)

	conditions[0] = fwpmFilterCondition0{
		fieldKey:  fwpmConditionIPProtocol,
		matchType: fwpMatchEqual,
	}
	conditions[0].condValue.valueType = fwpUint8
	conditions[0].condValue.value = uint64(proto)

	conditions[1] = fwpmFilterCondition0{
		fieldKey:  fwpmConditionIPRemotePort,
		matchType: fwpMatchEqual,
	}
	conditions[1].condValue.valueType = fwpUint16
	conditions[1].condValue.value = uint64(dnsPort)

	conditions[2] = fwpmFilterCondition0{
		fieldKey:  fwpmConditionIPRemoteAddress,
		matchType: fwpMatchEqual,
	}
	conditions[2].condValue.valueType = fwpV4AddrMask
	conditions[2].condValue.value = uint64(uintptr(unsafe.Pointer(&addrMask)))

	filter := fwpmFilter0{
		layerKey:        fwpmLayerALEAuthConnectV4,
		subLayerKey:     ctrldSubLayerGUID,
		numFilterConds:  3,
		filterCondition: &conditions[0],
	}
	filter.displayData.name = filterName
	filter.weight.valueType = fwpUint8
	filter.weight.value = 10
	filter.action.actionType = fwpActionPermit

	var filterID uint64
	r1, _, _ := procFwpmFilterAdd0.Call(
		engineHandle,
		uintptr(unsafe.Pointer(&filter)),
		0,
		uintptr(unsafe.Pointer(&filterID)),
	)
	runtime.KeepAlive(&addrMask)
	runtime.KeepAlive(conditions)
	if r1 != 0 {
		return 0, fmt.Errorf("FwpmFilterAdd0 failed: HRESULT 0x%x", r1)
	}
	return filterID, nil
}

// wfpSublayerExists checks whether our WFP sublayer still exists in the engine.
// Used by the watchdog to detect if another program removed our filters.
func wfpSublayerExists(engineHandle uintptr) bool {
	var sublayerPtr uintptr
	r1, _, _ := procFwpmSubLayerGetByKey0.Call(
		engineHandle,
		uintptr(unsafe.Pointer(&ctrldSubLayerGUID)),
		uintptr(unsafe.Pointer(&sublayerPtr)),
	)
	if r1 != 0 {
		return false
	}
	// Free the returned sublayer struct.
	if sublayerPtr != 0 {
		procFwpmFreeMemory0.Call(uintptr(unsafe.Pointer(&sublayerPtr)))
	}
	return true
}

// cleanupWFPFilters removes all WFP filters and the sublayer, then closes the engine.
// It logs each step and continues cleanup even if individual removals fail,
// to ensure maximum cleanup on shutdown.
func (p *prog) cleanupWFPFilters(state *wfpState) {
	if state == nil || state.engineHandle == 0 {
		return
	}

	for _, filterID := range state.vpnPermitFilterIDs {
		r1, _, _ := procFwpmFilterDeleteById0.Call(state.engineHandle, uintptr(filterID))
		if r1 != 0 {
			mainLog.Load().Warn().Msgf("DNS intercept: failed to remove VPN permit filter (ID: %d, code: 0x%x)", filterID, r1)
		} else {
			mainLog.Load().Debug().Msgf("DNS intercept: removed VPN permit filter (ID: %d)", filterID)
		}
	}

	for _, filterID := range state.subnetPermitFilterIDs {
		r1, _, _ := procFwpmFilterDeleteById0.Call(state.engineHandle, uintptr(filterID))
		if r1 != 0 {
			mainLog.Load().Warn().Msgf("DNS intercept: failed to remove subnet permit filter (ID: %d, code: 0x%x)", filterID, r1)
		} else {
			mainLog.Load().Debug().Msgf("DNS intercept: removed subnet permit filter (ID: %d)", filterID)
		}
	}

	filterIDs := []struct {
		name string
		id   uint64
	}{
		{"permit v4 UDP", state.permitIDv4UDP},
		{"permit v4 TCP", state.permitIDv4TCP},
		{"permit v6 UDP", state.permitIDv6UDP},
		{"permit v6 TCP", state.permitIDv6TCP},
		{"block v4 UDP", state.filterIDv4UDP},
		{"block v4 TCP", state.filterIDv4TCP},
		{"block v6 UDP", state.filterIDv6UDP},
		{"block v6 TCP", state.filterIDv6TCP},
	}

	for _, f := range filterIDs {
		if f.id == 0 {
			continue
		}
		r1, _, _ := procFwpmFilterDeleteById0.Call(state.engineHandle, uintptr(f.id))
		if r1 != 0 {
			mainLog.Load().Warn().Msgf("DNS intercept: failed to remove WFP filter %q (ID: %d, code: 0x%x)", f.name, f.id, r1)
		} else {
			mainLog.Load().Debug().Msgf("DNS intercept: removed WFP filter %q (ID: %d)", f.name, f.id)
		}
	}

	r1, _, _ := procFwpmSubLayerDeleteByKey0.Call(
		state.engineHandle,
		uintptr(unsafe.Pointer(&ctrldSubLayerGUID)),
	)
	if r1 != 0 {
		mainLog.Load().Warn().Msgf("DNS intercept: failed to remove WFP sublayer (code: 0x%x)", r1)
	} else {
		mainLog.Load().Debug().Msg("DNS intercept: removed WFP sublayer")
	}

	r1, _, _ = procFwpmEngineClose0.Call(state.engineHandle)
	if r1 != 0 {
		mainLog.Load().Warn().Msgf("DNS intercept: failed to close WFP engine (code: 0x%x)", r1)
	} else {
		mainLog.Load().Debug().Msg("DNS intercept: WFP engine closed")
	}
}

// stopDNSIntercept removes all WFP filters and shuts down the DNS interception.
func (p *prog) stopDNSIntercept() error {
	if p.dnsInterceptState == nil {
		mainLog.Load().Debug().Msg("DNS intercept: no state to clean up")
		return nil
	}

	state := p.dnsInterceptState.(*wfpState)

	// Stop the health monitor goroutine.
	if state.stopCh != nil {
		close(state.stopCh)
	}

	// Remove NRPT rule BEFORE WFP cleanup — restore normal DNS resolution
	// before removing the block filters that enforce it.
	if state.nrptActive {
		if err := removeNRPTCatchAllRule(); err != nil {
			mainLog.Load().Warn().Err(err).Msg("DNS intercept: failed to remove NRPT catch-all rule")
		} else {
			mainLog.Load().Info().Msg("DNS intercept: removed NRPT catch-all rule")
		}
		flushDNSCache()
		state.nrptActive = false
	}

	// Only clean up WFP if we actually opened the engine (hard mode).
	if state.engineHandle != 0 {
		mainLog.Load().Info().Msg("DNS intercept: shutting down WFP filters")
		p.cleanupWFPFilters(state)
		mainLog.Load().Info().Msg("DNS intercept: WFP shutdown complete")
	}

	p.dnsInterceptState = nil
	mainLog.Load().Info().Msg("DNS intercept: shutdown complete")
	return nil
}

// dnsInterceptSupported reports whether DNS intercept mode is supported on this platform.
func dnsInterceptSupported() bool {
	if err := fwpuclntDLL.Load(); err != nil {
		return false
	}
	return true
}

// validateDNSIntercept checks that the system meets requirements for DNS intercept mode.
func (p *prog) validateDNSIntercept() error {
	// Hard mode requires WFP and elevation for filter management.
	if hardIntercept {
		if !dnsInterceptSupported() {
			return fmt.Errorf("dns intercept: fwpuclnt.dll not available — WFP requires Windows Vista or later")
		}
		if !isElevated() {
			return fmt.Errorf("dns intercept: administrator privileges required for WFP filter management in hard mode")
		}
	}
	// dns mode only needs NRPT (HKLM registry writes), which services can do
	// without explicit elevation checks.
	return nil
}

// isElevated checks if the current process has administrator privileges.
func isElevated() bool {
	token := windows.GetCurrentProcessToken()
	return token.IsElevated()
}

// exemptVPNDNSServers updates the WFP filters to permit outbound DNS to the given
// VPN DNS server IPs. This prevents the block filters from intercepting ctrld's own
// forwarded queries to VPN DNS servers (split DNS routing).
//
// The function is idempotent: it first removes ALL existing VPN permit filters,
// then adds new ones for the current server list. When called with nil/empty
// servers (VPN disconnected), it just removes the old permits — leaving only
// the localhost permits and block-all filters active.
//
// Supports both IPv4 and IPv6 VPN DNS servers.
//
// Called by vpnDNSManager.onServersChanged() whenever VPN DNS servers change.
func (p *prog) exemptVPNDNSServers(exemptions []vpnDNSExemption) error {
	state, ok := p.dnsInterceptState.(*wfpState)
	if !ok || state == nil {
		return fmt.Errorf("DNS intercept state not available")
	}
	// In dns mode (no WFP), VPN DNS exemptions are not needed — there are no
	// block filters to exempt from.
	if state.engineHandle == 0 {
		mainLog.Load().Debug().Msg("DNS intercept: dns mode — skipping VPN DNS exemptions (no WFP filters)")
		return nil
	}

	for _, filterID := range state.vpnPermitFilterIDs {
		r1, _, _ := procFwpmFilterDeleteById0.Call(state.engineHandle, uintptr(filterID))
		if r1 != 0 {
			mainLog.Load().Warn().Msgf("DNS intercept: failed to remove old VPN permit filter (ID: %d, code: 0x%x)", filterID, r1)
		}
	}
	state.vpnPermitFilterIDs = nil

	// Extract unique server IPs (WFP doesn't need interface info).
	seen := make(map[string]bool)
	var servers []string
	for _, ex := range exemptions {
		if !seen[ex.Server] {
			seen[ex.Server] = true
			servers = append(servers, ex.Server)
		}
	}

	for _, server := range servers {
		ipv4 := parseIPv4AsUint32(server)
		isIPv6 := ipv4 == 0

		for _, proto := range []uint8{ipprotoUDP, ipprotoTCP} {
			protoName := "UDP"
			if proto == ipprotoTCP {
				protoName = "TCP"
			}
			filterName := fmt.Sprintf("ctrld: Permit VPN DNS to %s (%s)", server, protoName)

			var filterID uint64
			var err error
			if isIPv6 {
				ipv6Bytes := parseIPv6AsBytes(server)
				if ipv6Bytes == nil {
					mainLog.Load().Warn().Msgf("DNS intercept: skipping invalid VPN DNS server: %s", server)
					continue
				}
				filterID, err = p.addWFPPermitIPv6Filter(state.engineHandle, filterName, fwpmLayerALEAuthConnectV6, proto, ipv6Bytes)
			} else {
				filterID, err = p.addWFPPermitIPFilter(state.engineHandle, filterName, fwpmLayerALEAuthConnectV4, proto, ipv4)
			}
			if err != nil {
				return fmt.Errorf("failed to add VPN DNS permit filter for %s/%s: %w", server, protoName, err)
			}
			state.vpnPermitFilterIDs = append(state.vpnPermitFilterIDs, filterID)
			mainLog.Load().Debug().Msgf("DNS intercept: added VPN DNS permit filter for %s/%s (ID: %d)", server, protoName, filterID)
		}
	}

	mainLog.Load().Info().Msgf("DNS intercept: exempted %d VPN DNS servers from WFP block (%d filters)", len(servers), len(state.vpnPermitFilterIDs))
	return nil
}

// addWFPPermitIPFilter adds a WFP permit filter for outbound DNS to a specific IPv4 address.
func (p *prog) addWFPPermitIPFilter(engineHandle uintptr, name string, layerKey windows.GUID, proto uint8, ipAddr uint32) (uint64, error) {
	filterName, _ := windows.UTF16PtrFromString(name)

	conditions := make([]fwpmFilterCondition0, 3)

	conditions[0] = fwpmFilterCondition0{
		fieldKey:  fwpmConditionIPProtocol,
		matchType: fwpMatchEqual,
	}
	conditions[0].condValue.valueType = fwpUint8
	conditions[0].condValue.value = uint64(proto)

	conditions[1] = fwpmFilterCondition0{
		fieldKey:  fwpmConditionIPRemotePort,
		matchType: fwpMatchEqual,
	}
	conditions[1].condValue.valueType = fwpUint16
	conditions[1].condValue.value = uint64(dnsPort)

	conditions[2] = fwpmFilterCondition0{
		fieldKey:  fwpmConditionIPRemoteAddress,
		matchType: fwpMatchEqual,
	}
	conditions[2].condValue.valueType = fwpUint32
	conditions[2].condValue.value = uint64(ipAddr)

	filter := fwpmFilter0{
		layerKey:        layerKey,
		subLayerKey:     ctrldSubLayerGUID,
		numFilterConds:  3,
		filterCondition: &conditions[0],
	}
	filter.displayData.name = filterName
	filter.weight.valueType = fwpUint8
	filter.weight.value = 10
	filter.action.actionType = fwpActionPermit

	var filterID uint64
	r1, _, _ := procFwpmFilterAdd0.Call(
		engineHandle,
		uintptr(unsafe.Pointer(&filter)),
		0,
		uintptr(unsafe.Pointer(&filterID)),
	)
	runtime.KeepAlive(conditions)
	if r1 != 0 {
		return 0, fmt.Errorf("FwpmFilterAdd0 failed: HRESULT 0x%x", r1)
	}
	return filterID, nil
}

// addWFPPermitIPv6Filter adds a WFP permit filter for outbound DNS to a specific IPv6 address.
func (p *prog) addWFPPermitIPv6Filter(engineHandle uintptr, name string, layerKey windows.GUID, proto uint8, ipAddr *[16]byte) (uint64, error) {
	filterName, _ := windows.UTF16PtrFromString(name)

	conditions := make([]fwpmFilterCondition0, 3)

	conditions[0] = fwpmFilterCondition0{
		fieldKey:  fwpmConditionIPProtocol,
		matchType: fwpMatchEqual,
	}
	conditions[0].condValue.valueType = fwpUint8
	conditions[0].condValue.value = uint64(proto)

	conditions[1] = fwpmFilterCondition0{
		fieldKey:  fwpmConditionIPRemotePort,
		matchType: fwpMatchEqual,
	}
	conditions[1].condValue.valueType = fwpUint16
	conditions[1].condValue.value = uint64(dnsPort)

	conditions[2] = fwpmFilterCondition0{
		fieldKey:  fwpmConditionIPRemoteAddress,
		matchType: fwpMatchEqual,
	}
	conditions[2].condValue.valueType = fwpByteArray16Type
	conditions[2].condValue.value = uint64(uintptr(unsafe.Pointer(ipAddr)))

	filter := fwpmFilter0{
		layerKey:        layerKey,
		subLayerKey:     ctrldSubLayerGUID,
		numFilterConds:  3,
		filterCondition: &conditions[0],
	}
	filter.displayData.name = filterName
	filter.weight.valueType = fwpUint8
	filter.weight.value = 10
	filter.action.actionType = fwpActionPermit

	var filterID uint64
	r1, _, _ := procFwpmFilterAdd0.Call(
		engineHandle,
		uintptr(unsafe.Pointer(&filter)),
		0,
		uintptr(unsafe.Pointer(&filterID)),
	)
	runtime.KeepAlive(ipAddr)
	runtime.KeepAlive(conditions)
	if r1 != 0 {
		return 0, fmt.Errorf("FwpmFilterAdd0 failed: HRESULT 0x%x", r1)
	}
	return filterID, nil
}

// parseIPv6AsBytes parses an IPv6 address string into a 16-byte array for WFP.
// Returns nil if the string is not a valid IPv6 address.
func parseIPv6AsBytes(ipStr string) *[16]byte {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil
	}
	ip = ip.To16()
	if ip == nil || ip.To4() != nil {
		// It's IPv4, not IPv6
		return nil
	}
	var result [16]byte
	copy(result[:], ip)
	return &result
}

// parseIPv4AsUint32 converts an IPv4 string to a uint32 in host byte order for WFP.
func parseIPv4AsUint32(ipStr string) uint32 {
	parts := [4]byte{}
	n := 0
	val := uint32(0)
	for i := 0; i < len(ipStr) && n < 4; i++ {
		if ipStr[i] == '.' {
			parts[n] = byte(val)
			n++
			val = 0
		} else if ipStr[i] >= '0' && ipStr[i] <= '9' {
			val = val*10 + uint32(ipStr[i]-'0')
		} else {
			return 0
		}
	}
	if n == 3 {
		parts[3] = byte(val)
		return uint32(parts[0])<<24 | uint32(parts[1])<<16 | uint32(parts[2])<<8 | uint32(parts[3])
	}
	return 0
}

// ensurePFAnchorActive is a no-op on Windows (WFP handles intercept differently).
func (p *prog) ensurePFAnchorActive() bool {
	return false
}

// pfAnchorIsWiped is a no-op on Windows (WFP handles intercept differently).
func (p *prog) pfAnchorIsWiped() bool {
	return false
}

// checkTunnelInterfaceChanges is a no-op on Windows (WFP handles intercept differently).
func (p *prog) checkTunnelInterfaceChanges() bool {
	return false
}

// pfAnchorRecheckDelay is the delay for deferred pf anchor re-checks.
// Defined here as a stub for Windows (referenced from dns_proxy.go).
const pfAnchorRecheckDelay = 2 * time.Second

// pfAnchorRecheckDelayLong is the longer delayed re-check for slower VPN teardowns.
const pfAnchorRecheckDelayLong = 4 * time.Second

// scheduleDelayedRechecks schedules delayed OS resolver and VPN DNS refreshes after
// network change events. While WFP filters don't get wiped like pf anchors, the OS
// resolver and VPN DNS state can still be stale after VPN disconnect (same issue as macOS).
func (p *prog) scheduleDelayedRechecks() {
	for _, delay := range []time.Duration{pfAnchorRecheckDelay, pfAnchorRecheckDelayLong} {
		time.AfterFunc(delay, func() {
			if p.dnsInterceptState == nil {
				return
			}
			// Refresh OS resolver — VPN may have finished DNS cleanup since the
			// immediate handler ran.
			ctrld.InitializeOsResolver(true)
			if p.vpnDNS != nil {
				p.vpnDNS.Refresh(true)
			}

			// NRPT watchdog: some VPN software clears NRPT policy rules on
			// connect/disconnect. Re-add our catch-all rule if it was removed.
			state, ok := p.dnsInterceptState.(*wfpState)
			if ok && state.nrptActive && !nrptCatchAllRuleExists() {
				mainLog.Load().Warn().Msg("DNS intercept: NRPT catch-all rule was removed externally — re-adding")
				if err := addNRPTCatchAllRule(state.listenerIP); err != nil {
					mainLog.Load().Error().Err(err).Msg("DNS intercept: failed to re-add NRPT catch-all rule")
					state.nrptActive = false
				} else {
					flushDNSCache()
					mainLog.Load().Info().Msg("DNS intercept: NRPT catch-all rule restored")
				}
			}

			// WFP watchdog: verify our sublayer still exists. If another program
			// or a crash removed it, the block filters are gone too.
			if ok && state.engineHandle != 0 && !wfpSublayerExists(state.engineHandle) {
				mainLog.Load().Warn().Msg("DNS intercept: WFP sublayer was removed externally — re-creating all filters")
				// Full teardown + re-init. stopDNSIntercept clears state,
				// then startDNSIntercept creates everything fresh.
				_ = p.stopDNSIntercept()
				if err := p.startDNSIntercept(); err != nil {
					mainLog.Load().Error().Err(err).Msg("DNS intercept: failed to re-create WFP filters")
				}
			}
		})
	}
}

// nrptHealthMonitor periodically checks that the NRPT catch-all rule is still
// present and re-adds it if removed by VPN software or Group Policy updates.
// In hard mode, it also verifies the WFP sublayer exists and re-initializes
// all filters if they were removed.
func (p *prog) nrptHealthMonitor(state *wfpState) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-state.stopCh:
			return
		case <-ticker.C:
			if !state.nrptActive {
				continue
			}

			// Step 1: Check registry key exists.
			if !nrptCatchAllRuleExists() {
				mainLog.Load().Warn().Msg("DNS intercept: NRPT health check — catch-all rule missing, restoring")
				if err := addNRPTCatchAllRule(state.listenerIP); err != nil {
					mainLog.Load().Error().Err(err).Msg("DNS intercept: failed to restore NRPT catch-all rule")
					state.nrptActive = false
					continue
				}
				refreshNRPTPolicy()
				flushDNSCache()
				mainLog.Load().Info().Msg("DNS intercept: NRPT catch-all rule restored by health monitor")
				// After restoring, verify it's actually working.
				go p.nrptProbeAndHeal()
				continue
			}

			// Step 2: Registry key exists — verify NRPT is actually routing
			// queries to ctrld (catches the async GP refresh race).
			if !p.probeNRPT() {
				mainLog.Load().Warn().Msg("DNS intercept: NRPT health check — rule present but probe failed, running heal cycle")
				go p.nrptProbeAndHeal()
			}

			// Step 3: In hard mode, also verify WFP sublayer.
			if state.engineHandle != 0 && !wfpSublayerExists(state.engineHandle) {
				mainLog.Load().Warn().Msg("DNS intercept: WFP health check — sublayer missing, re-initializing all filters")
				_ = p.stopDNSIntercept()
				if err := p.startDNSIntercept(); err != nil {
					mainLog.Load().Error().Err(err).Msg("DNS intercept: failed to re-initialize after WFP sublayer loss")
				} else {
					mainLog.Load().Info().Msg("DNS intercept: WFP filters restored by health monitor")
				}
				return // stopDNSIntercept closed our stopCh; startDNSIntercept started a new monitor
			}
		}
	}
}

// pfInterceptMonitor is a no-op on Windows — WFP filters are kernel objects
// and don't suffer from the pf translation state corruption that macOS has.
func (p *prog) pfInterceptMonitor() {}

const (
	// nrptProbeDomain is the suffix used for NRPT verification probe queries.
	// Probes use "_nrpt-probe-<hex>.<nrptProbeDomain>" — ctrld recognizes the
	// prefix in the DNS handler and responds immediately without upstream forwarding.
	nrptProbeDomain = "nrpt-probe.ctrld.test"

	// nrptProbeTimeout is how long to wait for a single probe query to arrive.
	nrptProbeTimeout = 2 * time.Second
)

// nrptProbeRunning ensures only one NRPT probe sequence runs at a time.
// Prevents the health monitor and startup from overlapping.
var nrptProbeRunning atomic.Bool

// probeNRPT tests whether the NRPT catch-all rule is actually routing DNS queries
// to ctrld's listener. It sends a DNS query for a synthetic probe domain through
// the Windows DNS Client service (via Go's net.Resolver / GetAddrInfoW). If ctrld
// receives the query on its listener, NRPT is working.
//
// Returns true if NRPT is verified working, false if the probe timed out.
func (p *prog) probeNRPT() bool {
	if p.dnsInterceptState == nil {
		return true
	}

	// Generate unique probe domain to defeat DNS caching.
	probeID := fmt.Sprintf("_nrpt-probe-%x.%s", rand.Uint32(), nrptProbeDomain)

	// Register probe so DNS handler can detect and signal it.
	// Reuse the same mechanism as macOS pf probes (pfProbeExpected/pfProbeCh).
	probeCh := make(chan struct{}, 1)
	p.pfProbeExpected.Store(probeID)
	p.pfProbeCh.Store(&probeCh)
	defer func() {
		p.pfProbeExpected.Store("")
		p.pfProbeCh.Store((*chan struct{})(nil))
	}()

	mainLog.Load().Debug().Str("domain", probeID).Msg("DNS intercept: sending NRPT verification probe")

	// Use Go's default resolver which calls GetAddrInfoW → DNS Client service → NRPT.
	// If NRPT is active, the DNS Client routes this to 127.0.0.1 → ctrld receives it.
	// If NRPT isn't loaded, the query goes to interface DNS → times out or NXDOMAIN.
	ctx, cancel := context.WithTimeout(context.Background(), nrptProbeTimeout)
	defer cancel()

	go func() {
		resolver := &net.Resolver{}
		// We don't care about the result — only whether ctrld's handler receives it.
		_, _ = resolver.LookupHost(ctx, probeID)
	}()

	select {
	case <-probeCh:
		mainLog.Load().Debug().Str("domain", probeID).Msg("DNS intercept: NRPT probe received — interception verified")
		return true
	case <-ctx.Done():
		mainLog.Load().Debug().Str("domain", probeID).Msg("DNS intercept: NRPT probe timed out — interception not working")
		return false
	}
}

// sendParamChange sends SERVICE_CONTROL_PARAMCHANGE to the DNS Client (Dnscache)
// service, signaling it to re-read its configuration including NRPT rules from
// the registry. This is the standard mechanism used by FortiClient, Tailscale,
// and other DNS-aware software — it's reliable and non-disruptive unlike
// restarting the Dnscache service (which always fails on modern Windows because
// Dnscache is a protected shared svchost service).
func sendParamChange() {
	if out, err := exec.Command("sc", "control", "dnscache", "paramchange").CombinedOutput(); err != nil {
		mainLog.Load().Debug().Err(err).Str("output", string(out)).Msg("DNS intercept: sc control dnscache paramchange failed")
	} else {
		mainLog.Load().Debug().Msg("DNS intercept: sent paramchange to Dnscache service")
	}
}

// cleanEmptyNRPTParent removes empty NRPT parent keys that block activation.
// An empty DnsPolicyConfig key (exists but no subkeys) causes DNS Client to
// cache "no rules" and ignore subsequently-added rules.
//
// Also cleans the GP path entirely if it has no non-ctrld rules, since the GP
// path's existence forces DNS Client into "GP mode" where it ignores the local
// service store path.
//
// Returns true if cleanup was performed (caller should add a delay).
func cleanEmptyNRPTParent() bool {
	cleaned := false

	// Always clean the GP path — its existence blocks local path activation.
	cleanGPPath()

	// Clean empty local/direct path parent key.
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, nrptDirectKey, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return false
	}
	names, err := k.ReadSubKeyNames(-1)
	k.Close()
	if err != nil || len(names) > 0 {
		return false
	}

	mainLog.Load().Warn().Msg("DNS intercept: found empty NRPT local parent key (blocks activation) — removing")
	if err := registry.DeleteKey(registry.LOCAL_MACHINE, nrptDirectKey); err != nil {
		mainLog.Load().Warn().Err(err).Msg("DNS intercept: failed to delete empty NRPT local parent key")
		return false
	}
	cleaned = true

	// Signal DNS Client to process the deletion and reset its internal cache.
	mainLog.Load().Info().Msg("DNS intercept: empty NRPT parent key removed — signaling DNS Client")
	sendParamChange()
	flushDNSCache()
	return cleaned
}

// logNRPTParentKeyState logs the state of both NRPT registry paths for diagnostics.
func logNRPTParentKeyState(context string) {
	for _, path := range []struct {
		name string
		key  string
	}{
		{"GP", nrptBaseKey},
		{"local", nrptDirectKey},
	} {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, path.key, registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			mainLog.Load().Debug().Str("context", context).Str("path", path.name).
				Msg("DNS intercept: NRPT parent key does not exist")
			continue
		}
		names, err := k.ReadSubKeyNames(-1)
		k.Close()
		if err != nil {
			continue
		}
		if len(names) == 0 {
			mainLog.Load().Warn().Str("context", context).Str("path", path.name).
				Msg("DNS intercept: NRPT parent key exists but is EMPTY — blocks activation")
		} else {
			mainLog.Load().Debug().Str("context", context).Str("path", path.name).
				Int("subkeys", len(names)).Strs("names", names).
				Msg("DNS intercept: NRPT parent key state")
		}
	}
}

// nrptProbeAndHeal runs the NRPT probe with retries and escalating remediation.
// Called asynchronously after startup and from the health monitor.
//
// Retry sequence (each attempt: GP refresh + paramchange + flush → sleep → probe):
//  1. Immediate probe
//  2. GP refresh + paramchange + flush → 1s → probe
//  3. GP refresh + paramchange + flush → 2s → probe
//  4. GP refresh + paramchange + flush → 4s → probe
func (p *prog) nrptProbeAndHeal() {
	if !nrptProbeRunning.CompareAndSwap(false, true) {
		mainLog.Load().Debug().Msg("DNS intercept: NRPT probe already running, skipping")
		return
	}
	defer nrptProbeRunning.Store(false)

	mainLog.Load().Info().Msg("DNS intercept: starting NRPT verification probe sequence")

	// Log parent key state for diagnostics.
	logNRPTParentKeyState("probe-start")

	// Attempt 1: immediate probe
	if p.probeNRPT() {
		mainLog.Load().Info().Msg("DNS intercept: NRPT verified working")
		return
	}

	// Attempts 2-4: GP refresh + paramchange + flush with increasing backoff
	delays := []time.Duration{1 * time.Second, 2 * time.Second, 4 * time.Second}
	for i, delay := range delays {
		attempt := i + 2
		mainLog.Load().Info().Int("attempt", attempt).Dur("delay", delay).
			Msg("DNS intercept: NRPT probe failed, retrying with GP refresh + paramchange")
		logNRPTParentKeyState(fmt.Sprintf("probe-attempt-%d", attempt))
		refreshNRPTPolicy()
		sendParamChange()
		flushDNSCache()
		time.Sleep(delay)
		if p.probeNRPT() {
			mainLog.Load().Info().Int("attempt", attempt).
				Msg("DNS intercept: NRPT verified working")
			return
		}
	}

	// Nuclear option: two-phase delete → re-add cycle.
	// DNS Client may have cached a stale "no rules" state. Delete our rule,
	// signal DNS Client to forget it, wait, then re-add and signal again.
	mainLog.Load().Warn().Msg("DNS intercept: all probes failed — attempting two-phase NRPT recovery (delete → signal → re-add)")
	listenerIP := "127.0.0.1"
	if state, ok := p.dnsInterceptState.(*wfpState); ok {
		listenerIP = state.listenerIP
	}

	// Phase 1: Remove our rule and the parent key if now empty.
	_ = removeNRPTCatchAllRule()
	// If parent key is now empty after removing our rule, delete it too.
	cleanEmptyNRPTParent()
	refreshNRPTPolicy()
	sendParamChange()
	flushDNSCache()
	logNRPTParentKeyState("nuclear-after-delete")

	// Wait for DNS Client to process the deletion.
	time.Sleep(1 * time.Second)

	// Phase 2: Re-add the rule.
	if err := addNRPTCatchAllRule(listenerIP); err != nil {
		mainLog.Load().Error().Err(err).Msg("DNS intercept: failed to re-add NRPT after nuclear recovery")
		return
	}
	refreshNRPTPolicy()
	sendParamChange()
	flushDNSCache()
	logNRPTParentKeyState("nuclear-after-readd")

	// Final probe after recovery.
	time.Sleep(1 * time.Second)
	if p.probeNRPT() {
		mainLog.Load().Info().Msg("DNS intercept: NRPT verified working after two-phase recovery")
		return
	}

	logNRPTParentKeyState("probe-failed-final")
	mainLog.Load().Error().Msg("DNS intercept: NRPT verification failed after all retries including two-phase recovery — " +
		"DNS queries may not be routed through ctrld. A network interface toggle may be needed.")
}
