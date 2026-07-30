//go:build windows

package cli

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
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
	fwpV6AddrMask      uint32 = 0x101 // FWP_V6_ADDR_MASK

	// IP protocol numbers.
	ipprotoUDP uint8 = 17
	ipprotoTCP uint8 = 6

	// DNS port.
	dnsPort uint16 = 53

	// FWPM_FILTER_FLAG constants from fwpmtypes.h.
	// See: https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0
	//
	// FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT (0x08) prevents lower-weight sublayers
	// from overriding this filter's PERMIT action ("hard permit"). Used in DNS
	// mode to override third-party WFP blocks (e.g., OpenVPN's block-outside-dns).
	fwpmFilterFlagClearActionRight uint32 = 0x00000008

	// fwpmSessionFlagDynamic is FWPM_SESSION_FLAG_DYNAMIC from fwpmtypes.h.
	//
	// Every WFP object added through a dynamic session is owned by that session and
	// is deleted by the OS when the engine handle closes - including when the process
	// exits, crashes, or is killed. ctrld relies on this so its filters can never
	// outlive the process that installed them.
	//
	// This matters most in Firewall Mode: its block-all filters are machine-wide, so
	// an orphaned set silently denies outbound traffic for every process on the host
	// (browsers, other users, even a replacement ctrld's own API bootstrap) until a
	// reboot. Session-scoped ownership makes the OS clean that up for us instead of
	// depending on ctrld reaching its own shutdown or startup cleanup path.
	// See: https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_session0
	fwpmSessionFlagDynamic uint32 = 0x00000001
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

// fwpV6AddrAndMask represents FWP_V6_ADDR_AND_MASK for IPv6 subnet matching.
type fwpV6AddrAndMask struct {
	addr         [16]byte
	prefixLength uint8
}

// fwpmAction0 represents FWPM_ACTION0 for specifying what happens on match.
// Size: 20 bytes (uint32 + GUID). No padding needed — GUID has 4-byte alignment.
type fwpmAction0 struct {
	actionType uint32
	filterType windows.GUID // union: filterType or calloutKey
}

type nrptRuleOwner uint8

const (
	nrptRuleOwnerNone nrptRuleOwner = iota
	nrptRuleOwnerCtrld
	nrptRuleOwnerGroupPolicy
)

// wfpState holds the state of the WFP DNS interception filters.
// It tracks the engine handle and all filter IDs for cleanup on shutdown.
// All filter IDs are stored so we can remove them individually without
// needing to enumerate the sublayer's filters via WFP API.
//
// In "dns" mode, engineHandle is 0 (no WFP filters) and only NRPT is active.
// In "hard" mode, both NRPT and WFP filters are active.
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
	// nrptOwner distinguishes a ctrld-created rule from a GP rule that ctrld is
	// only observing. Shutdown and recovery must never delete the latter.
	nrptOwner nrptRuleOwner
	// externalGPRuleName is the GP child key currently routing the catch-all to
	// listenerIP. It is diagnostic identity, not an ownership claim.
	externalGPRuleName string
	// listenerIP is the actual IP address ctrld is listening on (e.g., "127.0.0.1"
	// or "127.0.0.2" on AD DC). Used by NRPT rule creation and health monitor to
	// ensure NRPT points to the correct address.
	listenerIP string
	// stopCh is used to shut down the NRPT health monitor goroutine.
	stopCh chan struct{}
	// mu protects NRPT ownership, externalGPRuleName, loopbackProtectActive,
	// loopbackPermitIDs, and engineHandle from concurrent monitor/recovery/stop use.
	mu sync.Mutex
	// loopbackProtectActive is true when DNS mode has activated a minimal WFP
	// session to permit loopback DNS. This counters third-party WFP block filters
	// (e.g., OpenVPN's block-outside-dns) that prevent NRPT from routing queries
	// to ctrld's listener on 127.0.0.1. See issue #526.
	loopbackProtectActive bool
	// loopbackPermitIDs stores the filter IDs for the loopback protect permits.
	loopbackPermitIDs []uint64
	// nrptRecoveryLimiter prevents repeated Windows policy/Dnscache signaling
	// when another agent keeps putting NRPT back into a broken state.
	nrptRecoveryLimiter nrptRecoveryLimiter
	// handbackAttempts records, per external rule name, when ctrld last removed its own
	// catch-all to test whether that rule routes on its own. Protected by mu.
	//
	// It is a map rather than one (rule, time) pair because Group Policy can alternate
	// between two rule names: with a single slot each swap erases the memory of the other
	// one, and every swap costs another removal of the live rule.
	handbackAttempts map[string]time.Time
}

// handbackAllowed reports whether ctrld may test external rule ruleName again, without
// recording anything.
//
// Each attempt takes ctrld's rule out of the way for a probe, so a rule that never routes
// would otherwise cost a brief DNS outage on every health tick - in hard mode a window
// where WFP blocks DNS with nothing redirecting it. A different rule name means the
// administrator changed policy, which is worth testing immediately; the same name is held
// off for minInterval.
func (s *wfpState) handbackAllowed(now time.Time, ruleName string, minInterval time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	last, ok := s.handbackAttempts[ruleName]
	return !ok || now.Sub(last) >= minInterval
}

// recordHandbackAttempt spends ruleName's budget. Callers record only once an attempt is
// actually about to disturb NRPT, so a cheap abort - a pre-probe that shows nothing is
// routing - does not cost the rule its next 15 minutes.
func (s *wfpState) recordHandbackAttempt(now time.Time, ruleName string, minInterval time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handbackAttempts == nil {
		s.handbackAttempts = make(map[string]time.Time, 2)
	}
	// Drop entries whose window has passed, so a churning GP store cannot grow this map.
	for rule, at := range s.handbackAttempts {
		if now.Sub(at) >= minInterval {
			delete(s.handbackAttempts, rule)
		}
	}
	s.handbackAttempts[ruleName] = now
}

func (s *wfpState) nrptPolicyOwner() (nrptRuleOwner, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.nrptOwner, s.externalGPRuleName
}

func (s *wfpState) setNRPTPolicyOwner(owner nrptRuleOwner, externalGPRuleName string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nrptOwner = owner
	s.externalGPRuleName = externalGPRuleName
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
	// nrptDirectRuleName is the key name for the direct service store path.
	// The DNS Client requires direct-path rules to use GUID-in-braces format.
	// Using a plain name like "CtrldCatchAll" makes the rule visible in
	// Get-DnsClientNrptRule but DNS Client won't apply it for resolution
	// (Get-DnsClientNrptPolicy returns empty). This is a deterministic GUID
	// so we can reliably find and clean up our own rule.
	nrptDirectRuleName = `{B2E9A3C1-7F4D-4A8E-9D6B-5C1E0F3A2B8D}`
)

func (p *prog) nrptListenerIP() string {
	listenerIP := "127.0.0.1"
	if lc := p.cfg.FirstListener(); lc != nil && lc.IP != "" && lc.IP != "0.0.0.0" && lc.IP != "::" {
		listenerIP = lc.IP
	}
	return listenerIP
}

// skipInitialDNSReset is the first half of GP-rule adoption. postRun normally
// resets adapter DNS before setDNS starts intercept mode; doing that first would
// violate externally managed policy even if startDNSIntercept adopted the GP rule
// a few milliseconds later. This is only a read-only candidate check. The rule is
// not trusted until a DNS Client probe reaches the listener and the same child is
// re-read by startDNSIntercept.
func (p *prog) skipInitialDNSReset() bool {
	mode := p.configuredInterceptMode()
	if mode != "dns" && mode != "hard" {
		return false
	}
	if ruleName := findMatchingGPNRPTRule(p.nrptListenerIP()); ruleName != "" {
		mainLog.Load().Info().Str("rule", ruleName).
			Msg("DNS intercept: matching GP-managed NRPT candidate found - preserving adapter DNS until functional verification")
		return true
	}
	return false
}

// findMatchingGPNRPTRule returns the first non-ctrld GP child that is exactly a
// catch-all for listenerIP. Multiple namespaces or nameservers are deliberately
// rejected: ctrld must not infer exclusive routing from a broader policy shape.
func findMatchingGPNRPTRule(listenerIP string) string {
	parent, err := registry.OpenKey(registry.LOCAL_MACHINE, nrptBaseKey, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return ""
	}
	names, err := parent.ReadSubKeyNames(-1)
	parent.Close()
	if err != nil {
		return ""
	}
	for _, name := range names {
		if gpNRPTRuleMatches(name, listenerIP) {
			return name
		}
	}
	return ""
}

func gpNRPTRuleMatches(ruleName, listenerIP string) bool {
	namespaces, dnsServers, ok := readGPNRPTRule(ruleName)
	return ok && isMatchingGPNRPTRule(ruleName, namespaces, dnsServers, listenerIP)
}

func readGPNRPTRule(ruleName string) ([]string, string, bool) {
	if ruleName == "" || strings.EqualFold(ruleName, nrptRuleName) {
		return nil, "", false
	}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, nrptBaseKey+`\`+ruleName, registry.QUERY_VALUE)
	if err != nil {
		return nil, "", false
	}
	defer key.Close()
	namespaces, _, err := key.GetStringsValue("Name")
	if err != nil {
		return nil, "", false
	}
	dnsServers, _, err := key.GetStringValue("GenericDNSServers")
	if err != nil {
		// A malformed external catch-all is still authoritative enough to block
		// ctrld from creating a second catch-all; it simply cannot be adopted.
		dnsServers = ""
	}
	return namespaces, dnsServers, true
}

// findConflictingGPCatchAll reports an administrator-owned catch-all that no
// longer targets ctrld. Adding another GP catch-all beside it would create the
// same ambiguous policy class as a competing local-store rule, so callers leave
// policy untouched and wait for the administrator to restore/remove it.
func findConflictingGPCatchAll(listenerIP string) (string, string) {
	parent, err := registry.OpenKey(registry.LOCAL_MACHINE, nrptBaseKey, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return "", ""
	}
	names, err := parent.ReadSubKeyNames(-1)
	parent.Close()
	if err != nil {
		return "", ""
	}
	for _, name := range names {
		namespaces, dnsServers, ok := readGPNRPTRule(name)
		if !ok || !isExternalGPCatchAll(name, namespaces) {
			continue
		}
		if !isMatchingGPNRPTRule(name, namespaces, dnsServers, listenerIP) {
			return name, dnsServers
		}
	}
	return "", ""
}

// addNRPTCatchAllRule creates an NRPT catch-all rule that directs all DNS queries
// to the specified listener IP.
//
// Windows NRPT has two registry paths with all-or-nothing precedence:
//   - GP path: SOFTWARE\Policies\...\DnsPolicyConfig (Group Policy)
//   - Local path: SYSTEM\CurrentControlSet\...\DnsPolicyConfig (service store)
//
// If the GP path contains real rules (from IT policy, VPN, MDM, etc.), DNS
// Client enters "GP mode" and ignores ALL local-path rules entirely. An empty GP
// parent key is worse: it still puts DNS Client in GP mode, but contributes no
// usable rule, so our local catch-all is hidden until that empty parent is gone.
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

// cleanGPPath removes only ctrld's GP-path rule and deletes the GP parent when
// no rules remain. The return value tells callers whether the parent key was
// actually deleted, which means DNS Client should be signaled once.
//
// Do not leave an empty GP parent behind: Windows treats the parent key itself
// as the policy store boundary, so an empty key can still hide local-path rules.
func cleanGPPath() bool {
	// Delete our specific rule.
	registry.DeleteKey(registry.LOCAL_MACHINE, nrptBaseKey+`\`+nrptRuleName)

	// If the GP parent key is now empty, delete it entirely to exit "GP mode".
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, nrptBaseKey, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return false // Key doesn't exist — clean state.
	}
	names, err := k.ReadSubKeyNames(-1)
	k.Close()
	if err != nil || len(names) > 0 {
		if len(names) > 0 {
			mainLog.Load().Debug().Strs("remaining", names).Msg("DNS intercept: GP path has other rules, leaving parent key")
		}
		return false
	}
	// Empty — delete it to exit "GP mode".
	if err := registry.DeleteKey(registry.LOCAL_MACHINE, nrptBaseKey); err == nil {
		mainLog.Load().Info().Msg("DNS intercept: deleted empty GP DnsPolicyConfig key (exits GP mode)")
		return true
	}
	return false
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
// nrptSignalExecTimeout bounds every helper process the NRPT signalling path shells out
// to. These run while a transition holds nrptTransitionMu, and a service stop takes that
// same lock: "gpupdate /force" against a slow or unreachable domain controller can take
// tens of seconds, which is exactly the Service Control Manager timeout the locking exists
// to avoid. A signal that cannot finish in this window has already failed as a nudge.
const nrptSignalExecTimeout = 10 * time.Second

// runBoundedNRPTExec runs one signalling helper with a hard deadline and reports its
// combined output.
func runBoundedNRPTExec(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), nrptSignalExecTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if ctx.Err() != nil {
		mainLog.Load().Warn().Str("command", name).Str("timeout", nrptSignalExecTimeout.String()).
			Msg("DNS intercept: NRPT signalling helper timed out and was killed")
	}
	return out, err
}

func runGPUpdate() {
	if out, err := runBoundedNRPTExec("gpupdate", "/target:computer", "/force"); err != nil {
		mainLog.Load().Debug().Msgf("DNS intercept: gpupdate failed: %v: %s", err, string(out))
	} else {
		mainLog.Load().Debug().Msg("DNS intercept: triggered GP refresh via gpupdate")
	}
}

func refreshNRPTPolicy() {
	if err := userenvDLL.Load(); err != nil {
		mainLog.Load().Debug().Err(err).Msg("DNS intercept: userenv.dll not available, falling back to gpupdate")
		runGPUpdate()
		return
	}
	if err := procRefreshPolicyEx.Find(); err != nil {
		mainLog.Load().Debug().Err(err).Msg("DNS intercept: RefreshPolicyEx not found, falling back to gpupdate")
		runGPUpdate()
		return
	}
	// RefreshPolicyEx(BOOL bMachine, DWORD dwOptions)
	// bMachine=1 (TRUE) = refresh computer policy, dwOptions=1 (RP_FORCE) = force refresh.
	// This one only asks the policy engine to refresh and returns; it does not wait for a
	// domain controller, which is why it is preferred over gpupdate.
	ret, _, _ := procRefreshPolicyEx.Call(1, 1)
	if ret != 0 {
		mainLog.Load().Debug().Msg("DNS intercept: triggered machine GP refresh via RefreshPolicyEx")
	} else {
		mainLog.Load().Debug().Msg("DNS intercept: RefreshPolicyEx returned FALSE, falling back to gpupdate")
		runGPUpdate()
	}
}

// flushDNSCache flushes the Windows DNS Client resolver cache and triggers a
// Group Policy refresh so NRPT changes take effect immediately.
func flushDNSCache() {
	refreshNRPTPolicy()
	flushDNSCacheOnly()
}

func flushDNSCacheOnly() {
	if err := dnsapiDLL.Load(); err == nil {
		if err := procDnsFlushResolverCache.Find(); err == nil {
			ret, _, _ := procDnsFlushResolverCache.Call()
			if ret != 0 {
				mainLog.Load().Debug().Msg("DNS intercept: flushed DNS resolver cache via DnsFlushResolverCache")
				return
			}
		}
	}
	if out, err := runBoundedNRPTExec("ipconfig", "/flushdns"); err != nil {
		mainLog.Load().Debug().Msgf("DNS intercept: ipconfig /flushdns failed: %v: %s", err, string(out))
	} else {
		mainLog.Load().Debug().Msg("DNS intercept: flushed DNS resolver cache via ipconfig /flushdns")
	}
}

func signalNRPTChange() {
	refreshNRPTPolicy()
	sendParamChange()
	flushDNSCacheOnly()
}

// sendParamChange sends SERVICE_CONTROL_PARAMCHANGE to the DNS Client (Dnscache)
// service, signaling it to re-read its configuration including NRPT rules from
// the registry. This is the standard mechanism used by FortiClient, Tailscale,
// and other DNS-aware software — it's reliable and non-disruptive unlike
// restarting the Dnscache service (which always fails on modern Windows because
// Dnscache is a protected shared svchost service).
func sendParamChange() {
	if out, err := runBoundedNRPTExec("sc", "control", "dnscache", "paramchange"); err != nil {
		mainLog.Load().Debug().Err(err).Str("output", string(out)).Msg("DNS intercept: sc control dnscache paramchange failed")
	} else {
		mainLog.Load().Debug().Msg("DNS intercept: sent paramchange to Dnscache service")
	}
}

// cleanEmptyNRPTParent removes empty NRPT parent keys that block activation.
// Empty GP and local parents have different failure shapes:
//   - empty GP parent: DNS Client is in GP mode and ignores local-path rules;
//   - empty local parent: DNS Client can cache an empty local policy store.
//
// This helper only changes registry state. The caller sends the single
// RefreshPolicyEx/paramchange/flush signal after it knows cleanup occurred.
//
// Returns true if cleanup was performed (caller should signal DNS Client).
func cleanEmptyNRPTParent() bool {
	// Always clean the GP path — its existence blocks local path activation.
	cleaned := cleanGPPath()

	// Clean empty local/direct path parent key.
	if !nrptParentKeyEmpty(nrptDirectKey) {
		return cleaned
	}

	mainLog.Load().Warn().Msg("DNS intercept: found empty NRPT local parent key (blocks activation) — removing")
	if err := registry.DeleteKey(registry.LOCAL_MACHINE, nrptDirectKey); err != nil {
		mainLog.Load().Warn().Err(err).Msg("DNS intercept: failed to delete empty NRPT local parent key")
		return cleaned
	}
	return true
}

func nrptParentKeyEmpty(keyPath string) bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return false
	}
	names, err := k.ReadSubKeyNames(-1)
	k.Close()
	return err == nil && len(names) == 0
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
	p.dnsInterceptMu.Lock()
	defer p.dnsInterceptMu.Unlock()
	return p.startDNSInterceptLocked()
}

// startDNSInterceptLocked is startDNSIntercept with p.dnsInterceptMu already held, so
// the rebuild path can make teardown and re-create one atomic transition.
//
// Nothing it calls may take p.dnsInterceptMu. It runs nrptProbeAndHeal synchronously,
// and that whole family - nrptProbeAndHeal, activateCtrldNRPTFallback,
// tryAdoptMatchingGPNRPT - stays lock-free on purpose and uses interceptStateRevoked
// instead: those flows wait seconds between probes, and holding the lifecycle lock
// across them would make a service stop wait just as long.
func (p *prog) startDNSInterceptLocked() error {
	ops := p.nrptOps()
	listenerIP := p.nrptListenerIP()
	if lc := p.cfg.FirstListener(); lc != nil && (lc.IP == "0.0.0.0" || lc.IP == "::") {
		mainLog.Load().Warn().Str("configured_ip", lc.IP).
			Msg("DNS intercept: listener configured with wildcard IP, using 127.0.0.1 for NRPT rules")
	}

	state := &wfpState{
		stopCh:     make(chan struct{}),
		listenerIP: listenerIP,
	}
	// The probe and heal flows take state as an argument rather than reading the
	// published field, so nothing is published until startup has fully succeeded.
	// Publishing a provisional state would expose a half-built wfpState - no engine
	// handle yet, filter IDs still being assigned - to exemptVPNDNSServers, which the
	// VPN DNS manager can call at any time.

	mainLog.Load().Info().Msgf("DNS intercept: initializing (mode: %s)", interceptMode)

	logNRPTParentKeyState("pre-write")

	// GP adoption is a two-part proof. Registry shape establishes ownership; the
	// DNS Client probe establishes that the policy actually routes to this listener.
	// Re-reading the same child after the probe prevents adopting a rule replaced
	// during a concurrent Group Policy refresh.
	externalProbeOK := false
	if ruleName := ops.findGPRule(listenerIP); ruleName != "" {
		// Adoption goes through the same handback transition the running service uses.
		// A rule left behind by an earlier unclean exit points at this very listener, so
		// a probe taken with it still installed proves nothing about the GP rule; the
		// transition removes ctrld's keys first, and puts them back if the GP rule
		// cannot carry DNS on its own.
		switch p.nrptHandbackToExternal(state, ruleName, "startup GP-managed catch-all candidate") {
		case nrptHandbackVerified:
			externalProbeOK = true
			mainLog.Load().Info().Str("rule", ruleName).Str("listener", listenerIP).
				Msg("DNS intercept: adopted working GP-managed NRPT catch-all; ctrld will not modify NRPT policy")
		case nrptHandbackUnverified:
			mainLog.Load().Warn().Str("rule", ruleName).Str("listener", listenerIP).
				Msg("DNS intercept: GP-managed NRPT catch-all is present but the probe did not reach ctrld; leaving external policy untouched")
		case nrptHandbackKeptCtrld:
			mainLog.Load().Warn().Str("rule", ruleName).Str("listener", listenerIP).
				Msg("DNS intercept: GP-managed NRPT catch-all could not carry DNS alone; keeping the ctrld-owned rule from the previous run")
		case nrptHandbackConflict:
			// The candidate turned out to target another resolver. Startup then refuses to
			// write a competing rule below, which is a hard startup failure by design.
			mainLog.Load().Error().Str("rule", ruleName).Str("listener", listenerIP).
				Msg("DNS intercept: GP catch-all does not target ctrld; refusing to write a competing NRPT rule")
		case nrptHandbackAborted:
			// Undecided, not decided: nothing was proved about the candidate and no
			// ownership was recorded. Say so, because the fall-through below writes
			// ctrld's rule, and an unlogged fall-through here is indistinguishable from
			// "no external policy exists".
			mainLog.Load().Warn().Str("rule", ruleName).Str("listener", listenerIP).
				Msg("DNS intercept: GP-managed NRPT candidate could not be tested at startup; continuing without external ownership")
		}
	}

	owner, _ := state.nrptPolicyOwner()
	if owner == nrptRuleOwnerNone {
		// No working external ownership contract exists. Preserve the current ctrld
		// path unless another GP catch-all already owns the namespace; writing a
		// second catch-all would create an ambiguous policy rather than recovery.
		if gpCatchAllConflictBlocksFallback(state, "startup GP catch-all does not target ctrld") {
			return fmt.Errorf("dns intercept: conflicting GP NRPT catch-all targets another resolver")
		}
		// A matching candidate that is still there means the handback above came back
		// undecided - typically because the pre-probe ran while the DNS Client was still
		// settling at boot. Give it one more pass before writing anything: the DNS Client
		// has had the startup work since, and a decision here avoids writing beside an
		// administrator rule that no probe has tested.
		if ruleName := ops.findGPRule(listenerIP); ruleName != "" {
			switch p.nrptHandbackToExternal(state, ruleName, "startup retry of an undecided GP candidate") {
			case nrptHandbackVerified:
				externalProbeOK = true
			case nrptHandbackUnverified, nrptHandbackConflict, nrptHandbackKeptCtrld:
				// Ownership is recorded by the transition (or ctrld's own rule was put
				// back), so the write below is neither needed nor safe.
			}
		}
	}

	owner, _ = state.nrptPolicyOwner()
	if owner == nrptRuleOwnerNone {
		if ops.ruleExists() {
			// A rule from an earlier run already points at this listener. Adopt it rather
			// than writing a second time: with a GP child present, addNRPTCatchAllRule
			// would also write ctrld's GP-path sibling.
			state.setNRPTPolicyOwner(nrptRuleOwnerCtrld, "")
			mainLog.Load().Info().Str("listener", listenerIP).
				Msg("DNS intercept: adopting the ctrld NRPT catch-all already present from an earlier run")
		} else {
			if ops.cleanParent() {
				ops.signal()
			}
			if err := ops.addRule(listenerIP); err != nil {
				return fmt.Errorf("dns intercept: failed to add NRPT catch-all rule: %w", err)
			}
			logNRPTParentKeyState("post-write")
			state.setNRPTPolicyOwner(nrptRuleOwnerCtrld, "")
			ops.signal()
			mainLog.Load().Info().Msgf("DNS intercept: NRPT catch-all rule active - all DNS queries directed to %s", listenerIP)
		}
	}

	// In hard mode, also set up WFP filters to block non-local DNS.
	if hardIntercept {
		if err := ops.startWFP(state); err != nil {
			owner, _ := state.nrptPolicyOwner()
			if owner == nrptRuleOwnerGroupPolicy && externalProbeOK {
				// A GP rule the probe proved is routing keeps DNS flowing through ctrld
				// even with no WFP filters, and rewriting adapter DNS would violate that
				// external policy - so this is not a fall-back-to-adapter-DNS failure.
				//
				// It is still a hard-mode enforcement gap: with no block filters, raw DNS
				// to a public resolver, DoH clients and apps with their own resolver are
				// not filtered at all. Publish the state and start the health monitor so
				// repairMissingWFP keeps retrying WFP instead of the process running
				// unenforced for its whole life on one error line. Ownership stays with
				// Group Policy so the monitor never writes NRPT policy here.
				mainLog.Load().Error().Err(err).
					Msg("DNS intercept: WFP setup failed while GP-managed NRPT is verified routing - DNS resolves through ctrld but hard-mode enforcement is OFF; retrying WFP in the background")
				p.dnsInterceptState = state
				go p.nrptHealthMonitor(state)
				// The service start is still reported as failed (setDnsOK stays false in
				// setDNS): a hard-mode process with no block filters must not read as a
				// healthy start, even though name resolution works.
				return fmt.Errorf("dns intercept: WFP setup failed: %w: %w", err, errGPNRPTVerified)
			}
			if owner == nrptRuleOwnerCtrld {
				mainLog.Load().Error().Err(err).Msg("DNS intercept: WFP setup failed, rolling back ctrld-owned NRPT")
				_ = ops.removeRule()
				ops.flush()
			} else {
				mainLog.Load().Error().Err(err).Msg("DNS intercept: WFP setup failed; leaving GP-managed NRPT untouched")
			}
			state.setNRPTPolicyOwner(nrptRuleOwnerNone, "")
			return fmt.Errorf("dns intercept: WFP setup failed: %w", err)
		}
	} else {
		mainLog.Load().Info().Msg("DNS intercept: dns mode — NRPT only, no WFP filters (graceful)")
		// Proactively add loopback WFP permit filters to protect the NRPT
		// → 127.0.0.1 path from third-party DNS block filters (e.g., OpenVPN's
		// block-outside-dns). These are narrowly scoped (port 53 to localhost
		// only) and use CLEAR_ACTION_RIGHT to override any block from other
		// sublayers. Adding them at startup eliminates the DNS outage window
		// that would otherwise occur between VPN connect and reactive activation.
		if err := ops.loopback(state); err != nil {
			// Non-fatal: loopback protect is a defense-in-depth measure.
			// NRPT still works when no third-party WFP blocks are present.
			mainLog.Load().Warn().Err(err).Msg("DNS intercept: failed to activate proactive loopback WFP protect — will retry on probe failure")
		}
	}

	owner, externalRuleName := state.nrptPolicyOwner()
	if owner == nrptRuleOwnerGroupPolicy && !externalProbeOK {
		// The first probe ran before loopback WFP protection existed. Verify once
		// more synchronously after WFP setup so service readiness does not race an
		// async proof; this path is ownership-aware and never mutates GP NRPT.
		externalProbeOK = p.nrptProbeAndHeal(state)
	}

	// Everything the host needs is in place: publish, then start the goroutines that
	// keep it that way. They receive state directly, so this ordering is only about
	// when the rest of ctrld may observe intercept mode as active.
	p.dnsInterceptState = state
	go p.nrptHealthMonitor(state)

	owner, _ = state.nrptPolicyOwner()
	if owner == nrptRuleOwnerCtrld {
		// ctrld-owned policy keeps the existing asynchronous activation/heal path.
		go p.nrptProbeAndHeal(state)
	}

	if owner == nrptRuleOwnerGroupPolicy && !externalProbeOK {
		// External policy owns the namespace and neither synchronous proof reached ctrld.
		// The recovery state and monitor stay up - the rule may start routing once the DNS
		// Client settles, and only external policy may fix it - but this start is not
		// ready: the DNS Client is not delivering queries to ctrld, adapter DNS was
		// deliberately preserved, and no owned fallback may be written beside an
		// administrator's catch-all. Reporting success here would publish readiness while
		// nothing is filtering, and in hard mode WFP is simultaneously blocking every
		// other resolver, which is an outage rather than degraded health.
		mainLog.Load().Error().Str("rule", externalRuleName).Str("listener", listenerIP).
			Msg("DNS intercept: GP-managed NRPT owns the namespace but no probe reached ctrld; leaving adapter DNS untouched and reporting a failed start until a probe succeeds")
		return fmt.Errorf("dns intercept: %w (rule %q)", errGPNRPTIneffective, externalRuleName)
	}

	return nil
}

// removeOrphanedCtrldNRPTRule deletes a ctrld-owned NRPT catch-all that no running
// ctrld is backing. It is safe against external policy: the rule is found by ctrld's
// own deterministic GUID, never by shape.
//
// Without this, one unclean exit can strand a rule that later takes the whole machine
// off DNS. ctrld dies without a stop while it owns policy, so the GUID rule stays in
// the local store pointing at 127.0.0.1. The org then deploys a GP catch-all: from that
// point every start adopts the GP rule and every stop takes the GP branch, so nothing
// ever looks at the local store - including the stop during uninstall. The orphan stays
// invisible, because any rule in the GP store puts the DNS Client in GP mode where the
// local store is ignored entirely. When the admin eventually removes the GP rule -
// most plausibly while cleaning up after uninstalling ctrld - the DNS Client leaves GP
// mode, reads the local store again, and every query on the machine goes to a listener
// that has not existed for months. It is also miserable to diagnose: local-store rules
// do not appear in Get-DnsClientNrptPolicy, so the standard tooling reports no policy
// at all while nothing resolves.
func (p *prog) removeOrphanedCtrldNRPTRule(reason string) {
	ops := p.nrptOps()
	if !ops.ruleExists() {
		return
	}
	mainLog.Load().Warn().Str("reason", reason).
		Msg("DNS intercept: removing orphaned ctrld NRPT catch-all left by an earlier run")
	if err := ops.removeRule(); err != nil {
		mainLog.Load().Warn().Err(err).Msg("DNS intercept: failed to remove orphaned ctrld NRPT catch-all")
		return
	}
	ops.signal()
}

// startWFPFilters opens the WFP engine and adds all block/permit filters.
// Called only in hard intercept mode.
func (p *prog) startWFPFilters(state *wfpState) error {
	mainLog.Load().Info().Msg("DNS intercept: initializing Windows Filtering Platform (WFP)")

	var engineHandle uintptr
	session := fwpmSession0{}
	sessionName, _ := windows.UTF16PtrFromString("ctrld DNS Intercept")
	session.displayData.name = sessionName
	// Session-scoped ownership: if this process dies without running its shutdown
	// path, Windows removes our filters (including Firewall Mode's machine-wide
	// block-all) instead of leaving the host enforced by a dead ctrld.
	session.flags = fwpmSessionFlagDynamic

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
	mainLog.Load().Info().Msgf("DNS intercept: WFP engine opened (handle: 0x%x, session-scoped)", engineHandle)

	// Clean up any sublayer left by an older ctrld that used a non-dynamic session
	// (or by a build predating session-scoped ownership). Deleting the sublayer
	// removes all its child filters.
	r1, _, _ = procFwpmSubLayerDeleteByKey0.Call(
		engineHandle,
		uintptr(unsafe.Pointer(&ctrldSubLayerGUID)),
	)
	if r1 == 0 {
		mainLog.Load().Info().Msg("DNS intercept: cleaned up stale WFP sublayer from previous session")
	}
	// A non-zero r1 is not necessarily "nothing to clean up": it is also
	// FWP_E_SUBLAYER_NOT_FOUND (the normal case), FWP_E_WRONG_SESSION for a sublayer a
	// live ctrld owns, or FWP_E_DYNAMIC_SESSION_IN_PROGRESS for a non-dynamic one this
	// dynamic session may not delete. None of them need handling here: the add below
	// fails cleanly if the sublayer really is still present, and the non-dynamic case is
	// what cleanupStaleDNSInterceptState handles at startup.

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
		addr uint32
		mask uint32
	}{
		{"10.0.0.0/8", 0x0A000000, 0xFF000000},
		{"172.16.0.0/12", 0xAC100000, 0xFFF00000},
		{"192.168.0.0/16", 0xC0A80000, 0xFFFF0000},
		{"100.64.0.0/10", 0x64400000, 0xFFC00000},
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

// addWFPPermitDNSFilter is the unified helper for adding a WFP permit filter for
// outbound DNS (port 53) with caller-specified address condition, flags, and weight.
// Both subnet permits (RFC1918/CGNAT, flags=0, weight=10) and hard loopback permits
// (CLEAR_ACTION_RIGHT, weight=15) use this to avoid code drift.
func (p *prog) addWFPPermitDNSFilter(engineHandle uintptr, name string, layerKey windows.GUID, proto uint8, addrCond fwpmFilterCondition0, flags uint32, weight uint8) (uint64, error) {
	filterName, _ := windows.UTF16PtrFromString("ctrld: " + name)

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

	conditions[2] = addrCond

	filter := fwpmFilter0{
		flags:           flags,
		layerKey:        layerKey,
		subLayerKey:     ctrldSubLayerGUID,
		numFilterConds:  3,
		filterCondition: &conditions[0],
	}
	filter.displayData.name = filterName
	filter.weight.valueType = fwpUint8
	filter.weight.value = uint64(weight)
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

// addWFPPermitSubnetFilter adds a WFP filter that permits outbound DNS to a given
// IPv4 subnet (addr/mask in host byte order). Used to exempt RFC1918 and CGNAT ranges
// so VPN DNS servers on private IPs are not blocked.
func (p *prog) addWFPPermitSubnetFilter(engineHandle uintptr, name string, proto uint8, addr, mask uint32) (uint64, error) {
	addrMask := fwpV4AddrAndMask{addr: addr, mask: mask}

	addrCond := fwpmFilterCondition0{
		fieldKey:  fwpmConditionIPRemoteAddress,
		matchType: fwpMatchEqual,
	}
	addrCond.condValue.valueType = fwpV4AddrMask
	addrCond.condValue.value = uint64(uintptr(unsafe.Pointer(&addrMask)))

	filterID, err := p.addWFPPermitDNSFilter(engineHandle, name, fwpmLayerALEAuthConnectV4, proto, addrCond, 0, 10)
	runtime.KeepAlive(&addrMask)
	return filterID, err
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

	// Hold state.mu across the whole teardown: engineHandle and every filter ID slice
	// below is shared with the VPN DNS exemption path and the recovery flows.
	state.mu.Lock()
	defer state.mu.Unlock()

	// Clean up loopback protect filters (DNS mode VPN workaround).
	loopbackIDs := state.loopbackPermitIDs
	state.loopbackPermitIDs = nil
	state.loopbackProtectActive = false
	for _, filterID := range loopbackIDs {
		r1, _, _ := procFwpmFilterDeleteById0.Call(state.engineHandle, uintptr(filterID))
		if r1 != 0 {
			mainLog.Load().Warn().Msgf("DNS intercept: failed to remove loopback protect filter (ID: %d, code: 0x%x)", filterID, r1)
		} else {
			mainLog.Load().Debug().Msgf("DNS intercept: removed loopback protect filter (ID: %d)", filterID)
		}
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

// activateLoopbackWFPProtect opens a minimal WFP session and adds "hard permit"
// filters for DNS to localhost. This is used in DNS mode when NRPT probe failures
// are detected, typically caused by third-party VPN software (e.g., OpenVPN) that
// installs WFP block filters via block-outside-dns. The hard permit (with
// FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT) in a max-weight sublayer overrides the
// third-party blocks without affecting their protection for non-loopback DNS.
func (p *prog) activateLoopbackWFPProtect(state *wfpState) error {
	state.mu.Lock()
	defer state.mu.Unlock()

	if state.loopbackProtectActive {
		mainLog.Load().Debug().Msg("DNS intercept: loopback WFP protect already active")
		return nil
	}
	// Only activate in DNS mode. Hard mode manages its own full WFP state
	// (block + permit filters in the same sublayer). Activating loopback
	// protect would delete the hard mode sublayer and all its filters.
	if hardIntercept {
		mainLog.Load().Debug().Msg("DNS intercept: skipping loopback WFP protect in hard mode")
		return nil
	}

	mainLog.Load().Info().Msg("DNS intercept: activating loopback WFP protect (countering third-party DNS block filters)")

	// Open WFP engine if not already open (DNS mode doesn't open it normally).
	if state.engineHandle == 0 {
		var engineHandle uintptr
		session := fwpmSession0{}
		sessionName, _ := windows.UTF16PtrFromString("ctrld DNS Loopback Protect")
		session.displayData.name = sessionName
		// Session-scoped, like the hard-intercept engine: no ctrld filter should
		// outlive the process that installed it.
		session.flags = fwpmSessionFlagDynamic

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
		mainLog.Load().Info().Msgf("DNS intercept: WFP engine opened for loopback protect (handle: 0x%x)", engineHandle)
		state.engineHandle = engineHandle
	}

	// Clean up any stale sublayer from a previous session.
	procFwpmSubLayerDeleteByKey0.Call(
		state.engineHandle,
		uintptr(unsafe.Pointer(&ctrldSubLayerGUID)),
	)

	// Create sublayer at maximum priority.
	sublayer := fwpmSublayer0{
		subLayerKey: ctrldSubLayerGUID,
		weight:      0xFFFF,
	}
	sublayerName, _ := windows.UTF16PtrFromString("ctrld DNS Loopback Protect Sublayer")
	sublayerDesc, _ := windows.UTF16PtrFromString("Permits DNS to localhost, overriding third-party VPN block filters")
	sublayer.displayData.name = sublayerName
	sublayer.displayData.description = sublayerDesc

	r1, _, _ := procFwpmSubLayerAdd0.Call(
		state.engineHandle,
		uintptr(unsafe.Pointer(&sublayer)),
		0,
	)
	if r1 != 0 {
		return fmt.Errorf("FwpmSubLayerAdd0 failed: HRESULT 0x%x", r1)
	}

	// Add hard permit filters for loopback DNS (v4+v6, UDP+TCP).
	permitFilters := []struct {
		name  string
		layer windows.GUID
		proto uint8
	}{
		{"Loopback Protect: Permit DNS to localhost (IPv4/UDP)", fwpmLayerALEAuthConnectV4, ipprotoUDP},
		{"Loopback Protect: Permit DNS to localhost (IPv4/TCP)", fwpmLayerALEAuthConnectV4, ipprotoTCP},
		{"Loopback Protect: Permit DNS to localhost (IPv6/UDP)", fwpmLayerALEAuthConnectV6, ipprotoUDP},
		{"Loopback Protect: Permit DNS to localhost (IPv6/TCP)", fwpmLayerALEAuthConnectV6, ipprotoTCP},
	}

	for _, pf := range permitFilters {
		filterID, err := p.addWFPHardPermitLocalhostFilter(state.engineHandle, pf.name, pf.layer, pf.proto, state.listenerIP)
		if err != nil {
			// Partial failure — clean up what we added (already holding mu).
			p.deactivateLoopbackWFPProtectLocked(state)
			return fmt.Errorf("failed to add loopback protect filter %q: %w", pf.name, err)
		}
		state.loopbackPermitIDs = append(state.loopbackPermitIDs, filterID)
		mainLog.Load().Debug().Str("filter", pf.name).Uint64("id", filterID).Msg("DNS intercept: added loopback protect filter")
	}

	state.loopbackProtectActive = true
	mainLog.Load().Info().Int("filters", len(state.loopbackPermitIDs)).
		Msg("DNS intercept: loopback WFP protect activated — localhost DNS permitted with CLEAR_ACTION_RIGHT")
	return nil
}

// osHealthcheckSuppressed reports whether the upstream.os healthcheck should
// be skipped because DNS intercept mode is active and the WFP loopback protect
// has been engaged. Loopback protect is only activated when an external WFP
// block filter (e.g. OpenVPN's block-outside-dns) is interfering with DNS,
// which is the same condition that makes the OS resolver healthcheck fail
// every 2s with i/o timeout — so suppressing the check avoids the log spam
// described in issue #526.
func (p *prog) osHealthcheckSuppressed() bool {
	if !dnsIntercept || p.dnsInterceptState == nil {
		return false
	}
	state, ok := p.dnsInterceptState.(*wfpState)
	if !ok || state == nil {
		return false
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.loopbackProtectActive
}

// deactivateLoopbackWFPProtectLocked is the lock-free inner implementation.
// Caller must hold state.mu.
func (p *prog) deactivateLoopbackWFPProtectLocked(state *wfpState) {
	if !state.loopbackProtectActive && len(state.loopbackPermitIDs) == 0 {
		return
	}

	for _, filterID := range state.loopbackPermitIDs {
		if state.engineHandle != 0 {
			r1, _, _ := procFwpmFilterDeleteById0.Call(state.engineHandle, uintptr(filterID))
			if r1 != 0 {
				mainLog.Load().Warn().Msgf("DNS intercept: failed to remove loopback protect filter (ID: %d, code: 0x%x)", filterID, r1)
			}
		}
	}
	state.loopbackPermitIDs = nil
	state.loopbackProtectActive = false
	mainLog.Load().Info().Msg("DNS intercept: loopback WFP protect deactivated")
}

// addWFPHardPermitLocalhostFilter adds a WFP permit filter for DNS to localhost with
// FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT. This "hard permit" prevents lower-priority
// sublayers (e.g., OpenVPN's block-outside-dns sublayer) from blocking DNS to
// ctrld's loopback listener. Weight is set to 15 (above hard mode's permit=10).
// For IPv4, the address is derived from listenerIP (e.g., 127.0.0.1 or 127.0.0.2).
func (p *prog) addWFPHardPermitLocalhostFilter(engineHandle uintptr, name string, layerKey windows.GUID, proto uint8, listenerIP string) (uint64, error) {
	addrCond := fwpmFilterCondition0{
		fieldKey:  fwpmConditionIPRemoteAddress,
		matchType: fwpMatchEqual,
	}

	ipv6Loopback := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}

	if layerKey == fwpmLayerALEAuthConnectV4 {
		addrCond.condValue.valueType = fwpUint32
		addrCond.condValue.value = uint64(parseIPv4AsUint32(listenerIP))
	} else {
		addrCond.condValue.valueType = fwpByteArray16Type
		addrCond.condValue.value = uint64(uintptr(unsafe.Pointer(&ipv6Loopback)))
	}

	filterID, err := p.addWFPPermitDNSFilter(engineHandle, name, layerKey, proto, addrCond, fwpmFilterFlagClearActionRight, 15)
	runtime.KeepAlive(&ipv6Loopback)
	return filterID, err
}

// stopDNSIntercept removes all WFP filters and shuts down the DNS interception.
func (p *prog) stopDNSIntercept() error {
	// Announce the stop before waiting for the lifecycle lock. A rebuild that holds it
	// runs a full start, whose NRPT verification can sit in probe backoffs for seconds;
	// the flag is what lets those flows abandon their work instead of making the stop
	// wait. A stop that waits too long is not a delay but a failure mode: the Service
	// Control Manager kills ctrld on timeout, and then nothing is cleaned up at all.
	p.dnsInterceptStopRequested.Store(true)
	p.dnsInterceptMu.Lock()
	defer p.dnsInterceptMu.Unlock()
	defer p.dnsInterceptStopRequested.Store(false)
	return p.stopDNSInterceptLocked()
}

// stopDNSInterceptLocked is stopDNSIntercept with p.dnsInterceptMu already held.
//
// It revokes the state before removing anything. Teardown deletes the WFP sublayer, and
// a missing sublayer is exactly what the health monitor reads as "our filters were
// wiped, rebuild everything" - so a monitor tick landing inside the shutdown window
// would otherwise re-add the NRPT catch-all and the WFP filters moments before the
// process exits, leaving Windows resolving through a ctrld that is gone. Revoking first
// means every such flow sees a retired state and stands down.
func (p *prog) stopDNSInterceptLocked() error {
	if p.dnsInterceptState == nil {
		mainLog.Load().Debug().Msg("DNS intercept: no state to clean up")
		return nil
	}

	state := p.dnsInterceptState.(*wfpState)

	// Revoke first, then remove. Both signals are what the monitor, the delayed
	// rechecks and the NRPT heal flows read to decide whether they may still write
	// host DNS state.
	p.dnsInterceptState = nil
	// Stop the health monitor goroutine.
	if state.stopCh != nil {
		close(state.stopCh)
	}

	// Remove only ctrld-owned NRPT state. A GP-owned catch-all is an external
	// deployment contract and must survive service stop, restart, and uninstall.
	//
	// Hold the transition lock across the removal so an in-flight NRPT transition
	// finishes first and any later one sees the revoked state under the same lock. The
	// stop-requested flag is already set, so an in-flight transition abandons its probes
	// rather than making this wait.
	p.nrptTransitionMu.Lock()
	defer p.nrptTransitionMu.Unlock()

	ops := p.nrptOps()
	owner, externalRuleName := state.nrptPolicyOwner()
	switch owner {
	case nrptRuleOwnerCtrld:
		if err := ops.removeRule(); err != nil {
			mainLog.Load().Warn().Err(err).Msg("DNS intercept: failed to remove ctrld-owned NRPT catch-all rule")
		} else {
			mainLog.Load().Info().Msg("DNS intercept: removed ctrld-owned NRPT catch-all rule")
		}
		ops.flush()
	case nrptRuleOwnerGroupPolicy:
		mainLog.Load().Info().Str("rule", externalRuleName).
			Msg("DNS intercept: leaving GP-managed NRPT catch-all untouched during shutdown")
		// External policy stays, but a ctrld rule from an earlier unclean exit must
		// not: while GP mode hides the local store, this stop is the last chance
		// anything will look there. See removeOrphanedCtrldNRPTRule.
		p.removeOrphanedCtrldNRPTRule("shutdown with externally owned NRPT policy")
	case nrptRuleOwnerNone:
		// No ownership was ever established this run - an activation that failed, or a
		// start that never got that far. A ctrld rule found here is still ours.
		p.removeOrphanedCtrldNRPTRule("shutdown with no NRPT owner")
	}
	state.setNRPTPolicyOwner(nrptRuleOwnerNone, "")

	// Clean up WFP if the engine was opened (hard mode or loopback protect).
	if state.engineHandle != 0 {
		mainLog.Load().Info().Msg("DNS intercept: shutting down WFP filters")
		p.cleanupWFPFilters(state)
		mainLog.Load().Info().Msg("DNS intercept: WFP shutdown complete")
	}

	mainLog.Load().Info().Msg("DNS intercept: shutdown complete")
	return nil
}

// interceptRebuildResult reports what rebuildDNSIntercept did.
type interceptRebuildResult int

const (
	// interceptRebuildRetired means the caller's state was no longer the live one -
	// shutdown revoked it, or an earlier rebuild replaced it - so nothing was touched.
	interceptRebuildRetired interceptRebuildResult = iota
	// interceptRebuildDone means the intercept was torn down and re-created.
	interceptRebuildDone
	// interceptRebuildFailed means teardown ran but the re-create returned an error.
	// dnsInterceptState is nil afterwards, except on the one path that publishes a
	// partial intercept on purpose - hard mode with verified GP NRPT but no WFP - which
	// leaves a health monitor running to keep retrying.
	interceptRebuildFailed
)

// rebuildDNSIntercept tears the intercept down and creates it again, for callers that
// found our filters wiped from underneath us.
//
// It refuses unless state is still the published intercept state. That check is what
// stops a health monitor tick from resurrecting DNS interception during or after a
// service stop: shutdown revokes the state under this same lock before it removes
// anything, so a monitor arriving late finds its state retired and does nothing.
// Holding the lock across teardown and create also means a stop that arrives
// mid-rebuild waits, then tears down whatever the rebuild published - never a
// half-built intercept.
//
// Whatever the result, the caller's state is dead afterwards: the monitor goroutine
// that owns it must exit.
// rebuildDNSInterceptFn is the rebuild entry point. Indirected so tests can assert which
// conditions ask for a rebuild without running a real teardown and start. Assigned in
// init because the rebuild reaches back here through the health monitor.
var rebuildDNSInterceptFn func(*prog, *wfpState, string) interceptRebuildResult

func init() {
	rebuildDNSInterceptFn = (*prog).rebuildDNSIntercept
}

func (p *prog) rebuildDNSIntercept(state *wfpState, reason string) interceptRebuildResult {
	p.dnsInterceptMu.Lock()
	defer p.dnsInterceptMu.Unlock()

	if live, ok := p.dnsInterceptState.(*wfpState); !ok || live != state {
		mainLog.Load().Info().Str("reason", reason).
			Msg("DNS intercept: not rebuilding - this intercept was already retired by shutdown or an earlier rebuild")
		return interceptRebuildRetired
	}

	mainLog.Load().Warn().Str("reason", reason).Msg("DNS intercept: rebuilding interception")
	_ = p.stopDNSInterceptLocked()
	if err := p.startDNSInterceptLocked(); err != nil {
		mainLog.Load().Error().Err(err).Str("reason", reason).Msg("DNS intercept: rebuild failed")
		return interceptRebuildFailed
	}
	return interceptRebuildDone
}

// interceptStateRevoked reports whether state has been retired, meaning nothing may
// write host DNS state on its behalf any more.
//
// stopDNSInterceptLocked closes stopCh before it removes the NRPT rule or the WFP
// filters, and a stop waiting for the lifecycle lock sets dnsInterceptStopRequested
// first. Together they are the cheap shutdown signal for the flows that must not take
// p.dnsInterceptMu: the NRPT probe and heal sequences, which wait seconds between
// probes and also run from inside the locked start path.
func (p *prog) interceptStateRevoked(state *wfpState) bool {
	if state == nil || state.stopCh == nil {
		return true
	}
	if p.dnsInterceptStopRequested.Load() {
		return true
	}
	select {
	case <-state.stopCh:
		return true
	default:
		return false
	}
}

// interceptRevocationPollInterval is how quickly the recovery flows notice a stop that
// is waiting for the lifecycle lock. A pending stop can only set a flag - it cannot
// close stopCh until it owns the lock - so waits poll instead of selecting on a channel.
const interceptRevocationPollInterval = 100 * time.Millisecond

// interceptWait waits for d, or until the intercept is retired, whichever comes first.
// It reports whether the caller may keep working.
//
// Every wait in the NRPT recovery flows goes through this. Those flows can be holding
// the lifecycle lock - startDNSInterceptLocked runs one synchronously, and a rebuild
// holds the lock across the whole start - and their backoffs add up to tens of seconds.
// A plain time.Sleep there makes a service stop wait that long for the lock, risking
// the Service Control Manager killing ctrld before it removes the NRPT rule and the WFP
// filters, which is the unclean shutdown the locking exists to prevent. Bounding each
// wait by the shutdown signal keeps a stop's wait to about one poll interval plus
// whatever uncancellable Windows call is in flight.
func (p *prog) interceptWait(state *wfpState, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for {
		if p.interceptStateRevoked(state) {
			return false
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return true
		}
		if remaining > interceptRevocationPollInterval {
			remaining = interceptRevocationPollInterval
		}
		timer := time.NewTimer(remaining)
		select {
		case <-state.stopCh:
			timer.Stop()
			return false
		case <-timer.C:
		}
	}
}

// exemptVPNDNSServers updates the WFP filters to permit outbound DNS to the given
// VPN DNS server IPs. This prevents the block filters from intercepting ctrld's own
// forwarded queries to VPN DNS servers (split DNS routing).
//
// The function is idempotent: it first removes ALL existing VPN permit filters,
// then adds new ones for the current server list. When called with nil/empty
// exemptions (VPN disconnected), it just removes the old permits — leaving only
// the localhost permits and block-all filters active.
//
// On Windows, WFP filters are process-scoped (not interface-scoped like macOS pf),
// so we only use the server IPs from the exemptions.
//
// Supports both IPv4 and IPv6 VPN DNS servers.
//
// Called by vpnDNSManager.onServersChanged() whenever VPN DNS servers change.
func (p *prog) exemptVPNDNSServers(exemptions []vpnDNSExemption) error {
	state, ok := p.dnsInterceptState.(*wfpState)
	if !ok || state == nil {
		return fmt.Errorf("DNS intercept state not available")
	}
	// engineHandle, loopbackProtectActive and vpnPermitFilterIDs are all shared with the
	// monitor, the recovery flows and teardown, so this runs under state.mu like every
	// other reader and writer of them.
	state.mu.Lock()
	defer state.mu.Unlock()

	// In dns mode (no WFP) or loopback-protect-only mode, VPN DNS exemptions
	// are not needed — there are no ctrld block filters to exempt from.
	// Loopback protect only adds hard-permit filters for localhost DNS;
	// VPN DNS traffic uses the tunnel interface and is already permitted by
	// the VPN's own WFP rules.
	if state.engineHandle == 0 || state.loopbackProtectActive {
		mainLog.Load().Debug().Msg("DNS intercept: dns mode — skipping VPN DNS exemptions (no WFP block filters)")
		return nil
	}

	for _, filterID := range state.vpnPermitFilterIDs {
		r1, _, _ := procFwpmFilterDeleteById0.Call(state.engineHandle, uintptr(filterID))
		if r1 != 0 {
			mainLog.Load().Warn().Msgf("DNS intercept: failed to remove old VPN permit filter (ID: %d, code: 0x%x)", filterID, r1)
		}
	}
	state.vpnPermitFilterIDs = nil

	// Extract unique server IPs from exemptions (WFP doesn't need interface info).
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
func (p *prog) ensurePFAnchorActive() pfAnchorCheckResult {
	return pfAnchorCheckSkipped
}

// checkTunnelInterfaceChanges is a no-op on Windows (WFP handles intercept differently).
func (p *prog) checkTunnelInterfaceChanges() bool {
	return false
}

// Windows preserves the existing immediate reconciliation behavior. NRPT/WFP
// and adapter DNS settling have different lifecycle requirements from macOS pf.
func (p *prog) dnsInterceptIgnoredChangeReconcileDue(time.Time) bool {
	return true
}

// pfAnchorRecheckDelay is the delay for deferred pf anchor re-checks.
// Defined here as a stub for Windows (referenced from dns_proxy.go).
const pfAnchorRecheckDelay = 2 * time.Second

// pfAnchorRecheckDelayLong is the longer delayed re-check for slower VPN teardowns.
const pfAnchorRecheckDelayLong = 4 * time.Second

func gpCatchAllConflictBlocksFallback(state *wfpState, reason string) bool {
	ruleName, dnsServers := findConflictingGPCatchAll(state.listenerIP)
	if ruleName == "" {
		return false
	}
	mainLog.Load().Error().Str("rule", ruleName).Str("nameservers", dnsServers).Str("reason", reason).
		Msg("DNS intercept: GP catch-all targets another resolver; refusing to create a competing fallback rule")
	return true
}

// nrptOps is the seam between NRPT ownership decisions and the Windows side effects
// they cause. Tests substitute it to drive a transition - probe outcomes, registry
// state, concurrency - without touching the host's registry or DNS Client.
type nrptOps struct {
	probe         func(state *wfpState) bool
	ruleExists    func() bool
	addRule       func(listenerIP string) error
	removeRule    func() error
	signal        func()
	findGPRule    func(listenerIP string) string
	gpRuleMatches func(ruleName, listenerIP string) bool
	gpConflicts   func(state *wfpState, reason string) bool
	loopback      func(state *wfpState) error
	wait          func(state *wfpState, d time.Duration) bool
	flush         func()
	parentEmpty   func(keyPath string) bool
	cleanParent   func() bool
	startWFP      func(state *wfpState) error
}

// nrptOpsForTest overrides the NRPT side effects. Windows tests only.
var nrptOpsForTest *nrptOps

func (p *prog) nrptOps() nrptOps {
	if nrptOpsForTest != nil {
		return *nrptOpsForTest
	}
	return nrptOps{
		probe:         p.probeNRPT,
		ruleExists:    nrptCatchAllRuleExists,
		addRule:       addNRPTCatchAllRule,
		removeRule:    removeNRPTCatchAllRule,
		signal:        signalNRPTChange,
		findGPRule:    findMatchingGPNRPTRule,
		gpRuleMatches: gpNRPTRuleMatches,
		gpConflicts:   p.gpCatchAllConflictBlocksFallbackOps,
		loopback:      p.activateLoopbackWFPProtect,
		wait:          p.interceptWait,
		flush:         flushDNSCache,
		parentEmpty:   nrptParentKeyEmpty,
		cleanParent:   cleanEmptyNRPTParent,
		startWFP:      p.startWFPFilters,
	}
}

func (p *prog) gpCatchAllConflictBlocksFallbackOps(state *wfpState, reason string) bool {
	return gpCatchAllConflictBlocksFallback(state, reason)
}

// nrptHandbackResult reports how a handback attempt ended.
type nrptHandbackResult int

const (
	// nrptHandbackVerified: external policy owns NRPT and proved, with ctrld's own keys
	// gone, that it routes to this listener.
	nrptHandbackVerified nrptHandbackResult = iota
	// nrptHandbackUnverified: external policy owns the namespace but is not routing.
	// Nothing of ctrld's was removed, so there was nothing to lose by recording it.
	nrptHandbackUnverified
	// nrptHandbackKeptCtrld: the proof failed with ctrld's rule removed, so the rule was
	// restored and ctrld keeps ownership.
	nrptHandbackKeptCtrld
	// nrptHandbackAborted: shutdown landed, a registry step failed, the attempt was
	// throttled, or the candidate child is no longer there. Nothing was decided.
	nrptHandbackAborted
	// nrptHandbackConflict: an administrator-owned catch-all is present that does not
	// target ctrld. External policy owns the namespace and ctrld must not write beside it.
	nrptHandbackConflict
)

// nrptHandbackRetryInterval bounds how often ctrld will take its own rule out of the way
// to re-test the same external catch-all. Each attempt briefly removes the only working
// route, so retrying on every 30s health tick would be its own outage. A rule the
// administrator has changed is retested immediately regardless.
const nrptHandbackRetryInterval = 15 * time.Minute

// nrptHandbackProbePasses bounds how many probes one handback spends chasing a Group
// Policy store that keeps changing under it. Each pass costs a probe timeout, and the
// budget being spent is not an excuse to guess: see externalAfterRemoval.
const nrptHandbackProbePasses = 2

// nrptHandbackToExternal is the only path that records external (Group Policy)
// ownership of NRPT.
//
// The proof has to be produced with ctrld's own keys gone. A probe taken while the ctrld
// fallback is still installed can be answered by that fallback, so a present-but-
// ineffective GP child would otherwise let ctrld delete the last working route and then
// declare external ownership. In hard mode that is a machine-wide DNS outage: WFP keeps
// blocking outbound DNS with nothing redirecting it to ctrld.
//
// The transition is: remove only ctrld's own keys, signal, probe again, re-read the same
// GP child - and if that second probe fails, put ctrld's rule back and keep ctrld
// ownership. Everything runs under nrptTransitionMu so a stop cannot interleave with it.
func (p *prog) nrptHandbackToExternal(state *wfpState, ruleName, reason string) nrptHandbackResult {
	ops := p.nrptOps()

	p.nrptTransitionMu.Lock()
	defer p.nrptTransitionMu.Unlock()

	if p.interceptStateRevoked(state) {
		return nrptHandbackAborted
	}

	if !ops.gpRuleMatches(ruleName, state.listenerIP) {
		return nrptHandbackAborted
	}

	// Nothing of ours in the way: a probe already measures external policy alone, and
	// refusing would mean writing a competing catch-all beside an administrator's rule.
	if !ops.ruleExists() {
		child, class, routes := p.externalAfterRemoval(ops, state, ruleName, reason)
		switch {
		case class == gpChildSameExact && routes:
			state.setNRPTPolicyOwner(nrptRuleOwnerGroupPolicy, child)
			state.nrptRecoveryLimiter.recordStableSuccess()
			mainLog.Load().Info().Str("rule", child).Str("reason", reason).
				Msg("DNS intercept: GP-managed catch-all verified routing to ctrld; external policy owns NRPT")
			return nrptHandbackVerified
		case class == gpChildSameExact:
			state.setNRPTPolicyOwner(nrptRuleOwnerGroupPolicy, child)
			mainLog.Load().Warn().Str("rule", child).Str("reason", reason).
				Msg("DNS intercept: GP-managed catch-all owns the namespace but is not routing; leaving external policy untouched")
			return nrptHandbackUnverified
		case class == gpChildConflicting:
			// An administrator-owned catch-all now targets another resolver, or is
			// malformed. It owns the namespace and ctrld must not write a sibling.
			state.setNRPTPolicyOwner(nrptRuleOwnerNone, "")
			mainLog.Load().Error().Str("rule", ruleName).Str("reason", reason).
				Msg("DNS intercept: GP catch-all changed to one that does not target ctrld; refusing to write a competing rule")
			return nrptHandbackConflict
		default:
			// External policy is gone, or the store is still churning. Decide nothing:
			// the caller re-reads and retries.
			return nrptHandbackAborted
		}
	}

	// ctrld's rule is installed. Taking it out to test the external one is disruptive, so
	// it is throttled: an external rule that never routes would otherwise cost a brief
	// outage on every health tick. The check comes before the probe so a throttled tick
	// costs nothing, and the budget is only spent below, once the attempt is real.
	now := time.Now()
	if !state.handbackAllowed(now, ruleName, nrptHandbackRetryInterval) {
		return nrptHandbackAborted
	}

	// Pre-probe: this measures whatever routes DNS today, ctrld's own rule included, so
	// it can never prove anything about external policy - it only says whether there is a
	// working route here to risk. If nothing is routing there is nothing to protect and
	// nothing to compare against, so leave it to the heal cycle rather than start
	// deleting rules.
	if !ops.probe(state) {
		return nrptHandbackAborted
	}
	state.recordHandbackAttempt(now, ruleName, nrptHandbackRetryInterval)

	if err := ops.removeRule(); err != nil {
		mainLog.Load().Warn().Err(err).Str("rule", ruleName).Str("reason", reason).
			Msg("DNS intercept: GP catch-all found but ctrld's own rule could not be removed for the handback probe")
		return nrptHandbackAborted
	}
	ops.signal()
	if !ops.wait(state, nrptHandbackSettleDelay) {
		// Shutdown landed. NRPT is clean, which is the right state to leave behind.
		return nrptHandbackAborted
	}

	// Post-removal probe and classification, always - not only when the probe succeeded.
	// Group Policy can refresh during the probe, and what it changed into decides whether
	// restoring ctrld's rule is right or would create a sibling that must never be written.
	child, class, routes := p.externalAfterRemoval(ops, state, ruleName, reason)

	switch {
	case class == gpChildSameExact && routes:
		state.setNRPTPolicyOwner(nrptRuleOwnerGroupPolicy, child)
		state.nrptRecoveryLimiter.recordStableSuccess()
		mainLog.Load().Info().Str("rule", child).Str("listener", state.listenerIP).Str("reason", reason).
			Msg("DNS intercept: GP-managed catch-all carried DNS without ctrld's rule; returned NRPT ownership to Group Policy")
		return nrptHandbackVerified

	case class == gpChildConflicting:
		// The child changed into a catch-all that does not target ctrld. It owns the
		// namespace, so ctrld's rule stays off: restoring it here is exactly the
		// competing sibling beside administrator policy that is forbidden elsewhere.
		state.setNRPTPolicyOwner(nrptRuleOwnerNone, "")
		mainLog.Load().Error().Str("rule", ruleName).Str("reason", reason).
			Msg("DNS intercept: GP catch-all changed to one that does not target ctrld during the handback probe; leaving NRPT to Group Policy and not restoring the ctrld rule")
		return nrptHandbackConflict

	case class == gpChildSameExact && child != ruleName:
		// A different administrator catch-all took the namespace while ctrld's keys were
		// off, and its own pass says it is not routing yet. ctrld's rule still must not
		// come back: addNRPTCatchAllRule writes ctrld's GP catch-all whenever another GP
		// rule exists, so restoring would put a sibling beside a catch-all that was not
		// even there when this transition started. Record external ownership and let the
		// health monitor keep watching the new child.
		state.setNRPTPolicyOwner(nrptRuleOwnerGroupPolicy, child)
		mainLog.Load().Warn().Str("old_rule", ruleName).Str("rule", child).Str("reason", reason).
			Msg("DNS intercept: a different GP catch-all took the namespace during the handback probe and is not routing yet; leaving NRPT to Group Policy without restoring the ctrld rule")
		return nrptHandbackUnverified

	}

	// The original child is still exact but cannot carry DNS, or external policy is gone
	// altogether: ctrld's route is the one that has to come back. This only restores the
	// state the transition started from, so it creates no new sibling.
	if err := ops.addRule(state.listenerIP); err != nil {
		mainLog.Load().Error().Err(err).Str("rule", ruleName).
			Msg("DNS intercept: handback probe failed and the ctrld NRPT rule could not be restored; the health monitor will retry")
		state.setNRPTPolicyOwner(nrptRuleOwnerNone, "")
		return nrptHandbackAborted
	}
	ops.signal()
	state.setNRPTPolicyOwner(nrptRuleOwnerCtrld, "")
	if class == gpChildGone {
		mainLog.Load().Warn().Str("rule", ruleName).Str("reason", reason).
			Msg("DNS intercept: GP-managed catch-all disappeared during the handback probe; restored the ctrld fallback and kept ctrld ownership")
	} else {
		mainLog.Load().Warn().Str("rule", ruleName).Str("reason", reason).
			Msg("DNS intercept: GP-managed catch-all did not carry DNS without ctrld's rule; restored the ctrld fallback and kept ctrld ownership")
	}
	return nrptHandbackKeptCtrld
}

// gpChildClass is what an external NRPT catch-all looks like at the moment ctrld checks,
// which is not necessarily what it looked like when a probe was sent: Group Policy can
// refresh while the probe is in flight.
type gpChildClass int

const (
	// gpChildSameExact: the same child still names exactly this listener.
	gpChildSameExact gpChildClass = iota
	// gpChildReplaced: a different child now matches this listener exactly. It has not
	// proved anything yet, so it is not adopted on this pass.
	gpChildReplaced
	// gpChildConflicting: an administrator-owned catch-all is present that does not target
	// ctrld - another resolver, or malformed. ctrld must not write a rule beside it.
	gpChildConflicting
	// gpChildGone: no external catch-all owns the namespace any more.
	gpChildGone
)

// externalAfterRemoval probes external policy with ctrld's keys already gone, then says
// which child the result belongs to, what state that child is in, and whether it routed.
// It writes nothing: the caller decides what the verdict means.
//
// A probe result can only ever be attributed to the child that was on disk for the whole
// probe. When Group Policy swaps the child mid-probe the old result is void, so the
// replacement gets one pass of its own here rather than inheriting a verdict it never
// earned. Two passes is the limit; a store that keeps changing is reported as still
// churning so the caller can retry instead of guessing.
func (p *prog) externalAfterRemoval(ops nrptOps, state *wfpState, candidate, reason string) (string, gpChildClass, bool) {
	for pass := 0; pass < nrptHandbackProbePasses; pass++ {
		routes := ops.probe(state)
		class := p.classifyGPChild(ops, state, candidate, reason)
		if class != gpChildReplaced {
			return candidate, class, routes
		}
		if pass == nrptHandbackProbePasses-1 {
			break
		}
		next := ops.findGPRule(state.listenerIP)
		if next == "" {
			return candidate, gpChildGone, routes
		}
		mainLog.Load().Warn().Str("old_rule", candidate).Str("rule", next).Str("reason", reason).
			Msg("DNS intercept: a different GP catch-all appeared during the probe; testing that one instead")
		candidate = next
	}

	// The probe budget is spent and the store is still moving. Report the store as it is
	// now, with no route proved, rather than reporting churn: "undecided" would let
	// startup and owned recovery fall through to writing ctrld's rule, and
	// addNRPTCatchAllRule puts that in the GP path beside whatever exact catch-all is
	// there - the sibling that must never exist. Failing safe from the current store
	// keeps every outcome terminal for those callers unless the namespace is genuinely
	// free.
	mainLog.Load().Warn().Str("rule", candidate).Str("reason", reason).
		Msg("DNS intercept: GP catch-alls kept changing during the handback probe; classifying the store as it stands with no route proved")
	if current := ops.findGPRule(state.listenerIP); current != "" {
		return current, gpChildSameExact, false
	}
	if ops.gpConflicts(state, reason) {
		return candidate, gpChildConflicting, false
	}
	return candidate, gpChildGone, false
}

// classifyGPChild re-reads the GP store and says what state the external catch-all is in.
// Every post-probe decision goes through it, so a child that changed mid-probe can never
// be treated as the child that was measured.
func (p *prog) classifyGPChild(ops nrptOps, state *wfpState, ruleName, reason string) gpChildClass {
	if ops.gpRuleMatches(ruleName, state.listenerIP) {
		return gpChildSameExact
	}
	if other := ops.findGPRule(state.listenerIP); other != "" {
		return gpChildReplaced
	}
	if ops.gpConflicts(state, reason) {
		return gpChildConflicting
	}
	return gpChildGone
}

// nrptHandbackSettleDelay gives the DNS Client a moment to drop ctrld's removed rule
// before the handback probe decides whether external policy routes on its own.
const nrptHandbackSettleDelay = 1 * time.Second

// deferToExternalCatchAll stops ctrld-owned recovery when an administrator catch-all owns
// the namespace, and reports whether the caller must stop.
//
// It hands back where a verdict is possible. Where one is not - the handback needs a
// working route to compare against, and during a heal cycle there often is none - the
// presence of an exact external catch-all is itself the ownership signal, so ownership is
// recorded without proof and recovery stops anyway. Continuing would mean signalling the
// DNS Client, or deleting and recreating ctrld's rule, while administrator policy owns the
// namespace: the two things #576 forbids. The health monitor keeps testing the rule and
// can hand back properly once it routes.
func (p *prog) deferToExternalCatchAll(ops nrptOps, state *wfpState, reason string) bool {
	ruleName := ops.findGPRule(state.listenerIP)
	if ruleName == "" || !ops.gpRuleMatches(ruleName, state.listenerIP) {
		return false
	}

	switch result := p.nrptHandbackToExternal(state, ruleName, reason); {
	case result == nrptHandbackKeptCtrld:
		// The external rule was proved unable to carry DNS and ctrld's rule is back, so
		// owned recovery is exactly what should continue.
		return false
	case nrptExternalOwns(result):
		if result == nrptHandbackUnverified {
			p.healBlockedLoopbackDNS(state, reason)
		}
		return true
	default:
		state.setNRPTPolicyOwner(nrptRuleOwnerGroupPolicy, ruleName)
		mainLog.Load().Warn().Str("rule", ruleName).Str("reason", reason).
			Msg("DNS intercept: a GP catch-all owns the namespace but could not be tested; stopping ctrld-owned recovery and leaving external policy untouched")
		p.healBlockedLoopbackDNS(state, reason)
		return true
	}
}

// nrptExternalOwns reports whether a handback left external policy owning the namespace.
//
// All three outcomes count, not just Verified: an administrator's catch-all owns the
// namespace whether it routes to ctrld (Verified), does not route at all (Unverified), or
// points somewhere else entirely (Conflict). Each is terminal for ctrld-owned recovery,
// because continuing would signal the DNS Client and delete and recreate ctrld's rule
// beside that catch-all - the competing, ambiguous policy #576 exists to avoid. Where the
// external rule is present but ineffective, loopback WFP protect is the only remediation
// left.
func nrptExternalOwns(result nrptHandbackResult) bool {
	switch result {
	case nrptHandbackVerified, nrptHandbackUnverified, nrptHandbackConflict:
		return true
	default:
		return false
	}
}

// nrptTransition runs one complete NRPT mutation - write or delete, signal, record
// owner - with the transition lock held, and reports whether it ran.
//
// Checking interceptStateRevoked and then mutating is not enough on its own: a stop can
// land in between, revoke the state, remove NRPT and finish, after which the mutation
// would write a catch-all pointing at a listener that no longer exists. The stop takes
// this same lock around its own NRPT removal, so holding it across the whole
// observe-mutate-signal step is what makes the two mutually exclusive. Callers must keep
// probe backoffs outside fn: the lock is for a single transition, not for a heal cycle.
func (p *prog) nrptTransition(state *wfpState, fn func()) bool {
	p.nrptTransitionMu.Lock()
	defer p.nrptTransitionMu.Unlock()
	if p.interceptStateRevoked(state) {
		return false
	}
	fn()
	return true
}

func (p *prog) activateCtrldNRPTFallback(state *wfpState, reason string) bool {
	ops := p.nrptOps()

	// Close the observation-to-write race in both directions. Group Policy can refresh
	// between the monitor's missing-rule check and this call, and again between this
	// check and the write - so the write path re-checks under the transition lock and
	// sends us back here when a matching child has appeared. Two passes is enough: the
	// second either hands back or writes with the store checked under the lock.
	for attempt := 0; attempt < 2; attempt++ {
		if ruleName := ops.findGPRule(state.listenerIP); ruleName != "" &&
			ops.gpRuleMatches(ruleName, state.listenerIP) {
			// A matching child owns the namespace, so hand back rather than create a
			// sibling rule. The handback runs its own transition, so it cannot be called
			// with the lock held.
			if p.nrptHandbackToExternal(state, ruleName, reason) == nrptHandbackKeptCtrld {
				// The handback restored ctrld's rule, which is what this call wanted.
				return true
			}
			// Every other outcome means external policy owns the namespace, or that
			// nothing could be decided. Either way this must not write a rule beside it.
			return false
		}
		wrote, gpAppeared := p.writeCtrldFallback(ops, state, reason)
		if !gpAppeared {
			return wrote
		}
	}
	return false
}

// writeCtrldFallback writes ctrld's own catch-all under the transition lock. It reports
// whether it wrote, and whether it stood down because a matching GP child appeared - in
// which case the caller must take the handback path instead.
func (p *prog) writeCtrldFallback(ops nrptOps, state *wfpState, reason string) (wrote, gpAppeared bool) {
	p.nrptTransitionMu.Lock()
	defer p.nrptTransitionMu.Unlock()

	// Re-check under the transition lock. A retired state must not write NRPT policy:
	// shutdown has already removed the ctrld-owned catch-all, and re-adding it
	// afterwards leaves the DNS Client routing every query to a listener that no longer
	// exists - a machine-wide resolution outage, not a cosmetic leftover. Checking
	// before the lock cannot close that gap, because a stop can land between the check
	// and the write; the stop takes this same lock around its own NRPT removal.
	if p.interceptStateRevoked(state) {
		mainLog.Load().Debug().Str("reason", reason).
			Msg("DNS intercept: skipping ctrld NRPT fallback - intercept was retired")
		return false, false
	}
	// The same reasoning applies to the GP store, which the caller read before taking
	// this lock. gpConflicts alone does not cover it: findConflictingGPCatchAll skips a
	// *matching* child by design, so without this re-read a policy refresh inside that
	// window would let the write land beside an administrator catch-all that no probe has
	// tested.
	if ruleName := ops.findGPRule(state.listenerIP); ruleName != "" &&
		ops.gpRuleMatches(ruleName, state.listenerIP) {
		mainLog.Load().Info().Str("rule", ruleName).Str("reason", reason).
			Msg("DNS intercept: a matching GP catch-all appeared before the fallback write; handing back instead of writing beside it")
		return false, true
	}
	if ops.gpConflicts(state, reason) {
		return false, false
	}
	// Another health or delayed-recheck path may have written the rule while this one
	// waited for the lock; do not duplicate the write and the signalling.
	if ops.ruleExists() {
		state.setNRPTPolicyOwner(nrptRuleOwnerCtrld, "")
		mainLog.Load().Debug().Str("reason", reason).
			Msg("DNS intercept: ctrld NRPT rule was already restored by a concurrent transition")
		return false, false
	}
	if err := ops.addRule(state.listenerIP); err != nil {
		mainLog.Load().Error().Err(err).Str("reason", reason).
			Msg("DNS intercept: failed to activate ctrld-owned NRPT fallback; the health monitor will retry")
		state.setNRPTPolicyOwner(nrptRuleOwnerNone, "")
		return false, false
	}
	state.setNRPTPolicyOwner(nrptRuleOwnerCtrld, "")
	ops.signal()
	mainLog.Load().Warn().Str("reason", reason).
		Msg("DNS intercept: GP-managed catch-all unavailable - activated ctrld-owned NRPT fallback")
	return true, false
}

// tryAdoptMatchingGPNRPT hands NRPT ownership back to Group Policy when a matching
// external catch-all exists. It reports whether external policy now owns NRPT.
//
// The proof lives in nrptHandbackToExternal: a probe taken while ctrld's fallback is
// still installed proves nothing about the external rule, so the decision is always
// made with ctrld's keys removed.
func (p *prog) tryAdoptMatchingGPNRPT(state *wfpState) bool {
	if p.interceptStateRevoked(state) {
		return false
	}
	ruleName := p.nrptOps().findGPRule(state.listenerIP)
	if ruleName == "" {
		return false
	}
	switch p.nrptHandbackToExternal(state, ruleName, "matching GP-managed catch-all detected") {
	case nrptHandbackVerified:
		return true
	case nrptHandbackUnverified:
		// External policy owns the namespace but is not routing. ctrld must not write a
		// competing rule, so the only remediation left is loopback WFP protect. Report
		// external ownership: the caller must not fall through to owned recovery.
		p.healBlockedLoopbackDNS(state, "GP-managed catch-all owns the namespace but is not routing")
		return true
	case nrptHandbackConflict:
		// External policy now points somewhere other than ctrld. It owns the namespace,
		// so report external ownership: owned recovery must not write beside it.
		return true
	case nrptHandbackKeptCtrld:
		// The external rule could not carry DNS alone. A third-party WFP block dropping
		// DNS below NRPT looks exactly like this, so try the one remediation that leaves
		// external policy untouched; the next handback attempt can then succeed.
		p.healBlockedLoopbackDNS(state, "GP-managed catch-all did not carry DNS on its own")
		return false
	}
	return false
}

// nrptNeedsCtrldActivation reports whether ctrld should write its own NRPT catch-all,
// given who owns policy and whether a ctrld rule is currently present.
//
// Owner None is the interesting case: it means an earlier write failed. Nothing else
// re-arms it - nrptProbeAndHeal returns early without ctrld ownership, and the health
// monitor used to skip the owner-None tick entirely - so without retrying, the machine
// keeps no NRPT rule for the rest of the process lifetime. In hard mode that is a full
// DNS outage rather than degraded interception: WFP goes on blocking outbound DNS while
// nothing redirects it to ctrld, and only a restart recovers.
func nrptNeedsCtrldActivation(owner nrptRuleOwner, ruleExists bool) bool {
	switch owner {
	case nrptRuleOwnerNone:
		return true
	case nrptRuleOwnerCtrld:
		return !ruleExists
	default:
		// nrptRuleOwnerGroupPolicy: external policy owns the namespace, and a competing
		// ctrld catch-all beside it would be ambiguous policy, not recovery.
		return false
	}
}

// loopbackProtectSettleDelay gives WFP a moment to apply the loopback permits before
// the retry probe goes out.
const loopbackProtectSettleDelay = 500 * time.Millisecond

// healBlockedLoopbackDNS retries the NRPT probe from behind loopback WFP protection and
// reports whether the probe then succeeded.
//
// A failed probe does not always mean the NRPT rule is wrong. Third-party WFP filters -
// OpenVPN's block-outside-dns is the common one - can drop DNS below NRPT, so the
// policy is correct and the packets never arrive. Loopback protect is the one
// remediation that fixes this while leaving externally owned policy untouched. Without
// this attempt, a GP rule blocked that way is never adopted and never healed: the
// monitor keeps finding a "present but not routing" rule for the life of the process.
// It is also the only remediation ctrld may run while external policy owns NRPT.
// signalNRPTChange is not a content-neutral nudge - it forces machine Group Policy via
// RefreshPolicyEx, sends Dnscache paramchange and flushes the resolver cache - so #576's
// contract for a present-but-ineffective GP rule is a warning plus WFP-only retries, with
// no refresh/paramchange/flush loop.
func (p *prog) healBlockedLoopbackDNS(state *wfpState, reason string) bool {
	ops := p.nrptOps()
	if p.interceptStateRevoked(state) {
		return false
	}
	if hardIntercept {
		// Hard mode owns the whole sublayer; loopback protect deliberately does
		// nothing there, so a retry probe would only burn the probe timeout.
		return false
	}
	if err := ops.loopback(state); err != nil {
		mainLog.Load().Warn().Err(err).Str("reason", reason).
			Msg("DNS intercept: could not activate loopback WFP protect while retrying a failed probe")
		return false
	}
	if !ops.wait(state, loopbackProtectSettleDelay) {
		return false
	}
	if !ops.probe(state) {
		return false
	}
	mainLog.Load().Info().Str("reason", reason).
		Msg("DNS intercept: probe recovered behind loopback WFP protect - a third-party WFP block was dropping DNS below NRPT")
	return true
}

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
			ctx := ctrld.LoggerCtx(context.Background(), p.logger.Load())
			ctrld.InitializeOsResolver(ctx, true)
			if p.vpnDNS != nil {
				p.vpnDNS.Refresh(ctx, true)
			}

			// Delayed rechecks must respect NRPT ownership. The old path looked only
			// for ctrld's deterministic key, so it recreated that key immediately
			// after startup had correctly adopted a GP-managed catch-all.
			state, ok := p.dnsInterceptState.(*wfpState)
			if ok && !p.interceptStateRevoked(state) {
				owner, _ := state.nrptPolicyOwner()
				switch owner {
				case nrptRuleOwnerGroupPolicy:
					if findMatchingGPNRPTRule(state.listenerIP) == "" {
						if p.activateCtrldNRPTFallback(state, "matching GP rule disappeared during delayed network recheck") {
							go p.nrptProbeAndHeal(state)
						}
					}
				case nrptRuleOwnerNone, nrptRuleOwnerCtrld:
					if nrptNeedsCtrldActivation(owner, nrptCatchAllRuleExists()) {
						mainLog.Load().Warn().Msg("DNS intercept: no ctrld NRPT catch-all in place - re-adding")
						if p.activateCtrldNRPTFallback(state, "ctrld NRPT rule missing during delayed network recheck") {
							go p.nrptProbeAndHeal(state)
						}
					}
				}
			}

			// WFP watchdog: verify our sublayer still exists. If another program
			// or a crash removed it, the block filters are gone too. A timer that
			// fires during shutdown must not rebuild what teardown removed, so this
			// goes through rebuildDNSIntercept's ownership check.
			if ok && !p.interceptStateRevoked(state) && state.engineHandle != 0 && !wfpSublayerExists(state.engineHandle) {
				mainLog.Load().Warn().Msg("DNS intercept: WFP sublayer was removed externally — re-creating all filters")
				rebuildDNSInterceptFn(p, state, "WFP sublayer removed externally (delayed network recheck)")
			}
		})
	}
}

// repairMissingWFP re-creates the intercept when hard mode has no WFP enforcement -
// because the sublayer disappeared, or because the engine never opened in the first place.
// It reports whether the caller's monitor goroutine must stop.
func (p *prog) repairMissingWFP(state *wfpState) bool {
	// Never interrogate WFP for a retired state: shutdown deletes our sublayer, so a
	// tick landing in the shutdown window would read "missing" and try to rebuild what
	// stopDNSIntercept just removed.
	if p.interceptStateRevoked(state) {
		return true
	}

	reason := ""
	switch {
	case state.engineHandle == 0:
		// In dns mode a closed engine is the normal state: loopback protect opens one
		// only when it is needed. In hard mode it means startWFPFilters never got the
		// engine open, so nothing is being blocked at all. That is the state a startup
		// WFP failure leaves behind, and this is what retries it - without this entry
		// point the process would run unenforced for its whole life.
		if !hardIntercept {
			return false
		}
		reason = "hard mode has no WFP engine - enforcement never started"
	case wfpSublayerExists(state.engineHandle):
		return false
	default:
		reason = "WFP sublayer missing during health check"
	}

	mainLog.Load().Warn().Str("reason", reason).Msg("DNS intercept: WFP health check - re-initializing all filters")
	if rebuildDNSInterceptFn(p, state, reason) == interceptRebuildDone {
		mainLog.Load().Info().Msg("DNS intercept: WFP filters restored by health monitor")
	}
	return true
}

// nrptHealthMonitor periodically checks that the NRPT catch-all rule is still
// present and re-adds it if removed by VPN software or Group Policy updates.
// In hard mode, it also verifies the WFP sublayer exists and re-initializes
// all filters if they were removed.
//
// One monitor belongs to one intercept state, and it exits when that state is retired:
// nothing here may act on state after stopDNSIntercept or a rebuild has moved on.
func (p *prog) nrptHealthMonitor(state *wfpState) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-state.stopCh:
			return
		case <-ticker.C:
			// A tick and a shutdown can become ready together and select picks either,
			// so re-check before doing any health work for a retired intercept.
			if p.interceptStateRevoked(state) {
				return
			}
			owner, externalRuleName := state.nrptPolicyOwner()
			switch owner {
			case nrptRuleOwnerNone:
				// No owner means an earlier NRPT write failed. Nothing else re-arms
				// it - nrptProbeAndHeal returns early without ctrld ownership, and the
				// missing-rule branch below used to be unreachable from here - so
				// without this retry the machine keeps no NRPT rule for the rest of the
				// process lifetime. In hard mode that is a full DNS outage: WFP still
				// blocks outbound DNS while nothing redirects it to ctrld. Fall through
				// to the activation path below.
			case nrptRuleOwnerGroupPolicy:
				currentRule := p.nrptOps().findGPRule(state.listenerIP)
				if currentRule == "" {
					if p.activateCtrldNRPTFallback(state, "matching GP rule disappeared during health check") {
						go p.nrptProbeAndHeal(state)
					}
					continue
				}
				// Confirm through the handback transition so the verdict is always about
				// external policy alone, never about a ctrld rule left behind by an
				// earlier run that happens to answer the probe.
				switch p.nrptHandbackToExternal(state, currentRule, "GP-managed NRPT health check") {
				case nrptHandbackVerified:
					// Ownership and stable-success are recorded by the transition.
				case nrptHandbackKeptCtrld:
					// External policy could not carry DNS; ctrld owns the rule again.
					// The next tick continues as ctrld-owned.
				case nrptHandbackConflict:
					// The administrator's catch-all no longer targets ctrld. Nothing to
					// remediate: ctrld may not write beside it, and the conflict is
					// already logged by the transition.
				default:
					mainLog.Load().Warn().Str("rule", externalRuleName).
						Msg("DNS intercept: GP-managed NRPT rule is present but its probe failed; leaving external policy untouched")
					// The only remediation allowed over external policy: a third-party
					// WFP block dropping DNS below NRPT looks exactly like an ineffective
					// rule. No policy refresh, paramchange or cache flush here - see
					// healBlockedLoopbackDNS.
					if !p.healBlockedLoopbackDNS(state, "GP-managed NRPT rule present but not routing") {
						go p.nrptProbeAndHeal(state)
					}
				}
				if p.repairMissingWFP(state) {
					return
				}
				continue
			case nrptRuleOwnerCtrld:
				// Group Policy may have returned after ctrld activated its fallback.
				// Prefer the externally owned rule once it proves the same route without
				// ctrld's rule installed.
				if p.tryAdoptMatchingGPNRPT(state) {
					continue
				}
			}
			if nrptNeedsCtrldActivation(owner, nrptCatchAllRuleExists()) {
				now := time.Now()
				if ok, wait := state.nrptRecoveryLimiter.allow(now, p.cfg); !ok {
					if state.nrptRecoveryLimiter.shouldLogSkip(now) {
						mainLog.Load().Warn().Str("remaining", wait.String()).
							Msg("DNS intercept: NRPT rule restore suppressed after repeated recovery flows")
					}
					continue
				}
				reason := "ctrld-owned rule missing during health check"
				if owner == nrptRuleOwnerNone {
					reason = "no NRPT owner during health check - retrying a failed activation"
				}
				if p.activateCtrldNRPTFallback(state, reason) {
					state.nrptRecoveryLimiter.recordRecoveryFlow(time.Now(), p.cfg)
					go p.nrptProbeAndHeal(state)
				} else if owner == nrptRuleOwnerNone && hardIntercept {
					// Worth shouting about: hard mode keeps blocking outbound DNS
					// whether or not NRPT redirects it, so a machine stuck here has no
					// working resolver until activation succeeds.
					mainLog.Load().Error().
						Msg("DNS intercept: hard mode is blocking DNS but no NRPT rule could be activated - DNS will not resolve until this recovers")
				}
				continue
			}

			if !p.nrptOps().probe(state) {
				mainLog.Load().Warn().Msg("DNS intercept: ctrld-owned NRPT rule present but probe failed, running heal cycle")
				go p.nrptProbeAndHeal(state)
			} else {
				state.nrptRecoveryLimiter.recordStableSuccess()
			}

			if p.repairMissingWFP(state) {
				return // our state was retired: shutdown, or a rebuild that started a new monitor
			}
		}
	}
}

// pfInterceptMonitor is a no-op on Windows — WFP filters are kernel objects
// and don't suffer from the pf translation state corruption that macOS has.
func (p *prog) pfInterceptMonitor() {}

// reconcileForwardedSources is a no-op on Windows — forwarded-workload DNS
// interception is macOS-pf-only; Windows Firewall Mode is tracked separately.
func (p *prog) reconcileForwardedSources() {}

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
// Returns true if NRPT is verified working, false if the probe timed out or a shutdown
// arrived first. Reporting an abandoned probe as "not working" is safe: every recovery
// action a failed probe can trigger checks for revocation before it writes anything.
//
// state is passed explicitly rather than read from p.dnsInterceptState so that startup
// can probe before it publishes, and so a probe belongs to exactly one intercept.
func (p *prog) probeNRPT(state *wfpState) bool {
	if state == nil {
		return true
	}

	// Generate unique probe domain to defeat DNS caching.
	probeID := fmt.Sprintf("_nrpt-probe-%x.%s", rand.Uint32(), nrptProbeDomain)

	// Register this attempt's own domain so overlapping probes - a health tick, a
	// handback and a heal cycle can each have one out - cannot cancel each other.
	probeCh, deregister := p.registerInterceptProbe(probeID)
	defer deregister()

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

	// Poll for a pending stop so a service stop never waits out the probe timeout on
	// top of the lifecycle lock.
	shutdownPoll := time.NewTicker(interceptRevocationPollInterval)
	defer shutdownPoll.Stop()
	for {
		select {
		case <-probeCh:
			mainLog.Load().Debug().Str("domain", probeID).Msg("DNS intercept: NRPT probe received - interception verified")
			return true
		case <-ctx.Done():
			mainLog.Load().Debug().Str("domain", probeID).Msg("DNS intercept: NRPT probe timed out - interception not working")
			return false
		case <-shutdownPoll.C:
			if p.interceptStateRevoked(state) {
				mainLog.Load().Debug().Str("domain", probeID).Msg("DNS intercept: abandoning NRPT probe - shutdown in progress")
				return false
			}
		}
	}
}

// nrptProbeAndHeal runs the NRPT probe with retries and escalating remediation.
// Called asynchronously after startup and from the health monitor.
//
// Retry sequence:
//  1. Immediate probe.
//  2. If the GP parent is empty, clean it immediately, signal once, then probe.
//     This is intentionally before the normal retry loop: policy refresh and
//     Dnscache paramchange cannot make local rules visible while GP mode is
//     selected by an empty GP parent.
//  3. Otherwise, signal DNS Client with increasing backoff between probes.
//
// state is passed in rather than read from p.dnsInterceptState: this runs from the
// locked start path before anything is published, and it must keep acting on the
// intercept it was launched for and no other.
// It reports whether the cycle ended with a probe that reached ctrld. Callers that need a
// readiness answer - startup's synchronous verification - use that; the asynchronous
// callers ignore it.
func (p *prog) nrptProbeAndHeal(state *wfpState) bool {
	if p.interceptStateRevoked(state) {
		return false
	}
	if !nrptProbeRunning.CompareAndSwap(false, true) {
		mainLog.Load().Debug().Msg("DNS intercept: NRPT probe already running, skipping")
		return false
	}
	defer nrptProbeRunning.Store(false)

	ops := p.nrptOps()
	owner, externalRuleName := state.nrptPolicyOwner()
	if owner == nrptRuleOwnerGroupPolicy {
		currentRule := ops.findGPRule(state.listenerIP)
		if currentRule == "" {
			if !p.activateCtrldNRPTFallback(state, "matching GP rule disappeared before verification") {
				return false
			}
			owner = nrptRuleOwnerCtrld
		} else {
			switch p.nrptHandbackToExternal(state, currentRule, "GP-managed NRPT verification") {
			case nrptHandbackVerified:
				mainLog.Load().Info().Str("rule", currentRule).
					Msg("DNS intercept: GP-managed NRPT verified working")
				return true
			case nrptHandbackKeptCtrld:
				// External policy could not carry DNS without ctrld's rule, which the
				// transition has restored. Continue as the ctrld-owned flow below.
				owner = nrptRuleOwnerCtrld
			case nrptHandbackConflict:
				// External policy owns the namespace and points elsewhere. Owned recovery
				// must not write beside it, so this heal cycle ends here.
				return false
			default:
				if ops.findGPRule(state.listenerIP) == "" {
					// The GP child went away while we were looking at it.
					if !p.activateCtrldNRPTFallback(state, "matching GP rule disappeared during verification") {
						return false
					}
					owner = nrptRuleOwnerCtrld
					break
				}
				// A matching external rule owns the GP store, so ctrld may not rewrite
				// policy or signal the DNS Client here. Loopback WFP protect is the one
				// ctrld-owned remediation left: a third-party WFP block dropping DNS
				// below NRPT presents exactly as an ineffective rule.
				if p.healBlockedLoopbackDNS(state, "GP-managed NRPT present but not routing") {
					mainLog.Load().Info().Str("rule", currentRule).
						Msg("DNS intercept: GP-managed NRPT verified after loopback WFP protection")
					return true
				}
				mainLog.Load().Error().Str("rule", externalRuleName).
					Msg("DNS intercept: GP-managed NRPT remains present but ineffective; no NRPT recovery actions were taken")
				return false
			}
		}
	}
	if owner != nrptRuleOwnerCtrld {
		return false
	}

	now := time.Now()
	if ok, wait := state.nrptRecoveryLimiter.allow(now, p.cfg); !ok {
		if state.nrptRecoveryLimiter.shouldLogSkip(now) {
			mainLog.Load().Warn().Str("remaining", wait.String()).
				Msg("DNS intercept: NRPT recovery suppressed after repeated failed recovery flows")
		}
		return false
	}

	remediated := false
	defer func() {
		if remediated && state != nil {
			state.nrptRecoveryLimiter.recordRecoveryFlow(time.Now(), p.cfg)
		}
	}()

	mainLog.Load().Info().Msg("DNS intercept: starting NRPT verification probe sequence")

	// Log parent key state for diagnostics.
	logNRPTParentKeyState("probe-start")

	// Attempt 1: immediate probe
	if ops.probe(state) {
		mainLog.Load().Info().Msg("DNS intercept: NRPT verified working")
		return true
	}
	// Group Policy can appear while a ctrld-owned heal is running. Once an exact
	// administrator catch-all is there, this cycle stops: everything below signals the
	// DNS Client or rewrites ctrld's rule, and neither may happen beside external policy.
	if p.deferToExternalCatchAll(ops, state, "GP catch-all appeared during ctrld recovery") {
		mainLog.Load().Warn().Msg("DNS intercept: matching GP catch-all present during ctrld recovery; stopping NRPT mutations and deferring to Group Policy")
		return false
	}
	remediated = true

	// If the GP parent exists but is empty, do not burn retries on Windows
	// signaling. Those retries create SIEM noise but cannot succeed because DNS
	// Client is still reading the empty GP store instead of the populated local
	// store. Delete the blocker, send one notification, then re-probe.
	if ops.parentEmpty(nrptBaseKey) {
		mainLog.Load().Warn().Msg("DNS intercept: NRPT probe failed with empty GP parent — cleaning before retry signaling")
		if ops.cleanParent() {
			ops.signal()
			if !ops.wait(state, nrptHandbackSettleDelay) {
				return false
			}
			logNRPTParentKeyState("empty-gp-after-clean")
			if ops.probe(state) {
				mainLog.Load().Info().Msg("DNS intercept: NRPT verified working after empty GP parent cleanup")
				return true
			}
		}
		if ops.parentEmpty(nrptBaseKey) {
			mainLog.Load().Warn().Msg("DNS intercept: empty GP NRPT parent still present after cleanup; skipping redundant policy refresh retries")
			return false
		}
	}

	// Attempts 2-4: signal DNS Client with increasing backoff between probes.
	delays := []time.Duration{1 * time.Second, 2 * time.Second, 4 * time.Second}
	for i, delay := range delays {
		attempt := i + 2
		// Each round signals Windows and then waits; a stop must not have the whole
		// remaining backoff added to the time it waits for the lifecycle lock.
		if p.interceptStateRevoked(state) {
			mainLog.Load().Debug().Int("attempt", attempt).
				Msg("DNS intercept: intercept retired - abandoning NRPT probe retries")
			return false
		}
		mainLog.Load().Info().Int("attempt", attempt).Str("delay", delay.String()).
			Msg("DNS intercept: NRPT probe failed, retrying with policy refresh + paramchange")
		logNRPTParentKeyState(fmt.Sprintf("probe-attempt-%d", attempt))
		ops.signal()
		if !ops.wait(state, delay) {
			return false
		}
		if ops.probe(state) {
			mainLog.Load().Info().Int("attempt", attempt).
				Msg("DNS intercept: NRPT verified working")
			return true
		}
	}

	// Re-check external ownership before the destructive two-phase recovery. A GP refresh
	// can land during the bounded retry waits above, and the delete half of that recovery
	// must not run once it has: it would strand the machine mid-recovery under policy
	// ctrld does not own.
	if p.deferToExternalCatchAll(ops, state, "GP catch-all appeared during ctrld retries") {
		mainLog.Load().Warn().Msg("DNS intercept: matching GP catch-all present after the retries; skipping ctrld two-phase recovery")
		return false
	}
	if gpCatchAllConflictBlocksFallback(state, "GP catch-all changed during ctrld recovery") {
		return false
	}

	// A stop can land during the retry waits above, and its own NRPT removal has
	// already run: deleting and re-adding from here would leave the rule behind.
	if p.interceptStateRevoked(state) {
		mainLog.Load().Debug().Msg("DNS intercept: intercept retired during probe retries - skipping two-phase NRPT recovery")
		return false
	}

	// Nuclear option: two-phase delete → re-add cycle.
	// DNS Client may have cached a stale "no rules" state. Delete our rule,
	// signal DNS Client to forget it, wait, then re-add and signal again.
	mainLog.Load().Warn().Msg("DNS intercept: all probes failed — attempting two-phase NRPT recovery (delete → signal → re-add)")
	listenerIP := state.listenerIP

	// Phase 1: Remove our rule and the parent key if now empty. Each phase is its own
	// transition: serialized against a stop and against other NRPT writers, but the lock
	// is released across the wait between them.
	if !p.nrptTransition(state, func() {
		_ = ops.removeRule()
		// If parent key is now empty after removing our rule, delete it too.
		ops.cleanParent()
		ops.signal()
		logNRPTParentKeyState("nuclear-after-delete")
	}) {
		mainLog.Load().Debug().Msg("DNS intercept: intercept retired - skipping two-phase NRPT recovery")
		return false
	}

	// Wait for DNS Client to process the deletion. Stopping here is the clean outcome:
	// phase 1 left no ctrld rule behind.
	if !ops.wait(state, nrptHandbackSettleDelay) {
		mainLog.Load().Debug().Msg("DNS intercept: intercept retired mid-recovery - leaving NRPT removed")
		return false
	}

	// Group Policy may refresh while the ctrld-owned rule is absent. Never re-create our
	// catch-all beside a newly authoritative GP catch-all. With ctrld's rule already
	// gone, this is the one place a probe measures external policy on its own.
	if p.deferToExternalCatchAll(ops, state, "GP catch-all appeared during two-phase recovery") {
		mainLog.Load().Warn().Msg("DNS intercept: matching GP catch-all appeared during two-phase recovery; skipping ctrld re-add")
		return false
	}
	if ops.gpConflicts(state, "GP catch-all appeared during two-phase recovery") {
		return false
	}

	// Phase 2: Re-add the rule. Phase 1 left NRPT clean, so if a stop arrived during the
	// wait the transition refuses and the host stays clean.
	readded := false
	if !p.nrptTransition(state, func() {
		// Re-validate the ownership picture here, inside the lock. The checks above ran
		// before this transition queued for nrptTransitionMu, and another health or
		// delayed path can complete a whole handback while this one waits: it may have
		// given the namespace to a GP child that arrived meanwhile and recorded
		// GroupPolicy. Re-adding on top of that would plant the competing catch-all this
		// work exists to prevent, and then stamp ctrld ownership over the administrator's.
		if owner, ruleName := state.nrptPolicyOwner(); owner == nrptRuleOwnerGroupPolicy {
			mainLog.Load().Warn().Str("rule", ruleName).
				Msg("DNS intercept: ownership moved to Group Policy while the two-phase re-add waited for the transition lock; leaving NRPT to external policy")
			return
		}
		if ruleName := ops.findGPRule(state.listenerIP); ruleName != "" &&
			ops.gpRuleMatches(ruleName, state.listenerIP) {
			mainLog.Load().Warn().Str("rule", ruleName).
				Msg("DNS intercept: a matching GP catch-all appeared while the two-phase re-add waited for the transition lock; skipping the ctrld re-add")
			return
		}
		if ops.gpConflicts(state, "two-phase re-add revalidation") {
			return
		}
		if err := ops.addRule(listenerIP); err != nil {
			mainLog.Load().Error().Err(err).Msg("DNS intercept: failed to re-add NRPT after nuclear recovery")
			return
		}
		ops.signal()
		state.setNRPTPolicyOwner(nrptRuleOwnerCtrld, "")
		logNRPTParentKeyState("nuclear-after-readd")
		readded = true
	}) || !readded {
		mainLog.Load().Debug().Msg("DNS intercept: two-phase recovery did not restore the ctrld NRPT rule")
		return false
	}

	// Final probe after recovery.
	if !ops.wait(state, nrptHandbackSettleDelay) {
		// This cycle is retired. Do not clean up from here: the deterministic ctrld key is
		// process-global, and by now it can belong to a successor intercept that a rebuild
		// started while this goroutine waited - deleting it would take out the successor's
		// route and leave hard mode blocking DNS with nothing redirecting it. Teardown of
		// the state this cycle belonged to already owns that cleanup.
		mainLog.Load().Debug().Msg("DNS intercept: intercept retired after the two-phase re-add - leaving cleanup to the owning teardown")
		return false
	}
	if ops.probe(state) {
		mainLog.Load().Info().Msg("DNS intercept: NRPT verified working after two-phase recovery")
		return true
	}

	logNRPTParentKeyState("probe-failed-final")
	mainLog.Load().Warn().Msg("DNS intercept: NRPT verification failed after all retries including two-phase recovery")

	// Last resort: activate WFP loopback protection.
	// Third-party VPN software (e.g., OpenVPN with block-outside-dns) may have
	// installed WFP filters that block DNS to non-tunnel interfaces, including
	// loopback. A high-priority "hard permit" for localhost DNS overrides these
	// blocks and restores NRPT routing to ctrld's listener.
	// Bail out if shutdown is in progress — avoid racing with cleanupWFPFilters.
	if p.interceptStateRevoked(state) {
		mainLog.Load().Info().Msg("DNS intercept: shutdown in progress, skipping loopback WFP protect activation")
		return false
	}

	if err := p.activateLoopbackWFPProtect(state); err != nil {
		mainLog.Load().Error().Err(err).Msg("DNS intercept: failed to activate loopback WFP protect — " +
			"DNS queries may not be routed through ctrld. A network interface toggle may be needed.")
		return false
	}

	// Retry NRPT probe now that loopback DNS is explicitly permitted through WFP.
	if !ops.wait(state, loopbackProtectSettleDelay) {
		return false
	}
	if ops.probe(state) {
		mainLog.Load().Info().Msg("DNS intercept: NRPT verified working after loopback WFP protect activation")
		return true
	}
	mainLog.Load().Error().Msg("DNS intercept: NRPT probe still failing after loopback WFP protect — " +
		"DNS queries may not be routed through ctrld. A network interface toggle may be needed.")
	return false
}
