//go:build windows

package cli

import (
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// wfpFirewallState holds the state for WFP-based firewall mode enforcement on Windows.
// When firewall mode is active, we add dynamic WFP permit filters for each allowed IP
// on top of a block-all base filter.
type wfpFirewallState struct {
	mu sync.Mutex

	// pendingAdds and pendingRemoves accumulate changes for batched WFP updates.
	pendingAdds    []netip.Addr
	pendingRemoves []netip.Addr

	// batchTimer fires after the accumulation window to flush pending changes.
	batchTimer *time.Timer

	// filterMap tracks WFP filter IDs for each dynamically allowed IP so we can remove them.
	// Maps IP string → WFP filter ID.
	filterMap map[string]uint64

	// permanentFilterMap tracks permit filters for permanent allowlist entries
	// (loopback/private/link-local/listener/upstream IPs). These stay installed
	// across dynamic allowlist flushes.
	permanentFilterMap map[string]uint64

	// exceptionFilterMap tracks permit filters for the organization's Allowed
	// Destination IP list, keyed by prefix string. Kept apart from filterMap so
	// the flushes that discard DNS-resolved IPs leave them installed, and apart
	// from permanentFilterMap because entries are removed when the organization
	// removes them. Guarded by mu.
	//
	// Known gap, shared with filterMap and permanentFilterMap: rebuildDNSIntercept
	// recreates the WFP engine without re-initializing this state, so after a
	// health-monitor repair every ID here refers to a filter in a session that is
	// gone. Mirroring then fails for good and allowed_destinations_pending stays
	// non-zero until the service restarts. Predates the allowed-destination work
	// and wants its own fix - re-initializing platform firewall state as part of
	// the rebuild - rather than a patch here.
	exceptionFilterMap map[string]uint64

	// blockFilterIDv4 and blockFilterIDv6 are the base block-all filters.
	blockFilterIDv4 uint64
	blockFilterIDv6 uint64

	// engineHandle is the WFP engine handle from the intercept state.
	engineHandle uintptr
}

const (
	// wfpFirewallBatchInterval is the accumulation window for batching WFP filter updates.
	wfpFirewallBatchInterval = 200 * time.Millisecond
)

// firewallFlushPlatform removes all dynamic WFP permit filters on Windows.
// Called on network changes and config reloads before the in-memory allowlist is flushed.
func (p *prog) firewallFlushPlatform() {
	fwState, ok := p.platformFirewallState.(*wfpFirewallState)
	if !ok || fwState == nil {
		return
	}
	fwState.flushAll(p)
}

// shutdownPlatformFirewall removes Windows firewall-mode WFP filters, including
// dynamic permits, permanent permits, and the base block-all filters.
func (p *prog) shutdownPlatformFirewall() {
	fwState, ok := p.platformFirewallState.(*wfpFirewallState)
	if !ok || fwState == nil {
		return
	}
	fwState.shutdown(p)
}

// initPlatformFirewall initializes Windows-specific firewall enforcement (WFP filters).
func (p *prog) initPlatformFirewall() {
	if fwState, ok := p.platformFirewallState.(*wfpFirewallState); ok && fwState != nil {
		// A reload re-enters here with enforcement already up, to install permits
		// for permanent entries added since - a newly resolved API address, say -
		// which AddPermanent records in memory without any callback that would
		// reach WFP. Both populate calls skip what they already hold, so this is a
		// refresh rather than a reinstall.
		fwState.populatePermanentFilters(p)
		// The filter IDs this state holds describe whatever engine session
		// installed them, which after a rebuildDNSIntercept is not the live one -
		// so ask for a full replace instead of a delta against a snapshot that may
		// describe filters that no longer exist. markDestinationsForResync is
		// idempotent and cheap, and an unnecessary replace is a no-op the mirrors
		// already tolerate.
		p.markDestinationsForResync()
		p.reconcileAllowedDestinations()
		fwState.populateFilters(p)
		return
	}

	if !hardIntercept || p.dnsInterceptState == nil {
		p.Info().Msg("Firewall: WFP enforcement requires hard intercept mode")
		return
	}

	state, ok := p.dnsInterceptState.(*wfpState)
	if !ok || state == nil {
		p.Warn().Msg("Firewall: could not access WFP state for firewall enforcement")
		return
	}

	fwState := &wfpFirewallState{
		filterMap:          make(map[string]uint64),
		permanentFilterMap: make(map[string]uint64),
		exceptionFilterMap: make(map[string]uint64),
		engineHandle:       state.engineHandle,
	}
	p.platformFirewallState = fwState

	// Install base block-all outbound filters. We add our firewall filters to the
	// SAME sublayer as DNS intercept with carefully chosen weights:
	//   - Existing DNS permits (localhost): weight 10 (highest, evaluated first)
	//   - Firewall IP permits: weight 5 (middle)
	//   - Existing DNS block: weight 1 (blocks non-localhost DNS)
	//   - Firewall block-all: weight 1 (catch-all for non-DNS)
	//
	// WFP evaluates higher weights first within a sublayer. DNS permits at 10
	// always win, ensuring DNS resolution works. Firewall IP permits at 5
	// override the block-all for resolved IPs. The existing DNS block at 1
	// and our block-all at 1 are both catch-alls (DNS block has port 53
	// conditions so it only catches DNS; our block-all has no conditions
	// so it catches everything else).
	if err := p.addWFPFirewallBlockFilters(fwState); err != nil {
		p.Error().Err(err).Msg("Firewall: failed to install WFP block-all filters")
		return
	}

	// Install permits for the permanent allowlist before enabling dynamic updates.
	// Without these, the block-all filters would also block ctrld upstreams,
	// listener/loopback traffic, LAN ranges, and other permanent exceptions.
	fwState.populatePermanentFilters(p)

	// The organization's allowed destinations are applied as soon as the allowlist
	// exists, which is before WFP enforcement comes up. This session holds no
	// filters of its own yet, so mark the set for a full install and let the
	// reconcile put it in - and retry it if WFP refuses.
	p.markDestinationsForResync()
	p.reconcileAllowedDestinations()

	// Register batch callback.
	p.allowList.SetOnBatchChange(func(added []netip.Addr, removed []netip.Addr) {
		fwState.mu.Lock()
		defer fwState.mu.Unlock()

		if len(added) > 0 {
			fwState.pendingAdds = append(fwState.pendingAdds, added...)
		}
		if len(removed) > 0 {
			fwState.pendingRemoves = append(fwState.pendingRemoves, removed...)
		}
		fwState.scheduleBatchFlush(p)
	})

	// Register individual change callback.
	p.allowList.SetOnChange(func(ip netip.Addr, isAdded bool) {
		fwState.mu.Lock()
		defer fwState.mu.Unlock()

		if isAdded {
			fwState.pendingAdds = append(fwState.pendingAdds, ip)
		} else {
			fwState.pendingRemoves = append(fwState.pendingRemoves, ip)
		}
		fwState.scheduleBatchFlush(p)
	})

	// DNS responses may have populated the allowlist before platform callbacks
	// were registered. Add permit filters for that snapshot so WFP starts with
	// the same view as the in-memory allowlist.
	fwState.populateFilters(p)

	p.Info().Msg("Firewall: WFP enforcement initialized with block-all base filters")
}

// scheduleBatchFlush starts or resets the batch timer. Must be called with fwState.mu held.
func (s *wfpFirewallState) scheduleBatchFlush(p *prog) {
	if s.batchTimer != nil {
		return
	}
	s.batchTimer = time.AfterFunc(wfpFirewallBatchInterval, func() {
		s.flushBatch(p)
	})
}

// flushBatch applies accumulated WFP filter changes.
func (s *wfpFirewallState) flushBatch(p *prog) {
	s.mu.Lock()
	defer s.mu.Unlock()

	adds := s.pendingAdds
	removes := s.pendingRemoves
	s.pendingAdds = nil
	s.pendingRemoves = nil
	s.batchTimer = nil

	// Collapse add/remove deltas into the current primary allowlist state. This
	// avoids leaving WFP opposite the allowlist when an Add and Remove for the
	// same IP land in one batch window.
	ipsToSync := make(map[netip.Addr]struct{}, len(adds)+len(removes))
	for _, ip := range adds {
		ipsToSync[ip] = struct{}{}
	}
	for _, ip := range removes {
		ipsToSync[ip] = struct{}{}
	}

	for ip := range ipsToSync {
		key := ip.String()
		allowed := p.allowList != nil && p.allowList.Contains(ip)
		if !allowed {
			s.removePermitFilterLocked(p, key)
			continue
		}

		if _, exists := s.filterMap[key]; exists {
			continue // Already has a permit filter.
		}

		filterID, err := p.addWFPFirewallPermitFilter(s, ip)
		if err != nil {
			p.Warn().Err(err).Msgf("Firewall: failed to add WFP permit filter for %s", key)
			continue
		}
		s.filterMap[key] = filterID
		p.Debug().Msgf("Firewall: added WFP permit filter for %s (ID: %d)", key, filterID)
	}
}

// removePermitFilterLocked removes one dynamic WFP permit filter. s.mu must be held.
func (s *wfpFirewallState) removePermitFilterLocked(p *prog, key string) {
	filterID, ok := s.filterMap[key]
	if !ok {
		return
	}
	r1, _, _ := procFwpmFilterDeleteById0.Call(s.engineHandle, uintptr(filterID))
	if r1 != 0 {
		p.Debug().Msgf("Firewall: failed to remove WFP filter for %s (HRESULT 0x%x, may already be gone)", key, r1)
	} else {
		p.Debug().Msgf("Firewall: removed WFP permit filter for %s", key)
	}
	delete(s.filterMap, key)
}

// flushAll synchronously removes every dynamic WFP permit filter and clears any
// queued batch work. The block-all filters stay installed.
func (s *wfpFirewallState) flushAll(p *prog) {
	s.mu.Lock()
	if s.batchTimer != nil {
		s.batchTimer.Stop()
		s.batchTimer = nil
	}
	s.pendingAdds = nil
	s.pendingRemoves = nil

	filters := make(map[string]uint64, len(s.filterMap))
	for key, filterID := range s.filterMap {
		filters[key] = filterID
	}
	s.filterMap = make(map[string]uint64)
	s.mu.Unlock()

	for key, filterID := range filters {
		r1, _, _ := procFwpmFilterDeleteById0.Call(s.engineHandle, uintptr(filterID))
		if r1 != 0 {
			p.Debug().Msgf("Firewall: failed to remove WFP filter for %s during flush (HRESULT 0x%x, may already be gone)", key, r1)
		} else {
			p.Debug().Msgf("Firewall: removed WFP permit filter for %s during flush", key)
		}
	}
}

// shutdown removes every WFP filter owned by firewall mode.
func (s *wfpFirewallState) shutdown(p *prog) {
	s.flushAll(p)

	s.mu.Lock()
	permanentFilters := make(map[string]uint64, len(s.permanentFilterMap))
	for key, filterID := range s.permanentFilterMap {
		permanentFilters[key] = filterID
	}
	s.permanentFilterMap = make(map[string]uint64)

	exceptionFilters := make(map[string]uint64, len(s.exceptionFilterMap))
	for key, filterID := range s.exceptionFilterMap {
		exceptionFilters[key] = filterID
	}
	s.exceptionFilterMap = make(map[string]uint64)

	blockIDs := []uint64{s.blockFilterIDv4, s.blockFilterIDv6}
	s.blockFilterIDv4 = 0
	s.blockFilterIDv6 = 0
	s.mu.Unlock()

	for key, filterID := range permanentFilters {
		if r1, _, _ := procFwpmFilterDeleteById0.Call(s.engineHandle, uintptr(filterID)); r1 != 0 {
			p.Debug().Msgf("Firewall: failed to remove permanent WFP filter for %s during shutdown (HRESULT 0x%x, may already be gone)", key, r1)
		}
	}
	for key, filterID := range exceptionFilters {
		if r1, _, _ := procFwpmFilterDeleteById0.Call(s.engineHandle, uintptr(filterID)); r1 != 0 {
			p.Debug().Msgf("Firewall: failed to remove allowed destination WFP filter for %s during shutdown (HRESULT 0x%x, may already be gone)", key, r1)
		}
	}
	for _, filterID := range blockIDs {
		if filterID == 0 {
			continue
		}
		if r1, _, _ := procFwpmFilterDeleteById0.Call(s.engineHandle, uintptr(filterID)); r1 != 0 {
			p.Debug().Msgf("Firewall: failed to remove WFP block filter %d during shutdown (HRESULT 0x%x, may already be gone)", filterID, r1)
		}
	}
}

// populatePermanentFilters mirrors the in-memory permanent allowlist into WFP
// permit filters so the base block-all rule does not block ctrld itself, local
// network traffic, or upstream resolver endpoints.
func (s *wfpFirewallState) populatePermanentFilters(p *prog) {
	if p.allowList == nil {
		return
	}
	addrs, prefixes := p.allowList.PermanentEntries()

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, ip := range addrs {
		key := "addr:" + ip.String()
		if _, exists := s.permanentFilterMap[key]; exists {
			continue
		}
		filterID, err := p.addWFPFirewallPermitFilter(s, ip)
		if err != nil {
			p.Warn().Err(err).Msgf("Firewall: failed to add permanent WFP permit for %s", ip)
			continue
		}
		s.permanentFilterMap[key] = filterID
		p.Debug().Msgf("Firewall: added permanent WFP permit for %s (ID: %d)", ip, filterID)
	}

	for _, prefix := range prefixes {
		key := "prefix:" + prefix.String()
		if _, exists := s.permanentFilterMap[key]; exists {
			continue
		}
		filterID, err := p.addWFPFirewallPermitPrefix(s, prefix)
		if err != nil {
			p.Warn().Err(err).Msgf("Firewall: failed to add permanent WFP permit for %s", prefix)
			continue
		}
		s.permanentFilterMap[key] = filterID
		p.Debug().Msgf("Firewall: added permanent WFP permit for %s (ID: %d)", prefix, filterID)
	}
}

// fwpErrFilterNotFound is FWP_E_FILTER_NOT_FOUND: the filter is already gone, so
// a delete that reports it has achieved what it was asked to do.
const fwpErrFilterNotFound = 0x80320003

// firewallApplyExceptionsPlatform mirrors a change to the organization's Allowed
// Destination IP list into WFP permit filters, reporting whether WFP took it.
//
// An error - including "WFP enforcement is not up yet", because there is no
// engine handle to install filters through - leaves the caller's applied snapshot
// unadvanced, so the same delta is retried later.
func (p *prog) firewallApplyExceptionsPlatform(added, removed []netip.Prefix) error {
	fwState, ok := p.platformFirewallState.(*wfpFirewallState)
	if !ok || fwState == nil {
		return errors.New("WFP firewall enforcement is not initialized")
	}
	return fwState.syncExceptionFilters(p, added, removed)
}

// firewallReplaceExceptionsPlatform makes WFP hold permit filters for exactly
// desired, whatever it held before, and reports whether it took.
//
// This is what runs when WFP enforcement starts. A fresh session holds nothing,
// but the session can also be re-initialized over state this process installed
// earlier, so anything not in desired is removed rather than assumed absent.
func (p *prog) firewallReplaceExceptionsPlatform(desired []netip.Prefix) error {
	fwState, ok := p.platformFirewallState.(*wfpFirewallState)
	if !ok || fwState == nil {
		return errors.New("WFP firewall enforcement is not initialized")
	}
	return fwState.syncExceptionFilters(p, desired, fwState.exceptionsNotIn(desired))
}

// exceptionsNotIn returns the prefixes WFP currently permits that are absent from
// keep, i.e. the filters a full resync has to remove.
func (s *wfpFirewallState) exceptionsNotIn(keep []netip.Prefix) []netip.Prefix {
	kept := make(map[string]struct{}, len(keep))
	for _, prefix := range keep {
		kept[prefix.String()] = struct{}{}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var out []netip.Prefix
	for key := range s.exceptionFilterMap {
		if _, ok := kept[key]; ok {
			continue
		}
		prefix, err := netip.ParsePrefix(key)
		if err != nil {
			continue
		}
		out = append(out, prefix)
	}
	return out
}

// syncExceptionFilters installs permit filters for added prefixes and removes the
// filters of removed ones. Permits use the same weight as dynamically allowed
// IPs, so they override the base block-all filter while still losing to the
// higher-weighted DNS permits.
//
// A filter whose deletion failed keeps its ID in the map: dropping it would leak
// a permit that no longer belongs to any allowed destination and that nothing
// could ever remove, while the returned error keeps the withdrawal pending so the
// next reconcile retries the same deletion.
func (s *wfpFirewallState) syncExceptionFilters(p *prog, added, removed []netip.Prefix) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var errs []error

	for _, prefix := range removed {
		key := prefix.String()
		filterID, ok := s.exceptionFilterMap[key]
		if !ok {
			continue
		}
		if r1, _, _ := procFwpmFilterDeleteById0.Call(s.engineHandle, uintptr(filterID)); r1 != 0 && r1 != fwpErrFilterNotFound {
			errs = append(errs, fmt.Errorf("delete WFP permit filter for allowed destination %s: HRESULT 0x%x", key, r1))
			continue
		}
		delete(s.exceptionFilterMap, key)
		p.Debug().Msgf("Firewall: removed WFP permit filter for allowed destination %s", key)
	}

	for _, prefix := range added {
		key := prefix.String()
		if _, exists := s.exceptionFilterMap[key]; exists {
			continue
		}
		filterID, err := p.addWFPFirewallPermitPrefix(s, prefix)
		if err != nil {
			errs = append(errs, fmt.Errorf("add WFP permit filter for allowed destination %s: %w", key, err))
			continue
		}
		s.exceptionFilterMap[key] = filterID
		p.Debug().Msgf("Firewall: added WFP permit filter for allowed destination %s (ID: %d)", key, filterID)
	}

	return errors.Join(errs...)
}

// populateFilters installs permit filters for IPs already present in the allowlist
// before WFP callbacks were registered.
func (s *wfpFirewallState) populateFilters(p *prog) {
	if p.allowList == nil {
		return
	}
	ips := p.allowList.AllowedIPs()
	if len(ips) == 0 {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, ip := range ips {
		key := ip.String()
		if _, exists := s.filterMap[key]; exists {
			continue
		}

		filterID, err := p.addWFPFirewallPermitFilter(s, ip)
		if err != nil {
			p.Warn().Err(err).Msgf("Firewall: failed to add initial WFP permit filter for %s", key)
			continue
		}
		s.filterMap[key] = filterID
		p.Debug().Msgf("Firewall: added initial WFP permit filter for %s (ID: %d)", key, filterID)
	}
}

// addWFPFirewallBlockFilters installs the base block-all outbound filters.
// These block ALL non-loopback outbound TCP/UDP traffic. Per-IP permit filters
// (added dynamically from the allowlist) override these for resolved IPs.
func (p *prog) addWFPFirewallBlockFilters(fwState *wfpFirewallState) error {
	// Block all outbound IPv4 TCP/UDP.
	filterName, _ := windows.UTF16PtrFromString("ctrld Firewall Block All IPv4")
	filter := fwpmFilter0{
		subLayerKey: ctrldSubLayerGUID,
		weight: fwpValue0{
			valueType: fwpUint8, // FWP_UINT8
			value:     1,        // Must be lower than DNS permits (10). Firewall IP permits (5) override this.
		},
		action: fwpmAction0{
			actionType: fwpActionBlock, // FWP_ACTION_BLOCK
		},
		layerKey: fwpmLayerALEAuthConnectV4,
	}
	filter.displayData.name = filterName

	var filterID uint64
	r1, _, _ := procFwpmFilterAdd0.Call(
		fwState.engineHandle,
		uintptr(unsafe.Pointer(&filter)),
		0,
		uintptr(unsafe.Pointer(&filterID)),
	)
	if r1 != 0 {
		return fmt.Errorf("FwpmFilterAdd0 (block IPv4) failed: HRESULT 0x%x", r1)
	}
	fwState.blockFilterIDv4 = filterID

	// Block all outbound IPv6 TCP/UDP.
	filterNameV6, _ := windows.UTF16PtrFromString("ctrld Firewall Block All IPv6")
	filterV6 := fwpmFilter0{
		subLayerKey: ctrldSubLayerGUID,
		weight: fwpValue0{
			valueType: fwpUint8,
			value:     1,
		},
		action: fwpmAction0{
			actionType: fwpActionBlock,
		},
		layerKey: fwpmLayerALEAuthConnectV6,
	}
	filterV6.displayData.name = filterNameV6

	var filterIDv6 uint64
	r1, _, _ = procFwpmFilterAdd0.Call(
		fwState.engineHandle,
		uintptr(unsafe.Pointer(&filterV6)),
		0,
		uintptr(unsafe.Pointer(&filterIDv6)),
	)
	if r1 != 0 {
		if fwState.blockFilterIDv4 != 0 {
			deleteResult, _, _ := procFwpmFilterDeleteById0.Call(fwState.engineHandle, uintptr(fwState.blockFilterIDv4))
			if deleteResult != 0 {
				p.Debug().Msgf("Firewall: failed to roll back IPv4 block filter %d after IPv6 setup failure (HRESULT 0x%x)", fwState.blockFilterIDv4, deleteResult)
			}
			fwState.blockFilterIDv4 = 0
		}
		return fmt.Errorf("FwpmFilterAdd0 (block IPv6) failed: HRESULT 0x%x", r1)
	}
	fwState.blockFilterIDv6 = filterIDv6

	p.Info().Msgf("Firewall: WFP block-all filters installed (v4 ID: %d, v6 ID: %d)", filterID, filterIDv6)
	return nil
}

// addWFPFirewallPermitPrefix adds a WFP permit filter for a permanent CIDR prefix.
func (p *prog) addWFPFirewallPermitPrefix(fwState *wfpFirewallState, prefix netip.Prefix) (uint64, error) {
	prefix = prefix.Masked()
	if prefix.Addr().Is4() {
		return p.addWFPFirewallPermitIPv4Prefix(fwState, prefix)
	}
	return p.addWFPFirewallPermitIPv6Prefix(fwState, prefix)
}

func (p *prog) addWFPFirewallPermitIPv4Prefix(fwState *wfpFirewallState, prefix netip.Prefix) (uint64, error) {
	addr4 := prefix.Addr().As4()
	addr := uint32(addr4[0])<<24 | uint32(addr4[1])<<16 | uint32(addr4[2])<<8 | uint32(addr4[3])
	bits := prefix.Bits()
	var mask uint32
	if bits == 0 {
		mask = 0
	} else {
		mask = ^uint32(0) << uint(32-bits)
	}
	addrMask := fwpV4AddrAndMask{addr: addr & mask, mask: mask}

	filterName, _ := windows.UTF16PtrFromString("ctrld Firewall Permit " + prefix.String())
	condition := fwpmFilterCondition0{
		fieldKey:  fwpmConditionIPRemoteAddress,
		matchType: fwpMatchEqual,
	}
	condition.condValue.valueType = fwpV4AddrMask
	condition.condValue.value = uint64(uintptr(unsafe.Pointer(&addrMask)))

	filter := fwpmFilter0{
		subLayerKey:     ctrldSubLayerGUID,
		numFilterConds:  1,
		filterCondition: (*fwpmFilterCondition0)(unsafe.Pointer(&condition)),
		weight: fwpValue0{
			valueType: fwpUint8,
			value:     5,
		},
		action: fwpmAction0{
			actionType: fwpActionPermit,
		},
		layerKey: fwpmLayerALEAuthConnectV4,
	}
	filter.displayData.name = filterName

	var filterID uint64
	r1, _, _ := procFwpmFilterAdd0.Call(
		fwState.engineHandle,
		uintptr(unsafe.Pointer(&filter)),
		0,
		uintptr(unsafe.Pointer(&filterID)),
	)
	runtime.KeepAlive(&addrMask)
	if r1 != 0 {
		return 0, fmt.Errorf("FwpmFilterAdd0 (permit IPv4 prefix %s) failed: HRESULT 0x%x", prefix, r1)
	}
	return filterID, nil
}

func (p *prog) addWFPFirewallPermitIPv6Prefix(fwState *wfpFirewallState, prefix netip.Prefix) (uint64, error) {
	addrMask := fwpV6AddrAndMask{addr: prefix.Addr().As16(), prefixLength: uint8(prefix.Bits())}

	filterName, _ := windows.UTF16PtrFromString("ctrld Firewall Permit " + prefix.String())
	condition := fwpmFilterCondition0{
		fieldKey:  fwpmConditionIPRemoteAddress,
		matchType: fwpMatchEqual,
	}
	condition.condValue.valueType = fwpV6AddrMask
	condition.condValue.value = uint64(uintptr(unsafe.Pointer(&addrMask)))

	filter := fwpmFilter0{
		subLayerKey:     ctrldSubLayerGUID,
		numFilterConds:  1,
		filterCondition: (*fwpmFilterCondition0)(unsafe.Pointer(&condition)),
		weight: fwpValue0{
			valueType: fwpUint8,
			value:     5,
		},
		action: fwpmAction0{
			actionType: fwpActionPermit,
		},
		layerKey: fwpmLayerALEAuthConnectV6,
	}
	filter.displayData.name = filterName

	var filterID uint64
	r1, _, _ := procFwpmFilterAdd0.Call(
		fwState.engineHandle,
		uintptr(unsafe.Pointer(&filter)),
		0,
		uintptr(unsafe.Pointer(&filterID)),
	)
	runtime.KeepAlive(&addrMask)
	if r1 != 0 {
		return 0, fmt.Errorf("FwpmFilterAdd0 (permit IPv6 prefix %s) failed: HRESULT 0x%x", prefix, r1)
	}
	return filterID, nil
}

// addWFPFirewallPermitFilter adds a WFP permit filter for a single IP address.
// Returns the filter ID for later removal.
func (p *prog) addWFPFirewallPermitFilter(fwState *wfpFirewallState, ip netip.Addr) (uint64, error) {
	ip = ip.Unmap()

	if ip.Is4() {
		return p.addWFPFirewallPermitIPv4(fwState, ip)
	}
	return p.addWFPFirewallPermitIPv6(fwState, ip)
}

// addWFPFirewallPermitIPv4 adds a WFP permit filter for an IPv4 address.
func (p *prog) addWFPFirewallPermitIPv4(fwState *wfpFirewallState, ip netip.Addr) (uint64, error) {
	addr4 := ip.As4()
	ipUint32 := uint32(addr4[0])<<24 | uint32(addr4[1])<<16 | uint32(addr4[2])<<8 | uint32(addr4[3])

	filterName, _ := windows.UTF16PtrFromString("ctrld Firewall Permit " + ip.String())

	condition := fwpmFilterCondition0{
		fieldKey:  fwpmConditionIPRemoteAddress,
		matchType: fwpMatchEqual,
	}
	condition.condValue.valueType = fwpUint32
	condition.condValue.value = uint64(ipUint32)

	filter := fwpmFilter0{
		subLayerKey:     ctrldSubLayerGUID,
		numFilterConds:  1,
		filterCondition: (*fwpmFilterCondition0)(unsafe.Pointer(&condition)),
		weight: fwpValue0{
			valueType: fwpUint8,
			value:     5, // Higher than block-all (1), lower than DNS permits (10).
		},
		action: fwpmAction0{
			actionType: fwpActionPermit, // FWP_ACTION_PERMIT
		},
		layerKey: fwpmLayerALEAuthConnectV4,
	}
	filter.displayData.name = filterName

	var filterID uint64
	r1, _, _ := procFwpmFilterAdd0.Call(
		fwState.engineHandle,
		uintptr(unsafe.Pointer(&filter)),
		0,
		uintptr(unsafe.Pointer(&filterID)),
	)
	if r1 != 0 {
		return 0, fmt.Errorf("FwpmFilterAdd0 (permit IPv4 %s) failed: HRESULT 0x%x", ip, r1)
	}
	return filterID, nil
}

// addWFPFirewallPermitIPv6 adds a WFP permit filter for an IPv6 address.
func (p *prog) addWFPFirewallPermitIPv6(fwState *wfpFirewallState, ip netip.Addr) (uint64, error) {
	addr16 := ip.As16()

	filterName, _ := windows.UTF16PtrFromString("ctrld Firewall Permit " + ip.String())

	condition := fwpmFilterCondition0{
		fieldKey:  fwpmConditionIPRemoteAddress,
		matchType: fwpMatchEqual,
	}
	condition.condValue.valueType = fwpByteArray16Type
	condition.condValue.value = uint64(uintptr(unsafe.Pointer(&addr16)))

	filter := fwpmFilter0{
		subLayerKey:     ctrldSubLayerGUID,
		numFilterConds:  1,
		filterCondition: (*fwpmFilterCondition0)(unsafe.Pointer(&condition)),
		weight: fwpValue0{
			valueType: fwpUint8,
			value:     5, // Higher than block-all (1), lower than DNS permits (10).
		},
		action: fwpmAction0{
			actionType: fwpActionPermit,
		},
		layerKey: fwpmLayerALEAuthConnectV6,
	}
	filter.displayData.name = filterName

	var filterID uint64
	r1, _, _ := procFwpmFilterAdd0.Call(
		fwState.engineHandle,
		uintptr(unsafe.Pointer(&filter)),
		0,
		uintptr(unsafe.Pointer(&filterID)),
	)
	runtime.KeepAlive(addr16)
	if r1 != 0 {
		return 0, fmt.Errorf("FwpmFilterAdd0 (permit IPv6 %s) failed: HRESULT 0x%x", ip, r1)
	}
	return filterID, nil
}
