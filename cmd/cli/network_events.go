package cli

import (
	"time"

	"github.com/Control-D-Inc/ctrld"
	"tailscale.com/net/netmon"
)

// networkEventsNowFn is the clock of the network events. Tests replace it.
var networkEventsNowFn = time.Now

const (
	hostWokeMessage = "Host woke"

	// noiseDeltaMessage names the deltas that no part of the daemon acts on.
	noiseDeltaMessage = "Network delta noise"

	// interfaceChangedMessage names one interface that a delta changed.
	interfaceChangedMessage = "Network interface changed"

	// networkTransitionMessage names the outcome of one delta.
	networkTransitionMessage = "Network transition"

	// transitionOutcomeIgnored names a delta that left every usable interface
	// as it was.
	transitionOutcomeIgnored = "ignored"

	// transitionOutcomeSnapshotSuperseded names a delta whose snapshot netmon
	// already replaced. A newer callback reports the same interfaces.
	transitionOutcomeSnapshotSuperseded = "snapshot_superseded"
)

// noteHostWoke reports one wake to the wake reporter. The caller passes the
// network of the wake, because the state that ctrld holds still describes the
// network before the sleep. netmon reports a time jump and measures no gap, so
// its report waits for the detector, and the journal gets one event per wake.
func (p *prog) noteHostWoke(source string, gap time.Duration, state *netmon.State) {
	now := networkEventsNowFn()
	// A resume moves the resolvers of the host, so every wake source starts the
	// fast poll.
	if p.dnsConfig != nil {
		p.dnsConfig.noteActivity(now)
	}
	p.wake.note(now, wakeReport{source: source, gap: gap, state: state}, logHostWoke)
}

// logHostWoke writes the Host woke journal event of one report.
func logHostWoke(report wakeReport) {
	gapKnown := report.gap > 0
	event := journal(mainLog.Load().Info()).Str("source", report.source).Bool("gap_known", gapKnown)
	if gapKnown {
		event.Int64("gap_ms", report.gap.Milliseconds())
	}
	event.Str("default_route", defaultRouteOf(report.state)).
		Int("interfaces_up", upInterfaceCount(report.state)).
		Msg(hostWokeMessage)
}

// noteNoiseDelta records one delta of a noise storm. AirDrop and the virtual
// adapters of a container host change every few seconds, so the journal keeps
// one line per window while the debug stream keeps them all.
func (p *prog) noteNoiseDelta(changes []interfaceChange) {
	names := changedInterfaceNames(changes)
	mainLog.Load().Debug().Strs("interfaces", names).Msg(noiseDeltaMessage)
	if summary, emit := p.networkNoise.add(names, networkEventsNowFn()); emit {
		logNoiseSummary(summary)
	}
}

// flushNoiseSummary closes the open noise window, because the delta that the
// daemon acts on ends the storm.
func (p *prog) flushNoiseSummary() {
	if summary, emit := p.networkNoise.flush(networkEventsNowFn()); emit {
		logNoiseSummary(summary)
	}
}

// logNoiseSummary writes one journal line for a window of noise deltas.
func logNoiseSummary(summary noiseSummary) {
	journal(mainLog.Load().Info()).
		Int("count", summary.Count).
		Strs("interfaces", summary.Interfaces).
		Str("first_at", summary.First.Format(time.RFC3339)).
		Str("last_at", summary.Last.Format(time.RFC3339)).
		Msg(noiseDeltaMessage)
}

// logInterfaceChanges puts the interfaces of one transition in the journal.
// Support reads back the port that lost its address at the time of an outage.
// An AirDrop or a container adapter changes every few seconds, so the
// transition names it and the journal keeps the interfaces that carry the
// traffic of the host.
func logInterfaceChanges(transitionID uint64, changes []interfaceChange) {
	for _, change := range changes {
		if noiseClass(change.Class) {
			continue
		}
		journal(mainLog.Load().Info()).
			Uint64("transition_id", transitionID).
			Str("interface", change.Name).
			Str("action", change.Action).
			Str("class", change.Class).
			Str("hardware_port", change.HardwarePort).
			Str("service", change.Service).
			Strs("ips_before", change.IPsBefore).
			Strs("ips_after", change.IPsAfter).
			Str("flags", change.Flags).
			Int("mtu", change.MTU).
			Bool("is_default_route", change.IsDefaultRoute).
			Msg(interfaceChangedMessage)
	}
}

// networkTransitionEvent picks the level of one transition line. An ignored
// delta and a superseded snapshot arrive many times per minute, so the journal
// keeps the outcomes that can change the resolver state only.
func networkTransitionEvent(outcome string) *ctrld.LogEvent {
	if outcome == transitionOutcomeIgnored || outcome == transitionOutcomeSnapshotSuperseded {
		return mainLog.Load().Debug()
	}
	return journal(mainLog.Load().Info())
}

// changedInterfaceNames names the interfaces of one delta, in the order of the
// diff.
func changedInterfaceNames(changes []interfaceChange) []string {
	names := make([]string, 0, len(changes))
	for _, change := range changes {
		names = append(names, change.Name)
	}
	return names
}

// hasAddOrRemove reports a delta that changed the adapter set of the host. The
// platform names of an adapter come from a cache, and that cache holds nothing
// for an adapter that just appeared.
func hasAddOrRemove(changes []interfaceChange) bool {
	for _, change := range changes {
		if change.Action == "added" || change.Action == "removed" {
			return true
		}
	}
	return false
}

func defaultRouteOf(state *netmon.State) string {
	if state == nil {
		return ""
	}
	return state.DefaultRouteInterface
}

// upInterfaceCount counts the interfaces with the up flag. A netmon entry
// without an embedded interface counts as down.
func upInterfaceCount(state *netmon.State) int {
	if state == nil {
		return 0
	}
	up := 0
	for _, iface := range state.Interface {
		if iface.Interface != nil && iface.IsUp() {
			up++
		}
	}
	return up
}
