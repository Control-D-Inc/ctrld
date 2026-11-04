package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	pfDiagnosticInterval = time.Minute
	pfDiagnosticTimeout  = 500 * time.Millisecond
	pfDiagnosticMaxBytes = 64 << 10
)

// Only these two exact, ctrld-generated rules are identified. PF's @N indexes
// are not stable identifiers. No rule text or other anchor contents are logged.
var pfDiagnosticRule = regexp.MustCompile(`^@[0-9]+ block drop out quick on ! ?lo0 inet6 proto (udp|tcp) from any to any port = 53$`)
var pfDiagnosticCounters = regexp.MustCompile(`^\[ Evaluations: +([0-9]+) +Packets: +([0-9]+) +Bytes: +([0-9]+) +States: +([0-9]+) +\]$`)

type pfDiagnosticRuleCount struct {
	Installed bool
	Known     bool
	Packets   uint64
}

type pfDiagnosticSnapshot struct {
	Code             string
	UDP, TCP         pfDiagnosticRuleCount
	RouteV4, RouteV6 string
	AddressCode      string
	NativeIPv4, CLAT bool
}

// A missing or unrecognized rule is not a zero counter. A counter describes all
// traffic matching that rule since its last reset, not delivery of our UDP4 probe.
func parsePFDiagnostic(data []byte) pfDiagnosticSnapshot {
	s := pfDiagnosticSnapshot{Code: "rules_not_observed"}
	var current *pfDiagnosticRuleCount
	duplicates := false
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "@") {
			current = nil
			if m := pfDiagnosticRule.FindStringSubmatch(line); m != nil {
				current = &s.UDP
				if m[1] == "tcp" {
					current = &s.TCP
				}
				if current.Installed {
					duplicates = true
				}
				current.Installed = true
			}
			continue
		}
		if current == nil {
			continue
		}
		if strings.HasPrefix(line, "[ Evaluations:") {
			m := pfDiagnosticCounters.FindStringSubmatch(line)
			if m != nil {
				valid := true
				for _, value := range m[1:] {
					if _, err := strconv.ParseUint(value, 10, 64); err != nil {
						valid = false
					}
				}
				if valid {
					current.Packets, _ = strconv.ParseUint(m[2], 10, 64)
					current.Known = true
				}
			}
			current = nil // never attach a later rule's counters to this rule
		}
	}
	switch {
	case duplicates:
		s.Code = "ambiguous_rules"
		s.UDP.Known, s.TCP.Known = false, false
	case s.UDP.Known && s.TCP.Known:
		s.Code = "ok"
	case s.UDP.Installed || s.TCP.Installed:
		s.Code = "partial_or_malformed"
	}
	return s
}

var errPFDiagnosticLimit = errors.New("PF diagnostic output limit")

type pfDiagnosticBuffer struct {
	data    bytes.Buffer // do not embed: promoted ReadFrom would bypass Write's cap
	limited bool
}

func (b *pfDiagnosticBuffer) Len() int { return b.data.Len() }

func (b *pfDiagnosticBuffer) Write(p []byte) (int, error) {
	if len(p) > pfDiagnosticMaxBytes-b.Len() {
		b.limited = true
		return 0, errPFDiagnosticLimit
	}
	return b.data.Write(p)
}

// Stdout is bounded, stderr is discarded, and no raw command error escapes.
// WaitDelay also bounds inherited stdout pipes if a helper fails to close them.
func runPFDiagnosticCommand(ctx context.Context, cmd *exec.Cmd) pfDiagnosticSnapshot {
	out, code := readPFDiagnosticOutput(ctx, cmd)
	if code != "" {
		return pfDiagnosticSnapshot{Code: code}
	}
	return parsePFDiagnostic(out)
}

// readPFDiagnosticOutput runs cmd under the diagnostic bounds and returns its
// stdout, or a failure code and no output.
func readPFDiagnosticOutput(ctx context.Context, cmd *exec.Cmd) ([]byte, string) {
	var out pfDiagnosticBuffer
	cmd.Stdout, cmd.Stderr = &out, io.Discard
	cmd.WaitDelay = 100 * time.Millisecond
	err := cmd.Run()
	switch {
	case ctx.Err() != nil:
		return nil, pfProbeContextCode(ctx)
	case out.limited:
		return nil, "output_limit"
	case err != nil:
		return nil, "read_failed"
	}
	return out.data.Bytes(), ""
}

// pfGroupRule is the blanket exemption for ctrld's own traffic, as pfctl
// prints it back: pfctl resolves the group name to a number when it loads the
// rule, so the number shows which group pf actually matches.
var pfGroupRule = regexp.MustCompile(`^@[0-9]+ pass out quick all group = ([0-9]+) flags S/SA keep state$`)

// pfGroupRuleSnapshot is the group exemption rule as loaded. Code is "ok",
// "rule_not_observed", "ambiguous_rules", "partial_or_malformed" or a read
// failure code.
type pfGroupRuleSnapshot struct {
	Code    string
	GID     string
	Known   bool
	Packets uint64
}

func parsePFGroupRule(data []byte) pfGroupRuleSnapshot {
	s := pfGroupRuleSnapshot{Code: "rule_not_observed"}
	installed, inRule, duplicates := false, false, false
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "@") {
			inRule = false
			if m := pfGroupRule.FindStringSubmatch(line); m != nil {
				if installed {
					duplicates = true
				}
				installed, inRule, s.GID = true, true, m[1]
			}
			continue
		}
		if !inRule || !strings.HasPrefix(line, "[ Evaluations:") {
			continue
		}
		if m := pfDiagnosticCounters.FindStringSubmatch(line); m != nil {
			if n, err := strconv.ParseUint(m[2], 10, 64); err == nil {
				s.Packets, s.Known = n, true
			}
		}
		inRule = false
	}
	switch {
	case duplicates:
		s.Code, s.Known = "ambiguous_rules", false
	case installed && s.Known:
		s.Code = "ok"
	case installed:
		s.Code = "partial_or_malformed"
	}
	return s
}

type pfDiagnosticEvent struct {
	Snapshot                   pfDiagnosticSnapshot
	Observation                pfProbeObservation
	Generation                 uint64
	Age                        time.Duration
	Cached                     bool
	UDPDelta, TCPDelta         uint64
	UDPDeltaCode, TCPDeltaCode string
}

// Deltas are shared-traffic observations, never per-probe attribution. Even an
// increasing counter may span an unobserved reload, so it is not an exact total.
func pfDiagnosticDelta(before, after pfDiagnosticRuleCount) (uint64, string) {
	if !before.Known || !after.Known {
		return 0, "unknown"
	}
	if after.Packets < before.Packets {
		return 0, "reset"
	}
	return after.Packets - before.Packets, "shared_traffic"
}

type pfDiagnosticState struct {
	mu            sync.Mutex
	active        bool
	captured      time.Time
	generation    uint64
	snapshot      pfDiagnosticSnapshot
	lastCondition pfProbeCondition
}

// Healthy polls do no work. Failures capture at most once a minute; a restoration
// inside that interval names the cached capture and its age, not a fresh reading.
// Identical outcomes and snapshots are quiet. This state never controls repair.
func (s *pfDiagnosticState) observe(now time.Time, o pfProbeObservation, capture func() pfDiagnosticSnapshot) (pfDiagnosticEvent, bool) {
	if o.code == "canceled" || !s.mu.TryLock() {
		return pfDiagnosticEvent{}, false
	}
	defer s.mu.Unlock()
	if o.result == pfProbeIntercepted && !s.active {
		return pfDiagnosticEvent{}, false
	}
	condition := pfProbeCondition{o.result, o.stage, o.code, o.target}
	e := pfDiagnosticEvent{Observation: o, Cached: true, UDPDeltaCode: "unknown", TCPDeltaCode: "unknown"}
	changed := condition != s.lastCondition
	if s.captured.IsZero() || now.Sub(s.captured) >= pfDiagnosticInterval {
		next := capture()
		changed = changed || next != s.snapshot
		e.UDPDelta, e.UDPDeltaCode = pfDiagnosticDelta(s.snapshot.UDP, next.UDP)
		e.TCPDelta, e.TCPDeltaCode = pfDiagnosticDelta(s.snapshot.TCP, next.TCP)
		s.snapshot, s.captured = next, now
		s.generation++
		e.Cached = false
	}
	s.active = o.result != pfProbeIntercepted
	s.lastCondition = condition
	e.Snapshot, e.Generation, e.Age = s.snapshot, s.generation, now.Sub(s.captured)
	return e, changed
}
