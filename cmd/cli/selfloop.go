package cli

import (
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"

	"github.com/Control-D-Inc/ctrld"
)

// selfLoopReportInterval bounds how often a self loop is reported. A broken
// intercept exemption makes every plain DNS query ctrld sends come back, so
// the event is a rate, not a line per query.
const selfLoopReportInterval = 5 * time.Minute

// selfLoopPathSuspected counts copies that matched an in-flight question but
// not its message ID. They are served normally and only reported.
const selfLoopPathSuspected = "suspected_id_mismatch"

// selfLoopReporter counts self loops and reports them at most once per
// selfLoopReportInterval: the first one at once, later ones as a count.
type selfLoopReporter struct {
	mu       sync.Mutex
	reported time.Time
	pending  uint64
	total    uint64
	paths    map[string]uint64
	ups      map[string]uint64
}

// selfLoopReport is one emitted report.
type selfLoopReport struct {
	count    uint64
	total    uint64
	paths    map[string]uint64
	upstream map[string]uint64
	first    bool
}

func (r *selfLoopReporter) note(now time.Time, path, upstream string) (selfLoopReport, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.paths == nil {
		r.paths, r.ups = make(map[string]uint64), make(map[string]uint64)
	}
	r.pending++
	r.total++
	r.paths[path]++
	if upstream != "" {
		r.ups[upstream]++
	}
	first := r.reported.IsZero()
	if !first && now.Sub(r.reported) < selfLoopReportInterval {
		return selfLoopReport{}, false
	}
	rep := selfLoopReport{count: r.pending, total: r.total, paths: r.paths, upstream: r.ups, first: first}
	r.reported, r.pending = now, 0
	r.paths, r.ups = make(map[string]uint64), make(map[string]uint64)
	return rep, true
}

// selfLoopReply is the answer the listener gives a returned query. Its only
// reader is the exchange that sent the query, which already knows from the
// match that the exchange failed; the answer just ends its wait at once.
func selfLoopReply(m *dns.Msg) *dns.Msg {
	answer := new(dns.Msg)
	answer.SetRcode(m, dns.RcodeRefused)
	return answer
}

// handleSelfQuery answers m at once and reports it when m is one of ctrld's
// own outbound queries that the OS delivered back to the listener.
//
// Without this, the returned query is served like a client query: in DNS
// intercept mode its forwarding is redirected back again, so each step holds
// a listener slot until the original query's timeout, and one lookup can fill
// every slot (defaultSemaphoreCap) while the host's other DNS waits.
func (p *prog) handleSelfQuery(w dns.ResponseWriter, m *dns.Msg) bool {
	match, ok := ctrld.MatchSelfQuery(w.RemoteAddr(), m)
	if !ok {
		return false
	}
	if match.Suspected {
		// Same question as an in-flight query of ctrld's, from this host, but a
		// different message ID: either a forwarder that rewrites IDs, or an
		// application asking the same name. Serve it, and count it so a report
		// shows whether IDs survive the path back.
		if rep, emit := p.selfLoopSuspects.note(time.Now(), selfLoopPathSuspected, ""); emit {
			go p.reportSelfLoop(rep, false)
		}
		return false
	}
	_ = w.WriteMsg(selfLoopReply(m))

	upstream := ""
	if match.UpstreamUID != "" {
		upstream = p.markUpstreamLoop(match.UpstreamUID)
	}
	if rep, emit := p.selfLoops.note(time.Now(), match.Kind, upstream); emit {
		go p.reportSelfLoop(rep, true)
	}
	return true
}

// markUpstreamLoop marks the upstream with uid as looping and returns its
// config key. Only upstreams the loop check manages are marked: it resets
// each of them every run, so a path that works again is used again on its
// own. Any other upstream (a hostname or public IP) would never be reset, so
// it is left unmarked; its query still ends at once.
func (p *prog) markUpstreamLoop(uid string) string {
	p.loopMu.Lock()
	if _, managed := p.loop[uid]; managed {
		p.loop[uid] = true
	}
	p.loopMu.Unlock()
	if p.cfg == nil {
		return ""
	}
	for n, uc := range p.cfg.Upstream {
		if uc != nil && uc.UID() == uid {
			return upstreamPrefix + n
		}
	}
	return ""
}

// selfLoopHostContextFn adds the host context to a report. It is a seam:
// the real reads take up to a few seconds on macOS, and listener tests assert
// the report itself.
var selfLoopHostContextFn atomic.Pointer[func(*zerolog.Event)]

func init() {
	f := addSelfLoopHostContext
	selfLoopHostContextFn.Store(&f)
}

// reportSelfLoop logs one self loop report, with the host context that can
// explain it. Upstream names are bounded like other journal lines; no server
// address or query name is logged.
func (p *prog) reportSelfLoop(rep selfLoopReport, confirmed bool) {
	paths := make([]string, 0, len(rep.paths))
	for path, n := range rep.paths {
		paths = append(paths, path+"="+strconv.FormatUint(n, 10))
	}
	ups := make([]string, 0, len(rep.upstream))
	for up, n := range rep.upstream {
		ups = append(ups, journalUpstreamName(up)+"="+strconv.FormatUint(n, 10))
	}
	stats := ctrld.ReadSelfQueryStats()
	slices.Sort(paths)
	slices.Sort(ups)
	level := mainLog.Load().Warn
	if !confirmed {
		level = mainLog.Load().Info
	}
	e := journal(level()).
		Uint64("count", rep.count).
		Uint64("total", rep.total).
		Str("paths", strings.Join(paths, ",")).
		Str("upstreams", strings.Join(ups, ",")).
		Str("intercept_mode", interceptMode).
		Uint64("self_queries_sent", stats.Sent).
		Uint64("self_queries_local_port_zero", stats.LocalPortZero).
		Bool("first", rep.first).
		Dur("report_interval_ms", selfLoopReportInterval)
	(*selfLoopHostContextFn.Load())(e)
	if !confirmed {
		e.Msg("DNS self loop suspected: a query for a name ctrld is forwarding arrived from this host with a different message ID")
		return
	}
	e.Msg("DNS self loop: ctrld's own DNS query returned to its listener; the intercept exemption for ctrld's traffic is not applying")
}
