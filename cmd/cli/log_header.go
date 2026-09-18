package cli

import (
	"bytes"
	"cmp"
	"net"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/Control-D-Inc/ctrld"
	"tailscale.com/net/netmon"
)

// processStartTime is the time this process started. A reader compares it with
// the time of the header line to tell a restart from a rotation.
var processStartTime = time.Now()

const (
	// logHeaderMessage is the message of the header line. Log tools select the
	// header by this message.
	logHeaderMessage = "Log header"

	// interceptModeOff is the mode word for a ctrld that does not intercept.
	interceptModeOff = "off"

	// logHeaderTriggerSend marks the header that a log request renders. It
	// tells a reader that the line came from an upload, not from a file open.
	logHeaderTriggerSend = "send"

	// upstreamTypeUnspecified names an upstream that has no type in the config.
	// ctrld resolves the type at start, so the header must not claim one.
	upstreamTypeUnspecified = "unspecified"
)

// headerOSVersion reads the OS version once. The read starts a subprocess on
// macOS, and a header refresh follows every network change.
var headerOSVersion = sync.OnceValue(osVersion)

// logHeaderInterface is one interface of the header network snapshot.
type logHeaderInterface struct {
	Name string
	Up   bool
	IPs  []string
}

// logHeaderNetwork is the minimal network snapshot of a header line.
type logHeaderNetwork struct {
	DefaultRouteInterface string
	HaveV4                bool
	HaveV6                bool
	Interfaces            []logHeaderInterface
}

// logHeaderInput holds every value of a header line. The caller collects the
// values, so the renderer stays free of locks and of system calls.
type logHeaderInput struct {
	Version       string
	Commit        string
	OS            string
	Arch          string
	PID           int
	StartTime     time.Time
	InterceptMode string
	Listeners     []string
	UpstreamCount int
	UpstreamTypes []string
	ResolverUID   string
	LogFiles      []string
	Network       logHeaderNetwork
	Trigger       string
}

// renderLogHeader renders the header as one log line. A file writer stores the
// bytes and writes them itself, so the header reaches a file that the logger
// never fills.
func renderLogHeader(in logHeaderInput) []byte {
	var buf bytes.Buffer
	logger := zerolog.New(&buf).With().Timestamp().Logger()
	event := journal(logHeaderEvent(&logger)).
		Str("version", in.Version).
		Str("commit", in.Commit).
		Str("os", in.OS).
		Str("arch", in.Arch).
		Int("pid", in.PID).
		Str("start_time", in.StartTime.Format(time.RFC3339)).
		Str("intercept_mode", in.InterceptMode).
		Strs("listeners", in.Listeners).
		Int("upstream_count", in.UpstreamCount).
		Strs("upstream_types", in.UpstreamTypes).
		Str("resolver_uid", in.ResolverUID).
		Strs("log_files", in.LogFiles).
		Dict("network", logHeaderNetworkDict(in.Network))
	if in.Trigger != "" {
		event = event.Str("trigger", in.Trigger)
	}
	event.Msg(logHeaderMessage)

	// The header is the first line of every file and of every upload, and it
	// bypasses the writers, so it passes the journal redaction here.
	return redactRetainedLine(buf.Bytes())
}

// logHeaderEvent starts the header event at info level. The global level sits
// above info on a default start, and a log file must hold its header at every
// level, so the event names its level itself.
func logHeaderEvent(logger *zerolog.Logger) *zerolog.Event {
	return logger.Log().Str(zerolog.LevelFieldName, zerolog.LevelInfoValue)
}

func logHeaderNetworkDict(network logHeaderNetwork) *zerolog.Event {
	interfaces := zerolog.Arr()
	for _, iface := range network.Interfaces {
		interfaces = interfaces.Dict(zerolog.Dict().
			Str("name", iface.Name).
			Bool("up", iface.Up).
			Strs("ips", iface.IPs))
	}
	return zerolog.Dict().
		Str("default_route_interface", network.DefaultRouteInterface).
		Bool("have_v4", network.HaveV4).
		Bool("have_v6", network.HaveV6).
		Array("interfaces", interfaces)
}

// logHeaderNetworkFromState makes the header snapshot from a netmon state.
func logHeaderNetworkFromState(st *netmon.State) logHeaderNetwork {
	if st == nil {
		return logHeaderNetwork{}
	}
	network := logHeaderNetwork{
		DefaultRouteInterface: st.DefaultRouteInterface,
		HaveV4:                st.HaveV4,
		HaveV6:                st.HaveV6,
	}
	for name, iface := range st.Interface {
		network.Interfaces = append(network.Interfaces, logHeaderInterface{
			Name: name,
			Up:   iface.Interface != nil && iface.IsUp(),
			IPs:  prefixStrings(st.InterfaceIPs[name]),
		})
	}
	slices.SortFunc(network.Interfaces, func(a, b logHeaderInterface) int {
		return cmp.Compare(a.Name, b.Name)
	})
	return network
}

// logHeaderNetworkFresh reads the network now. A header that no network
// callback reached yet, and the header of an upload, need the live picture.
func logHeaderNetworkFresh() logHeaderNetwork {
	state, err := readNetworkSourceStateFn()
	if err != nil {
		state = nil
	}
	network := logHeaderNetworkFromState(state)
	if route, err := netmon.DefaultRouteInterface(); err == nil {
		network.DefaultRouteInterface = route
	}
	network.HaveV4, network.HaveV6 = globalAddressFamilies(state)
	return network
}

// globalAddressFamilies reports which families the host can reach. A loopback
// or a link-local address reaches no other host, so it proves nothing.
func globalAddressFamilies(st *netmon.State) (haveV4, haveV6 bool) {
	if st == nil {
		return false, false
	}
	for name, iface := range st.Interface {
		if iface.Interface == nil || !iface.IsUp() {
			continue
		}
		for _, prefix := range st.InterfaceIPs[name] {
			addr := prefix.Addr().Unmap()
			if !addr.IsGlobalUnicast() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
				continue
			}
			if addr.Is4() {
				haveV4 = true
				continue
			}
			haveV6 = true
		}
	}
	return haveV4, haveV6
}

// logHeaderInput collects every header value of the running program.
func (p *prog) logHeaderInput() logHeaderInput {
	in := logHeaderInput{
		Version:   curVersion(),
		Commit:    commit,
		OS:        headerOSVersion(),
		Arch:      runtime.GOARCH,
		PID:       os.Getpid(),
		StartTime: processStartTime,
		// The resolver UID is a secret that the provisioning code strips from
		// every artifact, so the header keeps its first characters only.
		ResolverUID: redactToken(cdUID),
		LogFiles:    p.logHeaderFiles(),
		Network:     p.logHeaderNetwork(),
	}
	p.headerConfigInto(&in)
	return in
}

// headerConfigInto reads the config under p.mu, because a reload replaces the
// config under that lock while log view and log send render a header.
func (p *prog) headerConfigInto(in *logHeaderInput) {
	p.mu.Lock()
	defer p.mu.Unlock()
	logHeaderFromConfig(p.cfg, in)
}

// sendLogHeader renders the header that leads one upload.
func (p *prog) sendLogHeader() []byte {
	in := p.logHeaderInput()
	// The stored state can be older than the request, and support reads this
	// line to learn the network of the moment the user asked.
	in.Network = logHeaderNetworkFresh()
	in.Trigger = logHeaderTriggerSend
	return renderLogHeader(in)
}

// noteNetworkState keeps the newest network that ctrld saw and puts it in the
// header bytes of every open log file. The caller must hold no lock, because
// the render reads the config and the network.
func (p *prog) noteNetworkState(st *netmon.State) {
	if st != nil {
		p.lastNetworkState.Store(st)
	}
	p.refreshLogHeader()
}

// logHeaderNetwork takes the network that the last monitor callback reported.
func (p *prog) logHeaderNetwork() logHeaderNetwork {
	state := p.lastNetworkState.Load()
	if state == nil {
		return logHeaderNetworkFresh()
	}
	return logHeaderNetworkFromState(state)
}

// logHeaderFiles names the files that this run writes, debug first.
func (p *prog) logHeaderFiles() []string {
	files := make([]string, 0, 3)
	for _, rf := range p.openLogFiles() {
		files = append(files, rf.currentPath())
	}
	return files
}

// refreshLogHeader renders the header and hands the bytes to every open file.
// The caller must hold no writer lock, because the render reads the config
// and the network.
func (p *prog) refreshLogHeader() {
	header := renderLogHeader(p.logHeaderInput())
	for _, rf := range p.openLogFiles() {
		rf.setHeader(header)
	}
}

// writeLogHeaders puts the header at the append point of each open file. A
// header that cannot land leaves the file usable, so the error only earns a
// warning.
func (p *prog) writeLogHeaders() {
	for _, rf := range p.openLogFiles() {
		if err := rf.writeHeader(); err != nil {
			mainLog.Load().Warn().Err(err).Msg("could not write log header")
		}
	}
}

func prefixStrings(prefixes []netip.Prefix) []string {
	ips := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		ips = append(ips, prefix.String())
	}
	return ips
}

// logHeaderFromConfig fills the header fields that the config holds. It keeps
// every upstream endpoint, name, and bootstrap IP out of them, because a token
// can hide in each of them.
func logHeaderFromConfig(cfg *ctrld.Config, in *logHeaderInput) {
	if cfg == nil {
		in.InterceptMode = interceptModeOff
		return
	}
	in.InterceptMode = headerInterceptMode(cfg)
	in.Listeners = listenerAddresses(cfg)
	in.UpstreamCount = len(cfg.Upstream)
	in.UpstreamTypes = upstreamTypeWords(cfg)
}

// headerInterceptMode names the mode for the header. An unset mode means that
// ctrld does not intercept, which reads as off.
func headerInterceptMode(cfg *ctrld.Config) string {
	if mode := listenerInterceptMode(cfg); mode != "" {
		return mode
	}
	return interceptModeOff
}

func listenerAddresses(cfg *ctrld.Config) []string {
	addresses := make([]string, 0, len(cfg.Listener))
	for _, listener := range cfg.Listener {
		if listener == nil {
			continue
		}
		addresses = append(addresses, net.JoinHostPort(listener.IP, strconv.Itoa(listener.Port)))
	}
	slices.Sort(addresses)
	return addresses
}

func upstreamTypeWords(cfg *ctrld.Config) []string {
	words := make([]string, 0, len(cfg.Upstream))
	for _, upstream := range cfg.Upstream {
		if upstream == nil {
			continue
		}
		word := upstream.Type
		if word == "" {
			word = upstreamTypeUnspecified
		}
		if !slices.Contains(words, word) {
			words = append(words, word)
		}
	}
	slices.Sort(words)
	return words
}
