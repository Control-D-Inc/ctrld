package cli

import (
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Control-D-Inc/ctrld"
	"tailscale.com/net/netmon"
)

// logHeaderTestSecret is the string that must never reach a header line.
const logHeaderTestSecret = "secret-token"

// logHeaderTestLine is the parsed form of a header line. The json tags name
// the fields that a log tool reads, so a renamed field fails the test.
type logHeaderTestLine struct {
	Level         string   `json:"level"`
	Time          string   `json:"time"`
	Journal       bool     `json:"journal"`
	Message       string   `json:"message"`
	Version       string   `json:"version"`
	Commit        string   `json:"commit"`
	OS            string   `json:"os"`
	Arch          string   `json:"arch"`
	PID           int      `json:"pid"`
	StartTime     string   `json:"start_time"`
	InterceptMode string   `json:"intercept_mode"`
	Listeners     []string `json:"listeners"`
	UpstreamCount int      `json:"upstream_count"`
	UpstreamTypes []string `json:"upstream_types"`
	ResolverUID   string   `json:"resolver_uid"`
	LogFiles      []string `json:"log_files"`
	Network       struct {
		DefaultRouteV4 string `json:"default_route_v4"`
		DefaultRouteV6 string `json:"default_route_v6"`
		GatewayV4      string `json:"gateway_v4"`
		GatewayV6      string `json:"gateway_v6"`
		HaveV4         bool   `json:"have_v4"`
		HaveV6         bool   `json:"have_v6"`
		Interfaces     []struct {
			Name         string   `json:"name"`
			Class        string   `json:"class"`
			Up           bool     `json:"up"`
			IPs          []string `json:"ips"`
			HardwarePort string   `json:"hardware_port"`
			Service      string   `json:"service"`
		} `json:"interfaces"`
		Resolvers       []string `json:"resolvers"`
		SourceIPv4      string   `json:"source_ipv4"`
		SourceIPv6      string   `json:"source_ipv6"`
		InterceptTarget string   `json:"intercept_target"`
		LinkType        string   `json:"link_type"`
		Tethered        bool     `json:"tethered"`
	} `json:"network"`
	Trigger string `json:"trigger"`
}

func logHeaderTestInput() logHeaderInput {
	return logHeaderInput{
		Version:       "1.5.8",
		Commit:        "abc1234",
		OS:            "darwin 15.6",
		Arch:          "arm64",
		PID:           4242,
		StartTime:     time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC),
		InterceptMode: "dns",
		Listeners:     []string{"127.0.0.1:53", "127.0.0.1:5354"},
		UpstreamCount: 2,
		UpstreamTypes: []string{"doh", "os"},
		ResolverUID:   redactToken("abcd1234"),
		LogFiles:      []string{"/tmp/ctrld.log", "/tmp/ctrld-journal.log"},
		Network: networkSnapshot{
			DefaultRouteV4: "en0",
			GatewayV4:      "192.0.2.1",
			HaveV4:         true,
			Interfaces: []snapshotInterface{
				{Name: "en0", Class: "hardware", Up: true, IPs: []string{"192.0.2.10/24"}, HardwarePort: "Wi-Fi", Service: "Wi-Fi"},
			},
			Resolvers: []string{"192.0.2.1:53"},
			LinkType:  "wifi",
		},
	}
}

// parseLogHeader checks that the render is one line and returns it twice: as
// values, and as raw fields for the tests that ask whether a field is there.
func parseLogHeader(t *testing.T, line []byte) (logHeaderTestLine, map[string]json.RawMessage) {
	t.Helper()
	if len(line) == 0 {
		t.Fatal("renderLogHeader returned no bytes")
	}
	if line[len(line)-1] != '\n' {
		t.Fatalf("header does not end with a newline: %q", line)
	}
	if count := strings.Count(string(line), "\n"); count != 1 {
		t.Fatalf("header holds %d newlines, want 1: %q", count, line)
	}
	var parsed logHeaderTestLine
	if err := json.Unmarshal(line, &parsed); err != nil {
		t.Fatalf("parse header %q: %v", line, err)
	}
	fields := map[string]json.RawMessage{}
	if err := json.Unmarshal(line, &fields); err != nil {
		t.Fatalf("parse header fields %q: %v", line, err)
	}
	return parsed, fields
}

func Test_renderLogHeaderHoldsEveryField(t *testing.T) {
	in := logHeaderTestInput()

	parsed, fields := parseLogHeader(t, renderLogHeader(in))

	checks := []struct {
		field string
		got   any
		want  any
	}{
		{"level", parsed.Level, "info"},
		{"journal", parsed.Journal, true},
		{"message", parsed.Message, "Log header"},
		{"version", parsed.Version, in.Version},
		{"commit", parsed.Commit, in.Commit},
		{"os", parsed.OS, in.OS},
		{"arch", parsed.Arch, in.Arch},
		{"pid", parsed.PID, in.PID},
		{"start_time", parsed.StartTime, in.StartTime.Format(time.RFC3339)},
		{"intercept_mode", parsed.InterceptMode, in.InterceptMode},
		{"listeners", parsed.Listeners, in.Listeners},
		{"upstream_count", parsed.UpstreamCount, in.UpstreamCount},
		{"upstream_types", parsed.UpstreamTypes, in.UpstreamTypes},
		// The resolver UID is a secret, so the header keeps the first four
		// characters only.
		{"resolver_uid", parsed.ResolverUID, "abcd***"},
		{"log_files", parsed.LogFiles, in.LogFiles},
		{"network.default_route_v4", parsed.Network.DefaultRouteV4, in.Network.DefaultRouteV4},
		{"network.default_route_v6", parsed.Network.DefaultRouteV6, in.Network.DefaultRouteV6},
		{"network.gateway_v4", parsed.Network.GatewayV4, in.Network.GatewayV4},
		{"network.have_v4", parsed.Network.HaveV4, in.Network.HaveV4},
		{"network.have_v6", parsed.Network.HaveV6, in.Network.HaveV6},
		{"network.resolvers", parsed.Network.Resolvers, in.Network.Resolvers},
		{"network.link_type", parsed.Network.LinkType, in.Network.LinkType},
		{"network.tethered", parsed.Network.Tethered, in.Network.Tethered},
	}
	for _, c := range checks {
		if !reflect.DeepEqual(c.got, c.want) {
			t.Errorf("%s = %v, want %v", c.field, c.got, c.want)
		}
	}

	if len(parsed.Network.Interfaces) != 1 {
		t.Fatalf("network.interfaces holds %d entries, want 1", len(parsed.Network.Interfaces))
	}
	iface := parsed.Network.Interfaces[0]
	if iface.Name != "en0" || iface.Class != "hardware" || !iface.Up || iface.HardwarePort != "Wi-Fi" {
		t.Errorf("network.interfaces[0] = %+v, want the hardware port en0 up on Wi-Fi", iface)
	}
	if !reflect.DeepEqual(iface.IPs, []string{"192.0.2.10/24"}) {
		t.Errorf("network.interfaces[0].ips = %v, want 192.0.2.10/24", iface.IPs)
	}
	if parsed.Time == "" {
		t.Error("time is empty")
	}
	if _, ok := fields["trigger"]; ok {
		t.Errorf("trigger is present for an empty Trigger: %s", fields["trigger"])
	}
}

func Test_renderLogHeaderAddsTriggerWhenSet(t *testing.T) {
	in := logHeaderTestInput()
	in.Trigger = "send"

	parsed, _ := parseLogHeader(t, renderLogHeader(in))

	if parsed.Trigger != "send" {
		t.Errorf("trigger = %q, want %q", parsed.Trigger, "send")
	}
}

// Test_renderLogHeaderIgnoresConsoleLevel guards the promise that every log
// file starts with a header. The console core sits above info on a default
// start, and the header takes a core of its own.
func Test_renderLogHeaderIgnoresConsoleLevel(t *testing.T) {
	parsed, _ := parseLogHeader(t, renderLogHeader(logHeaderTestInput()))

	if parsed.Level != "info" {
		t.Errorf("level = %q, want %q", parsed.Level, "info")
	}
	if parsed.Message != "Log header" {
		t.Errorf("message = %q, want %q", parsed.Message, "Log header")
	}
}

func Test_logHeaderFromConfigKeepsUpstreamSecretsOut(t *testing.T) {
	old := interceptMode
	t.Cleanup(func() { interceptMode = old })
	interceptMode = ""

	cfg := &ctrld.Config{
		Listener: map[string]*ctrld.ListenerConfig{
			"0":                        {IP: "127.0.0.1", Port: 53},
			logHeaderTestSecret + "-l": {IP: "10.0.0.1", Port: 5354},
		},
		Upstream: map[string]*ctrld.UpstreamConfig{
			"0": {
				Name:        logHeaderTestSecret + "-name",
				Type:        "doh",
				Endpoint:    "https://dns.example/" + logHeaderTestSecret,
				BootstrapIP: "192.0.2.53",
			},
			"1": {Endpoint: "https://dns.example/" + logHeaderTestSecret},
		},
	}
	cfg.Service.InterceptMode = "dns"

	in := logHeaderTestInput()
	logHeaderFromConfig(cfg, &in)

	if in.InterceptMode != "dns" {
		t.Errorf("intercept mode = %q, want %q", in.InterceptMode, "dns")
	}
	if want := []string{"10.0.0.1:5354", "127.0.0.1:53"}; !reflect.DeepEqual(in.Listeners, want) {
		t.Errorf("listeners = %v, want %v", in.Listeners, want)
	}
	if in.UpstreamCount != 2 {
		t.Errorf("upstream count = %d, want 2", in.UpstreamCount)
	}
	if want := []string{"doh", "unspecified"}; !reflect.DeepEqual(in.UpstreamTypes, want) {
		t.Errorf("upstream types = %v, want %v", in.UpstreamTypes, want)
	}

	line := renderLogHeader(in)
	if strings.Contains(string(line), logHeaderTestSecret) {
		t.Errorf("header holds %q: %s", logHeaderTestSecret, line)
	}
}

func Test_logHeaderFromConfigReportsOffWhenUnset(t *testing.T) {
	old := interceptMode
	t.Cleanup(func() { interceptMode = old })
	interceptMode = ""

	var in logHeaderInput
	logHeaderFromConfig(&ctrld.Config{}, &in)

	if in.InterceptMode != "off" {
		t.Errorf("intercept mode = %q, want %q", in.InterceptMode, "off")
	}
}

// Test_renderLogHeaderShowsTheSnapshotOfAState renders the header of one
// network state, so a reader of the file sees every interface of the host in
// one order.
func Test_renderLogHeaderShowsTheSnapshotOfAState(t *testing.T) {
	stubHeaderSnapshotSources(t)
	state := &netmon.State{
		DefaultRouteInterface: "en0",
		HaveV4:                true,
		Interface: map[string]netmon.Interface{
			"en0":   {Interface: &net.Interface{Name: "en0", Flags: net.FlagUp}},
			"awdl0": {Interface: &net.Interface{Name: "awdl0"}},
		},
		InterfaceIPs: map[string][]netip.Prefix{
			"en0":   {netip.MustParsePrefix("192.0.2.10/24"), netip.MustParsePrefix("2001:db8::1/64")},
			"awdl0": {netip.MustParsePrefix("fe80::2/64")},
		},
	}

	in := logHeaderTestInput()
	in.Network = buildNetworkSnapshot(snapshotInputs{
		State:   state,
		RouteV4: defaultRoute{Gateway: "192.0.2.1", Interface: "en0"},
		RouteV6: defaultRoute{Gateway: "fe80::1%en0", Interface: "en0"},
		Meta:    interfaceMetaFor,
	})
	parsed, _ := parseLogHeader(t, renderLogHeader(in))

	if parsed.Network.DefaultRouteV4 != "en0" || parsed.Network.DefaultRouteV6 != "en0" {
		t.Errorf("default route = %q, %q, want en0 for both families", parsed.Network.DefaultRouteV4, parsed.Network.DefaultRouteV6)
	}
	if len(parsed.Network.Interfaces) != 2 {
		t.Fatalf("network.interfaces holds %d entries, want 2", len(parsed.Network.Interfaces))
	}
	if parsed.Network.Interfaces[0].Name != "awdl0" || parsed.Network.Interfaces[0].Class != "airdrop" || parsed.Network.Interfaces[0].Up {
		t.Errorf("network.interfaces[0] = %+v, want awdl0 down in the airdrop class", parsed.Network.Interfaces[0])
	}
	if got := parsed.Network.Interfaces[1].IPs; !reflect.DeepEqual(got, []string{"192.0.2.10/24", "2001:db8::1/64"}) {
		t.Errorf("network.interfaces[1].ips = %v", got)
	}
}

// setupLogHeaderWiringTest puts ctrld in cd mode with a temporary home
// directory, so initInternalLogging writes its files there. Every global that
// the logging setup touches goes back when the test ends.
func setupLogHeaderWiringTest(t *testing.T) string {
	t.Helper()
	stubHeaderSnapshotSources(t)
	origSilent, origCdUID, origHomedir, origVerbose := silent, cdUID, homedir, verbose
	origMainLog := mainLog.Load()
	origLogPathFile := logPathFile.Load()
	t.Cleanup(func() {
		silent, cdUID, homedir, verbose = origSilent, origCdUID, origHomedir, origVerbose
		mainLog.Store(origMainLog)
		logPathFile.Store(origLogPathFile)
	})

	homedir = t.TempDir()
	cdUID = "header-wiring-uid"
	silent, verbose = false, 0
	mainLog.Store(ctrld.NopLogger)
	logPathFile.Store(nil)
	return homedir
}

// startLogHeaderWiringProg runs the internal logging setup and closes both
// files when the test ends.
func startLogHeaderWiringProg(t *testing.T) *prog {
	t.Helper()
	p := &prog{cfg: &ctrld.Config{}}
	p.logger.Store(mainLog.Load())
	p.initInternalLogging(nil)
	t.Cleanup(func() {
		p.internalLogWriter.closeLogFile()
		p.internalJournalWriter.closeLogFile()
	})
	return p
}

// logHeaderFileLines parses every JSON line of a log file. It returns line 1
// and the number of header lines, so a test can tell a missing header from a
// repeated one. The debug stream writes console lines, which hold no header,
// so they do not count.
func logHeaderFileLines(t *testing.T, path string) (logHeaderTestLine, int) {
	t.Helper()
	content := strings.TrimRight(rotatingFileTestContent(t, path), "\n")
	if content == "" {
		t.Fatalf("%s is empty", path)
	}
	var firstLine logHeaderTestLine
	headers := 0
	for i, line := range strings.Split(content, "\n") {
		if i > 0 && !strings.HasPrefix(line, "{") {
			continue
		}
		var parsed logHeaderTestLine
		if err := json.Unmarshal([]byte(line), &parsed); err != nil {
			t.Fatalf("parse line %d of %s (%q): %v", i+1, path, line, err)
		}
		if i == 0 {
			firstLine = parsed
		}
		if parsed.Message == logHeaderMessage {
			headers++
		}
	}
	return firstLine, headers
}

func Test_logHeaderWiring_writesHeaderOnStart(t *testing.T) {
	dir := setupLogHeaderWiringTest(t)

	startLogHeaderWiringProg(t)

	for _, name := range []string{logFileName, journalLogFileName} {
		path := filepath.Join(dir, name)
		firstLine, headers := logHeaderFileLines(t, path)
		if firstLine.Message != logHeaderMessage {
			t.Errorf("line 1 of %s = %q, want %q", path, firstLine.Message, logHeaderMessage)
		}
		if !firstLine.Journal {
			t.Errorf("line 1 of %s carries no journal marker", path)
		}
		if want := redactToken(cdUID); firstLine.ResolverUID != want {
			t.Errorf("resolver_uid in %s = %q, want %q", path, firstLine.ResolverUID, want)
		}
		if headers != 1 {
			t.Errorf("%s holds %d header lines, want 1", path, headers)
		}
	}
}

func Test_logHeaderInput_keepsSecretsOut(t *testing.T) {
	dir := setupLogHeaderWiringTest(t)
	origInterceptMode := interceptMode
	t.Cleanup(func() { interceptMode = origInterceptMode })
	interceptMode = ""
	p := &prog{cfg: &ctrld.Config{
		Listener: map[string]*ctrld.ListenerConfig{
			logHeaderTestSecret + "-listener": {IP: "127.0.0.1", Port: 53},
		},
		Upstream: map[string]*ctrld.UpstreamConfig{
			"0": {
				Name:        logHeaderTestSecret + "-name",
				Type:        "doh",
				Endpoint:    "https://dns.example/" + logHeaderTestSecret,
				BootstrapIP: "192.0.2.53",
				Domain:      logHeaderTestSecret + ".example",
			},
		},
	}}
	p.initInternalLogging(nil)
	t.Cleanup(func() {
		p.internalLogWriter.closeLogFile()
		p.internalJournalWriter.closeLogFile()
	})

	if line := renderLogHeader(p.logHeaderInput()); strings.Contains(string(line), logHeaderTestSecret) {
		t.Errorf("the header holds %q: %s", logHeaderTestSecret, line)
	}

	for _, name := range []string{logFileName, journalLogFileName} {
		path := filepath.Join(dir, name)
		if content := rotatingFileTestContent(t, path); strings.Contains(content, logHeaderTestSecret) {
			t.Errorf("%s holds %q: %s", path, logHeaderTestSecret, content)
		}
	}
}

func Test_logHeaderWiring_secondInitAddsNoHeader(t *testing.T) {
	dir := setupLogHeaderWiringTest(t)
	p := startLogHeaderWiringProg(t)

	p.initInternalLogging(nil)

	for _, name := range []string{logFileName, journalLogFileName} {
		path := filepath.Join(dir, name)
		if _, headers := logHeaderFileLines(t, path); headers != 1 {
			t.Errorf("%s holds %d header lines after a second start, want 1", path, headers)
		}
	}
}

func Test_logHeaderWiring_headerLeadsRotatedFile(t *testing.T) {
	captureMainLog(t)
	lw, path := newTestFileLogWriter(t, testLogWriterBudget)
	header := string(renderLogHeader(logHeaderInput{Version: "v1"}))

	rf := lw.rotating()
	rf.setHeader([]byte(header))
	if err := rf.writeHeader(); err != nil {
		t.Fatalf("writeHeader: %v", err)
	}
	linesPerFile := int(testLogWriterBudget.maxSize) / rotatingFileTestLineSize
	for seq := 1; seq <= linesPerFile+1; seq++ {
		if _, err := lw.Write(rotatingFileTestLine(1, seq)); err != nil {
			t.Fatalf("write line %d: %v", seq, err)
		}
	}

	for _, name := range []string{path + ".1", path} {
		if content := rotatingFileTestContent(t, name); !strings.HasPrefix(content, header) {
			t.Errorf("%s starts with %q, want the header", name, strings.SplitN(content, "\n", 2)[0])
		}
	}
}

func Test_logHeaderWiring_restartAppendsHeader(t *testing.T) {
	dir := setupLogHeaderWiringTest(t)
	path := filepath.Join(dir, logFileName)
	const seed = `{"level":"info","message":"line of the run before"}`
	if err := os.WriteFile(path, []byte(seed+"\n"), 0o600); err != nil {
		t.Fatalf("seed %s: %v", path, err)
	}

	startLogHeaderWiringProg(t)

	lines := strings.Split(strings.TrimRight(rotatingFileTestContent(t, path), "\n"), "\n")
	if len(lines) < 2 {
		t.Fatalf("%s holds %d lines, want the seed line and the header", path, len(lines))
	}
	if lines[0] != seed {
		t.Errorf("line 1 of %s = %q, want the seed line", path, lines[0])
	}
	var header logHeaderTestLine
	if err := json.Unmarshal([]byte(lines[1]), &header); err != nil {
		t.Fatalf("parse line 2 of %s (%q): %v", path, lines[1], err)
	}
	if header.Message != logHeaderMessage {
		t.Errorf("line 2 of %s = %q, want %q", path, header.Message, logHeaderMessage)
	}
	if _, headers := logHeaderFileLines(t, path); headers != 1 {
		t.Errorf("%s holds %d header lines, want 1", path, headers)
	}
}

func Test_logHeaderWiring_usesLastNetworkState(t *testing.T) {
	stubHeaderSnapshotSources(t)
	origRead := readNetworkSourceStateFn
	t.Cleanup(func() { readNetworkSourceStateFn = origRead })
	p := &prog{cfg: &ctrld.Config{}}
	p.logger.Store(mainLog.Load())

	p.lastNetworkState.Store(&netmon.State{
		DefaultRouteInterface: "en7",
		Interface:             map[string]netmon.Interface{"en7": {Interface: &net.Interface{Name: "en7", Flags: net.FlagUp}}},
		InterfaceIPs:          map[string][]netip.Prefix{"en7": {netip.MustParsePrefix("192.0.2.7/24")}},
	})

	if got := p.logHeaderInput().Network.DefaultRouteV4; got != "en7" {
		t.Errorf("default_route_v4 = %q, want %q", got, "en7")
	}
	if got := p.logHeaderInput().Network.GatewayV4; got != "192.0.2.1" {
		t.Errorf("gateway_v4 = %q, want %q", got, "192.0.2.1")
	}

	p.lastNetworkState.Store(nil)
	readNetworkSourceStateFn = func() (*netmon.State, error) {
		return &netmon.State{
			Interface:    map[string]netmon.Interface{"en9": {Interface: &net.Interface{Name: "en9", Flags: net.FlagUp}}},
			InterfaceIPs: map[string][]netip.Prefix{"en9": {netip.MustParsePrefix("192.0.2.9/24")}},
		}, nil
	}

	network := p.logHeaderInput().Network
	if len(network.Interfaces) != 1 || network.Interfaces[0].Name != "en9" || !network.Interfaces[0].Up {
		t.Fatalf("interfaces = %+v, want one up en9", network.Interfaces)
	}
	if !network.HaveV4 {
		t.Error("have_v4 = false, want true for a global unicast v4 address")
	}
	if network.HaveV6 {
		t.Error("have_v6 = true, want false without a v6 address")
	}
}

// stubHeaderSnapshotSources keeps the header snapshot away from the host. One
// render reads the hardware ports, the route table, and the NAT64 class, and no
// test may run the commands behind them.
func stubHeaderSnapshotSources(t *testing.T) {
	t.Helper()
	stubSnapshotDNS64(t)
	stubSnapshotGateways(t, "192.0.2.1", "")
	stubSnapshotPlatformMeta(t, nil)
	stubSnapshotVirtualSet(t)
}

// stubLogHeaderNetworkRead makes the fresh network read return one up
// interface, so a header test never depends on the host network.
func stubLogHeaderNetworkRead(t *testing.T, name string) {
	t.Helper()
	stubHeaderSnapshotSources(t)
	origRead := readNetworkSourceStateFn
	t.Cleanup(func() { readNetworkSourceStateFn = origRead })
	readNetworkSourceStateFn = func() (*netmon.State, error) {
		return &netmon.State{
			Interface:    map[string]netmon.Interface{name: {Interface: &net.Interface{Name: name, Flags: net.FlagUp}}},
			InterfaceIPs: map[string][]netip.Prefix{name: {netip.MustParsePrefix("192.0.2.9/24")}},
		}, nil
	}
}

func Test_sendLogHeader_usesFreshNetworkAndTrigger(t *testing.T) {
	stubHeaderSnapshotSources(t)
	stubLogHeaderNetworkRead(t, "en9")
	p := &prog{cfg: &ctrld.Config{}}
	p.logger.Store(mainLog.Load())
	p.lastNetworkState.Store(&netmon.State{
		DefaultRouteInterface: "en7",
		Interface:             map[string]netmon.Interface{"en7": {Interface: &net.Interface{Name: "en7", Flags: net.FlagUp}}},
		InterfaceIPs:          map[string][]netip.Prefix{"en7": {netip.MustParsePrefix("192.0.2.7/24")}},
	})

	parsed, _ := parseLogHeader(t, p.sendLogHeader())

	if parsed.Trigger != "send" {
		t.Errorf("trigger = %q, want %q", parsed.Trigger, "send")
	}
	if parsed.Message != logHeaderMessage {
		t.Errorf("message = %q, want %q", parsed.Message, logHeaderMessage)
	}
	names := make([]string, 0, len(parsed.Network.Interfaces))
	for _, iface := range parsed.Network.Interfaces {
		names = append(names, iface.Name)
	}
	if want := []string{"en9"}; !reflect.DeepEqual(names, want) {
		t.Fatalf("network.interfaces = %v, want %v from the fresh read", names, want)
	}
}

// Test_logHeaderInputReadsTheConfigUnderTheLock renders headers beside the
// config swap of a reload. The race detector fails the test when the render
// reads the config outside the lock.
func Test_logHeaderInputReadsTheConfigUnderTheLock(t *testing.T) {
	stubLogHeaderNetworkRead(t, "en0")
	p := &prog{cfg: &ctrld.Config{
		Listener: map[string]*ctrld.ListenerConfig{"0": {IP: "127.0.0.1", Port: 53}},
		Upstream: map[string]*ctrld.UpstreamConfig{"0": {Type: "doh"}},
	}}
	reloaded := &ctrld.Config{
		Listener: map[string]*ctrld.ListenerConfig{"0": {IP: "127.0.0.1", Port: 5354}},
		Upstream: map[string]*ctrld.UpstreamConfig{"0": {Type: "doq"}, "1": {Type: "legacy"}},
	}

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			p.mu.Lock()
			*p.cfg = *reloaded
			p.mu.Unlock()
		}
	}()
	for i := 0; i < 300; i++ {
		if in := p.logHeaderInput(); len(in.Listeners) != 1 {
			t.Fatalf("listeners = %v, want one", in.Listeners)
		}
	}
	close(stop)
	<-done
}

// Test_renderLogHeaderPassesTheSink puts a provisioning secret where the
// header does not expect one. The header is the first line of every file and
// of every upload, so it must pass the same redaction as every other line.
func Test_renderLogHeaderPassesTheSink(t *testing.T) {
	origUID := cdUID
	cdUID = "abcd1234SECRETUID"
	t.Cleanup(func() { cdUID = origUID })

	line := string(renderLogHeader(logHeaderInput{Version: "1.0", LogFiles: []string{"/var/log/" + cdUID + "/ctrld.log"}}))

	if strings.Contains(line, cdUID) {
		t.Fatalf("the header holds the secret: %s", line)
	}
}
