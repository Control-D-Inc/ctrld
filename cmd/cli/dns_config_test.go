package cli

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const scutilDNSFixture = `DNS configuration

resolver #1
  search domain[0] : corp.example
  nameserver[0] : 192.168.50.200
  nameserver[1] : 192.168.50.1
  if_index : 16 (en0)
  flags    : Request A records, Request AAAA records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)
  order    : 200000

resolver #2
  nameserver[0] : 100.100.100.100
  if_index : 28 (utun4)
  flags    : Supplemental, Request A records, Request AAAA records
  reach    : 0x00000003 (Reachable,Transient Connection)
  order    : 101600

resolver #3
  domain   : local
  options  : mdns
  timeout  : 5
  flags    : Request A records
  reach    : 0x00000000 (Not Reachable)
  order    : 300000

DNS configuration (for scoped queries)

resolver #1
  nameserver[0] : 192.168.50.200
  if_index : 16 (en0)
  flags    : Scoped, Request A records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)
`

const scutilDNSScopedOnlyFixture = `DNS configuration

DNS configuration (for scoped queries)

resolver #1
  nameserver[0] : 192.168.50.200
  if_index : 16 (en0)
  flags    : Scoped, Request A records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)
`

var errStubResolverRun = errors.New("scutil failed")

func wifiResolverEntry() dnsResolverEntry {
	return dnsResolverEntry{
		Order:         200000,
		Nameservers:   []string{"192.168.50.200", "192.168.50.1"},
		IfIndex:       16,
		Interface:     "en0",
		Flags:         "Request A records, Request AAAA records",
		SearchDomains: []string{"corp.example"},
		Reachable:     "Reachable,Directly Reachable Address",
	}
}

func vpnResolverEntry() dnsResolverEntry {
	return dnsResolverEntry{
		Order:       101600,
		Nameservers: []string{"100.100.100.100"},
		IfIndex:     28,
		Interface:   "utun4",
		Flags:       "Supplemental, Request A records, Request AAAA records",
		Reachable:   "Reachable,Transient Connection",
	}
}

func mdnsResolverEntry() dnsResolverEntry {
	return dnsResolverEntry{
		Order:     300000,
		Flags:     "Request A records",
		Reachable: "Not Reachable",
	}
}

func Test_parseSCUtilDNS(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []dnsResolverEntry
	}{
		{
			name:  "both tables",
			input: scutilDNSFixture,
			want: []dnsResolverEntry{wifiResolverEntry(), vpnResolverEntry(), mdnsResolverEntry(), {
				Nameservers: []string{"192.168.50.200"},
				IfIndex:     16,
				Interface:   "en0",
				Flags:       "Scoped, Request A records",
				Reachable:   "Reachable,Directly Reachable Address",
				Scoped:      true,
			}},
		},
		{
			name:  "scoped table when the first is empty",
			input: scutilDNSScopedOnlyFixture,
			want: []dnsResolverEntry{{
				Nameservers: []string{"192.168.50.200"},
				IfIndex:     16,
				Interface:   "en0",
				Flags:       "Scoped, Request A records",
				Reachable:   "Reachable,Directly Reachable Address",
				Scoped:      true,
			}},
		},
		{
			name:  "no output",
			input: "",
			want:  nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseSCUtilDNS(strings.NewReader(tc.input))
			if err != nil {
				t.Fatalf("parseSCUtilDNS() error = %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("parseSCUtilDNS() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func Test_diffResolverTables(t *testing.T) {
	changedWiFi := wifiResolverEntry()
	changedWiFi.Nameservers = []string{"10.0.0.1"}
	changedWiFi.Action = resolverActionChanged
	vanishedVPN := vpnResolverEntry()
	vanishedVPN.Nameservers = nil
	vanishedVPN.Action = resolverActionRemoved
	appearedVPN := vpnResolverEntry()
	appearedVPN.Action = resolverActionAdded

	tests := []struct {
		name   string
		before []dnsResolverEntry
		after  []dnsResolverEntry
		want   []dnsResolverEntry
	}{
		{
			name:   "no change",
			before: []dnsResolverEntry{wifiResolverEntry(), vpnResolverEntry()},
			after:  []dnsResolverEntry{wifiResolverEntry(), vpnResolverEntry()},
			want:   nil,
		},
		{
			name:   "one resolver changed",
			before: []dnsResolverEntry{wifiResolverEntry(), vpnResolverEntry()},
			after:  []dnsResolverEntry{changedWiFi, vpnResolverEntry()},
			want:   []dnsResolverEntry{changedWiFi},
		},
		{
			name:   "one resolver vanished",
			before: []dnsResolverEntry{wifiResolverEntry(), vpnResolverEntry()},
			after:  []dnsResolverEntry{wifiResolverEntry()},
			want:   []dnsResolverEntry{vanishedVPN},
		},
		{
			name:   "one resolver appeared",
			before: []dnsResolverEntry{wifiResolverEntry()},
			after:  []dnsResolverEntry{wifiResolverEntry(), vpnResolverEntry()},
			want:   []dnsResolverEntry{appearedVPN},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := diffResolverTables(tc.before, tc.after)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("diffResolverTables() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func Test_diffResolverTablesKeepsTheInput(t *testing.T) {
	before := []dnsResolverEntry{vpnResolverEntry()}
	diffResolverTables(before, nil)
	if !reflect.DeepEqual(before[0], vpnResolverEntry()) {
		t.Fatalf("before entry = %+v, want %+v", before[0], vpnResolverEntry())
	}
}

// resolverRunResult is one answer of the stub runner.
type resolverRunResult struct {
	table []dnsResolverEntry
	err   error
}

// stubResolverRunner answers one result per call and repeats the last one.
type stubResolverRunner struct {
	mu      sync.Mutex
	results []resolverRunResult
	calls   int
}

func (s *stubResolverRunner) run() ([]dnsResolverEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := s.results[min(s.calls, len(s.results)-1)]
	s.calls++
	return result.table, result.err
}

func Test_dnsConfigPollerNextDelay(t *testing.T) {
	base := time.Date(2026, 9, 17, 10, 0, 0, 0, time.UTC)
	tests := []struct {
		name     string
		activity bool
		elapsed  time.Duration
		want     time.Duration
	}{
		{name: "nine minutes after activity", activity: true, elapsed: 9 * time.Minute, want: dnsConfigFastInterval},
		{name: "eleven minutes after activity", activity: true, elapsed: 11 * time.Minute, want: dnsConfigSlowInterval},
		{name: "no activity yet", elapsed: time.Minute, want: dnsConfigSlowInterval},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			poller := newDNSConfigPoller(func() ([]dnsResolverEntry, error) { return nil, nil })
			if tc.activity {
				poller.noteActivity(base)
			}
			if got := poller.nextDelay(base.Add(tc.elapsed)); got != tc.want {
				t.Fatalf("nextDelay() = %s, want %s", got, tc.want)
			}
		})
	}
}

func Test_dnsConfigPollerPollOnce(t *testing.T) {
	now := time.Date(2026, 9, 17, 10, 0, 0, 0, time.UTC)
	baseline := []dnsResolverEntry{wifiResolverEntry(), vpnResolverEntry()}
	changedWiFi := wifiResolverEntry()
	changedWiFi.Nameservers = []string{"10.0.0.1"}
	changedWiFi.Action = resolverActionChanged
	runner := &stubResolverRunner{results: []resolverRunResult{
		{table: baseline},
		{err: errStubResolverRun},
		{table: baseline},
		{table: []dnsResolverEntry{changedWiFi, vpnResolverEntry()}},
	}}
	poller := newDNSConfigPoller(runner.run)

	if got := poller.pollOnce(now); got != nil {
		t.Fatalf("baseline poll = %+v, want nil", got)
	}
	if got := poller.pollOnce(now.Add(time.Minute)); got != nil {
		t.Fatalf("failed poll = %+v, want nil", got)
	}
	if got := poller.pollOnce(now.Add(2 * time.Minute)); got != nil {
		t.Fatalf("poll after a failure = %+v, want nil", got)
	}
	want := []dnsResolverEntry{changedWiFi}
	if got := poller.pollOnce(now.Add(3 * time.Minute)); !reflect.DeepEqual(got, want) {
		t.Fatalf("changed poll = %+v, want %+v", got, want)
	}
}

func Test_dnsConfigPollerLoop(t *testing.T) {
	previous := dnsConfigDelayFn
	dnsConfigDelayFn = func(*dnsConfigPoller, time.Time) time.Duration { return time.Millisecond }
	t.Cleanup(func() { dnsConfigDelayFn = previous })

	changedWiFi := wifiResolverEntry()
	changedWiFi.Nameservers = []string{"10.0.0.1"}
	changedWiFi.Action = resolverActionChanged
	runner := &stubResolverRunner{results: []resolverRunResult{
		{table: []dnsResolverEntry{wifiResolverEntry()}},
		{table: []dnsResolverEntry{changedWiFi}},
	}}
	poller := newDNSConfigPoller(runner.run)

	emitted := make(chan []dnsResolverEntry, 4)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		poller.loop(stop, func(changed []dnsResolverEntry) { emitted <- changed })
	}()

	select {
	case got := <-emitted:
		want := []dnsResolverEntry{changedWiFi}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("emitted = %+v, want %+v", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the loop emitted no change")
	}

	close(stop)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the loop did not stop")
	}
}

// Test_dnsConfigPollerLoopWakesOnActivity proves that a network event does not
// wait for a sleeping timer. The delay is one hour until the event arrives, so
// a loop without the kick would poll after the test deadline.
func Test_dnsConfigPollerLoopWakesOnActivity(t *testing.T) {
	var kicked atomic.Bool
	parked := make(chan struct{}, 1)
	previous := dnsConfigDelayFn
	dnsConfigDelayFn = func(*dnsConfigPoller, time.Time) time.Duration {
		if kicked.Load() {
			return time.Millisecond
		}
		select {
		case parked <- struct{}{}:
		default:
		}
		return time.Hour
	}
	t.Cleanup(func() { dnsConfigDelayFn = previous })

	changedWiFi := wifiResolverEntry()
	changedWiFi.Nameservers = []string{"10.0.0.1"}
	changedWiFi.Action = resolverActionChanged
	runner := &stubResolverRunner{results: []resolverRunResult{
		{table: []dnsResolverEntry{wifiResolverEntry()}},
		{table: []dnsResolverEntry{changedWiFi}},
	}}
	poller := newDNSConfigPoller(runner.run)

	emitted := make(chan []dnsResolverEntry, 4)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		poller.loop(stop, func(changed []dnsResolverEntry) { emitted <- changed })
	}()
	t.Cleanup(func() {
		close(stop)
		<-done
	})

	// The kick matters only once the loop waits on the long delay.
	select {
	case <-parked:
	case <-time.After(5 * time.Second):
		t.Fatal("the loop did not park on the long delay")
	}
	kicked.Store(true)
	poller.noteActivity(time.Now())

	select {
	case got := <-emitted:
		want := []dnsResolverEntry{changedWiFi}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("emitted = %+v, want %+v", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the loop polled no table after the activity")
	}
}

// Test_dnsConfigPollerLoopTakesABaseline proves that the loop reads the table
// once at entry. Without that read the first change after the start reports
// the whole table.
func Test_dnsConfigPollerLoopTakesABaseline(t *testing.T) {
	previous := dnsConfigDelayFn
	dnsConfigDelayFn = func(*dnsConfigPoller, time.Time) time.Duration { return time.Hour }
	t.Cleanup(func() { dnsConfigDelayFn = previous })

	runner := &stubResolverRunner{results: []resolverRunResult{{table: []dnsResolverEntry{wifiResolverEntry()}}}}
	poller := newDNSConfigPoller(runner.run)

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		poller.loop(stop, func([]dnsResolverEntry) { t.Error("the baseline read reported a change") })
	}()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		runner.mu.Lock()
		calls := runner.calls
		runner.mu.Unlock()
		if calls > 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	close(stop)
	<-done

	runner.mu.Lock()
	defer runner.mu.Unlock()
	if runner.calls != 1 {
		t.Fatalf("reads at the loop entry: got %d, want 1", runner.calls)
	}
	if !poller.started {
		t.Fatal("the loop took no baseline")
	}
}

// oversizedSCUtilDNS is a table with one line that no scanner buffer holds. A
// stalled or hostile process produces output of this shape.
func oversizedSCUtilDNS() string {
	return "DNS configuration\n\nresolver #1\n  nameserver[0] : " + strings.Repeat("9", 70*1024) + "\n"
}

// Test_parseSCUtilDNSRejectsAnOversizedLine proves that a line the scanner
// cannot hold ends the read with an error. A part of a table must not pass for
// the table of the host.
func Test_parseSCUtilDNSRejectsAnOversizedLine(t *testing.T) {
	got, err := parseSCUtilDNS(strings.NewReader(oversizedSCUtilDNS()))
	if err == nil {
		t.Fatal("parseSCUtilDNS accepted a 70 KiB line")
	}
	if got != nil {
		t.Fatalf("parseSCUtilDNS() = %+v, want nil", got)
	}
}

// Test_parseSCUtilDNSRejectsAnOversizedOutput proves that output past the
// bound ends the read with an error instead of a table cut in the middle.
func Test_parseSCUtilDNSRejectsAnOversizedOutput(t *testing.T) {
	block := "resolver #1\n  nameserver[0] : 192.168.50.200\n  order    : 200000\n"
	repeats := scutilDNSOutputLimit/len(block) + 2
	got, err := parseSCUtilDNS(strings.NewReader("DNS configuration\n\n" + strings.Repeat(block, repeats)))
	if err == nil {
		t.Fatal("parseSCUtilDNS accepted output past the bound")
	}
	if got != nil {
		t.Fatalf("parseSCUtilDNS() = %+v, want nil", got)
	}
}

// Test_dnsConfigPollerKeepsTheTableOnAnOversizedRead proves that a read the
// parser rejects reports nothing and keeps the table of the read before.
func Test_dnsConfigPollerKeepsTheTableOnAnOversizedRead(t *testing.T) {
	now := time.Date(2026, 9, 17, 10, 0, 0, 0, time.UTC)
	outputs := []string{scutilDNSFixture, oversizedSCUtilDNS(), scutilDNSFixture}
	calls := 0
	poller := newDNSConfigPoller(func() ([]dnsResolverEntry, error) {
		output := outputs[min(calls, len(outputs)-1)]
		calls++
		return parseSCUtilDNS(strings.NewReader(output))
	})

	if got := poller.pollOnce(now); got != nil {
		t.Fatalf("baseline poll = %+v, want nil", got)
	}
	if got := poller.pollOnce(now.Add(time.Minute)); got != nil {
		t.Fatalf("oversized poll = %+v, want nil", got)
	}
	if got := poller.pollOnce(now.Add(2 * time.Minute)); got != nil {
		t.Fatalf("poll after the oversized read = %+v, want nil", got)
	}
}

// scutilTwoTables renders a host with one unscoped resolver and one scoped
// resolver, the shape of a Mac with two active services.
func scutilTwoTables(unscoped, scoped string) string {
	return "DNS configuration\n\nresolver #1\n  nameserver[0] : " + unscoped + "\n  if_index : 14 (en0)\n" +
		"  flags    : Request A records\n  reach    : 0x00020002 (Reachable,Directly Reachable Address)\n\n" +
		"DNS configuration (for scoped queries)\n\nresolver #1\n  nameserver[0] : " + scoped + "\n  if_index : 15 (en1)\n" +
		"  flags    : Scoped, Request A records\n  reach    : 0x00020002 (Reachable,Directly Reachable Address)\n"
}

// Test_diffResolverTablesSeesAScopedChange changes the scoped resolver of a
// second service while the unscoped resolver stays. The diff must report the
// scoped change, because the two tables are not copies of each other.
func Test_diffResolverTablesSeesAScopedChange(t *testing.T) {
	before, err := parseSCUtilDNS(strings.NewReader(scutilTwoTables("192.168.1.1", "10.0.0.1")))
	if err != nil {
		t.Fatal(err)
	}
	after, err := parseSCUtilDNS(strings.NewReader(scutilTwoTables("192.168.1.1", "9.9.9.9")))
	if err != nil {
		t.Fatal(err)
	}
	changed := diffResolverTables(before, after)
	if len(changed) != 1 || len(changed[0].Nameservers) != 1 || changed[0].Nameservers[0] != "9.9.9.9" {
		t.Fatalf("changed resolvers = %+v, want the scoped resolver with 9.9.9.9", changed)
	}
	if !changed[0].Scoped || before[0].Scoped || len(before) != 2 {
		t.Fatalf("scope marks: changed %v, before %+v; want the scoped resolver marked and the unscoped one not", changed[0].Scoped, before)
	}
}

// Test_dnsConfigPollerPollsUnderContinuousActivity kicks the poller faster
// than its fast interval. A kick must not push the read back again and again,
// or a host in a storm of transitions never reports a resolver change.
func Test_dnsConfigPollerPollsUnderContinuousActivity(t *testing.T) {
	var reads atomic.Int64
	changed := wifiResolverEntry()
	changed.Nameservers = []string{"9.9.9.9"}
	p := newDNSConfigPoller(func() ([]dnsResolverEntry, error) {
		if reads.Add(1) == 1 {
			return []dnsResolverEntry{wifiResolverEntry()}, nil
		}
		return []dnsResolverEntry{changed}, nil
	})
	origDelay := dnsConfigDelayFn
	t.Cleanup(func() { dnsConfigDelayFn = origDelay })
	dnsConfigDelayFn = func(*dnsConfigPoller, time.Time) time.Duration { return 50 * time.Millisecond }

	var emits atomic.Int64
	stop := make(chan struct{})
	done := p.startLoop(stop, func([]dnsResolverEntry) { emits.Add(1) })
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		p.noteActivity(time.Now())
		time.Sleep(5 * time.Millisecond)
	}
	close(stop)
	<-done

	if emits.Load() == 0 {
		t.Fatalf("no resolver event during 500 ms of activity (reads %d)", reads.Load())
	}
}

// scutilScopedTable renders the scoped table the way macOS prints it: one
// resolver per interface and no order line.
func scutilScopedTable(resolvers ...[2]string) string {
	var b strings.Builder
	b.WriteString("DNS configuration\n\nresolver #1\n  nameserver[0] : 100.100.100.100\n  if_index : 28 (utun4)\n  flags    : Request A records, Request AAAA records\n  reach    : 0x00000003 (Reachable,Transient Connection)\n  order    : 200000\n\n")
	b.WriteString("DNS configuration (for scoped queries)\n\n")
	for i, resolver := range resolvers {
		fmt.Fprintf(&b, "resolver #%d\n  nameserver[0] : %s\n  if_index : %s\n  flags    : Scoped, Request A records\n  reach    : 0x00020002 (Reachable,Directly Reachable Address)\n\n", i+1, resolver[1], resolver[0])
	}
	return b.String()
}

// Test_diffResolverTablesKeysScopedResolversByInterface inserts a scoped
// resolver between two others and removes it again. The scoped table has no
// order line, so the interface is the identity, and the diff must name the
// resolver that came and went, not its neighbors.
func Test_diffResolverTablesKeysScopedResolversByInterface(t *testing.T) {
	en0 := [2]string{"16 (en0)", "192.168.50.200"}
	en7 := [2]string{"30 (en7)", "10.9.9.1"}
	utun := [2]string{"28 (utun4)", "100.100.100.100"}
	before, err := parseSCUtilDNS(strings.NewReader(scutilScopedTable(en0, utun)))
	if err != nil {
		t.Fatal(err)
	}
	after, err := parseSCUtilDNS(strings.NewReader(scutilScopedTable(en0, en7, utun)))
	if err != nil {
		t.Fatal(err)
	}

	inserted := diffResolverTables(before, after)
	if len(inserted) != 1 || inserted[0].Interface != "en7" || inserted[0].Nameservers == nil {
		t.Fatalf("insert of en7 reported %+v, want en7 alone with its nameserver", inserted)
	}
	removed := diffResolverTables(after, before)
	if len(removed) != 1 || removed[0].Interface != "en7" || removed[0].Nameservers != nil {
		t.Fatalf("removal of en7 reported %+v, want en7 alone without nameservers", removed)
	}
}

// Test_diffResolverTablesNamesTheAction tells a resolver that came from one
// that went. An mDNS resolver has no nameservers, so without the action the
// two events read the same.
func Test_diffResolverTablesNamesTheAction(t *testing.T) {
	mdns := "DNS configuration\n\nresolver #1\n  domain   : local\n  options  : mdns\n  timeout  : 5\n  flags    : Request A records, Request AAAA records\n  reach    : 0x00000000 (Not Reachable)\n  order    : 300000\n"
	table, err := parseSCUtilDNS(strings.NewReader(mdns))
	if err != nil {
		t.Fatal(err)
	}
	appeared := diffResolverTables(nil, table)
	vanished := diffResolverTables(table, nil)
	if len(appeared) != 1 || appeared[0].Action != resolverActionAdded {
		t.Fatalf("appeared = %+v, want one resolver with action added", appeared)
	}
	if len(vanished) != 1 || vanished[0].Action != resolverActionRemoved {
		t.Fatalf("vanished = %+v, want one resolver with action removed", vanished)
	}
	moved := wifiResolverEntry()
	moved.Nameservers = []string{"9.9.9.9"}
	changed := diffResolverTables([]dnsResolverEntry{wifiResolverEntry()}, []dnsResolverEntry{moved})
	if len(changed) != 1 || changed[0].Action != resolverActionChanged {
		t.Fatalf("changed = %+v, want one resolver with action changed", changed)
	}
}
