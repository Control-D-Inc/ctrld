package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Native-format provenance: macOS pfctl's @N / Owner / Evaluations / Inserted
// layout is published at https://apple.stackexchange.com/questions/335019
// (pfctl -vvv -s all); the counter layout is also reported on macOS 26.3 at
// https://apple.stackexchange.com/questions/486150 (pfctl -s rules -v).
// This is an ADAPTED fixture, not a capture from a ctrld host: headers use the
// two expanded forms of generatePFRules' IPv6 DNS block, and numbers are test
// values. Keep the native spacing/metadata; do not use pf.conf input as output.
const pfDiagnosticFixture = `@30 block drop out quick on ! lo0 inet6 proto udp from any to any port = 53
  [ Owner : nil          Priority : 0     ]
  [ Evaluations: 574091    Packets: 812       Bytes: 51968       States: 0     ]
  [ Inserted: uid 0 pid 68 ]
@31 block drop out quick on ! lo0 inet6 proto tcp from any to any port = 53
  [ Owner : nil          Priority : 0     ]
  [ Evaluations: 573678    Packets: 210       Bytes: 13152       States: 0     ]
  [ Inserted: uid 0 pid 68 ]
`

func TestPFDiagnosticNativeFormat(t *testing.T) {
	s := parsePFDiagnostic([]byte(pfDiagnosticFixture))
	if s.Code != "ok" || !s.UDP.Installed || !s.TCP.Installed || !s.UDP.Known || !s.TCP.Known || s.UDP.Packets != 812 || s.TCP.Packets != 210 {
		t.Fatalf("native-format fixture: %+v", s)
	}
	// IDs and metadata do not become logged identity, and need not be stable.
	changed := strings.NewReplacer("@30", "@1", "@31", "@2", "! lo0", "!lo0", "pid 68", "pid 99").Replace(pfDiagnosticFixture)
	if got := parsePFDiagnostic([]byte(changed)); got != s {
		t.Fatalf("unstable identity: %+v", got)
	}
}

func TestPFDiagnosticUnknownIsNotZero(t *testing.T) {
	for _, tc := range []struct {
		name, input, code string
		installed         bool
	}{
		{"empty", "", "rules_not_observed", false},
		{"unrelated", strings.ReplaceAll(pfDiagnosticFixture, "inet6", "inet"), "rules_not_observed", false},
		{"other interface", strings.ReplaceAll(pfDiagnosticFixture, "! lo0", "en0"), "rules_not_observed", false},
		{"not exact", strings.ReplaceAll(pfDiagnosticFixture, "port = 53", "port = 53 label private"), "rules_not_observed", false},
		{"malformed", strings.ReplaceAll(pfDiagnosticFixture, "Packets:", "Packets: invalid"), "partial_or_malformed", true},
		{"overflow", strings.ReplaceAll(pfDiagnosticFixture, "Packets:", "Packets: 18446744073709551616"), "partial_or_malformed", true},
		{"duplicate", pfDiagnosticFixture + pfDiagnosticFixture, "ambiguous_rules", true},
		{"no counters", strings.Split(pfDiagnosticFixture, "\n")[0], "partial_or_malformed", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := parsePFDiagnostic([]byte(tc.input))
			if s.Code != tc.code || s.UDP.Installed != tc.installed || s.UDP.Known || s.TCP.Known {
				t.Fatalf("unknown misreported: %+v", s)
			}
		})
	}
	zero := strings.NewReplacer("812", "0", "210", "0").Replace(pfDiagnosticFixture)
	if s := parsePFDiagnostic([]byte(zero)); s.Code != "ok" || !s.UDP.Known || s.UDP.Packets != 0 {
		t.Fatalf("real zero: %+v", s)
	}
	// A missing UDP counter must not consume the following unrelated rule's one.
	input := strings.Split(pfDiagnosticFixture, "\n")[0] + "\n@32 pass out all\n  [ Evaluations: 1 Packets: 900 Bytes: 100 States: 0 ]\n"
	if s := parsePFDiagnostic([]byte(input)); s.UDP.Known {
		t.Fatalf("borrowed unrelated counter: %+v", s)
	}
}

func TestPFDiagnosticProcess(t *testing.T) {
	switch os.Getenv("CTRLD_PF_DIAGNOSTIC_TEST") {
	case "":
		return
	case "ok":
		fmt.Print(pfDiagnosticFixture)
	case "failure":
		fmt.Print(pfDiagnosticFixture)
		fmt.Fprint(os.Stderr, "private rules/client-address")
		os.Exit(1)
	case "limit":
		fmt.Print(strings.Repeat("x", pfDiagnosticMaxBytes+1))
	case "hang":
		time.Sleep(time.Minute)
	}
	os.Exit(0)
}

func pfDiagnosticTestCommand(ctx context.Context, mode string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPFDiagnosticProcess$")
	cmd.Env = append(os.Environ(), "CTRLD_PF_DIAGNOSTIC_TEST="+mode)
	return cmd
}

func TestPFDiagnosticCommandBounds(t *testing.T) {
	for _, tc := range []struct{ mode, code string }{{"ok", "ok"}, {"failure", "read_failed"}, {"limit", "output_limit"}, {"hang", "timeout"}} {
		t.Run(tc.mode, func(t *testing.T) {
			d := 5 * time.Second
			if tc.mode == "hang" {
				d = 100 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), d)
			defer cancel()
			start := time.Now()
			s := runPFDiagnosticCommand(ctx, pfDiagnosticTestCommand(ctx, tc.mode))
			if s.Code != tc.code {
				t.Fatalf("got %+v, want %s", s, tc.code)
			}
			if tc.mode != "ok" && (s.UDP.Known || s.TCP.Known || s.UDP.Installed) {
				t.Fatalf("failed read trusted: %+v", s)
			}
			if tc.mode == "hang" && time.Since(start) > time.Second {
				t.Fatal("deadline not bounded")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := runPFDiagnosticCommand(ctx, pfDiagnosticTestCommand(ctx, "ok")); got.Code != "canceled" {
		t.Fatalf("cancellation: %+v", got)
	}
	if got := runPFDiagnosticCommand(context.Background(), exec.Command(t.TempDir()+"/missing")); got.Code != "read_failed" {
		t.Fatalf("start failure: %+v", got)
	}
	var b pfDiagnosticBuffer
	_, _ = b.Write(make([]byte, pfDiagnosticMaxBytes))
	if _, err := b.Write([]byte{1}); err == nil || b.Len() != pfDiagnosticMaxBytes {
		t.Fatal("buffer is unbounded")
	}
}

func TestPFDiagnosticCadenceTransitionsAndReset(t *testing.T) {
	var s pfDiagnosticState
	now := time.Unix(1, 0)
	reads := 0
	fixture := parsePFDiagnostic([]byte(pfDiagnosticFixture))
	capture := func() pfDiagnosticSnapshot { reads++; return fixture }
	o := pfProbeObservation{result: pfProbeIntercepted, target: "192.0.2.1:53"}
	if _, emit := s.observe(now, o, capture); emit || reads != 0 {
		t.Fatal("healthy poll did work")
	}
	o.result, o.stage, o.code = pfProbeNotIntercepted, "delivery", "timeout"
	e, emit := s.observe(now, o, capture)
	if !emit || e.Cached || e.Generation != 1 || e.UDPDeltaCode != "unknown" {
		t.Fatalf("first failure: %+v %v", e, emit)
	}
	for i := 0; i < 100; i++ {
		o.probeID = fmt.Sprint(i)
		o.recoveryGeneration++
		if _, emit := s.observe(now.Add(time.Second), o, capture); emit {
			t.Fatal("duplicate failure noisy")
		}
	}
	if reads != 1 {
		t.Fatalf("unbounded reads: %d", reads)
	}
	if _, emit := s.observe(now.Add(time.Minute), o, capture); emit || reads != 2 {
		t.Fatal("unchanged refresh noisy")
	}
	fixture.UDP.Packets++
	e, emit = s.observe(now.Add(2*time.Minute), o, capture)
	if !emit || e.UDPDelta != 1 || e.UDPDeltaCode != "shared_traffic" {
		t.Fatalf("delta: %+v", e)
	}
	fixture.UDP.Packets = 0
	e, _ = s.observe(now.Add(3*time.Minute), o, capture)
	if e.UDPDeltaCode != "reset" || e.UDPDelta != 0 {
		t.Fatalf("reset: %+v", e)
	}
	o.result = pfProbeIntercepted
	e, emit = s.observe(now.Add(3*time.Minute+time.Second), o, capture)
	if !emit || !e.Cached || e.Age != time.Second || e.Generation != 4 || e.UDPDeltaCode != "unknown" {
		t.Fatalf("restored: %+v", e)
	}
	if _, emit := s.observe(now.Add(4*time.Minute), o, capture); emit || reads != 4 {
		t.Fatal("healthy repeats did work")
	}
	o.code = "canceled"
	o.result = pfProbeIndeterminate
	if _, emit := s.observe(now.Add(5*time.Minute), o, capture); emit || reads != 4 {
		t.Fatal("shutdown did work")
	}
	fixture.Code = "read_failed"
	fixture.UDP.Known = false
	fixture.TCP.Known = false
	o.code = "unavailable"
	e, emit = s.observe(now.Add(6*time.Minute), o, capture)
	if !emit || e.UDPDeltaCode != "unknown" {
		t.Fatalf("failed read: %+v", e)
	}
}

func TestPFDiagnosticConcurrentCaptureDoesNotBlock(t *testing.T) {
	var s pfDiagnosticState
	started, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		s.observe(time.Now(), pfProbeObservation{}, func() pfDiagnosticSnapshot { close(started); <-release; return pfDiagnosticSnapshot{} })
	}()
	<-started
	defer func() { close(release); <-done }()
	if _, emit := s.observe(time.Now(), pfProbeObservation{}, func() pfDiagnosticSnapshot { t.Error("overlapping capture"); return pfDiagnosticSnapshot{} }); emit {
		t.Fatal("concurrent capture should stand down")
	}
}
