package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestPFProbeProcess(t *testing.T) {
	mode := os.Getenv("CTRLD_PF_PROBE_TEST")
	if mode == "" {
		return
	}
	switch mode {
	case "main_dispatch":
		os.Args = []string{os.Args[0], "pf-probe-send", "127.0.0.1", "zz"}
		Main()
		os.Exit(99) // Production dispatch must exit on invalid input.
	case "sent":
		_, _ = os.Stdout.WriteString("sent\n")
	case "dial":
		_, _ = os.Stdout.WriteString("dial:unreachable\n")
		os.Exit(1)
	case "write":
		_, _ = os.Stdout.WriteString("write:permission\n")
		os.Exit(1)
	case "malformed":
		_, _ = os.Stdout.WriteString(strings.Repeat("private-payload", 1000))
	case "hang":
		time.Sleep(time.Minute)
	case "silent":
		os.Exit(1)
	}
	os.Exit(0)
}

func pfProbeTestCommand(ctx context.Context, mode string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPFProbeProcess$")
	cmd.Env = append(os.Environ(), "CTRLD_PF_PROBE_TEST="+mode)
	return cmd
}

func TestPFProbeProcessClassification(t *testing.T) {
	for _, tc := range []struct {
		mode  string
		want  pfProbeResult
		stage string
	}{
		{"dial", pfProbeIndeterminate, "dial"},
		{"write", pfProbeIndeterminate, "write"},
		{"silent", pfProbeIndeterminate, "helper"},
		{"malformed", pfProbeIndeterminate, "helper"},
		{"sent", pfProbeNotIntercepted, "delivery"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			got := runPFProbe(ctx, pfProbeTestCommand(ctx, tc.mode), make(chan struct{}), 10*time.Millisecond)
			if got.result != tc.want || got.stage != tc.stage {
				t.Fatalf("got %+v, want %v/%s", got, tc.want, tc.stage)
			}
			if strings.Contains(got.code, "private") {
				t.Fatal("helper output escaped into diagnostic")
			}
		})
	}
}

func TestPFProbeStartFailureAndCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got := runPFProbe(ctx, exec.Command(t.TempDir()+"/missing-helper"), make(chan struct{}), time.Second)
	if got.result != pfProbeIndeterminate || got.stage != "start" {
		t.Fatalf("start failure: %+v", got)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	got = runPFProbe(ctx, pfProbeTestCommand(ctx, "hang"), make(chan struct{}), time.Second)
	if got.result != pfProbeIndeterminate {
		t.Fatalf("canceled helper must not request repair: %+v", got)
	}
}

func TestPFProbeReceiptWins(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	received := make(chan struct{})
	close(received)
	got := runPFProbe(ctx, pfProbeTestCommand(ctx, "sent"), received, time.Millisecond)
	if got.result != pfProbeIntercepted {
		t.Fatalf("local receipt is conclusive: %+v", got)
	}
}

type pfProbeErrorConn struct {
	net.Conn
	writeErr error
	short    bool
}

func (c pfProbeErrorConn) SetDeadline(time.Time) error { return nil }
func (c pfProbeErrorConn) Close() error                { return nil }
func (c pfProbeErrorConn) Write(b []byte) (int, error) {
	if c.short {
		return len(b) - 1, nil
	}
	return 0, c.writeErr
}

func TestPFProbeSendFailures(t *testing.T) {
	for _, tc := range []struct {
		name, packet, want string
		dial               func(string, string, time.Duration) (net.Conn, error)
	}{
		{"decode", "zz", "decode:invalid_argument\n", nil},
		{"dial", "0102", "dial:unreachable\n", func(string, string, time.Duration) (net.Conn, error) {
			return nil, &net.OpError{Op: "dial", Err: syscall.ENETUNREACH}
		}},
		{"write", "0102", "write:permission\n", func(string, string, time.Duration) (net.Conn, error) {
			return pfProbeErrorConn{writeErr: syscall.EACCES}, nil
		}},
		{"short", "0102", "write:io\n", func(string, string, time.Duration) (net.Conn, error) { return pfProbeErrorConn{short: true}, nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			err := sendPFProbe("192.0.2.1", tc.packet, tc.dial, &out)
			if err == nil || out.String() != tc.want {
				t.Fatalf("status=%q err=%v", out.String(), err)
			}
			if strings.Contains(out.String(), "sent") {
				t.Fatal("failed write claimed success")
			}
		})
	}
}

func TestPFProbeSendRealUDP(t *testing.T) {
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	received := make(chan []byte, 1)
	go func() {
		b := make([]byte, 100)
		n, addr, e := listener.ReadFrom(b)
		if e != nil {
			return
		}
		received <- append([]byte(nil), b[:n]...)
		_, _ = listener.WriteTo([]byte{0}, addr)
	}()
	var out bytes.Buffer
	err = sendPFProbe("127.0.0.1", "010203", func(network, address string, timeout time.Duration) (net.Conn, error) {
		if network != "udp4" || address != "127.0.0.1:53" {
			t.Errorf("unexpected target %s %s", network, address)
		}
		return net.DialTimeout(network, listener.LocalAddr().String(), timeout)
	}, &out)
	if err != nil || out.String() != "sent\n" {
		t.Fatalf("status=%q error=%v", out.String(), err)
	}
	select {
	case b := <-received:
		if !bytes.Equal(b, []byte{1, 2, 3}) {
			t.Fatalf("wrong packet %v", b)
		}
	case <-time.After(time.Second):
		t.Fatal("helper reported sent without UDP receipt")
	}
}

func TestPFProbeTarget(t *testing.T) {
	for _, first := range []string{"[fe80::1%en0]:53", "[2001:db8::1]:53", "127.0.0.53:53", "0.0.0.0:53", "224.0.0.1:53", "bad"} {
		// Resolver construction can append this public fallback. No later entry
		// may become a new probe recipient when the original first target fails.
		if got := pfProbeTarget([]string{first, "76.76.2.0:53"}); got != "" {
			t.Fatalf("first=%s selected new recipient=%s", first, got)
		}
	}
	for _, first := range []string{"192.0.2.10", "76.76.2.0"} {
		if got := pfProbeTarget([]string{first + ":53", "192.0.2.11:53"}); got != first {
			t.Fatalf("changed original first target %s to %s", first, got)
		}
	}
	if got := pfProbeTarget(nil); got != "" {
		t.Fatalf("empty list selected %s", got)
	}
}

func TestPFProbeMainDispatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := pfProbeTestCommand(ctx, "main_dispatch").Output()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 || string(out) != "decode:invalid_argument\n" {
		t.Fatalf("production Main dispatch: output=%q error=%v", out, err)
	}
}

func TestPFProbeTargetLANScan(t *testing.T) {
	for _, tc := range []struct {
		servers []string
		want    string
	}{
		{[]string{"[fe80::1%en0]:53", "192.168.1.1:53", "76.76.2.0:53"}, "192.168.1.1"},
		{[]string{"127.0.0.1:53", "100.64.0.1:53", "76.76.2.0:53"}, "100.64.0.1"},
		{[]string{"[fd00::1]:53", "169.254.1.1:53", "76.76.2.0:53"}, "169.254.1.1"},
		{[]string{"[fe80::1%en0]:53", "76.76.2.0:53"}, ""},
		{[]string{"[fe80::1%en0]:53", "8.8.8.8:53", "192.168.1.1:53"}, ""},
		{[]string{"[2001:db8::1]:53", "192.168.1.1:53"}, ""},
		{[]string{"76.76.2.0:53"}, "76.76.2.0"},
		{[]string{"8.8.8.8:53", "192.168.1.1:53"}, "8.8.8.8"},
	} {
		if got := pfProbeTarget(tc.servers); got != tc.want {
			t.Errorf("%v: got %q want %q", tc.servers, got, tc.want)
		}
	}
}

func TestPFProbeLogConcurrentRepeats(t *testing.T) {
	var state pfProbeLogState
	observed := pfProbeObservation{stage: "dial", code: "unreachable"}
	state.change(observed)
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() { defer wg.Done(); state.change(observed) }()
	}
	wg.Wait()
	observed.result, observed.stage, observed.code = pfProbeIntercepted, "received", ""
	if retained, repeats := state.change(observed); !retained || repeats != 20 {
		t.Fatalf("retained=%v repeats=%d", retained, repeats)
	}
}

func TestPFProbeLogConditionChanges(t *testing.T) {
	var state pfProbeLogState
	missing := pfProbeObservation{stage: "target", code: "unavailable", target: "[fe80::1%en0]:53"}
	if retain, repeats := state.change(missing); !retain || repeats != 0 {
		t.Fatal("first missing target not retained")
	}
	missing.probeID, missing.recoveryGeneration = "new-attempt", 2
	if retain, repeats := state.change(missing); retain || repeats != 1 {
		t.Fatal("attempt IDs defeat dedupe")
	}
	for _, change := range []func(*pfProbeObservation){
		func(o *pfProbeObservation) { o.target = "127.0.0.1:53" },
		func(o *pfProbeObservation) { o.stage = "dial" },
		func(o *pfProbeObservation) { o.code = "unreachable" },
		func(o *pfProbeObservation) { o.result = pfProbeNotIntercepted },
	} {
		change(&missing)
		if retain, repeats := state.change(missing); !retain || repeats != 1 {
			t.Fatalf("change not retained with prior repeats: %v %d", retain, repeats)
		}
		if retain, repeats := state.change(missing); retain || repeats != 1 {
			t.Fatal("repeat not coalesced")
		}
	}
	healthy := pfProbeObservation{result: pfProbeIntercepted, stage: "received", target: missing.target}
	if retain, repeats := state.change(healthy); !retain || repeats != 1 {
		t.Fatal("restoration not retained")
	}
	if retain, _ := state.change(healthy); retain {
		t.Fatal("normal receipt retained")
	}
}

func TestPFProbeStatusIsBounded(t *testing.T) {
	if got := parsePFProbeStatus("decode:invalid_argument\n"); got.stage != "decode" || got.code != "invalid_argument" || got.result != pfProbeIndeterminate {
		t.Fatalf("invalid argument classification: %+v", got)
	}
	for _, s := range []string{"dial:secret-token\n", "secret:io\n", strings.Repeat("private", 1000)} {
		got := parsePFProbeStatus(s)
		if got.result != pfProbeIndeterminate || got.stage != "helper" || got.code != "invalid_status" {
			t.Fatalf("untrusted status leaked: %+v", got)
		}
	}
	if pfProbeErrorCode(errors.New("secret")) != "io" || pfProbeErrorCode(io.ErrShortWrite) != "io" {
		t.Fatal("unbounded diagnostic")
	}
}
