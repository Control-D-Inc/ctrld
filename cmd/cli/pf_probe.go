package cli

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"tailscale.com/net/tsaddr"
)

type pfProbeResult uint8

const (
	pfProbeIndeterminate pfProbeResult = iota
	pfProbeIntercepted
	pfProbeNotIntercepted
)

func (r pfProbeResult) String() string {
	switch r {
	case pfProbeIntercepted:
		return "intercepted"
	case pfProbeNotIntercepted:
		return "not_intercepted"
	default:
		return "indeterminate"
	}
}

type pfProbeObservation struct {
	result             pfProbeResult
	stage              string
	code               string
	probeID            string
	recoveryGeneration uint64
	target             string
}

// Conditions exclude attempt IDs and generations so repeated failures stay bounded.
type pfProbeCondition struct {
	result              pfProbeResult
	stage, code, target string
}

type pfProbeLogState struct {
	mu          sync.Mutex
	previous    pfProbeCondition
	initialized bool
	repeats     uint64
}

// change returns whether to retain a transition and the preceding repeat count.
// A restored receipt is retained too, so an old warning does not imply an outage.
func (s *pfProbeLogState) change(o pfProbeObservation) (retain bool, repeats uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	condition := pfProbeCondition{o.result, o.stage, o.code, o.target}
	if s.initialized && condition == s.previous {
		s.repeats++
		return false, s.repeats
	}
	retain = o.result != pfProbeIntercepted || (s.initialized && s.previous.result != pfProbeIntercepted)
	repeats = s.repeats
	s.previous, s.initialized, s.repeats = condition, true, 0
	return retain, repeats
}

// OsResolverNameservers groups LAN entries before public entries. Preserve a usable
// first target, including public DNS. Otherwise scan only the LAN group. Stop at
// the public boundary, not at a particular IP: the public group can be synthetic.
func pfProbeTarget(servers []string) string {
	for i, server := range servers {
		host, _, err := net.SplitHostPort(server)
		if err != nil {
			return ""
		}
		ip, err := netip.ParseAddr(host)
		if err != nil {
			return ""
		}
		lan := ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || tsaddr.CGNATRange().Contains(ip)
		usable := ip.Is4() && !ip.IsLoopback() && !ip.IsUnspecified() && !ip.IsMulticast()
		if usable && (i == 0 || lan) {
			return host
		}
		if !lan {
			return ""
		}
	}
	return ""
}

// Keep the helper protocol bounded and free of resolver IDs, queries and raw OS errors.
func pfProbeErrorCode(err error) string {
	switch {
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH):
		return "unreachable"
	case errors.Is(err, syscall.EADDRNOTAVAIL):
		return "source_unavailable"
	case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM):
		return "permission"
	default:
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return "timeout"
		}
		return "io"
	}
}

func sendPFProbe(host, hexPacket string, dial func(string, string, time.Duration) (net.Conn, error), status io.Writer) error {
	fail := func(stage string, err error) error {
		_, _ = fmt.Fprintf(status, "%s:%s\n", stage, pfProbeErrorCode(err))
		return err
	}
	packet, err := hex.DecodeString(hexPacket)
	if err != nil {
		_, _ = io.WriteString(status, "decode:invalid_argument\n")
		return err
	}
	conn, err := dial("udp4", net.JoinHostPort(host, "53"), time.Second)
	if err != nil {
		return fail("dial", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		return fail("deadline", err)
	}
	n, err := conn.Write(packet)
	if err == nil && n != len(packet) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return fail("write", err)
	}
	if _, err := io.WriteString(status, "sent\n"); err != nil {
		return err
	}
	// Keep the socket alive for the local handler's response. A read failure does
	// not undo the successful send acknowledged above.
	_, _ = conn.Read(make([]byte, 512))
	return nil
}

func parsePFProbeStatus(status string) pfProbeObservation {
	if status == "sent\n" {
		return pfProbeObservation{stage: "sent"}
	}
	stage, code, ok := strings.Cut(strings.TrimSuffix(status, "\n"), ":")
	if ok && (stage == "decode" || stage == "dial" || stage == "deadline" || stage == "write") {
		switch code {
		case "unreachable", "source_unavailable", "permission", "timeout", "io", "invalid_argument":
			return pfProbeObservation{stage: stage, code: code}
		}
	}
	return pfProbeObservation{stage: "helper", code: "invalid_status"}
}

func pfProbeContextCode(ctx context.Context) string {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return "timeout"
	}
	return "canceled"
}

// Receipt by the local handler is conclusive. A missing receipt is a failed
// interception test only after the child confirms a successful packet send.
func runPFProbe(ctx context.Context, cmd *exec.Cmd, received <-chan struct{}, deliveryTimeout time.Duration) pfProbeObservation {
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return pfProbeObservation{stage: "start", code: pfProbeErrorCode(err)}
	}
	if err := cmd.Start(); err != nil {
		_ = stdout.Close()
		return pfProbeObservation{stage: "start", code: pfProbeErrorCode(err)}
	}
	statusCh := make(chan pfProbeObservation, 1)
	done := make(chan struct{})
	go func() {
		line, _ := bufio.NewReader(io.LimitReader(stdout, 128)).ReadString('\n')
		statusCh <- parsePFProbeStatus(line)
		_ = cmd.Wait()
		close(done)
	}()
	defer func() {
		_ = cmd.Process.Kill()
		<-done
	}()

	var sent pfProbeObservation
	select {
	case <-received:
		return pfProbeObservation{result: pfProbeIntercepted, stage: "received"}
	case <-ctx.Done():
		return pfProbeObservation{stage: "helper", code: pfProbeContextCode(ctx)}
	case sent = <-statusCh:
	}
	if sent.stage != "sent" {
		select {
		case <-received:
			return pfProbeObservation{result: pfProbeIntercepted, stage: "received"}
		default:
			return sent
		}
	}

	timer := time.NewTimer(deliveryTimeout)
	defer timer.Stop()
	select {
	case <-received:
		return pfProbeObservation{result: pfProbeIntercepted, stage: "received"}
	case <-ctx.Done():
		return pfProbeObservation{stage: "delivery", code: pfProbeContextCode(ctx)}
	case <-timer.C:
		// Prefer receipt when notification and deadline became ready together.
		select {
		case <-received:
			return pfProbeObservation{result: pfProbeIntercepted, stage: "received"}
		default:
			return pfProbeObservation{result: pfProbeNotIntercepted, stage: "delivery", code: "timeout"}
		}
	}
}
