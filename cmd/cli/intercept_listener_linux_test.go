//go:build linux

package cli

import (
	"net"
	"strconv"
	"testing"

	ctrld "github.com/Control-D-Inc/ctrld"
)

// heldListener holds a port on one IP for both UDP and TCP, the two binds
// tryUpdateListenerConfigIntercept makes.
type heldListener struct {
	port int
	udp  net.PacketConn
	tcp  net.Listener
}

func (h *heldListener) Close() {
	if h.udp != nil {
		h.udp.Close()
		h.udp = nil
	}
	if h.tcp != nil {
		h.tcp.Close()
		h.tcp = nil
	}
}

// holdListenerPort binds a port on ip for both UDP and TCP and keeps it bound
// until the returned listener is closed. The test cleanup closes it too.
func holdListenerPort(t *testing.T, ip string) *heldListener {
	t.Helper()
	for range 20 {
		udp, err := net.ListenPacket("udp4", net.JoinHostPort(ip, "0"))
		if err != nil {
			t.Fatal(err)
		}
		port := udp.LocalAddr().(*net.UDPAddr).Port
		tcp, err := net.Listen("tcp4", net.JoinHostPort(ip, strconv.Itoa(port)))
		if err != nil {
			udp.Close()
			continue
		}
		h := &heldListener{port: port, udp: udp, tcp: tcp}
		t.Cleanup(h.Close)
		return h
	}
	t.Fatalf("no port free for both UDP and TCP on %s", ip)
	return nil
}

func explicitListenerConfig(ip string, port int) *ctrld.Config {
	return &ctrld.Config{Listener: map[string]*ctrld.ListenerConfig{"0": {IP: ip, Port: port}}}
}

// Socket-only Linux control for an explicit intercept listener: an address the
// configuration sets binds unchanged, and once occupied it fails rather than
// silently falling back to another address. Native macOS PF delivery is a
// separate QA gate.
//
// The ports are the test's own, so the result does not depend on what else the
// host runs. An occupied port stays held by the test for the whole check. A
// free one has to be released before the check, which binds it itself, so it
// is released immediately before.
func TestExplicitInterceptListenerBinding(t *testing.T) {
	captureDebugMainLog(t)
	for _, ip := range []string{"127.0.0.1", "127.0.0.2"} {
		t.Run(ip+"/free", func(t *testing.T) {
			held := holdListenerPort(t, ip)
			cfg := explicitListenerConfig(ip, held.port)
			held.Close()
			changed, ok := tryUpdateListenerConfigIntercept(cfg, func() {}, false)
			if !ok || changed {
				t.Fatalf("custom listener did not bind unchanged: changed=%v ok=%v", changed, ok)
			}
		})
		for _, occupied := range []string{"udp", "tcp", "udp+tcp"} {
			t.Run(ip+"/occupied "+occupied, func(t *testing.T) {
				held := holdListenerPort(t, ip)
				switch occupied {
				case "udp":
					held.tcp.Close()
					held.tcp = nil
				case "tcp":
					held.udp.Close()
					held.udp = nil
				}
				cfg := explicitListenerConfig(ip, held.port)
				changed, ok := tryUpdateListenerConfigIntercept(cfg, func() {}, false)
				if ok || changed || cfg.Listener["0"].IP != ip || cfg.Listener["0"].Port != held.port {
					t.Fatalf("occupied explicit listener silently fell back: changed=%v ok=%v listener=%s:%d",
						changed, ok, cfg.Listener["0"].IP, cfg.Listener["0"].Port)
				}
			})
		}
	}
}
