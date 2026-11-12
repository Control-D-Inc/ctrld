package clientinfo

import (
	"errors"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

func Test_mdns_storeDataFromAvahiBrowseOutput(t *testing.T) {
	const content = `+;wlp0s20f3;IPv6;Foo\032\0402\041;_companion-link._tcp;local
+;wlp0s20f3;IPv4;Foo\032\0402\041;_companion-link._tcp;local
=;wlp0s20f3;IPv6;Foo\032\0402\041;_companion-link._tcp;local;Foo-2.local;192.168.1.123;64842;"rpBA=00:00:00:00:00:01" "rpHI=e6ae2cbbca0e" "rpAD=36566f4d850f" "rpVr=510.71.1" "rpHA=0ddc20fdddc8" "rpFl=0x30000" "rpHN=1d4a03afdefa" "rpMac=0"
=;wlp0s20f3;IPv4;Foo\032\0402\041;_companion-link._tcp;local;Foo-2.local;192.168.1.123;64842;"rpBA=00:00:00:00:00:01" "rpHI=e6ae2cbbca0e" "rpAD=36566f4d850f" "rpVr=510.71.1" "rpHA=0ddc20fdddc8" "rpFl=0x30000" "rpHN=1d4a03afdefa" "rpMac=0"
`
	m := &mdns{}
	m.storeDataFromAvahiBrowseOutput(strings.NewReader(content))
	ip := "192.168.1.123"
	val, loaded := m.name.LoadOrStore(ip, "")
	if !loaded {
		t.Fatal("missing Foo-2 data from mdns table")
	}

	wantHostname := "Foo-2"
	hostname := val.(string)
	if hostname != wantHostname {
		t.Fatalf("unexpected hostname, want: %q, got: %q", wantHostname, hostname)
	}
}

type fakeMdnsConn struct {
	err    error
	writes int
}

func (c *fakeMdnsConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.writes++
	if c.err != nil {
		return 0, c.err
	}
	return len(b), nil
}

func (c *fakeMdnsConn) SetWriteDeadline(time.Time) error { return nil }
func (c *fakeMdnsConn) Close() error                     { return nil }

func sendtoErr(errno syscall.Errno) error {
	return &net.OpError{Op: "write", Net: "udp6", Addr: mdnsV6Addr, Err: os.NewSyscallError("sendto", errno)}
}

func Test_mdns_probe(t *testing.T) {
	eacces := sendtoErr(syscall.EACCES)
	transient := sendtoErr(syscall.ENOBUFS)

	tests := []struct {
		name       string
		conns      []*fakeMdnsConn
		wantErr    error
		wantActive []int // indexes into conns
	}{
		{"no sockets", nil, nil, nil},
		{"all sent", []*fakeMdnsConn{{}, {}}, nil, []int{0, 1}},
		// Bridge ports with IPv6 disabled fail with EACCES; the bridge itself sends.
		{"one sent, others permanent", []*fakeMdnsConn{{err: eacces}, {}, {err: eacces}}, nil, []int{1}},
		{"one sent, other transient", []*fakeMdnsConn{{err: transient}, {}}, nil, []int{0, 1}},
		{"all permanent", []*fakeMdnsConn{{err: eacces}, {err: eacces}}, eacces, nil},
		{"permanent and transient", []*fakeMdnsConn{{err: eacces}, {err: transient}}, transient, []int{1}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conns := make([]mdnsConn, len(tc.conns))
			for i, c := range tc.conns {
				conns[i] = c
			}
			active, err := (&mdns{}).probe(conns, mdnsV6Addr)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("unexpected error, want: %v, got: %v", tc.wantErr, err)
			}
			if len(active) != len(tc.wantActive) {
				t.Fatalf("unexpected active sockets, want: %d, got: %d", len(tc.wantActive), len(active))
			}
			for i, idx := range tc.wantActive {
				if active[i] != mdnsConn(tc.conns[idx]) {
					t.Fatalf("active socket %d: want conns[%d]", i, idx)
				}
			}
			for i, c := range tc.conns {
				if c.writes != 1 {
					t.Fatalf("conns[%d]: want 1 write, got %d", i, c.writes)
				}
			}
		})
	}
}

func Test_mdns_probeLoop_stopsOnPermanentErrors(t *testing.T) {
	bad := &fakeMdnsConn{err: sendtoErr(syscall.EACCES)}
	quitCh := make(chan struct{})
	close(quitCh)
	done := make(chan struct{})
	go func() {
		(&mdns{}).probeLoop([]mdnsConn{bad}, mdnsV6Addr, quitCh)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("probeLoop kept retrying a permanent EACCES error")
	}
	if bad.writes != 1 {
		t.Fatalf("want 1 write, got %d", bad.writes)
	}
}

func Test_shouldStopProbing(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.ENETUNREACH, syscall.EINVAL, syscall.EPERM, syscall.EACCES} {
		if !shouldStopProbing(sendtoErr(errno)) {
			t.Errorf("%v: want permanent", errno)
		}
	}
	for _, err := range []error{nil, sendtoErr(syscall.ENOBUFS), errors.New("other")} {
		if shouldStopProbing(err) {
			t.Errorf("%v: want not permanent", err)
		}
	}
}

func Test_hasIPv6Addr(t *testing.T) {
	ipNet := func(s string) net.Addr {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	tests := []struct {
		name  string
		addrs []net.Addr
		want  bool
	}{
		{"none", nil, false},
		{"ipv4 only", []net.Addr{ipNet("192.168.8.1/24")}, false},
		{"ipv4-mapped only", []net.Addr{&net.IPNet{IP: net.ParseIP("::ffff:192.168.8.1"), Mask: net.CIDRMask(128, 128)}}, false},
		{"link-local", []net.Addr{ipNet("192.168.8.1/24"), ipNet("fe80::1/64")}, true},
		{"global", []net.Addr{ipNet("2001:db8::1/64")}, true},
		{"non-IPNet", []net.Addr{&net.IPAddr{IP: net.ParseIP("fe80::1")}}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasIPv6Addr(tc.addrs); got != tc.want {
				t.Fatalf("want: %v, got: %v", tc.want, got)
			}
		})
	}
}
